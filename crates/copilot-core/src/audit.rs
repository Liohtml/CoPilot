//! Audit events — the CoPilot `audit_log` record, plus the Talon-style sink
//! abstraction (`talon_core::audit`) so both services report security
//! decisions the same way.
//!
//! Port of `app/audit/services/audit.py:record_audit_event`: the record is
//! written in its *own* transaction after the caller's commit and a failure is
//! logged, never raised — failing to audit must not fail the action.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// `audit_log.result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditResult {
    /// The action happened.
    Success,
    /// The action was refused or failed.
    Failure,
}

impl AuditResult {
    /// The stored string.
    pub const fn as_str(self) -> &'static str {
        match self {
            AuditResult::Success => "success",
            AuditResult::Failure => "failure",
        }
    }
}

/// One `audit_log` row. `action` follows `<domain>.<verb>` (`auth.login`,
/// `ai_analysis.request`, …).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// `<domain>.<verb>`.
    pub action: String,
    /// The acting user's id.
    pub actor_user_id: Option<i32>,
    /// The acting user's name.
    pub actor_username: Option<String>,
    /// The tenant the action concerns.
    pub customer_code: Option<String>,
    /// Kind of object acted on.
    pub entity_type: Option<String>,
    /// Id of the object acted on (stringified).
    pub entity_id: Option<String>,
    /// Outcome.
    pub result: AuditResult,
    /// State before (JSON object).
    pub old_value: Option<serde_json::Value>,
    /// State after (JSON object).
    pub new_value: Option<serde_json::Value>,
    /// First `X-Forwarded-For` entry, else the peer address.
    pub source_ip: Option<String>,
    /// Free text (≤ 5024 chars in the column).
    pub details: Option<String>,
}

impl AuditRecord {
    /// A successful action with only the required field set.
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            actor_user_id: None,
            actor_username: None,
            customer_code: None,
            entity_type: None,
            entity_id: None,
            result: AuditResult::Success,
            old_value: None,
            new_value: None,
            source_ip: None,
            details: None,
        }
    }

    /// Set the actor.
    pub fn actor(mut self, user_id: Option<i32>, username: Option<&str>) -> Self {
        self.actor_user_id = user_id;
        self.actor_username = username.map(str::to_string);
        self
    }

    /// Set the tenant.
    pub fn customer(mut self, code: Option<&str>) -> Self {
        self.customer_code = code.map(str::to_string);
        self
    }

    /// Set the entity acted on.
    pub fn entity(mut self, kind: &str, id: impl ToString) -> Self {
        self.entity_type = Some(kind.to_string());
        self.entity_id = Some(id.to_string());
        self
    }

    /// Mark the action as failed.
    pub fn failed(mut self) -> Self {
        self.result = AuditResult::Failure;
        self
    }

    /// Set the free-text details.
    pub fn details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Set the source address.
    pub fn source_ip(mut self, ip: Option<String>) -> Self {
        self.source_ip = ip;
        self
    }

    /// Set before/after values.
    pub fn values(
        mut self,
        old: Option<serde_json::Value>,
        new: Option<serde_json::Value>,
    ) -> Self {
        self.old_value = old;
        self.new_value = new;
        self
    }
}

/// Where audit records go. Implementations must never panic or block for
/// long; the database sink spawns its write.
pub trait AuditSink: Send + Sync {
    /// Record one event.
    fn record(&self, record: AuditRecord);
}

/// Shared handle type used across crates.
pub type SharedAuditSink = Arc<dyn AuditSink>;

/// Logs every record via `tracing` (target `copilot::audit`).
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn record(&self, r: AuditRecord) {
        match r.result {
            AuditResult::Failure => tracing::warn!(
                target: "copilot::audit", action = %r.action, actor = ?r.actor_username,
                customer = ?r.customer_code, entity = ?r.entity_id, "audit"
            ),
            AuditResult::Success => tracing::info!(
                target: "copilot::audit", action = %r.action, actor = ?r.actor_username,
                customer = ?r.customer_code, entity = ?r.entity_id, "audit"
            ),
        }
    }
}

/// Collects records in memory (tests).
#[derive(Debug, Default, Clone)]
pub struct MemoryAuditSink {
    /// Everything recorded so far.
    pub records: Arc<Mutex<Vec<AuditRecord>>>,
}

impl MemoryAuditSink {
    /// Copy of the recorded events.
    pub fn snapshot(&self) -> Vec<AuditRecord> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, record: AuditRecord) {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_and_memory_sink() {
        let sink = MemoryAuditSink::default();
        sink.record(
            AuditRecord::new("ai_analysis.request")
                .actor(Some(3), Some("bob"))
                .customer(Some("acme"))
                .entity("alert", 42)
                .failed()
                .details("refused"),
        );
        let got = sink.snapshot();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].entity_id.as_deref(), Some("42"));
        assert_eq!(got[0].result.as_str(), "failure");
    }
}
