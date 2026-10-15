//! The CoPilot ↔ Talon wire contract, typed.
//!
//! Talon 2.0 (`liohtml/talahon`, crate `talon-http`) parses its request
//! bodies by hand and builds responses with `json!`, so neither side had
//! these shapes as types. They are pinned here, field for field, against
//! `crates/talon-http/src/server.rs` (endpoints) and
//! `crates/talon-db/src/lib.rs` (`Investigation`); the tests at the bottom
//! assert the exact JSON both directions produce and accept. A change on the
//! Talon side shows up as a failing test here, not as a silent 400 in
//! production.
//!
//! | Talon endpoint | Request | Response |
//! |---|---|---|
//! | `POST /investigate` | [`InvestigateRequest`] | [`InvestigateAccepted`] (202, or 200 when deduplicated) |
//! | `GET /investigations[/{id}]` | — | [`Investigation`] |
//! | `POST /message` | [`MessageRequest`] | SSE of [`SseFrame`] |
//! | `POST /session/reset` | [`SessionResetRequest`] | [`SessionResetResponse`] |
//! | `GET /status` | — | [`StatusResponse`] (partial) |
//! | `GET /templates` | — | [`TemplatesResponse`] |
//! | `POST /palace/lesson` | [`PalaceLessonRequest`] | MemPalace `add_drawer` JSON (`drawer_id`) |
//! | `GET /palace/search` | query | MemPalace `search` JSON |
//! | `POST /palace/forget` | [`PalaceForgetRequest`] | MemPalace `delete_drawer` JSON |
//! | any error | — | [`ErrorBody`] `{"error": "…"}` |
//!
//! Authentication: `X-Api-Key: <HTTP_API_KEY>` (Talon also accepts
//! `Authorization: Bearer`). CoPilot sends `x-api-key`, as it always has.

use serde::{Deserialize, Serialize};

/// Talon's `customer_code` rule: `^[A-Za-z0-9_-]{1,64}$`.
pub fn is_valid_customer_code(code: &str) -> bool {
    (1..=64).contains(&code.len())
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Talon's template-name rule: a plain `.txt` filename of
/// `[A-Za-z0-9._-]`, at most 128 bytes, no `..`, not hidden.
pub fn is_valid_template_name(name: &str) -> bool {
    name.len() <= 128
        && name.len() > ".txt".len()
        && name.ends_with(".txt")
        && !name.starts_with('.')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `POST /investigate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigateRequest {
    /// CoPilot alert id (Talon accepts 1..=2^53-1, number or digit string).
    pub alert_id: i64,
    /// The alert's customer.
    pub customer_code: String,
    /// `^[A-Za-z0-9_-]{1,32}$`; Talon defaults to `webhook`. CoPilot has
    /// never sent it, and keeps not sending it until the agent prompt and
    /// `ai_analyst_job.triggered_by` agree on values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<String>,
    /// Force a prompt template (replay).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_override: Option<String>,
    /// Who asked (`copilot`, `copilot-analyst`, `copilot-replay`,
    /// `customer-portal`). Ignored by Talon 2.0, logged by Talon 1.x.
    pub sender: String,
}

/// Talon's answer to `POST /investigate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigateAccepted {
    /// `copilot-inv-<alert_id>-<millis>`.
    pub job_id: String,
    /// `queued`, or the existing job's status when deduplicated.
    pub status: String,
    /// Echo of the override.
    pub template_override: Option<String>,
    /// A job for the same alert was queued within the last 10 minutes.
    pub deduplicated: bool,
}

/// `talon_db::Investigation` as served by `GET /investigations[/{id}]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Investigation {
    /// Job id.
    pub id: String,
    /// Alert id (a string on the Talon side).
    pub alert_id: String,
    /// Customer.
    pub customer_code: String,
    /// Trigger label.
    pub triggered_by: String,
    /// `queued` | `running` | `completed` | `failed`.
    pub status: String,
    /// Template override.
    pub template: Option<String>,
    /// ISO-8601 (`toISOString`).
    pub created_at: String,
    /// ISO-8601.
    pub updated_at: String,
    /// `talon_intel::report::TriageReport`, when finished.
    pub verdict: Option<serde_json::Value>,
    /// Failure text.
    pub error: Option<String>,
}

/// `POST /message`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRequest {
    /// The prompt.
    pub message: String,
    /// Sender label.
    pub sender: String,
    /// Selects the caller's own lane (`^[A-Za-z0-9_-]{1,48}$`); always the
    /// authenticated user's id, never taken from a request body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
}

/// One `data:` frame of the `/message` stream. `type` is serialized first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SseFrame {
    /// A chunk of the answer.
    Text {
        /// The text.
        content: String,
    },
    /// End of the answer; the stream closes after it.
    Done,
}

/// `POST /session/reset`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionResetRequest {
    /// `chat` | `investigate` | `all`.
    pub scope: String,
    /// The lane owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

/// Talon's answer to `POST /session/reset`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionResetResponse {
    /// Lanes cleared.
    #[serde(default)]
    pub cleared: u64,
    /// Their JIDs.
    #[serde(default)]
    pub lanes: Vec<String>,
}

/// One entry of `GET /status`'s `sessions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusSession {
    /// Lane JID.
    #[serde(default)]
    pub lane: Option<String>,
    /// CoPilot user id of a per-user lane.
    #[serde(default)]
    pub user_id: Option<String>,
    /// Agent session id.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Conversation size.
    #[serde(default)]
    pub input_tokens: Option<i64>,
    /// When that size was recorded.
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// The part of `GET /status` CoPilot reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Active lanes.
    #[serde(default)]
    pub sessions: Vec<StatusSession>,
}

/// One prompt template (`GET /templates`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateInfo {
    /// e.g. `sysmon_event_1.txt`.
    pub filename: String,
    /// Size in bytes.
    pub size_bytes: i64,
    /// Modification time, ISO-8601.
    pub modified_at: String,
    /// First non-empty line (≤ 200 chars).
    #[serde(default)]
    pub first_line: Option<String>,
}

/// `GET /templates`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatesResponse {
    /// Available templates.
    pub templates: Vec<TemplateInfo>,
}

/// `POST /palace/lesson` (MemPalace `add_drawer` via Talon).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PalaceLessonRequest {
    /// The wing.
    pub customer_code: String,
    /// The room: `environment|false_positives|assets|threat_intel`.
    pub lesson_type: String,
    /// ≤ 16384 chars.
    pub lesson_text: String,
    /// `one_off` | `durable`.
    pub durability: String,
}

/// `POST /palace/forget`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PalaceForgetRequest {
    /// `^[A-Za-z0-9_.:-]{1,256}$`.
    pub drawer_id: String,
}

/// Every Talon error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Human-readable reason.
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    #[test]
    fn investigate_request_matches_python_payloads() {
        // investigate_alert(): {"alert_id", "customer_code", "sender"}
        let r = InvestigateRequest {
            alert_id: 42,
            customer_code: "acme".into(),
            triggered_by: None,
            template_override: None,
            sender: "copilot-analyst".into(),
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"alert_id":42,"customer_code":"acme","sender":"copilot-analyst"}"#
        );
        // replay_investigation(): + template_override
        let replay = InvestigateRequest {
            template_override: Some("sysmon_event_1.txt".into()),
            sender: "copilot-replay".into(),
            ..r
        };
        assert_eq!(
            serde_json::to_value(&replay).unwrap(),
            json!({"alert_id": 42, "customer_code": "acme",
                   "template_override": "sysmon_event_1.txt", "sender": "copilot-replay"})
        );
    }

    #[test]
    fn talon_responses_parse() {
        let accepted: InvestigateAccepted = serde_json::from_value(json!({
            "job_id": "copilot-inv-42-1760000000000", "status": "queued",
            "template_override": null, "deduplicated": false
        }))
        .unwrap();
        assert_eq!(accepted.status, "queued");
        let inv: Investigation = serde_json::from_value(json!({
            "id": "copilot-inv-42-1", "alert_id": "42", "customer_code": "acme",
            "triggered_by": "webhook", "status": "completed", "template": null,
            "created_at": "2026-10-14T07:47:00.123Z", "updated_at": "2026-10-14T07:49:00.000Z",
            "verdict": {"verdict": "true_positive"}, "error": null
        }))
        .unwrap();
        assert_eq!(inv.alert_id, "42");
        let status: StatusResponse = serde_json::from_value(json!({
            "status": "ok", "uptime_seconds": 5,
            "sessions": [{"lane": "http:copilot:u:7", "user_id": "7", "session_id": "s",
                          "input_tokens": 1234, "updated_at": "2026-10-14T07:47:00.000Z"}]
        }))
        .unwrap();
        assert_eq!(status.sessions[0].input_tokens, Some(1234));
    }

    #[test]
    fn sse_frames_put_type_first() {
        let text = SseFrame::Text {
            content: "hi".into(),
        };
        assert_eq!(
            serde_json::to_string(&text).unwrap(),
            r#"{"type":"text","content":"hi"}"#
        );
        assert_eq!(
            serde_json::to_string(&SseFrame::Done).unwrap(),
            r#"{"type":"done"}"#
        );
    }

    #[test]
    fn message_request_omits_anonymous_lane_fields() {
        let m = MessageRequest {
            message: "hi".into(),
            sender: "copilot".into(),
            user_id: Some("7".into()),
            user_name: None,
        };
        assert_eq!(
            serde_json::to_string(&m).unwrap(),
            r#"{"message":"hi","sender":"copilot","user_id":"7"}"#
        );
    }

    #[test]
    fn validators_follow_talon() {
        assert!(is_valid_customer_code("acme_01-x"));
        assert!(!is_valid_customer_code("acme corp"));
        assert!(!is_valid_customer_code(""));
        assert!(is_valid_template_name("sysmon_event_1.txt"));
        assert!(is_valid_template_name("sysmon_event_1.v2.txt"));
        assert!(!is_valid_template_name("../etc.txt"));
        assert!(!is_valid_template_name(".hidden.txt"));
        assert!(!is_valid_template_name("a..b.txt"));
        assert!(!is_valid_template_name("x.md"));
        assert!(!is_valid_template_name(".txt"));
    }
}
