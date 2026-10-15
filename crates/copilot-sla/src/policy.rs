//! SLA targets — port of `soc_management/domain/policy.py` and the reads of
//! `services/policy.py`.
//!
//! Resolution is per cell (entity × severity), most specific first:
//! customer override → global policy → built-in default.

use chrono::NaiveDateTime;
use sqlx::MySqlConnection;

use crate::SlaError;
use crate::calendar::Clock;

/// `SlaEntity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaEntity {
    /// An alert.
    Alert,
    /// A case.
    Case,
}

impl SlaEntity {
    /// Wire value (`entity_type`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Case => "case",
        }
    }

    /// The enum for a stored `entity_type` (exact, like `SlaEntity(value)`).
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "alert" => Some(Self::Alert),
            "case" => Some(Self::Case),
            _ => None,
        }
    }

    /// The tracking table.
    pub const fn tracking_table(self) -> &'static str {
        match self {
            Self::Alert => "soc_sla_alert_tracking",
            Self::Case => "soc_sla_case_tracking",
        }
    }

    /// The tracking table's key column.
    pub const fn key(self) -> &'static str {
        match self {
            Self::Alert => "alert_id",
            Self::Case => "case_id",
        }
    }
}

/// `SlaTargets` (the `source` label is the editor's, not needed here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlaTargets {
    /// Acknowledge target, minutes (`None` = no promise).
    pub ack_minutes: Option<i64>,
    /// Resolve target, minutes.
    pub resolve_minutes: Option<i64>,
    /// Count business hours.
    pub business_hours: bool,
}

impl SlaTargets {
    const NONE: Self = Self {
        ack_minutes: None,
        resolve_minutes: None,
        business_hours: false,
    };

    const fn of(ack: i64, resolve: i64) -> Self {
        Self {
            ack_minutes: Some(ack),
            resolve_minutes: Some(resolve),
            business_hours: false,
        }
    }

    /// `ack_due(opened_at, clock)`.
    pub fn ack_due(
        &self,
        opened_at: NaiveDateTime,
        clock: Clock<'_>,
    ) -> Result<Option<NaiveDateTime>, SlaError> {
        due(opened_at, self.ack_minutes, clock)
    }

    /// `resolve_due(opened_at, clock)`.
    pub fn resolve_due(
        &self,
        opened_at: NaiveDateTime,
        clock: Clock<'_>,
    ) -> Result<Option<NaiveDateTime>, SlaError> {
        due(opened_at, self.resolve_minutes, clock)
    }
}

fn due(
    opened_at: NaiveDateTime,
    minutes: Option<i64>,
    clock: Clock<'_>,
) -> Result<Option<NaiveDateTime>, SlaError> {
    minutes
        .map(|m| clock.add(opened_at, (m * 60) as f64))
        .transpose()
}

const HOUR: i64 = 60;
const DAY: i64 = 24 * HOUR;

/// `builtin_targets(entity, severity)`: `BUILTIN_TARGETS`, no promise for an
/// unknown severity.
pub fn builtin_targets(entity: SlaEntity, severity: &str) -> SlaTargets {
    match (entity, severity) {
        (SlaEntity::Alert, "Critical") => SlaTargets::of(15, 4 * HOUR),
        (SlaEntity::Alert, "High") => SlaTargets::of(HOUR, 8 * HOUR),
        (SlaEntity::Alert, "Medium") => SlaTargets::of(4 * HOUR, DAY),
        (SlaEntity::Alert, "Low") => SlaTargets::of(8 * HOUR, 3 * DAY),
        (SlaEntity::Case, "Critical") => SlaTargets::of(30, DAY),
        (SlaEntity::Case, "High") => SlaTargets::of(HOUR, 3 * DAY),
        (SlaEntity::Case, "Medium") => SlaTargets::of(4 * HOUR, 7 * DAY),
        (SlaEntity::Case, "Low") => SlaTargets::of(DAY, 14 * DAY),
        _ => SlaTargets::NONE,
    }
}

/// `PolicyRow`: one stored cell (`customer_code` `None` = global).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRow {
    /// Scope.
    pub customer_code: Option<String>,
    /// Entity.
    pub entity: SlaEntity,
    /// Severity.
    pub severity: String,
    /// Acknowledge target.
    pub ack_minutes: Option<i64>,
    /// Resolve target.
    pub resolve_minutes: Option<i64>,
    /// Business hours.
    pub business_hours: bool,
}

/// `resolve_targets`: the first customer row of the cell, else the last
/// global one, else the built-in default.
pub fn resolve_targets(
    entity: SlaEntity,
    severity: &str,
    customer_code: Option<&str>,
    rows: &[PolicyRow],
) -> SlaTargets {
    let mut global: Option<&PolicyRow> = None;
    for row in rows {
        if row.entity != entity || row.severity != severity {
            continue;
        }
        if customer_code.is_some() && row.customer_code.as_deref() == customer_code {
            return SlaTargets {
                ack_minutes: row.ack_minutes,
                resolve_minutes: row.resolve_minutes,
                business_hours: row.business_hours,
            };
        }
        if row.customer_code.is_none() {
            global = Some(row);
        }
    }
    match global {
        Some(row) => SlaTargets {
            ack_minutes: row.ack_minutes,
            resolve_minutes: row.resolve_minutes,
            business_hours: row.business_hours,
        },
        None => builtin_targets(entity, severity),
    }
}

/// `policy.load_rows(session, codes)`: the global rows plus the overrides of
/// `codes`.
pub async fn load_rows(
    conn: &mut MySqlConnection,
    codes: &[&str],
) -> Result<Vec<PolicyRow>, SlaError> {
    let codes: Vec<&str> = codes.iter().copied().filter(|c| !c.is_empty()).collect();
    let mut sql = String::from(
        "SELECT customer_code, entity_type, severity, ack_minutes, resolve_minutes, \
         business_hours FROM soc_sla_policy WHERE customer_code IS NULL",
    );
    if !codes.is_empty() {
        sql.push_str(" OR customer_code IN (");
        sql.push_str(&vec!["?"; codes.len()].join(", "));
        sql.push(')');
    }
    sql.push_str(" ORDER BY id");
    type Row = (
        Option<String>,
        String,
        String,
        Option<i32>,
        Option<i32>,
        bool,
    );
    let mut query = sqlx::query_as::<_, Row>(&sql);
    for code in &codes {
        query = query.bind(*code);
    }
    let rows = query.fetch_all(&mut *conn).await?;
    rows.into_iter()
        .map(|(customer_code, entity, severity, ack, resolve, bh)| {
            Ok(PolicyRow {
                customer_code,
                entity: SlaEntity::parse(&entity).ok_or_else(|| {
                    SlaError::Policy(format!("'{entity}' is not a valid SlaEntity"))
                })?,
                severity,
                ack_minutes: ack.map(i64::from),
                resolve_minutes: resolve.map(i64::from),
                business_hours: bh,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(code: Option<&str>, sev: &str, ack: i64) -> PolicyRow {
        PolicyRow {
            customer_code: code.map(str::to_string),
            entity: SlaEntity::Alert,
            severity: sev.into(),
            ack_minutes: Some(ack),
            resolve_minutes: None,
            business_hours: false,
        }
    }

    #[test]
    fn customer_then_global_then_builtin() {
        let rows = vec![
            row(None, "High", 10),
            row(Some("acme"), "High", 5),
            row(None, "High", 20),
        ];
        assert_eq!(
            resolve_targets(SlaEntity::Alert, "High", Some("acme"), &rows).ack_minutes,
            Some(5)
        );
        assert_eq!(
            resolve_targets(SlaEntity::Alert, "High", Some("other"), &rows).ack_minutes,
            Some(20)
        );
        assert_eq!(
            resolve_targets(SlaEntity::Alert, "Low", None, &rows),
            builtin_targets(SlaEntity::Alert, "Low")
        );
        assert_eq!(
            builtin_targets(SlaEntity::Case, "Informational"),
            SlaTargets::NONE
        );
        assert_eq!(builtin_targets(SlaEntity::Case, "Bogus"), SlaTargets::NONE);
    }
}
