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

/// `TargetSource`: where a cell's targets came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetSource {
    /// The customer's override.
    Customer,
    /// The global policy.
    Global,
    /// The built-in default.
    Default,
}

impl TargetSource {
    /// Wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Customer => "customer",
            Self::Global => "global",
            Self::Default => "default",
        }
    }
}

/// `SEVERITIES_DESC`: most severe first, the order of every table.
pub const SEVERITIES_DESC: [&str; 5] = ["Critical", "High", "Medium", "Low", "Informational"];

/// `MAX_TARGET_MINUTES`: one year.
pub const MAX_TARGET_MINUTES: i64 = 365 * 24 * 60;

/// `resolve_targets` with its source label: the first customer row of the
/// cell, else the last global one, else the built-in default.
pub fn resolve_with_source(
    entity: SlaEntity,
    severity: &str,
    customer_code: Option<&str>,
    rows: &[PolicyRow],
) -> (SlaTargets, TargetSource) {
    let mut global: Option<&PolicyRow> = None;
    for row in rows {
        if row.entity != entity || row.severity != severity {
            continue;
        }
        if customer_code.is_some() && row.customer_code.as_deref() == customer_code {
            return (
                SlaTargets {
                    ack_minutes: row.ack_minutes,
                    resolve_minutes: row.resolve_minutes,
                    business_hours: row.business_hours,
                },
                TargetSource::Customer,
            );
        }
        if row.customer_code.is_none() {
            global = Some(row);
        }
    }
    match global {
        Some(row) => (
            SlaTargets {
                ack_minutes: row.ack_minutes,
                resolve_minutes: row.resolve_minutes,
                business_hours: row.business_hours,
            },
            TargetSource::Global,
        ),
        None => (builtin_targets(entity, severity), TargetSource::Default),
    }
}

/// `resolve_targets`: the targets that apply to one item.
pub fn resolve_targets(
    entity: SlaEntity,
    severity: &str,
    customer_code: Option<&str>,
    rows: &[PolicyRow],
) -> SlaTargets {
    resolve_with_source(entity, severity, customer_code, rows).0
}

/// One resolved cell of a scope (`PolicyCell`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixCell {
    /// Entity.
    pub entity: SlaEntity,
    /// Severity.
    pub severity: &'static str,
    /// Targets in force.
    pub targets: SlaTargets,
    /// Where they come from.
    pub source: TargetSource,
}

/// `effective_matrix`: every cell of a scope as it would resolve — alerts
/// then cases, most severe first.
pub fn effective_matrix(customer_code: Option<&str>, rows: &[PolicyRow]) -> Vec<MatrixCell> {
    let mut cells = Vec::with_capacity(10);
    for entity in [SlaEntity::Alert, SlaEntity::Case] {
        for severity in SEVERITIES_DESC {
            let (targets, source) = resolve_with_source(entity, severity, customer_code, rows);
            cells.push(MatrixCell {
                entity,
                severity,
                targets,
                source,
            });
        }
    }
    cells
}

/// `validate_minutes`: a whole number of minutes in `(0, MAX_TARGET_MINUTES]`;
/// `Err` is the `ValueError` text.
pub fn validate_minutes(value: i64) -> Result<i64, String> {
    if value <= 0 {
        return Err(
            "Targets must be greater than zero; leave a target empty for no promise".into(),
        );
    }
    if value > MAX_TARGET_MINUTES {
        return Err(format!(
            "Targets cannot exceed {MAX_TARGET_MINUTES} minutes (one year)"
        ));
    }
    Ok(value)
}

type RowTuple = (
    Option<String>,
    String,
    String,
    Option<i32>,
    Option<i32>,
    bool,
);

fn to_rows(rows: Vec<RowTuple>) -> Result<Vec<PolicyRow>, SlaError> {
    rows.into_iter()
        .map(|(customer_code, entity, severity, ack, resolve, bh)| {
            Ok(PolicyRow {
                customer_code,
                entity: SlaEntity::parse(&entity).ok_or_else(|| {
                    SlaError::Policy(format!(
                        "{} is not a valid SlaEntity",
                        copilot_auth::pyvalue::str_repr(&entity)
                    ))
                })?,
                severity,
                ack_minutes: ack.map(i64::from),
                resolve_minutes: resolve.map(i64::from),
                business_hours: bh,
            })
        })
        .collect()
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
    let mut query = sqlx::query_as::<_, RowTuple>(&sql);
    for code in &codes {
        query = query.bind(*code);
    }
    to_rows(query.fetch_all(&mut *conn).await?)
}

/// `policy.load_rows(session)` without a scope: every row, every customer's
/// overrides included (what a deployment-wide re-target reads).
pub async fn load_all_rows(conn: &mut MySqlConnection) -> Result<Vec<PolicyRow>, SlaError> {
    let rows = sqlx::query_as::<_, RowTuple>(
        "SELECT customer_code, entity_type, severity, ack_minutes, resolve_minutes, \
         business_hours FROM soc_sla_policy ORDER BY id",
    )
    .fetch_all(&mut *conn)
    .await?;
    to_rows(rows)
}

/// A cell to store (`PolicyCellIn` that does not inherit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCell {
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

/// `replace_scope`: the scope's stored cells become exactly `cells`, written
/// in order (an inheriting cell is simply not passed). Does not commit.
pub async fn replace_scope(
    conn: &mut MySqlConnection,
    customer_code: Option<&str>,
    cells: &[StoredCell],
    actor: Option<&str>,
    now: NaiveDateTime,
) -> Result<(), SlaError> {
    match customer_code {
        None => {
            sqlx::query("DELETE FROM soc_sla_policy WHERE soc_sla_policy.customer_code IS NULL")
                .execute(&mut *conn)
                .await?;
        }
        Some(code) => {
            sqlx::query("DELETE FROM soc_sla_policy WHERE soc_sla_policy.customer_code = ?")
                .bind(code)
                .execute(&mut *conn)
                .await?;
        }
    }
    for cell in cells {
        sqlx::query(
            "INSERT INTO soc_sla_policy (customer_code, entity_type, severity, ack_minutes, \
             resolve_minutes, business_hours, updated_at, updated_by) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(customer_code)
        .bind(cell.entity.as_str())
        .bind(&cell.severity)
        .bind(cell.ack_minutes)
        .bind(cell.resolve_minutes)
        .bind(cell.business_hours)
        .bind(copilot_core::time::mysql_datetime(now))
        .bind(actor)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// `clear_scope`: remove a customer's overrides; the number removed.
pub async fn clear_scope(conn: &mut MySqlConnection, customer_code: &str) -> Result<u64, SlaError> {
    let done = sqlx::query("DELETE FROM soc_sla_policy WHERE soc_sla_policy.customer_code = ?")
        .bind(customer_code)
        .execute(&mut *conn)
        .await?;
    Ok(done.rows_affected())
}

/// `PolicyOverride`: a customer with at least one overridden cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyOverride {
    /// Customer.
    pub customer_code: String,
    /// How many cells.
    pub cells: i64,
    /// The newest edit (the first row seen with the newest time).
    pub updated_at: Option<NaiveDateTime>,
    /// Who made it.
    pub updated_by: Option<String>,
}

/// `list_overrides(codes)`: customers with an override, by code (`None`:
/// every customer; an empty list: nobody).
pub async fn list_overrides(
    conn: &mut MySqlConnection,
    customer_codes: Option<&[String]>,
) -> Result<Vec<PolicyOverride>, SlaError> {
    let mut sql = String::from(
        "SELECT soc_sla_policy.customer_code, soc_sla_policy.updated_at, \
         soc_sla_policy.updated_by FROM soc_sla_policy \
         WHERE soc_sla_policy.customer_code IS NOT NULL",
    );
    if let Some(codes) = customer_codes {
        if codes.is_empty() {
            return Ok(Vec::new());
        }
        sql.push_str(" AND soc_sla_policy.customer_code IN (");
        sql.push_str(&vec!["?"; codes.len()].join(", "));
        sql.push(')');
    }
    let mut query = sqlx::query_as::<_, (String, Option<NaiveDateTime>, Option<String>)>(&sql);
    for code in customer_codes.unwrap_or_default() {
        query = query.bind(code);
    }
    let rows = query.fetch_all(&mut *conn).await?;
    let mut out: Vec<PolicyOverride> = Vec::new();
    for (code, updated_at, updated_by) in rows {
        match out.iter_mut().find(|o| o.customer_code == code) {
            None => out.push(PolicyOverride {
                customer_code: code,
                cells: 1,
                updated_at,
                updated_by,
            }),
            Some(current) => {
                current.cells += 1;
                if let Some(at) = updated_at {
                    if current.updated_at.is_none_or(|c| at > c) {
                        current.updated_at = Some(at);
                        current.updated_by = updated_by;
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| a.customer_code.cmp(&b.customer_code));
    Ok(out)
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
