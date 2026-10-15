//! Recording what happens to alerts and cases into their SLA tracking rows —
//! port of `soc_management/services/lifecycle.py:SlaLifecycleRecorder`.
//!
//! **Best effort, never failing, in its own transaction.** Each call runs
//! after the caller's change is committed, on a connection and transaction of
//! its own: a failure is logged and rolled back there and never reaches the
//! request. Callers await it (as Python does), so its writes are visible when
//! the response is sent.

use chrono::NaiveDateTime;
use copilot_core::time::{mysql_datetime, now_utc_micros};
use copilot_db::Db;
use sqlx::MySqlConnection;

use crate::SlaError;
use crate::calendar::load_book;
use crate::lifecycle::{
    Actor, GuardedUpdate, LifecycleAction, LifecycleEvent, PauseState, Set, plan_milestones,
    resume_values, resumes, retarget_values,
};
use crate::policy::{SlaEntity, load_rows, resolve_targets};
use crate::severity::{normalize_severity, severity_of, severity_rank};

/// Writes lifecycle milestones, each call in a short transaction of its own.
#[derive(Clone)]
pub struct SlaRecorder {
    db: Db,
    default_severity: &'static str,
}

/// One tracking row, as the recorder reads it.
#[derive(Debug, Clone, sqlx::FromRow)]
struct Tracking {
    severity: String,
    opened_at: NaiveDateTime,
    ack_due_at: Option<NaiveDateTime>,
    resolve_due_at: Option<NaiveDateTime>,
    first_ack_at: Option<NaiveDateTime>,
    resolved_at: Option<NaiveDateTime>,
    business_hours: bool,
    paused_at: Option<NaiveDateTime>,
    paused_seconds: i32,
    pause_credit_seconds: i32,
    tracked: bool,
}

fn db_time(t: Option<NaiveDateTime>) -> Option<NaiveDateTime> {
    t.map(mysql_datetime)
}

impl SlaRecorder {
    /// A recorder over `db`; `default_severity` is `DEFAULT_ALERT_SEVERITY`
    /// resolved (`severity::default_severity`).
    pub fn new(db: Db, default_severity: &'static str) -> Self {
        Self {
            db,
            default_severity,
        }
    }

    fn report(what: &str, result: Result<(), SlaError>) {
        if let Err(e) = result {
            tracing::error!(target: "copilot::sla", "SLA tracking: failed to record {what}: {e}");
        }
    }

    // ── opening ─────────────────────────────────────────────────────────

    /// `alert_opened(alert)`: automation's doing, no acknowledgement.
    pub async fn alert_opened(
        &self,
        alert_id: i64,
        stored_severity: Option<&str>,
        customer_code: &str,
    ) {
        let severity = severity_of(stored_severity, self.default_severity);
        let now = now_utc_micros();
        let result = async {
            let mut tx = self.db.pool().begin().await?;
            open(
                &mut tx,
                SlaEntity::Alert,
                alert_id,
                severity,
                Some(customer_code),
                now,
            )
            .await?;
            tx.commit().await?;
            Ok(())
        }
        .await;
        Self::report(&format!("alert {alert_id} opened"), result);
    }

    /// `case_opened(case)`.
    pub async fn case_opened(&self, case_id: i64) {
        let now = now_utc_micros();
        let result = async {
            let mut tx = self.db.pool().begin().await?;
            let case = case_row(&mut tx, case_id)
                .await?
                .ok_or_else(|| SlaError::Missing(format!("case {case_id} does not exist")))?;
            let severity = self
                .case_effective_severity(&mut tx, case_id, case.severity.as_deref())
                .await?;
            open(
                &mut tx,
                SlaEntity::Case,
                case_id,
                severity,
                case.customer_code.as_deref(),
                now,
            )
            .await?;
            tx.commit().await?;
            Ok(())
        }
        .await;
        Self::report(&format!("case {case_id} opened"), result);
    }

    // ── actions ─────────────────────────────────────────────────────────

    /// `alert_action(alert_id, action, actor, to_status=, assignee=)`.
    pub async fn alert_action(
        &self,
        alert_id: i64,
        action: LifecycleAction,
        actor: &Actor,
        to_status: Option<&str>,
        assignee: Option<&str>,
    ) {
        self.action(
            SlaEntity::Alert,
            alert_id,
            action,
            actor,
            to_status,
            assignee,
        )
        .await;
    }

    /// `alerts_action(alert_ids, …)`: one call per alert.
    pub async fn alerts_action(
        &self,
        alert_ids: &[i64],
        action: LifecycleAction,
        actor: &Actor,
        to_status: Option<&str>,
        assignee: Option<&str>,
    ) {
        for id in alert_ids {
            self.alert_action(*id, action, actor, to_status, assignee)
                .await;
        }
    }

    /// `case_action(case_id, …)`.
    pub async fn case_action(
        &self,
        case_id: i64,
        action: LifecycleAction,
        actor: &Actor,
        to_status: Option<&str>,
        assignee: Option<&str>,
    ) {
        self.action(SlaEntity::Case, case_id, action, actor, to_status, assignee)
            .await;
    }

    async fn action(
        &self,
        entity: SlaEntity,
        id: i64,
        action: LifecycleAction,
        actor: &Actor,
        to_status: Option<&str>,
        assignee: Option<&str>,
    ) {
        let event = LifecycleEvent {
            action,
            actor,
            at: now_utc_micros(),
            to_status,
            assignee,
        };
        let result = async {
            let mut tx = self.db.pool().begin().await?;
            self.apply(&mut tx, entity, id, &event).await?;
            tx.commit().await?;
            Ok(())
        }
        .await;
        Self::report(
            &format!("{} {id} {}", entity.as_str(), action.as_str()),
            result,
        );
    }

    /// `case_severity_changed`: re-target the running clocks, then record
    /// the change as a response.
    pub async fn case_severity_changed(&self, case_id: i64, actor: &Actor) {
        let result = async {
            let mut tx = self.db.pool().begin().await?;
            self.retarget_case(&mut tx, case_id, now_utc_micros())
                .await?;
            let event = LifecycleEvent {
                action: LifecycleAction::SeverityChanged,
                actor,
                at: now_utc_micros(),
                to_status: None,
                assignee: None,
            };
            self.apply(&mut tx, SlaEntity::Case, case_id, &event)
                .await?;
            tx.commit().await?;
            Ok(())
        }
        .await;
        Self::report(&format!("case {case_id} severity changed"), result);
    }

    /// `case_links_changed`: a case without an explicit severity may change
    /// tier.
    pub async fn case_links_changed(&self, case_id: i64) {
        let result = async {
            let mut tx = self.db.pool().begin().await?;
            self.retarget_case(&mut tx, case_id, now_utc_micros())
                .await?;
            tx.commit().await?;
            Ok(())
        }
        .await;
        Self::report(&format!("case {case_id} links changed"), result);
    }

    // ── internals ───────────────────────────────────────────────────────

    /// `case_effective_severity`: the explicit one, else the most severe
    /// linked alert, else the default.
    pub async fn case_effective_severity(
        &self,
        conn: &mut MySqlConnection,
        case_id: i64,
        explicit: Option<&str>,
    ) -> Result<&'static str, SlaError> {
        if let Some(s) = normalize_severity(explicit) {
            return Ok(s);
        }
        let linked: Vec<(Option<String>,)> = sqlx::query_as(
            "SELECT a.severity FROM incident_management_alert a \
             JOIN incident_management_casealertlink l ON l.alert_id = a.id WHERE l.case_id = ?",
        )
        .bind(case_id)
        .fetch_all(&mut *conn)
        .await?;
        let mut best: Option<&'static str> = None;
        for (severity,) in &linked {
            let s = severity_of(severity.as_deref(), self.default_severity);
            if best.is_none_or(|b| severity_rank(Some(s)) > severity_rank(Some(b))) {
                best = Some(s);
            }
        }
        Ok(best.unwrap_or(self.default_severity))
    }

    async fn apply(
        &self,
        conn: &mut MySqlConnection,
        entity: SlaEntity,
        id: i64,
        event: &LifecycleEvent<'_>,
    ) -> Result<(), SlaError> {
        self.ensure_row(conn, entity, id, event.at).await?;
        if resumes(event) {
            resume(conn, entity, id, event.at).await?;
        }
        execute_plan(conn, entity, id, &plan_milestones(event), event.at).await
    }

    /// `_ensure_row`: an untracked row for an item that somehow has none.
    async fn ensure_row(
        &self,
        conn: &mut MySqlConnection,
        entity: SlaEntity,
        id: i64,
        now: NaiveDateTime,
    ) -> Result<(), SlaError> {
        if tracking(conn, entity, id).await?.is_some() {
            return Ok(());
        }
        let (severity, opened_at) = match entity {
            SlaEntity::Alert => {
                let row: Option<(Option<String>, NaiveDateTime)> = sqlx::query_as(
                    "SELECT severity, alert_creation_time FROM incident_management_alert \
                     WHERE id = ?",
                )
                .bind(id)
                .fetch_optional(&mut *conn)
                .await?;
                let (severity, created) =
                    row.ok_or_else(|| SlaError::Missing(format!("alert {id} does not exist")))?;
                (
                    severity_of(severity.as_deref(), self.default_severity),
                    created,
                )
            }
            SlaEntity::Case => {
                let case = case_row(conn, id)
                    .await?
                    .ok_or_else(|| SlaError::Missing(format!("case {id} does not exist")))?;
                let severity = self
                    .case_effective_severity(conn, id, case.severity.as_deref())
                    .await?;
                (severity, case.case_creation_time)
            }
        };
        tracing::warn!(
            target: "copilot::sla",
            "SLA tracking row missing for {} {id}; created untracked",
            entity.as_str()
        );
        sqlx::query(&format!(
            "INSERT INTO {} ({}, severity, opened_at, reopen_count, tracked, updated_at, \
             business_hours, paused_seconds, pause_credit_seconds) \
             VALUES (?, ?, ?, 0, 0, ?, 0, 0, 0)",
            entity.tracking_table(),
            entity.key()
        ))
        .bind(id)
        .bind(severity)
        .bind(mysql_datetime(opened_at))
        .bind(mysql_datetime(now))
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    /// `_retarget_case`.
    async fn retarget_case(
        &self,
        conn: &mut MySqlConnection,
        case_id: i64,
        now: NaiveDateTime,
    ) -> Result<(), SlaError> {
        let Some(case) = case_row(conn, case_id).await? else {
            return Ok(());
        };
        let Some(t) = tracking(conn, SlaEntity::Case, case_id).await? else {
            return Ok(());
        };
        let severity = self
            .case_effective_severity(conn, case_id, case.severity.as_deref())
            .await?;
        if severity == t.severity {
            return Ok(());
        }
        let code = case.customer_code.as_deref();
        let codes: Vec<&str> = code.into_iter().filter(|c| !c.is_empty()).collect();
        let rows = load_rows(conn, &codes).await?;
        let book = load_book(conn, &codes).await?;

        let mut sets: Vec<(&'static str, SetValue)> = vec![
            ("severity", SetValue::Text(Some(severity.to_string()))),
            ("updated_at", SetValue::Time(Some(now))),
        ];
        let ack_running = t.first_ack_at.is_none() && t.resolved_at.is_none();
        let resolve_running = t.resolved_at.is_none();
        if t.tracked && (ack_running || resolve_running) {
            let targets = resolve_targets(SlaEntity::Case, severity, code, &rows);
            let clock = book.clock(code, targets.business_hours);
            let (ack, resolve) = retarget_values(
                t.opened_at,
                &targets,
                ack_running,
                resolve_running,
                clock,
                i64::from(t.pause_credit_seconds),
            )?;
            // Only what differs is written (`changed` in `_retarget_row`).
            if let Some(ack) = ack.filter(|a| *a != t.ack_due_at) {
                sets.push(("ack_due_at", SetValue::Time(ack)));
            }
            if let Some(resolve) = resolve.filter(|r| *r != t.resolve_due_at) {
                sets.push(("resolve_due_at", SetValue::Time(resolve)));
            }
            if targets.business_hours != t.business_hours {
                sets.push(("business_hours", SetValue::Bool(targets.business_hours)));
            }
        }
        update(conn, SlaEntity::Case, case_id, &sets, None).await
    }
}

/// A column value of an `UPDATE`.
enum SetValue {
    Time(Option<NaiveDateTime>),
    Text(Option<String>),
    Bool(bool),
    Int(i64),
    Increment,
}

/// The guard of an `UPDATE` beyond the key.
enum Guard<'a> {
    IsNull(&'a str),
    IsNotNull(&'a str),
    Equals(&'a str, NaiveDateTime),
}

async fn update(
    conn: &mut MySqlConnection,
    entity: SlaEntity,
    id: i64,
    sets: &[(&'static str, SetValue)],
    guard: Option<Guard<'_>>,
) -> Result<(), SlaError> {
    let assignments: Vec<String> = sets
        .iter()
        .map(|(col, v)| match v {
            SetValue::Increment => format!("{col} = {col} + 1"),
            _ => format!("{col} = ?"),
        })
        .collect();
    let mut sql = format!(
        "UPDATE {} SET {} WHERE {} = ?",
        entity.tracking_table(),
        assignments.join(", "),
        entity.key()
    );
    match &guard {
        Some(Guard::IsNull(c)) => sql.push_str(&format!(" AND {c} IS NULL")),
        Some(Guard::IsNotNull(c)) => sql.push_str(&format!(" AND {c} IS NOT NULL")),
        Some(Guard::Equals(c, _)) => sql.push_str(&format!(" AND {c} = ?")),
        None => {}
    }
    let mut query = sqlx::query(&sql);
    for (_, v) in sets {
        query = match v {
            SetValue::Time(t) => query.bind(db_time(*t)),
            SetValue::Text(s) => query.bind(s.clone()),
            SetValue::Bool(b) => query.bind(*b),
            SetValue::Int(n) => query.bind(*n),
            SetValue::Increment => query,
        };
    }
    query = query.bind(id);
    if let Some(Guard::Equals(_, t)) = guard {
        query = query.bind(t);
    }
    query.execute(&mut *conn).await?;
    Ok(())
}

#[derive(sqlx::FromRow)]
struct CaseRow {
    customer_code: Option<String>,
    severity: Option<String>,
    case_creation_time: NaiveDateTime,
}

async fn case_row(conn: &mut MySqlConnection, case_id: i64) -> Result<Option<CaseRow>, SlaError> {
    Ok(sqlx::query_as::<_, CaseRow>(
        "SELECT customer_code, severity, case_creation_time FROM incident_management_case \
         WHERE id = ?",
    )
    .bind(case_id)
    .fetch_optional(&mut *conn)
    .await?)
}

async fn tracking(
    conn: &mut MySqlConnection,
    entity: SlaEntity,
    id: i64,
) -> Result<Option<Tracking>, SlaError> {
    Ok(sqlx::query_as::<_, Tracking>(&format!(
        "SELECT severity, opened_at, ack_due_at, resolve_due_at, first_ack_at, resolved_at, \
         business_hours, paused_at, paused_seconds, pause_credit_seconds, tracked \
         FROM {} WHERE {} = ?",
        entity.tracking_table(),
        entity.key()
    ))
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?)
}

/// `_open`: insert the row and snapshot the targets in force (idempotent).
async fn open(
    conn: &mut MySqlConnection,
    entity: SlaEntity,
    id: i64,
    severity: &str,
    customer_code: Option<&str>,
    now: NaiveDateTime,
) -> Result<(), SlaError> {
    if tracking(conn, entity, id).await?.is_some() {
        return Ok(());
    }
    let codes: Vec<&str> = customer_code
        .into_iter()
        .filter(|c| !c.is_empty())
        .collect();
    let rows = load_rows(conn, &codes).await?;
    let targets = resolve_targets(entity, severity, customer_code, &rows);
    let book = load_book(conn, &codes).await?;
    let clock = book.clock(customer_code, targets.business_hours);
    let ack = targets.ack_due(now, clock)?;
    let resolve = targets.resolve_due(now, clock)?;
    sqlx::query(&format!(
        "INSERT INTO {} ({}, severity, opened_at, ack_due_at, resolve_due_at, reopen_count, \
         tracked, updated_at, business_hours, paused_seconds, pause_credit_seconds) \
         VALUES (?, ?, ?, ?, ?, 0, 1, ?, ?, 0, 0)",
        entity.tracking_table(),
        entity.key()
    ))
    .bind(id)
    .bind(severity)
    .bind(mysql_datetime(now))
    .bind(db_time(ack))
    .bind(db_time(resolve))
    .bind(mysql_datetime(now))
    .bind(targets.business_hours)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// `_resume`: end a pause, guarded on the pause read.
async fn resume(
    conn: &mut MySqlConnection,
    entity: SlaEntity,
    id: i64,
    at: NaiveDateTime,
) -> Result<(), SlaError> {
    let Some(t) = tracking(conn, entity, id).await? else {
        return Ok(());
    };
    let Some(paused_at) = t.paused_at else {
        return Ok(());
    };
    let owner_sql = match entity {
        SlaEntity::Alert => "SELECT customer_code FROM incident_management_alert WHERE id = ?",
        SlaEntity::Case => "SELECT customer_code FROM incident_management_case WHERE id = ?",
    };
    let code: Option<String> = sqlx::query_as::<_, (Option<String>,)>(owner_sql)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?
        .and_then(|(c,)| c);
    let codes: Vec<&str> = code
        .as_deref()
        .into_iter()
        .filter(|c| !c.is_empty())
        .collect();
    let book = load_book(conn, &codes).await?;
    let clock = book.clock(code.as_deref(), t.business_hours);
    let values = resume_values(
        PauseState {
            paused_at,
            ack_due_at: t.ack_due_at,
            ack_running: t.first_ack_at.is_none() && t.resolved_at.is_none(),
            resolve_due_at: t.resolve_due_at,
            resolve_running: t.resolved_at.is_none(),
            paused_seconds: i64::from(t.paused_seconds),
            pause_credit_seconds: i64::from(t.pause_credit_seconds),
        },
        at,
        clock,
    )?;
    let mut sets = vec![
        ("paused_at", SetValue::Time(None)),
        ("paused_seconds", SetValue::Int(values.paused_seconds)),
        (
            "pause_credit_seconds",
            SetValue::Int(values.pause_credit_seconds),
        ),
    ];
    if let Some(ack) = values.ack_due_at {
        sets.push(("ack_due_at", SetValue::Time(Some(ack))));
    }
    if let Some(resolve) = values.resolve_due_at {
        sets.push(("resolve_due_at", SetValue::Time(Some(resolve))));
    }
    sets.push(("updated_at", SetValue::Time(Some(at))));
    update(
        conn,
        entity,
        id,
        &sets,
        Some(Guard::Equals("paused_at", paused_at)),
    )
    .await
}

/// `_execute_plan`: each step one guarded `UPDATE`.
async fn execute_plan(
    conn: &mut MySqlConnection,
    entity: SlaEntity,
    id: i64,
    plan: &[GuardedUpdate],
    now: NaiveDateTime,
) -> Result<(), SlaError> {
    for step in plan {
        let mut sets: Vec<(&'static str, SetValue)> = step
            .values
            .iter()
            .map(|(col, v)| {
                let value = match v {
                    Set::Time(t) => SetValue::Time(*t),
                    Set::Text(s) => SetValue::Text(s.clone()),
                    Set::Increment => SetValue::Increment,
                };
                (*col, value)
            })
            .collect();
        sets.push(("updated_at", SetValue::Time(Some(now))));
        let guard = if step.guard_is_null {
            Guard::IsNull(step.guard_column)
        } else {
            Guard::IsNotNull(step.guard_column)
        };
        update(conn, entity, id, &sets, Some(guard)).await?;
    }
    Ok(())
}
