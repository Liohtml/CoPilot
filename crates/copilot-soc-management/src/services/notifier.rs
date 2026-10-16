//! The SLA notifier — port of `soc_management/services/notifier.py`
//! (`notify_sla_transitions`, every two minutes).
//!
//! Each pass reads every open tracked item, asks `domain::notices` what it
//! owes, and for each notice **claims** it with a guarded
//! `UPDATE … SET <stamp> = now WHERE <stamp> IS NULL` (plus the at-risk stamp
//! a breach settles), commits, and sends only if the claim won. Two
//! overlapping passes can both *see* an unstamped clock; only one can stamp
//! it. A send that fails after its claim is not retried — by design.
//!
//! Notifications go to internal routes only (`sla_at_risk` /
//! `sla_breached`), emitted through `ctx.notifications` exactly as Python's
//! `emit` schedules `dispatch_event`.

use std::collections::HashMap;

use chrono::NaiveDateTime;
use copilot_core::notify::{SlaEventInput, sla_event};
use copilot_core::time::{mysql_datetime, now_utc_micros};
use copilot_sla::calendar::load_all_book;
use copilot_sla::evaluate::SlaState;
use copilot_sla::policy::SlaEntity;
use copilot_web::AppContext;
use sqlx::{MySql, QueryBuilder};

use crate::domain::analytics::ItemFact;
use crate::domain::notices::{Notice, NoticeKind, STAMP_COLUMNS, Stamps, notices_for};
use crate::services::datasets::{self, FactFilters, Visibility};

/// What one pass did (`{"sent", "silenced", "lost_race"}`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PassCounts {
    /// Notifications emitted.
    pub sent: i64,
    /// Stale breaches stamped without a message.
    pub silenced: i64,
    /// Claims another pass won.
    pub lost_race: i64,
}

/// A pass failed (a query): the scheduler records an error, no stamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifierError(pub String);

impl std::fmt::Display for NotifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NotifierError {}

fn err(e: impl std::fmt::Display) -> NotifierError {
    NotifierError(e.to_string())
}

/// Read the stamps of `ids` (one entity), in [`STAMP_COLUMNS`] order.
async fn stamps_of(
    ctx: &AppContext,
    entity: SlaEntity,
    ids: &[i64],
) -> Result<HashMap<i64, Stamps>, NotifierError> {
    let key = entity.key();
    let table = entity.tracking_table();
    let mut qb: QueryBuilder<'_, MySql> = QueryBuilder::new(format!(
        "SELECT {table}.{key}, {} FROM {table} WHERE {table}.{key} IN (",
        STAMP_COLUMNS
            .iter()
            .map(|c| format!("{table}.{c}"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let mut sep = qb.separated(", ");
    for id in ids {
        sep.push_bind(*id);
    }
    qb.push(")");
    type Row = (
        i64,
        Option<NaiveDateTime>,
        Option<NaiveDateTime>,
        Option<NaiveDateTime>,
        Option<NaiveDateTime>,
    );
    let rows: Vec<Row> = qb
        .build_query_as()
        .fetch_all(ctx.db.pool())
        .await
        .map_err(err)?;
    Ok(rows
        .into_iter()
        .map(|(id, a, b, c, d)| (id, [a, b, c, d]))
        .collect())
}

/// `_owed`: every (fact, notice) owed, reading the stamps only of items that
/// might owe one — alerts first, then cases, in load order.
async fn owed<'f, 'a>(
    ctx: &AppContext,
    facts: &'f [ItemFact<'a>],
    now: NaiveDateTime,
) -> Result<Vec<(&'f ItemFact<'a>, Notice)>, NotifierError> {
    let mut out = Vec::new();
    for entity in [SlaEntity::Alert, SlaEntity::Case] {
        let subset: Vec<&ItemFact<'a>> = facts
            .iter()
            .filter(|f| {
                f.entity == entity
                    && f.tracked
                    && matches!(f.live_state(now), SlaState::AtRisk | SlaState::Breached)
            })
            .collect();
        if subset.is_empty() {
            continue;
        }
        let ids: Vec<i64> = subset.iter().map(|f| f.id).collect();
        let stamps = stamps_of(ctx, entity, &ids).await?;
        for fact in subset {
            let none: Stamps = [None; 4];
            let s = stamps.get(&fact.id).unwrap_or(&none);
            for notice in notices_for(fact, s, now) {
                out.push((fact, notice));
            }
        }
    }
    Ok(out)
}

/// `_claim`: stamp the notice (and what it settles) if nobody did; commit;
/// whether this pass won.
async fn claim(
    ctx: &AppContext,
    fact: &ItemFact<'_>,
    notice: &Notice,
    now: NaiveDateTime,
) -> Result<bool, NotifierError> {
    let table = fact.entity.tracking_table();
    let key = fact.entity.key();
    let stored = mysql_datetime(now);
    let mut tx = ctx.db.pool().begin().await.map_err(err)?;
    let column = notice.column();
    let won = sqlx::query(&format!(
        "UPDATE {table} SET {column}=? WHERE {table}.{key} = ? AND {table}.{column} IS NULL"
    ))
    .bind(stored)
    .bind(fact.id)
    .execute(&mut *tx)
    .await
    .map_err(err)?
    .rows_affected()
        == 1;
    if let Some(settled) = notice.settles() {
        sqlx::query(&format!(
            "UPDATE {table} SET {settled}=? WHERE {table}.{key} = ? AND {table}.{settled} IS NULL"
        ))
        .bind(stored)
        .bind(fact.id)
        .execute(&mut *tx)
        .await
        .map_err(err)?;
    }
    tx.commit().await.map_err(err)?;
    Ok(won)
}

fn event(
    ctx: &AppContext,
    fact: &ItemFact<'_>,
    notice: &Notice,
    now: NaiveDateTime,
) -> copilot_core::notify::NotificationEvent {
    sla_event(
        &ctx.notification_defaults,
        &SlaEventInput {
            breached: notice.kind == NoticeKind::Breached,
            entity_type: fact.entity.as_str(),
            entity_id: fact.id,
            title: Some(fact.title.as_str()),
            severity: Some(fact.severity.as_str()),
            customer_code: fact.customer_code.as_deref(),
            assignee: fact.assigned_to.as_deref(),
            clock: notice.clock.label(),
            due_at: notice.due_at,
            opened_at: fact.opened_at,
            now,
            status: Some(fact.status.as_str()),
        },
    )
}

/// `SlaNotifier.run()`: one pass at `now`.
pub async fn run_pass(ctx: &AppContext, now: NaiveDateTime) -> Result<PassCounts, NotifierError> {
    let db = &ctx.db;
    let book = {
        let mut conn = db.pool().acquire().await.map_err(err)?;
        load_all_book(&mut conn).await.map_err(err)?
    };
    let everything = Visibility::everything();
    let alert_rows = datasets::open_alerts(db, &everything, &FactFilters::default())
        .await
        .map_err(err)?;
    let case_rows = datasets::open_cases(db, &everything, &FactFilters::default())
        .await
        .map_err(err)?;
    let facts: Vec<ItemFact<'_>> = alert_rows
        .iter()
        .map(|r| r.to_fact(&book))
        .chain(case_rows.iter().map(|r| r.to_fact(&book)))
        .collect();
    let mut counts = PassCounts::default();
    for (fact, notice) in owed(ctx, &facts, now).await? {
        if !claim(ctx, fact, &notice, now).await? {
            counts.lost_race += 1;
            continue;
        }
        if notice.silent {
            counts.silenced += 1;
            continue;
        }
        ctx.notifications.emit(event(ctx, fact, &notice, now), None);
        counts.sent += 1;
    }
    Ok(counts)
}

/// `notify_sla_transitions()`: one pass now; a failed pass is logged and
/// returned, so the scheduler records an error rather than a success.
pub async fn notify_sla_transitions(ctx: &AppContext) -> Result<PassCounts, NotifierError> {
    match run_pass(ctx, now_utc_micros()).await {
        Ok(counts) => {
            if counts != PassCounts::default() {
                tracing::info!(
                    target: "copilot::sla",
                    "SLA notifier: {} sent, {} stale breach(es) stamped silently",
                    counts.sent,
                    counts.silenced
                );
            }
            Ok(counts)
        }
        Err(e) => {
            tracing::error!(target: "copilot::sla", "SLA notifier pass failed: {e}");
            Err(e)
        }
    }
}
