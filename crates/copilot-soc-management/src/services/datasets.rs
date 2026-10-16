//! Loading facts: alerts and cases joined to their SLA tracking, within what
//! the caller may see — port of `soc_management/services/datasets.py`.
//!
//! Visibility goes through the one definition every alert read uses
//! (`copilot_db::visibility::AlertVisibility`: customer scoping *and* tag
//! RBAC); cases follow `resolve_effective_customers`. The statements keep the
//! shape SQLAlchemy emits (same columns, same filters in the same order, no
//! `ORDER BY` where Python has none), so MySQL returns rows in the same
//! order — which decides a `Counter`'s tie (a customer's top rule).

use std::collections::{HashMap, HashSet};

use chrono::NaiveDateTime;
use copilot_auth::AccessScope;
use copilot_db::Db;
use copilot_db::visibility::AlertVisibility;
use copilot_sla::calendar::CalendarBook;
use copilot_sla::lifecycle::CLOSED;
use copilot_sla::policy::SlaEntity;
use copilot_web::{ApiError, AppContext, CurrentUser};
use sqlx::{MySql, QueryBuilder};

use crate::domain::analytics::ItemFact;
use crate::domain::periods::Period;

/// `FactFilters`: optional narrowing on top of visibility.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FactFilters {
    /// Severities (tracking severity).
    pub severities: Vec<String>,
    /// Alert sources; cases are not narrowed by source.
    pub sources: Vec<String>,
}

/// `Visibility`: what one caller may see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Visibility {
    /// `None`: no alert at all.
    pub alerts: Option<AlertVisibility>,
    /// An extra `customer_code IN (…)` on alerts (the portal's narrowing).
    pub alert_codes: Option<Vec<String>>,
    /// `None`: every case; empty: no case.
    pub case_codes: Option<Vec<String>>,
}

impl Visibility {
    /// Every alert and every case (the notifier runs for the deployment).
    pub fn everything() -> Self {
        Self {
            alerts: Some(AlertVisibility {
                customers: None,
                tags: copilot_auth::tags::TagScope::All,
            }),
            alert_codes: None,
            case_codes: None,
        }
    }

    /// `sees_alerts`.
    pub fn sees_alerts(&self) -> bool {
        self.alerts.is_some()
    }

    /// `sees_cases`.
    pub fn sees_cases(&self) -> bool {
        self.case_codes.as_ref().is_none_or(|c| !c.is_empty())
    }
}

/// `requested or None`, and Python's `"*"`: an admin naming `*` asks for
/// everything (`resolve_effective_customers` returns it as given, and the
/// callers read `"*" in …` as no filter).
fn requested_codes<'r>(
    access: &AccessScope,
    requested: Option<&'r [String]>,
) -> Option<&'r [String]> {
    let requested = requested.filter(|r| !r.is_empty())?;
    if access.is_all() && requested.iter().any(|c| c == "*") {
        return None;
    }
    Some(requested)
}

/// `visibility_for(user, session, requested_codes)`.
pub async fn visibility_for(
    ctx: &AppContext,
    user: &CurrentUser,
    requested: Option<&[String]>,
) -> Result<Visibility, ApiError> {
    let access = user.access(ctx).await?;
    let requested = requested_codes(access, requested);
    let alerts =
        AlertVisibility::for_user(&ctx.db, user.id, user.role_id, access, requested).await?;
    let case_codes = match access.resolve_effective(requested) {
        AccessScope::All => None,
        AccessScope::Customers(codes) if codes.iter().any(|c| c == "*") => None,
        AccessScope::Customers(codes) => Some(codes),
    };
    Ok(Visibility {
        alerts,
        alert_codes: None,
        case_codes,
    })
}

// ── rows ────────────────────────────────────────────────────────────────

const TRACKING: &str = "severity, opened_at, tracked, ack_due_at, resolve_due_at, first_ack_at, \
                        first_ack_by, resolved_at, resolved_by, reopen_count, paused_at, \
                        paused_seconds, business_hours";

fn tracking_columns(table: &str) -> String {
    TRACKING
        .split(", ")
        .map(|c| format!("{table}.{}", c.trim()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// One alert joined to its tracking row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AlertRow {
    id: i64,
    alert_name: Option<String>,
    customer_code: Option<String>,
    status: Option<String>,
    assigned_to: Option<String>,
    source: Option<String>,
    verdict: Option<String>,
    escalated: Option<bool>,
    #[sqlx(flatten)]
    tracking: TrackingCols,
    #[sqlx(default)]
    in_case: Option<i64>,
}

/// One case joined to its tracking row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CaseRow {
    id: i64,
    case_name: Option<String>,
    customer_code: Option<String>,
    case_status: Option<String>,
    assigned_to: Option<String>,
    escalated: Option<bool>,
    #[sqlx(flatten)]
    tracking: TrackingCols,
}

/// The tracking columns both share.
#[derive(Debug, Clone, sqlx::FromRow)]
struct TrackingCols {
    severity: String,
    opened_at: NaiveDateTime,
    tracked: bool,
    ack_due_at: Option<NaiveDateTime>,
    resolve_due_at: Option<NaiveDateTime>,
    first_ack_at: Option<NaiveDateTime>,
    first_ack_by: Option<String>,
    resolved_at: Option<NaiveDateTime>,
    resolved_by: Option<String>,
    reopen_count: Option<i64>,
    paused_at: Option<NaiveDateTime>,
    paused_seconds: Option<i64>,
    business_hours: bool,
}

fn fact<'b>(
    entity: SlaEntity,
    id: i64,
    customer_code: Option<String>,
    t: &TrackingCols,
    book: &'b CalendarBook,
) -> ItemFact<'b> {
    let clock = book.clock(customer_code.as_deref(), t.business_hours);
    ItemFact {
        entity,
        id,
        title: String::new(),
        customer_code,
        severity: t.severity.clone(),
        status: String::new(),
        assigned_to: None,
        opened_at: t.opened_at,
        tracked: t.tracked,
        ack_due_at: t.ack_due_at,
        resolve_due_at: t.resolve_due_at,
        first_ack_at: t.first_ack_at,
        first_ack_by: t.first_ack_by.clone(),
        resolved_at: t.resolved_at,
        resolved_by: t.resolved_by.clone(),
        reopen_count: t.reopen_count.unwrap_or(0),
        paused_at: t.paused_at,
        paused_seconds: t.paused_seconds.unwrap_or(0),
        clock,
        source: None,
        verdict: None,
        in_case: false,
        escalated: false,
    }
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.is_empty())
}

impl AlertRow {
    /// `_alert_fact`.
    pub fn to_fact<'b>(&self, book: &'b CalendarBook) -> ItemFact<'b> {
        let mut f = fact(
            SlaEntity::Alert,
            self.id,
            self.customer_code.clone(),
            &self.tracking,
            book,
        );
        f.title = self.alert_name.clone().unwrap_or_default();
        f.status = self.status.clone().unwrap_or_default();
        f.assigned_to = non_empty(self.assigned_to.clone());
        f.source = self.source.clone();
        f.verdict = self.verdict.clone();
        f.escalated = self.escalated.unwrap_or(false);
        f.in_case = self.in_case.unwrap_or(0) != 0;
        f
    }
}

impl CaseRow {
    /// `_case_fact`.
    pub fn to_fact<'b>(&self, book: &'b CalendarBook) -> ItemFact<'b> {
        let mut f = fact(
            SlaEntity::Case,
            self.id,
            self.customer_code.clone(),
            &self.tracking,
            book,
        );
        f.title = self.case_name.clone().unwrap_or_default();
        f.status = self.case_status.clone().unwrap_or_default();
        f.assigned_to = non_empty(self.assigned_to.clone());
        f.escalated = self.escalated.unwrap_or(false);
        f
    }
}

/// A list of binds rendered `IN (?, ?, …)`.
fn push_in(qb: &mut QueryBuilder<'_, MySql>, column: &str, values: &[String]) {
    qb.push(format!(" AND {column} IN ("));
    let mut sep = qb.separated(", ");
    for v in values {
        sep.push_bind(v.clone());
    }
    qb.push(")");
}

fn alert_select(include_case_link: bool) -> QueryBuilder<'static, MySql> {
    let a = "incident_management_alert";
    let mut sql = format!(
        "SELECT {a}.id, {a}.alert_name, {a}.customer_code, {a}.status, {a}.assigned_to, \
         {a}.source, {a}.verdict, {a}.escalated, {}",
        tracking_columns("soc_sla_alert_tracking")
    );
    if include_case_link {
        sql.push_str(&format!(
            ", EXISTS (SELECT incident_management_casealertlink.alert_id FROM \
             incident_management_casealertlink WHERE incident_management_casealertlink.alert_id \
             = {a}.id) AS in_case"
        ));
    }
    sql.push_str(&format!(
        " FROM {a} INNER JOIN soc_sla_alert_tracking ON soc_sla_alert_tracking.alert_id = {a}.id \
         WHERE 1 = 1"
    ));
    QueryBuilder::new(sql)
}

fn case_select() -> QueryBuilder<'static, MySql> {
    let c = "incident_management_case";
    QueryBuilder::new(format!(
        "SELECT {c}.id, {c}.case_name, {c}.customer_code, {c}.case_status, {c}.assigned_to, \
         {c}.escalated, {} FROM {c} INNER JOIN soc_sla_case_tracking ON \
         soc_sla_case_tracking.case_id = {c}.id WHERE 1 = 1",
        tracking_columns("soc_sla_case_tracking")
    ))
}

fn push_alert_visibility(qb: &mut QueryBuilder<'_, MySql>, vis: &AlertVisibility, v: &Visibility) {
    vis.push_and(qb, "incident_management_alert");
    if let Some(codes) = &v.alert_codes {
        push_in(qb, "incident_management_alert.customer_code", codes);
    }
}

fn push_alert_narrowing(qb: &mut QueryBuilder<'_, MySql>, filters: &FactFilters) {
    if !filters.severities.is_empty() {
        push_in(qb, "soc_sla_alert_tracking.severity", &filters.severities);
    }
    if !filters.sources.is_empty() {
        push_in(qb, "incident_management_alert.source", &filters.sources);
    }
}

fn push_case_narrowing(qb: &mut QueryBuilder<'_, MySql>, v: &Visibility, filters: &FactFilters) {
    if let Some(codes) = &v.case_codes {
        push_in(qb, "incident_management_case.customer_code", codes);
    }
    if !filters.severities.is_empty() {
        push_in(qb, "soc_sla_case_tracking.severity", &filters.severities);
    }
}

fn push_window(qb: &mut QueryBuilder<'_, MySql>, table: &str, period: &Period) {
    qb.push(format!(" AND ({table}.opened_at >= "));
    qb.push_bind(period.start);
    qb.push(format!(" AND {table}.opened_at < "));
    qb.push_bind(period.end);
    qb.push(format!(" OR {table}.resolved_at >= "));
    qb.push_bind(period.start);
    qb.push(format!(" AND {table}.resolved_at < "));
    qb.push_bind(period.end);
    qb.push(")");
}

/// `window_alerts`: alerts opened or resolved in `period`.
pub async fn window_alerts(
    db: &Db,
    v: &Visibility,
    period: &Period,
    filters: &FactFilters,
) -> Result<Vec<AlertRow>, sqlx::Error> {
    let Some(vis) = &v.alerts else {
        return Ok(Vec::new());
    };
    let mut qb = alert_select(true);
    push_alert_visibility(&mut qb, vis, v);
    push_alert_narrowing(&mut qb, filters);
    push_window(&mut qb, "soc_sla_alert_tracking", period);
    qb.build_query_as::<AlertRow>().fetch_all(db.pool()).await
}

/// `open_alerts`: every alert not closed right now — the backlog.
pub async fn open_alerts(
    db: &Db,
    v: &Visibility,
    filters: &FactFilters,
) -> Result<Vec<AlertRow>, sqlx::Error> {
    let Some(vis) = &v.alerts else {
        return Ok(Vec::new());
    };
    let mut qb = alert_select(false);
    push_alert_visibility(&mut qb, vis, v);
    push_alert_narrowing(&mut qb, filters);
    qb.push(" AND incident_management_alert.status != ");
    qb.push_bind(CLOSED);
    qb.build_query_as::<AlertRow>().fetch_all(db.pool()).await
}

/// `window_cases`.
pub async fn window_cases(
    db: &Db,
    v: &Visibility,
    period: &Period,
    filters: &FactFilters,
) -> Result<Vec<CaseRow>, sqlx::Error> {
    if !v.sees_cases() {
        return Ok(Vec::new());
    }
    let mut qb = case_select();
    push_case_narrowing(&mut qb, v, filters);
    push_window(&mut qb, "soc_sla_case_tracking", period);
    qb.build_query_as::<CaseRow>().fetch_all(db.pool()).await
}

/// `open_cases`.
pub async fn open_cases(
    db: &Db,
    v: &Visibility,
    filters: &FactFilters,
) -> Result<Vec<CaseRow>, sqlx::Error> {
    if !v.sees_cases() {
        return Ok(Vec::new());
    }
    let mut qb = case_select();
    push_case_narrowing(&mut qb, v, filters);
    qb.push(" AND incident_management_case.case_status != ");
    qb.push_bind(CLOSED);
    qb.build_query_as::<CaseRow>().fetch_all(db.pool()).await
}

/// `alert_fact`: one alert, if the caller may see it.
pub async fn alert_row(
    db: &Db,
    v: &Visibility,
    alert_id: i64,
) -> Result<Option<AlertRow>, sqlx::Error> {
    let Some(vis) = &v.alerts else {
        return Ok(None);
    };
    let mut qb = alert_select(true);
    push_alert_visibility(&mut qb, vis, v);
    qb.push(" AND incident_management_alert.id = ");
    qb.push_bind(alert_id);
    qb.build_query_as::<AlertRow>()
        .fetch_optional(db.pool())
        .await
}

/// `case_fact`: one case, if the caller may see it.
pub async fn case_row(
    db: &Db,
    v: &Visibility,
    case_id: i64,
) -> Result<Option<CaseRow>, sqlx::Error> {
    if !v.sees_cases() {
        return Ok(None);
    }
    let mut qb = case_select();
    push_case_narrowing(&mut qb, v, &FactFilters::default());
    qb.push(" AND incident_management_case.id = ");
    qb.push_bind(case_id);
    qb.build_query_as::<CaseRow>()
        .fetch_optional(db.pool())
        .await
}

/// `alert_sources`: the sources of the alerts the caller may see, busiest
/// first (ties in MySQL's collation order, as Python's `ORDER BY` leaves
/// them).
pub async fn alert_sources(db: &Db, v: &Visibility) -> Result<Vec<(String, i64)>, sqlx::Error> {
    let Some(vis) = &v.alerts else {
        return Ok(Vec::new());
    };
    let a = "incident_management_alert";
    let mut qb: QueryBuilder<'_, MySql> = QueryBuilder::new(format!(
        "SELECT {a}.source, count({a}.id) AS count_1 FROM {a} WHERE 1 = 1"
    ));
    push_alert_visibility(&mut qb, vis, v);
    qb.push(format!(" AND {a}.source IS NOT NULL AND {a}.source != "));
    qb.push_bind("");
    qb.push(format!(
        " GROUP BY {a}.source ORDER BY count({a}.id) DESC, {a}.source"
    ));
    qb.build_query_as::<(String, i64)>()
        .fetch_all(db.pool())
        .await
}

/// `tracking_since`: the earliest opening observed rather than backfilled.
pub async fn tracking_since(db: &Db) -> Result<Option<NaiveDateTime>, sqlx::Error> {
    let mut earliest = Vec::new();
    for table in ["soc_sla_alert_tracking", "soc_sla_case_tracking"] {
        let value: Option<NaiveDateTime> = sqlx::query_scalar(&format!(
            "SELECT min({table}.opened_at) AS min_1 FROM {table} WHERE {table}.tracked IS true"
        ))
        .fetch_one(db.pool())
        .await?;
        earliest.extend(value);
    }
    Ok(earliest.into_iter().min())
}

/// `soc_usernames`: admins, analysts and responders.
pub async fn soc_usernames(db: &Db) -> Result<HashSet<String>, sqlx::Error> {
    let names: Vec<String> =
        sqlx::query_scalar("SELECT `user`.username FROM `user` WHERE `user`.role_id IN (1, 2, 5)")
            .fetch_all(db.pool())
            .await?;
    Ok(names.into_iter().collect())
}

/// `customer_names(codes)`.
pub async fn customer_names(
    db: &Db,
    codes: &[String],
) -> Result<HashMap<String, String>, sqlx::Error> {
    if codes.is_empty() {
        return Ok(HashMap::new());
    }
    let mut qb: QueryBuilder<'_, MySql> = QueryBuilder::new(
        "SELECT customers.customer_code, customers.customer_name FROM customers WHERE 1 = 1",
    );
    push_in(&mut qb, "customers.customer_code", codes);
    let rows = qb
        .build_query_as::<(String, String)>()
        .fetch_all(db.pool())
        .await?;
    Ok(rows.into_iter().collect())
}

/// What `item_sla` reads of a tracking row beyond the fact.
#[derive(Debug, Clone, Default, sqlx::FromRow)]
pub struct TrackingExtra {
    /// `first_ack_action`.
    pub first_ack_action: Option<String>,
    /// `first_assigned_at`.
    pub first_assigned_at: Option<NaiveDateTime>,
    /// `pause_credit_seconds`.
    pub pause_credit_seconds: Option<i64>,
}

/// `session.get(AlertSlaTracking | CaseSlaTracking, id)`.
pub async fn tracking_extra(
    db: &Db,
    entity: SlaEntity,
    id: i64,
) -> Result<Option<TrackingExtra>, sqlx::Error> {
    sqlx::query_as::<_, TrackingExtra>(&format!(
        "SELECT first_ack_action, first_assigned_at, pause_credit_seconds FROM {} WHERE {} = ?",
        entity.tracking_table(),
        entity.key()
    ))
    .bind(id)
    .fetch_optional(db.pool())
    .await
}
