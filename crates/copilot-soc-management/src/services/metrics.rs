//! Composing the dashboard: load facts once, derive every section from the
//! same snapshot — port of `soc_management/services/metrics.py`.
//!
//! One request, one snapshot: the Overview's breach count, the Workload
//! tab's and the attention list are the same items evaluated at the same
//! `now`. Per-analyst figures are the admin's view: an analyst gets every
//! aggregate but only their own row.

use std::collections::{HashMap, HashSet};

use chrono::NaiveDateTime;
use copilot_core::time::now_utc_micros;
use copilot_sla::calendar::{Clock, load_all_book};
use copilot_sla::evaluate::SlaState;
use copilot_sla::policy::SlaEntity;
use copilot_web::{ApiError, AppContext, CurrentUser};

use crate::domain::analytics::{
    self, AnalystRow, AttentionItem, CustomerRow, Headline, ItemFact, RuleRow, SeverityRow,
    TrendPoint, Workload,
};
use crate::domain::periods::{Bucket, Period, auto_bucket};
use crate::schema::metrics::{
    AnalystRowOut, AttentionItemOut, AttentionResponse, CustomerRowOut, DashboardResponse,
    ItemSlaResponse, PeriodOut, RuleRowOut, SeverityRowOut, SlaClockOut, SourceOption,
    SourcesResponse, TrendPointOut, Viewer,
};
use crate::schema::policy::PolicyMatrix;
use crate::services::datasets::{self, FactFilters, Visibility};
use crate::services::{internal, period_error, policy, sla_error};

/// `DASHBOARD_ATTENTION_LIMIT`.
pub const DASHBOARD_ATTENTION_LIMIT: usize = 10;
/// `MAX_ATTENTION_LIMIT`.
pub const MAX_ATTENTION_LIMIT: i64 = 500;
/// `rules(…, limit=25)`.
const RULES_LIMIT: usize = 25;

/// `DashboardQuery`.
#[derive(Debug, Clone)]
pub struct DashboardQuery {
    /// The period asked for.
    pub period: Period,
    /// Requested customers (`customer_codes_query`).
    pub customer_codes: Option<Vec<String>>,
    /// Severity / source narrowing.
    pub filters: FactFilters,
    /// Trend granularity (`None`: from the period's length).
    pub bucket: Option<Bucket>,
}

/// `Snapshot`: every section, computed once at `now` for one viewer.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// When.
    pub now: NaiveDateTime,
    /// The period.
    pub period: Period,
    /// Its predecessor.
    pub previous: Period,
    /// Trend granularity.
    pub bucket: Bucket,
    /// Who.
    pub viewer: Viewer,
    /// `visibility.case_codes`.
    pub customer_codes: Option<Vec<String>>,
    /// When tracking began.
    pub tracking_since: Option<NaiveDateTime>,
    /// This period.
    pub headline: Headline,
    /// The previous one.
    pub previous_headline: Headline,
    /// Per severity (alerts, then cases).
    pub severities: Vec<SeverityRow>,
    /// Trend.
    pub trends: Vec<TrendPoint>,
    /// Analysts.
    pub analysts: Vec<AnalystRow>,
    /// Rules.
    pub rules: Vec<RuleRow>,
    /// Customers.
    pub customers: Vec<CustomerRow>,
    /// Their names.
    pub customer_names: HashMap<String, String>,
    /// Workload.
    pub workload: Workload,
    /// Attention.
    pub attention: Vec<AttentionItem>,
    /// The policy shown.
    pub policy: PolicyMatrix,
}

/// `_single_customer(requested, visibility)`.
fn single_customer(requested: Option<&[String]>, v: &Visibility) -> Option<String> {
    let codes = v.case_codes.as_deref().or(requested)?;
    (codes.len() == 1).then(|| codes[0].clone())
}

/// `compute_snapshot(session, query, viewer=, visibility=, attention_limit=)`.
pub async fn compute_snapshot(
    ctx: &AppContext,
    query: &DashboardQuery,
    viewer: Viewer,
    v: &Visibility,
    attention_limit: usize,
) -> Result<Snapshot, ApiError> {
    let db = &ctx.db;
    let now = now_utc_micros();
    let period = query.period;
    let previous = period.previous().map_err(period_error)?;
    let loaded = Period {
        start: previous.start,
        end: period.end,
    };
    let bucket = query.bucket.unwrap_or_else(|| auto_bucket(&period));

    let book = {
        let mut conn = db.pool().acquire().await.map_err(internal)?;
        load_all_book(&mut conn).await.map_err(sla_error)?
    };
    let alert_rows = datasets::window_alerts(db, v, &loaded, &query.filters)
        .await
        .map_err(internal)?;
    let case_rows = datasets::window_cases(db, v, &loaded, &query.filters)
        .await
        .map_err(internal)?;
    let open_alert_rows = datasets::open_alerts(db, v, &query.filters)
        .await
        .map_err(internal)?;
    let open_case_rows = datasets::open_cases(db, v, &query.filters)
        .await
        .map_err(internal)?;
    let soc_users: HashSet<String> = datasets::soc_usernames(db).await.map_err(internal)?;

    let alerts: Vec<ItemFact<'_>> = alert_rows.iter().map(|r| r.to_fact(&book)).collect();
    let cases: Vec<ItemFact<'_>> = case_rows.iter().map(|r| r.to_fact(&book)).collect();
    let open_alerts: Vec<ItemFact<'_>> = open_alert_rows.iter().map(|r| r.to_fact(&book)).collect();
    let open_cases: Vec<ItemFact<'_>> = open_case_rows.iter().map(|r| r.to_fact(&book)).collect();

    let mut analyst_rows = analytics::analysts(
        &alerts,
        &cases,
        &open_alerts,
        &open_cases,
        &period,
        now,
        &soc_users,
    );
    let mut workload = analytics::workload(&open_alerts, &open_cases, now);
    if !viewer.sees_all_analysts {
        analyst_rows.retain(|r| r.username == viewer.username);
        workload
            .by_assignee
            .retain(|l| l.username == viewer.username);
    }
    let customer_rows =
        analytics::customers(&alerts, &cases, &open_alerts, &open_cases, &period, now);
    let single = single_customer(query.customer_codes.as_deref(), v);

    let tracking_since = datasets::tracking_since(db).await.map_err(internal)?;
    let headline = analytics::headline(&alerts, &cases, &period, now, &soc_users);
    let previous_headline = analytics::headline(&alerts, &cases, &previous, now, &soc_users);
    let mut severities =
        analytics::severity_rows(SlaEntity::Alert, &alerts, &open_alerts, &period, now);
    severities.extend(analytics::severity_rows(
        SlaEntity::Case,
        &cases,
        &open_cases,
        &period,
        now,
    ));
    let trends = analytics::trends(&alerts, &cases, &period, bucket, now).map_err(period_error)?;
    let rules =
        analytics::rules(&alerts, &period, bucket, now, RULES_LIMIT).map_err(period_error)?;
    let codes: Vec<String> = customer_rows
        .iter()
        .map(|r| r.customer_code.clone())
        .collect();
    let customer_names = datasets::customer_names(db, &codes)
        .await
        .map_err(internal)?;
    let attention =
        analytics::attention_items(open_alerts.iter().chain(&open_cases), now, attention_limit);
    let policy = policy::get_matrix(ctx, single.as_deref()).await?;

    Ok(Snapshot {
        now,
        period,
        previous,
        bucket,
        viewer,
        customer_codes: v.case_codes.clone(),
        tracking_since,
        headline,
        previous_headline,
        severities,
        trends,
        analysts: analyst_rows,
        rules,
        customers: customer_rows,
        customer_names,
        workload,
        attention,
        policy,
    })
}

/// `is_admin(user)`.
pub fn is_admin(user: &CurrentUser) -> bool {
    user.role_id == Some(1)
}

/// `snapshot_for_user(session, user, query)`.
pub async fn snapshot_for_user(
    ctx: &AppContext,
    user: &CurrentUser,
    query: &DashboardQuery,
    attention_limit: usize,
) -> Result<Snapshot, ApiError> {
    let admin = is_admin(user);
    let viewer = Viewer {
        username: user.username.clone(),
        is_admin: admin,
        sees_all_analysts: admin,
    };
    let v = datasets::visibility_for(ctx, user, query.customer_codes.as_deref()).await?;
    compute_snapshot(ctx, query, viewer, &v, attention_limit).await
}

/// `to_response(snapshot)`.
pub fn to_response(s: Snapshot) -> DashboardResponse {
    DashboardResponse {
        success: true,
        message: String::new(),
        generated_at: s.now,
        period: PeriodOut {
            date_from: s.period.start,
            date_to: s.period.end,
            previous_from: s.previous.start,
            previous_to: s.previous.end,
            bucket: s.bucket.as_str(),
        },
        viewer: s.viewer,
        customer_codes: s.customer_codes,
        tracking_since: s.tracking_since,
        headline: (&s.headline).into(),
        previous: (&s.previous_headline).into(),
        severities: s.severities.iter().map(SeverityRowOut::from).collect(),
        trends: s.trends.iter().map(TrendPointOut::from).collect(),
        analysts: s.analysts.iter().map(AnalystRowOut::from).collect(),
        rules: s.rules.iter().map(RuleRowOut::from).collect(),
        customers: s
            .customers
            .iter()
            .map(|r| CustomerRowOut::new(r, s.customer_names.get(&r.customer_code).cloned()))
            .collect(),
        workload: (&s.workload).into(),
        attention: s.attention.iter().map(AttentionItemOut::from).collect(),
        policy: s.policy,
    }
}

/// `build_dashboard`.
pub async fn build_dashboard(
    ctx: &AppContext,
    user: &CurrentUser,
    query: &DashboardQuery,
) -> Result<DashboardResponse, ApiError> {
    Ok(to_response(
        snapshot_for_user(ctx, user, query, DASHBOARD_ATTENTION_LIMIT).await?,
    ))
}

/// `build_attention`: every open item breached or at risk, most urgent first.
pub async fn build_attention(
    ctx: &AppContext,
    user: &CurrentUser,
    customer_codes: Option<&[String]>,
    filters: &FactFilters,
    entity: Option<SlaEntity>,
    state: Option<SlaState>,
    limit: usize,
) -> Result<AttentionResponse, ApiError> {
    let db = &ctx.db;
    let now = now_utc_micros();
    let v = datasets::visibility_for(ctx, user, customer_codes).await?;
    let book = {
        let mut conn = db.pool().acquire().await.map_err(internal)?;
        load_all_book(&mut conn).await.map_err(sla_error)?
    };
    let alert_rows = if entity.is_none_or(|e| e == SlaEntity::Alert) {
        datasets::open_alerts(db, &v, filters)
            .await
            .map_err(internal)?
    } else {
        Vec::new()
    };
    let case_rows = if entity.is_none_or(|e| e == SlaEntity::Case) {
        datasets::open_cases(db, &v, filters)
            .await
            .map_err(internal)?
    } else {
        Vec::new()
    };
    let facts: Vec<ItemFact<'_>> = alert_rows
        .iter()
        .map(|r| r.to_fact(&book))
        .chain(case_rows.iter().map(|r| r.to_fact(&book)))
        .collect();
    let mut items = analytics::attention_items(&facts, now, facts.len());
    if let Some(state) = state {
        items.retain(|i| i.state == state);
    }
    let total = items.len() as i64;
    items.truncate(limit);
    Ok(AttentionResponse {
        success: true,
        message: String::new(),
        items: items.iter().map(AttentionItemOut::from).collect(),
        total,
    })
}

/// `build_sources`.
pub async fn build_sources(
    ctx: &AppContext,
    user: &CurrentUser,
    customer_codes: Option<&[String]>,
) -> Result<SourcesResponse, ApiError> {
    let v = datasets::visibility_for(ctx, user, customer_codes).await?;
    let sources = datasets::alert_sources(&ctx.db, &v)
        .await
        .map_err(internal)?;
    Ok(SourcesResponse {
        success: true,
        message: String::new(),
        sources: sources
            .into_iter()
            .map(|(source, alerts)| SourceOption { source, alerts })
            .collect(),
    })
}

/// Python's `round()` of a float to an int: ties to even.
fn py_round_int(x: f64) -> i64 {
    x.round_ties_even() as i64
}

/// `_target_minutes`: the promised target on the clock's own basis.
fn target_minutes(fact: &ItemFact<'_>, due_at: Option<NaiveDateTime>, credit: i64) -> Option<i64> {
    let due = due_at?;
    Some(py_round_int(
        (fact.clock.elapsed(fact.opened_at, due) - credit as f64) / 60.0,
    ))
}

/// `item_sla`: one item's clocks, or `None` when the caller cannot see it.
pub async fn item_sla(
    ctx: &AppContext,
    user: &CurrentUser,
    entity: SlaEntity,
    item_id: i64,
) -> Result<Option<ItemSlaResponse>, ApiError> {
    let db = &ctx.db;
    let v = datasets::visibility_for(ctx, user, None).await?;
    let book = {
        let mut conn = db.pool().acquire().await.map_err(internal)?;
        load_all_book(&mut conn).await.map_err(sla_error)?
    };
    let (alert_row, case_row) = match entity {
        SlaEntity::Alert => (
            datasets::alert_row(db, &v, item_id)
                .await
                .map_err(internal)?,
            None,
        ),
        SlaEntity::Case => (
            None,
            datasets::case_row(db, &v, item_id)
                .await
                .map_err(internal)?,
        ),
    };
    let fact = alert_row
        .as_ref()
        .map(|r| r.to_fact(&book))
        .or_else(|| case_row.as_ref().map(|r| r.to_fact(&book)));
    let Some(fact) = fact else {
        return Ok(None);
    };
    let tracking = datasets::tracking_extra(db, entity, item_id)
        .await
        .map_err(internal)?;
    let credit = tracking
        .as_ref()
        .and_then(|t| t.pause_credit_seconds)
        .unwrap_or(0);
    let now = now_utc_micros();
    let business_hours = matches!(fact.clock, Clock::Business(_));
    let waited = fact.paused_at.map_or(0, |p| {
        py_round_int(copilot_sla::calendar::total_seconds(p, now))
    });
    Ok(Some(ItemSlaResponse {
        success: true,
        message: String::new(),
        entity: entity.as_str(),
        id: item_id,
        severity: fact.severity.clone(),
        opened_at: fact.opened_at,
        tracked: fact.tracked,
        ack: SlaClockOut {
            due_at: fact.ack_due_at,
            achieved_at: fact.ack_achieved_at(),
            state: fact.ack_state(now).as_str(),
            by: fact.first_ack_by.clone(),
            action: tracking.as_ref().and_then(|t| t.first_ack_action.clone()),
            target_minutes: target_minutes(&fact, fact.ack_due_at, credit),
        },
        resolve: SlaClockOut {
            due_at: fact.resolve_due_at,
            achieved_at: fact.resolved_at,
            state: fact.resolve_state(now).as_str(),
            by: fact.resolved_by.clone(),
            action: None,
            target_minutes: target_minutes(&fact, fact.resolve_due_at, credit),
        },
        first_assigned_at: tracking.as_ref().and_then(|t| t.first_assigned_at),
        reopen_count: fact.reopen_count,
        business_hours,
        calendar_timezone: business_hours.then(|| {
            book.for_customer(fact.customer_code.as_deref())
                .timezone
                .clone()
        }),
        paused_at: fact.paused_at,
        paused_seconds: fact.paused_seconds + waited,
        generated_at: now,
    }))
}
