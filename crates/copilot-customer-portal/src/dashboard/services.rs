//! Port of `app/customer_portal/services/overview.py` and the counters of
//! `routes/dashboard.py`.
//!
//! The Overview is built from light projections in one request: alert
//! visibility (`copilot_db::visibility`, customer scoping and tag RBAC) is
//! read **once** and shared by the alert counts, the recent alerts and the
//! AI findings; each list reads only the columns a row shows plus one query
//! for the assets of the rows returned; agents are counted in SQL. Sections
//! fail independently: a failure is logged and reported on its section only
//! (every statement here is its own transaction, so nothing needs rolling
//! back). The statements are SQLAlchemy's, in Python's order.

use std::collections::HashMap;

use chrono::NaiveDateTime;
use sqlx::{FromRow, MySql, QueryBuilder};

use copilot_auth::AccessScope;
use copilot_db::customer_portal as portal_db;
use copilot_db::visibility::AlertVisibility;
use copilot_db::{Db, DbError};
use copilot_incidents::{cases, lists, store};
use copilot_web::{ApiError, AppContext, CurrentUser};

use super::schema::{
    CustomerPortalOverviewResponse, OverviewAgentsSection, OverviewAiSection, OverviewAlert,
    OverviewAlertsSection, OverviewCase, OverviewCasesSection,
};
use crate::reports::severity_breakdown;

/// `resolve_effective_customers`, read the way Python reads its answer:
/// a `"*"` anywhere in the list (an admin asking for `customer_codes=*`)
/// means no customer filter at all.
pub fn effective_scope(access: &AccessScope, requested: Option<&[String]>) -> AccessScope {
    match access.resolve_effective(requested) {
        AccessScope::Customers(codes) if codes.iter().any(|c| c == "*") => AccessScope::All,
        other => other,
    }
}

/// Append ` WHERE {column} IN (…)` for a concrete scope (nothing for every
/// customer). The caller short-circuits an empty one.
fn push_customer_scope<'a>(qb: &mut QueryBuilder<'a, MySql>, column: &str, scope: &'a AccessScope) {
    if let AccessScope::Customers(codes) = scope {
        qb.push(format!(" WHERE {column} IN ("));
        store::push_list(qb, codes.iter().map(String::as_str));
        qb.push(")");
    }
}

/// `"*" not in customers and not customers`.
fn sees_nothing(scope: &AccessScope) -> bool {
    matches!(scope, AccessScope::Customers(c) if c.is_empty())
}

/// `alert_visibility_filters_for_user` over an effective scope.
pub async fn visibility(
    db: &Db,
    user: &CurrentUser,
    scope: &AccessScope,
) -> Result<Option<AlertVisibility>, DbError> {
    AlertVisibility::for_user(db, user.id, user.role_id, scope, None).await
}

#[derive(Debug, FromRow)]
struct AlertProjection {
    id: i32,
    alert_name: String,
    alert_description: String,
    status: String,
    alert_creation_time: NaiveDateTime,
    source: String,
    customer_code: String,
}

/// `_recent_alerts`: the newest `limit` alerts, then their assets.
async fn recent_alerts(
    db: &Db,
    vis: &AlertVisibility,
    limit: i64,
) -> Result<Vec<OverviewAlert>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT a.id, a.alert_name, a.alert_description, a.status, a.alert_creation_time, \
         a.source, a.customer_code FROM incident_management_alert a WHERE 1=1",
    );
    vis.push_and(&mut qb, "a");
    qb.push(" ORDER BY a.id DESC LIMIT ").push_bind(limit);
    let rows = qb
        .build_query_as::<AlertProjection>()
        .fetch_all(db.pool())
        .await?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let mut assets = QueryBuilder::<MySql>::new(
        "SELECT incident_management_asset.alert_linked, incident_management_asset.asset_name \
         FROM incident_management_asset WHERE incident_management_asset.alert_linked IN (",
    );
    store::push_list(&mut assets, rows.iter().map(|r| r.id));
    assets.push(") ORDER BY incident_management_asset.id");
    let mut names: HashMap<i32, Vec<String>> = HashMap::new();
    for (alert, name) in assets
        .build_query_as::<(Option<i32>, String)>()
        .fetch_all(db.pool())
        .await?
    {
        if let Some(alert) = alert {
            names.entry(alert).or_default().push(name);
        }
    }
    Ok(rows
        .into_iter()
        .map(|r| OverviewAlert {
            asset_names: names.remove(&r.id).unwrap_or_default(),
            id: r.id,
            alert_name: r.alert_name,
            alert_description: Some(r.alert_description),
            status: r.status,
            alert_creation_time: r.alert_creation_time,
            source: r.source,
            customer_code: r.customer_code,
        })
        .collect())
}

/// `_alerts_section`.
async fn alerts_section(
    db: &Db,
    vis: Option<&AlertVisibility>,
    limit: i64,
) -> Result<OverviewAlertsSection, DbError> {
    let Some(vis) = vis else {
        return Ok(OverviewAlertsSection::default());
    };
    let counts = lists::alert_status_counts(db, Some(vis)).await?;
    Ok(OverviewAlertsSection {
        counts: counts.into(),
        recent: recent_alerts(db, vis, limit).await?,
        error: None,
    })
}

#[derive(Debug, FromRow)]
struct CaseProjection {
    id: i32,
    case_name: String,
    case_description: String,
    case_status: String,
    case_creation_time: NaiveDateTime,
    assigned_to: Option<String>,
    customer_code: Option<String>,
    alert_count: i64,
}

/// `_cases_section`: the grouped counts, then the newest cases with their
/// linked-alert count (a correlated subquery).
async fn cases_section(
    db: &Db,
    scope: &AccessScope,
    limit: i64,
) -> Result<OverviewCasesSection, DbError> {
    let counts = cases::status_counts(db, scope).await?;
    if sees_nothing(scope) {
        return Ok(OverviewCasesSection::default());
    }
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT incident_management_case.id, incident_management_case.case_name, \
         incident_management_case.case_description, incident_management_case.case_status, \
         incident_management_case.case_creation_time, incident_management_case.assigned_to, \
         incident_management_case.customer_code, (SELECT count(*) AS count_1 \
         FROM incident_management_casealertlink \
         WHERE incident_management_casealertlink.case_id = incident_management_case.id) \
         AS alert_count FROM incident_management_case",
    );
    push_customer_scope(&mut qb, "incident_management_case.customer_code", scope);
    qb.push(" ORDER BY incident_management_case.id DESC LIMIT ")
        .push_bind(limit);
    let rows = qb
        .build_query_as::<CaseProjection>()
        .fetch_all(db.pool())
        .await?;
    Ok(OverviewCasesSection {
        counts: counts.into(),
        recent: rows
            .into_iter()
            .map(|r| OverviewCase {
                id: r.id,
                case_name: r.case_name,
                case_description: Some(r.case_description),
                case_status: r.case_status,
                case_creation_time: r.case_creation_time,
                assigned_to: r.assigned_to,
                customer_code: r.customer_code,
                alert_count: r.alert_count,
            })
            .collect(),
        error: None,
    })
}

/// `_agents_section`: counted in SQL, never loaded.
async fn agents_section(db: &Db, scope: &AccessScope) -> Result<OverviewAgentsSection, DbError> {
    if sees_nothing(scope) {
        return Ok(OverviewAgentsSection::default());
    }
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT count(agents.id) AS count_1, \
         CAST(coalesce(sum(CASE WHEN (agents.wazuh_agent_status = 'active') THEN 1 ELSE 0 END), 0) \
         AS SIGNED) AS coalesce_1, \
         CAST(coalesce(sum(CASE WHEN (agents.critical_asset IS true) THEN 1 ELSE 0 END), 0) \
         AS SIGNED) AS coalesce_2 FROM agents",
    );
    push_customer_scope(&mut qb, "agents.customer_code", scope);
    let (total, online, critical) = qb
        .build_query_as::<(i64, i64, i64)>()
        .fetch_one(db.pool())
        .await?;
    Ok(OverviewAgentsSection {
        total,
        online,
        offline: total - online,
        critical,
        error: None,
    })
}

/// `_ai_section`: the AI findings within the shared visibility and the
/// customers' AI report switch.
async fn ai_section(
    db: &Db,
    vis: Option<&AlertVisibility>,
    limit: i64,
) -> Result<OverviewAiSection, DbError> {
    let Some(vis) = vis else {
        return Ok(OverviewAiSection::default());
    };
    let (counts, recent) = portal_db::ai_insights(db, vis, limit).await?;
    let (total_reports, severity_counts) = severity_breakdown(counts);
    Ok(OverviewAiSection {
        total_reports,
        severity_counts,
        recent: recent.into_iter().map(Into::into).collect(),
        error: None,
    })
}

/// `_isolated`: a failing section is logged and reported, never fatal.
fn isolated<T>(name: &str, result: Result<T, DbError>, on_error: impl FnOnce(String) -> T) -> T {
    result.unwrap_or_else(|e| {
        tracing::error!(error = %e, "Customer portal overview: failed to load {name}");
        on_error(format!("Failed to load {name}"))
    })
}

/// `get_portal_overview`.
pub async fn overview(
    ctx: &AppContext,
    user: &CurrentUser,
    customer_codes: Option<&[String]>,
    recent_limit: i64,
    ai_limit: i64,
) -> Result<CustomerPortalOverviewResponse, ApiError> {
    let db = &ctx.db;
    // Python reads the caller's customers inside every section: when that
    // read fails, each section reports its own failure.
    let access = match user.access(ctx).await {
        Ok(access) => access,
        Err(e) => {
            tracing::error!(error = %e, "Customer portal overview: failed to resolve alert visibility");
            let failed = |name: &str| Some(format!("Failed to load {name}"));
            return Ok(CustomerPortalOverviewResponse {
                alerts: OverviewAlertsSection {
                    error: failed("alerts"),
                    ..OverviewAlertsSection::default()
                },
                cases: OverviewCasesSection {
                    error: failed("cases"),
                    ..OverviewCasesSection::default()
                },
                agents: OverviewAgentsSection {
                    error: failed("agents"),
                    ..OverviewAgentsSection::default()
                },
                ai: OverviewAiSection {
                    error: failed("alerts"),
                    ..OverviewAiSection::default()
                },
                success: true,
                message: "Overview retrieved successfully".into(),
            });
        }
    };
    let scope = effective_scope(access, customer_codes);
    // Built once and shared by the alert counts, recent alerts and AI
    // findings; if it fails, those sections report it.
    let visibility = match visibility(db, user, &scope).await {
        Ok(v) => Ok(v),
        Err(e) => {
            tracing::error!(error = %e, "Customer portal overview: failed to resolve alert visibility");
            Err("Failed to load alerts".to_string())
        }
    };
    let alerts = match &visibility {
        Err(error) => OverviewAlertsSection {
            error: Some(error.clone()),
            ..OverviewAlertsSection::default()
        },
        Ok(vis) => isolated(
            "alerts",
            alerts_section(db, vis.as_ref(), recent_limit).await,
            |error| OverviewAlertsSection {
                error: Some(error),
                ..OverviewAlertsSection::default()
            },
        ),
    };
    let cases = isolated(
        "cases",
        cases_section(db, &scope, recent_limit).await,
        |error| OverviewCasesSection {
            error: Some(error),
            ..OverviewCasesSection::default()
        },
    );
    let agents = isolated("agents", agents_section(db, &scope).await, |error| {
        OverviewAgentsSection {
            error: Some(error),
            ..OverviewAgentsSection::default()
        }
    });
    let ai = match &visibility {
        Err(error) => OverviewAiSection {
            error: Some(error.clone()),
            ..OverviewAiSection::default()
        },
        Ok(vis) => isolated(
            "AI findings",
            ai_section(db, vis.as_ref(), ai_limit).await,
            |error| OverviewAiSection {
                error: Some(error),
                ..OverviewAiSection::default()
            },
        ),
    };
    Ok(CustomerPortalOverviewResponse {
        alerts,
        cases,
        agents,
        ai,
        success: true,
        message: "Overview retrieved successfully".into(),
    })
}

/// `alert_total_for_user`: `count(Alert.id)` within the visibility.
pub async fn alert_total(db: &Db, vis: Option<&AlertVisibility>) -> Result<i64, DbError> {
    let Some(vis) = vis else {
        return Ok(0);
    };
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT count(a.id) AS count_1 FROM incident_management_alert a WHERE 1=1",
    );
    vis.push_and(&mut qb, "a");
    store::count(&mut qb, db).await
}

/// `case_total_for_user`.
pub async fn case_total(db: &Db, scope: &AccessScope) -> Result<i64, DbError> {
    if sees_nothing(scope) {
        return Ok(0);
    }
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT count(incident_management_case.id) AS count_1 FROM incident_management_case",
    );
    push_customer_scope(&mut qb, "incident_management_case.customer_code", scope);
    store::count(&mut qb, db).await
}

/// The agents of `/dashboard/stats`: `count(Agents.id)`, scoped.
pub async fn agent_total(db: &Db, scope: &AccessScope) -> Result<i64, DbError> {
    if sees_nothing(scope) {
        return Ok(0);
    }
    let mut qb = QueryBuilder::<MySql>::new("SELECT count(agents.id) AS count_1 FROM agents");
    push_customer_scope(&mut qb, "agents.customer_code", scope);
    store::count(&mut qb, db).await
}
