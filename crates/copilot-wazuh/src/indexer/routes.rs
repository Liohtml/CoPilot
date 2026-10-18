//! The Wazuh indexer routers of `app/routers/wazuh_indexer.py`:
//!
//! | Mount | Routes | Guard |
//! |---|---|---|
//! | `/api/alerts` | `POST ""`, `/by-id`, `/host`, `/index`, `/hosts/all`, `/rules/all`, `/rules/hosts/all`, `/alerts/graylog`, `/alerts/graylog/index` | admin/analyst (`require_any_scope`) |
//! | `/api/wazuh_indexer` | `GET /health`, `/allocation`, `/indices`, `/indices/size-per-customer`, `/shards`, `/output_shard_number_to_be_set_based_on_nodes`, `/resize_wazuh_index_fields` | admin/analyst |
//! | `/api/snapshots` | `GET /repositories`, `/status`, `/repositories/{repository}/snapshots`, `POST /create`, `/restore`, `GET`/`POST /schedules`, `GET`/`PUT`/`DELETE /schedules/{schedule_id}` | `get_current_user(scopes=["admin"])` |
//!
//! The alert routes but the Graylog ones read every tenant's indices in
//! Python; here a scoped caller searches only the indices named after one of
//! their customers (`alerts::scope_indices`, the rule of `/indices`).

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};

use copilot_web::body::JsonBody;
use copilot_web::validate::{IntRules, StrRules, Validator, path_int};
use copilot_web::{
    AdminOnly, AdminOrAnalyst, ApiError, ApiResult, Authorized, QueryPairs, ScopedUser, WithJson,
};

use crate::WazuhState;
use crate::indexer::schema::{
    ALERTS_BY_HOST, ALERTS_BY_RULE, ALERTS_BY_RULE_PER_HOST, ALERTS_SEARCH_RESPONSE,
    AlertByIdSearchBody, AlertsBodyKind, AlertsSearchBody, CreateSnapshotRequest,
    GraylogAlertsSearchBody, HOST_ALERTS_SEARCH_RESPONSE, INDEX_ALERTS_SEARCH_RESPONSE,
    RestoreSnapshotRequest, ScheduleBody,
};
use crate::indexer::services::{alerts, collect_indices, monitoring, snapshots};
use crate::pymodel::Model;

fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

type Analyst = Authorized<AdminOrAnalyst>;
type Admin = ScopedUser<AdminOnly>;

/// `/api/alerts`.
pub fn alerts_router(state: WazuhState) -> Router {
    Router::new()
        .route("/", post(all_alerts))
        .route("/by-id", post(by_id))
        .route("/host", post(host_alerts))
        .route("/index", post(index_alerts))
        .route("/hosts/all", post(by_host))
        .route("/rules/all", post(by_rule))
        .route("/rules/hosts/all", post(by_rule_per_host))
        .route("/alerts/graylog/index", post(graylog_index))
        .route("/alerts/graylog", post(graylog))
        .with_state(state)
}

/// `/api/wazuh_indexer`.
pub fn monitoring_router(state: WazuhState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/allocation", get(allocation))
        .route("/indices", get(indices))
        .route("/indices/size-per-customer", get(size_per_customer))
        .route("/shards", get(shards))
        .route(
            "/output_shard_number_to_be_set_based_on_nodes",
            get(shard_number),
        )
        .route("/resize_wazuh_index_fields", get(resize))
        .with_state(state)
}

/// `/api/snapshots`.
pub fn snapshots_router(state: WazuhState) -> Router {
    Router::new()
        .route("/repositories", get(repositories))
        .route("/status", get(status))
        .route("/repositories/{repository}/snapshots", get(list_snapshots))
        .route("/create", post(create_snapshot))
        .route("/restore", post(restore_snapshot))
        .route("/schedules", post(create_schedule).get(list_schedules))
        .route(
            "/schedules/{schedule_id}",
            get(get_schedule)
                .put(update_schedule)
                .delete(delete_schedule),
        )
        .with_state(state)
}

// ---------------------------------------------------------------------------
// /api/alerts
// ---------------------------------------------------------------------------

/// `validate_timerange` indexes `value[-1]`: an empty string is an
/// `IndexError` that escapes Pydantic — uvicorn's bare 500, whatever else
/// the body holds.
fn timerange_crash(body: &JsonBody) -> Result<(), ApiError> {
    if let JsonBody::Value(Value::Object(m)) = body {
        if m.get("timerange") == Some(&Value::String(String::new())) {
            return Err(ApiError::internal("IndexError: string index out of range"));
        }
    }
    Ok(())
}

/// The caller's customers for the alert routes (`None`: deployment-wide).
/// Not in Python, where these routes read every tenant's indices.
async fn alert_scope(st: &WazuhState, auth: &Analyst) -> Result<Option<Vec<String>>, ApiError> {
    Ok(auth.access(&st.ctx).await?.scoped_customer_codes(None))
}

async fn search(
    st: &WazuhState,
    auth: &Analyst,
    body: &JsonBody,
    kind: AlertsBodyKind,
    model: &'static Model,
) -> ApiResult {
    timerange_crash(body)?;
    let mut b = body.model(AlertsSearchBody::read(kind))?;
    let scope = alert_scope(st, auth).await?;
    let index = b.index_name.clone();
    let result = alerts::get_alerts_generic(
        st,
        &mut b,
        kind == AlertsBodyKind::Host,
        index.as_deref(),
        scope.as_deref(),
    )
    .await?;
    let out = alerts::summary_response(
        model,
        result["alerts_summary"]
            .as_array()
            .cloned()
            .unwrap_or_default(),
        result["success"].as_bool().unwrap_or(false),
        result["message"].as_str().unwrap_or_default().to_string(),
    )?;
    Ok(json(out))
}

async fn all_alerts(
    State(st): State<WazuhState>,
    WithJson(auth, body): WithJson<Analyst>,
) -> ApiResult {
    search(
        &st,
        &auth,
        &body,
        AlertsBodyKind::Plain,
        &ALERTS_SEARCH_RESPONSE,
    )
    .await
}

async fn host_alerts(
    State(st): State<WazuhState>,
    WithJson(auth, body): WithJson<Analyst>,
) -> ApiResult {
    search(
        &st,
        &auth,
        &body,
        AlertsBodyKind::Host,
        &HOST_ALERTS_SEARCH_RESPONSE,
    )
    .await
}

/// `/index`: `verify_index_name` (the name stripped, then looked up among
/// the managed indices) runs before the search, which collects the indices
/// again.
async fn index_alerts(
    State(st): State<WazuhState>,
    WithJson(auth, body): WithJson<Analyst>,
) -> ApiResult {
    timerange_crash(&body)?;
    let mut b = body.model(AlertsSearchBody::read(AlertsBodyKind::Index))?;
    let name = b.index_name.clone().unwrap_or_default().trim().to_string();
    b.index_name = Some(name.clone());
    let managed = collect_indices(&st, false).await?;
    let scope = alert_scope(&st, &auth).await?;
    // Another tenant's index reads as one that is not managed.
    if !managed.contains(&name) || !alerts::index_in_scope(&st, &name, scope.as_deref()).await? {
        return Err(ApiError::bad_request(format!(
            "Index name '{name}' is not managed by Wazuh Indexer or no longer exists."
        )));
    }
    let result = alerts::get_alerts_generic(&st, &mut b, false, Some(&name), None).await?;
    let out = alerts::summary_response(
        &INDEX_ALERTS_SEARCH_RESPONSE,
        result["alerts_summary"]
            .as_array()
            .cloned()
            .unwrap_or_default(),
        result["success"].as_bool().unwrap_or(false),
        result["message"].as_str().unwrap_or_default().to_string(),
    )?;
    Ok(json(out))
}

async fn by_id(State(st): State<WazuhState>, WithJson(auth, body): WithJson<Analyst>) -> ApiResult {
    let b = body.model(AlertByIdSearchBody::read)?;
    let scope = alert_scope(&st, &auth).await?;
    let alert = alerts::alert_by_id(&st, &b.index_name, &b.alert_id, scope.as_deref()).await?;
    // `alert.get("_source", {}).get("message")`: attribute errors on
    // anything but dicts.
    let source = match &alert {
        Value::Object(m) => m.get("_source").cloned().unwrap_or(json!({})),
        other => {
            return Err(ApiError::internal(format!(
                "'{}' object has no attribute 'get'",
                crate::indexer::services::py_type(other)
            )));
        }
    };
    let not_found = match &source {
        Value::Object(m) => m.get("message").and_then(Value::as_str) == Some("alert not found"),
        other => {
            return Err(ApiError::internal(format!(
                "'{}' object has no attribute 'get'",
                crate::indexer::services::py_type(other)
            )));
        }
    };
    Ok(json(json!({
        "alert": alert,
        "success": !not_found,
        "message": if not_found {
            format!("Alert {} not found in index {}", b.alert_id, b.index_name)
        } else {
            "Alert retrieved".into()
        },
    })))
}

async fn counts(
    st: &WazuhState,
    auth: &Analyst,
    body: &JsonBody,
    fields: &[&str],
) -> Result<Vec<(Vec<Value>, i64)>, ApiError> {
    timerange_crash(body)?;
    let mut b = body.model(AlertsSearchBody::read(AlertsBodyKind::Plain))?;
    let scope = alert_scope(st, auth).await?;
    Ok(alerts::collect_and_aggregate(st, fields, &mut b, scope.as_deref()).await?)
}

async fn by_host(
    State(st): State<WazuhState>,
    WithJson(auth, body): WithJson<Analyst>,
) -> ApiResult {
    let rows = counts(&st, &auth, &body, &["agent_name"]).await?;
    let mut out = Vec::new();
    for (values, n) in rows {
        let value = values.into_iter().next().unwrap_or(Value::Null);
        out.push(alerts::count_item(
            &ALERTS_BY_HOST,
            vec![("agent_name", value), ("number_of_alerts", json!(n))],
        )?);
    }
    let success = !out.is_empty();
    Ok(json(json!({
        "alerts_by_host": out,
        "success": success,
        "message": "Successfully collected alerts by host",
    })))
}

async fn by_rule(
    State(st): State<WazuhState>,
    WithJson(auth, body): WithJson<Analyst>,
) -> ApiResult {
    let rows = counts(&st, &auth, &body, &["rule_description"]).await?;
    let mut out = Vec::new();
    for (values, n) in rows {
        let value = values.into_iter().next().unwrap_or(Value::Null);
        out.push(alerts::count_item(
            &ALERTS_BY_RULE,
            vec![("rule", value), ("number_of_alerts", json!(n))],
        )?);
    }
    let success = !out.is_empty();
    Ok(json(json!({
        "alerts_by_rule": out,
        "success": success,
        "message": "Successfully collected alerts by rule",
    })))
}

async fn by_rule_per_host(
    State(st): State<WazuhState>,
    WithJson(auth, body): WithJson<Analyst>,
) -> ApiResult {
    let rows = counts(&st, &auth, &body, &["agent_name", "rule_description"]).await?;
    let mut out = Vec::new();
    for (values, n) in rows {
        let mut it = values.into_iter();
        let agent = it.next().unwrap_or(Value::Null);
        let rule = it.next().unwrap_or(Value::Null);
        out.push(alerts::count_item(
            &ALERTS_BY_RULE_PER_HOST,
            vec![
                ("agent_name", agent),
                ("rule", rule),
                ("number_of_alerts", json!(n)),
            ],
        )?);
    }
    let success = !out.is_empty();
    Ok(json(json!({
        "alerts_by_rule_per_host": out,
        "success": success,
        "message": "Successfully collected alerts by rule per host",
    })))
}

async fn graylog_common(
    st: &WazuhState,
    auth: &Analyst,
    body: &JsonBody,
    with_index: bool,
) -> ApiResult {
    timerange_crash(body)?;
    let b = body.model(GraylogAlertsSearchBody::read(with_index))?;
    let access = auth.access(&st.ctx).await?;
    let scoped = access.scoped_customer_codes(b.customer_codes.as_deref());
    let filter = b.index_name.as_deref().map(str::trim);
    let summary = alerts::graylog_alerts(st, &b, filter, scoped.as_deref()).await?;
    let (success, message) = if with_index {
        let found = !summary.is_empty();
        let message = if found {
            "Alerts retrieved".to_string()
        } else {
            format!(
                "No alerts found for index {}",
                b.index_name.clone().unwrap_or_default()
            )
        };
        (found, message)
    } else {
        (true, "Alerts retrieved".to_string())
    };
    let out = alerts::summary_response(&ALERTS_SEARCH_RESPONSE, summary, success, message)?;
    Ok(json(out))
}

async fn graylog_index(
    State(st): State<WazuhState>,
    WithJson(auth, body): WithJson<Analyst>,
) -> ApiResult {
    graylog_common(&st, &auth, &body, true).await
}

async fn graylog(
    State(st): State<WazuhState>,
    WithJson(auth, body): WithJson<Analyst>,
) -> ApiResult {
    graylog_common(&st, &auth, &body, false).await
}

// ---------------------------------------------------------------------------
// /api/wazuh_indexer
// ---------------------------------------------------------------------------

async fn health(_a: Analyst, State(st): State<WazuhState>) -> ApiResult {
    Ok(json(monitoring::cluster_health(&st).await?))
}

async fn allocation(_a: Analyst, State(st): State<WazuhState>) -> ApiResult {
    Ok(json(monitoring::node_allocation(&st).await?))
}

async fn shards(_a: Analyst, State(st): State<WazuhState>) -> ApiResult {
    Ok(json(monitoring::shards(&st).await?))
}

async fn shard_number(_a: Analyst, State(st): State<WazuhState>) -> ApiResult {
    Ok(json(monitoring::shard_number(&st).await?))
}

async fn resize(_a: Analyst, State(st): State<WazuhState>) -> ApiResult {
    monitoring::resize_fields(&st).await?;
    Ok(json(Value::Null))
}

/// `search_query`: `search` and `limit` (1..=1000).
const SEARCH_LIMIT: IntRules = IntRules {
    ge: Some(1),
    le: Some(1000),
};

async fn indices(auth: Analyst, State(st): State<WazuhState>, q: QueryPairs) -> ApiResult {
    let codes = q.customer_codes();
    let mut v = Validator::new();
    let search = q.opt_str(&mut v, "search", StrRules::any());
    let limit = q.opt_int(&mut v, "limit", SEARCH_LIMIT);
    v.finish()?;
    let access = auth.access(&st.ctx).await?;
    let scoped = access.scoped_customer_codes(codes.as_deref());
    let rows = monitoring::indices_stats(&st, scoped.as_deref()).await?;
    let rows = if rows.is_empty() {
        rows
    } else {
        monitoring::filter_and_limit(rows, search.as_deref(), limit)
    };
    Ok(json(json!({
        "indices_stats": rows,
        "message": "Successfully collected Wazuh Indexer indices stats",
        "success": true,
    })))
}

async fn size_per_customer(
    auth: Analyst,
    State(st): State<WazuhState>,
    q: QueryPairs,
) -> ApiResult {
    let codes = q.customer_codes();
    let scoped = match auth.access(&st.ctx).await {
        Ok(access) => access.scoped_customer_codes(codes.as_deref()),
        Err(e) => {
            return Err(ApiError::server_error(format!(
                "Failed to retrieve indices size per customer: {e}"
            )));
        }
    };
    match monitoring::size_per_customer(&st, scoped.as_deref()).await {
        Ok(v) => Ok(json(v)),
        Err(e) => Err(ApiError::server_error(format!(
            "Failed to retrieve indices size per customer: {e}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// /api/snapshots
// ---------------------------------------------------------------------------

fn answer(response: Value, lookup: bool) -> ApiResult {
    match snapshots::op_error(&response, lookup) {
        Some(e) => Err(e.into()),
        None => Ok(json(response)),
    }
}

async fn repositories(_a: Admin, State(st): State<WazuhState>) -> ApiResult {
    answer(snapshots::list_repositories(&st).await, false)
}

async fn status(_a: Admin, State(st): State<WazuhState>, q: QueryPairs) -> ApiResult {
    let repository = q.get("repository").map(str::to_string);
    let snapshot = q.get("snapshot").map(str::to_string);
    if snapshot.as_deref().is_some_and(|s| !s.is_empty())
        && repository.as_deref().is_none_or(str::is_empty)
    {
        return Err(ApiError::bad_request(
            "Repository must be specified when filtering by snapshot name.",
        ));
    }
    answer(
        snapshots::status(&st, repository.as_deref(), snapshot.as_deref()).await,
        false,
    )
}

async fn list_snapshots(
    _a: Admin,
    State(st): State<WazuhState>,
    Path(repository): Path<String>,
) -> ApiResult {
    answer(snapshots::list_snapshots(&st, &repository).await, false)
}

async fn create_snapshot(
    State(st): State<WazuhState>,
    WithJson(_a, body): WithJson<Admin>,
) -> ApiResult {
    let req = body.model(CreateSnapshotRequest::read)?;
    answer(snapshots::create(&st, &req).await, false)
}

async fn restore_snapshot(
    State(st): State<WazuhState>,
    WithJson(_a, body): WithJson<Admin>,
) -> ApiResult {
    let req = body.model(RestoreSnapshotRequest::read)?;
    answer(snapshots::restore(&st, &req).await, false)
}

async fn create_schedule(
    State(st): State<WazuhState>,
    WithJson(_a, body): WithJson<Admin>,
) -> ApiResult {
    let b = body.model(ScheduleBody::read_create)?;
    answer(snapshots::create_schedule(&st.ctx.db, &b).await, false)
}

async fn list_schedules(_a: Admin, State(st): State<WazuhState>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let mut m = serde_json::Map::new();
    if let Some(raw) = q.get("enabled_only") {
        m.insert("enabled_only".into(), Value::String(raw.into()));
    }
    let enabled_only = v.bool_or(
        &m,
        &vec![copilot_web::validate::LocPart::Key("query".into())],
        "enabled_only",
        false,
    );
    v.finish()?;
    answer(
        snapshots::list_schedules(&st.ctx.db, enabled_only).await,
        false,
    )
}

async fn get_schedule(
    _a: Admin,
    State(st): State<WazuhState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let id = path_int("schedule_id", &raw)?;
    answer(snapshots::get_schedule(&st.ctx.db, id).await, true)
}

async fn update_schedule(
    State(st): State<WazuhState>,
    Path(raw): Path<String>,
    WithJson(_a, body): WithJson<Admin>,
) -> ApiResult {
    let id = path_int("schedule_id", &raw)?;
    let b = body.model(ScheduleBody::read_update)?;
    answer(snapshots::update_schedule(&st.ctx.db, id, &b).await, true)
}

async fn delete_schedule(
    _a: Admin,
    State(st): State<WazuhState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let id = path_int("schedule_id", &raw)?;
    answer(snapshots::delete_schedule(&st.ctx.db, id).await, true)
}
