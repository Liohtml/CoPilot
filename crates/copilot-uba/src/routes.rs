//! `/api/uba` — port of `routes/uba.py`.
//!
//! Every route but `/availability` names its tenant in the path and carries
//! `verify_customer_code_access`. Reads are admin/analyst (`_READ`);
//! identity merges, identity-source test/sync, rule settings, the risk
//! policy and native-rule scores are admin only (`_ADMIN`). The caller's
//! username goes to UBA as `X-UBA-Actor` on writes.
//!
//! Upstream failures answer `{"detail", "reason", "success": false}` with
//! 502 (or 404 / 409 / 422) — a plain `JSONResponse`, so no `log_entries`
//! row — never 401/403. Check order is FastAPI's: a malformed JSON body
//! first, then the token, the customer, and the path, query and body
//! validation together (one 422).

use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::json::pydantic_json;
use copilot_web::body::JsonBody;
use copilot_web::validate::{Loc, Validator, body_loc};
use copilot_web::{AdminOnly, AdminOrAnalyst, ApiResult, Authorized, QueryPairs, WithJson};
use http::{Method, StatusCode};
use serde_json::{Map, Value};

use crate::UbaState;
use crate::client::{Call, UbaError, UbaResult, path_segment};
use crate::params::{
    NumSpec, StrSpec, path_int, q_bool_or, q_float_or, q_int_or, q_opt_str, q_req_str, q_str_or,
};
use crate::schema;
use crate::services::{int, opt, p, s, tenant};

type Reader = Authorized<AdminOrAnalyst>;
type Admin = Authorized<AdminOnly>;

/// The router, nested at `/api/uba`.
pub fn router(state: UbaState) -> Router {
    Router::new()
        .route("/availability", get(availability))
        .route("/{customer_code}/status", get(status))
        .route("/{customer_code}/entities", get(entities))
        .route("/{customer_code}/entity", get(entity))
        .route("/{customer_code}/entity/risk-history", get(risk_history))
        .route("/{customer_code}/entity/timeline", get(timeline))
        .route("/{customer_code}/signals", get(signals))
        .route("/{customer_code}/alerts", get(alerts))
        .route("/{customer_code}/alerts/{alert_id}", get(alert))
        .route(
            "/{customer_code}/suppressions",
            get(list_suppressions)
                .post(add_suppressions)
                .delete(remove_suppressions),
        )
        .route(
            "/{customer_code}/signals/{signal_id}/evidence",
            get(evidence),
        )
        .route("/{customer_code}/identities/review", get(identity_review))
        .route("/{customer_code}/identities", get(search_identities))
        .route("/{customer_code}/identities/merge", post(merge_identity))
        .route(
            "/{customer_code}/identities/reviewed",
            post(identity_reviewed),
        )
        .route(
            "/{customer_code}/identity-candidates/{candidate_id}/dismiss",
            post(dismiss_candidate),
        )
        .route("/{customer_code}/identity-sources", get(identity_sources))
        .route(
            "/{customer_code}/identity-sources/{source_id}/test",
            post(test_source),
        )
        .route(
            "/{customer_code}/identity-sources/{source_id}/sync",
            post(sync_source),
        )
        .route("/{customer_code}/about", get(about))
        .route("/{customer_code}/rules/catalog", get(rule_catalog))
        .route(
            "/{customer_code}/backtests",
            get(list_backtests).post(create_backtest),
        )
        .route("/{customer_code}/backtests/{job_id}", get(get_backtest))
        .route(
            "/{customer_code}/backtests/{job_id}/cancel",
            post(cancel_backtest),
        )
        .route("/{customer_code}/rules/stats", get(rule_stats))
        .route("/{customer_code}/rule-settings", get(rule_settings))
        .route(
            "/{customer_code}/rule-settings/{rule_id}",
            put(set_rule_setting).delete(reset_rule_setting),
        )
        .route(
            "/{customer_code}/risk-policy",
            put(set_threshold).delete(reset_threshold),
        )
        .route("/{customer_code}/native-overrides", get(native_overrides))
        .route(
            "/{customer_code}/native-overrides/{rule_id}",
            put(set_native_override).delete(delete_native_override),
        )
        .with_state(state)
}

// --- responses -------------------------------------------------------------------------

/// A route's answer: pydantic-core's JSON of the model dump.
pub fn respond(status: StatusCode, dump: &PyValue) -> Response {
    (
        status,
        [(http::header::CONTENT_TYPE, "application/json")],
        pydantic_json(dump),
    )
        .into_response()
}

/// `_error(e)`: `{"detail", "reason", "success": false}`.
pub fn error_response(status: u16, detail: &str, reason: &str) -> Response {
    respond(
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
        &PyValue::Dict(vec![
            ("detail".into(), PyValue::Str(detail.into())),
            ("reason".into(), PyValue::Str(reason.into())),
            ("success".into(), PyValue::Bool(false)),
        ]),
    )
}

/// `_call(awaitable)`: a `UbaRequestError` as the route's own answer, any
/// other exception as the backend's handlers answer it.
pub fn answer(result: UbaResult<PyValue>) -> Response {
    match result {
        Ok(dump) => respond(StatusCode::OK, &dump),
        Err(UbaError::Request {
            reason,
            detail,
            status,
        }) => error_response(status, &detail, reason),
        Err(UbaError::Py(e)) => e.unhandled().into_response(),
    }
}

/// FastAPI's body parameter, read into the validator that holds the path
/// and query errors.
pub fn read_body<T>(
    v: &mut Validator,
    body: &JsonBody,
    read: impl FnOnce(&mut Validator, &Map<String, Value>, &Loc) -> T,
) -> Option<T> {
    let root = body_loc();
    match body {
        JsonBody::Missing => {
            v.missing(root);
            None
        }
        JsonBody::NotJson => {
            v.object(&Value::Null, &root);
            None
        }
        JsonBody::Value(value) => v.object(value, &root).map(|obj| read(v, obj, &root)),
    }
}

fn lower(b: bool) -> PyValue {
    s(if b { "true" } else { "false" })
}

// --- availability and status -----------------------------------------------------------

async fn availability(_auth: Reader, State(st): State<UbaState>) -> ApiResult {
    let row = match st.client.attributes().await {
        Ok(row) => row,
        Err(e) => return Ok(answer(Err(e))),
    };
    let (configured, verified, message) = match &row {
        None => (
            false,
            false,
            "SOCFortress UBA connector is not installed".to_string(),
        ),
        Some(r) => {
            let url = copilot_web::form::py_strip(&r.connector_url);
            let key = copilot_web::form::py_strip(r.connector_api_key.as_deref().unwrap_or(""));
            let configured = !url.is_empty() && !key.is_empty();
            let verified = configured && r.connector_verified;
            let message = if verified {
                "SOCFortress UBA connector is verified"
            } else {
                "SOCFortress UBA connector is not verified"
            };
            (configured, verified, message.to_string())
        }
    };
    Ok(respond(
        StatusCode::OK,
        &PyValue::Dict(vec![
            ("success".into(), PyValue::Bool(true)),
            ("message".into(), PyValue::Str(message)),
            ("configured".into(), PyValue::Bool(configured)),
            ("verified".into(), PyValue::Bool(verified)),
        ]),
    ))
}

async fn status(auth: Reader, State(st): State<UbaState>, Path(code): Path<String>) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(answer(st.client.customer_status(&code).await))
}

// --- entities, signals, alerts ---------------------------------------------------------

async fn entities(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let entity_type = q_opt_str(&q, &mut v, "entity_type", StrSpec::ANY);
    let text = q_opt_str(&q, &mut v, "q", StrSpec::max(200));
    let min_risk = q_float_or(&q, &mut v, "min_risk", NumSpec::ge(0.0), 0.0);
    let native = q_bool_or(&q, &mut v, "native", true);
    let page = q_int_or(&q, &mut v, "page", NumSpec::ge(1.0), 1);
    let page_size = q_int_or(&q, &mut v, "page_size", NumSpec::range(1.0, 500.0), 50);
    v.finish()?;
    let params = vec![
        p("entity_type", opt(entity_type)),
        p("q", opt(text)),
        p("min_risk", PyValue::Float(min_risk)),
        p("native", lower(native)),
        p("page", int(&page)),
        p("page_size", int(&page_size)),
    ];
    Ok(answer(
        st.client
            .get_response(format!("{}/entities", tenant(&code)), params)
            .await,
    ))
}

async fn entity(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let key = q_req_str(&q, &mut v, "entity_key", StrSpec::len(1, 512));
    v.finish()?;
    Ok(answer(
        st.client
            .get_response(
                format!("{}/entities/{}", tenant(&code), path_segment(&key)),
                Vec::new(),
            )
            .await,
    ))
}

async fn risk_history(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let key = q_req_str(&q, &mut v, "entity_key", StrSpec::len(1, 512));
    let since = q_opt_str(&q, &mut v, "since", StrSpec::ANY);
    let step = q_str_or(
        &q,
        &mut v,
        "step",
        StrSpec::pattern("^(15m|1h|6h|1d)$"),
        "1h",
    );
    v.finish()?;
    Ok(answer(
        st.client
            .get_response(
                format!(
                    "{}/entities/{}/risk-history",
                    tenant(&code),
                    path_segment(&key)
                ),
                vec![p("since", opt(since)), p("step", s(&step))],
            )
            .await,
    ))
}

async fn timeline(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let key = q_req_str(&q, &mut v, "entity_key", StrSpec::len(1, 512));
    let since = q_opt_str(&q, &mut v, "since", StrSpec::ANY);
    let page = q_int_or(&q, &mut v, "page", NumSpec::ge(1.0), 1);
    let page_size = q_int_or(&q, &mut v, "page_size", NumSpec::range(1.0, 500.0), 100);
    v.finish()?;
    Ok(answer(
        st.client
            .get_response(
                format!("{}/entities/{}/timeline", tenant(&code), path_segment(&key)),
                vec![
                    p("since", opt(since)),
                    p("page", int(&page)),
                    p("page_size", int(&page_size)),
                ],
            )
            .await,
    ))
}

async fn signals(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let rule_id = q_opt_str(&q, &mut v, "rule_id", StrSpec::ANY);
    let key = q_opt_str(&q, &mut v, "entity_key", StrSpec::ANY);
    let since = q_opt_str(&q, &mut v, "since", StrSpec::ANY);
    let until = q_opt_str(&q, &mut v, "until", StrSpec::ANY);
    let include_native = q_bool_or(&q, &mut v, "include_native", false);
    let page = q_int_or(&q, &mut v, "page", NumSpec::ge(1.0), 1);
    let page_size = q_int_or(&q, &mut v, "page_size", NumSpec::range(1.0, 500.0), 50);
    v.finish()?;
    Ok(answer(
        st.client
            .get_response(
                format!("{}/signals", tenant(&code)),
                vec![
                    p("rule_id", opt(rule_id)),
                    p("entity_key", opt(key)),
                    p("since", opt(since)),
                    p("until", opt(until)),
                    p("include_native", lower(include_native)),
                    p("page", int(&page)),
                    p("page_size", int(&page_size)),
                ],
            )
            .await,
    ))
}

async fn alerts(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let status = q_opt_str(&q, &mut v, "status", StrSpec::pattern("^(open|closed)$"));
    let key = q_opt_str(&q, &mut v, "entity_key", StrSpec::ANY);
    let since = q_opt_str(&q, &mut v, "since", StrSpec::ANY);
    let page = q_int_or(&q, &mut v, "page", NumSpec::ge(1.0), 1);
    let page_size = q_int_or(&q, &mut v, "page_size", NumSpec::range(1.0, 500.0), 50);
    v.finish()?;
    Ok(answer(
        st.client
            .list_alerts(
                &code,
                vec![
                    p("status", opt(status)),
                    p("entity_key", opt(key)),
                    p("since", opt(since)),
                    p("page", int(&page)),
                    p("page_size", int(&page_size)),
                ],
            )
            .await,
    ))
}

async fn alert(
    auth: Reader,
    State(st): State<UbaState>,
    Path((code, alert_id)): Path<(String, String)>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(answer(st.client.get_alert(&code, &alert_id).await))
}

async fn evidence(
    auth: Reader,
    State(st): State<UbaState>,
    Path((code, signal_id)): Path<(String, String)>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(answer(
        st.client
            .get_response(
                format!(
                    "{}/signals/{}/evidence",
                    tenant(&code),
                    path_segment(&signal_id)
                ),
                Vec::new(),
            )
            .await,
    ))
}

// --- suppressions ----------------------------------------------------------------------

async fn list_suppressions(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let key = q_opt_str(&q, &mut v, "entity_key", StrSpec::ANY);
    let include_expired = q_bool_or(&q, &mut v, "include_expired", false);
    v.finish()?;
    Ok(answer(
        st.client
            .get_response(
                format!("{}/suppressions", tenant(&code)),
                vec![
                    p("entity_key", opt(key)),
                    p("include_expired", lower(include_expired)),
                ],
            )
            .await,
    ))
}

async fn add_suppressions(
    State(st): State<UbaState>,
    Path(code): Path<String>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let dump = read_body(&mut v, &body, schema::suppression);
    v.finish()?;
    let dump = dump.unwrap_or(PyValue::None);
    Ok(answer(
        st.client
            .write_response(
                Call::new(Method::POST, format!("{}/suppressions", tenant(&code)))
                    .json(dump)
                    .actor(&auth.username),
            )
            .await,
    ))
}

async fn remove_suppressions(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let key = q_req_str(&q, &mut v, "entity_key", StrSpec::len(1, 512));
    let rule_id = q_opt_str(&q, &mut v, "rule_id", StrSpec::ANY);
    v.finish()?;
    Ok(answer(
        st.client
            .write_response(
                Call::new(Method::DELETE, format!("{}/suppressions", tenant(&code)))
                    .params(vec![p("entity_key", s(&key)), p("rule_id", opt(rule_id))])
                    .actor(&auth.username),
            )
            .await,
    ))
}

// --- identities ------------------------------------------------------------------------

async fn identity_review(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let include = q_bool_or(&q, &mut v, "include_reviewed", false);
    v.finish()?;
    Ok(answer(
        st.client
            .get_response(
                format!("{}/identities/review", tenant(&code)),
                vec![p("include_reviewed", PyValue::Bool(include))],
            )
            .await,
    ))
}

async fn search_identities(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let text = q_req_str(&q, &mut v, "q", StrSpec::len(2, 200));
    v.finish()?;
    Ok(answer(
        st.client
            .get_response(
                format!("{}/identities", tenant(&code)),
                vec![p("q", s(&text))],
            )
            .await,
    ))
}

async fn merge_identity(
    State(st): State<UbaState>,
    Path(code): Path<String>,
    q: QueryPairs,
    WithJson(auth, body): WithJson<Admin>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let identity_id = q_req_str(&q, &mut v, "identity_id", StrSpec::len(1, 64));
    let dump = read_body(&mut v, &body, schema::merge);
    v.finish()?;
    let dump = dump.unwrap_or(PyValue::None);
    Ok(answer(
        st.client
            .write_response(
                Call::new(
                    Method::POST,
                    format!(
                        "{}/identities/{}/merge",
                        tenant(&code),
                        path_segment(&identity_id)
                    ),
                )
                .json(dump)
                .actor(&auth.username),
            )
            .await,
    ))
}

async fn identity_reviewed(
    auth: Admin,
    State(st): State<UbaState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let identity_id = q_req_str(&q, &mut v, "identity_id", StrSpec::len(1, 64));
    let reviewed = q_bool_or(&q, &mut v, "reviewed", true);
    v.finish()?;
    Ok(answer(
        st.client
            .write_response(
                Call::new(
                    Method::POST,
                    format!(
                        "{}/identities/{}/reviewed",
                        tenant(&code),
                        path_segment(&identity_id)
                    ),
                )
                .params(vec![p("reviewed", PyValue::Bool(reviewed))])
                .actor(&auth.username),
            )
            .await,
    ))
}

async fn dismiss_candidate(
    auth: Admin,
    State(st): State<UbaState>,
    Path((code, raw)): Path<(String, String)>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let candidate = path_int(&mut v, "candidate_id", &raw);
    v.finish()?;
    Ok(answer(
        st.client
            .write_response(
                Call::new(
                    Method::POST,
                    format!("{}/identity-candidates/{candidate}/dismiss", tenant(&code)),
                )
                .actor(&auth.username),
            )
            .await,
    ))
}

async fn identity_sources(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(answer(
        st.client
            .get_response(format!("{}/identity-sources", tenant(&code)), Vec::new())
            .await,
    ))
}

async fn source_action(
    auth: Admin,
    st: UbaState,
    code: String,
    source_id: String,
    action: &str,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(answer(
        st.client
            .write_response(
                Call::new(
                    Method::POST,
                    format!(
                        "{}/identity-sources/{}/{action}",
                        tenant(&code),
                        path_segment(&source_id)
                    ),
                )
                .actor(&auth.username),
            )
            .await,
    ))
}

async fn test_source(
    auth: Admin,
    State(st): State<UbaState>,
    Path((code, source_id)): Path<(String, String)>,
) -> ApiResult {
    source_action(auth, st, code, source_id, "test").await
}

async fn sync_source(
    auth: Admin,
    State(st): State<UbaState>,
    Path((code, source_id)): Path<(String, String)>,
) -> ApiResult {
    source_action(auth, st, code, source_id, "sync").await
}

// --- about, rules, backtests -----------------------------------------------------------

async fn about(auth: Reader, State(st): State<UbaState>, Path(code): Path<String>) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(answer(st.client.about().await))
}

async fn rule_catalog(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(answer(st.client.rule_catalog().await))
}

async fn create_backtest(
    State(st): State<UbaState>,
    Path(code): Path<String>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let dump = read_body(&mut v, &body, schema::backtest);
    v.finish()?;
    let dump = dump.unwrap_or(PyValue::None);
    Ok(answer(
        st.client
            .write_response(
                Call::new(Method::POST, format!("{}/backtests", tenant(&code)))
                    .json(dump)
                    .actor(&auth.username),
            )
            .await,
    ))
}

async fn list_backtests(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let limit = q_int_or(&q, &mut v, "limit", NumSpec::range(1.0, 100.0), 20);
    v.finish()?;
    Ok(answer(
        st.client
            .get_response(
                format!("{}/backtests", tenant(&code)),
                vec![p("limit", int(&limit))],
            )
            .await,
    ))
}

async fn get_backtest(
    auth: Reader,
    State(st): State<UbaState>,
    Path((code, job_id)): Path<(String, String)>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(answer(
        st.client
            .get_response(
                format!("{}/backtests/{}", tenant(&code), path_segment(&job_id)),
                Vec::new(),
            )
            .await,
    ))
}

async fn cancel_backtest(
    auth: Reader,
    State(st): State<UbaState>,
    Path((code, job_id)): Path<(String, String)>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(answer(
        st.client
            .write_response(
                Call::new(
                    Method::POST,
                    format!(
                        "{}/backtests/{}/cancel",
                        tenant(&code),
                        path_segment(&job_id)
                    ),
                )
                .actor(&auth.username),
            )
            .await,
    ))
}

async fn rule_stats(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let since = q_str_or(&q, &mut v, "since", StrSpec::ANY, "24h");
    v.finish()?;
    Ok(answer(
        st.client
            .get_response(
                format!("{}/rules/stats", tenant(&code)),
                vec![p("since", s(&since))],
            )
            .await,
    ))
}

async fn rule_settings(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(answer(
        st.client
            .get_response(format!("{}/rule-settings", tenant(&code)), Vec::new())
            .await,
    ))
}

async fn set_rule_setting(
    State(st): State<UbaState>,
    Path((code, rule_id)): Path<(String, String)>,
    WithJson(auth, body): WithJson<Admin>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let dump = read_body(&mut v, &body, schema::rule_setting);
    v.finish()?;
    let dump = dump.unwrap_or(PyValue::None);
    Ok(answer(
        st.client
            .write_response(
                Call::new(
                    Method::PUT,
                    format!("{}/rule-settings/{}", tenant(&code), path_segment(&rule_id)),
                )
                .json(dump)
                .actor(&auth.username),
            )
            .await,
    ))
}

async fn reset_rule_setting(
    auth: Admin,
    State(st): State<UbaState>,
    Path((code, rule_id)): Path<(String, String)>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(answer(
        st.client
            .write_response(
                Call::new(
                    Method::DELETE,
                    format!("{}/rule-settings/{}", tenant(&code), path_segment(&rule_id)),
                )
                .actor(&auth.username),
            )
            .await,
    ))
}

async fn set_threshold(
    State(st): State<UbaState>,
    Path(code): Path<String>,
    WithJson(auth, body): WithJson<Admin>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let dump = read_body(&mut v, &body, schema::alert_threshold);
    v.finish()?;
    let dump = dump.unwrap_or(PyValue::None);
    Ok(answer(
        st.client
            .write_response(
                Call::new(Method::PUT, format!("{}/risk-policy", tenant(&code)))
                    .json(dump)
                    .actor(&auth.username),
            )
            .await,
    ))
}

async fn reset_threshold(
    auth: Admin,
    State(st): State<UbaState>,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(answer(
        st.client
            .write_response(
                Call::new(Method::DELETE, format!("{}/risk-policy", tenant(&code)))
                    .actor(&auth.username),
            )
            .await,
    ))
}

async fn native_overrides(
    auth: Reader,
    State(st): State<UbaState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let integration = q_str_or(&q, &mut v, "integration", StrSpec::ANY, "wazuh");
    v.finish()?;
    Ok(answer(
        st.client
            .get_response(
                format!("{}/native-overrides", tenant(&code)),
                vec![p("integration", s(&integration))],
            )
            .await,
    ))
}

async fn set_native_override(
    State(st): State<UbaState>,
    Path((code, rule_id)): Path<(String, String)>,
    q: QueryPairs,
    WithJson(auth, body): WithJson<Admin>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let integration = q_str_or(&q, &mut v, "integration", StrSpec::ANY, "wazuh");
    let dump = read_body(&mut v, &body, schema::score);
    v.finish()?;
    let dump = dump.unwrap_or(PyValue::None);
    Ok(answer(
        st.client
            .write_response(
                Call::new(
                    Method::PUT,
                    format!(
                        "{}/native-overrides/{}",
                        tenant(&code),
                        path_segment(&rule_id)
                    ),
                )
                .params(vec![p("integration", s(&integration))])
                .json(dump)
                .actor(&auth.username),
            )
            .await,
    ))
}

async fn delete_native_override(
    auth: Admin,
    State(st): State<UbaState>,
    Path((code, rule_id)): Path<(String, String)>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let mut v = Validator::new();
    let integration = q_str_or(&q, &mut v, "integration", StrSpec::ANY, "wazuh");
    v.finish()?;
    Ok(answer(
        st.client
            .write_response(
                Call::new(
                    Method::DELETE,
                    format!(
                        "{}/native-overrides/{}",
                        tenant(&code),
                        path_segment(&rule_id)
                    ),
                )
                .params(vec![p("integration", s(&integration))])
                .actor(&auth.username),
            )
            .await,
    ))
}
