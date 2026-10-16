//! The HTTP routes, with FastAPI's check order: the body is read first (a
//! malformed one is a 422 before anything else), then the token (or the
//! webhook header), the path, the query, the body's validation.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::json;

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::json::pydantic_json;
use copilot_upstream::model::{Invalid, Model, Ty, format_validation_error, validate};
use copilot_wazuh::error::PyErr;
use copilot_web::body::JsonBody;
use copilot_web::form::latin1;
use copilot_web::validate::{Validator, loc};
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized, QueryPairs, WithJson};

use crate::create::{Origin, PayloadArgs, add_alert_to_document, create_alert, create_alert_full};
use crate::schema::{
    CreateAlertRequest, CreateAlertRequestRoute, ThresholdNotification, py_datetime_str,
    read_dry_run, read_sigma,
};
use crate::source::single_alert_details;
use crate::{IngestState, collect, es, indices, threshold};

type Soc = Authorized<AdminOrAnalyst>;

/// `/api/incidents/alerts` and the indexer routes of
/// `/api/incidents/db_operations`, with full paths (they sit beside the
/// routers `copilot-incidents` nests at those prefixes).
pub fn router(state: IngestState) -> Router {
    let alerts = "/api/incidents/alerts";
    let db = "/api/incidents/db_operations";
    let legacy = state.legacy.clone();
    Router::new()
        .route(&format!("{alerts}/index/names"), get(index_names))
        .route(&format!("{alerts}/alerts/not-created"), get(not_created))
        .route(&format!("{alerts}/alert/details"), post(alert_details))
        .route(&format!("{alerts}/alert/timeline"), post(alert_timeline))
        .route(&format!("{alerts}/create/manual"), post(create_manual))
        .route(&format!("{alerts}/create/auto"), post(create_auto))
        .route(
            &format!("{alerts}/create/threshold"),
            post(create_threshold),
        )
        .route(
            &format!("{alerts}/create/velo-sigma"),
            post(create_velo_sigma),
        )
        .route(
            &format!("{alerts}/alert/{{alert_id}}/velo-sigma/exclusion-draft"),
            get(exclusion_draft),
        )
        .route(
            &format!("{alerts}/alert/{{alert_id}}/velo-sigma/exclusion-dry-run"),
            post(exclusion_dry_run),
        )
        .route(
            &format!("{db}/available-source/{{index_name}}"),
            get(available_source),
        )
        .route(
            &format!("{db}/available-indices/{{source}}"),
            get(available_indices),
        )
        .route(
            &format!("{db}/mappings/fields-assets-title-and-timefield"),
            get(mappings),
        )
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            legacy,
            copilot_wazuh::decoded_slash_to_legacy,
        ))
}

/// A response model's JSON (pydantic's writer).
fn pyjson(v: &PyValue) -> Response {
    (
        [(http::header::CONTENT_TYPE, "application/json")],
        pydantic_json(v),
    )
        .into_response()
}

fn s(text: &str) -> PyValue {
    PyValue::Str(text.to_string())
}

fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn str_list(items: Vec<String>) -> PyValue {
    PyValue::List(items.into_iter().map(PyValue::Str).collect())
}

/// `GET /index/names`.
async fn index_names(_auth: Soc, State(st): State<IngestState>) -> ApiResult {
    let names = collect::graylog_event_indices(&st).await?;
    Ok(pyjson(&dict(vec![
        ("index_names", str_list(names)),
        ("success", PyValue::Bool(true)),
        ("message", s("Success")),
    ])))
}

/// `GET /alerts/not-created`: the handler returns `(AlertsPayload, int)`,
/// which its response model refuses — a bare 500 once the events are read.
async fn not_created(_auth: Soc, State(st): State<IngestState>) -> ApiResult {
    collect::alerts_not_created(&st, 100).await?;
    Err(ApiError::internal(
        "ResponseValidationError: the handler returned a tuple for AlertsPayload",
    ))
}

/// `POST /alert/details`.
async fn alert_details(
    State(st): State<IngestState>,
    WithJson(_auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(CreateAlertRequestRoute::read)?;
    let details = single_alert_details(&st, &req.index_name, &req.index_id).await?;
    // The return annotation is the response model (FastAPI infers it).
    Ok(pyjson(&dict(vec![
        ("alert_details", details.dump),
        ("success", PyValue::Bool(true)),
        ("message", s("Alert details retrieved")),
    ])))
}

static ALERT_TIMELINE_RESPONSE: Model = Model::new(
    "AlertTimelineResponse",
    &[
        copilot_upstream::model::Field::req("alert_timeline", Ty::List(&Ty::Dict(&Ty::Any))),
        copilot_upstream::model::Field::req("success", Ty::Bool),
        copilot_upstream::model::Field::req("message", Ty::Str),
    ],
);

/// `POST /alert/timeline`: a threshold alert's replay, else the process's
/// events of the alert's day.
async fn alert_timeline(
    State(st): State<IngestState>,
    WithJson(_auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(CreateAlertRequestRoute::read)?;
    let timeline =
        match threshold::threshold_timeline(&st, req.alert_id, &req.index_name, &req.index_id)
            .await?
        {
            Some(t) => t,
            None => {
                let details = single_alert_details(&st, &req.index_name, &req.index_id).await?;
                match details.source_str("process_id").map(str::to_string) {
                    None => PyValue::List(Vec::new()),
                    Some(process_id) => {
                        let timestamp = details.source_str("timestamp").unwrap_or_default();
                        let (start, end) = crate::py::day_range(timestamp)?;
                        let agent = crate::py::dict_get(&details.source, "agent_name")
                            .cloned()
                            .unwrap_or(PyValue::None);
                        let query = dict(vec![(
                            "query",
                            dict(vec![(
                                "bool",
                                dict(vec![(
                                    "must",
                                    PyValue::List(vec![
                                        dict(vec![(
                                            "match",
                                            dict(vec![("process_id", s(&process_id))]),
                                        )]),
                                        dict(vec![("match", dict(vec![("agent_name", agent)]))]),
                                        dict(vec![(
                                            "range",
                                            dict(vec![(
                                                "timestamp",
                                                dict(vec![("gte", s(&start)), ("lt", s(&end))]),
                                            )]),
                                        )]),
                                    ]),
                                )]),
                            )]),
                        )]);
                        let client = es::sync_client(&st).await?;
                        let response = es::search(&client, &req.index_name, &query, Some(50), None)
                            .await
                            .map_err(PyErr::from)?;
                        threshold::hits_of(&response).map_err(PyErr::Other)?
                    }
                }
            }
        };
    let body = dict(vec![
        ("alert_timeline", timeline),
        ("success", PyValue::Bool(true)),
        ("message", s("Alert timeline retrieved")),
    ]);
    match validate(&ALERT_TIMELINE_RESPONSE, &body) {
        Ok(dump) => Ok(pyjson(&dump)),
        Err(Invalid::Errors(e)) => Err(ApiError::bad_request(format_validation_error(
            ALERT_TIMELINE_RESPONSE.name,
            &e,
        ))),
        Err(Invalid::Abort(status, detail)) => Err(PyErr::http(status, detail).into()),
    }
}

/// `POST /create/manual`.
async fn create_manual(
    State(st): State<IngestState>,
    WithJson(_auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(CreateAlertRequest::read)?;
    tracing::info!(target: "copilot::ingest", "Creating alert {} in CoPilot", req.alert_id);
    let id = create_alert(&st, &req.index_name, &req.alert_id).await?;
    Ok(
        axum::Json(json!({"success": true, "message": "Alert created in CoPilot", "alert_id": id}))
            .into_response(),
    )
}

/// `POST /create/auto` (no body is read).
async fn create_auto(_auth: Soc, State(st): State<IngestState>) -> ApiResult {
    let out = collect::create_alerts_auto(&st).await?;
    Ok(axum::Json(out).into_response())
}

/// The webhook header check (`verify_graylog_header` /
/// `verify_velociraptor_header`): fails closed without a configured value.
fn check_header(
    headers: &HeaderMap,
    name: &str,
    expected: Option<&str>,
    tool: &str,
) -> Result<(), ApiError> {
    let Some(expected) = expected.filter(|e| !e.is_empty()) else {
        tracing::error!(target: "copilot::ingest", "{tool} header value is not configured; denying the webhook request");
        return Err(ApiError::forbidden(format!(
            "{tool} header authentication is not configured"
        )));
    };
    let sent = headers.get(name).map(|v| latin1(v.as_bytes()));
    if sent.as_deref() != Some(expected) {
        tracing::error!(target: "copilot::ingest", "Invalid or missing {tool} header");
        return Err(ApiError::forbidden(format!(
            "Invalid or missing {tool} header"
        )));
    }
    Ok(())
}

/// `POST /create/threshold` (`graylog` header).
async fn create_threshold(
    State(st): State<IngestState>,
    headers: HeaderMap,
    body: JsonBody,
) -> ApiResult {
    check_header(
        &headers,
        "graylog",
        st.env.graylog_api_header_value.as_deref(),
        "Graylog",
    )?;
    let req = body.model(ThresholdNotification::read)?;
    let req = req.ok_or_else(|| ApiError::internal("threshold body without errors"))?;
    let source = req.fields.source.clone();
    let (index, id) = threshold::resolve_threshold_event(
        &st,
        &req.replay.query,
        req.replay.timerange_start.wall,
        req.replay.timerange_end.wall,
        &req.group_by_fields,
        &source,
    )
    .await?;
    let asset = threshold::resolve_threshold_asset(&st, &index, &id, &source).await?;
    let mut payload = PayloadArgs {
        context: PyValue::Dict(req.fields.dump.clone()),
        asset,
        timefield: PyValue::Str(py_datetime_str(&req.timestamp)),
        title: PyValue::Str(req.message.clone()),
        ioc: None,
        source: PyValue::Str(source.clone()),
        index_name: PyValue::Str(index.clone()),
        index_id: PyValue::Str(id.clone()),
        rule_level: None,
        severity: None,
    }
    .build()?;
    let alert_id = create_alert_full(
        &st,
        &mut payload,
        &req.fields.customer_code,
        Origin::Threshold,
    )
    .await?;
    if threshold::is_resolved(&index, &id) {
        add_alert_to_document(&st, &index, &id, alert_id).await?;
    }
    if let Err(e) = threshold::save_threshold_metadata(
        &st,
        alert_id,
        &req.event_definition_id,
        &req.replay.query,
        req.replay.timerange_start.wall,
        req.replay.timerange_end.wall,
        &req.group_by_fields,
        &req.source_streams,
        &source,
        &index,
        &id,
    )
    .await
    {
        tracing::error!(
            target: "copilot::ingest",
            "Failed to save threshold metadata for alert {alert_id}: {}",
            e.py_str()
        );
    }
    Ok(axum::Json(json!({
        "success": true,
        "message": "Alert threshold Graylog invoked successfully",
        "alert_id": alert_id,
    }))
    .into_response())
}

/// `POST /create/velo-sigma` (`velociraptor` header).
async fn create_velo_sigma(
    State(st): State<IngestState>,
    headers: HeaderMap,
    body: JsonBody,
) -> ApiResult {
    check_header(
        &headers,
        "velociraptor",
        st.env.velociraptor_api_header_value.as_deref(),
        "Velociraptor",
    )?;
    let alert = body.model(read_sigma)?;
    let alert = alert.ok_or_else(|| ApiError::internal("sigma body without errors"))?;
    let out = crate::sigma::ingest::process_alert(&st, &alert).await;
    Ok(axum::Json(out).into_response())
}

/// `GET /alert/{alert_id}/velo-sigma/exclusion-draft`.
async fn exclusion_draft(
    auth: Soc,
    State(st): State<IngestState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let alert_id = copilot_incidents::routes::common::path_int("alert_id", &raw)?;
    let loaded = copilot_incidents::access::ensure_alert(&st.ctx, &auth, alert_id).await?;
    let alert = loaded.build()?;
    let Some(draft) = crate::sigma::draft::build_exclusion_draft(&alert) else {
        return Err(ApiError::not_found(
            "Alert carries no Velociraptor Sigma event payload; cannot draft an exclusion rule",
        ));
    };
    Ok(axum::Json(json!({
        "success": true,
        "message": "Exclusion draft built from alert",
        "draft": draft,
    }))
    .into_response())
}

/// `POST /alert/{alert_id}/velo-sigma/exclusion-dry-run`.
async fn exclusion_dry_run(
    State(st): State<IngestState>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    // Path and body errors are one 422, path first (FastAPI collects both).
    let mut v = Validator::new();
    let alert_id = v
        .check_int(
            &loc("path", "alert_id"),
            &serde_json::Value::String(raw),
            copilot_web::validate::IntRules::default(),
        )
        .unwrap_or_default();
    let rule = copilot_incidents::requests::merge(v, body.model(read_dry_run))?;
    let loaded = copilot_incidents::access::ensure_alert(&st.ctx, &auth, alert_id).await?;
    let alert = loaded.build()?;
    let out = crate::sigma::draft::dry_run(&alert, &rule).map_err(ApiError::internal)?;
    Ok(axum::Json(out).into_response())
}

static AVAILABLE_SOURCES_RESPONSE: Model = Model::new(
    "AvailableSourcesResponse",
    &[
        copilot_upstream::model::Field::req("source", Ty::Str),
        copilot_upstream::model::Field::req("success", Ty::Bool),
        copilot_upstream::model::Field::req("message", Ty::Str),
    ],
);

/// `GET /db_operations/available-source/{index_name}`.
async fn available_source(
    _auth: Soc,
    State(st): State<IngestState>,
    Path(index): Path<String>,
) -> ApiResult {
    let source = indices::index_source(&st, &index).await?;
    let body = dict(vec![
        ("source", source),
        ("success", PyValue::Bool(true)),
        ("message", s("Source retrieved successfully")),
    ]);
    match validate(&AVAILABLE_SOURCES_RESPONSE, &body) {
        Ok(dump) => Ok(pyjson(&dump)),
        Err(Invalid::Errors(e)) => Err(ApiError::bad_request(format_validation_error(
            AVAILABLE_SOURCES_RESPONSE.name,
            &e,
        ))),
        Err(Invalid::Abort(status, detail)) => Err(PyErr::http(status, detail).into()),
    }
}

/// `GET /db_operations/available-indices/{source}`.
async fn available_indices(
    _auth: Soc,
    State(st): State<IngestState>,
    Path(source): Path<String>,
) -> ApiResult {
    let found = indices::available_indices(&st, &source).await?;
    Ok(pyjson(&dict(vec![
        ("indices", str_list(found)),
        ("success", PyValue::Bool(true)),
        ("message", s("Indices retrieved successfully")),
    ])))
}

/// `GET /db_operations/mappings/fields-assets-title-and-timefield?index_name=`.
async fn mappings(_auth: Soc, State(st): State<IngestState>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let index = match q.get("index_name") {
        Some(i) => i.to_string(),
        None => {
            v.missing(loc("query", "index_name"));
            String::new()
        }
    };
    v.finish()?;
    let keys = indices::mapping_keys(&st, &index).await?;
    Ok(pyjson(&dict(vec![
        ("available_mappings", str_list(keys)),
        ("success", PyValue::Bool(true)),
        (
            "message",
            s("Field names and asset names retrieved successfully"),
        ),
    ])))
}
