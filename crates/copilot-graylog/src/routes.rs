//! `/api/graylog/*` — port of `app/connectors/graylog/routes/` (collector,
//! events, management, monitoring, pipelines, streams, receiver): 21 routes,
//! with Python's guards (`require_any_scope("admin", "analyst")` for the
//! reads, `get_current_user(scopes=["admin"])` for index/input/stream
//! management and the URL allowlist, `require_any_scope("admin")` for the
//! Event Shipper receiver) and FastAPI's check order. Graylog data is
//! deployment-wide: no route is tenant-scoped, as in Python.

use axum::Router;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{self, Ty, construct, field};
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::{body_model, body_value, model_response, validation_error};
use copilot_web::{
    AdminOnly, AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, QueryPairs, ScopedUser,
    WithJson,
};

use crate::client::GraylogClient;
use crate::schema::{
    ALERT_QUERY, DELETED_INDEX_BODY, EVENT_SHIPPER_PAYLOAD, INPUT_BODY, STREAM_BODY,
};
use crate::{gelf, services};

/// Route state.
#[derive(Debug, Clone)]
pub struct GraylogState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The Graylog client.
    pub client: GraylogClient,
}

impl axum::extract::FromRef<GraylogState> for AppContext {
    fn from_ref(s: &GraylogState) -> AppContext {
        s.ctx.clone()
    }
}

type Reader = Authorized<AdminOrAnalyst>;
type Admin = ScopedUser<AdminOnly>;

/// The router, to be nested at `/api/graylog`.
pub fn router(state: GraylogState) -> Router {
    Router::new()
        .route("/indices", get(indices))
        .route("/inputs", get(inputs))
        .route("/inputs/running", get(inputs_running))
        .route("/inputs/configured", get(inputs_configured))
        .route("/event/definitions", get(event_definitions))
        .route("/event/alerts", post(event_alerts))
        .route("/url_whitelist", get(url_whitelist))
        .route("/index", delete(delete_index))
        .route("/input/stop", post(stop_input))
        .route("/input/start", post(start_input))
        .route("/stream/stop", post(stop_stream))
        .route("/stream/start", post(start_stream))
        .route("/messages", get(messages))
        .route("/metrics", get(metrics))
        .route("/event_notifications", get(event_notifications))
        .route("/streams", get(streams))
        .route("/pipelines", get(pipelines))
        .route("/pipeline/full", get(pipeline_full))
        .route("/pipeline/rules", get(pipeline_rules))
        .route("/pipeline/rules/{pipeline_id}", get(pipeline_rule))
        .route("/receiver", post(receiver))
        .with_state(state)
}

fn answer(result: Result<PyValue, PyExc>) -> ApiResult {
    result
        .map(|dump| model_response(&dump))
        .map_err(PyExc::unhandled)
}

/// A path parameter as Starlette matches it: decoded, and never spanning a
/// `/` (an encoded slash makes the path match no route).
pub fn path_segment(raw: &str) -> Result<&str, ApiError> {
    if raw.contains('/') {
        return Err(ApiError::RouteNotFound);
    }
    Ok(raw)
}

async fn indices(_: Reader, State(st): State<GraylogState>) -> ApiResult {
    answer(services::indices_full(&st.client).await)
}

async fn inputs(_: Reader, State(st): State<GraylogState>) -> ApiResult {
    answer(services::inputs(&st.client).await)
}

async fn inputs_running(_: Reader, State(st): State<GraylogState>) -> ApiResult {
    answer(services::inputs_running(&st.client).await)
}

async fn inputs_configured(_: Reader, State(st): State<GraylogState>) -> ApiResult {
    answer(services::inputs_configured(&st.client).await)
}

async fn event_definitions(_: Reader, State(st): State<GraylogState>) -> ApiResult {
    answer(services::event_definitions(&st.client).await)
}

async fn event_alerts(
    State(st): State<GraylogState>,
    WithJson(_auth, body): WithJson<Reader>,
) -> ApiResult {
    let query = body_model(&body, &ALERT_QUERY)?;
    answer(services::alerts(&st.client, query).await)
}

async fn url_whitelist(_: Admin, State(st): State<GraylogState>) -> ApiResult {
    answer(services::url_whitelist_entries(&st.client).await)
}

async fn delete_index(
    State(st): State<GraylogState>,
    WithJson(_auth, body): WithJson<Admin>,
) -> ApiResult {
    let body = body_model(&body, &DELETED_INDEX_BODY)?;
    let raw = field(&body, "index_name").py_str();
    let result = async {
        let name = services::verify_index_name(&st.client, &raw).await?;
        services::delete_index(&st.client, &name).await
    }
    .await;
    answer(result)
}

async fn stop_input(
    State(st): State<GraylogState>,
    WithJson(_auth, body): WithJson<Admin>,
) -> ApiResult {
    let body = body_model(&body, &INPUT_BODY)?;
    let raw = field(&body, "input_id").py_str();
    let result = async {
        let id = services::verify_input_id(&st.client, &raw).await?;
        services::stop_input(&st.client, &id).await
    }
    .await;
    answer(result)
}

async fn start_input(
    State(st): State<GraylogState>,
    WithJson(_auth, body): WithJson<Admin>,
) -> ApiResult {
    let body = body_model(&body, &INPUT_BODY)?;
    let raw = field(&body, "input_id").py_str();
    let result = async {
        let id = services::verify_input_id(&st.client, &raw).await?;
        services::start_input(&st.client, &id).await
    }
    .await;
    answer(result)
}

async fn stop_stream(
    State(st): State<GraylogState>,
    WithJson(_auth, body): WithJson<Admin>,
) -> ApiResult {
    let body = body_model(&body, &STREAM_BODY)?;
    let raw = field(&body, "stream_id").py_str();
    let result = async {
        let id = services::verify_stream_id(&st.client, &raw).await?;
        services::stop_stream(&st.client, &id).await
    }
    .await;
    answer(result)
}

async fn start_stream(
    State(st): State<GraylogState>,
    WithJson(_auth, body): WithJson<Admin>,
) -> ApiResult {
    let body = body_model(&body, &STREAM_BODY)?;
    let raw = field(&body, "stream_id").py_str();
    let result = async {
        let id = services::verify_stream_id(&st.client, &raw).await?;
        services::start_stream(&st.client, &id).await
    }
    .await;
    answer(result)
}

/// `page_number: int = 1` (a query parameter).
fn page_number(q: &QueryPairs) -> Result<String, ApiError> {
    let Some(raw) = q.get("page_number") else {
        return Ok("1".into());
    };
    match model::validate_ty(&Ty::Int, &PyValue::Str(raw.to_string())) {
        Ok(v) => Ok(v.py_str()),
        Err(model::Invalid::Errors(errors)) => Err(validation_error(
            errors
                .into_iter()
                .map(|mut e| {
                    e.loc.insert(0, model::Loc::Key("page_number".into()));
                    e
                })
                .collect(),
            "query",
        )),
        Err(model::Invalid::Abort(status, detail)) => Err(PyExc::http(status, detail).unhandled()),
    }
}

async fn messages(_: Reader, State(st): State<GraylogState>, q: QueryPairs) -> ApiResult {
    let page = page_number(&q)?;
    answer(services::messages(&st.client, &page).await)
}

async fn metrics(_: Reader, State(st): State<GraylogState>) -> ApiResult {
    answer(services::metrics(&st.client).await)
}

async fn event_notifications(_: Reader, State(st): State<GraylogState>) -> ApiResult {
    answer(services::event_notifications(&st.client).await)
}

async fn streams(_: Reader, State(st): State<GraylogState>) -> ApiResult {
    answer(services::streams(&st.client).await)
}

async fn pipelines(_: Reader, State(st): State<GraylogState>) -> ApiResult {
    answer(services::pipelines(&st.client).await)
}

async fn pipeline_full(_: Reader, State(st): State<GraylogState>) -> ApiResult {
    answer(services::pipelines_with_rule_ids(&st.client).await)
}

async fn pipeline_rules(_: Reader, State(st): State<GraylogState>) -> ApiResult {
    answer(services::pipeline_rules(&st.client).await)
}

async fn pipeline_rule(
    _: Reader,
    State(st): State<GraylogState>,
    Path(pipeline_id): Path<String>,
) -> ApiResult {
    let id = path_segment(&pipeline_id)?;
    answer(services::pipeline_rule_by_id(&st.client, id).await)
}

/// `forward_to_graylog`: `payload: dict` → `EventShipperPayload(**payload)`
/// → one GELF frame to the Event Shipper.
async fn receiver(
    State(st): State<GraylogState>,
    WithJson(_auth, body): WithJson<Authorized<AdminOnly>>,
) -> ApiResult {
    let payload = body_value(&body, &Ty::Dict(&Ty::Any))?;
    let message = construct(&EVENT_SHIPPER_PAYLOAD, &payload).map_err(PyExc::unhandled)?;
    // `to_dict()`: `model_dump(exclude_none=True)` (top level only).
    let message = match message {
        PyValue::Dict(items) => PyValue::Dict(
            items
                .into_iter()
                .filter(|(_, v)| !matches!(v, PyValue::None))
                .collect(),
        ),
        other => other,
    };
    gelf::ship(&st.ctx.connectors, &message)
        .await
        .map_err(PyExc::unhandled)?;
    Ok(axum::Json(serde_json::json!({
        "message": "Message forwarded to Graylog",
        "success": true,
    }))
    .into_response())
}
