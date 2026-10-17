//! `/api/analyzers` — port of `routes/analyzers.py`: `GET ""` and `POST
//! /run`, both `require_any_scope("admin", "analyst")`. An analyzer runs on
//! a bare IoC (IPv4 address, hash or domain), no customer is involved.
//!
//! `POST /run` keeps FastAPI's order: the body is read, then the token,
//! then `RunAnalyzerBody` is validated (its `model_validator` refusing a
//! value that is no IP, hash or domain at the body's root); the
//! `verify_analyzer_exists` dependency then lists the analyzers (Cortex
//! asked once) and answers 400 for an unknown name before the job runs.

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::PyError;
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::{body_model, model_response, validation_error};
use copilot_web::{AdminOrAnalyst, ApiResult, Authorized, WithJson};

use super::schema;
use super::services;
use crate::IntelState;

type Reader = Authorized<AdminOrAnalyst>;

/// The router, with full paths (`/api/analyzers`, `/api/analyzers/run`).
pub fn router(state: IntelState) -> Router {
    Router::new()
        .route("/api/analyzers", get(all))
        .route("/api/analyzers/run", post(run))
        .with_state(state)
}

fn answer(result: Result<PyValue, PyExc>) -> ApiResult {
    result
        .map(|dump| model_response(&dump))
        .map_err(PyExc::unhandled)
}

async fn all(_: Reader, State(st): State<IntelState>) -> ApiResult {
    tracing::info!("Fetching all analyzers");
    answer(services::analyzers(&st.ctx.connectors, &st.cortex_http).await)
}

async fn run(State(st): State<IntelState>, WithJson(_auth, body): WithJson<Reader>) -> ApiResult {
    let fields = body_model(&body, &schema::RUN_ANALYZER_BODY)?;
    let text = |key: &str| {
        fields
            .get(key)
            .and_then(PyValue::as_str)
            .unwrap_or("")
            .to_string()
    };
    let (name, data) = (text("analyzer_name"), text("analyzer_data"));
    let Some(data_type) = schema::is_valid_datatype(&data) else {
        return Err(validation_error(
            vec![PyError {
                loc: Vec::new(),
                kind: "value_error",
                msg: "Value error, Invalid data type: Unknown".into(),
                input: fields.clone(),
            }],
            "body",
        ));
    };
    // `verify_analyzer_exists`.
    let names = services::analyzer_names(&st.ctx.connectors, &st.cortex_http)
        .await
        .map_err(PyExc::unhandled)?;
    if !names.contains(&name) {
        return Err(PyExc::http(400, format!("Analyzer {name} does not exist.")).unhandled());
    }
    tracing::info!("Running analyzer {name} with data {data} of type {data_type}");
    answer(services::run(&st.ctx.connectors, &st.cortex_http, &name, &data, data_type).await)
}
