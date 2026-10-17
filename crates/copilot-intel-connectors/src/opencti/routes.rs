//! `/api/opencti/*` — port of `routes/opencti.py`: six routes, every one
//! `require_any_scope("admin", "analyst")`. OpenCTI holds deployment-wide
//! threat intelligence, not tenant data, so none is tenant-scoped (as in
//! Python).

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{self, Loc, PyError, Ty};
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::{from_json, model_response, validation_error};
use copilot_web::{
    AdminOrAnalyst, ApiError, ApiResult, Authorized, JsonBody, QueryPairs, WithJson,
};

use super::schema;
use super::services::{self, IndicatorQuery};
use crate::IntelState;

type Reader = Authorized<AdminOrAnalyst>;

/// The router, with full paths (`/api/opencti/...`).
pub fn router(state: IntelState) -> Router {
    Router::new()
        .route("/api/opencti/availability", get(availability))
        .route("/api/opencti/about", get(about))
        .route("/api/opencti/observables/search", get(search))
        .route("/api/opencti/observables/lookup", post(lookup))
        .route("/api/opencti/indicators", get(indicators))
        .route("/api/opencti/entities/{entity_id}", get(entity))
        .with_state(state)
}

fn answer(result: Result<PyValue, PyExc>) -> ApiResult {
    result
        .map(|dump| model_response(&dump))
        .map_err(PyExc::unhandled)
}

/// Query or path parameters read in declaration order, every error
/// collected (FastAPI's 422).
struct Params {
    location: &'static str,
    errors: Vec<PyError>,
}

/// `-1`, `0` or `1`: `text` (Python's `int` text) against `bound`.
fn cmp_int(text: &str, bound: i64) -> std::cmp::Ordering {
    match text.parse::<i128>() {
        Ok(n) => n.cmp(&i128::from(bound)),
        // Beyond i128: the sign decides.
        Err(_) if text.starts_with('-') => std::cmp::Ordering::Less,
        Err(_) => std::cmp::Ordering::Greater,
    }
}

impl Params {
    fn new(location: &'static str) -> Self {
        Self {
            location,
            errors: Vec::new(),
        }
    }

    fn push(&mut self, name: &str, kind: &'static str, msg: impl Into<String>, input: PyValue) {
        self.errors.push(PyError {
            loc: vec![Loc::Key(name.into())],
            kind,
            msg: msg.into(),
            input,
        });
    }

    /// `str` with `min_length` / `max_length` (Python's length: code points).
    fn text(
        &mut self,
        name: &str,
        raw: Option<&str>,
        required: bool,
        min: usize,
        max: usize,
    ) -> Option<String> {
        let Some(raw) = raw else {
            if required {
                self.push(name, "missing", "Field required", PyValue::None);
            }
            return None;
        };
        let n = raw.chars().count();
        let unit = |k: usize| if k == 1 { "character" } else { "characters" };
        if n < min {
            self.push(
                name,
                "string_too_short",
                format!("String should have at least {min} {}", unit(min)),
                PyValue::Str(raw.into()),
            );
            return None;
        }
        if n > max {
            self.push(
                name,
                "string_too_long",
                format!("String should have at most {max} {}", unit(max)),
                PyValue::Str(raw.into()),
            );
            return None;
        }
        Some(raw.to_string())
    }

    /// `int` with `ge` / `le`: Python's `int` text.
    fn int(&mut self, name: &str, raw: Option<&str>, ge: i64, le: i64) -> Option<String> {
        let raw = raw?;
        let value = match model::validate_ty(&Ty::Int, &PyValue::Str(raw.to_string())) {
            Ok(v) => v.py_str(),
            Err(model::Invalid::Errors(errors)) => {
                for mut e in errors {
                    e.loc.insert(0, Loc::Key(name.into()));
                    self.errors.push(e);
                }
                return None;
            }
            Err(model::Invalid::Abort(..)) => return None,
        };
        if cmp_int(&value, ge).is_lt() {
            self.push(
                name,
                "greater_than_equal",
                format!("Input should be greater than or equal to {ge}"),
                PyValue::Int(value),
            );
            return None;
        }
        if cmp_int(&value, le).is_gt() {
            self.push(
                name,
                "less_than_equal",
                format!("Input should be less than or equal to {le}"),
                PyValue::Int(value),
            );
            return None;
        }
        Some(value)
    }

    fn finish(self) -> Result<(), ApiError> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(validation_error(self.errors, self.location))
        }
    }
}

async fn availability(_: Reader, State(st): State<IntelState>) -> ApiResult {
    answer(services::availability(&st.ctx.connectors).await)
}

async fn about(_: Reader, State(st): State<IntelState>) -> ApiResult {
    tracing::info!("Fetching OpenCTI platform info");
    answer(services::platform_info(&st.ctx.connectors).await)
}

async fn search(_: Reader, State(st): State<IntelState>, q: QueryPairs) -> ApiResult {
    let mut p = Params::new("query");
    let value = p.text("value", q.get("value"), true, 1, 2048);
    let first = p.int("first", q.get("first"), 1, 100);
    p.finish()?;
    let value = value.unwrap_or_default();
    let first = first.unwrap_or_else(|| "10".into());
    tracing::info!("Looking up OpenCTI observable: {value}");
    answer(services::lookup_observable(&st.ctx.connectors, &value, &first).await)
}

async fn lookup(
    State(st): State<IntelState>,
    WithJson(_auth, body): WithJson<Reader>,
) -> ApiResult {
    let input = match &body {
        JsonBody::Value(v @ serde_json::Value::Object(_)) => from_json(v),
        // Not an object: the model's own 422.
        other => {
            copilot_upstream::respond::body_model(other, &BATCH_REQUEST)?;
            return Err(ApiError::internal("a non-object body validated"));
        }
    };
    let values = schema::batch_values(&input).map_err(|errors| validation_error(errors, "body"))?;
    answer(services::lookup_observables(&st.ctx.connectors, &values).await)
}

/// `OpenCTIBatchLookupRequest`'s shape, for the 422 of a body that is not
/// an object (its `values` rules are [`schema::batch_values`]).
static BATCH_REQUEST: model::Model = model::Model::new(
    "OpenCTIBatchLookupRequest",
    &[model::Field::req("values", Ty::List(&Ty::Str))],
);

async fn indicators(_: Reader, State(st): State<IntelState>, q: QueryPairs) -> ApiResult {
    let mut p = Params::new("query");
    let search = p.text("search", q.get("search"), false, 0, 512);
    let first = p.int("first", q.get("first"), 1, 500);
    let after = p.text("after", q.get("after"), false, 0, 1024);
    let min_score = p.int("min_score", q.get("min_score"), 0, 100);
    let main_observable_type = p.text(
        "main_observable_type",
        q.get("main_observable_type"),
        false,
        0,
        64,
    );
    p.finish()?;
    let query = IndicatorQuery {
        search,
        first: first.unwrap_or_else(|| "25".into()),
        after,
        min_score,
        main_observable_type,
    };
    answer(services::search_indicators(&st.ctx.connectors, &query).await)
}

async fn entity(
    _: Reader,
    State(st): State<IntelState>,
    Path(entity_id): Path<String>,
) -> ApiResult {
    let mut p = Params::new("path");
    let entity_id = p.text("entity_id", Some(&entity_id), true, 1, 256);
    p.finish()?;
    answer(services::entity(&st.ctx.connectors, &entity_id.unwrap_or_default()).await)
}
