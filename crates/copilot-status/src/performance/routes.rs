//! `/api/performance` — `app/performance/routes/performance.py`: six
//! routes, all `require_any_scope("admin")` (they enumerate route
//! templates, live paths and timings: reconnaissance material). Query
//! parameters are validated as FastAPI does, every error collected in
//! declaration order after the token.

use axum::Router;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{self, Loc, PyError, Ty};
use copilot_upstream::respond::validation_error;
use copilot_web::{AdminOnly, ApiError, AppContext, Authorized, QueryPairs};

use super::{perf, services};

type Admin = Authorized<AdminOnly>;

/// The router, to be nested at `/api/performance` (the registries are the
/// process's; the context serves the token check).
pub fn router(ctx: AppContext) -> Router {
    Router::new()
        .route("/summary", get(summary))
        .route("/endpoints", get(endpoints))
        .route("/stalls", get(stalls))
        .route("/requests", get(requests))
        .route("/reset", post(reset))
        .route("/database", get(database))
        .with_state(ctx)
}

fn json<T: serde::Serialize>(value: &T) -> Response {
    axum::Json(value).into_response()
}

/// FastAPI's query validation, errors collected before the 422.
#[derive(Default)]
struct QueryCheck {
    errors: Vec<PyError>,
}

fn error(name: &str, kind: &'static str, msg: String, raw: &str) -> PyError {
    PyError {
        loc: vec![Loc::Key(name.to_string())],
        kind,
        msg,
        input: PyValue::Str(raw.to_string()),
    }
}

impl QueryCheck {
    fn typed(&mut self, name: &str, raw: &str, ty: &Ty) -> Option<PyValue> {
        match model::validate_ty(ty, &PyValue::Str(raw.to_string())) {
            Ok(v) => Some(v),
            Err(model::Invalid::Errors(errors)) => {
                self.errors.extend(errors.into_iter().map(|mut e| {
                    e.loc.insert(0, Loc::Key(name.to_string()));
                    e
                }));
                None
            }
            Err(model::Invalid::Abort(..)) => None,
        }
    }

    /// `int = Query(default, ge=…, le=…)`.
    fn int(&mut self, q: &QueryPairs, name: &str, default: usize, ge: i64, le: i64) -> usize {
        let Some(raw) = q.get(name) else {
            return default;
        };
        let Some(PyValue::Int(text)) = self.typed(name, raw, &Ty::Int) else {
            return default;
        };
        let n = text.parse::<i128>().unwrap_or(if text.starts_with('-') {
            i128::MIN
        } else {
            i128::MAX
        });
        if n < i128::from(ge) {
            self.errors.push(error(
                name,
                "greater_than_equal",
                format!("Input should be greater than or equal to {ge}"),
                raw,
            ));
            return default;
        }
        if n > i128::from(le) {
            self.errors.push(error(
                name,
                "less_than_equal",
                format!("Input should be less than or equal to {le}"),
                raw,
            ));
            return default;
        }
        usize::try_from(n).unwrap_or(default)
    }

    /// `float = Query(0.0, ge=0.0)` (NaN fails the bound).
    fn non_negative(&mut self, q: &QueryPairs, name: &str) -> f64 {
        let Some(raw) = q.get(name) else {
            return 0.0;
        };
        let value = match self.typed(name, raw, &Ty::Float) {
            Some(PyValue::Float(f)) => f,
            Some(PyValue::Int(text)) => text.parse().unwrap_or(0.0),
            _ => return 0.0,
        };
        if value >= 0.0 {
            value
        } else {
            self.errors.push(error(
                name,
                "greater_than_equal",
                "Input should be greater than or equal to 0".into(),
                raw,
            ));
            0.0
        }
    }

    fn finish(self) -> Result<(), ApiError> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(validation_error(self.errors, "query"))
        }
    }
}

async fn summary(_admin: Admin) -> Response {
    json(&services::summary(perf()))
}

async fn endpoints(_admin: Admin, q: QueryPairs) -> Result<Response, ApiError> {
    let mut check = QueryCheck::default();
    let limit = check.int(&q, "limit", 50, 1, 500);
    let sort_by = q.get("sort_by").unwrap_or("stalled_ms").to_string();
    check.finish()?;
    Ok(json(&services::endpoints(perf(), limit, &sort_by)))
}

async fn stalls(_admin: Admin, q: QueryPairs) -> Result<Response, ApiError> {
    let mut check = QueryCheck::default();
    let limit = check.int(&q, "limit", 50, 1, 200);
    check.finish()?;
    Ok(json(&services::stalls(perf(), limit)))
}

async fn requests(_admin: Admin, q: QueryPairs) -> Result<Response, ApiError> {
    let mut check = QueryCheck::default();
    let limit = check.int(&q, "limit", 50, 1, 500);
    let min_duration_ms = check.non_negative(&q, "min_duration_ms");
    check.finish()?;
    Ok(json(&services::requests(perf(), limit, min_duration_ms)))
}

async fn reset(_admin: Admin) -> Response {
    json(&services::reset(perf()))
}

async fn database(_admin: Admin) -> Response {
    json(&services::database(perf()))
}
