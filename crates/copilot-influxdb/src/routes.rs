//! `/api/influxdb/*` — port of `app/connectors/influxdb/routes/` (`alerts.py`
//! under `/influxdb`, `metrics.py` under `/influxdb/metrics`): 10 routes,
//! all `require_any_scope("admin", "analyst")`, with FastAPI's query
//! validation (declaration order, every error collected). InfluxDB data is
//! deployment-wide: no route is tenant-scoped, as in Python.

use axum::Router;
use axum::extract::State;
use axum::routing::get;
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{self, Loc, PyError, Ty};
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::{model_response, validation_error};
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, QueryPairs};

use crate::client::InfluxClient;
use crate::schema::{ALERT_STATUSES, SEVERITY_FILTERS};
use crate::services::{self, AlertParams, Metrics};

/// Route state.
#[derive(Debug, Clone)]
pub struct InfluxState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The InfluxDB client.
    pub client: InfluxClient,
}

impl axum::extract::FromRef<InfluxState> for AppContext {
    fn from_ref(s: &InfluxState) -> AppContext {
        s.ctx.clone()
    }
}

type Reader = Authorized<AdminOrAnalyst>;

/// The router, to be nested at `/api/influxdb`.
pub fn router(state: InfluxState) -> Router {
    Router::new()
        .route("/alerts", get(alerts))
        .route("/check-names", get(check_names))
        .route("/metrics/hosts", get(hosts))
        .route("/metrics/summary", get(summary))
        .route("/metrics/cpu", get(cpu))
        .route("/metrics/memory", get(memory))
        .route("/metrics/kernel", get(kernel))
        .route("/metrics/disks", get(disks))
        .route("/metrics/processes", get(processes))
        .route("/metrics/network", get(network))
        .with_state(state)
}

fn answer(result: Result<PyValue, PyExc>) -> ApiResult {
    result
        .map(|dump| model_response(&dump))
        .map_err(PyExc::unhandled)
}

/// Query parameters read the way FastAPI does: every error is collected
/// (in declaration order) before the 422.
#[derive(Default)]
struct QueryCheck {
    errors: Vec<PyError>,
}

fn error(loc: Vec<Loc>, kind: &'static str, msg: String, input: &str) -> PyError {
    PyError {
        loc,
        kind,
        msg,
        input: PyValue::Str(input.to_string()),
    }
}

/// Pydantic's `'a', 'b' or 'c'`.
fn expected(values: &[&str]) -> String {
    let quoted: Vec<String> = values.iter().map(|v| format!("'{v}'")).collect();
    match quoted.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
        Some((last, _)) => last.clone(),
        None => String::new(),
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
    fn int(&mut self, q: &QueryPairs, name: &str, default: i64, ge: i64, le: i64) -> i64 {
        let Some(raw) = q.get(name) else {
            return default;
        };
        let Some(PyValue::Int(text)) = self.typed(name, raw, &Ty::Int) else {
            return default;
        };
        // An integer too large for i128 is past either bound by its sign.
        let n = text.parse::<i128>().unwrap_or(if text.starts_with('-') {
            i128::MIN
        } else {
            i128::MAX
        });
        let loc = vec![Loc::Key(name.to_string())];
        if n < i128::from(ge) {
            self.errors.push(error(
                loc,
                "greater_than_equal",
                format!("Input should be greater than or equal to {ge}"),
                raw,
            ));
            return default;
        }
        if n > i128::from(le) {
            self.errors.push(error(
                loc,
                "less_than_equal",
                format!("Input should be less than or equal to {le}"),
                raw,
            ));
            return default;
        }
        i64::try_from(n).unwrap_or(default)
    }

    fn bool(&mut self, q: &QueryPairs, name: &str) -> bool {
        match q.get(name) {
            None => false,
            Some(raw) => matches!(self.typed(name, raw, &Ty::Bool), Some(PyValue::Bool(true))),
        }
    }

    fn enum_value(&mut self, loc: Vec<Loc>, raw: &str, allowed: &[&str]) -> Option<String> {
        if allowed.contains(&raw) {
            return Some(raw.to_string());
        }
        self.errors.push(error(
            loc,
            "enum",
            format!("Input should be {}", expected(allowed)),
            raw,
        ));
        None
    }

    fn finish<T>(self, value: T) -> Result<T, ApiError> {
        if self.errors.is_empty() {
            Ok(value)
        } else {
            Err(validation_error(self.errors, "query"))
        }
    }
}

/// `get_alerts_route`'s parameters.
fn alert_params(q: &QueryPairs) -> Result<AlertParams, ApiError> {
    let mut check = QueryCheck::default();
    let days = check.int(q, "days", 7, 1, 90);
    let raw_severity = q.get_all("severity");
    let severity = if raw_severity.is_empty() {
        None
    } else {
        let mut out = Vec::new();
        for (i, raw) in raw_severity.iter().enumerate() {
            let loc = vec![Loc::Key("severity".into()), Loc::Index(i)];
            if let Some(v) = check.enum_value(loc, raw, &SEVERITY_FILTERS) {
                out.push(v);
            }
        }
        Some(out)
    };
    let check_name = q.get("check_name").map(str::to_string);
    let sensor_type = q.get("sensor_type").map(str::to_string);
    let status = match q.get("status") {
        None => "all".to_string(),
        Some(raw) => check
            .enum_value(vec![Loc::Key("status".into())], raw, &ALERT_STATUSES)
            .unwrap_or_default(),
    };
    let latest_only = check.bool(q, "latest_only");
    let exclude_ok = check.bool(q, "exclude_ok");
    let limit = check.int(q, "limit", 500, 1, 1000);
    check.finish(AlertParams {
        days,
        severity,
        check_name,
        sensor_type,
        status,
        latest_only,
        exclude_ok,
        limit: Some(limit),
    })
}

/// `host: str = Query(...)`, `range_h: str = Query("1")`.
fn host_and_range(q: &QueryPairs) -> Result<(String, String), ApiError> {
    let mut check = QueryCheck::default();
    let host = match q.get("host") {
        Some(h) => h.to_string(),
        None => {
            check.errors.push(PyError {
                loc: vec![Loc::Key("host".into())],
                kind: "missing",
                msg: "Field required".into(),
                input: PyValue::None,
            });
            String::new()
        }
    };
    let range_h = q.get("range_h").unwrap_or("1").to_string();
    check.finish((host, range_h))
}

async fn alerts(_: Reader, State(st): State<InfluxState>, q: QueryPairs) -> ApiResult {
    let params = alert_params(&q)?;
    answer(services::alerts(&st.client, &params).await)
}

async fn check_names(_: Reader, State(st): State<InfluxState>) -> ApiResult {
    answer(services::check_names(&st.client).await)
}

async fn hosts(_: Reader, State(st): State<InfluxState>) -> ApiResult {
    answer(services::hosts(&st.client).await)
}

async fn metrics(st: &InfluxState, q: &QueryPairs, route: Metrics) -> ApiResult {
    let (host, range_h) = host_and_range(q)?;
    answer(services::metrics(&st.client, &route, &host, &range_h).await)
}

async fn summary(_: Reader, State(st): State<InfluxState>, q: QueryPairs) -> ApiResult {
    metrics(&st, &q, Metrics::summary()).await
}

async fn cpu(_: Reader, State(st): State<InfluxState>, q: QueryPairs) -> ApiResult {
    metrics(&st, &q, Metrics::cpu()).await
}

async fn memory(_: Reader, State(st): State<InfluxState>, q: QueryPairs) -> ApiResult {
    metrics(&st, &q, Metrics::memory()).await
}

async fn kernel(_: Reader, State(st): State<InfluxState>, q: QueryPairs) -> ApiResult {
    metrics(&st, &q, Metrics::kernel()).await
}

async fn disks(_: Reader, State(st): State<InfluxState>, q: QueryPairs) -> ApiResult {
    metrics(&st, &q, Metrics::disks()).await
}

async fn processes(_: Reader, State(st): State<InfluxState>, q: QueryPairs) -> ApiResult {
    metrics(&st, &q, Metrics::processes()).await
}

async fn network(_: Reader, State(st): State<InfluxState>, q: QueryPairs) -> ApiResult {
    metrics(&st, &q, Metrics::network()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errors(query: &str) -> Vec<String> {
        match alert_params(&QueryPairs::parse(Some(query))) {
            Ok(_) => Vec::new(),
            Err(ApiError::Validation(items)) => items
                .into_iter()
                .map(|i| format!("{} {}", i.field, i.message.unwrap_or_default()))
                .collect(),
            Err(other) => vec![other.to_string()],
        }
    }

    #[test]
    fn alert_parameters_validate_like_fastapi() {
        let p = alert_params(&QueryPairs::parse(Some(
            "days=30&severity=ok&severity=critical&status=active&latest_only=yes&limit=10",
        )))
        .unwrap();
        assert_eq!(p.days, 30);
        assert_eq!(p.severity, Some(vec!["ok".into(), "critical".into()]));
        assert!(p.latest_only && !p.exclude_ok);
        assert_eq!(p.limit, Some(10));
        assert_eq!(
            errors("days=0&severity=bad&status=x&exclude_ok=maybe&limit=1001"),
            [
                "days Value is too small.",
                "0 Value is not a valid enumeration member.",
                "status Value is not a valid enumeration member.",
                "exclude_ok exclude_ok: Input should be a valid boolean, unable to interpret input",
                "limit Value is too large.",
            ]
        );
        assert_eq!(errors("days="), ["days Input is not a valid integer."]);
    }
}
