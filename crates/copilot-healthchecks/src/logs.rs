//! `POST /api/healthcheck/logs` (`get_host_logs`): whether the Wazuh
//! indexer holds a recent log of one host.
//!
//! In Python's order: the host's tenant (`enforce_hostname_access`: the
//! first agent with that hostname decides, an unknown host is refused to a
//! scoped caller), the host itself (404), then `host_logs`: the open indices
//! (`collect_indices`), and per index the `LogsQueryBuilder` query — the time
//! range (`m`, `h`, `d`, `w`; CPython's `int()`, `timedelta` and `datetime`
//! limits), the `log_field` match, the `agent_name` phrase, the sort — sent as
//! the sync elasticsearch7 client sends `search(index, body, size)`, stopping
//! at the first index with a hit. A failing search is skipped, as Python's
//! `except` skips it. The answer says healthy or not; the logs it found are
//! not in it (`HostLogsSearchResponse`'s `logs_summary` keeps its default).

use axum::Router;
use axum::extract::State;
use axum::response::Response;
use axum::routing::post;
use chrono::{Duration, NaiveDate};
use http::Method;
use serde_json::{Value, json};

use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_upstream::model::{Check, Field, Model, Ty};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_upstream::respond::{body_model, model_response};
use copilot_wazuh::WazuhState;
use copilot_wazuh::error::PyErr;
use copilot_wazuh::es::make_path;
use copilot_wazuh::indexer::services::alerts::{isoformat, time_range_query};
use copilot_wazuh::indexer::services::{client, collect_indices};
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized, WithJson};

fn one() -> PyValue {
    PyValue::Int("1".into())
}

fn day() -> PyValue {
    PyValue::Str("24h".into())
}

fn syslog_level() -> PyValue {
    PyValue::Str("syslog_level".into())
}

fn info() -> PyValue {
    PyValue::Str("INFO".into())
}

fn timestamp_utc() -> PyValue {
    PyValue::Str("timestamp_utc".into())
}

/// `validate_timerange` (an empty value is the `IndexError` of `value[-1]`,
/// handled before validation: see [`host_logs`]).
fn check_timerange(v: &PyValue) -> Result<PyValue, Check> {
    let PyValue::Str(text) = v else {
        return Ok(v.clone());
    };
    if !matches!(text.chars().last(), Some('h' | 'd' | 'w' | 'm')) {
        return Err(Check::ValueError(
            "Invalid timerange format. The string should end with either 'h', 'd', 'w', or 'm'."
                .into(),
        ));
    }
    let mut prefix = text.chars();
    prefix.next_back();
    let prefix = prefix.as_str();
    if prefix.is_empty() || !prefix.chars().all(copilot_jinja::unicode::is_digit) {
        return Err(Check::ValueError(
            "Invalid timerange format. The string should start with a number.".into(),
        ));
    }
    Ok(v.clone())
}

/// `HostLogsSearchBody`.
pub static HOST_LOGS_SEARCH_BODY: Model = Model::new(
    "HostLogsSearchBody",
    &[
        Field::def("size", Ty::Int, one),
        Field::def("timerange", Ty::Str, day).after(check_timerange),
        Field::def("log_field", Ty::Str, syslog_level),
        Field::def("log_value", Ty::Str, info),
        Field::def("timestamp_field", Ty::Str, timestamp_utc),
        Field::req("agent_name", Ty::Str),
    ],
);

/// `timedelta`'s limit: `|days| <= 999999999`.
const MAX_DAYS: i128 = 999_999_999;
/// The C `int` conversion of `timedelta`'s normalised days.
const TOO_LARGE: &str = "Python int too large to convert to C int";

fn overflow(text: impl Into<String>) -> PyExc {
    PyExc::Other("OverflowError", text.into())
}

/// `int(text)` (base 10) as CPython 3.11 parses a `str`; `Ok(None)` when
/// it does not fit 128 bits.
fn py_int(text: &str) -> PyResult<Option<i128>> {
    let invalid = || {
        let mut r = str_repr(text);
        if r.chars().count() > 200 {
            r = r.chars().take(200).collect();
        }
        PyExc::ValueError(format!("invalid literal for int() with base 10: {r}"))
    };
    let ascii: String = text
        .chars()
        .map(|c| {
            if c.is_ascii() {
                c
            } else if copilot_jinja::unicode::is_space(c) {
                ' '
            } else if let Some(d) = copilot_jinja::unicode::decimal_value(c) {
                char::from_digit(d, 10).unwrap_or('?')
            } else {
                '?'
            }
        })
        .collect();
    let t = ascii.trim_matches(|c: char| c == ' ' || ('\t'..='\r').contains(&c));
    let (negative, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let bytes = digits.as_bytes();
    if bytes.is_empty()
        || bytes[0] == b'_'
        || bytes[bytes.len() - 1] == b'_'
        || digits.contains("__")
        || !bytes.iter().all(|b| b.is_ascii_digit() || *b == b'_')
    {
        return Err(invalid());
    }
    let clean = digits.replace('_', "");
    if clean.len() > 4300 {
        return Err(PyExc::ValueError(format!(
            "Exceeds the limit (4300 digits) for integer string conversion: value has {} \
             digits; use sys.set_int_max_str_digits() to increase the limit",
            clean.len()
        )));
    }
    Ok(clean
        .parse::<i128>()
        .ok()
        .map(|n| if negative { -n } else { n }))
}

/// `LogsQueryBuilder._get_time_range_start(timerange)`.
pub fn time_range_start(timerange: &str) -> PyResult<String> {
    let (per_unit, amount) = if let Some(a) = timerange.strip_suffix('m') {
        (60i128, a)
    } else if let Some(a) = timerange.strip_suffix('h') {
        (3600, a)
    } else if let Some(a) = timerange.strip_suffix('d') {
        (86_400, a)
    } else if let Some(a) = timerange.strip_suffix('w') {
        (604_800, a)
    } else {
        return Err(PyExc::ValueError(
            "Invalid timerange format. Expected a string like '24h', '1d', '1w', '1m', etc.".into(),
        ));
    };
    let n = py_int(amount)?.ok_or_else(|| overflow(TOO_LARGE))?;
    let seconds = n.checked_mul(per_unit).ok_or_else(|| overflow(TOO_LARGE))?;
    let days = seconds.div_euclid(86_400);
    if days > i128::from(i32::MAX) || days < i128::from(i32::MIN) {
        return Err(overflow(TOO_LARGE));
    }
    if days.abs() > MAX_DAYS {
        return Err(overflow(format!(
            "days={days}; must have magnitude <= 999999999"
        )));
    }
    let delta = Duration::try_seconds(i64::try_from(seconds).unwrap_or(i64::MAX))
        .ok_or_else(|| overflow("date value out of range"))?;
    let start = copilot_core::time::now_utc_micros()
        .checked_sub_signed(delta)
        .ok_or_else(|| overflow("date value out of range"))?;
    let min = NaiveDate::from_ymd_opt(1, 1, 1)
        .unwrap_or_default()
        .and_hms_opt(0, 0, 0)
        .unwrap_or_default();
    let max = NaiveDate::from_ymd_opt(9999, 12, 31)
        .unwrap_or_default()
        .and_hms_micro_opt(23, 59, 59, 999_999)
        .unwrap_or_default();
    if start < min || start > max {
        return Err(overflow("date value out of range"));
    }
    Ok(format!("{}Z", isoformat(start)))
}

/// The validated body.
#[derive(Debug, Clone)]
struct Search {
    size: String,
    timerange: String,
    log_field: String,
    log_value: String,
    timestamp_field: String,
    agent_name: String,
}

impl Search {
    fn of(dump: &PyValue) -> Self {
        let text = |k: &str| match dump.get(k) {
            Some(PyValue::Str(s)) => s.clone(),
            Some(PyValue::Int(i)) => i.clone(),
            _ => String::new(),
        };
        Self {
            size: text("size"),
            timerange: text("timerange"),
            log_field: text("log_field"),
            log_value: text("log_value"),
            timestamp_field: text("timestamp_field"),
            agent_name: text("agent_name"),
        }
    }

    /// `LogsQueryBuilder` with the host's phrase.
    fn query(&self) -> PyResult<Value> {
        let start = time_range_start(&self.timerange)?;
        Ok(json!({
            "query": {"bool": {"must": [
                time_range_query(&self.timestamp_field, &start, "now"),
                {"match": {self.log_field.clone(): self.log_value}},
                {"match_phrase": {"agent_name": self.agent_name}},
            ]}},
            "sort": [{self.timestamp_field.clone(): {"order": "desc"}}],
        }))
    }
}

/// `collect_logs_generic(index, body, is_host_specific=True)`: the hits, or
/// `None` where Python's `try` caught the failure.
async fn collect_logs(
    st: &WazuhState,
    index: &str,
    search: &Search,
) -> Result<Option<usize>, ApiError> {
    let es = match client(st).await {
        Ok(es) => es,
        // `create_wazuh_indexer_client` raises before the `try`: an
        // `HTTPException` is the loop's warning, anything else escapes.
        Err(e @ PyErr::Http { .. }) => {
            tracing::warn!(
                "An error occurred while processing index {index}: {}",
                e.detail().unwrap_or_default()
            );
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    };
    let query = search.query().map_err(PyExc::unhandled)?;
    let path = make_path(&[index, "_search"]);
    let answer = es
        .perform(
            Method::POST,
            &path,
            &[("size", search.size.clone())],
            Some(&query),
        )
        .await;
    match answer {
        Ok(v) => {
            // `[log for log in logs["hits"]["hits"]]` validated as
            // `List[Dict[str, Any]]`: anything else is caught (`None`); an
            // empty string iterates to no logs.
            let hits = match v.get("hits").and_then(|h| h.get("hits")) {
                Some(Value::Array(items)) if items.iter().all(Value::is_object) => {
                    Some(items.len())
                }
                Some(Value::String(t)) if t.is_empty() => Some(0),
                Some(Value::Object(m)) if m.is_empty() => Some(0),
                Some(Value::Array(items)) if items.is_empty() => Some(0),
                _ => None,
            };
            if hits.is_none() {
                tracing::debug!("Failed to collect logs: unexpected answer");
            }
            Ok(hits)
        }
        Err(e) => {
            tracing::debug!("Failed to collect logs: {e}");
            Ok(None)
        }
    }
}

/// `select(Agents.customer_code).where(Agents.hostname == h)`, first.
async fn owner_of(st: &WazuhState, hostname: &str) -> Result<Option<String>, ApiError> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT agents.customer_code FROM agents WHERE agents.hostname = ?")
            .bind(hostname)
            .fetch_optional(st.ctx.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(row.and_then(|(c,)| c))
}

async fn host_exists(st: &WazuhState, hostname: &str) -> Result<bool, ApiError> {
    let row: Option<(i32,)> =
        sqlx::query_as("SELECT agents.id FROM agents WHERE agents.hostname = ?")
            .bind(hostname)
            .fetch_optional(st.ctx.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(row.is_some())
}

/// `POST /logs`.
async fn host_logs(
    State(st): State<WazuhState>,
    WithJson(auth, body): WithJson<Authorized<AdminOrAnalyst>>,
) -> ApiResult {
    // `value[-1]` of an empty `timerange` is an `IndexError` that leaves
    // validation as it is: uvicorn's bare 500, whatever else the body holds.
    if let copilot_web::JsonBody::Value(Value::Object(map)) = &body {
        if map.get("timerange") == Some(&Value::String(String::new())) {
            return Err(ApiError::internal(
                "IndexError: string index out of range".to_string(),
            ));
        }
    }
    let dump = body_model(&body, &HOST_LOGS_SEARCH_BODY)?;
    let search = Search::of(&dump);
    tracing::info!(
        "Received request to get host logs for {}",
        search.agent_name
    );
    let owner = owner_of(&st, &search.agent_name).await?;
    auth.enforce_owned(
        &st.ctx,
        owner.as_deref(),
        &format!("host {}", search.agent_name),
    )
    .await?;
    if !host_exists(&st, &search.agent_name).await? {
        return Err(ApiError::not_found(format!(
            "Agent with hostname {} not found",
            search.agent_name
        )));
    }
    let indices = collect_indices(&st, false).await?;
    let mut total = 0usize;
    for index in &indices {
        if let Some(n) = collect_logs(&st, index, &search).await? {
            if n > 0 {
                total += n;
                break;
            }
        }
    }
    let (healthy, message) = if total > 0 {
        (
            true,
            format!(
                "Host is healthy. At least one log was found within the specified time range of {}",
                search.timerange
            ),
        )
    } else {
        (
            false,
            format!(
                "Host is unhealthy. No logs were found within the specified time range of {}",
                search.timerange
            ),
        )
    };
    Ok(response(healthy, message))
}

fn response(healthy: bool, message: String) -> Response {
    model_response(&PyValue::Dict(vec![
        ("logs_summary".into(), PyValue::List(Vec::new())),
        ("healthy".into(), PyValue::Bool(healthy)),
        ("success".into(), PyValue::Bool(true)),
        ("message".into(), PyValue::Str(message)),
    ]))
}

/// `POST /api/healthcheck/logs`, at its full path.
pub fn router(state: WazuhState) -> Router {
    Router::new()
        .route("/api/healthcheck/logs", post(host_logs))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_ranges_follow_python() {
        assert!(time_range_start("15m").unwrap().ends_with('Z'));
        assert_eq!(
            time_range_start("\u{b2}h").unwrap_err().text(),
            "invalid literal for int() with base 10: '\u{b2}'"
        );
        assert_eq!(
            time_range_start("1000000000d").unwrap_err().text(),
            "days=1000000000; must have magnitude <= 999999999"
        );
        assert_eq!(
            time_range_start("1000000000000d").unwrap_err().text(),
            "Python int too large to convert to C int"
        );
        assert_eq!(
            check_timerange(&PyValue::Str("5x".into())),
            Err(Check::ValueError(
                "Invalid timerange format. The string should end with either 'h', 'd', 'w', or \
                 'm'."
                    .into()
            ))
        );
        assert_eq!(
            check_timerange(&PyValue::Str("h".into())),
            Err(Check::ValueError(
                "Invalid timerange format. The string should start with a number.".into()
            ))
        );
        assert!(check_timerange(&PyValue::Str("\u{b2}h".into())).is_ok());
    }
}
