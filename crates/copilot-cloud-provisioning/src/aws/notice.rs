//! The `/root/.aws/config` half of `services/wazuh_manager.py`: the
//! manager's log read before a restart (`log_markers`) and watched after it
//! for the aws-s3 module's exit-23 error (`wait_for_profile_error`).

use std::time::Duration;

use copilot_integrations::office365::{get, json_type, truthy, wazuh};
use copilot_upstream::py::PyExc;
use copilot_wazuh::WazuhState;
use copilot_wazuh::manager::client::{self, Param};
use serde_json::Value;

/// `AWS_MODULE_LOG_TAG`.
pub const AWS_MODULE_LOG_TAG: &str = "wazuh-modulesd:aws-s3";
/// `PROFILE_ERROR_TEXT`.
pub const PROFILE_ERROR_TEXT: &str = "No profile named";
/// `RUN_FINISHED_TEXT`.
pub const RUN_FINISHED_TEXT: &str = "Fetching logs finished";

/// `PROFILE_CHECK_INTERVAL_SECONDS` and `PROFILE_CHECK_TIMEOUT_SECONDS`
/// (10 and 60). `COPILOT_AWS_PROFILE_CHECK_SECONDS="interval,timeout"`
/// shortens them for the e2e and parity suites only — never set in
/// production.
pub fn profile_check_seconds(env: &copilot_core::cloud_env::CloudEnv) -> (f64, f64) {
    env.aws_profile_check_seconds
        .as_deref()
        .and_then(|v| {
            let (i, t) = v.split_once(',')?;
            Some((i.trim().parse().ok()?, t.trim().parse().ok()?))
        })
        .filter(|(i, t): &(f64, f64)| *i > 0.0 && *t >= 0.0)
        .unwrap_or((10.0, 60.0))
}

/// `_latest_log_timestamp(search)`: the newest matching entry's
/// `timestamp` (any JSON value), `None` when there is none.
async fn latest_log_timestamp(st: &WazuhState, search: &str) -> Result<Option<Value>, PyExc> {
    let params = vec![
        ("tag".to_string(), Param::Str(AWS_MODULE_LOG_TAG.into())),
        ("search".to_string(), Param::Str(search.into())),
        ("sort".to_string(), Param::Str("-timestamp".into())),
        ("limit".to_string(), Param::Int(1)),
    ];
    let response = client::send_get(st, "/manager/logs", Some(&params))
        .await
        .map_err(wazuh)?;
    if !truthy(&response) || !get(&response, "success")?.is_some_and(truthy) {
        return Ok(None);
    }
    // `(response.get("data") or {}).get("data", {}).get("affected_items", [])`.
    let empty = Value::Object(Default::default());
    let outer = match get(&response, "data")? {
        Some(d) if truthy(d) => d,
        _ => &empty,
    };
    let inner = get(outer, "data")?.unwrap_or(&empty);
    let items = match get(inner, "affected_items")? {
        Some(v) => v,
        None => return Ok(None),
    };
    // `items[0].get("timestamp") if items else None`.
    if !truthy(items) {
        return Ok(None);
    }
    let first = match items {
        Value::Array(a) => &a[0],
        Value::Object(_) => return Err(PyExc::KeyError("0".into())),
        Value::String(_) => {
            return Err(PyExc::AttributeError(
                "'str' object has no attribute 'get'".into(),
            ));
        }
        other => {
            return Err(PyExc::TypeError(format!(
                "'{}' object is not subscriptable",
                json_type(other)
            )));
        }
    };
    Ok(get(first, "timestamp")?.cloned())
}

/// `datetime.fromisoformat(text.replace("Z", "+00:00"))` as a comparable
/// instant: `(aware, microseconds)`.
fn instant(text: &str) -> Result<(bool, i64), String> {
    let parsed = copilot_ingest::py::fromisoformat(&text.replace('Z', "+00:00"))?;
    let micros = parsed.wall.and_utc().timestamp_micros();
    Ok(match parsed.offset_us {
        Some(offset) => (true, micros - offset),
        None => (false, micros),
    })
}

/// `a > b` on two JSON values where `a` is a `str`.
fn py_greater(a: &str, b: &Value) -> Result<bool, PyExc> {
    match b {
        Value::String(b) => Ok(a > b.as_str()),
        other => Err(PyExc::TypeError(format!(
            "'>' not supported between instances of 'str' and '{}'",
            json_type(other)
        ))),
    }
}

/// `x.replace("Z", "+00:00")` on a JSON value.
fn replaced(v: &Value) -> Result<String, PyExc> {
    match v {
        Value::String(s) => Ok(s.replace('Z', "+00:00")),
        other => Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'replace'",
            json_type(other)
        ))),
    }
}

/// `_is_after(timestamp, marker)`: both parsed by `fromisoformat` (left
/// first), compared as datetimes, else as they are.
pub(crate) fn is_after(timestamp: Option<&Value>, marker: Option<&Value>) -> Result<bool, PyExc> {
    let Some(timestamp) = timestamp.filter(|t| truthy(t)) else {
        return Ok(false);
    };
    let Some(marker) = marker.filter(|m| truthy(m)) else {
        return Ok(true);
    };
    let left = replaced(timestamp)?;
    let fallback = |t: &str| py_greater(t, marker);
    let Ok(left) = instant(&left) else {
        return match timestamp {
            Value::String(t) => fallback(t),
            _ => Ok(false),
        };
    };
    let right = replaced(marker)?;
    let Ok(right) = instant(&right) else {
        return match timestamp {
            Value::String(t) => fallback(t),
            _ => Ok(false),
        };
    };
    if left.0 != right.0 {
        return Err(PyExc::TypeError(
            "can't compare offset-naive and offset-aware datetimes".into(),
        ));
    }
    Ok(left.1 > right.1)
}

/// `log_markers()`: the newest exit-23 and run-finished entries before a
/// change.
pub async fn log_markers(st: &WazuhState) -> Result<(Option<Value>, Option<Value>), PyExc> {
    Ok((
        latest_log_timestamp(st, PROFILE_ERROR_TEXT).await?,
        latest_log_timestamp(st, RUN_FINISHED_TEXT).await?,
    ))
}

/// `wait_for_profile_error(markers)`: whether the exit-23 error appeared
/// after the restart (best effort: a finished run ends the watch early).
pub async fn wait_for_profile_error(
    st: &WazuhState,
    env: &copilot_core::cloud_env::CloudEnv,
    markers: &(Option<Value>, Option<Value>),
) -> Result<bool, PyExc> {
    let (interval, timeout) = profile_check_seconds(env);
    let mut waited = 0.0;
    while waited < timeout {
        tokio::time::sleep(Duration::from_secs_f64(interval)).await;
        waited += interval;
        let error = latest_log_timestamp(st, PROFILE_ERROR_TEXT).await?;
        if is_after(error.as_ref(), markers.0.as_ref())? {
            tracing::warn!(
                "The aws-s3 module reported a missing [default] profile in /root/.aws/config \
                 after the restart."
            );
            return Ok(true);
        }
        let finished = latest_log_timestamp(st, RUN_FINISHED_TEXT).await?;
        if is_after(finished.as_ref(), markers.1.as_ref())? {
            return Ok(false);
        }
    }
    Ok(false)
}
