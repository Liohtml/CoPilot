//! `app/integrations/aws/services/wazuh_manager.py` (the half the delete
//! shares with provisioning): one instance's buckets applied to the Wazuh
//! manager, every write guarded so it can never amount to more than them.
//!
//! 1. The live `ossec.conf` read and reconciled ([`super::config`]).
//! 2. Re-read right before writing: changed in between, the edit starts
//!    over once from the new file, then the request fails (409).
//! 3. Written, then validated by the manager (`GET
//!    /manager/configuration/validation`); refused or unanswered, the
//!    original is written back and nothing restarts.
//! 4. Restarted after a clean validation.
//!
//! Every step runs under [`WAZUH_CONFIG_LOCK`], one per process, as Python's
//! `asyncio.Lock` is one per Python process: two AWS deployments (or a
//! deployment and a delete) in this process cannot interleave. Across the two
//! processes, step 2 is what keeps one from undoing the other's edit.

use copilot_upstream::py::PyExc;
use copilot_wazuh::WazuhState;
use copilot_wazuh::manager::client::{self, Body, Param, PutKind};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::etree::Element;
use crate::office365::{equals_zero, get, json_type, repr, truthy, wazuh};

use super::config::{ConfigError, ReconcileResult, reconcile_aws_buckets};

/// `WAZUH_CONFIG_LOCK`.
pub static WAZUH_CONFIG_LOCK: Mutex<()> = Mutex::const_new(());

/// `(response or {}).get('message', 'no response')`, as an f-string writes
/// it.
fn message_of(response: &Value) -> Result<String, PyExc> {
    if !truthy(response) {
        return Ok("no response".into());
    }
    Ok(match get(response, "message")? {
        Some(Value::String(s)) => s.clone(),
        Some(other) => copilot_upstream::respond::from_json(other).py_str(),
        None => "no response".into(),
    })
}

/// `get_manager_configuration()`: `response["data"]` (the raw file).
pub async fn get_manager_configuration(st: &WazuhState) -> Result<Value, PyExc> {
    let params = vec![("raw".to_string(), Param::Bool(true))];
    let response = client::send_get(st, "/manager/configuration", Some(&params))
        .await
        .map_err(wazuh)?;
    let ok = truthy(&response)
        && get(&response, "success")?.is_some_and(truthy)
        && get(&response, "data")?.is_some();
    if !ok {
        return Err(PyExc::http(
            502,
            format!(
                "Could not read the Wazuh manager's ossec.conf: {}",
                message_of(&response)?
            ),
        ));
    }
    Ok(get(&response, "data")?.cloned().unwrap_or(Value::Null))
}

/// The configuration as the `str` the reconcile reads (`raw.strip()` on
/// anything else is its `AttributeError`).
pub fn as_text(raw: &Value) -> Result<String, PyExc> {
    match raw {
        Value::String(s) => Ok(s.clone()),
        other if !truthy(other) => Ok(String::new()),
        other => Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'strip'",
            json_type(other)
        ))),
    }
}

/// `push_manager_configuration(config)`.
pub async fn push_manager_configuration(st: &WazuhState, config: &str) -> Result<(), PyExc> {
    let response = client::send_put(
        st,
        "/manager/configuration",
        Some(Body::Bytes(config.as_bytes().to_vec())),
        None,
        PutKind::Binary,
    )
    .await
    .map_err(wazuh)?;
    let accepted = truthy(&response) && get(&response, "success")?.is_some_and(truthy) && {
        let data = match get(&response, "data")? {
            Some(d) => d.clone(),
            None => Value::Object(Default::default()),
        };
        get(&data, "error")?.is_some_and(equals_zero)
    };
    if !accepted {
        return Err(PyExc::http(
            502,
            format!(
                "The Wazuh manager rejected the new ossec.conf: {}",
                message_of(&response)?
            ),
        ));
    }
    Ok(())
}

/// `restart_manager()` (its answer is not looked at).
pub async fn restart_manager(st: &WazuhState) -> Result<(), PyExc> {
    tracing::info!("Restarting the Wazuh manager to apply the aws-s3 configuration.");
    client::send_put(st, "/manager/restart", None, None, PutKind::Json)
        .await
        .map_err(wazuh)?;
    Ok(())
}

/// `iter(value)` over a JSON value: a list's items, a dict's keys, a
/// string's characters; anything else is the `TypeError`.
fn iterate(v: &Value) -> Result<Vec<Value>, PyExc> {
    match v {
        Value::Array(items) => Ok(items.clone()),
        Value::Object(m) => Ok(m.keys().map(|k| Value::String(k.clone())).collect()),
        Value::String(s) => Ok(s.chars().map(|c| Value::String(c.to_string())).collect()),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not iterable",
            json_type(other)
        ))),
    }
}

/// `validate_manager_configuration()`: `None` when valid, otherwise why
/// not.
pub async fn validate_manager_configuration(st: &WazuhState) -> Result<Option<String>, PyExc> {
    let response = client::send_get(st, "/manager/configuration/validation", None)
        .await
        .map_err(wazuh)?;
    if !truthy(&response) || !get(&response, "success")?.is_some_and(truthy) {
        return Ok(Some(format!(
            "the manager could not validate it ({})",
            message_of(&response)?
        )));
    }
    let outer = match get(&response, "data")? {
        Some(d) if truthy(d) => d.clone(),
        _ => Value::Object(Default::default()),
    };
    let data = match get(&outer, "data")? {
        Some(d) if truthy(d) => d.clone(),
        _ => Value::Object(Default::default()),
    };
    let total_failed = get(&data, "total_failed_items")?.is_some_and(truthy);
    if total_failed || get(&data, "failed_items")?.is_some_and(truthy) {
        let failed = get(&data, "failed_items")?.cloned().unwrap_or(Value::Null);
        return Ok(Some(format!(
            "the manager reported it invalid: {}",
            repr(&failed)
        )));
    }
    let items = match get(&data, "affected_items")? {
        Some(v) => iterate(v)?,
        None => Vec::new(),
    };
    let mut statuses: Vec<Value> = Vec::new();
    for item in &items {
        let status = get(item, "status")?.cloned().unwrap_or(Value::Null);
        if matches!(status, Value::Array(_) | Value::Object(_)) {
            return Err(PyExc::TypeError(format!(
                "unhashable type: '{}'",
                json_type(&status)
            )));
        }
        if !statuses.contains(&status) {
            statuses.push(status);
        }
    }
    let only_ok = statuses.len() == 1 && statuses[0] == Value::String("OK".into());
    if !statuses.is_empty() && !only_ok {
        let affected = get(&data, "affected_items")?
            .cloned()
            .unwrap_or(Value::Null);
        return Ok(Some(format!(
            "the manager reported it invalid: {}",
            repr(&affected)
        )));
    }
    Ok(None)
}

/// `_write_guarded(original, updated)`.
async fn write_guarded(st: &WazuhState, original: &Value, updated: &str) -> Result<(), PyExc> {
    if let Err(e) = push_manager_configuration(st, updated).await {
        if !e.is_http() {
            return Err(e);
        }
        let current = get_manager_configuration(st).await?;
        if &current != original {
            push_manager_configuration(st, &as_text(original)?).await?;
        }
        return Err(e);
    }
    if let Some(problem) = validate_manager_configuration(st).await? {
        tracing::error!(
            "The new ossec.conf did not validate ({problem}); restoring the previous \
             configuration."
        );
        push_manager_configuration(st, &as_text(original)?).await?;
        return Err(PyExc::http(
            502,
            format!(
                "The new ossec.conf did not validate: {problem}. The previous configuration was \
                 restored and the manager was not restarted."
            ),
        ));
    }
    Ok(())
}

/// A reconcile refusal as `apply_instance_buckets` raises it: the 400, or
/// the `ParseError` that escapes it.
pub fn config_exc(e: ConfigError) -> PyExc {
    match e {
        ConfigError::Refused(m) => PyExc::http(400, m),
        ConfigError::Parse(m) => PyExc::Other("ParseError", m),
    }
}

/// `apply_instance_buckets(desired, bucket_name, account_id, adopt_existing,
/// keep_only_logs_after)`: writes and restarts only when something changed.
pub async fn apply_instance_buckets(
    st: &WazuhState,
    desired: &[Element],
    bucket_name: &str,
    account_id: &str,
    adopt_existing: bool,
    keep_only_logs_after: bool,
) -> Result<ReconcileResult, PyExc> {
    let _guard = WAZUH_CONFIG_LOCK.lock().await;
    let mut ready: Option<(Value, ReconcileResult)> = None;
    for attempt in 1..=2 {
        let raw = get_manager_configuration(st).await?;
        let result = reconcile_aws_buckets(
            &as_text(&raw)?,
            desired,
            bucket_name,
            account_id,
            adopt_existing,
            keep_only_logs_after,
        )
        .map_err(config_exc)?;
        if !result.changed {
            tracing::info!(
                "aws-s3 buckets for {bucket_name} / {account_id} already match; the Wazuh \
                 manager is not restarted."
            );
            return Ok(result);
        }
        if get_manager_configuration(st).await? == raw {
            ready = Some((raw, result));
            break;
        }
        tracing::warn!(
            "ossec.conf changed while it was being edited (attempt {attempt}); starting over \
             from the new file."
        );
    }
    let Some((raw, result)) = ready else {
        return Err(PyExc::http(
            409,
            "ossec.conf kept changing on the Wazuh manager while CoPilot was editing it; nothing \
             was written. Try again.",
        ));
    };
    write_guarded(st, &raw, &result.config).await?;
    tracing::info!(
        "aws-s3 buckets for {bucket_name} / {account_id}: added {:?}, updated {:?}, removed {:?}.",
        result.added,
        result.updated,
        result.removed
    );
    restart_manager(st).await?;
    Ok(result)
}
