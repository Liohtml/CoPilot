//! `app/integrations/office365/services/decommission.py`: stop the Wazuh
//! manager collecting from one Microsoft 365 tenant.
//!
//! The manager's `ossec.conf` is read raw (`GET /manager/configuration
//! ?raw=True`), the tenant's `<api_auth>` blocks are taken out of the root's
//! `<office365>` blocks with [`crate::etree`] (an `<office365>` left without
//! one goes too — Wazuh refuses it), and when anything was removed the file
//! is written back (`PUT /manager/configuration`, octet-stream) and the
//! manager restarted. The surviving tenants' blocks stay exactly as they
//! were.
//!
//! Python also keeps a copy of the edited file next to its module
//! (`wazuh_decommission_config.xml`, on the Python host); the Rust service
//! does not write one (RUST_MIGRATION.md §4): it has no `backend/` tree, and
//! the file holds every tenant's client secret.

use copilot_upstream::py::PyExc;
use copilot_wazuh::WazuhState;
use copilot_wazuh::error::PyErr;
use copilot_wazuh::manager::client::{self, Body, Param, PutKind};
use copilot_web::form::py_strip;
use serde_json::Value;

use crate::etree::{self, Element};

/// What a failed parse becomes (the `HTTPException` of
/// `remove_api_auth_block`).
pub const PARSE_FAILURE: &str =
    "Could not parse ossec.conf. Remove the Office365 api_auth block manually.";

/// `remove_api_auth_block(config, tenant_id)`: the new configuration, `None`
/// when the tenant is not configured, `Err` when the text is not XML.
pub fn remove_api_auth_block(config: &str, tenant_id: &str) -> Result<Option<String>, PyExc> {
    let mut root = etree::fromstring(config).map_err(|_| PyExc::http(500, PARSE_FAILURE))?;
    let mut removed = false;
    let blocks = root.findall("office365");
    // Indices shift as blocks are removed: walk them from the end, deciding
    // each in document order first.
    let mut drop_blocks = Vec::new();
    for &i in &blocks {
        let block: &mut Element = &mut root.children[i];
        block.children.retain(|child| {
            if child.tag != "api_auth" {
                return true;
            }
            let matches = child
                .find("tenant_id")
                .is_some_and(|t| py_strip(t.text.as_deref().unwrap_or_default()) == tenant_id);
            if matches {
                removed = true;
            }
            !matches
        });
        if removed && block.findall("api_auth").is_empty() {
            drop_blocks.push(i);
        }
    }
    for i in drop_blocks.into_iter().rev() {
        root.children.remove(i);
    }
    if !removed {
        return Ok(None);
    }
    Ok(Some(etree::tostring(&root)))
}

fn attribute_error(type_name: &str) -> PyExc {
    PyExc::AttributeError(format!("'{type_name}' object has no attribute 'get'"))
}

fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// `response.get(key, default)` on a JSON value (an `AttributeError` when it
/// is not a dict).
fn get<'a>(v: &'a Value, key: &str) -> Result<Option<&'a Value>, PyExc> {
    match v {
        Value::Object(m) => Ok(m.get(key)),
        other => Err(attribute_error(json_type(other))),
    }
}

/// Python truthiness of a JSON value.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `x == 0` in Python (`False` and `0.0` are equal to `0`).
fn equals_zero(v: &Value) -> bool {
    match v {
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64() == Some(0.0),
        _ => false,
    }
}

fn wazuh(e: PyErr) -> PyExc {
    match e {
        PyErr::Http { status, detail } => PyExc::Http(status, detail),
        PyErr::Value(m) => PyExc::ValueError(m),
        PyErr::Other(m) => PyExc::Other("Exception", m),
    }
}

/// `repr()` of a helper's answer dict.
fn repr(v: &Value) -> String {
    copilot_upstream::respond::from_json(v).py_repr()
}

/// `decommission_office365_tenant(customer_code, tenant_id)`.
pub async fn decommission_tenant(st: &WazuhState, tenant_id: &str) -> Result<(), PyExc> {
    let endpoint = "/manager/configuration";
    let params = vec![("raw".to_string(), Param::Bool(true))];
    let response = client::send_get(st, endpoint, Some(&params))
        .await
        .map_err(wazuh)?;
    // `response["data"]`.
    let config = match &response {
        Value::Object(m) => m
            .get("data")
            .cloned()
            .ok_or_else(|| PyExc::key_error("data"))?,
        _ => return Err(PyExc::key_error("data")),
    };
    let config = match config {
        Value::String(s) => s,
        other => {
            return Err(PyExc::TypeError(format!(
                "a bytes-like object is required, not '{}'",
                json_type(&other)
            )));
        }
    };
    let Some(updated) = remove_api_auth_block(&config, tenant_id)? else {
        tracing::info!(
            "Microsoft 365 tenant {tenant_id} is not configured on the Wazuh manager; nothing to \
             remove."
        );
        return Ok(());
    };
    let response = client::send_put(
        st,
        endpoint,
        Some(Body::Bytes(updated.into_bytes())),
        None,
        PutKind::Binary,
    )
    .await
    .map_err(wazuh)?;
    let success = get(&response, "success")?.is_some_and(truthy);
    let accepted = success && {
        let data = get(&response, "data")?
            .cloned()
            .unwrap_or(Value::Object(Default::default()));
        get(&data, "error")?.is_some_and(equals_zero)
    };
    if !accepted {
        return Err(PyExc::http(
            500,
            format!(
                "Failed to remove the Office365 api_auth block from ossec.conf: {}",
                repr(&response)
            ),
        ));
    }
    tracing::info!(
        "Removed Microsoft 365 tenant {tenant_id} from the Wazuh manager configuration; \
         restarting it."
    );
    client::send_put(st, "/manager/restart", None, None, PutKind::Json)
        .await
        .map_err(wazuh)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// `etree_vectors.json` (`scripts/gen-integrations-vectors.py`): what
    /// CPython 3.11's ElementTree accepts and writes back, and what the
    /// decommission makes of each document.
    #[test]
    fn cpython_vectors() {
        let vectors: Value = serde_json::from_str(include_str!("etree_vectors.json")).unwrap();
        for v in vectors.as_array().unwrap() {
            let doc = v["doc"].as_str().unwrap();
            let tenant = v["tenant"].as_str().unwrap();
            let parsed = etree::fromstring(doc);
            assert_eq!(parsed.is_ok(), v["parsed"].as_bool().unwrap(), "{doc:?}");
            if let Ok(root) = &parsed {
                assert_eq!(
                    etree::tostring(root),
                    v["tostring"].as_str().unwrap(),
                    "{doc:?}"
                );
            }
            match (remove_api_auth_block(doc, tenant), &v["removed"]) {
                (Ok(None), Value::Null) => {}
                (Ok(Some(text)), Value::String(want)) => assert_eq!(&text, want, "{doc:?}"),
                (Err(PyExc::Http(status, _)), Value::Object(want)) => {
                    assert_eq!(Some(u64::from(status)), want["error"].as_u64(), "{doc:?}");
                }
                (got, want) => panic!("{doc:?}: {got:?} where CPython gives {want}"),
            }
        }
    }

    const TWO: &str = "<ossec_config>\n  <office365>\n    <enabled>yes</enabled>\n    \
                       <api_auth>\n      <tenant_id>tenant-a</tenant_id>\n    </api_auth>\n    \
                       <api_auth>\n      <tenant_id>tenant-b</tenant_id>\n    </api_auth>\n  \
                       </office365>\n</ossec_config>";

    #[test]
    fn one_tenant_out_leaves_the_others() {
        let out = remove_api_auth_block(TWO, "tenant-a").unwrap().unwrap();
        assert!(!out.contains("tenant-a"));
        assert!(out.contains("tenant-b"));
        let out = remove_api_auth_block(&out, "tenant-b").unwrap().unwrap();
        assert!(!out.contains("office365"));
        assert_eq!(remove_api_auth_block(TWO, "tenant-z").unwrap(), None);
        assert!(remove_api_auth_block("<a/><b/>", "x").is_err());
    }
}
