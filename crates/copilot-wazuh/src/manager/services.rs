//! `wazuh_manager/services/{rules,groups,mitre}.py` (the routes kept in
//! Rust), line by line over the helpers' dicts: each `.get`, `in` and
//! `[…]` keeps Python's exception text for an unexpected answer, and each
//! `except` catches what Python's catches.

use serde_json::{Value, json};

use crate::WazuhState;
use crate::error::PyErr;
use crate::manager::client::{Body, Param, PutKind, send_get, send_put};
use crate::manager::schema;
use crate::pymodel::{Model, validate};
use crate::pyops;

/// A step that raises `str(e)`-able exceptions.
type Step<T> = Result<T, PyErr>;

fn other(e: String) -> PyErr {
    PyErr::Other(e)
}

/// `Model(**fields)` (a `ValidationError` is a `ValueError`).
fn build(model: &Model, fields: Value) -> Step<Value> {
    validate(model, &fields).map_err(PyErr::from)
}

/// `response.get("data", {}).get("data", {})`.
fn wazuh_data(response: &Value) -> Step<Value> {
    let outer = pyops::get(response, "data", json!({})).map_err(other)?;
    pyops::get(&outer, "data", json!({})).map_err(other)
}

/// `(items, total)`: `wazuh_data.get("affected_items", [])` and
/// `wazuh_data.get("total_affected_items", len(items))` (the default is
/// evaluated first, so an unsized `items` raises).
fn items_and_total(data: &Value) -> Step<(Value, Value, usize)> {
    let items = pyops::get(data, "affected_items", json!([])).map_err(other)?;
    let n = pyops::len(&items).map_err(other)?;
    let total = pyops::get(data, "total_affected_items", json!(n)).map_err(other)?;
    Ok((items, total, n))
}

fn succeeded(response: &Value) -> Step<bool> {
    pyops::get(response, "success", Value::Null)
        .map(|v| pyops::truthy(&v))
        .map_err(other)
}

fn message_or(response: &Value, default: &str) -> Step<Value> {
    pyops::get(response, "message", json!(default)).map_err(other)
}

/// `{k: v for k, v in params.items() if v is not None}` with the list
/// parameters joined by commas.
pub fn clean(params: Vec<(&str, Option<Param>)>) -> Vec<(String, Param)> {
    params
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k.to_string(), v)))
        .collect()
}

/// `get_wazuh_rules(**params)`.
pub async fn get_rules(st: &WazuhState, params: Vec<(String, Param)>) -> Step<Value> {
    let inner: Step<Value> = async {
        let response = send_get(st, "/rules", Some(&params)).await?;
        if !succeeded(&response)? {
            return Err(PyErr::server("Failed to fetch rules from Wazuh API"));
        }
        let data = wazuh_data(&response)?;
        let (rules, total, n) = items_and_total(&data)?;
        tracing::info!("Retrieved {n} of {} Wazuh rules", pyops::py_str(&total));
        build(
            &schema::RULES_RESPONSE,
            json!({
                "success": true,
                "message": format!("Successfully retrieved {n} rules"),
                "results": rules,
                "total_items": total,
            }),
        )
    }
    .await;
    inner.map_err(|e| PyErr::server(format!("Error fetching rules: {}", e.py_str())))
}

/// Re-raise an `HTTPException`, wrap anything else.
fn reraise_http(e: PyErr, wrap: &str) -> PyErr {
    match e {
        PyErr::Http { .. } => e,
        other => PyErr::server(format!("{wrap}: {}", other.py_str())),
    }
}

/// `get_wazuh_rule_files(**params)`.
pub async fn get_rule_files(st: &WazuhState, params: Vec<(String, Param)>) -> Step<Value> {
    let inner: Step<Value> = async {
        let response = send_get(st, "/rules/files", Some(&params)).await?;
        if !succeeded(&response)? {
            let detail = message_or(&response, "Failed to fetch rule files from Wazuh API")?;
            return Err(PyErr::server(pyops::py_str(&detail)));
        }
        let data = wazuh_data(&response)?;
        let (files, total, n) = items_and_total(&data)?;
        build(
            &schema::RULE_FILES_RESPONSE,
            json!({
                "success": true,
                "message": format!("Successfully retrieved {n} rule files"),
                "results": files,
                "total_items": total,
            }),
        )
    }
    .await;
    inner.map_err(|e| reraise_http(e, "Error fetching rule files"))
}

/// The `not found` → 404 rule of the file lookups.
fn not_found_or(detail: &Value, not_found: String) -> PyErr {
    match pyops::lower(detail) {
        Ok(l) if l.contains("not found") => PyErr::http(404, not_found),
        Ok(_) => PyErr::server(pyops::py_str(detail)),
        Err(e) => PyErr::Other(e),
    }
}

/// `get_wazuh_rule_file_content(filename, **params)`.
pub async fn get_rule_file_content(
    st: &WazuhState,
    filename: &str,
    params: Vec<(String, Param)>,
) -> Step<Value> {
    let is_raw = params
        .iter()
        .find(|(k, _)| k == "raw")
        .is_some_and(|(_, v)| *v == Param::Bool(true));
    let endpoint = format!("/rules/files/{filename}");
    let inner: Step<Value> = async {
        if is_raw {
            let raw_params = vec![("raw".to_string(), Param::Bool(true))];
            let response = send_get(st, &endpoint, Some(&raw_params)).await?;
            if !succeeded(&response)? {
                let detail = message_or(
                    &response,
                    &format!("Failed to fetch raw rule file content for {filename}"),
                )?;
                return Err(not_found_or(
                    &detail,
                    format!("Rule file '{filename}' not found"),
                ));
            }
            let content = pyops::get(&response, "data", json!("")).map_err(other)?;
            pyops::len(&content).map_err(other)?;
            return build(
                &schema::RULE_FILE_CONTENT_RESPONSE,
                json!({
                    "success": true,
                    "message": format!("Successfully retrieved raw content for rule file '{filename}'"),
                    "filename": filename,
                    "content": content,
                    "is_raw": true,
                    "total_items": null,
                }),
            );
        }
        let response = send_get(st, &endpoint, Some(&params)).await?;
        if !succeeded(&response)? {
            let detail = message_or(
                &response,
                &format!("Failed to fetch rule file content for {filename}"),
            )?;
            return Err(not_found_or(
                &detail,
                format!("Rule file '{filename}' not found"),
            ));
        }
        let data = wazuh_data(&response)?;
        let (items, total, _) = items_and_total(&data)?;
        if !pyops::truthy(&items) {
            return Err(PyErr::http(
                404,
                format!("No content found for rule file '{filename}'"),
            ));
        }
        let content = pyops::first(&items).map_err(other)?;
        build(
            &schema::RULE_FILE_CONTENT_RESPONSE,
            json!({
                "success": true,
                "message": format!("Successfully retrieved content for rule file '{filename}'"),
                "filename": filename,
                "content": content,
                "is_raw": false,
                "total_items": total,
            }),
        )
    }
    .await;
    inner.map_err(|e| reraise_http(e, "Error fetching rule file content"))
}

/// `update_wazuh_rule_file(filename, file_content, …)`.
pub async fn update_rule_file(
    st: &WazuhState,
    filename: &str,
    content: Vec<u8>,
    params: Vec<(String, Param)>,
) -> Step<Value> {
    tracing::info!("Uploading/updating rule file: {filename}");
    let inner: Step<Value> = async {
        let response = send_put(
            st,
            &format!("/rules/files/{filename}"),
            Some(Body::Bytes(content)),
            Some(&params),
            PutKind::Binary,
        )
        .await?;
        if !succeeded(&response)? {
            let detail = message_or(&response, "Failed to upload rule file to Wazuh API")?;
            let status = pyops::get(&response, "status_code", json!(500)).map_err(other)?;
            return Err(PyErr::http(
                status
                    .as_u64()
                    .and_then(|s| u16::try_from(s).ok())
                    .unwrap_or(500),
                pyops::py_str(&detail),
            ));
        }
        let data = wazuh_data(&response)?;
        let total = pyops::get(&data, "total_affected_items", json!(1)).map_err(other)?;
        build(
            &schema::RULE_FILE_UPLOAD_RESPONSE,
            json!({
                "success": true,
                "message": format!("Successfully uploaded/updated rule file: {filename}"),
                "filename": filename,
                "details": data,
                "total_items": total,
            }),
        )
    }
    .await;
    inner.map_err(|e| reraise_http(e, "Error uploading rule file"))
}

/// `get_wazuh_groups(**params)`.
pub async fn get_groups(st: &WazuhState, params: Vec<(String, Param)>) -> Step<Value> {
    let inner: Step<Value> = async {
        let response = send_get(st, "/groups", Some(&params)).await?;
        if !succeeded(&response)? {
            let detail = message_or(&response, "Failed to fetch groups from Wazuh API")?;
            return Err(PyErr::server(pyops::py_str(&detail)));
        }
        let data = wazuh_data(&response)?;
        let (groups, total, n) = items_and_total(&data)?;
        build(
            &schema::GROUPS_RESPONSE,
            json!({
                "success": true,
                "message": format!("Successfully retrieved {n} groups"),
                "results": groups,
                "total_items": total,
            }),
        )
    }
    .await;
    inner.map_err(|e| reraise_http(e, "Error fetching groups"))
}

/// `get_wazuh_group_files(group_id, **params)`.
pub async fn get_group_files(
    st: &WazuhState,
    group_id: &str,
    params: Vec<(String, Param)>,
) -> Step<Value> {
    let inner: Step<Value> = async {
        let response = send_get(st, &format!("/groups/{group_id}/files"), Some(&params)).await?;
        if !succeeded(&response)? {
            let detail = message_or(
                &response,
                &format!("Failed to fetch group files for group '{group_id}'"),
            )?;
            return Err(not_found_or(
                &detail,
                format!("Group '{group_id}' not found"),
            ));
        }
        let data = wazuh_data(&response)?;
        let (files, total, n) = items_and_total(&data)?;
        build(
            &schema::GROUP_FILES_RESPONSE,
            json!({
                "success": true,
                "message": format!("Successfully retrieved {n} files for group '{group_id}'"),
                "group_id": group_id,
                "results": files,
                "total_items": total,
            }),
        )
    }
    .await;
    inner.map_err(|e| reraise_http(e, "Error fetching group files"))
}

/// `get_wazuh_group_file(group_id, filename, **params)`.
pub async fn get_group_file(
    st: &WazuhState,
    group_id: &str,
    filename: &str,
    params: Vec<(String, Param)>,
) -> Step<Value> {
    let is_raw = params
        .iter()
        .find(|(k, _)| k == "raw")
        .is_some_and(|(_, v)| *v == Param::Bool(true));
    let inner: Step<Value> = async {
        let response = send_get(
            st,
            &format!("/groups/{group_id}/files/{filename}"),
            Some(&params),
        )
        .await?;
        if !succeeded(&response)? {
            let detail = message_or(
                &response,
                &format!("Failed to fetch group file '{filename}' for group '{group_id}'"),
            )?;
            return Err(not_found_or(
                &detail,
                format!("Group file '{filename}' not found in group '{group_id}'"),
            ));
        }
        if is_raw {
            let content = pyops::get(&response, "data", json!("")).map_err(other)?;
            pyops::len(&content).map_err(other)?;
            return build(
                &schema::GROUP_FILE_RESPONSE,
                json!({
                    "success": true,
                    "message": format!(
                        "Successfully retrieved raw content for group file '{filename}' in group '{group_id}'"
                    ),
                    "group_id": group_id,
                    "filename": filename,
                    "content": content,
                    "is_raw": true,
                    "total_items": null,
                }),
            );
        }
        let data = wazuh_data(&response)?;
        let (items, total, _) = items_and_total(&data)?;
        if !pyops::truthy(&items) {
            return Err(PyErr::http(
                404,
                format!("No content found for group file '{filename}' in group '{group_id}'"),
            ));
        }
        let content = pyops::first(&items).map_err(other)?;
        build(
            &schema::GROUP_FILE_RESPONSE,
            json!({
                "success": true,
                "message": format!(
                    "Successfully retrieved content for group file '{filename}' in group '{group_id}'"
                ),
                "group_id": group_id,
                "filename": filename,
                "content": content,
                "is_raw": false,
                "total_items": total,
            }),
        )
    }
    .await;
    inner.map_err(|e| reraise_http(e, "Error fetching group file"))
}

/// `update_wazuh_group_configuration(group_id, configuration, **params)`.
pub async fn update_group_configuration(
    st: &WazuhState,
    group_id: &str,
    configuration: &str,
    params: Vec<(String, Param)>,
) -> Step<Value> {
    let inner: Step<Value> = async {
        let trimmed = configuration.trim_matches(copilot_web::form::is_py_space);
        if trimmed.is_empty() {
            return Err(PyErr::http(400, "Configuration content cannot be empty"));
        }
        if !trimmed.starts_with('<') {
            tracing::warn!("Configuration does not appear to be XML format");
            return Err(PyErr::http(400, "Configuration must be valid XML format"));
        }
        let response = send_put(
            st,
            &format!("/groups/{group_id}/configuration"),
            Some(Body::Text(configuration.to_string())),
            Some(&params),
            PutKind::Xml,
        )
        .await?;
        if !succeeded(&response)? {
            let detail = message_or(
                &response,
                &format!("Failed to update group configuration for group '{group_id}'"),
            )?;
            let status = pyops::get(&response, "status_code", json!(500)).map_err(other)?;
            let lowered = pyops::lower(&detail).map_err(other)?;
            if lowered.contains("not found") {
                return Err(PyErr::http(404, format!("Group '{group_id}' not found")));
            }
            let text = pyops::py_str(&detail);
            if status == json!(400) {
                return Err(PyErr::http(
                    400,
                    format!("Invalid configuration data: {text}"),
                ));
            }
            return Err(PyErr::http(
                status
                    .as_u64()
                    .and_then(|s| u16::try_from(s).ok())
                    .unwrap_or(500),
                text,
            ));
        }
        let data = wazuh_data(&response)?;
        let total = pyops::get(&data, "total_affected_items", json!(1)).map_err(other)?;
        build(
            &schema::GROUP_CONFIGURATION_RESPONSE,
            json!({
                "success": true,
                "message": format!("Successfully updated configuration for group '{group_id}'"),
                "group_id": group_id,
                "total_items": total,
            }),
        )
    }
    .await;
    inner.map_err(|e| reraise_http(e, "Error updating group configuration"))
}

/// One of the six MITRE listings of `services/mitre.py`.
#[derive(Debug, Clone, Copy)]
pub struct MitreList {
    /// `/mitre/<what>`.
    pub endpoint: &'static str,
    /// The noun in `Successfully retrieved N MITRE <noun>`.
    pub noun: &'static str,
    /// The response model.
    pub model: &'static Model,
    /// Whether the service catches `ValidationError` apart (all but tactics).
    pub validation_apart: bool,
    /// Whether the response carries `total` (references, mitigations, groups).
    pub with_total: bool,
    /// Techniques: `is_subtechnique` is set from `subtechnique_of` first.
    pub mark_subtechniques: bool,
}

/// The six listings.
pub mod lists {
    use super::MitreList;
    use crate::manager::schema;

    /// Tactics.
    pub const TACTICS: MitreList = MitreList {
        endpoint: "/mitre/tactics",
        noun: "tactics",
        model: &schema::MITRE_TACTICS_RESPONSE,
        validation_apart: false,
        with_total: false,
        mark_subtechniques: false,
    };
    /// Techniques.
    pub const TECHNIQUES: MitreList = MitreList {
        endpoint: "/mitre/techniques",
        noun: "techniques",
        model: &schema::MITRE_TECHNIQUES_RESPONSE,
        validation_apart: true,
        with_total: false,
        mark_subtechniques: true,
    };
    /// Software.
    pub const SOFTWARE: MitreList = MitreList {
        endpoint: "/mitre/software",
        noun: "software",
        model: &schema::MITRE_SOFTWARE_RESPONSE,
        validation_apart: true,
        with_total: false,
        mark_subtechniques: false,
    };
    /// References.
    pub const REFERENCES: MitreList = MitreList {
        endpoint: "/mitre/references",
        noun: "references",
        model: &schema::MITRE_REFERENCES_RESPONSE,
        validation_apart: true,
        with_total: true,
        mark_subtechniques: false,
    };
    /// Mitigations.
    pub const MITIGATIONS: MitreList = MitreList {
        endpoint: "/mitre/mitigations",
        noun: "mitigations",
        model: &schema::MITRE_MITIGATIONS_RESPONSE,
        validation_apart: true,
        with_total: true,
        mark_subtechniques: false,
    };
    /// Groups.
    pub const GROUPS: MitreList = MitreList {
        endpoint: "/mitre/groups",
        noun: "groups",
        model: &schema::MITRE_GROUPS_RESPONSE,
        validation_apart: true,
        with_total: true,
        mark_subtechniques: false,
    };
}

/// `get_mitre_<what>(limit, offset, select, sort, search, q)`; `params`
/// already in the service's order with `None`s dropped.
pub async fn get_mitre(
    st: &WazuhState,
    list: MitreList,
    params: Vec<(String, Param)>,
) -> Step<Value> {
    let response = send_get(st, list.endpoint, Some(&params)).await?;
    let inner: Step<Value> = (|| {
        let has_data = pyops::contains(&response, "data").map_err(other)?
            && pyops::contains(&pyops::index(&response, "data").map_err(other)?, "data")
                .map_err(other)?;
        if !has_data {
            tracing::error!("Unexpected response structure from Wazuh API");
            return Err(PyErr::server(
                "Unexpected response structure from Wazuh API",
            ));
        }
        let outer = pyops::index(&response, "data").map_err(other)?;
        let data = pyops::index(&outer, "data").map_err(other)?;
        let (mut items, total, n) = items_and_total(&data)?;
        if list.mark_subtechniques {
            // `for technique in techniques: if "subtechnique_of" in technique
            // and technique["subtechnique_of"]: technique["is_subtechnique"] = True`
            for (i, item) in pyops::iterate(&items).map_err(other)?.iter().enumerate() {
                let marks = pyops::contains(item, "subtechnique_of").map_err(other)?
                    && pyops::truthy(&pyops::index(item, "subtechnique_of").map_err(other)?);
                if let (true, Value::Array(all)) = (marks, &mut items) {
                    if let Some(Value::Object(m)) = all.get_mut(i) {
                        m.insert("is_subtechnique".into(), Value::Bool(true));
                    }
                }
            }
        }
        let mut fields = serde_json::Map::new();
        fields.insert("success".into(), Value::Bool(true));
        fields.insert(
            "message".into(),
            Value::String(format!("Successfully retrieved {n} MITRE {}", list.noun)),
        );
        fields.insert("results".into(), items);
        if list.with_total {
            fields.insert("total".into(), total);
        }
        match validate(list.model, &Value::Object(fields)) {
            Ok(v) => Ok(v),
            Err(e) if list.validation_apart => {
                Err(PyErr::server(format!("Data validation error: {e}")))
            }
            Err(e) => Err(PyErr::Value(e.to_string())),
        }
    })();
    inner.map_err(|e| match e {
        PyErr::Http {
            status: 500,
            ref detail,
        } if detail.starts_with("Data validation error: ") => e,
        other => PyErr::server(format!("Error processing MITRE data: {}", other.py_str())),
    })
}
