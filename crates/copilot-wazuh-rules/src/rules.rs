//! `app/connectors/wazuh_manager/services/rules.py`'s disable/enable chain
//! (`process_rule`): the rule's file found through the manager, the
//! rule's level set in the file's JSON, the file written back as XML, the
//! manager restarted.
//!
//! Python addresses the manager as `f"{connector_url}{endpoint}"` with the
//! endpoints `rules`, `rules/files/{filename}` — no leading `/`, so against
//! a connector URL without a trailing slash (`https://wazuh:55000`) every
//! call is a malformed URL (`https://wazuh:55000rules`) and the chain fails
//! with a `KeyError` — and writes the XML back as `application/json`, a type
//! the Wazuh API refuses for a rule file. Here the endpoints carry their
//! `/` and the file goes up as `application/octet-stream`, as the rule-file
//! upload route (`PUT /rules/files/{filename}`) sends it (RUST_MIGRATION.md
//! §4: Python fails, Rust works). Every other step is Python's, failures
//! included.

use serde_json::{Map, Value};

use copilot_auth::pyvalue::str_repr;
use copilot_wazuh::WazuhState;
use copilot_wazuh::error::PyErr;
use copilot_wazuh::manager::client::{self, Body, Param, PutKind};
use copilot_wazuh::pyops;

use crate::xmltodict::{self, DECLARATION, py_strip};

/// The level a disabled rule gets (`NEW_LEVEL`).
pub const NEW_LEVEL: &str = "1";

/// A `KeyError` / `TypeError` caught by `set_rule_level`.
fn level_error(text: String) -> PyErr {
    PyErr::server(format!("Failed to set rule level: {text}"))
}

/// `value[key]` with `KeyError` / `TypeError` as `set_rule_level` sees them.
fn subscript(value: &Value, key: &str) -> Result<Value, PyErr> {
    pyops::index(value, key).map_err(level_error)
}

/// `for x in value` (`TypeError` for what does not iterate).
fn iterate(value: &Value) -> Result<Vec<Value>, PyErr> {
    pyops::iterate(value).map_err(level_error)
}

/// `set_rule_level(file_content, rule_id, new_level)`: the previous level of
/// the last group's matching rule (each group stops at its first match), and
/// the content with the level set — a dict wrapped in a list. A `KeyError`
/// or `TypeError` is the 500 `Failed to set rule level: …`; the
/// `AttributeError` of a group that is no dict escapes (a bare 500).
pub fn set_rule_level(
    file_content: Value,
    rule_id: &str,
    new_level: &str,
) -> Result<(Option<Value>, Value), PyErr> {
    let mut groups = match file_content {
        Value::Object(map) => vec![Value::Object(map)],
        Value::Array(items) => items,
        other => {
            // `for group_block in <scalar>`: a str iterates its characters,
            // whose `.get` is the `AttributeError`; anything else is the
            // `TypeError` of iteration.
            let items = iterate(&other)?;
            match items.first() {
                Some(first) => {
                    return Err(PyErr::Other(
                        pyops::get(first, "rule", Value::Null)
                            .err()
                            .unwrap_or_default(),
                    ));
                }
                None => return Ok((None, other)),
            }
        }
    };
    let mut previous_level = None;
    for group in &mut groups {
        let Value::Object(group_map) = group else {
            return Err(PyErr::Other(
                pyops::get(group, "rule", Value::Null)
                    .err()
                    .unwrap_or_default(),
            ));
        };
        let Some(rule_block) = group_map.get_mut("rule") else {
            continue;
        };
        if !pyops::truthy(rule_block) {
            continue;
        }
        let rules: Vec<&mut Value> = match rule_block {
            Value::Object(_) => vec![rule_block],
            Value::Array(items) => items.iter_mut().collect(),
            other => {
                // A truthy str iterates its characters (`"c"["@id"]`), a
                // number does not iterate at all.
                let chars = iterate(other)?;
                if let Some(first) = chars.first() {
                    subscript(first, "@id")?;
                }
                continue;
            }
        };
        for rule in rules {
            let id = subscript(rule, "@id")?;
            if id == Value::String(rule_id.to_string()) {
                previous_level = Some(subscript(rule, "@level")?);
                if let Value::Object(m) = rule {
                    m.insert("@level".into(), Value::String(new_level.to_string()));
                }
                break;
            }
        }
    }
    Ok((previous_level, Value::Array(groups)))
}

/// `convert_to_xml(updated_file_content)`: each group unparsed
/// (`xmltodict.unparse({"group": group}, pretty=True)`), its declaration
/// removed, the groups joined by a line end and the whole stripped. Any
/// failure is the 500 `Failed to convert to XML: …`.
pub fn convert_to_xml(updated: &Value) -> Result<String, PyErr> {
    let groups = pyops::iterate(updated)
        .map_err(|e| PyErr::server(format!("Failed to convert to XML: {e}")))?;
    let mut parts = Vec::new();
    for group in &groups {
        let xml = xmltodict::unparse("group", group)
            .map_err(|e| PyErr::server(format!("Failed to convert to XML: {e}")))?;
        parts.push(xml.replace(DECLARATION, ""));
    }
    Ok(py_strip(&parts.join("\n")).to_string())
}

/// `x["data"]["data"][key]` on a helper's answer: a `KeyError` (or the
/// `TypeError` of a subscript) escapes — a bare 500.
fn data_field(answer: &Value, key: &str) -> Result<Value, PyErr> {
    let data = pyops::index(answer, "data").map_err(PyErr::Other)?;
    let inner = pyops::index(&data, "data").map_err(PyErr::Other)?;
    pyops::index(&inner, key).map_err(PyErr::Other)
}

/// Python's `== 0` on a JSON value.
fn is_zero(v: &Value) -> bool {
    match v {
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::Bool(b) => !*b,
        _ => false,
    }
}

/// `fetch_filename(rule_id)`.
pub async fn fetch_filename(st: &WazuhState, rule_id: &str) -> Result<Value, PyErr> {
    let params = vec![("rule_ids".to_string(), Param::Str(rule_id.to_string()))];
    let answer = client::send_get(st, "/rules", Some(&params)).await?;
    if is_zero(&data_field(&answer, "total_affected_items")?) {
        return Err(PyErr::http(
            404,
            format!(
                "Rule {rule_id} not found. Make sure the rule ID is correct within the Wazuh \
                 Manager."
            ),
        ));
    }
    let items = data_field(&answer, "affected_items")?;
    let first = pyops::first(&items).map_err(PyErr::Other)?;
    pyops::index(&first, "filename").map_err(PyErr::Other)
}

/// `fetch_file_content(filename)`.
pub async fn fetch_file_content(st: &WazuhState, filename: &str) -> Result<Value, PyErr> {
    let answer = client::send_get(st, &format!("/rules/files/{filename}"), None).await?;
    if is_zero(&data_field(&answer, "total_affected_items")?) {
        return Err(PyErr::http(
            404,
            format!(
                "File {filename} not found. Make sure the file name is correct within the Wazuh \
                 Manager."
            ),
        ));
    }
    let items = data_field(&answer, "affected_items")?;
    let first = pyops::first(&items).map_err(PyErr::Other)?;
    pyops::index(&first, "group").map_err(PyErr::Other)
}

/// `upload_updated_rule(filename, xml_content)`.
pub async fn upload_updated_rule(
    st: &WazuhState,
    filename: &str,
    xml: &str,
) -> Result<Value, PyErr> {
    let params = vec![("overwrite".to_string(), Param::Str("true".into()))];
    let answer = client::send_put(
        st,
        &format!("/rules/files/{filename}"),
        Some(Body::Text(xml.to_string())),
        Some(&params),
        PutKind::Binary,
    )
    .await?;
    if is_zero(&data_field(&answer, "total_affected_items")?) {
        return Err(PyErr::server(
            "Failed to upload updated rule to Wazuh Manager.",
        ));
    }
    Ok(answer)
}

/// What `process_rule` hands to the response model.
#[derive(Debug, Clone, PartialEq)]
pub struct Processed {
    /// The level the rule had (`None` when the file did not hold it).
    pub previous_level: Option<Value>,
    /// `Rule {id} successfully processed in file {filename}.`
    pub message: String,
}

/// `process_rule(rule, rule_action_func, ResponseModel)` with
/// `set_rule_level(…, new_level)` as the action.
pub async fn process_rule(
    st: &WazuhState,
    rule_id: &str,
    new_level: &str,
) -> Result<Processed, PyErr> {
    let filename = fetch_filename(st, rule_id).await?;
    // An f-string of whatever the API named the file.
    let filename_text = pyops::py_str(&filename);
    let content = fetch_file_content(st, &filename_text).await?;
    let (previous_level, updated) = set_rule_level(content, rule_id, new_level)?;
    let xml = convert_to_xml(&updated)?;
    upload_updated_rule(st, &filename_text, &xml).await?;
    // The restart's own answer (or failure) is not looked at.
    client::restart_service(st).await?;
    Ok(Processed {
        previous_level,
        message: format!("Rule {rule_id} successfully processed in file {filename_text}."),
    })
}

/// `previous_level` as `Optional[str]` validates it: a `str`, or `None`;
/// anything else is the response model's `ValidationError` (a `ValueError`:
/// the 400 with its text).
pub fn previous_level_text(model: &str, level: &Option<Value>) -> Result<Option<String>, PyErr> {
    match level {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(other) => {
            let input = copilot_wazuh::pymodel::py(other);
            Err(PyErr::Value(
                copilot_upstream::model::format_validation_error(
                    model,
                    &[copilot_upstream::model::PyError {
                        loc: vec![copilot_upstream::model::Loc::Key("previous_level".into())],
                        kind: "string_type",
                        msg: "Input should be a valid string".into(),
                        input,
                    }],
                ),
            ))
        }
    }
}

/// A rule's previous level as the `disabledrule` row stores it (`None` is
/// a `NULL`, which the column refuses: the bare 500 of the insert).
pub fn stored_level(level: &Option<Value>) -> Option<String> {
    match level {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => Some(pyops::py_str(other)),
    }
}

/// The JSON object of a response model.
pub fn object(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    Value::Object(m)
}

/// `repr()` of a rule id in an error (unused by the chain, kept for the
/// tests' messages).
pub fn rule_repr(id: &str) -> String {
    str_repr(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[derive(serde::Deserialize)]
    struct Vectors {
        levels: Vec<Value>,
    }

    /// `wazuh_rules_vectors.json` (`scripts/gen-wazuh-rules-vectors.py`):
    /// `set_rule_level` then `convert_to_xml`, against Python's.
    #[test]
    fn levels_and_xml_follow_python() {
        let v: Vectors =
            serde_json::from_str(include_str!("wazuh_rules_vectors.json")).expect("vectors");
        for probe in v.levels {
            let content = probe["content"].clone();
            let rule_id = probe["rule_id"].as_str().unwrap();
            let level = probe["new_level"].as_str().unwrap();
            let got = set_rule_level(content.clone(), rule_id, level)
                .and_then(|(prev, updated)| convert_to_xml(&updated).map(|xml| (prev, xml)));
            match got {
                Ok((prev, xml)) => {
                    assert_eq!(
                        prev.unwrap_or(Value::Null),
                        probe["previous_level"],
                        "{content}"
                    );
                    assert_eq!(json!(xml), probe["xml"], "{content}");
                }
                Err(PyErr::Http {
                    status: 500,
                    detail,
                }) => {
                    assert_eq!(json!(detail), probe["http"], "{content}");
                }
                Err(PyErr::Other(text)) => {
                    assert_eq!(json!(text), probe["text"], "{content}");
                }
                Err(e) => panic!("{content}: {e:?}"),
            }
        }
    }

    #[test]
    fn a_non_string_level_fails_the_response_model() {
        let e = previous_level_text("RuleDisableResponse", &Some(json!(3))).unwrap_err();
        assert_eq!(
            e,
            PyErr::Value(
                "1 validation error for RuleDisableResponse\nprevious_level\n  Input should be a \
                 valid string [type=string_type, input_value=3, input_type=int]\n    For further \
                 information visit https://errors.pydantic.dev/2.13/v/string_type"
                    .into()
            )
        );
        assert_eq!(rule_repr("5"), "'5'");
    }
}
