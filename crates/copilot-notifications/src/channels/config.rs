//! Each channel's `config` model (`WebhookConfig`, `ResendConfig`,
//! `TeamsConfig`, `ShuffleConfig`), validated the way Pydantic 2 validates
//! them in lax mode — the same coercions, the same `extra="forbid"`, the
//! same validators, the same `model_dump()` — so a config is accepted,
//! normalized and refused (with the same text) by either backend.
//!
//! Values are [`PyValue`]s: a request's `config` and a stored row's
//! `json.loads(config)` alike.

use copilot_auth::pyvalue::PyValue;
use copilot_web::form::py_strip;

use crate::channels::Channel;
use crate::pydantic::{Loc, PyError};

const STRING_TYPE: &str = "Input should be a valid string";

fn key(name: &str) -> Vec<Loc> {
    vec![Loc::Key(name.into())]
}

fn str_err(loc: Vec<Loc>, input: &PyValue) -> PyError {
    PyError::new(loc, "string_type", STRING_TYPE, input.clone())
}

/// `str`.
fn check_str(loc: Vec<Loc>, v: &PyValue, errors: &mut Vec<PyError>) -> Option<String> {
    match v {
        PyValue::Str(s) => Some(s.clone()),
        other => {
            errors.push(str_err(loc, other));
            None
        }
    }
}

/// `Optional[str]`: `Some(None)` for an explicit `None`.
fn check_opt_str(loc: Vec<Loc>, v: &PyValue, errors: &mut Vec<PyError>) -> Option<Option<String>> {
    match v {
        PyValue::None => Some(None),
        other => check_str(loc, other, errors).map(Some),
    }
}

/// `bool` in lax mode.
fn check_bool(loc: Vec<Loc>, v: &PyValue, errors: &mut Vec<PyError>) -> Option<bool> {
    let parsed = match v {
        PyValue::Bool(b) => Some(*b),
        PyValue::Int(i) => match i.as_str() {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        },
        PyValue::Float(f) => {
            if *f == 0.0 {
                Some(false)
            } else if *f == 1.0 {
                Some(true)
            } else {
                None
            }
        }
        PyValue::Str(s) => match s.to_lowercase().as_str() {
            "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
            "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
            _ => None,
        },
        other => {
            errors.push(PyError::new(
                loc,
                "bool_type",
                "Input should be a valid boolean",
                other.clone(),
            ));
            return None;
        }
    };
    if parsed.is_none() {
        errors.push(PyError::new(
            loc,
            "bool_parsing",
            "Input should be a valid boolean, unable to interpret input",
            v.clone(),
        ));
    }
    parsed
}

/// The canonical decimal of an integer string as `int(s)` reads it
/// (surrounding whitespace, a sign, `_` between digits), if it is one.
fn canonical_int(s: &str) -> Option<String> {
    let t = py_strip(s);
    let (neg, body) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let bytes = body.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.iter().enumerate().all(|(i, b)| {
            b.is_ascii_digit()
                || (*b == b'_'
                    && i > 0
                    && i + 1 < bytes.len()
                    && bytes[i - 1].is_ascii_digit()
                    && bytes[i + 1].is_ascii_digit())
        });
    if !valid {
        return None;
    }
    let digits: String = body.chars().filter(|c| *c != '_').collect();
    let trimmed = digits.trim_start_matches('0');
    let body = if trimmed.is_empty() { "0" } else { trimmed };
    Some(if neg && body != "0" {
        format!("-{body}")
    } else {
        body.to_string()
    })
}

/// `int` in lax mode, as its canonical decimal.
fn check_int(loc: Vec<Loc>, v: &PyValue, errors: &mut Vec<PyError>) -> Option<String> {
    let err = |kind: &'static str, msg: &str| PyError::new(loc.clone(), kind, msg, v.clone());
    match v {
        PyValue::Int(i) => Some(i.clone()),
        PyValue::Bool(b) => Some(if *b { "1" } else { "0" }.to_string()),
        PyValue::Float(f) if !f.is_finite() => {
            errors.push(err("finite_number", "Input should be a finite number"));
            None
        }
        PyValue::Float(f) if f.fract() != 0.0 => {
            errors.push(err(
                "int_from_float",
                "Input should be a valid integer, got a number with a fractional part",
            ));
            None
        }
        // i64's range, as pydantic-core converts a float.
        PyValue::Float(f) if !(-9.223_372_036_854_776e18..9.223_372_036_854_776e18).contains(f) => {
            errors.push(err(
                "int_parsing_size",
                "Unable to parse input string as an integer, exceeded maximum size",
            ));
            None
        }
        PyValue::Float(f) => Some((*f as i64).to_string()),
        PyValue::Str(s) => match canonical_int(s) {
            Some(i) => Some(i),
            None => {
                errors.push(err(
                    "int_parsing",
                    "Input should be a valid integer, unable to parse string as an integer",
                ));
                None
            }
        },
        _ => {
            errors.push(err("int_type", "Input should be a valid integer"));
            None
        }
    }
}

/// `Dict[str, str]`.
fn check_str_dict(
    name: &str,
    v: &PyValue,
    errors: &mut Vec<PyError>,
) -> Option<Vec<(String, String)>> {
    let PyValue::Dict(items) = v else {
        errors.push(PyError::new(
            key(name),
            "dict_type",
            "Input should be a valid dictionary",
            v.clone(),
        ));
        return None;
    };
    let before = errors.len();
    let mut out = Vec::new();
    for (k, item) in items {
        let loc = vec![Loc::Key(name.into()), Loc::Key(k.clone())];
        if let Some(s) = check_str(loc, item, errors) {
            out.push((k.clone(), s));
        }
    }
    (errors.len() == before).then_some(out)
}

/// `List[str]` behind `_coerce_single_address` (`None` → `[]`, a string →
/// a one-element list unless blank).
fn check_address_list(name: &str, v: &PyValue, errors: &mut Vec<PyError>) -> Option<Vec<String>> {
    let items = match v {
        PyValue::None => return Some(Vec::new()),
        PyValue::Str(s) => {
            return Some(if py_strip(s).is_empty() {
                Vec::new()
            } else {
                vec![s.clone()]
            });
        }
        PyValue::List(items) => items,
        other => {
            errors.push(PyError::new(
                key(name),
                "list_type",
                "Input should be a valid list",
                other.clone(),
            ));
            return None;
        }
    };
    let before = errors.len();
    let mut out = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let loc = vec![Loc::Key(name.into()), Loc::Index(i)];
        if let Some(s) = check_str(loc, item, errors) {
            out.push(s);
        }
    }
    (errors.len() == before).then_some(out)
}

fn value_error(name: &str, msg: &str, input: &PyValue) -> PyError {
    PyError::new(
        key(name),
        "value_error",
        format!("Value error, {msg}"),
        input.clone(),
    )
}

fn opt_str_value(v: Option<String>) -> PyValue {
    v.map_or(PyValue::None, PyValue::Str)
}

fn str_list(items: Vec<String>) -> PyValue {
    PyValue::List(items.into_iter().map(PyValue::Str).collect())
}

/// The fields a model declares, in order.
fn fields(channel: Channel) -> &'static [&'static str] {
    match channel {
        Channel::Webhook => &["url", "method", "headers", "include_full_report"],
        Channel::Resend => &[
            "to",
            "cc",
            "from_address",
            "reply_to",
            "subject_prefix",
            "max_per_hour",
        ],
        Channel::Teams => &["webhook_url"],
        Channel::Shuffle => &["app_id", "app_name"],
    }
}

/// `config_schema.model_validate(data).model_dump()` — the normalized config,
/// or the errors in Pydantic's order (declared fields, then each extra key).
pub fn validate(channel: Channel, data: &[(String, PyValue)]) -> Result<PyValue, Vec<PyError>> {
    let get = |name: &str| data.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    let mut errors = Vec::new();
    let mut out: Vec<(String, PyValue)> = Vec::new();
    match channel {
        Channel::Webhook => {
            let url = match get("url") {
                None => Some(None),
                Some(v) => check_opt_str(key("url"), v, &mut errors),
            };
            let method = match get("method") {
                None => Some("POST".to_string()),
                Some(v) => check_str(key("method"), v, &mut errors).and_then(|m| {
                    let upper = if m.is_empty() {
                        "POST".to_string()
                    } else {
                        m.to_uppercase()
                    };
                    if upper == "POST" || upper == "PUT" {
                        Some(upper)
                    } else {
                        errors.push(value_error("method", "method must be POST or PUT", v));
                        None
                    }
                }),
            };
            let headers = match get("headers") {
                None | Some(PyValue::None) => Some(None),
                Some(v) => check_str_dict("headers", v, &mut errors).map(Some),
            };
            let full = match get("include_full_report") {
                None => Some(false),
                Some(v) => check_bool(key("include_full_report"), v, &mut errors),
            };
            out.push(("url".into(), opt_str_value(url.flatten())));
            out.push(("method".into(), PyValue::Str(method.unwrap_or_default())));
            out.push((
                "headers".into(),
                headers.flatten().map_or(PyValue::None, |h| {
                    PyValue::Dict(h.into_iter().map(|(k, v)| (k, PyValue::Str(v))).collect())
                }),
            ));
            out.push((
                "include_full_report".into(),
                PyValue::Bool(full.unwrap_or(false)),
            ));
        }
        Channel::Resend => {
            let to = match get("to") {
                None => Some(Vec::new()),
                Some(v) => check_address_list("to", v, &mut errors),
            };
            let cc = match get("cc") {
                None => Some(Vec::new()),
                Some(v) => check_address_list("cc", v, &mut errors),
            };
            let from = match get("from_address") {
                None => Some(None),
                Some(v) => check_opt_str(key("from_address"), v, &mut errors),
            };
            let reply = match get("reply_to") {
                None => Some(None),
                Some(v) => check_opt_str(key("reply_to"), v, &mut errors),
            };
            let prefix = match get("subject_prefix") {
                None => Some("[CoPilot]".to_string()),
                Some(v) => check_str(key("subject_prefix"), v, &mut errors),
            };
            let max = match get("max_per_hour") {
                None => Some(Some("20".to_string())),
                Some(PyValue::None) => Some(None),
                Some(v) => check_int(key("max_per_hour"), v, &mut errors).and_then(|n| {
                    if n.starts_with('-') || n == "0" {
                        errors.push(value_error(
                            "max_per_hour",
                            "max_per_hour must be at least 1, or null to disable the throttle",
                            v,
                        ));
                        None
                    } else {
                        Some(Some(n))
                    }
                }),
            };
            out.push(("to".into(), str_list(to.unwrap_or_default())));
            out.push(("cc".into(), str_list(cc.unwrap_or_default())));
            out.push(("from_address".into(), opt_str_value(from.flatten())));
            out.push(("reply_to".into(), opt_str_value(reply.flatten())));
            out.push((
                "subject_prefix".into(),
                PyValue::Str(prefix.unwrap_or_default()),
            ));
            out.push((
                "max_per_hour".into(),
                max.flatten().map_or(PyValue::None, PyValue::Int),
            ));
        }
        Channel::Teams => {
            let url = match get("webhook_url") {
                None | Some(PyValue::None) => Some(None),
                Some(v) => check_str(key("webhook_url"), v, &mut errors).and_then(|s| {
                    let cleaned = py_strip(&s).to_string();
                    if !cleaned.is_empty() && !cleaned.to_lowercase().starts_with("https://") {
                        errors.push(value_error(
                            "webhook_url",
                            "webhook_url must start with https://",
                            v,
                        ));
                        None
                    } else {
                        Some(Some(cleaned))
                    }
                }),
            };
            out.push(("webhook_url".into(), opt_str_value(url.flatten())));
        }
        Channel::Shuffle => {
            for name in ["app_id", "app_name"] {
                let value = match get(name) {
                    None => Some(None),
                    Some(v) => check_opt_str(key(name), v, &mut errors),
                };
                out.push((name.into(), opt_str_value(value.flatten())));
            }
        }
    }
    let declared = fields(channel);
    for (k, v) in data {
        if !declared.contains(&k.as_str()) {
            errors.push(PyError::new(
                key(k),
                "extra_forbidden",
                "Extra inputs are not permitted",
                v.clone(),
            ));
        }
    }
    if errors.is_empty() {
        Ok(PyValue::Dict(out))
    } else {
        Err(errors)
    }
}

/// A [`PyValue`] dict's items, or `None` for anything else.
pub fn dict_items(v: &PyValue) -> Option<&[(String, PyValue)]> {
    match v {
        PyValue::Dict(items) => Some(items),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pydantic;
    use crate::pyjson::{Dumps, dumps, from_json};
    use serde_json::Value;

    #[test]
    fn vectors_match_pydantic() {
        let vectors: Vec<Value> =
            serde_json::from_str(include_str!("../config_vectors.json")).unwrap();
        let mut checked = 0;
        for v in vectors {
            let channel = Channel::parse(v["channel"].as_str().unwrap()).unwrap();
            let input = from_json(&v["input"]);
            let items = dict_items(&input).unwrap();
            let got = validate(channel, items);
            match (&got, v.get("ok"), v.get("error")) {
                (Ok(dump), Some(want), None) => assert_eq!(
                    dumps(dump, Dumps::DEFAULT).unwrap(),
                    dumps(&from_json(want), Dumps::DEFAULT).unwrap(),
                    "{}",
                    v["input"]
                ),
                (Err(errors), None, Some(want)) => assert_eq!(
                    pydantic::format(channel.model_name(), errors),
                    want.as_str().unwrap(),
                    "{}",
                    v["input"]
                ),
                _ => panic!("{} -> {got:?}, want {v}", v["input"]),
            }
            checked += 1;
        }
        assert!(checked > 60, "{checked}");
    }
}
