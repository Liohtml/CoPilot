//! `app/integrations/copilot_action/services/copilot_action.py`
//! (`CopilotActionService`): the inventory, one action, the metrics — each
//! answer the model Python builds, whatever went wrong.

use copilot_auth::pyvalue::{PyValue, loads_bytes};
use copilot_upstream::model::{construct, construct_star, field, kwargs};
use copilot_upstream::py::{PyExc, type_name};

use crate::copilot_action::client::{ActionHttp, HttpxError};
use crate::copilot_action::schema::{
    ACTION_DETAIL_RESPONSE, INVENTORY_METRICS_RESPONSE, INVENTORY_RESPONSE, set_icon_defaults,
};

/// `get_inventory`'s filters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InventoryQuery {
    /// `technology.value`.
    pub technology: Option<String>,
    /// `category`.
    pub category: Option<String>,
    /// `tag`.
    pub tag: Option<String>,
    /// `q`.
    pub q: Option<String>,
    /// `limit`.
    pub limit: i64,
    /// `offset`.
    pub offset: i64,
    /// `refresh`.
    pub refresh: bool,
    /// `include`.
    pub include: Option<String>,
}

impl InventoryQuery {
    /// `params`, in Python's order; empty strings are falsy and left out.
    fn params(&self) -> Vec<(String, String)> {
        let mut p = Vec::new();
        let mut put = |k: &str, v: &Option<String>| {
            if let Some(v) = v.as_deref().filter(|v| !v.is_empty()) {
                p.push((k.to_string(), v.to_string()));
            }
        };
        put("technology", &self.technology);
        put("category", &self.category);
        put("tag", &self.tag);
        put("q", &self.q);
        if self.limit != 100 {
            p.push(("limit".into(), self.limit.to_string()));
        }
        if self.offset != 0 {
            p.push(("offset".into(), self.offset.to_string()));
        }
        if self.refresh {
            p.push(("refresh".into(), "true".into()));
        }
        if let Some(v) = self.include.as_deref().filter(|v| !v.is_empty()) {
            p.push(("include".into(), v.to_string()));
        }
        p
    }
}

fn int(n: i64) -> PyValue {
    PyValue::Int(n.to_string())
}

fn str_v(s: impl Into<String>) -> PyValue {
    PyValue::Str(s.into())
}

/// `InventoryResponse(...)` of fixed values (the error answers).
fn inventory_failure(message: String, limit: Option<i64>, offset: Option<i64>) -> PyValue {
    let mut pairs = vec![
        ("copilot_actions", PyValue::List(Vec::new())),
        ("message", str_v(message)),
        ("success", PyValue::Bool(false)),
    ];
    if let (Some(limit), Some(offset)) = (limit, offset) {
        pairs.extend([
            ("total", int(0)),
            ("count", int(0)),
            ("limit", int(limit)),
            ("offset", int(offset)),
            ("has_more", PyValue::Bool(false)),
        ]);
    }
    construct(&INVENTORY_RESPONSE, &kwargs(pairs)).unwrap_or(PyValue::None)
}

/// `data.get(key, default)` on a JSON value: `AttributeError` unless a dict.
fn get(data: &PyValue, key: &str, default: PyValue) -> Result<PyValue, PyExc> {
    match data {
        PyValue::Dict(items) => Ok(items
            .iter()
            .find(|(k, _)| k == key)
            .map_or(default, |(_, v)| v.clone())),
        other => Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'get'",
            type_name(other)
        ))),
    }
}

/// `len(value)`.
fn py_len(value: &PyValue) -> Result<i64, PyExc> {
    let n = match value {
        PyValue::List(items) => items.len(),
        PyValue::Dict(items) => items.len(),
        PyValue::Str(s) => s.chars().count(),
        other => {
            return Err(PyExc::TypeError(format!(
                "object of type '{}' has no len()",
                type_name(other)
            )));
        }
    };
    Ok(i64::try_from(n).unwrap_or(i64::MAX))
}

/// The four patterns `get_inventory` reads a total from when the answer
/// has none (`re.search(…, re.IGNORECASE)`, group 2).
fn total_from_message(message: &PyValue) -> Result<Option<i64>, PyExc> {
    let PyValue::Str(message) = message else {
        return Err(PyExc::TypeError(format!(
            "expected string or bytes-like object, got '{}'",
            type_name(message)
        )));
    };
    let lower = message.to_lowercase();
    // `(\d+) of (\d+) matching items`, `Returned (\d+) of (\d+)`,
    // `(\d+)/(\d+) items`, `showing (\d+) of (\d+)`.
    let patterns: [(&str, &str, &str); 4] = [
        ("", " of ", " matching items"),
        ("returned ", " of ", ""),
        ("", "/", " items"),
        ("showing ", " of ", ""),
    ];
    for (prefix, sep, suffix) in patterns {
        if let Some(total) = find_pair(&lower, prefix, sep, suffix) {
            return Ok(Some(total));
        }
    }
    Ok(None)
}

/// The first `{prefix}(\d+){sep}(\d+){suffix}` in `s`: the second number
/// (ASCII digits: `int()` of the group).
fn find_pair(s: &str, prefix: &str, sep: &str, suffix: &str) -> Option<i64> {
    let digits = |t: &str| t.bytes().take_while(u8::is_ascii_digit).count();
    for (start, _) in s.char_indices() {
        let Some(after_prefix) = s[start..].strip_prefix(prefix) else {
            continue;
        };
        let first = digits(after_prefix);
        if first == 0 {
            continue;
        }
        let Some(after_sep) = after_prefix[first..].strip_prefix(sep) else {
            continue;
        };
        let second = digits(after_sep);
        if second == 0 {
            continue;
        }
        if after_sep[second..].starts_with(suffix) {
            return after_sep[..second].parse().ok();
        }
    }
    None
}

/// `get_inventory(...)`.
pub async fn get_inventory(http: &ActionHttp, key: &str, q: &InventoryQuery) -> PyValue {
    tracing::info!("Fetching inventory with params: {:?}", q.params());
    let answer = match http.get("/inventory", key, &q.params()).await {
        Ok(a) => a,
        Err(e) => {
            return inventory_failure(
                format!("HTTP error fetching inventory: {}", e.text()),
                Some(q.limit),
                Some(q.offset),
            );
        }
    };
    let Ok(data) = loads_bytes(&answer.body) else {
        return inventory_failure(
            "Invalid response format from inventory API".into(),
            None,
            None,
        );
    };
    let run = || -> Result<PyValue, PyExc> {
        let actions = get(&data, "copilot_actions", PyValue::List(Vec::new()))?;
        let count = py_len(&actions)?;
        let total = match get(&data, "total", PyValue::None)? {
            PyValue::None => {
                let message = get(&data, "message", str_v(""))?;
                match total_from_message(&message)? {
                    Some(t) => int(t),
                    None => int(count),
                }
            }
            other => other,
        };
        let total_n = match &total {
            PyValue::Int(t) => t.parse::<i128>().unwrap_or(0),
            PyValue::Bool(b) => i128::from(*b),
            PyValue::Float(f) => {
                let has_more = ((q.offset + count) as f64) < *f;
                return finish(&data, actions, total, count, q, has_more);
            }
            other => {
                return Err(PyExc::TypeError(format!(
                    "'<' not supported between instances of 'int' and '{}'",
                    type_name(other)
                )));
            }
        };
        let has_more = i128::from(q.offset + count) < total_n;
        finish(&data, actions, total, count, q, has_more)
    };
    run().unwrap_or_else(|e| {
        tracing::error!("Unexpected error fetching inventory: {}", e.display());
        inventory_failure(
            format!("Unexpected error: {}", e.display()),
            Some(q.limit),
            Some(q.offset),
        )
    })
}

fn finish(
    data: &PyValue,
    actions: PyValue,
    total: PyValue,
    count: i64,
    q: &InventoryQuery,
    has_more: bool,
) -> Result<PyValue, PyExc> {
    let next_offset = if has_more {
        int(q.offset + q.limit)
    } else {
        PyValue::None
    };
    let prev_offset = if q.offset > 0 {
        int((q.offset - q.limit).max(0))
    } else {
        PyValue::None
    };
    let mut dump = construct(
        &INVENTORY_RESPONSE,
        &kwargs(vec![
            ("copilot_actions", actions),
            (
                "message",
                get(data, "message", str_v("Successfully fetched inventory"))?,
            ),
            ("success", get(data, "success", PyValue::Bool(true))?),
            ("total", total),
            ("count", int(count)),
            ("limit", int(q.limit)),
            ("offset", int(q.offset)),
            ("has_more", PyValue::Bool(has_more)),
            ("next_offset", next_offset),
            ("prev_offset", prev_offset),
        ]),
    )?;
    if let PyValue::Dict(fields) = &mut dump {
        if let Some((_, items)) = fields.iter_mut().find(|(k, _)| k == "copilot_actions") {
            set_icon_defaults(items);
        }
    }
    Ok(dump)
}

/// `ActionDetailResponse(copilot_action=None, …)`: always a
/// `ValidationError` (the field is required and not `Optional`).
fn detail_none() -> PyExc {
    construct(
        &ACTION_DETAIL_RESPONSE,
        &kwargs(vec![
            ("copilot_action", PyValue::None),
            ("message", str_v("")),
            ("success", PyValue::Bool(false)),
        ]),
    )
    .err()
    .unwrap_or_else(|| PyExc::Other("RuntimeError", String::new()))
}

/// `get_action_by_name(name)`: the `ActionDetailResponse` dump, or what it
/// raises — the 404 `Action '…' not found` for an HTTP 404, else the
/// `ValidationError` of `ActionDetailResponse(copilot_action=None, …)`,
/// which every other failure ends in.
pub async fn get_action_by_name(
    http: &ActionHttp,
    key: &str,
    name: &str,
) -> Result<PyValue, PyExc> {
    tracing::info!("Fetching action details for: {name}");
    let answer = match http.get(&format!("/inventory/{name}"), key, &[]).await {
        Ok(a) => a,
        Err(HttpxError::Status(404, _)) => {
            tracing::warn!("Action not found: {name}");
            return Err(PyExc::http(404, format!("Action '{name}' not found")));
        }
        Err(_) => return Err(detail_none()),
    };
    let Ok(data) = loads_bytes(&answer.body) else {
        return Err(detail_none());
    };
    let mut dump = construct_star(
        &ACTION_DETAIL_RESPONSE,
        "app.integrations.copilot_action.schema.copilot_action.ActionDetailResponse",
        &data,
    )
    .map_err(|_| detail_none())?;
    if let PyValue::Dict(fields) = &mut dump {
        if let Some((_, item)) = fields.iter_mut().find(|(k, _)| k == "copilot_action") {
            let mut one = PyValue::List(vec![item.clone()]);
            set_icon_defaults(&mut one);
            if let PyValue::List(mut v) = one {
                if let Some(x) = v.pop() {
                    *item = x;
                }
            }
        }
    }
    Ok(dump)
}

/// `get_metrics()`.
pub async fn get_metrics(http: &ActionHttp, key: &str) -> PyValue {
    let failure = |message: String| {
        construct(
            &INVENTORY_METRICS_RESPONSE,
            &kwargs(vec![
                ("status", str_v("error")),
                ("metrics", PyValue::Dict(Vec::new())),
                ("message", str_v(message)),
                ("success", PyValue::Bool(false)),
            ]),
        )
        .unwrap_or(PyValue::None)
    };
    let answer = match http.get("/metrics", key, &[]).await {
        Ok(a) => a,
        Err(e) => return failure(format!("HTTP error fetching metrics: {}", e.text())),
    };
    let Ok(data) = loads_bytes(&answer.body) else {
        return failure("Invalid response format from metrics API".into());
    };
    let run = || -> Result<PyValue, PyExc> {
        construct(
            &INVENTORY_METRICS_RESPONSE,
            &kwargs(vec![
                ("status", get(&data, "status", str_v("unknown"))?),
                ("metrics", get(&data, "metrics", PyValue::Dict(Vec::new()))?),
                ("message", str_v("Successfully retrieved inventory metrics")),
                ("success", PyValue::Bool(true)),
            ]),
        )
    };
    run().unwrap_or_else(|e| failure(format!("Unexpected error: {}", e.display())))
}

/// A field of a dump (re-exported for the routes).
pub fn dump_field<'a>(dump: &'a PyValue, key: &str) -> &'a PyValue {
    field(dump, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_total_is_read_from_the_message_like_re_search() {
        let read = |m: &str| total_from_message(&str_v(m)).unwrap();
        assert_eq!(read("Returned 1 of 44 matching items"), Some(44));
        assert_eq!(read("RETURNED 2 OF 7"), Some(7));
        assert_eq!(read("page 5/12 Items here"), Some(12));
        assert_eq!(read("Showing 3 of 9 results"), Some(9));
        assert_eq!(read("x12 of 3 matching items"), Some(3));
        assert_eq!(read("1 of x"), None);
        assert_eq!(read(""), None);
        assert_eq!(
            total_from_message(&int(4)).unwrap_err().text(),
            "expected string or bytes-like object, got 'int'"
        );
    }

    #[test]
    fn params_follow_the_service() {
        let q = InventoryQuery {
            technology: Some("Wazuh".into()),
            category: Some(String::new()),
            tag: Some("t".into()),
            q: None,
            limit: 100,
            offset: 5,
            refresh: true,
            include: Some("a,b".into()),
        };
        assert_eq!(
            q.params(),
            vec![
                ("technology".to_string(), "Wazuh".to_string()),
                ("tag".into(), "t".into()),
                ("offset".into(), "5".into()),
                ("refresh".into(), "true".into()),
                ("include".into(), "a,b".into()),
            ]
        );
    }
}
