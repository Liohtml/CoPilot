//! Small Python-value helpers the SIEM services share.

use chrono::NaiveDateTime;
use copilot_auth::pyvalue::PyValue;
use copilot_db::DbError;
use copilot_upstream::model::{
    Invalid, Loc, Model, PyError, construct, format_validation_error, kwargs, validate,
};
use copilot_upstream::py::{PyExc, PyResult};
use serde_json::Value;

/// A `str`.
pub fn s(v: impl Into<String>) -> PyValue {
    PyValue::Str(v.into())
}

/// An `int`.
pub fn int(n: i64) -> PyValue {
    PyValue::Int(n.to_string())
}

/// A `dict` in the given order.
pub fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// A naive `datetime` (what the ORM loads), as a model input.
pub fn dt(t: NaiveDateTime) -> PyValue {
    PyValue::Str(copilot_wazuh::indexer::services::alerts::isoformat(t))
}

/// A database failure: SQLAlchemy's exception, which nothing catches (a
/// bare 500).
pub fn db(e: DbError) -> PyExc {
    PyExc::Other("DBAPIError", e.to_string())
}

/// `Model(**kwargs)`.
pub fn model(m: &'static Model, pairs: Vec<(&str, PyValue)>) -> PyResult<PyValue> {
    construct(m, &kwargs(pairs))
}

/// A Python `dict` whose keys need not be `str` (panel ids, table fields
/// as stored), in insertion order.
pub type AnyKeyDict = Vec<(PyValue, PyValue)>;

/// `TypeError: unhashable type` for a key that cannot go into a `dict`.
pub fn hashable(key: &PyValue) -> PyResult<()> {
    match key {
        PyValue::List(_) | PyValue::Dict(_) => Err(PyExc::TypeError(format!(
            "unhashable type: '{}'",
            copilot_upstream::py::type_name(key)
        ))),
        _ => Ok(()),
    }
}

/// `d[key] = value`: an equal key keeps its place (`1`, `1.0` and `True`
/// are one key).
pub fn set_item(d: &mut AnyKeyDict, key: PyValue, value: PyValue) -> PyResult<()> {
    hashable(&key)?;
    match d
        .iter_mut()
        .find(|(k, _)| copilot_upstream::py::py_eq(k, &key))
    {
        Some(slot) => slot.1 = value,
        None => d.push((key, value)),
    }
    Ok(())
}

/// A `Dict[str, …]` field's input: the `str`-keyed entries, and the
/// `string_type` error of every other key at `loc.<key>.[key]`, as
/// pydantic-core reports them.
pub fn str_keys(loc: &[Loc], d: &AnyKeyDict) -> (PyValue, Vec<PyError>) {
    let mut kept = Vec::new();
    let mut errors = Vec::new();
    for (k, v) in d {
        match k {
            PyValue::Str(key) => kept.push((key.clone(), v.clone())),
            other => {
                // pydantic-core's location of a key: an `int` (a `bool` as
                // one) by its value, anything else by its `repr`.
                let item = match other {
                    PyValue::Bool(b) => i64::from(*b).to_string(),
                    PyValue::Int(n) => n.clone(),
                    v => v.py_repr(),
                };
                let mut at = loc.to_vec();
                at.push(Loc::Key(item));
                at.push(Loc::Key("[key]".into()));
                errors.push(PyError {
                    loc: at,
                    kind: "string_type",
                    msg: "Input should be a valid string".into(),
                    input: other.clone(),
                });
            }
        }
    }
    (PyValue::Dict(kept), errors)
}

/// `Model(**kwargs)` with key errors found by [`str_keys`]: `before` are
/// those of fields declared before every field in `pairs` that can fail,
/// `after` those declared after them.
pub fn model_with_key_errors(
    m: &'static Model,
    pairs: Vec<(&str, PyValue)>,
    before: Vec<PyError>,
    after: Vec<PyError>,
) -> PyResult<PyValue> {
    if before.is_empty() && after.is_empty() {
        return model(m, pairs);
    }
    let rest = match validate(m, &kwargs(pairs)) {
        Ok(_) => Vec::new(),
        Err(Invalid::Errors(errors)) => errors,
        Err(Invalid::Abort(status, detail)) => return Err(PyExc::Http(status, detail)),
    };
    let errors: Vec<PyError> = before.into_iter().chain(rest).chain(after).collect();
    Err(PyExc::Validation(format_validation_error(m.name, &errors)))
}

/// A JSON value as `json.loads` makes it.
pub fn from_json(v: &Value) -> PyValue {
    copilot_wazuh::pymodel::py(v)
}

/// A Python value as the JSON a SQLAlchemy `JSON` column stores.
pub fn to_json(v: &PyValue) -> Value {
    match v {
        PyValue::None => Value::Null,
        PyValue::Bool(b) => Value::Bool(*b),
        PyValue::Int(i) => i
            .parse::<i64>()
            .map(Value::from)
            .or_else(|_| i.parse::<u64>().map(Value::from))
            .unwrap_or_else(|_| {
                i.parse::<f64>()
                    .ok()
                    .and_then(serde_json::Number::from_f64)
                    .map_or(Value::Null, Value::Number)
            }),
        PyValue::Float(f) => serde_json::Number::from_f64(*f).map_or(Value::Null, Value::Number),
        PyValue::Str(t) => Value::String(t.clone()),
        PyValue::List(items) => Value::Array(items.iter().map(to_json).collect()),
        PyValue::Dict(items) => {
            Value::Object(items.iter().map(|(k, v)| (k.clone(), to_json(v))).collect())
        }
    }
}

/// An `HTTPException(status, detail)`.
pub fn http(status: u16, detail: impl Into<String>) -> PyExc {
    PyExc::http(status, detail)
}
