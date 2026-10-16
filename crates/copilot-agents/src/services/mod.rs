//! The agents module's services, ported function by function.

pub mod csv;
pub mod epss;
pub mod matching;
pub mod sca;
pub mod sync;
pub mod velociraptor;
pub mod vulnerabilities;
pub mod wazuh;

use copilot_upstream::py::PyExc;
use copilot_wazuh::error::PyErr;

/// An `AttributeError` (a `.get` on something that is not a dict).
pub fn attr(text: String) -> PyExc {
    PyExc::AttributeError(text)
}

/// A Wazuh connector exception as a [`PyExc`].
pub fn wazuh_err(e: PyErr) -> PyExc {
    match e {
        PyErr::Http { status, detail } => PyExc::Http(status, detail),
        PyErr::Value(s) => PyExc::ValueError(s),
        PyErr::Other(s) => PyExc::Other("Exception", s),
    }
}

/// A Python value as JSON (for request bodies built from model dumps).
pub fn to_json(v: &copilot_auth::pyvalue::PyValue) -> serde_json::Value {
    use copilot_auth::pyvalue::PyValue;
    use serde_json::Value;
    match v {
        PyValue::None => Value::Null,
        PyValue::Bool(b) => Value::Bool(*b),
        PyValue::Int(i) => serde_json::from_str(i).unwrap_or(Value::Null),
        PyValue::Float(f) => serde_json::Number::from_f64(*f).map_or(Value::Null, Value::Number),
        PyValue::Str(s) => Value::String(s.clone()),
        PyValue::List(items) => Value::Array(items.iter().map(to_json).collect()),
        PyValue::Dict(items) => {
            Value::Object(items.iter().map(|(k, v)| (k.clone(), to_json(v))).collect())
        }
    }
}
