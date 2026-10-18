//! Request and response shapes — ports of `soc_management/schema/` and
//! `customer_portal/schema/sla.py`.
//!
//! Responses are the Pydantic models in their field order. Floats are
//! written as CPython's `repr()` writes them (what `json.dumps` emits), and
//! datetimes as Pydantic renders a naive `datetime`.

pub mod calendar;
pub mod metrics;
pub mod policy;
pub mod portal;
pub mod pydate;

use serde::Serializer;
use serde::ser::Error as _;
use serde_json::value::RawValue;

/// Write `v` the way CPython's `json.dumps` writes a float.
pub fn py_float<S: Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    let raw =
        RawValue::from_string(copilot_auth::pyvalue::float_repr(*v)).map_err(S::Error::custom)?;
    serde::Serialize::serialize(&*raw, s)
}

/// [`py_float`] for an optional value (`null` for `None`).
pub fn py_opt_float<S: Serializer>(v: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(v) => py_float(v, s),
        None => s.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize)]
    struct T {
        #[serde(serialize_with = "py_float")]
        a: f64,
        #[serde(serialize_with = "py_opt_float")]
        b: Option<f64>,
        #[serde(serialize_with = "py_opt_float")]
        c: Option<f64>,
    }

    #[test]
    fn floats_render_like_python() {
        let t = T {
            a: 5400.0,
            b: Some(1e16),
            c: None,
        };
        assert_eq!(
            serde_json::to_string(&t).unwrap(),
            r#"{"a":5400.0,"b":1e+16,"c":null}"#
        );
        let t = T {
            a: -0.000012,
            b: Some(66.7),
            c: Some(1234.567891),
        };
        assert_eq!(
            serde_json::to_string(&t).unwrap(),
            r#"{"a":-1.2e-05,"b":66.7,"c":1234.567891}"#
        );
    }
}
