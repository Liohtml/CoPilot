//! `app/threat_intel/services/socfortress.py`: the SOCFortress threat-intel
//! lookup (`get_ioc_response`).

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{
    Invalid, Loc, PyError, construct, format_validation_error, kwargs, validate,
};
use copilot_upstream::py::{PyExc, PyResult, get, int_of, type_name};
use http::Method;

use crate::ThreatIntelState;
use crate::httpx::{self, HttpxError, Request};
use crate::py::py_float;
use crate::schema::{IOC_MAPPING, IOC_RESPONSE};

/// `invoke_socfortress_threat_intel_api` then `get_ioc_response`: `GET
/// {intel}?value={ioc}%26customer_code%3D{code}` (the customer code is part
/// of the one `value` parameter, as Python builds it), the licence key as
/// `x-api-key`, `module-version: your_module_version`. The answer's status
/// is not looked at; nothing is caught.
pub async fn lookup(
    st: &ThreatIntelState,
    license_key: &str,
    ioc_value: &str,
    customer_code: Option<&str>,
) -> PyResult<PyValue> {
    let value = format!(
        "{ioc_value}&customer_code={}",
        customer_code.unwrap_or("None")
    );
    tracing::info!("Invoking Socfortress Threat Intel API");
    let response = httpx::send(
        Request::new(Method::GET, st.urls.intel.clone())
            .header("module-version", Some("your_module_version"))
            .header("x-api-key", Some(license_key))
            .params(vec![("value".into(), value)]),
    )
    .await
    .map_err(HttpxError::into_py)?;
    let data = response.json()?;
    let mapping = get(&data, "data")?
        .cloned()
        .unwrap_or(PyValue::Dict(Vec::new()));
    let success = get(&data, "success")?
        .cloned()
        .unwrap_or(PyValue::Bool(false));
    let message = get(&data, "message")?
        .cloned()
        .unwrap_or_else(|| PyValue::Str("No message provided".into()));
    let mapping = ioc_mapping(&mapping)?;
    construct(
        &IOC_RESPONSE,
        &kwargs(vec![
            ("data", mapping),
            ("success", success),
            ("message", message),
        ]),
    )
}

/// What `convert_score_to_int` does with the input: `None` stays, a string
/// is `int(float(v))` or `None` when that raises `ValueError` /
/// `TypeError`, a number is `int(v)`; anything else is left to the `int`
/// validator. `Err` is the exception it lets through (`OverflowError` of an
/// infinity, the `ValueError` of a NaN number, which Pydantic reports).
pub fn score(v: &PyValue) -> PyResult<PyValue> {
    match v {
        PyValue::None => Ok(PyValue::None),
        PyValue::Str(s) => match py_float(s) {
            None => Ok(PyValue::None),
            Some(f) => match int_of(&PyValue::Float(f)) {
                Ok(i) => Ok(PyValue::Int(i)),
                Err(PyExc::ValueError(_)) => Ok(PyValue::None),
                Err(e) => Err(e),
            },
        },
        PyValue::Int(_) | PyValue::Bool(_) | PyValue::Float(_) => int_of(v).map(PyValue::Int),
        other => Ok(other.clone()),
    }
}

/// `IoCMapping(**data)`.
pub fn ioc_mapping(data: &PyValue) -> PyResult<PyValue> {
    let PyValue::Dict(items) = data else {
        return Err(PyExc::TypeError(format!(
            "app.threat_intel.schema.socfortress.IoCMapping() argument after ** must be a \
             mapping, not {}",
            type_name(data)
        )));
    };
    let mut items = items.clone();
    let mut score_error = None;
    if let Some(slot) = items.iter_mut().find(|(k, _)| k == "score") {
        match score(&slot.1) {
            Ok(v) => slot.1 = v,
            Err(PyExc::ValueError(msg)) => {
                score_error = Some(PyError {
                    loc: vec![Loc::Key("score".into())],
                    kind: "value_error",
                    msg: format!("Value error, {msg}"),
                    input: slot.1.clone(),
                });
                slot.1 = PyValue::None;
            }
            Err(e) => return Err(e),
        }
    }
    let input = PyValue::Dict(items);
    let Some(error) = score_error else {
        return construct(&IOC_MAPPING, &input);
    };
    let mut errors = match validate(&IOC_MAPPING, &input) {
        Ok(_) => Vec::new(),
        Err(Invalid::Errors(e)) => e,
        Err(Invalid::Abort(status, detail)) => return Err(PyExc::Http(status, detail)),
    };
    let before = ["comment", "ioc_source", "report_url"];
    let at = errors
        .iter()
        .position(|e| !matches!(e.loc.first(), Some(Loc::Key(k)) if before.contains(&k.as_str())))
        .unwrap_or(errors.len());
    errors.insert(at, error);
    Err(PyExc::Validation(format_validation_error(
        IOC_MAPPING.name,
        &errors,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_convert_like_the_validator() {
        let s = |v: &str| PyValue::Str(v.into());
        assert_eq!(score(&s("100.0")).unwrap(), PyValue::Int("100".into()));
        assert_eq!(score(&s(" 7 ")).unwrap(), PyValue::Int("7".into()));
        assert_eq!(score(&s("x")).unwrap(), PyValue::None);
        assert_eq!(score(&s("nan")).unwrap(), PyValue::None);
        assert!(matches!(
            score(&s("inf")),
            Err(PyExc::Other("OverflowError", _))
        ));
        assert_eq!(
            score(&PyValue::Bool(true)).unwrap(),
            PyValue::Int("1".into())
        );
        assert_eq!(
            score(&PyValue::Float(2.9)).unwrap(),
            PyValue::Int("2".into())
        );
        assert!(matches!(
            ioc_mapping(&PyValue::Dict(vec![("score".into(), PyValue::Float(f64::NAN))])),
            Err(PyExc::Validation(t)) if t.contains("Value error, cannot convert float NaN to integer")
        ));
    }
}
