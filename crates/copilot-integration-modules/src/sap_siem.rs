//! The SAP SIEM module: `app/integrations/modules/routes/sap_siem.py` and
//! `services/sap_siem/collect.py`.
//!
//! The analyses ("same user from different IPs", "brute force from one IP",
//! …) run inside the module container; CoPilot only POSTs the threshold,
//! the window and the customer's IRIS id. The `sap_siem_multiple_logins`
//! table and the CoPilot-side analyses that once read it are gone from the
//! Python code (their imports are commented out, Alembic does not create the
//! table), so there is nothing of them to port.
//!
//! The collection (`POST …/sap_siem`) has no `try`: every failure is the
//! exception's own answer. With comma-separated keys each key is POSTed as
//! a `CollectSapSiemRequest`. With one API key Python calls
//! `get_customer_meta_attribute(code, column)` without its session, so its
//! route always ends in the `AttributeError` of `Depends.execute` (uvicorn's
//! bare 500) and never collects; here that key is POSTed exactly as the
//! several-keys path POSTs each of its keys (RUST_MIGRATION.md §4, "Python
//! fails, Rust works").

use chrono::{Datelike, NaiveDateTime, TimeDelta, Timelike};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{
    Invalid, Loc, Model, PyError, Ty, field, format_validation_error, kwargs, validate,
    validate_body,
};
use copilot_upstream::py::{PyExc, PyResult, int_of, type_name};
use copilot_upstream::respond::{from_json, validation_error};
use copilot_web::{ApiError, JsonBody};

use crate::ModulesState;
use crate::error::{Fail, FailResult};
use crate::lookups;
use crate::schema;
use crate::upstream::{MODULE_TIMEOUT, SAP_URL};

/// `^[1-9][0-9]*[mhdw]$`, as pydantic-core's regex matches it (`$` is the
/// end of the text).
pub fn time_range_matches(s: &str) -> bool {
    let b = s.as_bytes();
    match (b.first(), b.last()) {
        (Some(first), Some(last)) if b.len() >= 2 => {
            (b'1'..=b'9').contains(first)
                && matches!(last, b'm' | b'h' | b'd' | b'w')
                && b[1..b.len() - 1].iter().all(u8::is_ascii_digit)
        }
        _ => false,
    }
}

/// The `string_pattern_mismatch` line of a `time_range` field.
pub fn pattern_error(value: &str) -> PyError {
    PyError {
        loc: vec![Loc::Key("time_range".into())],
        kind: "string_pattern_mismatch",
        msg: "String should match pattern '^[1-9][0-9]*[mhdw]$'".into(),
        input: PyValue::Str(value.into()),
    }
}

/// `model` validated, its `time_range` (a string) then checked against the
/// pattern — the error in its field's place among the others.
pub fn validate_with_pattern(
    model: &'static Model,
    values: &PyValue,
    body: bool,
) -> Result<PyValue, Vec<PyError>> {
    let result = if body {
        validate_body(&Ty::Model(model), values)
    } else {
        validate(model, values)
    };
    let pattern = match values.get("time_range") {
        Some(PyValue::Str(s)) if !time_range_matches(s) => Some(pattern_error(s)),
        _ => None,
    };
    let index = |e: &PyError| match e.loc.first() {
        Some(Loc::Key(k)) => model.fields.iter().position(|f| f.key() == k),
        _ => None,
    };
    let mine = model.fields.iter().position(|f| f.key() == "time_range");
    match (result, pattern) {
        (Ok(dump), None) => Ok(dump),
        (Ok(_), Some(p)) => Err(vec![p]),
        (Err(Invalid::Errors(mut errors)), p) => {
            if let Some(p) = p {
                let at = errors
                    .iter()
                    .position(|e| index(e) > mine)
                    .unwrap_or(errors.len());
                errors.insert(at, p);
            }
            Err(errors)
        }
        (Err(Invalid::Abort(..)), _) => Err(Vec::new()),
    }
}

/// `datetime.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"` (glibc's `%Y`
/// does not pad a year below 1000).
pub fn bound(t: NaiveDateTime) -> String {
    format!(
        "{}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.nanosecond() / 1_000_000 % 1000
    )
}

fn overflow(message: &str) -> PyExc {
    PyExc::Other("OverflowError", message.into())
}

/// The bounds `set_time_bounds` computes from a truthy `time_range`, or what
/// it raises: `time_range[-1]`, `int(time_range[:-1])`, the unit (another
/// leaves `lower_bound` unbound), `timedelta`'s and `datetime`'s range.
pub fn time_bounds(time_range: &PyValue, now: NaiveDateTime) -> PyResult<(String, String)> {
    let (unit, rest) = match time_range {
        PyValue::Str(s) => {
            let chars: Vec<char> = s.chars().collect();
            let n = chars.len();
            let last = chars.get(n.saturating_sub(1)).copied().unwrap_or_default();
            (
                PyValue::Str(last.to_string()),
                PyValue::Str(chars[..n.saturating_sub(1)].iter().collect()),
            )
        }
        PyValue::List(items) => {
            let n = items.len();
            (
                items
                    .get(n.saturating_sub(1))
                    .cloned()
                    .unwrap_or(PyValue::None),
                PyValue::List(items[..n.saturating_sub(1)].to_vec()),
            )
        }
        PyValue::Dict(_) => return Err(PyExc::KeyError("-1".into())),
        other => {
            return Err(PyExc::TypeError(format!(
                "'{}' object is not subscriptable",
                type_name(other)
            )));
        }
    };
    let amount = int_of(&rest)?;
    let per: i128 = match unit.as_str() {
        Some("m") => 60,
        Some("h") => 3_600,
        Some("d") => 86_400,
        Some("w") => 604_800,
        _ => {
            return Err(PyExc::Other(
                "UnboundLocalError",
                "cannot access local variable 'lower_bound' where it is not associated with a \
                 value"
                    .into(),
            ));
        }
    };
    let amount: i128 = amount
        .parse()
        .map_err(|_| overflow("Python int too large to convert to C int"))?;
    let seconds = amount
        .checked_mul(per)
        .ok_or_else(|| overflow("Python int too large to convert to C int"))?;
    // `timedelta`: the days as a C `int` first, then their range.
    let days = seconds.div_euclid(86_400);
    if i32::try_from(days).is_err() {
        return Err(overflow("Python int too large to convert to C int"));
    }
    if days.abs() > 999_999_999 {
        return Err(overflow(&format!(
            "days={days}; must have magnitude <= 999999999"
        )));
    }
    let delta = i64::try_from(seconds)
        .ok()
        .and_then(TimeDelta::try_seconds)
        .ok_or_else(|| overflow("date value out of range"))?;
    let lower = now
        .checked_sub_signed(delta)
        .filter(|t| (1..=9999).contains(&t.year()))
        .ok_or_else(|| overflow("date value out of range"))?;
    Ok((bound(lower), bound(now)))
}

/// `set_time_bounds(values)` (`mode="before"`): `values` with the two bounds
/// set (a key already there keeps its place), or what it raised.
pub fn set_time_bounds(values: &PyValue, now: NaiveDateTime) -> PyResult<PyValue> {
    let PyValue::Dict(items) = values else {
        return Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'get'",
            type_name(values)
        )));
    };
    let time_range = values.get("time_range").cloned().unwrap_or(PyValue::None);
    if !time_range.truthy() {
        return Ok(values.clone());
    }
    let (lower, upper) = time_bounds(&time_range, now)?;
    let mut out = items.clone();
    for (key, value) in [("lower_bound", lower), ("upper_bound", upper)] {
        match out.iter_mut().find(|(k, _)| k == key) {
            Some(slot) => slot.1 = PyValue::Str(value),
            None => out.push((key.into(), PyValue::Str(value))),
        }
    }
    Ok(PyValue::Dict(out))
}

/// A model carrying `set_time_bounds` and the `time_range` pattern
/// (`InvokeSapSiemRequest`, `CollectSapSiemRequest`) built from keyword
/// arguments: its dump, or the exception Python's constructor raises.
pub fn construct_bounded(
    model: &'static Model,
    values: &PyValue,
    now: NaiveDateTime,
) -> PyResult<PyValue> {
    let values = set_time_bounds(values, now).map_err(|e| match e {
        // A `ValueError` in the validator is a validation error at the root.
        PyExc::ValueError(m) => PyExc::Validation(format_validation_error(
            model.name,
            &[PyError {
                loc: Vec::new(),
                kind: "value_error",
                msg: format!("Value error, {m}"),
                input: values.clone(),
            }],
        )),
        other => other,
    })?;
    validate_with_pattern(model, &values, false)
        .map_err(|errors| PyExc::Validation(format_validation_error(model.name, &errors)))
}

/// The `InvokeSapSiemRequest` body as FastAPI validates it: the model
/// validator first (a `ValueError` is a 422 at the root, anything else it
/// raises the bare 500), then the fields.
pub fn validate_request(body: &JsonBody, now: NaiveDateTime) -> Result<PyValue, ApiError> {
    let input = match body {
        JsonBody::Missing => {
            return Err(validation_error(
                vec![PyError {
                    loc: Vec::new(),
                    kind: "missing",
                    msg: "Field required".into(),
                    input: PyValue::None,
                }],
                "body",
            ));
        }
        // Raw bytes: `bytes.get`.
        JsonBody::NotJson => {
            return Err(
                PyExc::AttributeError("'bytes' object has no attribute 'get'".into()).unhandled(),
            );
        }
        JsonBody::Value(v) => from_json(v),
    };
    let values = set_time_bounds(&input, now).map_err(|e| match e {
        PyExc::ValueError(m) => validation_error(
            vec![PyError {
                loc: Vec::new(),
                kind: "value_error",
                msg: format!("Value error, {m}"),
                input: PyValue::None,
            }],
            "body",
        ),
        other => other.unhandled(),
    })?;
    validate_with_pattern(&schema::INVOKE_SAP, &values, true)
        .map_err(|errors| validation_error(errors, "body"))
}

/// The current UTC time (`datetime.utcnow()`).
pub fn utcnow() -> NaiveDateTime {
    chrono::Utc::now().naive_utc()
}

fn text(v: &PyValue) -> String {
    v.as_str().unwrap_or_default().to_string()
}

/// `collect_sap_siem_route` after its body is valid (`request` is the
/// `InvokeSapSiemRequest` dump).
pub async fn collect(st: &ModulesState, request: &PyValue) -> FailResult<()> {
    let code = text(field(request, "customer_code"));
    let name = text(field(request, "integration_name"));
    let cis = lookups::integration_response(&st.ctx.db, &code).await?;
    let ci = lookups::find_customer_integration(&cis, &name)?;
    let keys = lookups::extract_auth_keys(ci, "SAP SIEM")?;
    let auth = copilot_upstream::model::construct(&schema::SAP_KEYS, &keys)?;
    let api_key = text(field(&auth, "API_KEY"));
    // `auth_keys.API_KEY.split(",")` — one key is a list of one (Python's
    // single-key branch fails before it sends anything, §4).
    for key in api_key.split(',') {
        let auth_keys = copilot_upstream::model::construct(
            &schema::SAP_KEYS,
            &kwargs(vec![
                ("API_KEY", PyValue::Str(key.into())),
                ("SECRET_KEY", field(&auth, "SECRET_KEY").clone()),
                ("USER_KEY", field(&auth, "USER_KEY").clone()),
                ("API_DOMAIN", field(&auth, "API_DOMAIN").clone()),
            ]),
        )?;
        let iris = lookups::iris_customer_id(&st.ctx.db, &code).await?;
        let details = copilot_upstream::model::construct(
            &schema::CUSTOMER_DETAILS,
            &kwargs(vec![
                ("customer_code", PyValue::Str(code.clone())),
                ("iris_customer_id", iris),
            ]),
        )?;
        let data = construct_bounded(
            &schema::COLLECT_SAP,
            &kwargs(vec![
                ("auth_keys", auth_keys),
                ("customer_code", PyValue::Str(code.clone())),
                ("integration_name", PyValue::Str(name.clone())),
                ("threshold", field(request, "threshold").clone()),
                ("time_range", field(request, "time_range").clone()),
                ("customer_details", details),
            ]),
            utcnow(),
        )?;
        post(st, "collect", data).await?;
    }
    Ok(())
}

/// One POST to the SAP module: a `RequestError` is logged and swallowed,
/// an answer that is not JSON is `response.json()`'s `JSONDecodeError`.
async fn post(st: &ModulesState, path: &str, data: PyValue) -> FailResult<()> {
    let url = format!("{SAP_URL}/{path}");
    match st.upstream.post_json(&url, data, &[], MODULE_TIMEOUT).await {
        Ok(resp) => {
            resp.json()?;
            Ok(())
        }
        Err(e) if e.is_request_error() => {
            tracing::error!(target: "copilot::integration_modules",
                "An error occurred while sending the POST request to copilot-sap-module: {}", e.message);
            Ok(())
        }
        Err(e) => Err(Fail::Py(e.into_py())),
    }
}

/// One analysis route of the module: its path under `/sap-siem/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Analysis {
    /// The CoPilot route (`/api/integrations/modules/sap_siem/<route>`).
    pub route: &'static str,
    /// The module's path.
    pub module_path: &'static str,
    /// The scheduler job that calls it.
    pub job_id: &'static str,
    /// The job's `time_range` without `extra_data`.
    pub default_window: i64,
}

/// The seven analyses.
pub const ANALYSES: &[Analysis] = &[
    Analysis {
        route: "successful_user_login_with_different_ip",
        module_path: "successful_user_login_with_different_ip",
        job_id: "invoke_sap_siem_integration_successful_user_login_with_different_ip",
        default_window: 15,
    },
    Analysis {
        route: "same_user_failed_login_from_different_ip",
        module_path: "same_user_failed_login_from_different_ip",
        job_id: "invoke_sap_siem_integration_same_user_failed_login_from_different_ip",
        default_window: 15,
    },
    Analysis {
        route: "same_user_failed_login_from_different_geo_location",
        module_path: "same_user_failed_login_from_different_geo_location",
        job_id: "invoke_sap_siem_integration_same_user_failed_login_from_different_geo_location",
        default_window: 15,
    },
    Analysis {
        route: "same_user_successful_login_from_different_geo_location",
        module_path: "same_user_successful_login_from_different_geo_location",
        job_id: "invoke_sap_siem_integration_same_user_successful_login_from_different_geo_location",
        default_window: 15,
    },
    Analysis {
        route: "brute_force_failed_logins_multiple_ips",
        module_path: "brute_force_failed_logins_multiple_ips",
        job_id: "invoke_sap_siem_integration_brute_force_failed_logins",
        default_window: 3,
    },
    Analysis {
        route: "brute_force_failed_logins_same_ip",
        module_path: "brute_force_failed_logins_same_ip",
        job_id: "invoke_sap_siem_integration_brute_force_failed_logins_same_ip",
        default_window: 3,
    },
    Analysis {
        route: "successful_login_after_multiple_failed_logins",
        module_path: "successful_login_after_multiple_failed_logins",
        job_id: "invoke_sap_siem_integration_successful_login_after_multiple_failed_logins",
        default_window: 3,
    },
];

/// The route's `InvokeSapSiemAnalysis(threshold=…, time_range=…,
/// iris_customer_id=…)` (validated again: the default `"15"` becomes 15),
/// then the POST.
pub async fn analyse(
    st: &ModulesState,
    analysis: &Analysis,
    threshold: PyValue,
    time_range: PyValue,
    iris_customer_id: PyValue,
) -> FailResult<()> {
    let data = copilot_upstream::model::construct(
        &schema::SAP_ANALYSIS,
        &kwargs(vec![
            ("threshold", threshold),
            ("time_range", time_range),
            ("iris_customer_id", iris_customer_id),
        ]),
    )?;
    post(st, analysis.module_path, data).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn now() -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 10, 17)
            .and_then(|d| d.and_hms_micro_opt(10, 20, 30, 123_987))
            .expect("date")
    }

    #[test]
    fn the_pattern_is_anchored_at_both_ends() {
        for ok in ["1m", "15m", "10h", "7d", "2w", "100000m"] {
            assert!(time_range_matches(ok), "{ok}");
        }
        for bad in [
            "", "m", "0m", "01m", "5", "5x", "-5m", "5m\n", " 5m", "5M", "1.5h",
        ] {
            assert!(!time_range_matches(bad), "{bad:?}");
        }
    }

    #[test]
    fn bounds_are_millisecond_utc_text() {
        let (lower, upper) = time_bounds(&PyValue::Str("15m".into()), now()).expect("ok");
        assert_eq!(lower, "2026-10-17T10:05:30.123Z");
        assert_eq!(upper, "2026-10-17T10:20:30.123Z");
        let (lower, _) = time_bounds(&PyValue::Str("53000w".into()), now()).expect("ok");
        assert!(lower.starts_with("1011-"), "{lower}");
        let (lower, _) = time_bounds(&PyValue::Str("53500w".into()), now()).expect("ok");
        assert!(
            lower.starts_with("1001-") || !lower.starts_with('0'),
            "{lower}"
        );
        let (lower, _) = time_bounds(&PyValue::Str("-5m".into()), now()).expect("ok");
        assert_eq!(lower, "2026-10-17T10:25:30.123Z");
    }

    #[test]
    fn the_validator_raises_what_python_raises() {
        let kind = |v: PyValue| match time_bounds(&v, now()) {
            Ok(_) => "ok".to_string(),
            Err(e) => format!("{e:?}"),
        };
        assert!(kind(PyValue::Str("5x".into())).contains("UnboundLocalError"));
        assert!(
            kind(PyValue::Str("ab".into())).contains("invalid literal for int() with base 10: 'a'")
        );
        assert!(kind(PyValue::Int("5".into())).contains("'int' object is not subscriptable"));
        assert!(kind(PyValue::Dict(vec![("a".into(), PyValue::None)])).contains("KeyError"));
        assert!(kind(PyValue::Str("99999999999w".into())).contains("OverflowError"));
        assert!(
            kind(PyValue::Str("999999999999999999999999999999999m".into()))
                .contains("OverflowError")
        );
        assert!(
            kind(PyValue::List(vec![
                PyValue::Str("5".into()),
                PyValue::Str("m".into())
            ]))
            .contains("TypeError")
        );
    }

    #[test]
    fn a_pattern_error_takes_its_fields_place() {
        let values = PyValue::Dict(vec![
            ("time_range".into(), PyValue::Str("0m".into())),
            ("lower_bound".into(), PyValue::Int("5".into())),
        ]);
        let errors = validate_with_pattern(&schema::INVOKE_SAP, &values, true).expect_err("bad");
        let kinds: Vec<&str> = errors.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, ["missing", "string_pattern_mismatch", "string_type"]);
    }
}
