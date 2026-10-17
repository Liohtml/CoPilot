//! The Pydantic models of `schema/opencti.py`, as `copilot_upstream::model`
//! statics (declaration order, lax rules, `ValidationError` texts), and the
//! batch lookup's request model with its `values` validator.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Loc, Model, PyError, Ty};

use crate::py::{lower, strip};

fn list() -> PyValue {
    PyValue::List(Vec::new())
}

fn zero() -> PyValue {
    PyValue::Int("0".into())
}

fn no() -> PyValue {
    PyValue::Bool(false)
}

const OPT_STR: Ty = Ty::Nullable(&Ty::Str);
const OPT_INT: Ty = Ty::Nullable(&Ty::Int);

/// `OpenCTILabel`.
pub static LABEL: Model = Model::new(
    "OpenCTILabel",
    &[Field::req("value", Ty::Str), Field::opt("color", OPT_STR)],
);

/// `OpenCTIPageInfo`.
pub static PAGE_INFO: Model = Model::new(
    "OpenCTIPageInfo",
    &[
        Field::opt("global_count", OPT_INT),
        Field::def("has_next_page", Ty::Bool, no),
        Field::opt("end_cursor", OPT_STR),
    ],
);

macro_rules! meta_fields {
    ($($extra:expr),* $(,)?) => {
        &[
            Field::req("id", Ty::Str),
            Field::opt("standard_id", OPT_STR),
            Field::req("entity_type", Ty::Str),
            Field::opt("created_at", OPT_STR),
            Field::opt("updated_at", OPT_STR),
            Field::opt("created_by", OPT_STR),
            Field::def("labels", Ty::List(&Ty::Model(&LABEL)), list),
            Field::def("markings", Ty::List(&Ty::Str), list),
            $($extra),*
        ]
    };
}

/// `OpenCTIIndicator`.
pub static INDICATOR: Model = Model::new(
    "OpenCTIIndicator",
    meta_fields![
        Field::opt("name", OPT_STR),
        Field::opt("description", OPT_STR),
        Field::opt("pattern", OPT_STR),
        Field::opt("pattern_type", OPT_STR),
        Field::opt("main_observable_type", OPT_STR),
        Field::opt("score", OPT_INT),
        Field::opt("confidence", OPT_INT),
        Field::opt("valid_from", OPT_STR),
        Field::opt("valid_until", OPT_STR),
        Field::opt("revoked", Ty::Nullable(&Ty::Bool)),
    ],
);

/// `OpenCTIHash`.
pub static HASH: Model = Model::new(
    "OpenCTIHash",
    &[
        Field::req("algorithm", Ty::Str),
        Field::req("hash", Ty::Str),
    ],
);

/// `OpenCTIReportRef`.
pub static REPORT_REF: Model = Model::new(
    "OpenCTIReportRef",
    &[
        Field::req("id", Ty::Str),
        Field::opt("name", OPT_STR),
        Field::opt("published", OPT_STR),
    ],
);

/// `OpenCTIObservable`.
pub static OBSERVABLE: Model = Model::new(
    "OpenCTIObservable",
    meta_fields![
        Field::opt("value", OPT_STR),
        Field::opt("description", OPT_STR),
        Field::opt("score", OPT_INT),
        Field::opt("file_name", OPT_STR),
        Field::def("hashes", Ty::List(&Ty::Model(&HASH)), list),
        Field::def("indicators", Ty::List(&Ty::Model(&INDICATOR)), list),
        Field::def("indicators_count", Ty::Int, zero),
        Field::def("reports", Ty::List(&Ty::Model(&REPORT_REF)), list),
        Field::def("reports_count", Ty::Int, zero),
    ],
);

/// `OpenCTIExternalReference`.
pub static EXTERNAL_REFERENCE: Model = Model::new(
    "OpenCTIExternalReference",
    &[
        Field::opt("source_name", OPT_STR),
        Field::opt("url", OPT_STR),
        Field::opt("external_id", OPT_STR),
        Field::opt("description", OPT_STR),
    ],
);

/// `OpenCTIEntity`.
pub static ENTITY: Model = Model::new(
    "OpenCTIEntity",
    meta_fields![
        Field::def("parent_types", Ty::List(&Ty::Str), list),
        Field::opt("name", OPT_STR),
        Field::opt("description", OPT_STR),
        Field::opt("confidence", OPT_INT),
        Field::opt("score", OPT_INT),
        Field::def(
            "external_references",
            Ty::List(&Ty::Model(&EXTERNAL_REFERENCE)),
            list
        ),
    ],
);

/// `OpenCTIDependency`.
pub static DEPENDENCY: Model = Model::new(
    "OpenCTIDependency",
    &[Field::req("name", Ty::Str), Field::opt("version", OPT_STR)],
);

/// `OpenCTIAbout`.
pub static ABOUT: Model = Model::new(
    "OpenCTIAbout",
    &[
        Field::opt("version", OPT_STR),
        Field::def("dependencies", Ty::List(&Ty::Model(&DEPENDENCY)), list),
        Field::opt("user_name", OPT_STR),
        Field::opt("user_email", OPT_STR),
    ],
);

/// `OpenCTIAvailabilityResponse`.
pub static AVAILABILITY_RESPONSE: Model = Model::new(
    "OpenCTIAvailabilityResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("configured", Ty::Bool),
        Field::req("verified", Ty::Bool),
        Field::opt("platform_url", OPT_STR),
    ],
);

/// `OpenCTIAboutResponse`.
pub static ABOUT_RESPONSE: Model = Model::new(
    "OpenCTIAboutResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("about", Ty::Model(&ABOUT)),
    ],
);

/// `OpenCTIObservableLookupResponse`.
pub static LOOKUP_RESPONSE: Model = Model::new(
    "OpenCTIObservableLookupResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("value", Ty::Str),
        Field::req("found", Ty::Bool),
        Field::def("total", Ty::Int, zero),
        Field::def("observables", Ty::List(&Ty::Model(&OBSERVABLE)), list),
    ],
);

/// `OpenCTIValueLookup`.
pub static VALUE_LOOKUP: Model = Model::new(
    "OpenCTIValueLookup",
    &[
        Field::req("value", Ty::Str),
        Field::req("found", Ty::Bool),
        Field::def("observables", Ty::List(&Ty::Model(&OBSERVABLE)), list),
    ],
);

/// `OpenCTIBatchLookupResponse`.
pub static BATCH_RESPONSE: Model = Model::new(
    "OpenCTIBatchLookupResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::def("results", Ty::List(&Ty::Model(&VALUE_LOOKUP)), list),
        Field::def("truncated", Ty::Bool, no),
    ],
);

/// `OpenCTIIndicatorsResponse`.
pub static INDICATORS_RESPONSE: Model = Model::new(
    "OpenCTIIndicatorsResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::def("indicators", Ty::List(&Ty::Model(&INDICATOR)), list),
        Field::req("page_info", Ty::Model(&PAGE_INFO)),
    ],
);

/// `OpenCTIEntityResponse`.
pub static ENTITY_RESPONSE: Model = Model::new(
    "OpenCTIEntityResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("entity", Ty::Model(&ENTITY)),
    ],
);

/// `MAX_BATCH_VALUES`.
pub const MAX_BATCH_VALUES: usize = 100;
/// `MAX_VALUE_LENGTH`.
pub const MAX_VALUE_LENGTH: usize = 2048;

fn error(loc: Vec<Loc>, kind: &'static str, msg: impl Into<String>, input: PyValue) -> PyError {
    PyError {
        loc,
        kind,
        msg: msg.into(),
        input,
    }
}

/// `OpenCTIBatchLookupRequest.model_validate(body)` once FastAPI has the
/// body as a dict: the cleaned `values`, or Pydantic's errors (located
/// below the model, without the `body` prefix). `values: List[str]` with
/// `min_length=1, max_length=100` (a list over the maximum is `too_long`
/// before any item is looked at, as pydantic-core checks a list's length
/// first), then the `_clean` validator: strip, drop blanks and
/// case-insensitive duplicates, 2048 characters at most.
pub fn batch_values(body: &PyValue) -> Result<Vec<String>, Vec<PyError>> {
    let loc = || vec![Loc::Key("values".into())];
    let Some(raw) = body.get("values") else {
        return Err(vec![error(
            loc(),
            "missing",
            "Field required",
            body.clone(),
        )]);
    };
    let PyValue::List(items) = raw else {
        return Err(vec![error(
            loc(),
            "list_type",
            "Input should be a valid list",
            raw.clone(),
        )]);
    };
    if items.len() > MAX_BATCH_VALUES {
        return Err(vec![error(
            loc(),
            "too_long",
            format!(
                "List should have at most {MAX_BATCH_VALUES} items after validation, not {}",
                items.len()
            ),
            raw.clone(),
        )]);
    }
    let mut errors = Vec::new();
    let mut values = Vec::new();
    for (i, item) in items.iter().enumerate() {
        match item {
            PyValue::Str(v) => values.push(v.clone()),
            other => errors.push(error(
                vec![Loc::Key("values".into()), Loc::Index(i)],
                "string_type",
                "Input should be a valid string",
                other.clone(),
            )),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    if values.is_empty() {
        return Err(vec![error(
            loc(),
            "too_short",
            "List should have at least 1 item after validation, not 0",
            raw.clone(),
        )]);
    }
    let value_error = |text: String| {
        vec![error(
            loc(),
            "value_error",
            format!("Value error, {text}"),
            PyValue::List(values.iter().cloned().map(PyValue::Str).collect()),
        )]
    };
    let mut seen: Vec<String> = Vec::new();
    let mut cleaned = Vec::new();
    for value in &values {
        let value = strip(value);
        if value.chars().count() > MAX_VALUE_LENGTH {
            return Err(value_error(format!(
                "Each value must be at most {MAX_VALUE_LENGTH} characters"
            )));
        }
        let key = lower(value);
        if !value.is_empty() && !seen.contains(&key) {
            seen.push(key);
            cleaned.push(value.to_string());
        }
    }
    if cleaned.is_empty() {
        return Err(value_error(
            "At least one non-blank value is required".into(),
        ));
    }
    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    fn kinds(body: &str) -> Result<Vec<String>, Vec<(String, String)>> {
        batch_values(&loads(body).unwrap()).map_err(|errs| {
            errs.into_iter()
                .map(|e| (e.kind.to_string(), e.msg))
                .collect()
        })
    }

    #[test]
    fn batch_values_validate_like_pydantic() {
        assert_eq!(
            kinds(r#"{"values": [" A ", "a", "b", ""]}"#).unwrap(),
            ["A", "b"]
        );
        assert_eq!(
            kinds(r#"{"values": []}"#).unwrap_err()[0].1,
            "List should have at least 1 item after validation, not 0"
        );
        assert_eq!(
            kinds(r#"{"values": ["  "]}"#).unwrap_err()[0].1,
            "Value error, At least one non-blank value is required"
        );
        assert_eq!(kinds(r#"{"values": "x"}"#).unwrap_err()[0].0, "list_type");
        assert_eq!(kinds(r#"{}"#).unwrap_err()[0].0, "missing");
        let errs = kinds(r#"{"values": [1, null, "x"]}"#).unwrap_err();
        assert_eq!(errs.len(), 2);
    }
}
