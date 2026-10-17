//! `schema/analyzers.py`: the response models, the run body and its data
//! type check (`RunAnalyzerBody.is_valid_datatype`).

use std::sync::LazyLock;

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};
use regex::Regex;

fn tlp_default() -> PyValue {
    PyValue::Int("1".into())
}

fn message_default() -> PyValue {
    PyValue::Str("custom message sent to analyzer".into())
}

/// `AnalyzersResponse`.
pub static ANALYZERS_RESPONSE: Model = Model::new(
    "AnalyzersResponse",
    &[
        Field::req("analyzers", Ty::List(&Ty::Str)),
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
    ],
);

/// `RunAnalyzerBody`'s fields (its `model_validator` is
/// [`is_valid_datatype`], run by the route once they validate).
pub static RUN_ANALYZER_BODY: Model = Model::new(
    "RunAnalyzerBody",
    &[
        Field::req("analyzer_name", Ty::Str),
        Field::req("analyzer_data", Ty::Str),
        Field::opt("data_type", Ty::Nullable(&Ty::Str)),
    ],
);

/// `RunAnalyzerResponse`.
pub static RUN_ANALYZER_RESPONSE: Model = Model::new(
    "RunAnalyzerResponse",
    &[
        Field::req("report", Ty::Dict(&Ty::Any)),
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
    ],
);

/// `AnalyzerJobData`.
pub static ANALYZER_JOB_DATA: Model = Model::new(
    "AnalyzerJobData",
    &[
        Field::req("data", Ty::Str),
        Field::req("dataType", Ty::Str),
        Field::def("tlp", Ty::Int, tlp_default),
        Field::def("message", Ty::Str, message_default),
    ],
);

/// `HASH_REGEX` (`re.match`: anchored at the start only).
static HASH: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^(?:[a-fA-F\d]{32}|[a-fA-F\d]{64})").ok());

/// `DOMAIN_REGEX`; Python's `$` also matches before a final newline.
static DOMAIN: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}\n?\z").ok()
});

/// `ipaddress.IPv4Address(value)` accepts it (CPython 3.11: four decimal
/// octets of one to three ASCII digits, no leading zero, at most 255).
pub fn is_ipv4(value: &str) -> bool {
    let octets: Vec<&str> = value.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|o| {
            !o.is_empty()
                && o.len() <= 3
                && o.bytes().all(|b| b.is_ascii_digit())
                && (*o == "0" || !o.starts_with('0'))
                && o.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// `RunAnalyzerBody.is_valid_datatype(value)`: `ip`, `hash`, `domain`, or
/// `None` (Python's `(False, "Unknown")`).
pub fn is_valid_datatype(value: &str) -> Option<&'static str> {
    let matches = |re: &LazyLock<Option<Regex>>| re.as_ref().is_some_and(|r| r.is_match(value));
    if is_ipv4(value) {
        Some("ip")
    } else if matches(&HASH) {
        Some("hash")
    } else if matches(&DOMAIN) {
        Some("domain")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_types_like_python() {
        for (input, want) in [
            ("1.2.3.4", Some("ip")),
            ("01.2.3.4", None),
            ("256.1.1.1", None),
            ("d41d8cd98f00b204e9800998ecf8427e", Some("hash")),
            ("d41d8cd98f00b204e9800998ecf8427ezzz", Some("hash")),
            ("example.com", Some("domain")),
            ("example.com\n", Some("domain")),
            ("Example.com", None),
            ("example.c", None),
            ("", None),
        ] {
            assert_eq!(is_valid_datatype(input), want, "{input:?}");
        }
    }
}
