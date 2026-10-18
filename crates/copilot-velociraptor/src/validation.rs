//! `app/connectors/velociraptor/utils/validation.py`: the identifier formats
//! a value must have before it is interpolated into VQL
//! (GHSA-5542-j2fc-gqjm). Same patterns, same 400s.
//!
//! Free-form values (a command, a collection glob, artifact parameters) are
//! not identifiers and are not checked here, as in Python.

use std::sync::OnceLock;

use regex::Regex;

use copilot_upstream::py::{PyExc, PyResult};

fn pattern(slot: &'static OnceLock<Option<Regex>>, re: &str) -> Option<&'static Regex> {
    slot.get_or_init(|| Regex::new(re).ok()).as_ref()
}

fn full_match(slot: &'static OnceLock<Option<Regex>>, re: &str, value: Option<&str>) -> bool {
    match (value, pattern(slot, re)) {
        (Some(v), Some(re)) => re.is_match(v),
        _ => false,
    }
}

/// `"C.<hex>"`, `"C.<hex>-<ORGID>"` or `"server"`.
pub fn validate_client_id(value: Option<&str>) -> PyResult<&str> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    match value {
        Some(v)
            if full_match(
                &RE,
                r"^(server|C\.[0-9A-Fa-f]+(-[A-Za-z0-9._-]+)?)$",
                Some(v),
            ) =>
        {
            Ok(v)
        }
        _ => Err(PyExc::http(400, "Invalid Velociraptor client id")),
    }
}

/// `"root"` or a generated org id.
pub fn validate_org_id(value: Option<&str>) -> PyResult<&str> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    match value {
        Some(v) if full_match(&RE, r"^[A-Za-z0-9._-]+$", Some(v)) => Ok(v),
        _ => Err(PyExc::http(400, "Invalid Velociraptor org id")),
    }
}

/// Dotted alphanumeric segments, `/` for a source.
pub fn validate_artifact_name(value: Option<&str>) -> PyResult<&str> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    match value {
        Some(v) if full_match(&RE, r"^[A-Za-z0-9._/-]+$", Some(v)) => Ok(v),
        _ => Err(PyExc::http(400, "Invalid Velociraptor artifact name")),
    }
}

/// `"F.<alnum>"`.
pub fn validate_flow_id(value: Option<&str>) -> PyResult<&str> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    match value {
        Some(v) if full_match(&RE, r"^F\.[A-Za-z0-9]+$", Some(v)) => Ok(v),
        _ => Err(PyExc::http(400, "Invalid Velociraptor flow id")),
    }
}

/// A hostname without a VQL string-literal escape.
pub fn validate_hostname(value: Option<&str>) -> PyResult<&str> {
    match value {
        Some(v)
            if !v
                .chars()
                .any(|c| matches!(c, '\'' | '"' | '`' | '\\' | '\n' | '\r')) =>
        {
            Ok(v)
        }
        _ => Err(PyExc::http(400, "Invalid Velociraptor hostname")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers() {
        for ok in [
            "server",
            "C.475df76785008b04",
            "C.aaaaaaaaaaaaaaaa-OXXXXXXX",
            "C.ab-O1.2_3",
        ] {
            assert!(validate_client_id(Some(ok)).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "C.",
            "C.xyz",
            "C.12' OR 1=1",
            "c.12",
            "server ",
            "C.12\n",
            "C.12-",
            "Unknown",
            "n/a",
        ] {
            assert_eq!(
                validate_client_id(Some(bad)),
                Err(PyExc::http(400, "Invalid Velociraptor client id")),
                "{bad:?}"
            );
        }
        assert!(validate_client_id(None).is_err());
        assert!(validate_org_id(Some("root")).is_ok());
        assert!(validate_org_id(Some("O123")).is_ok());
        assert!(validate_org_id(Some("ro'ot")).is_err());
        assert!(validate_org_id(Some("")).is_err());
        assert!(validate_artifact_name(Some("Generic.Client.Info/BasicInformation")).is_ok());
        assert!(validate_artifact_name(Some("A B")).is_err());
        assert!(validate_flow_id(Some("F.CMVK8U")).is_ok());
        assert!(validate_flow_id(Some("F.")).is_err());
        assert!(validate_hostname(Some("web-01.example")).is_ok());
        assert!(validate_hostname(Some("web'01")).is_err());
        assert!(validate_hostname(None).is_err());
    }
}
