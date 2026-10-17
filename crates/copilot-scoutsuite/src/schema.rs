//! `app/integrations/scoutsuite/schema/scoutsuite.py`: the two scan
//! requests (their `model_validator(mode="after")` raises the 400 `Invalid
//! report type.` once every field is valid), the GCP service-account key
//! the upload must be, and the answers.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

/// `AWSScoutSuiteReportRequest`.
pub static AWS_REQUEST: Model = Model::new(
    "AWSScoutSuiteReportRequest",
    &[
        Field::req("report_type", Ty::Str),
        Field::req("access_key_id", Ty::Str),
        Field::req("secret_access_key", Ty::Str),
        Field::req("report_name", Ty::Str),
    ],
);

/// `AzureScoutSuiteReportRequest`.
pub static AZURE_REQUEST: Model = Model::new(
    "AzureScoutSuiteReportRequest",
    &[
        Field::req("report_type", Ty::Str),
        Field::req("username", Ty::Str),
        Field::req("password", Ty::Str),
        Field::req("tenant_id", Ty::Str),
        Field::req("report_name", Ty::Str),
    ],
);

/// `GCPScoutSuiteJSON`: a service-account key's fields.
pub static GCP_JSON: Model = Model::new(
    "GCPScoutSuiteJSON",
    &[
        Field::req("type", Ty::Str),
        Field::req("project_id", Ty::Str),
        Field::req("private_key_id", Ty::Str),
        Field::req("private_key", Ty::Str),
        Field::req("client_email", Ty::Str),
        Field::req("client_id", Ty::Str),
        Field::req("auth_uri", Ty::Str),
        Field::req("token_uri", Ty::Str),
        Field::req("auth_provider_x509_cert_url", Ty::Str),
        Field::req("client_x509_cert_url", Ty::Str),
        Field::req("universe_domain", Ty::Str),
    ],
);

/// The class `GCPScoutSuiteJSON(**data)` names in its `TypeError`.
pub const GCP_JSON_QUALNAME: &str =
    "app.integrations.scoutsuite.schema.scoutsuite.GCPScoutSuiteJSON";

/// `ScoutSuiteReportOptions`' values.
pub const OPTIONS: [&str; 3] = ["aws", "azure", "gcp"];

/// A dict in the given key order.
pub fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn s(v: impl Into<String>) -> PyValue {
    PyValue::Str(v.into())
}

/// `ScoutSuiteReportOptionsResponse`.
pub fn options_response() -> PyValue {
    dict(vec![
        (
            "options",
            PyValue::List(OPTIONS.iter().map(|o| s(*o)).collect()),
        ),
        ("success", PyValue::Bool(true)),
        (
            "message",
            s("ScoutSuite Report generation options retrieved successfully"),
        ),
    ])
}

/// `AvailableScoutSuiteReportsResponse`.
pub fn available_response(reports: Vec<String>) -> PyValue {
    dict(vec![
        ("success", PyValue::Bool(true)),
        (
            "message",
            s("Available ScoutSuite reports retrieved successfully"),
        ),
        (
            "available_reports",
            PyValue::List(reports.into_iter().map(PyValue::Str).collect()),
        ),
    ])
}

/// `ScoutSuiteReportResponse`.
pub fn report_response(message: String) -> PyValue {
    dict(vec![
        ("success", PyValue::Bool(true)),
        ("message", PyValue::Str(message)),
    ])
}

/// The answer of a scan that was started.
pub fn started(cloud: &str) -> PyValue {
    report_response(format!(
        "{cloud} ScoutSuite report generation started successfully. This will take a few \
         minutes to complete. Check back in shortly."
    ))
}
