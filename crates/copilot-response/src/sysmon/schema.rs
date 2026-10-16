//! `app/active_response/schema/sysmon_config.py`.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

fn no() -> PyValue {
    PyValue::Bool(false)
}

/// `SysmonConfigDeploymentResult`.
pub static DEPLOYMENT_RESULT: Model = Model::new(
    "SysmonConfigDeploymentResult",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("customer_code", Ty::Str),
        Field::def("worker_success", Ty::Bool, no),
        Field::opt("worker_message", Ty::Nullable(&Ty::Str)),
        Field::opt("error_detail", Ty::Nullable(&Ty::Str)),
    ],
);

/// `SysmonConfigListResponse`.
pub fn list_response(codes: Vec<String>) -> PyValue {
    PyValue::Dict(vec![
        ("success".into(), PyValue::Bool(true)),
        (
            "message".into(),
            PyValue::Str("Successfully retrieved list of customer sysmon configs".into()),
        ),
        (
            "customer_codes".into(),
            PyValue::List(codes.into_iter().map(PyValue::Str).collect()),
        ),
    ])
}

/// `SysmonConfigContentResponse`.
pub fn content_response(customer_code: &str, content: String) -> PyValue {
    PyValue::Dict(vec![
        ("success".into(), PyValue::Bool(true)),
        (
            "message".into(),
            PyValue::Str("Successfully retrieved Sysmon config".into()),
        ),
        ("customer_code".into(), PyValue::Str(customer_code.into())),
        ("config_content".into(), PyValue::Str(content)),
    ])
}
