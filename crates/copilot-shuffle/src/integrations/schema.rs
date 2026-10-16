//! `app/connectors/shuffle/schema/integrations.py`.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

fn empty_list() -> PyValue {
    PyValue::List(Vec::new())
}

fn empty_dict() -> PyValue {
    PyValue::Dict(Vec::new())
}

fn no() -> PyValue {
    PyValue::Bool(false)
}

fn empty_str() -> PyValue {
    PyValue::Str(String::new())
}

/// `ShuffleConnectorCredentialsResponse`.
pub static CREDENTIALS_RESPONSE: Model = Model::new(
    "ShuffleConnectorCredentialsResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("base_url", Ty::Str),
        Field::req("api_key", Ty::Str),
    ],
);

/// `IntegrationRequest`.
pub static INTEGRATION_REQUEST: Model = Model::new(
    "IntegrationRequest",
    &[
        Field::req("app_name", Ty::Str),
        Field::req("category", Ty::Str),
        Field::req("label", Ty::Str),
        Field::def(
            "fields",
            Ty::Nullable(&Ty::List(&Ty::Dict(&Ty::Any))),
            empty_list,
        ),
        Field::def("skip_workflow", Ty::Nullable(&Ty::Bool), no),
    ],
);

/// `ExecuteWorkflowRequest` (its `check_customer_code` model validator is
/// [`crate::integrations::services::check_customer_code`]).
pub static EXECUTE_WORKFLOW_REQUEST: Model = Model::new(
    "ExecuteWorkflowRequest",
    &[
        Field::req("workflow_id", Ty::Str),
        Field::def(
            "execution_arguments",
            Ty::Nullable(&Ty::Dict(&Ty::Any)),
            empty_dict,
        ),
        Field::def("start", Ty::Str, empty_str),
    ],
);
