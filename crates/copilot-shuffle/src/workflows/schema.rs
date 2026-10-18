//! `app/connectors/shuffle/schema/workflows.py`.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

fn empty_list() -> PyValue {
    PyValue::List(Vec::new())
}

/// `WorkflowsResponse`.
pub static WORKFLOWS_RESPONSE: Model = Model::new(
    "WorkflowsResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
        Field::def(
            "workflows",
            Ty::Nullable(&Ty::List(&Ty::Dict(&Ty::Any))),
            empty_list,
        ),
    ],
);

/// `WorkflowExecutionBodyModel`.
pub static WORKFLOW_EXECUTION_BODY: Model = Model::new(
    "WorkflowExecutionBodyModel",
    &[Field::req("workflow_id", Ty::Str)],
);

/// `WorkflowExecutionStatusResponseModel` (`last_run` required, nullable).
pub static WORKFLOW_EXECUTION_STATUS: Model = Model::new(
    "WorkflowExecutionStatusResponseModel",
    &[Field::req("last_run", Ty::Nullable(&Ty::Str))],
);

/// `WorkflowExecutionModel`.
pub static WORKFLOW_EXECUTION: Model = Model::new(
    "WorkflowExecutionModel",
    &[
        Field::req("status", Ty::Model(&WORKFLOW_EXECUTION_STATUS)),
        Field::req("workflow_id", Ty::Str),
        Field::req("workflow_name", Ty::Str),
    ],
);

/// `WorkflowExecutionResponseModel`.
pub static WORKFLOW_EXECUTION_RESPONSE: Model = Model::new(
    "WorkflowExecutionResponseModel",
    &[
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
        Field::req("workflows", Ty::List(&Ty::Model(&WORKFLOW_EXECUTION))),
    ],
);

/// `RequestWorkflowExecutionModel`.
pub static REQUEST_WORKFLOW_EXECUTION: Model = Model::new(
    "RequestWorkflowExecutionModel",
    &[
        Field::req("workflow_id", Ty::Str),
        Field::req("execution_argument", Ty::Str),
    ],
);

/// `ExecuteWorklow`'s `success` (its two `UUID4` fields are
/// [`crate::uuid4`]'s).
pub static EXECUTE_WORKFLOW_SUCCESS: Model =
    Model::new("ExecuteWorklow", &[Field::req("success", Ty::Bool)]);

/// `RequestWorkflowExecutionResponse`.
pub static REQUEST_WORKFLOW_EXECUTION_RESPONSE: Model = Model::new(
    "RequestWorkflowExecutionResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
        Field::req("data", Ty::Dict(&Ty::Any)),
    ],
);
