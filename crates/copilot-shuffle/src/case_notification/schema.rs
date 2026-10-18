//! `CaseNotificationCreate`, `CaseNotificationResponse`
//! (`app/incidents/schema/db_operations.py`) and `CreatedAlertPayload`
//! (`app/incidents/schema/incident_alert.py`).

use copilot_upstream::model::{Field, Model, Ty};

/// `CaseNotificationCreate`.
pub static CASE_NOTIFICATION_CREATE: Model =
    Model::new("CaseNotificationCreate", &[Field::req("case_id", Ty::Int)]);

/// `CaseNotificationResponse`.
pub static CASE_NOTIFICATION_RESPONSE: Model = Model::new(
    "CaseNotificationResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `CreatedAlertPayload`.
pub static CREATED_ALERT_PAYLOAD: Model = Model::new(
    "CreatedAlertPayload",
    &[
        Field::req("alert_context_payload", Ty::Dict(&Ty::Any)),
        Field::req("asset_payload", Ty::Str),
        Field::req("timefield_payload", Ty::Str),
        Field::req("alert_title_payload", Ty::Str),
        Field::opt("ioc_payload", Ty::Nullable(&Ty::Dict(&Ty::Any))),
        Field::req("source", Ty::Str),
        Field::opt("index_name", Ty::Nullable(&Ty::Str)),
        Field::opt("index_id", Ty::Nullable(&Ty::Str)),
        Field::opt("alert_id", Ty::Nullable(&Ty::Int)),
        Field::opt("rule_level", Ty::Nullable(&Ty::Int)),
        Field::opt("severity", Ty::Nullable(&Ty::Str)),
    ],
);
