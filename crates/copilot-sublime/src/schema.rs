//! `app/connectors/sublime/schema/alerts.py`: the webhook's body
//! (`AlertRequestBody` and its nested models, Pydantic's lax rules and
//! errors) and the listing's `SublimeAlertsSchema`, which every stored alert
//! is validated against (`from_orm`) before it is answered.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

/// `FlaggedRule` (the request's).
pub static FLAGGED_RULE: Model = Model::new(
    "FlaggedRule",
    &[
        Field::req("id", Ty::Str),
        Field::req("name", Ty::Str),
        Field::opt("severity", Ty::Nullable(&Ty::Str)),
        Field::req("tags", Ty::List(&Ty::Str)),
    ],
);

/// `Mailbox`.
pub static MAILBOX: Model = Model::new(
    "Mailbox",
    &[
        Field::opt("external_id", Ty::Nullable(&Ty::Str)),
        Field::req("id", Ty::Str),
    ],
);

/// `Message`.
pub static MESSAGE: Model = Model::new(
    "Message",
    &[
        Field::req("canonical_id", Ty::Str),
        Field::opt("external_id", Ty::Nullable(&Ty::Str)),
        Field::req("id", Ty::Str),
        Field::req("mailbox", Ty::Model(&MAILBOX)),
        Field::req("message_source_id", Ty::Str),
    ],
);

/// `TriggeredAction`.
pub static TRIGGERED_ACTION: Model = Model::new(
    "TriggeredAction",
    &[
        Field::req("id", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("type", Ty::Str),
    ],
);

/// `Data`.
pub static DATA: Model = Model::new(
    "Data",
    &[
        Field::req("flagged_rules", Ty::List(&Ty::Model(&FLAGGED_RULE))),
        Field::req("message", Ty::Model(&MESSAGE)),
        Field::req("triggered_actions", Ty::List(&Ty::Model(&TRIGGERED_ACTION))),
    ],
);

/// `AlertRequestBody`.
pub static ALERT_REQUEST_BODY: Model = Model::new(
    "AlertRequestBody",
    &[
        Field::req("api_version", Ty::Str).alias("api_version"),
        Field::req("created_at", Ty::Str).alias("created_at"),
        Field::req("data", Ty::Model(&DATA)),
        Field::req("id", Ty::Str),
        Field::req("type", Ty::Str),
    ],
);

/// `FlaggedRuleSchema`.
pub static FLAGGED_RULE_SCHEMA: Model = Model::new(
    "FlaggedRuleSchema",
    &[
        Field::req("rule_id", Ty::Str),
        Field::req("name", Ty::Str),
        Field::opt("severity", Ty::Nullable(&Ty::Str)),
        Field::req("tags", Ty::Str),
    ],
);

/// `MailboxSchema`.
pub static MAILBOX_SCHEMA: Model = Model::new(
    "MailboxSchema",
    &[
        Field::opt("external_id", Ty::Nullable(&Ty::Str)),
        Field::req("mailbox_id", Ty::Str),
    ],
);

/// `TriggeredActionSchema`.
pub static TRIGGERED_ACTION_SCHEMA: Model = Model::new(
    "TriggeredActionSchema",
    &[
        Field::req("action_id", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("type", Ty::Str),
    ],
);

/// `SenderSchema` (`RecipientSchema` has the same fields): the name is a
/// `str`, though the column is nullable.
pub static SENDER_SCHEMA: Model = Model::new(
    "SenderSchema",
    &[Field::req("email", Ty::Str), Field::req("name", Ty::Str)],
);

/// `RecipientSchema`.
pub static RECIPIENT_SCHEMA: Model = Model::new(
    "RecipientSchema",
    &[Field::req("email", Ty::Str), Field::req("name", Ty::Str)],
);

/// `SublimeAlertsSchema`.
pub static SUBLIME_ALERTS_SCHEMA: Model = Model::new(
    "SublimeAlertsSchema",
    &[
        Field::req("api_version", Ty::Str),
        Field::req("created_at", Ty::Str),
        Field::req("event_id", Ty::Str),
        Field::req("type", Ty::Str),
        Field::req("message_id", Ty::Str),
        Field::req("canonical_id", Ty::Str),
        Field::req("external_id", Ty::Str),
        Field::req("message_source_id", Ty::Str),
        Field::req("timestamp", Ty::DateTime),
        Field::req("flagged_rules", Ty::List(&Ty::Model(&FLAGGED_RULE_SCHEMA))),
        Field::req("mailbox", Ty::List(&Ty::Model(&MAILBOX_SCHEMA))),
        Field::req(
            "triggered_actions",
            Ty::List(&Ty::Model(&TRIGGERED_ACTION_SCHEMA)),
        ),
        Field::req("sender", Ty::List(&Ty::Model(&SENDER_SCHEMA))),
        Field::req("recipients", Ty::List(&Ty::Model(&RECIPIENT_SCHEMA))),
    ],
);

/// A dict in the given key order.
pub fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// `AlertResponseBody(success, message)` (the route's return annotation is
/// its response model).
pub fn alert_response(success: bool, message: String) -> PyValue {
    dict(vec![
        ("success", PyValue::Bool(success)),
        ("message", PyValue::Str(message)),
    ])
}

/// `SublimeAlertsResponse(sublime_alerts, success, message)`.
pub fn alerts_response(alerts: Vec<PyValue>) -> PyValue {
    dict(vec![
        ("sublime_alerts", PyValue::List(alerts)),
        ("success", PyValue::Bool(true)),
        (
            "message",
            PyValue::Str("Successfully retrieved all Sublime Alerts".into()),
        ),
    ])
}
