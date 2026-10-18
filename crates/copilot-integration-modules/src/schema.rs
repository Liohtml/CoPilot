//! The Pydantic models of `app/integrations/modules/schema/*.py` and
//! `app/integrations/mimecast/schema/mimecast.py`, on
//! `copilot_upstream::model` (lax validation, `ValidationError` texts, the
//! JSON-mode dump in declaration order). The `time_range` pattern
//! (`^[1-9][0-9]*[mhdw]$`) and the `set_time_bounds` model validators are
//! [`crate::sap_siem`]'s and [`crate::mimecast`]'s.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

fn none() -> PyValue {
    PyValue::None
}

fn s(v: &str) -> PyValue {
    PyValue::Str(v.into())
}

fn huntress() -> PyValue {
    s("Huntress")
}

fn mimecast() -> PyValue {
    s("Mimecast")
}

fn duo() -> PyValue {
    s("Duo")
}

fn cato() -> PyValue {
    s("CATO")
}

fn carbonblack() -> PyValue {
    s("CarbonBlack")
}

fn darktrace() -> PyValue {
    s("Darktrace")
}

fn sap_siem() -> PyValue {
    s("SAP SIEM")
}

fn three() -> PyValue {
    PyValue::Int("3".into())
}

fn zero() -> PyValue {
    PyValue::Int("0".into())
}

/// `InvokeSapSiemAnalysis.time_range`'s default: the *string* `"15"`, which
/// Pydantic does not validate.
fn fifteen_str() -> PyValue {
    s("15")
}

fn minutes_15() -> PyValue {
    s("15m")
}

fn minus_15m() -> PyValue {
    s("-15m")
}

fn siem_logs_uri() -> PyValue {
    s("/api/audit/get-siem-logs")
}

/// `{success, message}` (every `Invoke*Response`, `MimecastResponse`).
pub static INVOKE_RESPONSE: Model = Model::new(
    "InvokeResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `InvokeHuntressRequest`.
pub static INVOKE_HUNTRESS: Model = Model::new(
    "InvokeHuntressRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, huntress),
    ],
);

/// `InvokeMimecastRequest` (the module's).
pub static INVOKE_MIMECAST: Model = Model::new(
    "InvokeMimecastRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, mimecast),
    ],
);

/// `InvokeDuoRequest`.
pub static INVOKE_DUO: Model = Model::new(
    "InvokeDuoRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, duo),
    ],
);

/// `InvokeCatoRequest`.
pub static INVOKE_CATO: Model = Model::new(
    "InvokeCatoRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, cato),
    ],
);

/// `InvokeCarbonBlackRequest` (the job's only).
pub static INVOKE_CARBONBLACK: Model = Model::new(
    "InvokeCarbonBlackRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, carbonblack),
    ],
);

/// `InvokeDarktraceRequest` (the job's only).
pub static INVOKE_DARKTRACE: Model = Model::new(
    "InvokeDarktraceRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, darktrace),
    ],
);

/// `HuntressAuthKeys`.
pub static HUNTRESS_KEYS: Model = Model::new(
    "HuntressAuthKeys",
    &[
        Field::req("API_KEY", Ty::Str),
        Field::req("API_SECRET", Ty::Str),
    ],
);

/// `CollectHuntress` (its `SecretStr` fields validate as `str`; `to_wire()`
/// sends their values).
pub static COLLECT_HUNTRESS: Model = Model::new(
    "CollectHuntress",
    &[
        Field::req("integration", Ty::Str),
        Field::req("customer_code", Ty::Str),
        Field::req("graylog_host", Ty::Str),
        Field::req("graylog_port", Ty::Str),
        Field::req("wazuh_indexer_host", Ty::Str),
        Field::req("wazuh_indexer_username", Ty::Str),
        Field::req("wazuh_indexer_password", Ty::Str),
        Field::req("api_key", Ty::Str),
        Field::req("api_secret", Ty::Str),
    ],
);

/// `MimecastAuthKeys` (the module's and the integration's are the same).
pub static MIMECAST_KEYS: Model = Model::new(
    "MimecastAuthKeys",
    &[
        Field::req("APP_ID", Ty::Str),
        Field::req("APP_KEY", Ty::Str),
        Field::opt("EMAIL_ADDRESS", Ty::Nullable(&Ty::Str)),
        Field::req("ACCESS_KEY", Ty::Str),
        Field::req("SECRET_KEY", Ty::Str),
        Field::def("URI", Ty::Str, siem_logs_uri),
    ],
);

/// `CollectMimecast` (its `time_range` is always `"15m"`).
pub static COLLECT_MIMECAST: Model = Model::new(
    "CollectMimecast",
    &[
        Field::req("integration", Ty::Str),
        Field::req("customer_code", Ty::Str),
        Field::req("graylog_host", Ty::Str),
        Field::req("graylog_port", Ty::Str),
        Field::req("app_id", Ty::Str),
        Field::req("app_key", Ty::Str),
        Field::opt("email_address", Ty::Nullable(&Ty::Str)),
        Field::req("access_key", Ty::Str),
        Field::req("secret_key", Ty::Str),
        Field::def("uri", Ty::Str, siem_logs_uri),
        Field::def("time_range", Ty::Nullable(&Ty::Str), minutes_15),
    ],
);

/// `DuoAuthKeys`.
pub static DUO_KEYS: Model = Model::new(
    "DuoAuthKeys",
    &[
        Field::req("API_HOSTNAME", Ty::Str),
        Field::req("INTEGRATION_KEY", Ty::Str),
        Field::req("SECRET_KEY", Ty::Str),
    ],
);

/// `CollectDuo`.
pub static COLLECT_DUO: Model = Model::new(
    "CollectDuo",
    &[
        Field::req("integration", Ty::Str),
        Field::req("customer_code", Ty::Str),
        Field::req("integration_key", Ty::Str),
        Field::req("secret_key", Ty::Str),
        Field::req("api_host", Ty::Str),
        Field::req("api_endpoint", Ty::Str),
        Field::req("graylog_host", Ty::Str),
        Field::req("graylog_port", Ty::Str),
        Field::req("range", Ty::Str),
    ],
);

/// `CatoAuthKeys`.
pub static CATO_KEYS: Model = Model::new(
    "CatoAuthKeys",
    &[
        Field::req("API_KEY", Ty::Str),
        Field::req("ACCOUNT_ID", Ty::Int),
        Field::req("EVENT_TYPES", Ty::Str),
        Field::req("EVENT_SUB_TYPES", Ty::Str),
    ],
);

/// `CollectCato`.
pub static COLLECT_CATO: Model = Model::new(
    "CollectCato",
    &[
        Field::req("integration", Ty::Str),
        Field::req("customer_code", Ty::Str),
        Field::req("graylog_host", Ty::Str),
        Field::req("graylog_port", Ty::Str),
        Field::req("api_key", Ty::Str),
        Field::req("account_id", Ty::Int),
        Field::req("event_types", Ty::Str),
        Field::req("event_sub_types", Ty::Str),
    ],
);

/// `CarbonBlackAuthKeys`.
pub static CARBONBLACK_KEYS: Model = Model::new(
    "CarbonBlackAuthKeys",
    &[
        Field::req("carbonblack_api_url", Ty::Str),
        Field::req("carbonblack_api_key", Ty::Str),
        Field::req("carbonblack_api_id", Ty::Str),
        Field::req("carbonblack_org_key", Ty::Str),
        Field::def("time_range", Ty::Nullable(&Ty::Str), minus_15m),
    ],
);

/// `CollectCarbonBlack`.
pub static COLLECT_CARBONBLACK: Model = Model::new(
    "CollectCarbonBlack",
    &[
        Field::req("integration", Ty::Str),
        Field::req("customer_code", Ty::Str),
        Field::req("graylog_host", Ty::Str),
        Field::req("graylog_port", Ty::Str),
        Field::req("carbonblack_api_url", Ty::Str),
        Field::req("carbonblack_api_key", Ty::Str),
        Field::req("carbonblack_api_id", Ty::Str),
        Field::req("carbonblack_org_key", Ty::Str),
        Field::def("time_range", Ty::Nullable(&Ty::Str), minus_15m),
    ],
);

/// `DarktraceAuthKeys`.
pub static DARKTRACE_KEYS: Model = Model::new(
    "DarktraceAuthKeys",
    &[
        Field::req("PUBLIC_TOKEN", Ty::Str),
        Field::req("PRIVATE_TOKEN", Ty::Str),
        Field::req("HOST", Ty::Str),
        Field::req("PORT", Ty::Str),
    ],
);

/// `CollectDarktrace`.
pub static COLLECT_DARKTRACE: Model = Model::new(
    "CollectDarktrace",
    &[
        Field::req("integration", Ty::Str),
        Field::req("customer_code", Ty::Str),
        Field::req("graylog_host", Ty::Str),
        Field::req("graylog_port", Ty::Str),
        Field::req("public_token", Ty::Str),
        Field::req("private_token", Ty::Str),
        Field::req("darktrace_host", Ty::Str),
        Field::req("darktrace_port", Ty::Str),
        Field::req("timeframe", Ty::Str),
    ],
);

/// `SapSiemAuthKeys`.
pub static SAP_KEYS: Model = Model::new(
    "SapSiemAuthKeys",
    &[
        Field::req("API_KEY", Ty::Str),
        Field::req("SECRET_KEY", Ty::Str),
        Field::opt("USER_KEY", Ty::Nullable(&Ty::Str)),
        Field::req("API_DOMAIN", Ty::Str),
    ],
);

/// `CustomerDetails`.
pub static CUSTOMER_DETAILS: Model = Model::new(
    "CustomerDetails",
    &[
        Field::req("customer_code", Ty::Str),
        Field::req("iris_customer_id", Ty::Int),
    ],
);

/// `InvokeSapSiemRequest`'s fields (the module's and the integration's are
/// the same); `time_range`'s pattern and the model validator are applied
/// around it ([`crate::sap_siem::validate_request`]).
pub static INVOKE_SAP: Model = Model::new(
    "InvokeSapSiemRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, sap_siem),
        Field::def("threshold", Ty::Nullable(&Ty::Int), three),
        Field::def("time_range", Ty::Nullable(&Ty::Str), minutes_15),
        Field::opt("lower_bound", Ty::Str),
        Field::opt("upper_bound", Ty::Str),
    ],
);

/// `CollectSapSiemRequest`.
pub static COLLECT_SAP: Model = Model::new(
    "CollectSapSiemRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, sap_siem),
        Field::def("threshold", Ty::Nullable(&Ty::Int), three),
        Field::def("time_range", Ty::Nullable(&Ty::Str), minutes_15),
        Field::opt("lower_bound", Ty::Str),
        Field::opt("upper_bound", Ty::Str),
        Field::req("auth_keys", Ty::Model(&SAP_KEYS)),
        Field::req("customer_details", Ty::Model(&CUSTOMER_DETAILS)),
    ],
);

/// `InvokeSapSiemAnalysis`.
pub static SAP_ANALYSIS: Model = Model::new(
    "InvokeSapSiemAnalysis",
    &[
        Field::def("threshold", Ty::Int, zero),
        Field::def("time_range", Ty::Int, fifteen_str),
        Field::req("iris_customer_id", Ty::Int),
    ],
);

/// `MimecastRequest` (`/api/mimecast/invoke`, `/ttp/urls`); the
/// `time_range` pattern is checked around it.
pub static MIMECAST_REQUEST: Model = Model::new(
    "MimecastRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, mimecast),
        Field::def("time_range", Ty::Nullable(&Ty::Str), minutes_15),
    ],
);

/// `MimecastTTPURLSRequest`'s fields (its `__init__` and model validator are
/// [`crate::mimecast`]'s).
pub static MIMECAST_TTP_REQUEST: Model = Model::new(
    "MimecastTTPURLSRequest",
    &[
        Field::req("ApplicationID", Ty::Str),
        Field::req("ApplicationKey", Ty::Str),
        Field::req("AccessKey", Ty::Str),
        Field::req("SecretKey", Ty::Str),
        Field::req("EmailAddress", Ty::Str),
        Field::opt("BaseURL", Ty::Nullable(&Ty::Str)),
        Field::def("time_range", Ty::Nullable(&Ty::Str), minutes_15),
        Field::opt("headers", Ty::Any),
        Field::opt("pagination_token", Ty::Str),
        Field::opt("lower_bound", Ty::Str),
        Field::opt("upper_bound", Ty::Str),
    ],
);

/// `APIEndpointRegion` (the three `HttpUrl`s are checked by
/// [`crate::mimecast::is_http_url`] after this).
pub static ENDPOINT_REGION: Model = Model::new(
    "APIEndpointRegion",
    &[
        Field::req("code", Ty::Str),
        Field::req("api", Ty::Str),
        Field::req("mpp", Ty::Str),
        Field::req("adminConsole", Ty::Str),
        Field::req("name", Ty::Str),
    ],
);

/// `APIEndpointDataItem`.
pub static ENDPOINT_ITEM: Model = Model::new(
    "APIEndpointDataItem",
    &[
        Field::req("emailAddress", Ty::Str),
        Field::req("emailToken", Ty::Str),
        Field::req("authenticate", Ty::List(&Ty::Any)),
        Field::req("region", Ty::Model(&ENDPOINT_REGION)),
    ],
);

/// `APIEndpointMeta`.
pub static ENDPOINT_META: Model = Model::new("APIEndpointMeta", &[Field::req("status", Ty::Int)]);

/// `APIEndpointData`.
pub static ENDPOINT_DATA: Model = Model::new(
    "APIEndpointData",
    &[
        Field::req("meta", Ty::Model(&ENDPOINT_META)),
        Field::req("data", Ty::List(&Ty::Model(&ENDPOINT_ITEM))),
        Field::req("fail", Ty::List(&Ty::Any)),
    ],
);

/// `MimecastAPIEndpointResponse`.
pub static ENDPOINT_RESPONSE: Model = Model::new(
    "MimecastAPIEndpointResponse",
    &[
        Field::req("data", Ty::Model(&ENDPOINT_DATA)),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `DataItem` (given by name, so its `from_` field reports as `from_`).
pub static DATA_ITEM: Model = Model::new(
    "DataItem",
    &[
        Field::req("oldestFirst", Ty::Bool),
        Field::req("from_", Ty::DateTime),
        Field::req("to", Ty::DateTime),
        Field::req("route", Ty::Str),
        Field::req("scanResult", Ty::Str),
    ],
);

/// `TTPResponseClickLogs`: one clicked TTP URL.
pub static TTP_CLICK_LOGS: Model = Model::new(
    "TTPResponseClickLogs",
    &[
        Field::req("userEmailAddress", Ty::Str),
        Field::req("fromUserEmailAddress", Ty::Str),
        Field::req("url", Ty::Str),
        Field::req("ttpDefinition", Ty::Str),
        Field::req("subject", Ty::Str),
        Field::req("action", Ty::Str),
        Field::req("adminOverride", Ty::Str),
        Field::req("userOverride", Ty::Str),
        Field::req("scanResult", Ty::Str),
        Field::req("category", Ty::Str),
        Field::req("sendingIp", Ty::Str),
        Field::req("userAwarenessAction", Ty::Str),
        Field::req("date", Ty::Str),
        Field::req("actions", Ty::Str),
        Field::req("route", Ty::Str),
        Field::req("creationMethod", Ty::Str),
        Field::req("emailPartsDescription", Ty::List(&Ty::Str)),
        Field::req("messageId", Ty::Str),
    ],
);

/// `TTPResponseDataItem`.
pub static TTP_DATA_ITEM: Model = Model::new(
    "TTPResponseDataItem",
    &[Field::req(
        "clickLogs",
        Ty::List(&Ty::Model(&TTP_CLICK_LOGS)),
    )],
);

/// `TTPResponsePagination`.
pub static TTP_PAGINATION: Model = Model::new(
    "TTPResponsePagination",
    &[
        Field::req("pageSize", Ty::Int),
        Field::req("totalCount", Ty::Int),
        Field::opt("next", Ty::Nullable(&Ty::Str)),
    ],
);

/// `ResponseMeta`.
pub static TTP_META: Model = Model::new(
    "ResponseMeta",
    &[
        Field::req("pagination", Ty::Model(&TTP_PAGINATION)),
        Field::req("status", Ty::Int),
    ],
);

/// `TtpURLResponseBody`: one page of `/api/ttp/url/get-logs`.
pub static TTP_RESPONSE: Model = Model::new(
    "TtpURLResponseBody",
    &[
        Field::req("meta", Ty::Model(&TTP_META)),
        Field::req("data", Ty::List(&Ty::Model(&TTP_DATA_ITEM))),
        Field::req("fail", Ty::List(&Ty::Dict(&Ty::Any))),
    ],
);

/// `{"success": …, "message": …}`.
pub fn invoke_response(success: bool, message: &str) -> PyValue {
    PyValue::Dict(vec![
        ("success".into(), PyValue::Bool(success)),
        ("message".into(), PyValue::Str(message.into())),
    ])
}

/// The default of an absent `Optional` field.
pub fn absent() -> PyValue {
    none()
}
