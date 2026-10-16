//! The models of `app/stack_provisioning/*/schema/` and of the Graylog
//! connector schemas the flows validate against, and the request bodies.
//!
//! The request models with a custom `__init__` (`ProvisionContentPackRequest`,
//! `ProvisionInfluxDBCheckRequest`, `DecommissionNetworkContentPackRequest`)
//! look their name up in an `Enum` before Pydantic sees a single field, so an
//! unknown name is the `HTTPException(400)` `__init__` raises, an unhashable
//! one the `TypeError` `Enum.__getitem__` raises (a bare 500), and only then
//! are the fields validated — inside `__init__`, which is why a nested model
//! there is `model_type`, not FastAPI's `model_attributes_type`.
//! `provisioning_vectors.json` pins the models against Pydantic.

use copilot_auth::pyvalue::{PyValue, loads};
use copilot_upstream::model::{Field, Model, Ty};
use copilot_web::ApiError;
use copilot_web::body::JsonBody;
use copilot_web::validate::{IntRules, Loc, LocPart, StrRules, Validator, body_loc};
use serde_json::{Map, Value};

// --- enums ---------------------------------------------------------------

/// `AvailbleContentPacksOverview` (what the listing offers).
pub const CONTENT_PACKS_OVERVIEW: &[(&str, &str)] = &[(
    "SOCFORTRESS_WAZUH_CONTENT_PACK",
    "The Wazuh Content Pack which includes Input, Stream, Pipeline Rules, Pipelines, and \
     Lookup Tables for Wazuh logs and the SOCFortress SIEM stack.",
)];

/// `AvailableContentPacks` (what the provisioning route accepts), by name.
pub const CONTENT_PACKS: &[&str] = &[
    "SOCFORTRESS_WAZUH_CONTENT_PACK",
    "SOCFORTRESS_FORTINET_INPUT_SYSLOG_TCP",
    "SOCFORTRESS_FORTINET_INPUT_SYSLOG_UDP",
    "SOCFORTRESS_FORTINET_PROCESSING_PIPELINE",
    "SOCFORTRESS_FORTINET_STREAM",
    "SOCFORTRESS_CROWDSTRIKE_INPUT_TCP",
    "SOCFORTRESS_CROWDSTRIKE_STREAM",
    "SOCFORTRESS_CROWDSTRIKE_PROCESSING_PIPELINE",
    "SOCFORTRESS_BITDEFENDER_INPUT_TCP",
    "SOCFORTRESS_BITDEFENDER_STREAM",
    "SOCFORTRESS_DEFENDER_FOR_ENDPOINT_INPUT_TCP",
    "SOCFORTRESS_DEFENDER_FOR_ENDPOINT_STREAM",
    "SOCFORTRESS_SONICWALL_INPUT_SYSLOG_TLS",
    "SOCFORTRESS_SONICWALL_STREAM",
    "SOCFORTRESS_SONICWALL_PROCESSING_PIPELINE",
];

/// `AvailableInfluxDBChecks`: name and description.
pub const INFLUX_CHECKS: &[(&str, &str)] = &[
    (
        "SOCFORTRESS_INFLUXDB_CPU_CHECK",
        "Threshold check on CPU idle time (`cpu`/`usage_idle`). Raises INFO below 25% idle, \
         WARN below 15% and CRIT below 5%, evaluated every minute per host.",
    ),
    (
        "SOCFORTRESS_INFLUXDB_MEMORY_CHECK",
        "Threshold check on available memory (`mem`/`available_percent`). Raises INFO below \
         25% available, WARN below 15% and CRIT below 10%, evaluated every minute per host.",
    ),
    (
        "SOCFORTRESS_INFLUXDB_DISK_CHECK",
        "Threshold check on filesystem usage (`disk`/`used_percent`), excluding pseudo \
         filesystems. Raises INFO above 75% used, WARN above 85% and CRIT above 90%, evaluated \
         every 5 minutes per host and mount point.",
    ),
    (
        "SOCFORTRESS_INFLUXDB_CRITICAL_SERVICES_CHECK",
        "Threshold check on the critical SIEM stack systemd units (`systemd_units`/\
         `active_code`). Raises CRIT when a watched unit reports failed, evaluated every minute \
         per host and unit. A unit that is stopped by design is deliberately ignored, so the \
         check is safe on a role-split stack where not every host runs every service.",
    ),
];

/// `AvailableNetworkConnectors` (decommissioning), by name.
pub const NETWORK_CONNECTORS: &[&str] = &["FORTINET", "CROWDSTRIKE", "SONICWALL"];

// --- models --------------------------------------------------------------

/// `content_packs.Data`: three fields read from the one `@value` key.
pub static CP_DATA: Model = Model::allowing_extra(
    "Data",
    &[
        Field::opt("description", Ty::Nullable(&Ty::Str)).alias("@value"),
        Field::opt("name", Ty::Nullable(&Ty::Str)).alias("@value"),
        Field::opt("title", Ty::Nullable(&Ty::Str)).alias("@value"),
    ],
);

/// `content_packs.Type`.
pub static CP_TYPE: Model = Model::allowing_extra(
    "Type",
    &[Field::req("name", Ty::Str), Field::req("version", Ty::Str)],
);

/// `content_packs.Constraint`.
pub static CP_CONSTRAINT: Model = Model::allowing_extra(
    "Constraint",
    &[Field::req("type", Ty::Str), Field::req("version", Ty::Str)],
);

/// `content_packs.Entity`.
pub static CP_ENTITY: Model = Model::allowing_extra(
    "Entity",
    &[
        Field::req("id", Ty::Str),
        Field::req("type", Ty::Model(&CP_TYPE)),
        Field::req("v", Ty::Str),
        Field::req("data", Ty::Model(&CP_DATA)),
        Field::req("constraints", Ty::List(&Ty::Model(&CP_CONSTRAINT))),
    ],
);

/// `content_packs.ContentPack`.
pub static CONTENT_PACK: Model = Model::allowing_extra(
    "ContentPack",
    &[
        Field::req("id", Ty::Str),
        Field::req("rev", Ty::Int),
        Field::req("v", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("summary", Ty::Str),
        Field::req("description", Ty::Str),
        Field::req("vendor", Ty::Str),
        Field::req("url", Ty::Str),
        Field::req("created_at", Ty::Str),
        Field::req("server_version", Ty::Str),
        Field::req("parameters", Ty::List(&Ty::Any)),
        Field::req("entities", Ty::List(&Ty::Model(&CP_ENTITY))),
    ],
);

/// `content_packs.ContentPackList`.
pub static CONTENT_PACK_LIST: Model = Model::allowing_extra(
    "ContentPackList",
    &[
        Field::req("total", Ty::Int),
        Field::req("content_packs", Ty::List(&Ty::Model(&CONTENT_PACK))),
        Field::opt("content_packs_metadata", Ty::Nullable(&Ty::Dict(&Ty::Any))),
    ],
);

/// `management.GraylogServerInfo`.
pub static GRAYLOG_SERVER_INFO: Model = Model::new(
    "GraylogServerInfo",
    &[
        Field::req("facility", Ty::Str),
        Field::req("codename", Ty::Str),
        Field::req("node_id", Ty::Str),
        Field::req("cluster_id", Ty::Str),
        Field::req("version", Ty::Str),
        Field::req("started_at", Ty::DateTime),
        Field::req("hostname", Ty::Str),
        Field::req("lifecycle", Ty::Str),
        Field::req("lb_status", Ty::Str),
        Field::req("timezone", Ty::Str),
        Field::req("operating_system", Ty::Str),
        Field::req("is_processing", Ty::Bool),
    ],
);

/// `ProvisionedInfluxDBCheck`.
pub static PROVISIONED_CHECK: Model = Model::new(
    "ProvisionedInfluxDBCheck",
    &[
        Field::req("name", Ty::Str),
        Field::req("check_name", Ty::Str),
        Field::req("action", Ty::Str),
        Field::opt("check_id", Ty::Nullable(&Ty::Str)),
    ],
);

/// Every model, by the name `provisioning_vectors.json` uses.
pub fn registry() -> Vec<(&'static str, &'static Model)> {
    vec![
        ("ContentPackList", &CONTENT_PACK_LIST),
        ("GraylogServerInfo", &GRAYLOG_SERVER_INFO),
        ("ProvisionedInfluxDBCheck", &PROVISIONED_CHECK),
    ]
}

// --- request bodies --------------------------------------------------------

fn child(at: &Loc, name: &str) -> Loc {
    let mut l = at.clone();
    l.push(LocPart::Key(name.to_string()));
    l
}

/// The body as an object, or the 422 FastAPI answers before any `__init__`.
fn object<'a>(v: &mut Validator, body: &'a JsonBody) -> Option<&'a Map<String, Value>> {
    let root = body_loc();
    match body {
        JsonBody::Missing => {
            v.missing(root);
            None
        }
        JsonBody::NotJson => {
            v.object(&Value::Null, &root);
            None
        }
        JsonBody::Value(value) => v.object(value, &root),
    }
}

/// A JSON value as Python sees it (`json.loads`).
fn py(value: &Value) -> PyValue {
    loads(&value.to_string()).unwrap_or(PyValue::None)
}

/// `Enum[name]` for the value `data.get(key)` gave: the member, or `Err`
/// with the `KeyError` (`None` = the `TypeError` of an unhashable value).
fn member<'a>(value: Option<&PyValue>, names: &'a [&'a str]) -> Result<&'a str, Option<String>> {
    match value {
        None => Err(Some("None".into())),
        Some(PyValue::List(_) | PyValue::Dict(_)) => Err(None),
        Some(PyValue::Str(s)) => names
            .iter()
            .copied()
            .find(|n| n == s)
            .ok_or_else(|| Some(s.clone())),
        Some(other) => Err(Some(other.py_str())),
    }
}

/// `TypeError: unhashable type: …` from `Enum.__getitem__`.
fn unhashable() -> ApiError {
    ApiError::internal("TypeError: unhashable type")
}

/// What a request reader gives: the body, or the answer it stops at.
pub type Read<T> = Result<T, ApiError>;

/// `ProvisionContentPackRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentPackRequest {
    /// `content_pack_name.name`.
    pub content_pack_name: &'static str,
}

fn keywords(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) {
    let l = child(at, "keywords");
    match obj.get("keywords") {
        None | Some(Value::Null) => {}
        Some(value) => {
            if let Some(k) = v.nested(value, &l, "ContentPackKeywords") {
                for name in ["customer_name", "customer_code", "protocol_type"] {
                    v.opt_str(k, &l, name, StrRules::default());
                }
                v.opt_int(k, &l, "syslog_port", IntRules::default());
                for name in ["tls_cert_file", "tls_key_file"] {
                    v.opt_str(k, &l, name, StrRules::default());
                }
            }
        }
    }
}

impl ContentPackRequest {
    /// Read the body (FastAPI, then `__init__`, then the fields).
    pub fn read(body: &JsonBody) -> Read<Self> {
        let mut v = Validator::new();
        let Some(obj) = object(&mut v, body) else {
            v.finish()?;
            return Err(ApiError::internal("unreachable"));
        };
        let name = match member(obj.get("content_pack_name").map(py).as_ref(), CONTENT_PACKS) {
            Ok(n) => n,
            Err(Some(shown)) => {
                return Err(ApiError::bad_request(format!(
                    "Content pack {shown} is not available. Please choose from the available \
                     content packs."
                )));
            }
            Err(None) => return Err(unhashable()),
        };
        keywords(&mut v, obj, &body_loc());
        v.finish()?;
        Ok(Self {
            content_pack_name: name,
        })
    }
}

/// `ProvisionInfluxDBCheckRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRequest {
    /// `check_name.name`.
    pub check_name: &'static str,
    /// `overwrite`.
    pub overwrite: bool,
}

const CHECK_NAMES: &[&str] = &[
    "SOCFORTRESS_INFLUXDB_CPU_CHECK",
    "SOCFORTRESS_INFLUXDB_MEMORY_CHECK",
    "SOCFORTRESS_INFLUXDB_DISK_CHECK",
    "SOCFORTRESS_INFLUXDB_CRITICAL_SERVICES_CHECK",
];

/// `check_name in AvailableInfluxDBChecks.__members__`.
pub fn is_check(name: &str) -> bool {
    CHECK_NAMES.contains(&name)
}

impl CheckRequest {
    /// Read the body.
    pub fn read(body: &JsonBody) -> Read<Self> {
        let mut v = Validator::new();
        let Some(obj) = object(&mut v, body) else {
            v.finish()?;
            return Err(ApiError::internal("unreachable"));
        };
        let name = match member(obj.get("check_name").map(py).as_ref(), CHECK_NAMES) {
            Ok(n) => n,
            Err(Some(shown)) => {
                return Err(ApiError::bad_request(format!(
                    "Check {shown} is not available. Please choose from the available checks."
                )));
            }
            Err(None) => return Err(unhashable()),
        };
        let overwrite = v.bool_or(obj, &body_loc(), "overwrite", false);
        v.finish()?;
        Ok(Self {
            check_name: name,
            overwrite,
        })
    }
}

/// `ProvisionInfluxDBAllChecksRequest`: `overwrite`.
pub fn read_all_checks(body: &JsonBody) -> Read<bool> {
    let mut v = Validator::new();
    let Some(obj) = object(&mut v, body) else {
        v.finish()?;
        return Err(ApiError::internal("unreachable"));
    };
    let overwrite = v.bool_or(obj, &body_loc(), "overwrite", false);
    v.finish()?;
    Ok(overwrite)
}

/// `DecommissionNetworkContentPackRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecommissionRequest {
    /// `network_connector.name`.
    pub network_connector: &'static str,
    /// `customer_code`.
    pub customer_code: String,
}

impl DecommissionRequest {
    /// Read the body: `__init__` upper-cases a truthy name (a non-string one
    /// has no `upper`: a bare 500), then looks it up.
    pub fn read(body: &JsonBody) -> Read<Self> {
        let mut v = Validator::new();
        let Some(obj) = object(&mut v, body) else {
            v.finish()?;
            return Err(ApiError::internal("unreachable"));
        };
        let raw = obj.get("network_connector").map(py);
        let raw = match raw {
            Some(value) if value.truthy() => match value {
                PyValue::Str(s) => Some(PyValue::Str(s.to_uppercase())),
                _ => {
                    return Err(ApiError::internal(
                        "AttributeError: object has no attribute 'upper'",
                    ));
                }
            },
            other => other,
        };
        let name = match member(raw.as_ref(), NETWORK_CONNECTORS) {
            Ok(n) => n,
            Err(Some(shown)) => {
                return Err(ApiError::bad_request(format!(
                    "{shown} is not available. Please choose from the available network \
                     connectors."
                )));
            }
            Err(None) => return Err(unhashable()),
        };
        let customer_code = v.req_str(obj, &body_loc(), "customer_code", StrRules::default());
        v.finish()?;
        Ok(Self {
            network_connector: name,
            customer_code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(text: &str) -> JsonBody {
        JsonBody::Value(serde_json::from_str(text).unwrap())
    }

    #[test]
    fn enum_lookups_come_first() {
        assert_eq!(
            ContentPackRequest::read(&body(
                r#"{"content_pack_name": "SOCFORTRESS_WAZUH_CONTENT_PACK", "keywords": null}"#
            ))
            .unwrap()
            .content_pack_name,
            "SOCFORTRESS_WAZUH_CONTENT_PACK"
        );
        for (text, status) in [
            (r#"{}"#, 400),
            (r#"{"content_pack_name": 1.0, "keywords": 5}"#, 400),
            (r#"{"content_pack_name": ["x"]}"#, 500),
            (
                r#"{"content_pack_name": "SOCFORTRESS_WAZUH_CONTENT_PACK", "keywords": 5}"#,
                422,
            ),
        ] {
            let err = ContentPackRequest::read(&body(text)).unwrap_err();
            assert_eq!(err.status().as_u16(), status, "{text}");
        }
        let d = DecommissionRequest::read(&body(
            r#"{"network_connector": "fortinet", "customer_code": "x"}"#,
        ))
        .unwrap();
        assert_eq!(d.network_connector, "FORTINET");
        for (text, status) in [
            (r#"{"network_connector": 5}"#, 500),
            (r#"{"network_connector": 0}"#, 400),
            (r#"{"network_connector": []}"#, 500),
            (r#"{"network_connector": "sonicwall"}"#, 422),
        ] {
            let err = DecommissionRequest::read(&body(text)).unwrap_err();
            assert_eq!(err.status().as_u16(), status, "{text}");
        }
        assert!(
            CheckRequest::read(&body(
                r#"{"check_name": "SOCFORTRESS_INFLUXDB_CPU_CHECK", "overwrite": "yes"}"#
            ))
            .unwrap()
            .overwrite
        );
        assert!(!read_all_checks(&body("{}")).unwrap());
        assert!(read_all_checks(&body(r#"{"overwrite": null}"#)).is_err());
    }
}
