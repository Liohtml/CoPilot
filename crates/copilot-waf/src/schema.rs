//! Request and response shapes — port of `app/customer_waf/schema/customer_waf.py`.
//!
//! Responses are a deliberate projection of what the WAF returns: the token
//! (plaintext or ciphertext) appears in none of them, a WAF event's
//! `raw_log` stays out, and a site's TLS / auth configuration is not exposed.
//! The models that read WAF answers are `copilot_upstream::model` statics
//! (Pydantic's lax rules and `ValidationError` text); request bodies are
//! read with `copilot_web::Validator` (the constraints and 422 texts).

use chrono::NaiveDateTime;
use copilot_auth::pyvalue::PyValue;
use copilot_core::time::to_pydantic_iso;
use copilot_upstream::model::{Field, Model, Ty};
use copilot_web::validate::{Loc, StrRules, Validator};
use serde_json::{Map, Value};

use crate::store::WafRow;

fn opt_dt(t: Option<NaiveDateTime>) -> PyValue {
    t.map_or(PyValue::None, |t| PyValue::Str(to_pydantic_iso(t)))
}

fn opt_str(s: &Option<String>) -> PyValue {
    s.clone().map_or(PyValue::None, PyValue::Str)
}

fn opt_int(n: Option<i32>) -> PyValue {
    n.map_or(PyValue::None, |n| PyValue::Int(n.to_string()))
}

/// `to_schema(row)`: the `WafInstance` dump (everything but the token).
pub fn instance(row: &WafRow) -> PyValue {
    PyValue::Dict(vec![
        ("id".into(), PyValue::Int(row.id.to_string())),
        (
            "customer_code".into(),
            PyValue::Str(row.customer_code.clone()),
        ),
        ("name".into(), PyValue::Str(row.name.clone())),
        ("api_url".into(), PyValue::Str(row.api_url.clone())),
        (
            "token_prefix".into(),
            PyValue::Str(row.token_prefix.clone()),
        ),
        ("verify_tls".into(), PyValue::Bool(row.verify_tls)),
        (
            "has_ca_cert".into(),
            PyValue::Bool(row.ca_cert_pem.as_deref().is_some_and(|p| !p.is_empty())),
        ),
        ("enabled".into(), PyValue::Bool(row.enabled)),
        ("last_verified_at".into(), opt_dt(row.last_verified_at)),
        (
            "last_verified_role".into(),
            opt_str(&row.last_verified_role),
        ),
        ("created_by".into(), opt_int(row.created_by)),
        ("created_at".into(), opt_dt(row.created_at)),
        ("updated_by".into(), opt_int(row.updated_by)),
        ("updated_at".into(), opt_dt(row.updated_at)),
        ("syslog_host".into(), opt_str(&row.syslog_host)),
        ("syslog_port".into(), opt_int(row.syslog_port)),
        ("graylog_input_id".into(), opt_str(&row.graylog_input_id)),
        ("graylog_stream_id".into(), opt_str(&row.graylog_stream_id)),
        (
            "graylog_index_set_id".into(),
            opt_str(&row.graylog_index_set_id),
        ),
        (
            "forwarding_provisioned_at".into(),
            opt_dt(row.forwarding_provisioned_at),
        ),
    ])
}

/// `WafCapabilities`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// `can_read`.
    pub can_read: bool,
    /// `can_block`.
    pub can_block: bool,
    /// `can_manage_forwarders`.
    pub can_manage_forwarders: bool,
}

impl Capabilities {
    /// The dump.
    pub fn dump(&self) -> PyValue {
        PyValue::Dict(vec![
            ("can_read".into(), PyValue::Bool(self.can_read)),
            ("can_block".into(), PyValue::Bool(self.can_block)),
            (
                "can_manage_forwarders".into(),
                PyValue::Bool(self.can_manage_forwarders),
            ),
        ])
    }
}

/// `WafVerifyResult`.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyResult {
    /// `reachable`.
    pub reachable: bool,
    /// `authenticated`.
    pub authenticated: bool,
    /// `reason`.
    pub reason: Option<String>,
    /// `detail`.
    pub detail: Option<String>,
    /// `waf_user_email` (already validated as `Optional[str]`).
    pub waf_user_email: PyValue,
    /// `waf_roles`.
    pub waf_roles: Vec<String>,
    /// `capabilities`.
    pub capabilities: Capabilities,
    /// `health` (a dict or `None`).
    pub health: PyValue,
}

impl VerifyResult {
    /// A failed check.
    pub fn failed(reachable: bool, reason: &str, detail: String) -> Self {
        Self {
            reachable,
            authenticated: false,
            reason: Some(reason.to_string()),
            detail: Some(detail),
            waf_user_email: PyValue::None,
            waf_roles: Vec::new(),
            capabilities: Capabilities::default(),
            health: PyValue::None,
        }
    }

    /// The dump.
    pub fn dump(&self) -> PyValue {
        PyValue::Dict(vec![
            ("reachable".into(), PyValue::Bool(self.reachable)),
            ("authenticated".into(), PyValue::Bool(self.authenticated)),
            ("reason".into(), opt_str(&self.reason)),
            ("detail".into(), opt_str(&self.detail)),
            ("waf_user_email".into(), self.waf_user_email.clone()),
            (
                "waf_roles".into(),
                PyValue::List(self.waf_roles.iter().cloned().map(PyValue::Str).collect()),
            ),
            ("capabilities".into(), self.capabilities.dump()),
            ("health".into(), self.health.clone()),
        ])
    }
}

// --- WAF answers ------------------------------------------------------------

/// `WafSite`.
pub static WAF_SITE: Model = Model::new(
    "WafSite",
    &[
        Field::req("id", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("hostname", Ty::Str),
        Field::req("upstream_url", Ty::Str),
        Field::req("is_enabled", Ty::Bool),
        Field::req("detection_mode", Ty::Bool),
        Field::opt("created_at", Ty::Nullable(&Ty::DateTime)),
    ],
);

/// `WafMatchedRule` (`extra="ignore"`).
pub static WAF_MATCHED_RULE: Model = Model::new(
    "WafMatchedRule",
    &[
        Field::opt("id", Ty::Nullable(&Ty::Str)),
        Field::opt("msg", Ty::Nullable(&Ty::Str)),
    ],
);

fn empty_list() -> PyValue {
    PyValue::List(Vec::new())
}

/// `WafEvent`.
pub static WAF_EVENT: Model = Model::new(
    "WafEvent",
    &[
        Field::req("id", Ty::Str),
        Field::req("timestamp", Ty::DateTime),
        Field::req("transaction_id", Ty::Str),
        Field::opt("site_id", Ty::Nullable(&Ty::Str)),
        Field::req("client_ip", Ty::Str),
        Field::req("method", Ty::Str),
        Field::req("uri", Ty::Str),
        Field::req("host", Ty::Str),
        Field::opt("rule_id", Ty::Nullable(&Ty::Str)),
        Field::req("action", Ty::Str),
        Field::opt("severity", Ty::Nullable(&Ty::Str)),
        Field::opt("anomaly_score", Ty::Nullable(&Ty::Int)),
        Field::def(
            "matched_rules",
            Ty::List(&Ty::Model(&WAF_MATCHED_RULE)),
            empty_list,
        ),
        Field::opt("geoip_country_code", Ty::Nullable(&Ty::Str)),
        Field::opt("geoip_country_name", Ty::Nullable(&Ty::Str)),
        Field::opt("geoip_city", Ty::Nullable(&Ty::Str)),
    ],
);

/// `WafEvent.model_fields`, in order.
pub const WAF_EVENT_FIELDS: &[&str] = &[
    "id",
    "timestamp",
    "transaction_id",
    "site_id",
    "client_ip",
    "method",
    "uri",
    "host",
    "rule_id",
    "action",
    "severity",
    "anomaly_score",
    "matched_rules",
    "geoip_country_code",
    "geoip_country_name",
    "geoip_city",
];

/// `WafRuleCount`.
pub static WAF_RULE_COUNT: Model = Model::new(
    "WafRuleCount",
    &[
        Field::opt("rule_id", Ty::Nullable(&Ty::Str)),
        Field::req("count", Ty::Int),
    ],
);

static WAF_IP_COUNT: Model = Model::new(
    "WafIpCount",
    &[
        Field::req("client_ip", Ty::Str),
        Field::req("count", Ty::Int),
    ],
);

static WAF_HOUR_COUNT: Model = Model::new(
    "WafHourCount",
    &[Field::req("hour", Ty::Str), Field::req("count", Ty::Int)],
);

static WAF_CATEGORY_COUNT: Model = Model::new(
    "WafCategoryCount",
    &[
        Field::req("category", Ty::Str),
        Field::req("count", Ty::Int),
    ],
);

static WAF_COUNTRY_COUNT: Model = Model::new(
    "WafCountryCount",
    &[
        Field::opt("country_code", Ty::Nullable(&Ty::Str)),
        Field::opt("country_name", Ty::Nullable(&Ty::Str)),
        Field::req("count", Ty::Int),
    ],
);

/// `WafStats`.
pub static WAF_STATS: Model = Model::new(
    "WafStats",
    &[
        Field::req("total_1h", Ty::Int),
        Field::req("blocked_1h", Ty::Int),
        Field::req("detected_1h", Ty::Int),
        Field::req("block_rate", Ty::Float),
        Field::def(
            "top_rules",
            Ty::List(&Ty::Model(&WAF_RULE_COUNT)),
            empty_list,
        ),
        Field::def("top_ips", Ty::List(&Ty::Model(&WAF_IP_COUNT)), empty_list),
        Field::def(
            "requests_per_hour",
            Ty::List(&Ty::Model(&WAF_HOUR_COUNT)),
            empty_list,
        ),
        Field::def(
            "attack_categories",
            Ty::List(&Ty::Model(&WAF_CATEGORY_COUNT)),
            empty_list,
        ),
        Field::def(
            "top_countries",
            Ty::List(&Ty::Model(&WAF_COUNTRY_COUNT)),
            empty_list,
        ),
        Field::opt("ingestion_lag_seconds", Ty::Nullable(&Ty::Float)),
        Field::opt("events_per_minute", Ty::Nullable(&Ty::Float)),
        Field::opt("caddy_healthy", Ty::Nullable(&Ty::Bool)),
    ],
);

/// `WafThreatIntelEntry`.
pub static WAF_THREAT_INTEL_ENTRY: Model = Model::new(
    "WafThreatIntelEntry",
    &[
        Field::req("ip_address", Ty::Str),
        Field::req("block_count", Ty::Int),
        Field::req("rule_hit_count", Ty::Int),
        Field::req("total_events", Ty::Int),
        Field::req("threat_score", Ty::Int),
        Field::def(
            "top_rules",
            Ty::List(&Ty::Model(&WAF_RULE_COUNT)),
            empty_list,
        ),
        Field::opt("country_code", Ty::Nullable(&Ty::Str)),
        Field::opt("country_name", Ty::Nullable(&Ty::Str)),
        Field::req("first_seen_at", Ty::DateTime),
        Field::req("last_seen_at", Ty::DateTime),
        Field::req("is_blocked", Ty::Bool),
    ],
);

/// `WafThreatIntelSummary`.
pub static WAF_THREAT_INTEL_SUMMARY: Model = Model::new(
    "WafThreatIntelSummary",
    &[
        Field::req("total_ips", Ty::Int),
        Field::opt("last_run_at", Ty::Nullable(&Ty::DateTime)),
        Field::opt("window_days", Ty::Nullable(&Ty::Int)),
        Field::opt("min_score", Ty::Nullable(&Ty::Int)),
    ],
);

/// `WafBlock`.
pub static WAF_BLOCK: Model = Model::new(
    "WafBlock",
    &[
        Field::req("target", Ty::Str),
        Field::req("rule_uuid", Ty::Str),
        Field::req("rule_id", Ty::Int),
        Field::req("name", Ty::Str),
        Field::def("description", Ty::Str, empty_str),
        Field::req("enabled", Ty::Bool),
        Field::req("created_by_copilot", Ty::Bool),
        Field::opt("created_at", Ty::Nullable(&Ty::DateTime)),
    ],
);

fn empty_str() -> PyValue {
    PyValue::Str(String::new())
}

// --- request bodies -----------------------------------------------------------

fn child(at: &Loc, name: &str) -> Loc {
    let mut l = at.clone();
    l.push(copilot_web::validate::LocPart::Key(name.into()));
    l
}

/// A `bool` field with a default (an explicit `null` is an error).
fn bool_or(v: &mut Validator, obj: &Map<String, Value>, at: &Loc, name: &str, d: bool) -> bool {
    match obj.get(name) {
        None => d,
        Some(_) => v.req_bool(obj, at, name),
    }
}

/// `WafInstanceCreate`.
#[derive(Debug, Clone, Default)]
pub struct InstanceCreate {
    /// `name` (1–100).
    pub name: String,
    /// `api_url` (≤ 1024).
    pub api_url: String,
    /// `service_token`.
    pub service_token: String,
    /// `verify_tls` (default off).
    pub verify_tls: bool,
    /// `ca_cert_pem` (≤ 65536).
    pub ca_cert_pem: Option<String>,
    /// `enabled` (default on).
    pub enabled: bool,
}

impl InstanceCreate {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            name: v.req_str(obj, at, "name", StrRules::max(100).min(1)),
            api_url: v.req_str(obj, at, "api_url", StrRules::max(1024)),
            service_token: v.req_str(obj, at, "service_token", StrRules::any()),
            verify_tls: bool_or(v, obj, at, "verify_tls", false),
            ca_cert_pem: v.opt_str(obj, at, "ca_cert_pem", StrRules::max(65536)),
            enabled: bool_or(v, obj, at, "enabled", true),
        }
    }
}

/// `WafInstanceUpdate`: every field optional (`None` = unchanged).
#[derive(Debug, Clone, Default)]
pub struct InstanceUpdate {
    /// `name`.
    pub name: Option<String>,
    /// `api_url`.
    pub api_url: Option<String>,
    /// `service_token`.
    pub service_token: Option<String>,
    /// `verify_tls`.
    pub verify_tls: Option<bool>,
    /// `ca_cert_pem`.
    pub ca_cert_pem: Option<String>,
    /// `enabled`.
    pub enabled: Option<bool>,
}

impl InstanceUpdate {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            name: v.opt_str(obj, at, "name", StrRules::max(100).min(1)),
            api_url: v.opt_str(obj, at, "api_url", StrRules::max(1024)),
            service_token: v.opt_str(obj, at, "service_token", StrRules::any()),
            verify_tls: v.opt_bool(obj, at, "verify_tls"),
            ca_cert_pem: v.opt_str(obj, at, "ca_cert_pem", StrRules::max(65536)),
            enabled: v.opt_bool(obj, at, "enabled"),
        }
    }
}

/// `WafBlockRequest`.
#[derive(Debug, Clone, Default)]
pub struct BlockRequest {
    /// `target` (≤ 64).
    pub target: String,
    /// `reason` (1–500).
    pub reason: String,
    /// `alert_id`.
    pub alert_id: Option<i64>,
    /// `case_id`.
    pub case_id: Option<i64>,
}

impl BlockRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            target: v.req_str(obj, at, "target", StrRules::max(64)),
            reason: v.req_str(obj, at, "reason", StrRules::max(500).min(1)),
            alert_id: v.opt_int(obj, at, "alert_id", Default::default()),
            case_id: v.opt_int(obj, at, "case_id", Default::default()),
        }
    }
}

/// `WafForwardingRequest`.
#[derive(Debug, Clone, Default)]
pub struct ForwardingRequest {
    /// `syslog_host` (≤ 255).
    pub syslog_host: Option<String>,
}

impl ForwardingRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            syslog_host: v.opt_str(obj, at, "syslog_host", StrRules::max(255)),
        }
    }
}

/// Exposed for the routes (`child` location).
pub fn field_loc(at: &Loc, name: &str) -> Loc {
    child(at, name)
}
