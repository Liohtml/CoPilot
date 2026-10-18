//! Alert creation — port of `app/incidents/services/incident_alert.py`:
//! `create_alert` (one indexer document → a CoPilot alert, or a merge into
//! the customer's open alert of the same title), `create_alert_full` and the
//! steps they share.
//!
//! The side effects run in Python's order, each committed on its own:
//! the alert (then its SLA clocks, `SlaRecorder::alert_opened`), its
//! context, its asset, its IoC; the customer's legacy Shuffle workflow and
//! the MDR forward (both best-effort); the Talon investigation (handed to a
//! task, never awaited); the `alert_created` notification (a genuinely new
//! alert only); the write-back of the CoPilot id onto the document.

use chrono::NaiveDateTime;
use sqlx::MySql;
use sqlx::query::Query;

use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_core::notify::{AlertCreatedInput, alert_created_event};
use copilot_core::time::{mysql_datetime, now_utc_micros};
use copilot_incidents::config::{self, FieldTable};
use copilot_upstream::model::{
    Field, Invalid, Model, Ty, field, format_validation_error, validate,
};
use copilot_wazuh::error::PyErr;

use crate::IngestState;
use crate::es;
use crate::notify;
use crate::py::{
    basename, dict_get, dict_pop, dict_set, fromisoformat, is_ip_address, isoformat, py_int,
    py_strip,
};
use crate::source::{AlertDetails, single_alert_details};

// ---------------------------------------------------------------------------
// CreatedAlertPayload
// ---------------------------------------------------------------------------

/// The IoC an alert is created with (`ioc_payload`'s three keys the
/// creation reads).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ioc {
    /// `ioc_value`.
    pub value: String,
    /// `ioc_type` (`AlertIocValue`).
    pub kind: &'static str,
    /// `ioc_description`.
    pub description: String,
}

/// `CreatedAlertPayload`.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertPayload {
    /// `alert_context_payload`.
    pub context: Vec<(String, PyValue)>,
    /// `asset_payload`.
    pub asset: String,
    /// `timefield_payload`.
    pub timefield: String,
    /// `alert_title_payload`.
    pub title: String,
    /// `ioc_payload`.
    pub ioc: Option<Ioc>,
    /// `source`.
    pub source: String,
    /// `index_name`.
    pub index_name: Option<String>,
    /// `index_id`.
    pub index_id: Option<String>,
    /// `alert_id` (set once the alert exists).
    pub alert_id: Option<i64>,
    /// `rule_level`.
    pub rule_level: Option<i64>,
    /// `severity`.
    pub severity: Option<String>,
}

const OPT_STR: Ty = Ty::Nullable(&Ty::Str);

static CREATED_ALERT_PAYLOAD: Model = Model::new(
    "CreatedAlertPayload",
    &[
        Field::req("alert_context_payload", Ty::Dict(&Ty::Any)),
        Field::req("asset_payload", Ty::Str),
        Field::req("timefield_payload", Ty::Str),
        Field::req("alert_title_payload", Ty::Str),
        Field::opt("ioc_payload", Ty::Nullable(&Ty::Dict(&Ty::Any))),
        Field::req("source", Ty::Str),
        Field::opt("index_name", OPT_STR),
        Field::opt("index_id", OPT_STR),
        Field::opt("alert_id", Ty::Nullable(&Ty::Int)),
        Field::opt("rule_level", Ty::Nullable(&Ty::Int)),
        Field::opt("severity", OPT_STR),
    ],
);

/// The keyword arguments of a `CreatedAlertPayload(...)` call.
#[derive(Debug, Clone)]
pub struct PayloadArgs {
    /// `alert_context_payload=`.
    pub context: PyValue,
    /// `asset_payload=`.
    pub asset: PyValue,
    /// `timefield_payload=`.
    pub timefield: PyValue,
    /// `alert_title_payload=`.
    pub title: PyValue,
    /// `ioc_payload=`.
    pub ioc: Option<Ioc>,
    /// `source=`.
    pub source: PyValue,
    /// `index_name=`.
    pub index_name: PyValue,
    /// `index_id=`.
    pub index_id: PyValue,
    /// `rule_level=`.
    pub rule_level: Option<i64>,
    /// `severity=`.
    pub severity: Option<String>,
}

impl PayloadArgs {
    /// `CreatedAlertPayload(**args)`; `Err` is the `ValidationError` (a
    /// `ValueError`: the 400 of the backend's handler).
    pub fn build(self) -> Result<AlertPayload, PyErr> {
        let ioc_placeholder = self.ioc.as_ref().map_or(PyValue::None, |i| {
            PyValue::Dict(vec![("ioc_value".into(), PyValue::Str(i.value.clone()))])
        });
        let kwargs = PyValue::Dict(vec![
            ("alert_context_payload".into(), self.context),
            ("asset_payload".into(), self.asset),
            ("timefield_payload".into(), self.timefield),
            ("alert_title_payload".into(), self.title),
            ("ioc_payload".into(), ioc_placeholder),
            ("source".into(), self.source),
            ("index_name".into(), self.index_name),
            ("index_id".into(), self.index_id),
            (
                "rule_level".into(),
                self.rule_level
                    .map_or(PyValue::None, |l| PyValue::Int(l.to_string())),
            ),
            (
                "severity".into(),
                self.severity.clone().map_or(PyValue::None, PyValue::Str),
            ),
        ]);
        let dump = match validate(&CREATED_ALERT_PAYLOAD, &kwargs) {
            Ok(d) => d,
            Err(Invalid::Errors(e)) => {
                return Err(PyErr::Value(format_validation_error(
                    CREATED_ALERT_PAYLOAD.name,
                    &e,
                )));
            }
            Err(Invalid::Abort(status, detail)) => return Err(PyErr::http(status, detail)),
        };
        let s = |k: &str| field(&dump, k).as_str().unwrap_or_default().to_string();
        let opt = |k: &str| field(&dump, k).as_str().map(str::to_string);
        Ok(AlertPayload {
            context: match field(&dump, "alert_context_payload") {
                PyValue::Dict(d) => d.clone(),
                _ => Vec::new(),
            },
            asset: s("asset_payload"),
            timefield: s("timefield_payload"),
            title: s("alert_title_payload"),
            ioc: self.ioc,
            source: s("source"),
            index_name: opt("index_name"),
            index_id: opt("index_id"),
            alert_id: None,
            rule_level: self.rule_level,
            severity: self.severity,
        })
    }
}

// ---------------------------------------------------------------------------
// building the payload from a document
// ---------------------------------------------------------------------------

/// `clean_alert_title`: BOMs removed, stripped.
pub fn clean_alert_title(title: &str) -> String {
    let t = title
        .replace(['\u{feff}', '\u{fffe}'], "")
        .replace("\u{ff}\u{fe}", "");
    py_strip(&t).to_string()
}

/// `extract_rule_level`: `rule_level`, else `rule.level`, as `int()`.
pub fn extract_rule_level(context: &[(String, PyValue)]) -> Result<Option<i64>, PyErr> {
    if context.is_empty() {
        return Ok(None);
    }
    let mut candidate = dict_get(context, "rule_level").cloned();
    if candidate.as_ref().is_none_or(|c| *c == PyValue::None) {
        candidate = match dict_get(context, "rule") {
            Some(PyValue::Dict(rule)) => dict_get(rule, "level").cloned(),
            _ => None,
        };
    }
    match candidate {
        None | Some(PyValue::None) => Ok(None),
        Some(c) => py_int(&c).map_err(PyErr::Other),
    }
}

/// `severity_from_rule_level`.
pub fn severity_from_rule_level(level: Option<i64>) -> Option<String> {
    copilot_incidents::notify::severity_from_rule_level(level).map(str::to_string)
}

/// `get_process_name`: `process_name` dropped for osquery, then the
/// basename of the first process image field.
fn process_name(source: &mut Vec<(String, PyValue)>) -> Result<PyValue, PyErr> {
    if dict_get(source, "rule_group1") == Some(&PyValue::Str("osquery".into())) {
        dict_pop(source, "process_name");
    }
    let mut image = None;
    for key in [
        "process_image",
        "data_win_eventdata_image",
        "data_event_Image",
        "data_win_eventdata_sourceImage",
    ] {
        let v = dict_get(source, key).cloned();
        if v.as_ref().is_some_and(PyValue::truthy) {
            image = v;
            break;
        }
        image = v;
    }
    let name = match image.filter(PyValue::truthy) {
        None => None,
        Some(PyValue::Str(p)) => Some(basename(&p).to_string()),
        Some(other) => {
            return Err(PyErr::Other(format!(
                "expected str, bytes or os.PathLike object, not {}",
                crate::py::type_name(&other)
            )));
        }
    };
    Ok(PyValue::List(
        name.filter(|n| !n.is_empty())
            .map(PyValue::Str)
            .into_iter()
            .collect(),
    ))
}

/// `AlertIocValue`, from the most specific.
const IP: &str = "IP";
const HASH: &str = "HASH";
const URL: &str = "URL";
const DOMAIN: &str = "DOMAIN";

fn is_hash(v: &str) -> bool {
    matches!(v.len(), 32 | 40 | 64) && v.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `^[a-zA-Z][a-zA-Z0-9+.-]*://\S+$`.
fn is_url(v: &str) -> bool {
    let Some((scheme, rest)) = v.split_once("://") else {
        return false;
    };
    let mut sc = scheme.bytes();
    sc.next().is_some_and(|b| b.is_ascii_alphabetic())
        && sc.all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
        && !rest.is_empty()
        && !rest.chars().any(crate::py::is_py_space)
}

/// `^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`.
fn is_domain(v: &str) -> bool {
    let Some((labels, tld)) = v.rsplit_once('.') else {
        return false;
    };
    tld.len() >= 2
        && tld.bytes().all(|b| b.is_ascii_alphabetic())
        && labels
            .split('.')
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

/// `get_ioc_type`.
pub fn get_ioc_type(value: &str) -> Option<&'static str> {
    let v = py_strip(value);
    if is_ip_address(v) {
        Some(IP)
    } else if is_hash(v) {
        Some(HASH)
    } else if is_url(v) {
        Some(URL)
    } else if is_domain(v) {
        Some(DOMAIN)
    } else {
        None
    }
}

/// `classify_ioc_value`: the value to store and its type; a MISP composite
/// (`a|b`) keeps its most specific part.
pub fn classify_ioc_value(value: &str) -> Option<(String, &'static str)> {
    let v = py_strip(value);
    if let Some(t) = get_ioc_type(v) {
        return Some((v.to_string(), t));
    }
    if !v.contains('|') {
        return None;
    }
    let mut candidates: Vec<(&'static str, String)> = Vec::new();
    for part in v.split('|').map(py_strip) {
        if part.is_empty() {
            continue;
        }
        if let Some(t) = get_ioc_type(part) {
            if !candidates.iter().any(|(k, _)| *k == t) {
                candidates.push((t, part.to_string()));
            }
        }
    }
    [HASH, IP, URL, DOMAIN].into_iter().find_map(|preferred| {
        candidates
            .iter()
            .find(|(k, _)| *k == preferred)
            .map(|(k, p)| (p.clone(), *k))
    })
}

/// `build_ioc_payload`: the first IoC field's value, classified.
fn build_ioc(source: &[(String, PyValue)], ioc_fields: &[String]) -> Option<Ioc> {
    let first = ioc_fields
        .iter()
        .find_map(|f| dict_get(source, f).cloned())?;
    if !first.truthy() {
        tracing::info!(target: "copilot::ingest", "No IOC value found, returning None");
        return None;
    }
    let raw = first.py_str();
    let Some((value, kind)) = classify_ioc_value(&raw) else {
        tracing::warn!(
            target: "copilot::ingest",
            "IOC value {} has no recognised type (IP, DOMAIN, HASH or URL); creating the alert \
             without an IOC",
            first.py_repr()
        );
        return None;
    };
    let mut description = "IOC Auto-Generated From SOCFortress CoPilot".to_string();
    let stripped = py_strip(&raw);
    if value != stripped {
        description.push_str(&format!(
            " (extracted from composite value {})",
            str_repr(stripped)
        ));
    }
    Some(Ioc {
        value,
        kind,
        description,
    })
}

/// `FieldNames` for a source (`get_all_field_names`).
#[derive(Debug, Clone)]
struct FieldNames {
    field_names: Vec<String>,
    asset_name: String,
    timefield_name: String,
    alert_title_name: String,
    ioc_field_names: Vec<String>,
}

static FIELD_NAMES: Model = Model::new(
    "FieldNames",
    &[
        Field::req("field_names", Ty::List(&Ty::Str)),
        Field::req("asset_name", Ty::Str),
        Field::req("timefield_name", Ty::Str),
        Field::req("alert_title_name", Ty::Str),
        Field::opt("ioc_field_names", Ty::Nullable(&Ty::List(&Ty::Str))),
    ],
);

async fn field_names(st: &IngestState, source: &str) -> Result<FieldNames, PyErr> {
    let db = &st.ctx.db;
    let first = |v: Vec<String>| v.into_iter().next();
    let names = config::field_names(db, FieldTable::Field, source).await?;
    let asset = first(config::field_names(db, FieldTable::Asset, source).await?);
    let time = first(config::field_names(db, FieldTable::Timestamp, source).await?);
    let title = first(config::field_names(db, FieldTable::AlertTitle, source).await?);
    let iocs = config::field_names(db, FieldTable::Ioc, source).await?;
    let opt = |v: &Option<String>| v.clone().map_or(PyValue::None, PyValue::Str);
    let list = |v: &[String]| PyValue::List(v.iter().cloned().map(PyValue::Str).collect());
    let kwargs = PyValue::Dict(vec![
        ("field_names".into(), list(&names)),
        ("asset_name".into(), opt(&asset)),
        ("timefield_name".into(), opt(&time)),
        ("alert_title_name".into(), opt(&title)),
        ("ioc_field_names".into(), list(&iocs)),
    ]);
    if let Err(Invalid::Errors(e)) = validate(&FIELD_NAMES, &kwargs) {
        return Err(PyErr::Value(format_validation_error(FIELD_NAMES.name, &e)));
    }
    Ok(FieldNames {
        field_names: names,
        asset_name: asset.unwrap_or_default(),
        timefield_name: time.unwrap_or_default(),
        alert_title_name: title.unwrap_or_default(),
        ioc_field_names: iocs,
    })
}

/// `build_alert_payload(syslog_type, index_name, index_id, source.to_dict())`.
async fn build_alert_payload(
    st: &IngestState,
    details: &AlertDetails,
) -> Result<AlertPayload, PyErr> {
    let names = field_names(st, &details.syslog_type).await?;
    let mut source = details.source_dict();
    // `resolve_asset_name_from_payload`: the first comma-separated field
    // holding a truthy value.
    let asset = names
        .asset_name
        .split(',')
        .map(py_strip)
        .find_map(|f| dict_get(&source, f).filter(|v| v.truthy()).cloned());
    if asset.is_none() {
        tracing::warn!(target: "copilot::ingest", "No asset name found in any of these fields");
    }
    if dict_get(&source, &names.alert_title_name).is_none() {
        return Err(PyErr::http(
            400,
            format!(
                "Field name {} not found in alert payload",
                names.alert_title_name
            ),
        ));
    }
    let timefield = match dict_get(&source, &names.timefield_name) {
        Some(v) => v.clone(),
        None => match dict_get(&source, "timestamp") {
            Some(v) => v.clone(),
            None => PyValue::Str(isoformat(now_utc_micros())),
        },
    };
    let raw_title = dict_get(&source, &names.alert_title_name).cloned();
    let title = match raw_title.filter(PyValue::truthy) {
        None => PyValue::None,
        Some(PyValue::Str(t)) => PyValue::Str(clean_alert_title(&t)),
        Some(other) => {
            return Err(PyErr::Other(format!(
                "'{}' object has no attribute 'replace'",
                crate::py::type_name(&other)
            )));
        }
    };
    let rule_level = extract_rule_level(&source)?;
    // `build_alert_context_payload` (which drops osquery's `process_name`
    // from the document first), then `build_ioc_payload`.
    let process = process_name(&mut source)?;
    let mut context: Vec<(String, PyValue)> = names
        .field_names
        .iter()
        .filter_map(|f| dict_get(&source, f).map(|v| (f.clone(), v.clone())))
        .collect();
    dict_set(&mut context, "process_name", process);
    let ioc = build_ioc(&source, &names.ioc_field_names);
    PayloadArgs {
        context: PyValue::Dict(context),
        asset: asset.unwrap_or(PyValue::None),
        timefield,
        title,
        ioc,
        source: PyValue::Str(details.syslog_type.clone()),
        index_name: PyValue::Str(details.index.clone()),
        index_id: PyValue::Str(details.id.clone()),
        rule_level,
        severity: severity_from_rule_level(rule_level),
    }
    .build()
}

// ---------------------------------------------------------------------------
// customer code
// ---------------------------------------------------------------------------

/// `CustomerCodeKeys`, in their order.
const CUSTOMER_CODE_KEYS: [&str; 6] = [
    "agent_labels_customer",
    "data_office365_OrganizationId",
    "syslog_customer",
    "customer_code",
    "aws_account_id",
    "cluster_node",
];

/// Bind a Python value the way SQLAlchemy binds it in a comparison.
fn bind_py<'q>(
    q: Query<'q, MySql, sqlx::mysql::MySqlArguments>,
    v: &PyValue,
) -> Result<Query<'q, MySql, sqlx::mysql::MySqlArguments>, PyErr> {
    Ok(match v {
        PyValue::Str(s) => q.bind(s.clone()),
        PyValue::Int(i) => match i.parse::<i64>() {
            Ok(n) => q.bind(n),
            Err(_) => q.bind(i.clone()),
        },
        PyValue::Float(f) => q.bind(*f),
        PyValue::Bool(b) => q.bind(*b),
        PyValue::None => q.bind(None::<String>),
        other => {
            return Err(PyErr::Other(format!(
                "(pymysql.err.ProgrammingError) Python type {} cannot be bound",
                crate::py::type_name(other)
            )));
        }
    })
}

const AUTH_KEY_JOIN: &str = "FROM customer_integrations \
     JOIN integration_subscriptions ON customer_integrations.id = integration_subscriptions.customer_id \
     JOIN integration_services ON integration_subscriptions.integration_service_id = integration_services.id \
     JOIN integration_auth_keys ON integration_subscriptions.id = integration_auth_keys.subscription_id";

/// `get_customer_by_auth_key("Office365", "TENANT_ID", value)`: the code,
/// `None` where Python raises its `HTTPException` (not found, or any error).
async fn customer_by_office365_tenant(st: &IngestState, value: &PyValue) -> Option<String> {
    let sql = format!(
        "SELECT customer_integrations.customer_code, customer_integrations.customer_name {AUTH_KEY_JOIN} \
         WHERE integration_services.service_name = ? AND integration_auth_keys.auth_key_name = ? \
         AND integration_auth_keys.auth_value = ?"
    );
    let q = sqlx::query(&sql).bind("Office365").bind("TENANT_ID");
    let q = bind_py(q, value).ok()?;
    let rows = q.fetch_all(st.ctx.db.pool()).await.ok()?;
    let row = rows.first()?;
    sqlx::Row::try_get::<String, _>(row, 0).ok()
}

/// `resolve_customer_code_from_office365_tenant(tenant_id)`.
async fn office365_tenant_owner(st: &IngestState, tenant: &str) -> Result<Option<String>, PyErr> {
    if tenant.is_empty() {
        return Ok(None);
    }
    let sql = format!(
        "SELECT customer_integrations.customer_code {AUTH_KEY_JOIN} \
         WHERE integration_services.service_name = ? AND integration_auth_keys.auth_key_name = ? \
         AND integration_auth_keys.auth_value = ?"
    );
    let rows: Vec<String> = sqlx::query_scalar(&sql)
        .bind("Office365")
        .bind("TENANT_ID")
        .bind(tenant)
        .fetch_all(st.ctx.db.pool())
        .await?;
    Ok(rows.into_iter().next())
}

/// `resolve_customer_code_from_aws_account(account_id)`: the one customer a
/// *deployed* AWS instance names the account for (two claimants: nobody).
async fn aws_account_owner(st: &IngestState, account: &str) -> Result<Option<String>, PyErr> {
    if account.is_empty() {
        return Ok(None);
    }
    let sql = format!(
        "SELECT DISTINCT customer_integrations.customer_code {AUTH_KEY_JOIN} \
         WHERE integration_services.service_name = ? AND integration_auth_keys.auth_key_name = ? \
         AND integration_auth_keys.auth_value = ? AND customer_integrations.deployed IS true"
    );
    let codes: Vec<String> = sqlx::query_scalar(&sql)
        .bind("AWS")
        .bind("AWS_ACCOUNT_ID")
        .bind(account)
        .fetch_all(st.ctx.db.pool())
        .await?;
    if codes.len() > 1 {
        let mut sorted = codes.clone();
        sorted.sort();
        tracing::error!(
            target: "copilot::ingest",
            "AWS account {account} is claimed by several customers ({}); not routing it to any of them.",
            sorted.join(", ")
        );
        return Ok(None);
    }
    Ok(codes.into_iter().next())
}

/// `get_customer_code(dict(source), session)`.
async fn customer_code_of(
    st: &IngestState,
    source: &[(String, PyValue)],
) -> Result<PyValue, PyErr> {
    for key in CUSTOMER_CODE_KEYS {
        let Some(value) = dict_get(source, key) else {
            continue;
        };
        match key {
            "data_office365_OrganizationId" => {
                if let Some(code) = customer_by_office365_tenant(st, value).await {
                    return Ok(PyValue::Str(code));
                }
                tracing::warn!(
                    target: "copilot::ingest",
                    "Failed to get customer code from Office365 organization ID"
                );
            }
            "aws_account_id" => {
                if let Some(code) = aws_account_owner(st, &value.py_str()).await? {
                    return Ok(PyValue::Str(code));
                }
                tracing::warn!(
                    target: "copilot::ingest",
                    "AWS account {} does not belong to any customer's AWS integration",
                    value.py_str()
                );
            }
            "cluster_node" => {
                let PyValue::Str(s) = value else {
                    return Err(PyErr::Other(format!(
                        "'{}' object has no attribute 'startswith'",
                        crate::py::type_name(value)
                    )));
                };
                if s.starts_with("wazuh.worker.") {
                    let parts: Vec<&str> = s.split('.').collect();
                    if parts.len() >= 3 {
                        return Ok(PyValue::Str(parts[2].to_lowercase()));
                    }
                }
                return Ok(value.clone());
            }
            _ => return Ok(value.clone()),
        }
    }
    Err(PyErr::http(
        400,
        format!(
            "Failed to fetch customer code. Valid customer code field names are {}",
            CUSTOMER_CODE_KEYS.join(", ")
        ),
    ))
}

/// `fetch_settings(field, value)`: a `custom_alert_creation_settings` row
/// exists.
async fn settings_exist(
    st: &IngestState,
    column: &str,
    value: &PyValue,
    case_insensitive: bool,
) -> Result<bool, PyErr> {
    if *value == PyValue::None && !case_insensitive {
        let sql = format!("SELECT id FROM custom_alert_creation_settings WHERE {column} IS NULL");
        let rows = sqlx::query(&sql).fetch_all(st.ctx.db.pool()).await?;
        return Ok(!rows.is_empty());
    }
    let sql = if case_insensitive {
        format!("SELECT id FROM custom_alert_creation_settings WHERE lower({column}) = ?")
    } else {
        format!("SELECT id FROM custom_alert_creation_settings WHERE {column} = ?")
    };
    let q = bind_py(sqlx::query(&sql), value)?;
    Ok(!q.fetch_all(st.ctx.db.pool()).await?.is_empty())
}

/// `is_customer_code_valid(customer_code)`; the code the alert is filed
/// under (the value itself, as a string).
async fn validate_customer_code(st: &IngestState, code: &PyValue) -> Result<String, PyErr> {
    if settings_exist(st, "customer_code", code, false).await? {
        return Ok(code.py_str());
    }
    let PyValue::Str(code) = code else {
        return Err(PyErr::Other(format!(
            "'{}' object has no attribute 'lower'",
            crate::py::type_name(code)
        )));
    };
    let normalized = code.to_lowercase().replace('_', " ");
    if settings_exist(
        st,
        "customer_name",
        &PyValue::Str(normalized.to_lowercase()),
        true,
    )
    .await?
    {
        return Ok(code.clone());
    }
    let value = PyValue::Str(code.clone());
    if settings_exist(st, "office365_organization_id", &value, false).await? {
        return Ok(code.clone());
    }
    if let Some(owner) = office365_tenant_owner(st, code).await? {
        if settings_exist(st, "customer_code", &PyValue::Str(owner), false).await? {
            return Ok(code.clone());
        }
    }
    if let Some(owner) = aws_account_owner(st, code).await? {
        if settings_exist(st, "customer_code", &PyValue::Str(owner), false).await? {
            return Ok(code.clone());
        }
    }
    Err(PyErr::http(
        400,
        format!("Customer code {code} is not valid. Has the customer been provisioned?"),
    ))
}

// ---------------------------------------------------------------------------
// rows
// ---------------------------------------------------------------------------

/// `open_alert_exists`: the customer's first OPEN alert of that title.
pub async fn open_alert(
    st: &IngestState,
    customer: &str,
    title: &str,
) -> Result<Option<i64>, PyErr> {
    let ids: Vec<i32> = sqlx::query_scalar(
        "SELECT incident_management_alert.id FROM incident_management_alert \
         WHERE incident_management_alert.customer_code = ? \
         AND incident_management_alert.alert_name = ? AND incident_management_alert.status = ?",
    )
    .bind(customer)
    .bind(title)
    .bind("OPEN")
    .fetch_all(st.ctx.db.pool())
    .await?;
    Ok(ids.first().map(|i| i64::from(*i)))
}

/// `update_alert_creation_time`: the latest trigger time (`fromisoformat`,
/// else now).
pub async fn update_alert_creation_time(
    st: &IngestState,
    alert_id: i64,
    timefield: Option<&str>,
) -> Result<(), PyErr> {
    let exists: Option<i32> =
        sqlx::query_scalar("SELECT id FROM incident_management_alert WHERE id = ?")
            .bind(alert_id)
            .fetch_optional(st.ctx.db.pool())
            .await?;
    if exists.is_none() {
        return Ok(());
    }
    let when: NaiveDateTime = match timefield.filter(|t| !t.is_empty()) {
        Some(t) => match fromisoformat(t) {
            Ok(d) => d.wall,
            Err(_) => now_utc_micros(),
        },
        None => now_utc_micros(),
    };
    sqlx::query("UPDATE incident_management_alert SET alert_creation_time = ? WHERE id = ?")
        .bind(mysql_datetime(when))
        .bind(alert_id)
        .execute(st.ctx.db.pool())
        .await?;
    Ok(())
}

/// `retrieve_agent_details_from_db(hostname)`: `(agent_id, velociraptor_id)`.
async fn agent_by_hostname(
    st: &IngestState,
    hostname: &str,
) -> Result<Option<(String, Option<String>)>, PyErr> {
    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT agent_id, velociraptor_id FROM agents WHERE agents.hostname = ?")
            .bind(hostname)
            .fetch_all(st.ctx.db.pool())
            .await?;
    Ok(rows.into_iter().next())
}

/// `json.dumps(value)` for a JSON column (`NaN` as Python writes it, which
/// MySQL refuses as Python's driver sees it refuse).
fn json_column(v: &[(String, PyValue)]) -> String {
    crate::py::dumps_compact_allow_nan(&PyValue::Dict(v.to_vec()))
}

/// `create_alert_in_copilot`: the alert row, then its SLA clocks.
async fn create_alert_row(
    st: &IngestState,
    payload: &AlertPayload,
    customer: &str,
) -> Result<i64, PyErr> {
    let severity = copilot_sla::severity::normalize_severity(payload.severity.as_deref());
    let result = sqlx::query(
        "INSERT INTO incident_management_alert (alert_name, alert_description, status, \
         alert_creation_time, customer_code, time_closed, source, severity, assigned_to, \
         escalated, verdict, verdict_reason, verdict_note, verdict_by, verdict_at) \
         VALUES (?, ?, 'OPEN', ?, ?, NULL, ?, ?, NULL, 0, NULL, NULL, NULL, NULL, NULL)",
    )
    .bind(&payload.title)
    .bind(&payload.title)
    .bind(mysql_datetime(now_utc_micros()))
    .bind(customer)
    .bind(&payload.source)
    .bind(severity)
    .execute(st.ctx.db.pool())
    .await?;
    let id = result.last_insert_id() as i64;
    copilot_incidents::routes::common::sla(&st.ctx)
        .alert_opened(id, severity, customer)
        .await;
    Ok(id)
}

/// `create_alert_context_payload`.
async fn create_context(st: &IngestState, payload: &AlertPayload) -> Result<i64, PyErr> {
    let result =
        sqlx::query("INSERT INTO incident_management_alertcontext (source, context) VALUES (?, ?)")
            .bind(&payload.source)
            .bind(json_column(&payload.context))
            .execute(st.ctx.db.pool())
            .await?;
    Ok(result.last_insert_id() as i64)
}

/// `create_asset_context_payload` / the asset of `add_asset_to_copilot_alert`.
async fn create_asset(
    st: &IngestState,
    payload: &AlertPayload,
    alert_id: i64,
    context_id: i64,
    customer: &str,
) -> Result<(), PyErr> {
    let agent = agent_by_hostname(st, &payload.asset).await?;
    sqlx::query(
        "INSERT INTO incident_management_asset (alert_linked, asset_name, alert_context_id, \
         agent_id, velociraptor_id, customer_code, index_name, index_id) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(alert_id)
    .bind(&payload.asset)
    .bind(context_id)
    .bind(agent.as_ref().map(|a| a.0.clone()))
    .bind(agent.and_then(|a| a.1))
    .bind(customer)
    .bind(&payload.index_name)
    .bind(&payload.index_id)
    .execute(st.ctx.db.pool())
    .await?;
    Ok(())
}

/// `create_ioc_payload` / `add_ioc_to_copilot_alert`: the IoC and its link.
async fn create_ioc(st: &IngestState, ioc: &Ioc, alert_id: i64) -> Result<(), PyErr> {
    let mut tx = st.ctx.db.pool().begin().await?;
    let created = sqlx::query(
        "INSERT INTO incident_management_ioc (value, type, description) VALUES (?, ?, ?)",
    )
    .bind(&ioc.value)
    .bind(ioc.kind)
    .bind(&ioc.description)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO incident_management_alert_to_ioc (alert_id, ioc_id) VALUES (?, ?)")
        .bind(alert_id)
        .bind(created.last_insert_id())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// `does_assit_exist`.
async fn asset_exists(st: &IngestState, alert_id: i64, asset: &str) -> Result<bool, PyErr> {
    let rows: Vec<i32> = sqlx::query_scalar(
        "SELECT id FROM incident_management_asset WHERE incident_management_asset.alert_linked = ? \
         AND incident_management_asset.asset_name = ?",
    )
    .bind(alert_id)
    .bind(asset)
    .fetch_all(st.ctx.db.pool())
    .await?;
    Ok(!rows.is_empty())
}

/// `does_ioc_exist`.
async fn ioc_exists(st: &IngestState, alert_id: i64, value: &str) -> Result<bool, PyErr> {
    let rows: Vec<i32> = sqlx::query_scalar(
        "SELECT incident_management_ioc.id FROM incident_management_ioc \
         JOIN incident_management_alert_to_ioc ON incident_management_alert_to_ioc.ioc_id = incident_management_ioc.id \
         WHERE incident_management_alert_to_ioc.alert_id = ? AND incident_management_ioc.value = ?",
    )
    .bind(alert_id)
    .bind(value)
    .fetch_all(st.ctx.db.pool())
    .await?;
    Ok(!rows.is_empty())
}

/// `add_asset_to_copilot_alert`: a new context and asset unless the alert
/// already has an asset of that name.
async fn add_asset(
    st: &IngestState,
    payload: &AlertPayload,
    alert_id: i64,
    customer: &str,
) -> Result<(), PyErr> {
    if asset_exists(st, alert_id, &payload.asset).await? {
        return Ok(());
    }
    let context_id = create_context(st, payload).await?;
    create_asset(st, payload, alert_id, context_id, customer).await
}

/// `add_ioc_to_copilot_alert`.
async fn add_ioc(st: &IngestState, payload: &AlertPayload, alert_id: i64) -> Result<(), PyErr> {
    let Some(ioc) = &payload.ioc else {
        return Ok(());
    };
    if ioc_exists(st, alert_id, &ioc.value).await? {
        return Ok(());
    }
    create_ioc(st, ioc, alert_id).await
}

/// `add_alert_to_document`: `{"doc": {"alert_id": id}}` onto the document
/// (never onto the `not_applicable` sentinel).
pub async fn add_alert_to_document(
    st: &IngestState,
    index_name: &str,
    index_id: &str,
    alert_id: i64,
) -> Result<(), PyErr> {
    if index_name == "not_applicable" || index_id == "not_applicable" {
        tracing::info!(
            target: "copilot::ingest",
            "Skipping document write-back for 'not_applicable' sentinel index/id"
        );
        return Ok(());
    }
    let client = es::async_client(st).await?;
    let body = PyValue::Dict(vec![(
        "doc".into(),
        PyValue::Dict(vec![(
            "alert_id".into(),
            PyValue::Int(alert_id.to_string()),
        )]),
    )]);
    es::update_lifting_write_block(
        &client,
        index_name,
        index_id,
        &body,
        &format!("add alert ID {alert_id} to alert {index_id} in index {index_name}"),
    )
    .await;
    Ok(())
}

// ---------------------------------------------------------------------------
// creation
// ---------------------------------------------------------------------------

/// Which path called `create_alert_full`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// An indexer document (`create_alert`).
    Document,
    /// A Graylog threshold event (`threshold_alert=True`).
    Threshold,
    /// The Sigma ingest (`velo_sigma_alert=True`).
    VeloSigma,
}

/// `create_alert_full(alert_payload, customer_code, …)`.
pub async fn create_alert_full(
    st: &IngestState,
    payload: &mut AlertPayload,
    customer: &str,
    origin: Origin,
) -> Result<i64, PyErr> {
    if origin == Origin::VeloSigma {
        if let Some(existing) = open_alert(st, customer, &payload.title).await? {
            update_alert_creation_time(st, existing, Some(&payload.timefield)).await?;
            let mut asset_already_exists = false;
            if !payload.asset.is_empty() {
                asset_already_exists = asset_exists(st, existing, &payload.asset).await?;
            }
            if !asset_already_exists && !payload.asset.is_empty() {
                add_asset(st, payload, existing, customer).await?;
            }
            add_ioc(st, payload, existing).await?;
            if let (Some(index), Some(id)) = (&payload.index_name, &payload.index_id) {
                if !index.is_empty()
                    && !id.is_empty()
                    && index != "not_applicable"
                    && id != "not_applicable"
                {
                    add_alert_to_document(st, index, id, existing).await?;
                }
            }
            payload.alert_id = Some(existing);
            if !asset_already_exists {
                let asset = if payload.asset.is_empty() {
                    "No asset found".to_string()
                } else {
                    payload.asset.clone()
                };
                notify::customer_notifications(st, customer, &asset, payload, "alert").await?;
            }
            notify::talon_investigation(st, existing, customer).await;
            return Ok(existing);
        }
    }
    let alert_id = create_alert_row(st, payload, customer).await?;
    let context_id = create_context(st, payload).await?;
    create_asset(st, payload, alert_id, context_id, customer).await?;
    if let Some(ioc) = &payload.ioc {
        create_ioc(st, ioc, alert_id).await?;
    }
    payload.alert_id = Some(alert_id);
    let asset = payload.asset.clone();
    notify::customer_notifications(st, customer, &asset, payload, "alert").await?;
    notify::talon_investigation(st, alert_id, customer).await;
    let event = alert_created_event(
        &st.ctx.notification_defaults,
        &AlertCreatedInput {
            alert_id,
            customer_code: customer,
            alert_title: Some(&payload.title),
            severity: payload.severity.as_deref(),
            rule_level: payload.rule_level,
            asset_name: Some(&payload.asset),
            link_url: None,
        },
    );
    st.ctx.notifications.emit(event, None);
    if origin != Origin::Document {
        return Ok(alert_id);
    }
    add_alert_to_document(
        st,
        payload.index_name.as_deref().unwrap_or_default(),
        payload.index_id.as_deref().unwrap_or_default(),
        alert_id,
    )
    .await?;
    Ok(alert_id)
}

/// `create_alert(CreateAlertRequest(index_name, alert_id))`: the alert id
/// (created, or the open alert merged into).
pub async fn create_alert(
    st: &IngestState,
    index_name: &str,
    alert_id: &str,
) -> Result<i64, PyErr> {
    tracing::info!(target: "copilot::ingest", "Creating alert {alert_id} in CoPilot");
    let details = single_alert_details(st, index_name, alert_id).await?;
    // `validate_syslog_type_source`.
    let sources = config::configured_sources(&st.ctx.db).await?;
    if !sources.contains(&details.syslog_type) {
        return Err(PyErr::http(
            400,
            format!(
                "Incident Management: {} Source must be configured",
                details.syslog_type
            ),
        ));
    }
    let code = customer_code_of(st, &details.source).await?;
    let customer = validate_customer_code(st, &code).await?;
    let mut payload = build_alert_payload(st, &details).await?;
    if let Some(existing) = open_alert(st, &customer, &payload.title).await? {
        update_alert_creation_time(st, existing, Some(&payload.timefield)).await?;
        add_alert_to_document(
            st,
            payload.index_name.as_deref().unwrap_or_default(),
            payload.index_id.as_deref().unwrap_or_default(),
            existing,
        )
        .await?;
        add_asset(st, &payload, existing, &customer).await?;
        add_ioc(st, &payload, existing).await?;
        return Ok(existing);
    }
    create_alert_full(st, &mut payload, &customer, Origin::Document).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioc_types() {
        assert_eq!(get_ioc_type(" 8.8.8.8 "), Some(IP));
        assert_eq!(get_ioc_type("d41d8cd98f00b204e9800998ecf8427e"), Some(HASH));
        assert_eq!(get_ioc_type("https://x.example/a b"), None);
        assert_eq!(get_ioc_type("https://x.example/a"), Some(URL));
        assert_eq!(get_ioc_type("evil.example.com"), Some(DOMAIN));
        assert_eq!(get_ioc_type("evil.exe"), Some(DOMAIN));
        assert_eq!(get_ioc_type("nope"), None);
        assert_eq!(
            classify_ioc_value("evil.exe|d41d8cd98f00b204e9800998ecf8427e"),
            Some(("d41d8cd98f00b204e9800998ecf8427e".into(), HASH))
        );
        assert_eq!(
            classify_ioc_value("0.0.0.0|4449"),
            Some(("0.0.0.0".into(), IP))
        );
        assert_eq!(classify_ioc_value("a|b"), None);
    }

    #[test]
    fn titles_lose_their_marks() {
        assert_eq!(clean_alert_title("\u{feff} Mimikatz \u{1c}"), "Mimikatz");
    }
}
