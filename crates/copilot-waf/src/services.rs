//! Business logic for a customer's SOCFortress WAFs — port of
//! `app/customer_waf/services/customer_waf.py`.
//!
//! Two rules every function keeps:
//!
//! - **A WAF id belongs to a tenant.** [`get_instance_for_customer`] is the
//!   only way a route turns `{waf_id}` into a row, and it answers 404 for a
//!   row of another customer than the path's (so ids cannot be enumerated).
//! - **The token is write-only**: encrypted on the way in, decrypted only in
//!   the transport, never in a response ([`crate::schema::instance`]).

use std::sync::Arc;

use chrono::NaiveDateTime;
use copilot_auth::pyvalue::PyValue;
use copilot_core::config::Secret;
use copilot_core::time::now_utc_micros;
use copilot_db::DbError;
use copilot_graylog::GraylogClient;
use copilot_upstream::model::{Invalid, construct, format_validation_error, kwargs, validate};
use copilot_upstream::py::{PyExc, get, getitem, iterate, type_name};
use copilot_web::form::py_strip;
use copilot_web::{AppContext, CurrentUser};

use crate::client::{Call, WafClient, WafError, WafResult, normalize_api_url};
use crate::crypto;
use crate::pem::{self, PemCheck};
use crate::schema::{
    Capabilities, InstanceCreate, InstanceUpdate, VerifyResult, WAF_EVENT, WAF_EVENT_FIELDS,
    WAF_SITE, WAF_STATS, WAF_THREAT_INTEL_ENTRY, WAF_THREAT_INTEL_SUMMARY,
};
use crate::store::{self, NewWaf, WafRow};

/// The environment the module reads (`os.environ.get(…)`, per call in Python).
#[derive(Debug, Clone, Default)]
pub struct WafEnv {
    /// `WAF_TOKEN_ENCRYPTION_KEY`.
    pub token_key: Option<Secret>,
    /// `WAF_SYSLOG_PORT_RANGE`.
    pub syslog_port_range: Option<String>,
    /// `WAF_SYSLOG_DEFAULT_HOST`.
    pub syslog_default_host: Option<String>,
    /// `ALERT_FORWARDING_IP`.
    pub alert_forwarding_ip: Option<String>,
    /// `GRAYLOG_API_HEADER_VALUE`.
    pub graylog_api_header_value: Option<Secret>,
}

/// Route state.
#[derive(Debug, Clone)]
pub struct WafState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The WAF transport.
    pub client: WafClient,
    /// Graylog (event forwarding, the alerts).
    pub graylog: GraylogClient,
    /// The environment.
    pub env: Arc<WafEnv>,
}

impl axum::extract::FromRef<WafState> for AppContext {
    fn from_ref(s: &WafState) -> AppContext {
        s.ctx.clone()
    }
}

fn db(e: DbError) -> WafError {
    WafError::Py(PyExc::Other("OperationalError", e.to_string()))
}

fn http(status: u16, detail: impl Into<String>) -> WafError {
    WafError::Py(PyExc::Http(status, detail.into()))
}

// --- roles -------------------------------------------------------------------------

/// `WAF_ROLE_PERMISSIONS[role]` (the WAF's own `rbac.py` table).
fn permissions(role: &str) -> &'static [&'static str] {
    match role {
        "admin" => &[
            "sites:read",
            "sites:write",
            "sites:delete",
            "rules:read",
            "rules:write",
            "rules:delete",
            "config:read",
            "config:write",
            "logs:read",
            "alerts:read",
            "alerts:write",
            "audit:read",
        ],
        "operator" => &["rules:read", "rules:write", "logs:read"],
        "viewer" => &[
            "sites:read",
            "rules:read",
            "config:read",
            "logs:read",
            "alerts:read",
            "audit:read",
        ],
        _ => &[],
    }
}

/// `capabilities_for_roles`.
pub fn capabilities_for_roles(roles: &[String]) -> Capabilities {
    let has = |p: &str| roles.iter().any(|r| permissions(r).contains(&p));
    Capabilities {
        can_read: has("sites:read") && has("logs:read"),
        can_block: has("rules:read") && has("rules:write"),
        can_manage_forwarders: has("config:write"),
    }
}

/// `summarize_roles`: sorted, comma-joined, cut to the 50-character column.
pub fn summarize_roles(roles: &[String]) -> Option<String> {
    if roles.is_empty() {
        return None;
    }
    let mut sorted = roles.to_vec();
    sorted.sort();
    let joined = sorted.join(",");
    if joined.chars().count() <= 50 {
        Some(joined)
    } else {
        Some(format!(
            "{}...",
            joined.chars().take(47).collect::<String>()
        ))
    }
}

// --- validation -----------------------------------------------------------------

fn clean_name(name: &str) -> WafResult<String> {
    let name = py_strip(name);
    if name.is_empty() {
        return Err(http(400, "name must not be blank"));
    }
    Ok(name.to_string())
}

fn clean_api_url(api_url: &str) -> WafResult<String> {
    normalize_api_url(api_url).map_err(|e| http(400, e))
}

fn clean_ca_cert(ca_cert_pem: Option<&str>) -> WafResult<Option<String>> {
    let pem_text = py_strip(ca_cert_pem.unwrap_or_default());
    if pem_text.is_empty() {
        return Ok(None);
    }
    match pem::check(pem_text) {
        PemCheck::Ok => Ok(Some(pem_text.to_string())),
        PemCheck::SslError(e) => Err(http(
            400,
            format!("ca_cert_pem is not a valid PEM certificate: {e}"),
        )),
        PemCheck::NotAscii => Err(WafError::Py(PyExc::TypeError(
            "cadata should be an ASCII string or a bytes-like object".into(),
        ))),
    }
}

/// `config_warnings`.
pub fn config_warnings(row: &WafRow) -> Vec<String> {
    if row.api_url.starts_with("http://") {
        vec![
            "The API URL uses http:// — the service token is sent in clear text. Prefer the WAF \
             admin UI's https listener."
                .into(),
        ]
    } else {
        Vec::new()
    }
}

// --- persistence ------------------------------------------------------------------

/// `list_all_instances` (`None` = no filter; the caller handles `[]`).
pub async fn list_all_instances(st: &WafState, codes: Option<&[String]>) -> WafResult<Vec<WafRow>> {
    store::list_all(&st.ctx.db, codes).await.map_err(db)
}

/// `list_instances`.
pub async fn list_instances(st: &WafState, code: &str) -> WafResult<Vec<WafRow>> {
    store::list_for_customer(&st.ctx.db, code).await.map_err(db)
}

/// `get_instance_for_customer`: 404 for a missing row or another tenant's.
pub async fn get_instance_for_customer(st: &WafState, code: &str, id: i64) -> WafResult<WafRow> {
    match store::get(&st.ctx.db, id).await.map_err(db)? {
        Some(row) if row.customer_code == code => Ok(row),
        _ => Err(http(404, format!("WAF {id} not found for customer {code}"))),
    }
}

async fn reload(st: &WafState, id: i64) -> WafResult<WafRow> {
    store::get(&st.ctx.db, id)
        .await
        .map_err(db)?
        .ok_or_else(|| WafError::Py(PyExc::Other("ObjectDeletedError", format!("row {id}"))))
}

fn is_integrity_error(e: &DbError) -> bool {
    match e {
        DbError::Sqlx(sqlx::Error::Database(d)) => d.code().as_deref() == Some("23000"),
        _ => false,
    }
}

/// `create_instance`.
pub async fn create_instance(
    st: &WafState,
    code: &str,
    req: &InstanceCreate,
    user_id: Option<i32>,
) -> WafResult<WafRow> {
    if store::customer_name(&st.ctx.db, code)
        .await
        .map_err(db)?
        .is_none()
    {
        return Err(http(404, format!("Customer {code} not found")));
    }
    let token = crypto::normalize_token(&req.service_token)?;
    let name = clean_name(&req.name)?;
    let api_url = clean_api_url(&req.api_url)?;
    let encrypted = crypto::encrypt_token(st.env.token_key.as_ref(), &token)?;
    let prefix = crypto::display_prefix(&token);
    let ca = clean_ca_cert(req.ca_cert_pem.as_deref())?;
    let new = NewWaf {
        customer_code: code,
        name: &name,
        api_url: &api_url,
        service_token_encrypted: &encrypted,
        token_prefix: &prefix,
        verify_tls: req.verify_tls,
        ca_cert_pem: ca.as_deref(),
        enabled: req.enabled,
        created_by: user_id,
        created_at: now_utc_micros(),
    };
    let id = match store::insert(&st.ctx.db, &new).await {
        Ok(id) => id,
        Err(e) if is_integrity_error(&e) => {
            return Err(http(
                409,
                format!("Customer {code} already has a WAF named '{name}'"),
            ));
        }
        Err(e) => return Err(db(e)),
    };
    let row = reload(st, id).await?;
    tracing::info!(
        "Customer WAF created: id={} customer={code} name={} by user={}",
        row.id,
        row.name,
        user_id.map_or("None".into(), |u| u.to_string())
    );
    Ok(row)
}

/// `update_instance`: `(row, connection_changed)`.
pub async fn update_instance(
    st: &WafState,
    mut row: WafRow,
    req: &InstanceUpdate,
    user_id: Option<i32>,
) -> WafResult<(WafRow, bool)> {
    let mut changed = false;
    if let Some(name) = &req.name {
        row.name = clean_name(name)?;
    }
    if let Some(url) = &req.api_url {
        let new_url = clean_api_url(url)?;
        changed |= new_url != row.api_url;
        row.api_url = new_url;
    }
    if let Some(token) = req
        .service_token
        .as_deref()
        .filter(|t| !py_strip(t).is_empty())
    {
        let token = crypto::normalize_token(token)?;
        row.service_token_encrypted = crypto::encrypt_token(st.env.token_key.as_ref(), &token)?;
        row.token_prefix = crypto::display_prefix(&token);
        changed = true;
    }
    if let Some(verify) = req.verify_tls {
        changed |= verify != row.verify_tls;
        row.verify_tls = verify;
    }
    if let Some(pem_text) = &req.ca_cert_pem {
        row.ca_cert_pem = clean_ca_cert(Some(pem_text))?;
        changed = true;
    }
    if let Some(enabled) = req.enabled {
        row.enabled = enabled;
    }
    if changed {
        row.last_verified_at = None;
        row.last_verified_role = None;
    }
    row.updated_by = user_id;
    row.updated_at = Some(now_utc_micros());
    match store::write_config(&st.ctx.db, &row).await {
        Ok(()) => {}
        Err(e) if is_integrity_error(&e) => {
            return Err(http(
                409,
                format!(
                    "Customer {} already has a WAF named '{}'",
                    row.customer_code, row.name
                ),
            ));
        }
        Err(e) => return Err(db(e)),
    }
    let fresh = reload(st, i64::from(row.id)).await?;
    tracing::info!(
        "Customer WAF updated: id={} customer={} by user={}",
        fresh.id,
        fresh.customer_code,
        user_id.map_or("None".into(), |u| u.to_string())
    );
    Ok((fresh, changed))
}

/// `delete_instance`.
pub async fn delete_instance(st: &WafState, row: &WafRow, user_id: Option<i32>) -> WafResult<()> {
    store::delete(&st.ctx.db, row.id).await.map_err(db)?;
    tracing::info!(
        "Customer WAF deleted: id={} customer={} name={} by user={}",
        row.id,
        row.customer_code,
        row.name,
        user_id.map_or("None".into(), |u| u.to_string())
    );
    Ok(())
}

// --- WAF-facing -------------------------------------------------------------------

/// `[r.get("name") for r in (me.get("roles") or []) if isinstance(r, dict) and r.get("name")]`
/// — the names as Python values (any truthy value is kept).
pub fn role_names(me: &PyValue) -> Result<Vec<PyValue>, PyExc> {
    let roles = get(me, "roles")?.cloned().unwrap_or(PyValue::None);
    if !roles.truthy() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for r in iterate(&roles)? {
        if let PyValue::Dict(_) = r {
            if let Some(name) = get(&r, "name")? {
                if name.truthy() {
                    out.push(name.clone());
                }
            }
        }
    }
    Ok(out)
}

/// Role names as strings: `sorted()`/`",".join()` raise `TypeError` on
/// anything else.
pub fn role_strings(names: &[PyValue]) -> Result<Vec<String>, PyExc> {
    names
        .iter()
        .map(|n| match n {
            PyValue::Str(s) => Ok(s.clone()),
            other => Err(PyExc::TypeError(format!(
                "sequence item 0: expected str instance, {} found",
                type_name(other)
            ))),
        })
        .collect()
}

/// `verify_instance`: check the token and cache the role on the row.
pub async fn verify_instance(st: &WafState, row: &WafRow) -> WafResult<(VerifyResult, WafRow)> {
    let me = match st
        .client
        .request(row, Call::get("/users/me").allow_disabled())
        .await
    {
        Ok(me) => me,
        Err(WafError::Request { reason, detail, .. }) => {
            if reason == "not_found" || reason == "bad_response" {
                return Ok((
                    VerifyResult::failed(
                        true,
                        "not_a_waf",
                        format!(
                            "{} answered, but not as a SOCFortress WAF API with service-token \
                             support. Check the URL points at the WAF admin UI (e.g. \
                             https://waf-host:8080) and the WAF is up to date.",
                            row.api_url
                        ),
                    ),
                    row.clone(),
                ));
            }
            let reachable = reason != "unreachable" && reason != "tls_error";
            return Ok((VerifyResult::failed(reachable, reason, detail), row.clone()));
        }
        Err(other) => return Err(other),
    };
    let names = role_names(&me)?;
    let health = match st
        .client
        .request(
            row,
            Call::get("/health")
                .outside_api()
                .allow_disabled()
                .timeout(5.0),
        )
        .await
    {
        Ok(body @ PyValue::Dict(_)) => body,
        Ok(_) | Err(WafError::Request { .. }) => PyValue::None,
        Err(other) => return Err(other),
    };
    let roles = role_strings(&names)?;
    let now: NaiveDateTime = now_utc_micros();
    store::write_verified(&st.ctx.db, row.id, now, summarize_roles(&roles).as_deref())
        .await
        .map_err(db)?;
    let fresh = reload(st, i64::from(row.id)).await?;
    // `WafVerifyResult(waf_user_email=me.get("email"), …)`: an `Optional[str]`.
    let email = get(&me, "email")?.cloned().unwrap_or(PyValue::None);
    let email = match email {
        PyValue::None | PyValue::Str(_) => email,
        other => {
            return Err(WafError::Py(PyExc::Validation(format!(
                "1 validation error for WafVerifyResult\nwaf_user_email\n  Input should be a \
                 valid string [type=string_type, input_value={}, input_type={}]\n    For further \
                 information visit https://errors.pydantic.dev/{}/v/string_type",
                copilot_upstream::model::input_value(&other),
                type_name(&other),
                copilot_upstream::model::PYDANTIC_VERSION
            ))));
        }
    };
    let capabilities = capabilities_for_roles(&roles);
    Ok((
        VerifyResult {
            reachable: true,
            authenticated: true,
            reason: None,
            detail: None,
            waf_user_email: email,
            waf_roles: roles,
            capabilities,
            health,
        },
        fresh,
    ))
}

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

/// `s.get(key, default)`.
fn get_or(v: &PyValue, key: &str, default: PyValue) -> Result<PyValue, PyExc> {
    Ok(get(v, key)?.cloned().unwrap_or(default))
}

/// `fetch_sites`.
pub async fn fetch_sites(st: &WafState, row: &WafRow) -> WafResult<Vec<PyValue>> {
    let body = st.client.request(row, Call::get("/sites/")).await?;
    let items = if body.truthy() {
        iterate(&body)?
    } else {
        Vec::new()
    };
    let mut out = Vec::new();
    for site in &items {
        let id = getitem(site, "id")?.py_str();
        let args = kwargs(vec![
            ("id", PyValue::Str(id)),
            ("name", get_or(site, "name", s(""))?),
            ("hostname", get_or(site, "hostname", s(""))?),
            ("upstream_url", get_or(site, "upstream_url", s(""))?),
            (
                "is_enabled",
                PyValue::Bool(get(site, "is_enabled")?.is_some_and(PyValue::truthy)),
            ),
            (
                "detection_mode",
                PyValue::Bool(get(site, "detection_mode")?.is_some_and(PyValue::truthy)),
            ),
            ("created_at", get_or(site, "created_at", PyValue::None)?),
        ]);
        out.push(construct(&WAF_SITE, &args)?);
    }
    Ok(out)
}

/// `_utc_iso`: always an explicit `+00:00` (the WAF reads a naive time in its
/// own process's zone); a naive value is taken to be UTC.
pub fn utc_iso(wall: NaiveDateTime, offset_seconds: Option<i32>) -> Result<String, PyExc> {
    let utc = match offset_seconds {
        None | Some(0) => Some(wall),
        Some(off) => wall.checked_sub_signed(chrono::Duration::seconds(i64::from(off))),
    };
    let utc = utc
        .filter(|t| (1..=9999).contains(&chrono::Datelike::year(t)))
        .ok_or_else(|| PyExc::Other("OverflowError", "date value out of range".into()))?;
    let base = utc.format("%Y-%m-%dT%H:%M:%S").to_string();
    let micros = chrono::Timelike::nanosecond(&utc) / 1000;
    Ok(if micros == 0 {
        format!("{base}+00:00")
    } else {
        format!("{base}.{micros:06}+00:00")
    })
}

/// The `/events` filters (`build_event_params`).
#[derive(Debug, Clone, Default)]
pub struct EventFilters {
    /// `action`.
    pub action: Option<String>,
    /// `severity`.
    pub severity: Option<String>,
    /// `client_ip`.
    pub client_ip: Option<String>,
    /// `rule_id`.
    pub rule_id: Option<String>,
    /// `site_id`.
    pub site_id: Option<String>,
    /// `start_time` (already `_utc_iso`'d).
    pub start_time: Option<String>,
    /// `end_time` (already `_utc_iso`'d).
    pub end_time: Option<String>,
    /// `limit`.
    pub limit: i64,
    /// `offset`.
    pub offset: i64,
}

/// `build_event_params`: limit and offset, the truthy filters, the times.
pub fn build_event_params(f: &EventFilters) -> Vec<(String, String)> {
    let mut out = vec![
        ("limit".to_string(), f.limit.to_string()),
        ("offset".to_string(), f.offset.to_string()),
    ];
    for (k, v) in [
        ("action", &f.action),
        ("severity", &f.severity),
        ("client_ip", &f.client_ip),
        ("rule_id", &f.rule_id),
        ("site_id", &f.site_id),
    ] {
        if let Some(v) = v.as_deref().filter(|v| !v.is_empty()) {
            out.push((k.to_string(), v.to_string()));
        }
    }
    if let Some(t) = &f.start_time {
        out.push(("start_time".into(), t.clone()));
    }
    if let Some(t) = &f.end_time {
        out.push(("end_time".into(), t.clone()));
    }
    out
}

fn validation(model: &'static copilot_upstream::model::Model, e: Invalid) -> PyExc {
    match e {
        Invalid::Errors(errors) => PyExc::Validation(format_validation_error(model.name, &errors)),
        Invalid::Abort(status, detail) => PyExc::Http(status, detail),
    }
}

/// `fetch_events` (`raw_log` and other undeclared keys dropped).
pub async fn fetch_events(
    st: &WafState,
    row: &WafRow,
    params: Vec<(String, String)>,
) -> WafResult<Vec<PyValue>> {
    let body = st
        .client
        .request(row, Call::get("/logs/").params(params))
        .await?;
    let items = if body.truthy() {
        iterate(&body)?
    } else {
        Vec::new()
    };
    let mut out = Vec::new();
    for e in &items {
        let PyValue::Dict(pairs) = e else {
            return Err(WafError::Py(PyExc::AttributeError(format!(
                "'{}' object has no attribute 'items'",
                type_name(e)
            ))));
        };
        let mut data: Vec<(String, PyValue)> = pairs
            .iter()
            .filter(|(k, _)| WAF_EVENT_FIELDS.contains(&k.as_str()))
            .cloned()
            .collect();
        let mut set = |k: &str, v: PyValue| match data.iter_mut().find(|(key, _)| key == k) {
            Some(slot) => slot.1 = v,
            None => data.push((k.to_string(), v)),
        };
        set("id", PyValue::Str(getitem(e, "id")?.py_str()));
        let site = match get(e, "site_id")? {
            Some(v) if v.truthy() => PyValue::Str(getitem(e, "site_id")?.py_str()),
            _ => PyValue::None,
        };
        set("site_id", site);
        let matched = match get(e, "matched_rules")? {
            Some(v) if v.truthy() => iterate(v)?
                .into_iter()
                .filter(|m| matches!(m, PyValue::Dict(_)))
                .collect(),
            _ => Vec::new(),
        };
        set("matched_rules", PyValue::List(matched));
        out.push(
            validate(&WAF_EVENT, &PyValue::Dict(data)).map_err(|e| validation(&WAF_EVENT, e))?,
        );
    }
    Ok(out)
}

/// `fetch_stats`.
pub async fn fetch_stats(st: &WafState, row: &WafRow) -> WafResult<PyValue> {
    let body = st.client.request(row, Call::get("/logs/stats")).await?;
    Ok(validate(&WAF_STATS, &body).map_err(|e| validation(&WAF_STATS, e))?)
}

/// `fetch_threat_intel`: `(summary, entries)`.
pub async fn fetch_threat_intel(st: &WafState, row: &WafRow) -> WafResult<(PyValue, Vec<PyValue>)> {
    let stats = st
        .client
        .request(row, Call::get("/threat-intel/stats"))
        .await?;
    let entries = st.client.request(row, Call::get("/threat-intel/")).await?;
    let stats = if stats.truthy() {
        stats
    } else {
        kwargs(vec![("total_ips", PyValue::Int("0".into()))])
    };
    let summary = validate(&WAF_THREAT_INTEL_SUMMARY, &stats)
        .map_err(|e| validation(&WAF_THREAT_INTEL_SUMMARY, e))?;
    let items = if entries.truthy() {
        iterate(&entries)?
    } else {
        Vec::new()
    };
    let mut parsed = Vec::new();
    for e in &items {
        // `dict(e)`.
        let PyValue::Dict(pairs) = e else {
            return Err(WafError::Py(PyExc::TypeError(format!(
                "'{}' object is not iterable",
                type_name(e)
            ))));
        };
        let mut data = pairs.clone();
        let top = match get(e, "top_rules")? {
            Some(v) if v.truthy() => v.clone(),
            _ => PyValue::List(Vec::new()),
        };
        match data.iter_mut().find(|(k, _)| k == "top_rules") {
            Some(slot) => slot.1 = top,
            None => data.push(("top_rules".into(), top)),
        }
        parsed.push(
            validate(&WAF_THREAT_INTEL_ENTRY, &PyValue::Dict(data))
                .map_err(|e| validation(&WAF_THREAT_INTEL_ENTRY, e))?,
        );
    }
    Ok((summary, parsed))
}

// --- block provenance ---------------------------------------------------------------

/// `verify_block_provenance`: the caller may cite the alert / case, and it
/// is the WAF's customer's.
pub async fn verify_block_provenance(
    st: &WafState,
    user: &CurrentUser,
    code: &str,
    alert_id: Option<i64>,
    case_id: Option<i64>,
) -> Result<(), copilot_web::ApiError> {
    if let Some(id) = alert_id {
        let alert = copilot_incidents::access::alert_for(&st.ctx, user, id).await?;
        alert.build()?;
        user.enforce_owned(
            &st.ctx,
            Some(&alert.row.customer_code),
            &format!("alert {id}"),
        )
        .await?;
        if alert.row.customer_code != code {
            return Err(copilot_web::ApiError::bad_request(format!(
                "Alert {id} belongs to a different customer than this WAF"
            )));
        }
    }
    if let Some(id) = case_id {
        let case = copilot_incidents::views::case_full(&st.ctx.db, id).await?;
        user.enforce_owned(
            &st.ctx,
            case.customer_code.as_deref(),
            &format!("case {id}"),
        )
        .await?;
        if case.customer_code.as_deref() != Some(code) {
            return Err(copilot_web::ApiError::bad_request(format!(
                "Case {id} belongs to a different customer than this WAF"
            )));
        }
    }
    Ok(())
}

/// `BLOCK_COMMENT_PREFIX`.
pub const BLOCK_COMMENT_PREFIX: &str = "WAF block: ";

/// `comment_block_on_alert`: best effort, after the block.
pub async fn comment_block_on_alert(st: &WafState, alert_id: i64, text: &str, username: &str) {
    let exists: Result<Option<(i32,)>, sqlx::Error> =
        sqlx::query_as("SELECT id FROM incident_management_alert WHERE id = ?")
            .bind(alert_id)
            .fetch_optional(st.ctx.db.pool())
            .await;
    let result = match exists {
        Ok(Some(_)) => copilot_incidents::writes::create_comment(
            &st.ctx.db,
            copilot_incidents::writes::CommentKind::Alert,
            alert_id,
            &format!("{BLOCK_COMMENT_PREFIX}{text}"),
            username,
            None,
        )
        .await
        .map(|_| ())
        .map_err(|e| e.to_string()),
        Ok(None) => Err("404: Alert not found".to_string()),
        Err(e) => Err(e.to_string()),
    };
    if let Err(e) = result {
        tracing::error!("WAF block succeeded but the comment on alert {alert_id} failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn roles_like_python() {
        let v: Value = serde_json::from_str(include_str!("waf_vectors.json")).unwrap();
        for case in v["roles"].as_array().unwrap() {
            let roles: Vec<String> = case["roles"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r.as_str().unwrap().to_string())
                .collect();
            let caps = capabilities_for_roles(&roles);
            let want = &case["capabilities"];
            assert_eq!(caps.can_read, want["can_read"].as_bool().unwrap());
            assert_eq!(caps.can_block, want["can_block"].as_bool().unwrap());
            assert_eq!(
                caps.can_manage_forwarders,
                want["can_manage_forwarders"].as_bool().unwrap()
            );
            assert_eq!(
                summarize_roles(&roles).as_deref(),
                case["summary"].as_str(),
                "{roles:?}"
            );
        }
    }

    #[test]
    fn ca_uploads_like_python() {
        let v: Value = serde_json::from_str(include_str!("waf_vectors.json")).unwrap();
        for case in v["pems"].as_array().unwrap() {
            let got = clean_ca_cert(case["pem"].as_str());
            let label = case["label"].as_str().unwrap();
            if let Some(ok) = case.get("ok") {
                assert_eq!(got.unwrap().as_deref(), ok.as_str(), "{label}");
            } else if let Some(err) = case.get("error") {
                assert_eq!(
                    got.unwrap_err(),
                    WafError::Py(PyExc::Http(400, err.as_str().unwrap().into())),
                    "{label}"
                );
            } else {
                assert!(
                    matches!(got, Err(WafError::Py(PyExc::TypeError(_)))),
                    "{label}"
                );
            }
        }
    }

    #[test]
    fn times_like_python() {
        let v: Value = serde_json::from_str(include_str!("waf_vectors.json")).unwrap();
        for case in v["times"].as_array().unwrap() {
            let (wall, off) =
                copilot_web::datetime::parse_lax_offset(case["input"].as_str().unwrap()).unwrap();
            assert_eq!(
                utc_iso(wall, off).unwrap(),
                case["utc_iso"].as_str().unwrap(),
                "{case}"
            );
        }
    }

    #[test]
    fn tokens_and_keys_like_python() {
        let v: Value = serde_json::from_str(include_str!("waf_vectors.json")).unwrap();
        for case in v["tokens"].as_array().unwrap() {
            let got = crypto::normalize_token(case["input"].as_str().unwrap());
            match case.get("ok") {
                Some(ok) => {
                    let ok = ok.as_str().unwrap();
                    assert_eq!(got.as_deref(), Ok(ok));
                    assert_eq!(crypto::display_prefix(ok), case["prefix"].as_str().unwrap());
                }
                None => assert_eq!(got.unwrap_err().message, case["error"].as_str().unwrap()),
            }
        }
        for case in v["keys"].as_array().unwrap() {
            let key = case["value"].as_str().map(Secret::new);
            let got = crypto::fernet(key.as_ref());
            if case["configured"].as_bool().unwrap() {
                assert!(got.is_ok(), "{case}");
            } else {
                let e = got.unwrap_err();
                assert_eq!(e.kind, case["error"].as_str().unwrap());
                assert_eq!(e.message, case["message"].as_str().unwrap());
            }
        }
    }
}
