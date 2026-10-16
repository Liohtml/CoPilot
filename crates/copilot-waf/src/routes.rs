//! `/api/customer_waf/*` — port of `app/customer_waf/routes/customer_waf.py`
//! — and the WAF half of `POST /api/monitoring_alert/provision`.
//!
//! Every route but `GET ""` names its tenant in the path and carries
//! `verify_customer_code_access`; a `{waf_id}` is resolved through
//! [`services::get_instance_for_customer`], which refuses another customer's
//! WAF. Configuration writes are admin-only, reads, the connection check and
//! IP blocks admin/analyst. Upstream failures answer 502 (or 404 / 409) with
//! `{"detail", "reason", "success": false}` — a plain `JSONResponse`, so no
//! `log_entries` row — never 401/403.
//!
//! Check order is FastAPI's: the body is read first, then the token, the
//! customer, and the path, query and body validation together (one 422).

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{FromRequest, Path, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::json::pydantic_json;
use copilot_upstream::py::{PyExc, getitem};
use copilot_web::body::JsonBody;
use copilot_web::validate::{IntRules, Loc, LocPart, StrRules, Validator, body_loc, loc};
use copilot_web::{
    AdminOnly, AdminOrAnalyst, ApiError, ApiResult, Authorized, QueryPairs, WithJson,
};
use http::StatusCode;
use serde_json::{Map, Value};

use crate::alerts::{self, AlertError, WAF_ALERTS};
use crate::blocks::{self, BlockAction};
use crate::client::WafError;
use crate::crypto;
use crate::forwarding::{self, ProvisionError};
use crate::schema::{self, BlockRequest, ForwardingRequest, InstanceCreate, InstanceUpdate};
use crate::services::{self, EventFilters, WafState};
use crate::store::WafRow;

type Reader = Authorized<AdminOrAnalyst>;
type Admin = Authorized<AdminOnly>;

/// The router, nested at `/api/customer_waf`.
pub fn router(state: WafState) -> Router {
    Router::new()
        .route("/", get(list_all))
        .route("/{customer_code}", get(list_customer).post(create))
        .route("/{customer_code}/{waf_id}", put(update).delete(remove))
        .route(
            "/{customer_code}/{waf_id}/forwarding",
            post(forwarding_set_up).delete(forwarding_remove),
        )
        .route("/{customer_code}/{waf_id}/verify", post(verify))
        .route("/{customer_code}/{waf_id}/sites", get(sites))
        .route("/{customer_code}/{waf_id}/events", get(events))
        .route("/{customer_code}/{waf_id}/stats", get(stats))
        .route("/{customer_code}/{waf_id}/threat-intel", get(threat_intel))
        .route(
            "/{customer_code}/{waf_id}/blocks",
            get(list_blocks).post(block).delete(unblock),
        )
        .with_state(state)
}

/// `POST /api/monitoring_alert/provision` for the two WAF alerts (full path:
/// every other alert is handed to Python with its body).
pub fn monitoring_router(state: WafState) -> Router {
    Router::new()
        .route(
            "/api/monitoring_alert/provision",
            post(provision_monitoring_alert),
        )
        .with_state(state)
}

// --- responses -------------------------------------------------------------------

fn respond(status: StatusCode, dump: PyValue) -> Response {
    (
        status,
        [(http::header::CONTENT_TYPE, "application/json")],
        pydantic_json(&dump),
    )
        .into_response()
}

fn ok(dump: PyValue) -> Response {
    respond(StatusCode::OK, dump)
}

fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn st(v: impl Into<String>) -> PyValue {
    PyValue::Str(v.into())
}

fn list_of(items: Vec<String>) -> PyValue {
    PyValue::List(items.into_iter().map(PyValue::Str).collect())
}

/// A route's own `JSONResponse` (no `log_entries` row).
fn json_error(status: u16, detail: String, reason: Option<&str>) -> Response {
    let mut pairs = vec![("detail", st(detail))];
    if let Some(r) = reason {
        pairs.push(("reason", st(r)));
    }
    pairs.push(("success", PyValue::Bool(false)));
    respond(
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
        dict(pairs),
    )
}

/// `_error(e)`: a WAF or token failure as the route's `JSONResponse`, any
/// other exception as the backend's handlers answer it.
fn waf_error(e: WafError) -> Response {
    match e {
        WafError::Request {
            reason,
            detail,
            status,
        } => json_error(status, detail, Some(reason)),
        WafError::Crypto(c) if c.status == 500 => {
            ApiError::internal(format!("{}: {}", c.kind, c.message)).into_response()
        }
        WafError::Crypto(c) => json_error(c.status, c.message, Some("token_crypto")),
        WafError::Py(p) => p.unhandled().into_response(),
    }
}

/// An exception the route does not catch.
fn uncaught(e: WafError) -> ApiError {
    match e {
        WafError::Py(p) => p.unhandled(),
        WafError::Request { reason, detail, .. } => {
            ApiError::internal(format!("WafRequestError {reason}: {detail}"))
        }
        WafError::Crypto(c) => ApiError::internal(format!("{}: {}", c.kind, c.message)),
    }
}

fn path_id(v: &mut Validator, raw: &str) -> i64 {
    v.check_int(
        &loc("path", "waf_id"),
        &Value::String(raw.to_string()),
        IntRules::default(),
    )
    .unwrap_or_default()
}

/// FastAPI's body parameter, read into the validator that already holds the
/// path and query errors.
fn read_body<T: Default>(
    v: &mut Validator,
    body: &JsonBody,
    read: impl FnOnce(&mut Validator, &Map<String, Value>, &Loc) -> T,
) -> T {
    let root = body_loc();
    match body {
        JsonBody::Missing => {
            v.missing(root);
            T::default()
        }
        JsonBody::NotJson => {
            v.object(&Value::Null, &root);
            T::default()
        }
        JsonBody::Value(value) => match v.object(value, &root) {
            Some(obj) => read(v, obj, &root),
            None => T::default(),
        },
    }
}

async fn row_for(st_: &WafState, code: &str, id: i64) -> Result<WafRow, ApiError> {
    services::get_instance_for_customer(st_, code, id)
        .await
        .map_err(uncaught)
}

fn message(text: String) -> PyValue {
    PyValue::Str(text)
}

// --- configuration ------------------------------------------------------------------

async fn list_all(State(s): State<WafState>, auth: Reader) -> ApiResult {
    let codes = auth.access(&s.ctx).await?.scoped_customer_codes(None);
    let rows = match &codes {
        Some(c) if c.is_empty() => Vec::new(),
        other => services::list_all_instances(&s, other.as_deref())
            .await
            .map_err(uncaught)?,
    };
    Ok(ok(dict(vec![
        (
            "instances",
            PyValue::List(rows.iter().map(schema::instance).collect()),
        ),
        (
            "encryption_key_configured",
            PyValue::Bool(crypto::key_configured(s.env.token_key.as_ref())),
        ),
        ("forwarding_default_host", PyValue::None),
        ("forwarding_port_range", PyValue::None),
        ("success", PyValue::Bool(true)),
        ("message", message(format!("{} WAF(s) visible", rows.len()))),
    ])))
}

async fn list_customer(
    State(s): State<WafState>,
    Path(code): Path<String>,
    auth: Reader,
) -> ApiResult {
    auth.enforce_customer(&s.ctx, &code).await?;
    let rows = services::list_instances(&s, &code)
        .await
        .map_err(uncaught)?;
    let range = forwarding::port_range(s.env.syslog_port_range.as_deref())
        .map(|(lo, hi)| st(format!("{lo}-{hi}")))
        .unwrap_or(PyValue::None);
    let host = forwarding::default_syslog_host(s.env.syslog_default_host.as_deref())
        .map_or(PyValue::None, st);
    Ok(ok(dict(vec![
        (
            "instances",
            PyValue::List(rows.iter().map(schema::instance).collect()),
        ),
        (
            "encryption_key_configured",
            PyValue::Bool(crypto::key_configured(s.env.token_key.as_ref())),
        ),
        ("forwarding_default_host", host),
        ("forwarding_port_range", range),
        ("success", PyValue::Bool(true)),
        (
            "message",
            message(format!("{} WAF(s) configured", rows.len())),
        ),
    ])))
}

/// `_verify_quietly`: the save stands even when the WAF is unreachable.
async fn verify_quietly(
    s: &WafState,
    row: &WafRow,
) -> Result<(Option<schema::VerifyResult>, WafRow), ApiError> {
    match services::verify_instance(s, row).await {
        Ok((result, fresh)) => Ok((Some(result), fresh)),
        Err(WafError::Request { .. }) => Ok((None, row.clone())),
        Err(WafError::Crypto(c)) if c.status != 500 => Ok((None, row.clone())),
        Err(e) => Err(uncaught(e)),
    }
}

fn instance_response(
    status: StatusCode,
    row: &WafRow,
    verification: Option<&schema::VerifyResult>,
    text: String,
) -> Response {
    respond(
        status,
        dict(vec![
            ("instance", schema::instance(row)),
            (
                "verification",
                verification.map_or(PyValue::None, schema::VerifyResult::dump),
            ),
            ("warnings", list_of(services::config_warnings(row))),
            ("success", PyValue::Bool(true)),
            ("message", message(text)),
        ]),
    )
}

async fn create(
    State(s): State<WafState>,
    Path(code): Path<String>,
    WithJson(auth, body): WithJson<Admin>,
) -> ApiResult {
    auth.enforce_customer(&s.ctx, &code).await?;
    let mut v = Validator::new();
    let req: InstanceCreate = read_body(&mut v, &body, InstanceCreate::read);
    v.finish()?;
    let row = match services::create_instance(&s, &code, &req, Some(auth.id)).await {
        Ok(row) => row,
        Err(e @ WafError::Crypto(_)) => return Ok(waf_error(e)),
        Err(e) => return Err(uncaught(e)),
    };
    let (verification, row) = verify_quietly(&s, &row).await?;
    let text = if verification.as_ref().is_some_and(|v| v.authenticated) {
        "WAF saved"
    } else {
        "WAF saved, but the connection test did not pass"
    };
    Ok(instance_response(
        StatusCode::CREATED,
        &row,
        verification.as_ref(),
        text.into(),
    ))
}

async fn update(
    State(s): State<WafState>,
    Path((code, raw_id)): Path<(String, String)>,
    WithJson(auth, body): WithJson<Admin>,
) -> ApiResult {
    auth.enforce_customer(&s.ctx, &code).await?;
    let mut v = Validator::new();
    let id = path_id(&mut v, &raw_id);
    let req: InstanceUpdate = read_body(&mut v, &body, InstanceUpdate::read);
    v.finish()?;
    let row = row_for(&s, &code, id).await?;
    let (row, changed) = match services::update_instance(&s, row, &req, Some(auth.id)).await {
        Ok(r) => r,
        Err(e @ WafError::Crypto(_)) => return Ok(waf_error(e)),
        Err(e) => return Err(uncaught(e)),
    };
    let (verification, row) = if changed {
        verify_quietly(&s, &row).await?
    } else {
        (None, row)
    };
    Ok(instance_response(
        StatusCode::OK,
        &row,
        verification.as_ref(),
        "WAF updated".into(),
    ))
}

async fn remove(
    State(s): State<WafState>,
    Path((code, raw_id)): Path<(String, String)>,
    auth: Admin,
) -> ApiResult {
    auth.enforce_customer(&s.ctx, &code).await?;
    let mut v = Validator::new();
    let id = path_id(&mut v, &raw_id);
    v.finish()?;
    let row = row_for(&s, &code, id).await?;
    let (name, prefix) = (row.name.clone(), row.token_prefix.clone());
    let warnings = if row.forwarding_provisioned_at.is_some() {
        forwarding::deprovision(&s, &row).await.map_err(uncaught)?.0
    } else {
        Vec::new()
    };
    services::delete_instance(&s, &row, Some(auth.id))
        .await
        .map_err(uncaught)?;
    let mut parts = vec![format!(
        "WAF '{name}' removed from CoPilot. Its token ({prefix}) is still valid on the WAF — \
         revoke it under Service Tokens in the WAF UI."
    )];
    parts.extend(warnings);
    Ok(ok(dict(vec![
        ("success", PyValue::Bool(true)),
        ("message", message(parts.join(" "))),
    ])))
}

// --- event forwarding ----------------------------------------------------------

fn forwarding_response(
    row: &WafRow,
    test_success: Option<bool>,
    test_message: PyValue,
    reused: Vec<String>,
    warnings: Vec<String>,
    text: String,
) -> ApiResult {
    // `test_message: Optional[str]`: anything else fails the response model.
    if !matches!(test_message, PyValue::None | PyValue::Str(_)) {
        return Err(ApiError::internal("ResponseValidationError: test_message"));
    }
    Ok(ok(dict(vec![
        ("instance", schema::instance(row)),
        (
            "test_success",
            test_success.map_or(PyValue::None, PyValue::Bool),
        ),
        ("test_message", test_message),
        ("reused", list_of(reused)),
        ("warnings", list_of(warnings)),
        ("success", PyValue::Bool(true)),
        ("message", message(text)),
    ])))
}

async fn forwarding_set_up(
    State(s): State<WafState>,
    Path((code, raw_id)): Path<(String, String)>,
    WithJson(auth, body): WithJson<Admin>,
) -> ApiResult {
    auth.enforce_customer(&s.ctx, &code).await?;
    let mut v = Validator::new();
    let id = path_id(&mut v, &raw_id);
    let req: ForwardingRequest = read_body(&mut v, &body, ForwardingRequest::read);
    v.finish()?;
    let row = row_for(&s, &code, id).await?;
    let host = req
        .syslog_host
        .as_deref()
        .map(copilot_web::form::py_strip)
        .filter(|h| !h.is_empty())
        .map(str::to_string)
        .or_else(|| forwarding::default_syslog_host(s.env.syslog_default_host.as_deref()));
    let Some(host) = host else {
        return Ok(json_error(
            400,
            "Give the syslog host the WAF should send to (the Graylog address the WAF can \
             reach), or set WAF_SYSLOG_DEFAULT_HOST."
                .into(),
            Some("no_syslog_host"),
        ));
    };
    let done = match forwarding::provision(&s, &row, &host).await {
        Ok(d) => d,
        Err(ProvisionError::Forwarding(f)) => {
            let mut detail = f.detail.clone();
            if !f.rollback_failures.is_empty() {
                detail.push_str(&format!(
                    " Rollback could not undo: {}",
                    f.rollback_failures.join("; ")
                ));
            }
            return Ok(json_error(f.status, detail, Some("forwarding_failed")));
        }
        Err(ProvisionError::Waf(e @ (WafError::Request { .. } | WafError::Crypto(_)))) => {
            return Ok(waf_error(e));
        }
        Err(ProvisionError::Waf(e)) => return Err(uncaught(e)),
    };
    let port = done
        .row
        .syslog_port
        .map_or("None".to_string(), |p| p.to_string());
    let mut warnings = Vec::new();
    if done.test_success == Some(false) {
        warnings.push(format!(
            "The WAF's test event did not reach {host}:{port} ({}). Forwarding is set up; check \
             that the WAF can reach that address and port.",
            done.test_message.py_str()
        ));
    }
    let text = format!(
        "WAF '{}' now forwards its events to {host}:{port}",
        done.row.name
    );
    forwarding_response(
        &done.row,
        done.test_success,
        done.test_message.clone(),
        done.reused.clone(),
        warnings,
        text,
    )
}

async fn forwarding_remove(
    State(s): State<WafState>,
    Path((code, raw_id)): Path<(String, String)>,
    auth: Admin,
) -> ApiResult {
    auth.enforce_customer(&s.ctx, &code).await?;
    let mut v = Validator::new();
    let id = path_id(&mut v, &raw_id);
    v.finish()?;
    let row = row_for(&s, &code, id).await?;
    if row.forwarding_provisioned_at.is_none() {
        return Ok(json_error(
            404,
            "Event forwarding is not set up for this WAF".into(),
            None,
        ));
    }
    let (warnings, row) = match forwarding::deprovision(&s, &row).await {
        Ok(r) => r,
        Err(e @ WafError::Crypto(_)) => return Ok(waf_error(e)),
        Err(e) => return Err(uncaught(e)),
    };
    let text = format!(
        "Event forwarding removed for WAF '{}'. Events already stored are kept.",
        row.name
    );
    forwarding_response(&row, None, PyValue::None, Vec::new(), warnings, text)
}

// --- WAF-facing ----------------------------------------------------------------

async fn verify(
    State(s): State<WafState>,
    Path((code, raw_id)): Path<(String, String)>,
    auth: Reader,
) -> ApiResult {
    auth.enforce_customer(&s.ctx, &code).await?;
    let mut v = Validator::new();
    let id = path_id(&mut v, &raw_id);
    v.finish()?;
    let row = row_for(&s, &code, id).await?;
    let (result, row) = match services::verify_instance(&s, &row).await {
        Ok(r) => r,
        Err(e @ WafError::Crypto(_)) => return Ok(waf_error(e)),
        Err(e) => return Err(uncaught(e)),
    };
    let text = if result.authenticated {
        "Connection OK".to_string()
    } else {
        result
            .detail
            .clone()
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| "Connection test failed".into())
    };
    Ok(ok(dict(vec![
        ("instance", schema::instance(&row)),
        ("verification", result.dump()),
        ("success", PyValue::Bool(result.authenticated)),
        ("message", message(text)),
    ])))
}

/// The four reads: the row, then the WAF call (whose WAF and token failures
/// are the route's `JSONResponse`).
macro_rules! caught {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e @ (WafError::Request { .. } | WafError::Crypto(_))) => return Ok(waf_error(e)),
            Err(e) => return Err(uncaught(e)),
        }
    };
}

async fn sites(
    State(s): State<WafState>,
    Path((code, raw_id)): Path<(String, String)>,
    auth: Reader,
) -> ApiResult {
    auth.enforce_customer(&s.ctx, &code).await?;
    let mut v = Validator::new();
    let id = path_id(&mut v, &raw_id);
    v.finish()?;
    let row = row_for(&s, &code, id).await?;
    let sites = caught!(services::fetch_sites(&s, &row).await);
    let n = sites.len();
    Ok(ok(dict(vec![
        ("sites", PyValue::List(sites)),
        ("success", PyValue::Bool(true)),
        ("message", message(format!("{n} site(s)"))),
    ])))
}

/// `Optional[Literal[…]] = Query(None)`.
fn literal_query(
    v: &mut Validator,
    q: &QueryPairs,
    name: &str,
    allowed: &[&str],
) -> Option<String> {
    let raw = q.get(name)?;
    if allowed.contains(&raw) {
        return Some(raw.to_string());
    }
    let quoted: Vec<String> = allowed.iter().map(|a| format!("'{a}'")).collect();
    let expected = match quoted.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
        Some((last, _)) => last.clone(),
        None => String::new(),
    };
    v.push(
        "literal_error",
        loc("query", name),
        format!("Input should be {expected}"),
    );
    None
}

/// `Optional[datetime] = Query(None)` → `_utc_iso(value)`.
fn time_query(
    v: &mut Validator,
    q: &QueryPairs,
    name: &str,
) -> Option<(chrono::NaiveDateTime, Option<i32>)> {
    let raw = q.get(name)?;
    match copilot_web::datetime::parse_lax_offset(raw) {
        Ok(t) => Some(t),
        Err(e) => {
            v.push(e.kind, loc("query", name), e.msg);
            None
        }
    }
}

async fn events(
    State(s): State<WafState>,
    Path((code, raw_id)): Path<(String, String)>,
    auth: Reader,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&s.ctx, &code).await?;
    let mut v = Validator::new();
    let id = path_id(&mut v, &raw_id);
    let action = literal_query(&mut v, &q, "action", &["blocked", "detected", "passed"]);
    let severity = q.opt_str(&mut v, "severity", StrRules::max(20));
    let client_ip = q.opt_str(&mut v, "client_ip", StrRules::max(45));
    let rule_id = q.opt_str(&mut v, "rule_id", StrRules::max(20));
    let site_id = q.opt_str(&mut v, "site_id", StrRules::max(64));
    let start = time_query(&mut v, &q, "start_time");
    let end = time_query(&mut v, &q, "end_time");
    let limit = q.int_or(
        &mut v,
        "limit",
        IntRules {
            ge: Some(1),
            le: Some(500),
        },
        100,
    );
    let offset = q.int_or(
        &mut v,
        "offset",
        IntRules {
            ge: Some(0),
            le: None,
        },
        0,
    );
    v.finish()?;
    let row = row_for(&s, &code, id).await?;
    let iso =
        |t: Option<(chrono::NaiveDateTime, Option<i32>)>| -> Result<Option<String>, ApiError> {
            t.map(|(wall, off)| services::utc_iso(wall, off))
                .transpose()
                .map_err(PyExc::unhandled)
        };
    let params = services::build_event_params(&EventFilters {
        action,
        severity,
        client_ip,
        rule_id,
        site_id,
        start_time: iso(start)?,
        end_time: iso(end)?,
        limit,
        offset,
    });
    let events = caught!(services::fetch_events(&s, &row, params).await);
    let n = events.len();
    Ok(ok(dict(vec![
        ("events", PyValue::List(events)),
        ("limit", PyValue::Int(limit.to_string())),
        ("offset", PyValue::Int(offset.to_string())),
        ("success", PyValue::Bool(true)),
        ("message", message(format!("{n} event(s)"))),
    ])))
}

async fn stats(
    State(s): State<WafState>,
    Path((code, raw_id)): Path<(String, String)>,
    auth: Reader,
) -> ApiResult {
    auth.enforce_customer(&s.ctx, &code).await?;
    let mut v = Validator::new();
    let id = path_id(&mut v, &raw_id);
    v.finish()?;
    let row = row_for(&s, &code, id).await?;
    let stats = caught!(services::fetch_stats(&s, &row).await);
    Ok(ok(dict(vec![
        ("stats", stats),
        ("success", PyValue::Bool(true)),
        ("message", st("WAF stats retrieved")),
    ])))
}

async fn threat_intel(
    State(s): State<WafState>,
    Path((code, raw_id)): Path<(String, String)>,
    auth: Reader,
) -> ApiResult {
    auth.enforce_customer(&s.ctx, &code).await?;
    let mut v = Validator::new();
    let id = path_id(&mut v, &raw_id);
    v.finish()?;
    let row = row_for(&s, &code, id).await?;
    let (summary, entries) = caught!(services::fetch_threat_intel(&s, &row).await);
    let n = entries.len();
    Ok(ok(dict(vec![
        ("summary", summary),
        ("entries", PyValue::List(entries)),
        ("success", PyValue::Bool(true)),
        ("message", message(format!("{n} offender(s)"))),
    ])))
}

// --- IP blocks -------------------------------------------------------------------

fn target_or_422(value: &str) -> Result<crate::ip::Network, Box<Response>> {
    blocks::normalize_target(value)
        .map_err(|e| Box::new(json_error(422, e, Some("invalid_target"))))
}

fn py(e: PyExc) -> ApiError {
    e.unhandled()
}

async fn list_blocks(
    State(s): State<WafState>,
    Path((code, raw_id)): Path<(String, String)>,
    auth: Reader,
) -> ApiResult {
    auth.enforce_customer(&s.ctx, &code).await?;
    let mut v = Validator::new();
    let id = path_id(&mut v, &raw_id);
    v.finish()?;
    let row = row_for(&s, &code, id).await?;
    let rules = caught!(blocks::fetch_rules(&s.client, &row).await);
    let (copilot, other) = caught!(blocks::ip_block_rules(&rules).map_err(WafError::Py));
    let mut active = 0usize;
    for r in &copilot {
        if copilot_upstream::py::get(r, "is_enabled")
            .map_err(py)?
            .is_some_and(PyValue::truthy)
        {
            active += 1;
        }
    }
    let to = |rs: &[PyValue]| -> Result<Vec<PyValue>, ApiError> {
        rs.iter()
            .map(|r| blocks::to_block(r, None).map_err(py))
            .collect()
    };
    Ok(ok(dict(vec![
        ("copilot_blocks", PyValue::List(to(&copilot)?)),
        ("other_ip_blocks", PyValue::List(to(&other)?)),
        ("success", PyValue::Bool(true)),
        (
            "message",
            message(format!(
                "{active} active CoPilot block(s), {} WAF-managed IP block(s)",
                other.len()
            )),
        ),
    ])))
}

async fn block(
    State(s): State<WafState>,
    Path((code, raw_id)): Path<(String, String)>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    auth.enforce_customer(&s.ctx, &code).await?;
    let mut v = Validator::new();
    let id = path_id(&mut v, &raw_id);
    let req: BlockRequest = read_body(&mut v, &body, BlockRequest::read);
    v.finish()?;
    let row = row_for(&s, &code, id).await?;
    let network = match target_or_422(&req.target) {
        Ok(n) => n,
        Err(resp) => return Ok(*resp),
    };
    services::verify_block_provenance(&s, &auth.user, &code, req.alert_id, req.case_id).await?;
    let username = if auth.username.is_empty() {
        "unknown".to_string()
    } else {
        auth.username.clone()
    };
    let description = blocks::build_description(&req.reason, &username, req.alert_id, req.case_id);
    let (action, rule) = caught!(blocks::block(&s.client, &row, &network, &description).await);
    let target = blocks::display(&network);
    // The four messages are all built (and their subscripts evaluated).
    let rule_id = getitem(&rule, "rule_id").map_err(py)?.py_str();
    let rule_name = copilot_upstream::py::get(&rule, "name")
        .map_err(py)?
        .map_or("None".to_string(), PyValue::py_str);
    let text = match action {
        BlockAction::Created => format!("Blocked {target} on WAF '{}' (rule {rule_id})", row.name),
        BlockAction::Reenabled => format!(
            "Re-enabled CoPilot's block of {target} on WAF '{}' (rule {rule_id})",
            row.name
        ),
        BlockAction::AlreadyBlocked => format!(
            "{target} is already blocked on WAF '{}' by CoPilot rule {rule_id}",
            row.name
        ),
        BlockAction::BlockedByWafRule => format!(
            "{target} is already blocked on WAF '{}' by its own rule {rule_id} ('{rule_name}'), \
             which CoPilot doesn't manage — no CoPilot rule was added",
            row.name
        ),
    };
    if let Some(alert_id) = req.alert_id {
        if matches!(action, BlockAction::Created | BlockAction::Reenabled) {
            let comment = format!(
                "{target} blocked on WAF '{}' (rule {rule_id}) by {username}: {}",
                row.name,
                blocks::collapse_whitespace(&req.reason)
            );
            services::comment_block_on_alert(&s, alert_id, &comment, &username).await;
        }
    }
    let shown = (action != BlockAction::BlockedByWafRule).then_some(&network);
    let block = blocks::to_block(&rule, shown).map_err(py)?;
    Ok(ok(dict(vec![
        ("action", st(action.as_str())),
        ("target", st(target)),
        ("block", block),
        ("warnings", list_of(blocks::target_warnings(&network))),
        ("success", PyValue::Bool(true)),
        ("message", message(text)),
    ])))
}

async fn unblock(
    State(s): State<WafState>,
    Path((code, raw_id)): Path<(String, String)>,
    auth: Reader,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&s.ctx, &code).await?;
    let mut v = Validator::new();
    let id = path_id(&mut v, &raw_id);
    let target = match q.get("target") {
        None => {
            v.missing(loc("query", "target"));
            String::new()
        }
        Some(_) => q
            .opt_str(&mut v, "target", StrRules::max(64))
            .unwrap_or_default(),
    };
    v.finish()?;
    let row = row_for(&s, &code, id).await?;
    let network = match target_or_422(&target) {
        Ok(n) => n,
        Err(resp) => return Ok(*resp),
    };
    let (unblocked, rules, waf_rule) = caught!(blocks::unblock(&s.client, &row, &network).await);
    let shown = blocks::display(&network);
    let rule_text = |r: &PyValue| -> Result<(String, String), ApiError> {
        let id = getitem(r, "rule_id").map_err(py)?.py_str();
        let name = copilot_upstream::py::get(r, "name")
            .map_err(py)?
            .map_or("None".to_string(), PyValue::py_str);
        Ok((id, name))
    };
    if rules.is_empty() {
        if let Some(w) = &waf_rule {
            let (rid, rname) = rule_text(w)?;
            return Ok(json_error(
                409,
                format!(
                    "{shown} is blocked by WAF '{}' rule {rid} ('{rname}'), which CoPilot didn't \
                     create — lift it in the WAF UI.",
                    row.name
                ),
                Some("blocked_by_waf_rule"),
            ));
        }
        return Ok(json_error(
            404,
            format!("No CoPilot block for {shown} on WAF '{}'", row.name),
            Some("not_blocked"),
        ));
    }
    let mut text = if unblocked {
        format!("Unblocked {shown} on WAF '{}'", row.name)
    } else {
        format!("CoPilot's block of {shown} was already lifted")
    };
    if let Some(w) = &waf_rule {
        let (rid, rname) = rule_text(w)?;
        text.push_str(&format!(
            " — but the WAF's own rule {rid} ('{rname}') still blocks it. CoPilot doesn't manage \
             that rule; lift it in the WAF UI."
        ));
    }
    let blocks_out = rules
        .iter()
        .map(|r| blocks::to_block(r, Some(&network)).map_err(py))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ok(dict(vec![
        (
            "action",
            st(if unblocked {
                "unblocked"
            } else {
                "already_unblocked"
            }),
        ),
        ("target", st(shown)),
        ("blocks", PyValue::List(blocks_out)),
        ("success", PyValue::Bool(true)),
        ("message", message(text)),
    ])))
}

// --- POST /api/monitoring_alert/provision -------------------------------------------

/// The request's `alert_name` as the validator normalizes it, when the body
/// is a JSON object naming one of the WAF alerts.
fn waf_alert_name(content_type: Option<&str>, bytes: &[u8]) -> Option<String> {
    if !content_type.is_some_and(copilot_web::body::is_json_content_type) {
        return None;
    }
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let name = value.get("alert_name")?.as_str()?;
    let normalized = name.replace(' ', "_").to_uppercase();
    WAF_ALERTS
        .contains(&normalized.as_str())
        .then_some(normalized)
}

/// `ProvisionMonitoringAlertRequest` (the two `validate_non_zero` fields raise
/// an `HTTPException` mid-validation, which ends it).
fn read_provision_request(body: &JsonBody) -> Result<(i64, i64, String), ApiError> {
    let mut v = Validator::new();
    let root = body_loc();
    let obj = match body {
        JsonBody::Value(value) => v.object(value, &root).cloned(),
        JsonBody::Missing => {
            v.missing(root.clone());
            None
        }
        JsonBody::NotJson => {
            v.object(&Value::Null, &root);
            None
        }
    };
    let Some(obj) = obj else {
        v.finish()?;
        return Err(ApiError::internal("unreachable"));
    };
    let mut ints = [0i64; 2];
    for (i, name) in ["search_within_last", "execute_every"].iter().enumerate() {
        let at = {
            let mut l = root.clone();
            l.push(LocPart::Key((*name).into()));
            l
        };
        match obj.get(*name) {
            None => v.missing(at),
            Some(raw) => {
                if let Some(n) = v.check_int(&at, raw, IntRules::default()) {
                    if n == 0 {
                        return Err(ApiError::bad_request(
                            "Invalid value: 0. Must be greater than 0.",
                        ));
                    }
                    ints[i] = n;
                }
            }
        }
    }
    let name = obj
        .get("alert_name")
        .and_then(Value::as_str)
        .map(|n| n.replace(' ', "_").to_uppercase())
        .unwrap_or_default();
    v.enum_or(
        &obj,
        &root,
        "graylog_instance",
        &["default", "network"],
        "default",
    );
    v.finish()?;
    Ok((ints[0], ints[1], name))
}

async fn provision_monitoring_alert(State(s): State<WafState>, req: Request) -> Response {
    let content_type = req
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, 64 << 20).await {
        Ok(b) => b,
        Err(_) => {
            return ApiError::detail(
                StatusCode::BAD_REQUEST,
                "There was an error parsing the body",
            )
            .into_response();
        }
    };
    if waf_alert_name(content_type.as_deref(), &bytes).is_none() {
        // Not a WAF alert: Python answers it, body and all.
        return match &s.legacy {
            Some(proxy) => {
                proxy
                    .forward(Request::from_parts(parts, Body::from(bytes)))
                    .await
            }
            None => ApiError::RouteNotFound.into_response(),
        };
    }
    let request = Request::from_parts(parts, Body::from(Bytes::clone(&bytes)));
    let WithJson(auth, body) = match WithJson::<Reader>::from_request(request, &s).await {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let _ = auth;
    match provision_waf_alert(&s, &body).await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

async fn provision_waf_alert(s: &WafState, body: &JsonBody) -> ApiResult {
    let (search_within, execute_every, name) = read_provision_request(body)?;
    // Pinned to the default Graylog, whatever `graylog_instance` asked for.
    if let Err(e) = alerts::check_event_definition(s, &name.replace('_', " ")).await {
        return Err(e.unhandled());
    }
    let result = if name == "SOCFORTRESS_WAF_BLOCKED" {
        alerts::provision_blocked_alert(s, i128::from(execute_every), i128::from(search_within))
            .await
    } else {
        alerts::provision_brute_force_alert(s).await
    };
    match result {
        Ok(()) => {}
        Err(AlertError::Py(e)) => return Err(e.unhandled()),
        Err(AlertError::Api(e)) => return Err(e),
    }
    Ok(ok(dict(vec![
        ("success", PyValue::Bool(true)),
        (
            "message",
            st(format!("Monitoring alert {name} provisioned successfully.")),
        ),
    ])))
}
