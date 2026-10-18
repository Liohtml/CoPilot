//! The handlers, at their full paths under `/api/wazuh_manager`.

use std::time::Duration;

use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use http::StatusCode;
use num_bigint_dig::BigInt;

use copilot_auth::pyvalue::PyValue;
use copilot_monitoring_alerts::body::WithPyJson;
use copilot_searches::{py, pyd};
use copilot_threat_intel::httpx::HttpxError;
use copilot_upstream::model;
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::model_response;
use copilot_web::validate::{Validator, loc};
use copilot_web::{AdminOnly, AdminOrAnalyst, ApiError, Authorized, QueryPairs, ScopedUser};
use copilot_yaml::Value;

use crate::RulesState;
use crate::mitre_alerts::{self as mitre, Search};
use crate::rules::{self, NEW_LEVEL};
use crate::schema::{self, atomic as models};
use crate::services::{self as db, NewDisabledRule};

type Admin = ScopedUser<AdminOnly>;
type Res = Result<Response, ApiError>;

/// The AI module's exclusion route.
pub const AI_MODULE_URL: &str = "http://copilot-ai-module/wazuh-rule-exclusion";
/// `timeout=120`.
const AI_TIMEOUT: Duration = Duration::from_secs(120);

/// The routes, at their full paths.
pub fn router(state: RulesState) -> Router {
    Router::new()
        .route("/api/wazuh_manager/rule/disabled", get(disabled))
        .route("/api/wazuh_manager/rule/disable", post(disable))
        .route("/api/wazuh_manager/rule/enable", post(enable))
        .route("/api/wazuh_manager/rule/exclude", post(exclude))
        .route("/api/wazuh_manager/mitre/atomic-tests", get(atomic_tests))
        .route(
            "/api/wazuh_manager/mitre/techniques/{technique_id}/atomic-tests",
            get(technique_tests),
        )
        .route(
            "/api/wazuh_manager/mitre/techniques/alerts",
            get(techniques_in_alerts),
        )
        .route(
            "/api/wazuh_manager/mitre/techniques/{technique_id}/alerts",
            get(technique_alerts),
        )
        .with_state(state)
}

/// `GET /rule/disabled`. Python validated the rows without
/// `from_attributes`, so any stored row was the response model's 400; the
/// rows are listed here (RUST_MIGRATION.md §4).
async fn disabled(_a: Admin, State(st): State<RulesState>) -> Res {
    let rows = db::all(&st.wazuh.ctx.db).await?;
    Ok(model_response(&schema::all_disabled(&rows)))
}

fn text_field(dump: &PyValue, key: &str) -> String {
    dump.get(key)
        .and_then(PyValue::as_str)
        .unwrap_or_default()
        .to_string()
}

/// `POST /rule/disable`.
async fn disable(State(st): State<RulesState>, WithPyJson(user, body): WithPyJson<Admin>) -> Res {
    let dump = body.model(&schema::RULE_DISABLE)?;
    let rule_id = text_field(&dump, "rule_id");
    let db = &st.wazuh.ctx.db;
    if db::first_for(db, &rule_id).await?.is_some() {
        return Err(ApiError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Rule is already disabled",
        ));
    }
    let processed = rules::process_rule(&st.wazuh, &rule_id, NEW_LEVEL).await?;
    let previous = rules::previous_level_text("RuleDisableResponse", &processed.previous_level)?;
    db::insert(
        db,
        &NewDisabledRule {
            rule_id: &rule_id,
            previous_level: previous.as_deref(),
            new_level: NEW_LEVEL,
            reason_for_disabling: &text_field(&dump, "reason_for_disabling"),
            length_of_time: &text_field(&dump, "length_of_time"),
            disabled_by: &user.username,
        },
    )
    .await?;
    Ok(model_response(&schema::level_response(
        "previous_level",
        previous,
        processed.message,
    )))
}

/// `POST /rule/enable`.
async fn enable(State(st): State<RulesState>, WithPyJson(_u, body): WithPyJson<Admin>) -> Res {
    let dump = body.model(&schema::RULE_ENABLE)?;
    let rule_id = text_field(&dump, "rule_id");
    tracing::info!("rule: {}", dump.py_repr());
    let db = &st.wazuh.ctx.db;
    let Some(row) = db::first_for(db, &rule_id).await? else {
        return Err(ApiError::http(
            StatusCode::NOT_FOUND,
            "Rule is already enabled",
        ));
    };
    let processed = rules::process_rule(&st.wazuh, &rule_id, &row.previous_level).await?;
    db::delete(db, row.id).await?;
    // `RuleEnableResponse(previous_level=…)`: the field it has is
    // `new_level`, left `None`.
    Ok(model_response(&schema::level_response(
        "new_level",
        None,
        processed.message,
    )))
}

fn httpx_exc(e: HttpxError) -> PyExc {
    if e.class == "ValueError" {
        PyExc::ValueError(e.message)
    } else {
        PyExc::Other(e.class, e.message)
    }
}

/// `POST /rule/exclude`: `RuleExcludeResponse(**response.json())` of the AI
/// module's answer, whatever its status.
async fn exclude(
    State(st): State<RulesState>,
    WithPyJson(_a, body): WithPyJson<Authorized<AdminOnly>>,
) -> Res {
    let dump = body.model(&schema::RULE_EXCLUDE_REQUEST)?;
    tracing::info!(
        "Sending POST request to {AI_MODULE_URL} with data: {}",
        dump.py_repr()
    );
    let answer = st
        .upstream
        .post_json(AI_MODULE_URL, dump, &[], AI_TIMEOUT)
        .await
        .map_err(httpx_exc)?;
    let data = answer.json()?;
    let out = model::construct_star(
        &schema::RULE_EXCLUDE_RESPONSE,
        schema::RULE_EXCLUDE_RESPONSE_QUALNAME,
        &data,
    )?;
    Ok(model_response(&out))
}

/// Pydantic's `str` → `int` (whitespace, a sign, single `_` between digits,
/// a fraction of zeros; beyond `i128` it saturates).
pub fn pyd_int(raw: &str) -> Option<i128> {
    let s = raw.trim();
    let s = match s.split_once('.') {
        Some((int, frac)) if !frac.is_empty() && frac.bytes().all(|b| b == b'0') => int,
        Some(_) => return None,
        None => s,
    };
    let (negative, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let bytes = digits.as_bytes();
    if bytes.is_empty()
        || bytes[0] == b'_'
        || bytes[bytes.len() - 1] == b'_'
        || digits.contains("__")
        || !bytes.iter().all(|b| b.is_ascii_digit() || *b == b'_')
    {
        return None;
    }
    let mut value: i128 = 0;
    for b in bytes.iter().filter(|b| **b != b'_') {
        value = value
            .saturating_mul(10)
            .saturating_add(i128::from(b - b'0'));
    }
    Some(if negative { -value } else { value })
}

/// `int = Query(default, gt=…)`.
fn int_query(
    v: &mut Validator,
    q: &QueryPairs,
    name: &str,
    default: i128,
    gt: Option<i128>,
) -> i128 {
    let Some(raw) = q.get(name) else {
        return default;
    };
    let at = loc("query", name);
    let Some(n) = pyd_int(raw) else {
        v.push(
            "int_parsing",
            at,
            "Input should be a valid integer, unable to parse string as an integer",
        );
        return default;
    };
    if let Some(gt) = gt.filter(|gt| n <= *gt) {
        v.push(
            "greater_than",
            at,
            format!("Input should be greater than {gt}"),
        );
        return default;
    }
    n
}

/// Python's slice bounds for `items[start:end]`.
fn slice_bound(i: i128, len: i128) -> i128 {
    if i < 0 { (i + len).max(0) } else { i.min(len) }
}

/// Python's `a // b` (`b != 0`).
fn floor_div(a: i128, b: i128) -> i128 {
    let q = a / b;
    if (a % b != 0) && ((a < 0) != (b < 0)) {
        q - 1
    } else {
        q
    }
}

fn big(n: i128) -> Value {
    Value::Int(BigInt::from(n))
}

/// The body of `list_atomic_tests`' `try`.
async fn list_atomic(
    st: &RulesState,
    size: i128,
    page: i128,
    os_category: Option<&str>,
) -> Result<Value, PyExc> {
    let listing = st.atomic.list_all().await?;
    let all_tests = listing.tests;
    let filtered = match os_category.filter(|c| !c.is_empty()) {
        Some(category) => {
            let wanted = copilot_jinja::unicode::lower(category);
            let mut kept = Vec::new();
            for test in &all_tests {
                let cats = py::get(test, "categories", py::list(Vec::new()))?;
                let mut lowered = Vec::new();
                for cat in py::iterate(&cats)? {
                    lowered.push(py::lower(&cat)?);
                }
                if lowered.contains(&wanted) {
                    kept.push(test.clone());
                }
            }
            tracing::info!(
                "Filtered {} tests down to {} tests for OS category '{category}'",
                all_tests.len(),
                kept.len()
            );
            kept
        }
        None => all_tests,
    };
    let total = filtered.len() as i128;
    let total_pages = if total > 0 {
        if size == 0 {
            return Err(PyExc::Other(
                "ZeroDivisionError",
                "integer division or modulo by zero".into(),
            ));
        }
        floor_div(total.saturating_add(size).saturating_sub(1), size)
    } else {
        1
    };
    let start = page.saturating_sub(1).saturating_mul(size);
    let end = start.saturating_add(size);
    let (from, to) = (slice_bound(start, total), slice_bound(end, total));
    let page_tests: Vec<Value> = if to > from {
        filtered[from as usize..to as usize].to_vec()
    } else {
        Vec::new()
    };
    let message = match os_category.filter(|c| !c.is_empty()) {
        Some(c) => {
            format!("Found {total} MITRE techniques for OS '{c}' (page {page} of {total_pages})")
        }
        None => format!("Found {total} MITRE techniques (page {page} of {total_pages})"),
    };
    let response = py::dict(vec![
        ("success", Value::Bool(true)),
        ("message", py::s(message)),
        ("total_techniques", big(total)),
        (
            "total_tests",
            listing.total_tests.map_or(Value::None, Value::Int),
        ),
        ("tests", py::list(page_tests)),
        ("last_updated", py::s(listing.last_updated)),
        ("page", big(page)),
        ("page_size", big(size)),
        ("total_pages", big(total_pages)),
    ]);
    pyd::build(&models::ATOMIC_TESTS_LIST_RESPONSE, &response)
}

/// `GET /mitre/atomic-tests`: any failure is the 500 `Error retrieving
/// atomic tests: …`.
async fn atomic_tests(
    _a: Authorized<AdminOrAnalyst>,
    State(st): State<RulesState>,
    q: QueryPairs,
) -> Res {
    let mut v = Validator::new();
    let size = int_query(&mut v, &q, "size", 25, None);
    let page = int_query(&mut v, &q, "page", 1, Some(0));
    let os_category = q.get("os_category").map(str::to_string);
    v.finish()?;
    tracing::info!(
        "Request for list of all Atomic Red Team tests (page {page}, size {size}, os_category: \
         {os_category:?})"
    );
    match list_atomic(&st, size, page, os_category.as_deref()).await {
        Ok(dump) => {
            let text = dump
                .to_pydantic_json()
                .map_err(|e| ApiError::internal(format!("PydanticSerializationError: {e}")))?;
            Ok((
                StatusCode::OK,
                [(http::header::CONTENT_TYPE, "application/json")],
                text,
            )
                .into_response())
        }
        Err(e) => {
            tracing::error!("Error retrieving atomic tests: {}", e.display());
            Err(ApiError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error retrieving atomic tests: {}", e.display()),
            ))
        }
    }
}

/// `GET /mitre/techniques/{technique_id}/atomic-tests`.
async fn technique_tests(
    _a: Authorized<AdminOrAnalyst>,
    State(st): State<RulesState>,
    Path(technique_id): Path<String>,
) -> Res {
    tracing::info!("Request for Atomic Red Team tests for technique {technique_id}");
    let clean = if technique_id.contains('-') {
        technique_id.rsplit('-').next().unwrap_or("").to_string()
    } else {
        technique_id.clone()
    };
    let content = st.atomic.technique_markdown(&clean).await;
    let s = |t: String| PyValue::Str(t);
    let out = match content {
        None => PyValue::Dict(vec![
            ("success".into(), PyValue::Bool(false)),
            (
                "message".into(),
                s(format!(
                    "No Atomic Red Team tests found for technique {technique_id}"
                )),
            ),
            ("technique_id".into(), s(clean)),
            ("markdown_content".into(), PyValue::None),
        ]),
        Some(markdown) => PyValue::Dict(vec![
            ("success".into(), PyValue::Bool(true)),
            (
                "message".into(),
                s(format!(
                    "Atomic Red Team tests retrieved for technique {technique_id}"
                )),
            ),
            ("technique_id".into(), s(clean)),
            ("markdown_content".into(), s(markdown)),
        ]),
    };
    Ok(model_response(&out))
}

/// `Optional[int] = Query(None)`.
fn opt_int_query(v: &mut Validator, q: &QueryPairs, name: &str) -> Option<i128> {
    let raw = q.get(name)?;
    let parsed = pyd_int(raw);
    if parsed.is_none() {
        v.push(
            "int_parsing",
            loc("query", name),
            "Input should be a valid integer, unable to parse string as an integer",
        );
    }
    parsed
}

/// `mitre_field`'s pattern.
const MITRE_FIELD_PATTERN: &str = "^[A-Za-z0-9_.]+$";
/// `technique_id`'s pattern.
const TECHNIQUE_ID_PATTERN: &str = r"^T?[0-9]{4}(\.[0-9]{3})?$";

/// `^[A-Za-z0-9_.]+$`.
fn is_field_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}

/// `^T?[0-9]{4}(\.[0-9]{3})?$`.
fn is_technique_id(s: &str) -> bool {
    let rest = s.strip_prefix('T').unwrap_or(s);
    let digits = |t: &str, n: usize| t.len() == n && t.bytes().all(|b| b.is_ascii_digit());
    match rest.split_once('.') {
        None => digits(rest, 4),
        Some((main, sub)) => digits(main, 4) && digits(sub, 3),
    }
}

/// `Optional[str] = Query(None, pattern=…)`.
fn mitre_field_query(v: &mut Validator, q: &QueryPairs) -> Option<String> {
    let raw = q.get("mitre_field")?;
    if !is_field_name(raw) {
        v.push(
            "string_pattern_mismatch",
            loc("query", "mitre_field"),
            format!("String should match pattern '{MITRE_FIELD_PATTERN}'"),
        );
        return None;
    }
    Some(raw.to_string())
}

/// The query both searches read, validated in declaration order, and the
/// route's `additional_filters` (`alert_id` only for the second).
fn search_query(v: &mut Validator, q: &QueryPairs, with_alert_id: bool) -> (Search, i128, i128) {
    let time_range = q.get("time_range").unwrap_or("now-24h").to_string();
    let size = int_query(v, q, "size", 25, None);
    let page = int_query(v, q, "page", 1, Some(0));
    let rule_level = opt_int_query(v, q, "rule_level");
    let rule_group = q.get("rule_group").map(str::to_string);
    let mitre_field = mitre_field_query(v, q);
    let index_pattern = q.get("index_pattern").unwrap_or("wazuh-*").to_string();
    let alert_id = if with_alert_id {
        q.get("alert_id").map(str::to_string)
    } else {
        None
    };
    let phrase = |field: &str, text: String| {
        py::dict(vec![(
            "match_phrase",
            py::dict(vec![(field, py::dict(vec![("query", py::s(text))]))]),
        )])
    };
    let mut filters = Vec::new();
    if let Some(level) = rule_level {
        filters.push(phrase("rule_level", level.to_string()));
    }
    if let Some(group) = rule_group {
        filters.push(phrase("rule_groups", group));
    }
    if let Some(id) = alert_id {
        filters.push(py::dict(vec![("term", py::dict(vec![("id", py::s(id))]))]));
    }
    let size_big = BigInt::from(size);
    let offset = (BigInt::from(page) - BigInt::from(1)) * &size_big;
    (
        Search {
            time_range,
            size: size_big,
            offset,
            filters,
            index_pattern,
            mitre_field,
        },
        size,
        page,
    )
}

/// A validated response model as FastAPI writes it.
fn json_answer(model: &'static pyd::Model, value: &Value) -> Res {
    let dump = pyd::build(model, value).map_err(PyExc::unhandled)?;
    let text = dump
        .to_pydantic_json()
        .map_err(|e| ApiError::internal(format!("PydanticSerializationError: {e}")))?;
    Ok((
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "application/json")],
        text,
    )
        .into_response())
}

/// `GET /mitre/techniques/alerts`.
async fn techniques_in_alerts(
    auth: Authorized<AdminOrAnalyst>,
    State(st): State<RulesState>,
    q: QueryPairs,
) -> Res {
    let mut v = Validator::new();
    let (search, size, page) = search_query(&mut v, &q, false);
    v.finish()?;
    tracing::info!(
        "Searching for MITRE techniques in alerts from {} (page {page}, size {size})",
        search.time_range
    );
    let scope = auth.access(&st.wazuh.ctx).await?.clone();
    let tenant = mitre::tenant(&st.wazuh, &scope).await?;
    let found = mitre::techniques_in_alerts(&st.wazuh, &search, &tenant)
        .await
        .map_err(PyExc::unhandled)?;
    let total = py::as_bigint(&found.total_count).unwrap_or_default();
    let size_big = BigInt::from(size);
    let total_pages = if total > BigInt::from(0) {
        mitre::floor_div(&(&total + &size_big - BigInt::from(1)), &size_big)
            .map_err(PyExc::unhandled)?
    } else {
        BigInt::from(1)
    };
    let message = format!(
        "Found {total} MITRE techniques in {} alerts (page {page} of {total_pages},)",
        found.total_alerts.py_str()
    );
    let response = py::dict(vec![
        ("success", Value::Bool(true)),
        ("message", py::s(message)),
        ("total_alerts", found.total_alerts),
        ("techniques_count", Value::Int(total)),
        ("techniques", py::list(found.techniques)),
        ("time_range", py::s(search.time_range.clone())),
        ("field_used", py::opt_str(found.field_used)),
        ("page", big(page)),
        ("page_size", big(size)),
        ("total_pages", Value::Int(total_pages)),
    ]);
    json_answer(
        &schema::mitre_alerts::MITRE_TECHNIQUES_IN_ALERTS_RESPONSE,
        &response,
    )
}

/// `GET /mitre/techniques/{technique_id}/alerts`.
async fn technique_alerts(
    auth: Authorized<AdminOrAnalyst>,
    State(st): State<RulesState>,
    Path(technique_id): Path<String>,
    q: QueryPairs,
) -> Res {
    let mut v = Validator::new();
    if !is_technique_id(&technique_id) {
        v.push(
            "string_pattern_mismatch",
            loc("path", "technique_id"),
            format!("String should match pattern '{TECHNIQUE_ID_PATTERN}'"),
        );
    }
    let (search, size, page) = search_query(&mut v, &q, true);
    v.finish()?;
    tracing::info!(
        "Request for alerts related to MITRE technique {technique_id} from {} (page {page}, \
         size {size})",
        search.time_range
    );
    let clean = py::py_strip(&technique_id).to_string();
    let scope = auth.access(&st.wazuh.ctx).await?.clone();
    let tenant = mitre::tenant(&st.wazuh, &scope).await?;
    let found = mitre::alerts_for_technique(&st.wazuh, &search, &clean, &tenant)
        .await
        .map_err(PyExc::unhandled)?;
    let size_big = BigInt::from(size);
    let pages = mitre::pages_of(&found.total_alerts, &size_big).map_err(PyExc::unhandled)?;
    let message = format!(
        "Found {} alerts for MITRE technique {clean} (page {page} of {},)",
        found.total_alerts.py_str(),
        pages.py_str()
    );
    let response = py::dict(vec![
        ("success", Value::Bool(true)),
        ("message", py::s(message)),
        ("technique_id", py::s(clean)),
        ("technique_name", py::s(found.technique_name)),
        ("total_alerts", found.total_alerts),
        ("alerts", py::list(found.alerts)),
        ("field_used", py::opt_str(found.field_used)),
        ("time_range", py::s(search.time_range.clone())),
        ("page", big(page)),
        ("page_size", big(size)),
        ("total_pages", pages),
    ]);
    json_answer(
        &schema::mitre_alerts::MITRE_TECHNIQUE_ALERTS_RESPONSE,
        &response,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_arithmetic() {
        assert_eq!(floor_div(7, -3), -3);
        assert_eq!(floor_div(-7, 3), -3);
        assert_eq!(floor_div(6, 3), 2);
        assert_eq!(slice_bound(-2, 5), 3);
        assert_eq!(slice_bound(-9, 5), 0);
        assert_eq!(slice_bound(9, 5), 5);
        assert_eq!(pyd_int(" 1_0 "), Some(10));
        assert_eq!(pyd_int("1.00"), Some(1));
        assert_eq!(pyd_int("1.5"), None);
        assert_eq!(pyd_int("_1"), None);
    }

    #[test]
    fn the_route_patterns() {
        for (id, ok) in [
            ("T1047", true),
            ("1047", true),
            ("T1003.004", true),
            ("T1003.04", false),
            ("TT1047", false),
            ("T104", false),
            ("T1047\n", false),
            ("T1047.", false),
            ("t1047", false),
        ] {
            assert_eq!(is_technique_id(id), ok, "{id}");
        }
        assert!(is_field_name("rule.mitre.id"));
        assert!(!is_field_name(""));
        assert!(!is_field_name("rule mitre"));
        assert!(!is_field_name("rule'].value"));
    }
}
