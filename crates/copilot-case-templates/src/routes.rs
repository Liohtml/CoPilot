//! The library and suggestion routes of `app/incidents/routes/case_templates.py`
//! (the router's `require_any_scope("admin", "analyst")`), merged by the
//! binary into `copilot-incidents`' `/api/incidents/case_templates` router.
//!
//! | Route | Here |
//! |---|---|
//! | `GET /library` | the sorted entries, or `success: false` with `str(e)` |
//! | `POST /library/refresh` | the forced refresh, or `success: false` with `str(e)` |
//! | `GET /library/{key}` (and `GET /library/refresh`, which Starlette routes there) | the entry, a 404, or what the load raised |
//! | `POST /library/{key}/import` | 404, 409 on the name, then `create_template` |
//! | `GET /suggest` | the ranked templates (`crate::suggest`) |

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::NaiveDateTime;
use serde_json::Value as JsonValue;

use copilot_auth::AccessScope;
use copilot_core::time::to_pydantic_iso;
use copilot_web::validate::{Validator, loc};
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized, QueryPairs};

use crate::CaseTemplatesState;
use crate::library::{Entry, entry_response, import_payload};
use crate::suggest::{self, DEFAULT_SUGGESTION_LIMIT};

type Soc = Authorized<AdminOrAnalyst>;

/// The routes, relative to `/api/incidents/case_templates`.
pub fn router(state: CaseTemplatesState) -> Router {
    Router::new()
        .route("/library", get(list))
        .route("/library/refresh", post(refresh).get(get_refresh))
        .route("/library/{key}", get(get_entry))
        .route("/library/{key}/import", post(import))
        .route("/suggest", get(suggest_route))
        .with_state(state)
}

/// A body the routes build from model dumps (`to_pydantic_json`), kept as
/// text so that YAML values (big integers, dates) are written as Pydantic
/// writes them.
fn raw_json(body: String) -> Response {
    ([(http::header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn text(t: &str) -> String {
    serde_json::to_string(t).unwrap_or_else(|_| "\"\"".into())
}

fn when(t: Option<NaiveDateTime>) -> String {
    t.map_or_else(|| "null".into(), |t| text(&to_pydantic_iso(t)))
}

fn strings(items: &[String]) -> String {
    serde_json::to_string(items).unwrap_or_else(|_| "[]".into())
}

fn dump(v: &copilot_yaml::Value) -> Result<String, ApiError> {
    v.to_pydantic_json()
        .map_err(|e| ApiError::internal(format!("PydanticSerializationError: {e:?}")))
}

/// `CaseTemplateLibraryListResponse`.
fn list_body(
    entries: &[String],
    invalid: &[String],
    last: Option<NaiveDateTime>,
    success: bool,
    message: &str,
) -> Response {
    raw_json(format!(
        "{{\"entries\":[{}],\"invalid_paths\":{},\"last_refresh\":{},\"success\":{success},\"message\":{}}}",
        entries.join(","),
        strings(invalid),
        when(last),
        text(message)
    ))
}

/// `GET /library`: every exception is the answer's `message`.
async fn list(_auth: Soc, State(st): State<CaseTemplatesState>) -> ApiResult {
    let library = &st.library;
    let failure = |e: String| {
        list_body(
            &[],
            &[],
            library.last_refresh(),
            false,
            &format!("Failed to load case-template library: {e}"),
        )
    };
    if let Err(e) = library.ensure_loaded().await {
        return Ok(failure(e.display()));
    }
    let entries = library.sorted_entries();
    let mut dumps = Vec::with_capacity(entries.len());
    for e in &entries {
        match entry_response(e) {
            Ok(d) => dumps.push(dump(&d)?),
            Err(invalid) => return Ok(failure(invalid.text())),
        }
    }
    Ok(list_body(
        &dumps,
        &library.invalid_paths(),
        library.last_refresh(),
        true,
        &format!("Retrieved {} library entr(ies)", entries.len()),
    ))
}

/// `POST /library/refresh`.
async fn refresh(_auth: Soc, State(st): State<CaseTemplatesState>) -> ApiResult {
    let library = &st.library;
    let (loaded, invalid, success, message) = match library.refresh().await {
        Ok(n) => {
            let invalid = library.invalid_paths();
            let message = format!(
                "Library refreshed: {n} entr(ies) loaded, {} skipped",
                invalid.len()
            );
            (n, invalid, true, message)
        }
        Err(e) => (
            0,
            Vec::new(),
            false,
            format!("Failed to refresh case-template library: {}", e.display()),
        ),
    };
    Ok(raw_json(format!(
        "{{\"loaded\":{loaded},\"invalid_paths\":{},\"last_refresh\":{},\"success\":{success},\"message\":{}}}",
        strings(&invalid),
        when(library.last_refresh()),
        text(&message)
    )))
}

fn not_found(key: &str) -> ApiError {
    ApiError::not_found(format!(
        "Library entry '{key}' not found. Try POST /library/refresh if you just pushed it."
    ))
}

/// `get_library_entry(key)`: what loading raised leaves the route
/// (`ValueError`s are the handler's 400, the rest uvicorn's bare 500).
async fn lookup(st: &CaseTemplatesState, key: &str) -> Result<Entry, ApiError> {
    st.library.ensure_loaded().await.map_err(ApiError::from)?;
    st.library.entry(key).ok_or_else(|| not_found(key))
}

async fn entry_answer(st: &CaseTemplatesState, key: &str) -> ApiResult {
    let entry = lookup(st, key).await?;
    // Outside any `try`: the `ValidationError` is the handler's 400.
    let response = entry_response(&entry).map_err(|e| ApiError::bad_request(e.text()))?;
    Ok(raw_json(format!(
        "{{\"entry\":{},\"success\":true,\"message\":{}}}",
        dump(&response)?,
        text(&format!("Retrieved library entry '{key}'"))
    )))
}

/// `GET /library/{key}`.
async fn get_entry(
    _auth: Soc,
    State(st): State<CaseTemplatesState>,
    Path(key): Path<String>,
) -> ApiResult {
    entry_answer(&st, &key).await
}

/// `GET /library/refresh`: Starlette routes it to `/library/{key}`.
async fn get_refresh(_auth: Soc, State(st): State<CaseTemplatesState>) -> ApiResult {
    entry_answer(&st, "refresh").await
}

/// `POST /library/{key}/import`: a global template, never a default.
async fn import(
    auth: Soc,
    State(st): State<CaseTemplatesState>,
    Path(key): Path<String>,
) -> ApiResult {
    let entry = lookup(&st, &key).await?;
    let taken: Option<i32> = sqlx::query_scalar(
        "SELECT incident_management_case_template.id FROM incident_management_case_template \
         WHERE incident_management_case_template.name = ? LIMIT 1",
    )
    .bind(&entry.name)
    .persistent(false)
    .fetch_optional(st.ctx.db.pool())
    .await
    .map_err(ApiError::internal)?;
    if taken.is_some() {
        return Err(ApiError::http(
            http::StatusCode::CONFLICT,
            format!(
                "A case template named '{}' already exists. Rename or delete the existing \
                 template before re-importing this entry.",
                entry.name
            ),
        ));
    }
    let payload = import_payload(&entry).map_err(|e| ApiError::bad_request(e.text()))?;
    copilot_incidents::case_templates::create_template(&st.ctx, &auth.username, &payload).await
}

/// Pydantic's `str` → `int` (trimmed, a sign, single `_` between digits, a
/// fraction of zeros), as the decimal text of the value (`int` has no bound).
fn pyd_int_text(raw: &str) -> Option<String> {
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
    let plain: String = digits.chars().filter(|c| *c != '_').collect();
    let trimmed = plain.trim_start_matches('0');
    let magnitude = if trimmed.is_empty() { "0" } else { trimmed };
    Some(if negative && magnitude != "0" {
        format!("-{magnitude}")
    } else {
        magnitude.to_string()
    })
}

fn int_error(v: &mut Validator, name: &str) {
    v.push(
        "int_parsing",
        loc("query", name),
        "Input should be a valid integer, unable to parse string as an integer",
    );
}

/// `GET /suggest?alert_id=&customer_code=&source=&limit=`.
async fn suggest_route(
    auth: Soc,
    State(st): State<CaseTemplatesState>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let alert_id = match q.get("alert_id") {
        None => None,
        Some(raw) => {
            let parsed = pyd_int_text(raw);
            if parsed.is_none() {
                int_error(&mut v, "alert_id");
            }
            parsed
        }
    };
    let customer_code = q.get("customer_code").map(str::to_string);
    let source = q.get("source").map(str::to_string);
    let mut limit = DEFAULT_SUGGESTION_LIMIT;
    if let Some(raw) = q.get("limit") {
        match pyd_int_text(raw) {
            None => int_error(&mut v, "limit"),
            Some(n) => {
                let big = n.parse::<i128>().unwrap_or(if n.starts_with('-') {
                    i128::MIN
                } else {
                    i128::MAX
                });
                if big > 50 {
                    v.push(
                        "less_than_equal",
                        loc("query", "limit"),
                        "Input should be less than or equal to 50",
                    );
                } else if big < 1 {
                    v.push(
                        "greater_than_equal",
                        loc("query", "limit"),
                        "Input should be greater than or equal to 1",
                    );
                } else {
                    limit = i64::try_from(big).unwrap_or(DEFAULT_SUGGESTION_LIMIT);
                }
            }
        }
    }
    v.finish()?;
    let scope = auth.access(&st.ctx).await?.clone();
    // A customer named for the manual path is the caller's (Python checked
    // none); with an alert, the alert's customer is used and checked.
    if alert_id.is_none() {
        if let Some(code) = customer_code.as_deref().filter(|c| !c.is_empty()) {
            if !matches!(scope, AccessScope::All) && !scope.can_access(code) {
                return Err(ApiError::forbidden(format!(
                    "Access denied to customer {code} - insufficient customer permissions"
                )));
            }
        }
    }
    let answer: JsonValue = suggest::suggest(
        &st.ctx,
        &st.es,
        &auth,
        &scope,
        suggest::Request {
            alert_id,
            customer_code,
            source,
            limit,
        },
    )
    .await;
    Ok(Json(answer).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_ints_are_pydantic_s() {
        assert_eq!(pyd_int_text(" 12 ").as_deref(), Some("12"));
        assert_eq!(pyd_int_text("1_0").as_deref(), Some("10"));
        assert_eq!(pyd_int_text("+007").as_deref(), Some("7"));
        assert_eq!(pyd_int_text("-0").as_deref(), Some("0"));
        assert_eq!(pyd_int_text("3.00").as_deref(), Some("3"));
        assert_eq!(
            pyd_int_text("99999999999999999999999").as_deref(),
            Some("99999999999999999999999")
        );
        for bad in ["", "1.5", "_1", "1__0", "1_", "x", "1.", "0x10"] {
            assert_eq!(pyd_int_text(bad), None, "{bad:?}");
        }
    }
}
