//! `/api/wazuh_manager` (`app/routers/wazuh_manager.py`), the routes kept
//! in Rust:
//!
//! | Route | Guard |
//! |---|---|
//! | `GET /rules`, `/rules/files`, `/rules/files/{filename}`, `PUT /rules/files/{filename}` | `get_current_user(scopes=["admin"])` |
//! | `GET /groups`, `/groups/{group_id}/files`, `/groups/{group_id}/files/{filename}`, `PUT /groups/{group_id}/configuration` | admin |
//! | `GET /mitre/{groups,mitigations,references,software,tactics,techniques}` | admin/analyst (`require_any_scope`) |
//! | `POST /management/restart` | admin |
//!
//! Not routed here, so served by the Python backend: `/rule/disabled`,
//! `/rule/disable`, `/rule/enable` (their `disabledrule` table is not in the
//! Alembic schema: every call is a 500 there), `/rule/exclude` (a fixed
//! `copilot-ai-module` host), `/mitre/atomic-tests`,
//! `/mitre/techniques/{id}/atomic-tests` (GitHub with in-process caches) and
//! the two MITRE alert searches (`/mitre/techniques/alerts`,
//! `/mitre/techniques/{id}/alerts`).

use axum::Router;
use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Path, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Map, Value};

use copilot_web::form::{FormError, FormValue, UploadPart, read_form_files};
use copilot_web::validate::{IntRules, LocPart, Validator, loc};
use copilot_web::{
    AdminOnly, AdminOrAnalyst, ApiError, ApiResult, Authorized, QueryPairs, ScopedUser,
};

use crate::WazuhState;
use crate::error::PyErr;
use crate::manager::client::{Param, restart_wazuh_manager_service};
use crate::manager::services::{self as svc, MitreList, clean, lists};

type Admin = ScopedUser<AdminOnly>;
type Analyst = Authorized<AdminOrAnalyst>;

const HASH_PATTERN: &str =
    "^(md5|sha1|sha224|sha256|sha384|sha512|blake2b|blake2s|sha3_224|sha3_256|sha3_384|sha3_512)$";
const HASHES: &[&str] = &[
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s", "sha3_224",
    "sha3_256", "sha3_384", "sha3_512",
];

/// `/api/wazuh_manager`.
pub fn router(state: WazuhState) -> Router {
    Router::new()
        .route("/rules", get(list_rules))
        .route("/rules/files", get(list_rule_files))
        .route(
            "/rules/files/{filename}",
            get(rule_file_content).put(upload_rule_file),
        )
        .route("/groups", get(list_groups))
        .route("/groups/{group_id}/files", get(group_files))
        .route("/groups/{group_id}/files/{filename}", get(group_file))
        .route(
            "/groups/{group_id}/configuration",
            axum::routing::put(group_configuration),
        )
        .route("/mitre/groups", get(mitre_groups))
        .route("/mitre/mitigations", get(mitre_mitigations))
        .route("/mitre/references", get(mitre_references))
        .route("/mitre/software", get(mitre_software))
        .route("/mitre/tactics", get(mitre_tactics))
        .route("/mitre/techniques", get(mitre_techniques))
        .route("/management/restart", post(restart))
        .with_state(state)
}

fn answer(result: Result<Value, PyErr>) -> ApiResult {
    match result {
        Ok(v) => Ok(axum::Json(v).into_response()),
        Err(e) => Err(e.into()),
    }
}

/// FastAPI's query parameters, validated in declaration order.
struct Query<'a> {
    q: &'a QueryPairs,
    v: Validator,
}

impl<'a> Query<'a> {
    fn new(q: &'a QueryPairs) -> Self {
        Self {
            q,
            v: Validator::new(),
        }
    }

    /// `Optional[bool] = Query(default)`.
    fn bool(&mut self, name: &str, default: bool) -> Option<Param> {
        let mut m = Map::new();
        if let Some(raw) = self.q.get(name) {
            m.insert(name.into(), Value::String(raw.into()));
        }
        Some(Param::Bool(self.v.bool_or(
            &m,
            &vec![LocPart::Key("query".into())],
            name,
            default,
        )))
    }

    /// `Optional[int] = Query(default, ge=…, le=…)`.
    fn int(&mut self, name: &str, default: Option<i64>, rules: IntRules) -> Option<Param> {
        match self.q.get(name) {
            None => default.map(Param::Int),
            Some(raw) => self
                .v
                .check_int(&loc("query", name), &Value::String(raw.into()), rules)
                .map(Param::Int),
        }
    }

    /// `Optional[str] = Query(None)`.
    fn str(&mut self, name: &str) -> Option<Param> {
        self.q.get(name).map(|s| Param::Str(s.to_string()))
    }

    /// `Optional[str] = Query(None, pattern=HASH_PATTERN)`.
    fn hash(&mut self) -> Option<Param> {
        let raw = self.q.get("hash")?;
        if HASHES.contains(&raw) {
            return Some(Param::Str(raw.to_string()));
        }
        self.v.push(
            "string_pattern_mismatch",
            loc("query", "hash"),
            format!("String should match pattern '{HASH_PATTERN}'"),
        );
        None
    }

    /// `Optional[List[str]] = Query(None)`, joined by commas.
    fn str_list(&mut self, name: &str) -> Option<Param> {
        let all = self.q.get_all(name);
        (!all.is_empty()).then(|| Param::Str(all.join(",")))
    }

    /// `Optional[List[int]] = Query(None)`, joined by commas.
    fn int_list(&mut self, name: &str) -> Option<Param> {
        let all = self.q.get_all(name);
        if all.is_empty() {
            return None;
        }
        let mut out = Vec::new();
        for (i, raw) in all.iter().enumerate() {
            let at = vec![
                LocPart::Key("query".into()),
                LocPart::Key(name.into()),
                LocPart::Index(i),
            ];
            if let Some(n) = self
                .v
                .check_int(&at, &Value::String(raw.clone()), IntRules::default())
            {
                out.push(n.to_string());
            }
        }
        Some(Param::Str(out.join(",")))
    }

    fn finish(self) -> Result<(), ApiError> {
        self.v.finish()
    }
}

const OFFSET: IntRules = IntRules {
    ge: Some(0),
    le: None,
};
const LIMIT: IntRules = IntRules {
    ge: Some(1),
    le: Some(100_000),
};

async fn list_rules(_a: Admin, State(st): State<WazuhState>, q: QueryPairs) -> ApiResult {
    let mut p = Query::new(&q);
    let params = vec![
        ("rule_ids", p.int_list("rule_ids")),
        ("pretty", p.bool("pretty", false)),
        ("wait_for_complete", p.bool("wait_for_complete", false)),
        ("offset", p.int("offset", Some(0), OFFSET)),
        ("limit", p.int("limit", Some(500), LIMIT)),
        ("select", p.str_list("select")),
        ("sort", p.str("sort")),
        ("search", p.str("search")),
        ("q", p.str("q")),
        ("status", p.str("status")),
        ("group", p.str("group")),
        ("level", p.str("level")),
        ("filename", p.str_list("filename")),
        ("relative_dirname", p.str("relative_dirname")),
        ("pci_dss", p.str("pci_dss")),
        ("gdpr", p.str("gdpr")),
        ("gpg13", p.str("gpg13")),
        ("hipaa", p.str("hipaa")),
        ("nist_800_53", p.str("nist_800_53")),
        ("tsc", p.str("tsc")),
        ("mitre", p.str("mitre")),
        ("distinct", p.bool("distinct", false)),
    ];
    p.finish()?;
    answer(svc::get_rules(&st, clean(params)).await)
}

async fn list_rule_files(_a: Admin, State(st): State<WazuhState>, q: QueryPairs) -> ApiResult {
    let mut p = Query::new(&q);
    let params = vec![
        ("pretty", p.bool("pretty", false)),
        ("wait_for_complete", p.bool("wait_for_complete", false)),
        ("offset", p.int("offset", Some(0), OFFSET)),
        ("limit", p.int("limit", Some(500), LIMIT)),
        ("sort", p.str("sort")),
        ("search", p.str("search")),
        ("relative_dirname", p.str("relative_dirname")),
        ("filename", p.str_list("filename")),
        ("status", p.str("status")),
        ("q", p.str("q")),
        ("select", p.str_list("select")),
        ("distinct", p.bool("distinct", false)),
    ];
    p.finish()?;
    answer(svc::get_rule_files(&st, clean(params)).await)
}

async fn rule_file_content(
    _a: Admin,
    State(st): State<WazuhState>,
    Path(filename): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut p = Query::new(&q);
    let params = vec![
        ("pretty", p.bool("pretty", false)),
        ("wait_for_complete", p.bool("wait_for_complete", false)),
        ("raw", p.bool("raw", true)),
        ("relative_dirname", p.str("relative_dirname")),
    ];
    p.finish()?;
    answer(svc::get_rule_file_content(&st, &filename, clean(params)).await)
}

/// `file: UploadFile = File(...)`: the form is read before the guard
/// (FastAPI's order: body errors first).
struct WithUpload<A>(A, Result<UploadPart, ApiError>);

impl<A, S> FromRequest<S> for WithUpload<A>
where
    A: FromRequestParts<S> + Send,
    A::Rejection: IntoResponse,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Response> {
        let ct = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let (mut parts, body) = req.into_parts();
        let guard = A::from_request_parts(&mut parts, state)
            .await
            .map_err(IntoResponse::into_response);
        let raw = Bytes::from_request(Request::from_parts(parts, body), state)
            .await
            .map_err(IntoResponse::into_response)?;
        let (form, uploads) = read_form_files(ct.as_deref(), &raw).map_err(|e| {
            let detail = match e {
                FormError::Rejected(message) => message,
                FormError::Malformed => "There was an error parsing the body".to_string(),
            };
            ApiError::detail(http::StatusCode::BAD_REQUEST, detail).into_response()
        })?;
        let guard = guard?;
        let file = match form.get("file") {
            Some(FormValue::File { .. }) => uploads
                .into_iter()
                .rev()
                .find(|u| u.field == "file")
                .ok_or_else(missing_file),
            Some(FormValue::Text(t)) if t.is_empty() => Err(missing_file()),
            Some(FormValue::Text(_)) => {
                let mut v = Validator::new();
                v.push(
                    "value_error",
                    vec![LocPart::Key("body".into()), LocPart::Key("file".into())],
                    "Value error, Expected UploadFile, received: <class 'str'>",
                );
                Err(v.finish().err().unwrap_or(ApiError::RouteNotFound))
            }
            None => Err(missing_file()),
        };
        Ok(Self(guard, file))
    }
}

fn missing_file() -> ApiError {
    let mut v = Validator::new();
    v.missing(vec![
        LocPart::Key("body".into()),
        LocPart::Key("file".into()),
    ]);
    v.finish().err().unwrap_or(ApiError::RouteNotFound)
}

async fn upload_rule_file(
    State(st): State<WazuhState>,
    Path(filename): Path<String>,
    q: QueryPairs,
    WithUpload(_a, file): WithUpload<Admin>,
) -> ApiResult {
    let mut p = Query::new(&q);
    let pretty = p.bool("pretty", false);
    let wait = p.bool("wait_for_complete", false);
    let overwrite = p.bool("overwrite", true);
    let relative_dirname = p.str("relative_dirname");
    let file = match (p.finish(), file) {
        (Ok(()), Ok(f)) => f,
        (Err(ApiError::Validation(mut q_items)), Err(ApiError::Validation(b_items))) => {
            q_items.extend(b_items);
            return Err(ApiError::Validation(q_items));
        }
        (Err(e), _) | (Ok(()), Err(e)) => return Err(e),
    };
    if let Some(ct) = file.content_type.as_deref() {
        let lower = ct.to_lowercase();
        if !["xml", "text", "octet-stream", "application/xml"]
            .iter()
            .any(|t| lower.contains(t))
        {
            tracing::warn!("Unexpected content type: {ct}");
        }
    }
    let result: Result<Value, PyErr> = async {
        if file.data.is_empty() {
            return Err(PyErr::http(400, "File content is empty"));
        }
        tracing::info!(
            "Received file upload: {filename}, size: {} bytes",
            file.data.len()
        );
        // `str(pretty).lower()` and friends.
        let lowered = |p: Option<Param>| match p {
            Some(Param::Bool(b)) => Some(Param::Str(if b { "true" } else { "false" }.into())),
            other => other,
        };
        let params = clean(vec![
            ("pretty", lowered(pretty)),
            ("wait_for_complete", lowered(wait)),
            ("overwrite", lowered(overwrite)),
            ("relative_dirname", relative_dirname),
        ]);
        svc::update_rule_file(&st, &filename, file.data, params).await
    }
    .await;
    answer(result.map_err(|e| {
        tracing::error!(
            "Error processing file upload for {filename}: {}",
            e.py_str()
        );
        PyErr::server(format!("Error processing file upload: {}", e.py_str()))
    }))
}

fn group_query(p: &mut Query<'_>) -> Vec<(&'static str, Option<Param>)> {
    vec![
        ("pretty", p.bool("pretty", false)),
        ("wait_for_complete", p.bool("wait_for_complete", false)),
    ]
}

async fn list_groups(_a: Admin, State(st): State<WazuhState>, q: QueryPairs) -> ApiResult {
    let mut p = Query::new(&q);
    let mut params = group_query(&mut p);
    params.extend([
        ("groups_list", p.str_list("groups_list")),
        ("offset", p.int("offset", Some(0), OFFSET)),
        ("limit", p.int("limit", Some(500), LIMIT)),
        ("sort", p.str("sort")),
        ("search", p.str("search")),
        ("hash", p.hash()),
        ("q", p.str("q")),
        ("select", p.str_list("select")),
        ("distinct", p.bool("distinct", false)),
    ]);
    p.finish()?;
    answer(svc::get_groups(&st, clean(params)).await)
}

async fn group_files(
    _a: Admin,
    State(st): State<WazuhState>,
    Path(group_id): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut p = Query::new(&q);
    let mut params = group_query(&mut p);
    params.extend([
        ("offset", p.int("offset", Some(0), OFFSET)),
        ("limit", p.int("limit", Some(500), LIMIT)),
        ("sort", p.str("sort")),
        ("search", p.str("search")),
        ("hash", p.hash()),
        ("q", p.str("q")),
        ("select", p.str_list("select")),
        ("distinct", p.bool("distinct", false)),
    ]);
    p.finish()?;
    answer(svc::get_group_files(&st, &group_id, clean(params)).await)
}

async fn group_file(
    _a: Admin,
    State(st): State<WazuhState>,
    Path((group_id, filename)): Path<(String, String)>,
    q: QueryPairs,
) -> ApiResult {
    let mut p = Query::new(&q);
    let mut params = group_query(&mut p);
    // `type: Optional[List[str]] = Query(None, pattern=…)`: Pydantic cannot
    // apply a pattern to a list, so any `type` is an uncaught `TypeError`.
    if !q.get_all("type").is_empty() {
        return Err(ApiError::internal(
            "TypeError: Unable to apply constraint 'pattern' to supplied value",
        ));
    }
    params.push(("raw", p.bool("raw", true)));
    p.finish()?;
    answer(svc::get_group_file(&st, &group_id, &filename, clean(params)).await)
}

async fn group_configuration(
    _a: Admin,
    State(st): State<WazuhState>,
    Path(group_id): Path<String>,
    q: QueryPairs,
    body: Bytes,
) -> ApiResult {
    let mut p = Query::new(&q);
    let params = group_query(&mut p);
    p.finish()?;
    // `UnicodeDecodeError` is a `ValueError`: the backend's 400 handler.
    if let Some(e) = crate::pyops::utf8_decode_error(&body) {
        return Err(PyErr::Value(e).into());
    }
    let configuration = String::from_utf8_lossy(&body);
    answer(svc::update_group_configuration(&st, &group_id, &configuration, clean(params)).await)
}

/// `limit, offset, sort, search, q` then `select` (appended when given).
fn mitre_params(q: &QueryPairs, with_select: bool) -> Result<Vec<(String, Param)>, ApiError> {
    let mut p = Query::new(q);
    let limit = p.int("limit", None, IntRules::default());
    let offset = p.int("offset", None, IntRules::default());
    let select = if with_select {
        p.str_list("select")
    } else {
        None
    };
    let sort = p.str("sort");
    let search = p.str("search");
    let query = p.str("q");
    p.finish()?;
    let mut params = vec![
        ("limit", limit),
        ("offset", offset),
        ("sort", sort),
        ("search", search),
        ("q", query),
    ];
    if with_select {
        // `if select: params["select"] = ",".join(select)`.
        params.push(("select", select));
    }
    Ok(clean(params))
}

async fn mitre(st: &WazuhState, q: &QueryPairs, list: MitreList, with_select: bool) -> ApiResult {
    let params = mitre_params(q, with_select)?;
    answer(svc::get_mitre(st, list, params).await)
}

async fn mitre_groups(_a: Analyst, State(st): State<WazuhState>, q: QueryPairs) -> ApiResult {
    mitre(&st, &q, lists::GROUPS, true).await
}

async fn mitre_mitigations(_a: Analyst, State(st): State<WazuhState>, q: QueryPairs) -> ApiResult {
    mitre(&st, &q, lists::MITIGATIONS, true).await
}

async fn mitre_references(_a: Analyst, State(st): State<WazuhState>, q: QueryPairs) -> ApiResult {
    mitre(&st, &q, lists::REFERENCES, false).await
}

async fn mitre_software(_a: Analyst, State(st): State<WazuhState>, q: QueryPairs) -> ApiResult {
    mitre(&st, &q, lists::SOFTWARE, true).await
}

async fn mitre_tactics(_a: Analyst, State(st): State<WazuhState>, q: QueryPairs) -> ApiResult {
    mitre(&st, &q, lists::TACTICS, true).await
}

async fn mitre_techniques(_a: Analyst, State(st): State<WazuhState>, q: QueryPairs) -> ApiResult {
    mitre(&st, &q, lists::TECHNIQUES, true).await
}

async fn restart(_a: Admin, State(st): State<WazuhState>) -> ApiResult {
    tracing::info!("Restarting Wazuh Manager service.");
    answer(restart_wazuh_manager_service(&st).await)
}
