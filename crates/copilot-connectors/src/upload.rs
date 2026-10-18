//! `POST /api/connectors/upload/{connector_identifier}` (`upload_yaml_file`,
//! `ConnectorServices.save_file`): a connector's YAML file (Velociraptor's
//! `api.config.yaml`) written to the Python backend's data directory, its
//! path recorded as the connector's `connector_api_key`, then the connector
//! verified.
//!
//! In Python's order, after FastAPI's (the form, the token, the `file`
//! field):
//! - the identifier as `int()` reads it: an id must be 5 or 6 (400); any
//!   other text is a connector name, and every way that name fails — no row,
//!   several, a connector other than 5 or 6 — is the 404 `Could not find
//!   connector with name: …` (Python's `except Exception` re-wraps its own
//!   404 and 400);
//! - the file name must end in `.yaml` (400);
//! - the file goes to `{COPILOT_BACKEND_DATA_DIR}/{secure_filename(name)}`
//!   (werkzeug 3.1's), the row gets `connector_configured` and the path,
//!   this process's cached row is dropped after the commit, then the
//!   connector is verified (its answer unread, as Python ignores
//!   `verify_connector_by_id`'s); any failure of the write is the 500
//!   `Failed to upload file`.
//!
//! The Rust container mounts the backend's data directory at the path
//! Python uses (`docker-compose.rust.yml`), so the file is where Python —
//! and the Velociraptor client — reads it. A directory this process may not
//! write (its permissions, a read-only mount) fails the write as it fails
//! Python's: the 500 `Failed to upload file`, nothing written.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Path, Request, State};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use unicode_normalization::UnicodeNormalization;

use copilot_web::form::{FormError, FormValue, UploadPart, read_form_files};
use copilot_web::validate::{LocPart, Validator};
use copilot_web::{AdminOnly, ApiError, ApiResult, ScopedUser};

use crate::ConnectorsState;
use crate::verify::PYTHON_VERIFIED;

/// The connector ids that take a YAML upload.
pub const YAML_CONNECTOR_IDS: [i64; 2] = [5, 6];

/// `file: UploadFile = File(...)` beside the guard, read in FastAPI's order
/// (the form's errors first).
pub struct WithUpload<A>(pub A, pub Result<UploadPart, ApiError>);

fn missing_file() -> ApiError {
    let mut v = Validator::new();
    v.missing(vec![
        LocPart::Key("body".into()),
        LocPart::Key("file".into()),
    ]);
    v.finish().err().unwrap_or(ApiError::RouteNotFound)
}

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

/// `int(text)` (base 10) as CPython reads a `str`: `None` for a
/// `ValueError`; a value beyond 64 bits saturates (it is not 5 or 6).
pub fn py_int(text: &str) -> Option<i64> {
    let ascii: String = text
        .chars()
        .map(|c| {
            if c.is_ascii() {
                c
            } else if copilot_jinja::unicode::is_space(c) {
                ' '
            } else if let Some(d) = copilot_jinja::unicode::decimal_value(c) {
                char::from_digit(d, 10).unwrap_or('?')
            } else {
                '?'
            }
        })
        .collect();
    let t = ascii.trim_matches(|c: char| c == ' ' || ('\t'..='\r').contains(&c));
    let (negative, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
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
    let clean = digits.replace('_', "");
    if clean.len() > 4300 {
        // `int()`'s digit limit is a `ValueError` too.
        return None;
    }
    let value = clean.bytes().fold(0i64, |acc, b| {
        acc.saturating_mul(10).saturating_add(i64::from(b - b'0'))
    });
    Some(if negative { -value } else { value })
}

/// `str.isspace()` for an ASCII character (`\x1c`–`\x1f` included).
fn ascii_space(c: char) -> bool {
    matches!(
        c,
        ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r' | '\x1c'..='\x1f'
    )
}

/// werkzeug 3.1's `secure_filename` (on POSIX).
pub fn secure_filename(filename: &str) -> String {
    let ascii: String = filename.nfkd().filter(char::is_ascii).collect();
    let spaced = ascii.replace('/', " ");
    let joined = spaced
        .split(ascii_space)
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    let kept: String = joined
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        .collect();
    kept.trim_matches(|c| c == '.' || c == '_').to_string()
}

fn could_not_find(name: &str) -> ApiError {
    ApiError::not_found(format!("Could not find connector with name: {name}"))
}

fn failed() -> ApiError {
    ApiError::http(
        http::StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to upload file",
    )
}

/// The connector the identifier names.
async fn resolve(st: &ConnectorsState, identifier: &str) -> Result<i64, ApiError> {
    if let Some(id) = py_int(identifier) {
        if !YAML_CONNECTOR_IDS.contains(&id) {
            return Err(ApiError::bad_request(
                "Only the Velociraptor or another specific connector is allowed for YAML file \
                 uploads.",
            ));
        }
        return Ok(id);
    }
    tracing::info!("Using connector name: {identifier}");
    // `scalar_one_or_none()`: several rows raise, and that is caught too.
    let ids: Vec<i32> = sqlx::query_scalar(
        "SELECT connectors.id FROM connectors WHERE connectors.connector_name = ?",
    )
    .bind(identifier)
    .persistent(false)
    .fetch_all(st.ctx.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Error fetching connector by name '{identifier}': {e}");
        could_not_find(identifier)
    })?;
    match ids.as_slice() {
        [id] if YAML_CONNECTOR_IDS.contains(&i64::from(*id)) => Ok(i64::from(*id)),
        _ => Err(could_not_find(identifier)),
    }
}

/// `save_file`: the file written, then the row. `Ok(None)`: no row has the
/// id (Python's `False`).
async fn save(
    st: &ConnectorsState,
    id: i64,
    filename: &str,
    data: &[u8],
) -> Result<Option<String>, String> {
    let path = st.data_dir.join(secure_filename(filename));
    let path_text = path.to_string_lossy().into_owned();
    tokio::fs::write(&path, data)
        .await
        .map_err(|e| e.to_string())?;
    let row: Option<(String,)> =
        sqlx::query_as("SELECT connector_name FROM connectors WHERE connectors.id = ?")
            .bind(id)
            .fetch_optional(st.ctx.db.pool())
            .await
            .map_err(|e| e.to_string())?;
    let Some((name,)) = row else {
        return Ok(None);
    };
    sqlx::query(
        "UPDATE connectors SET connector_configured = 1, connector_api_key = ? WHERE \
         connectors.id = ?",
    )
    .bind(&path_text)
    .bind(id)
    .execute(st.ctx.db.pool())
    .await
    .map_err(|e| e.to_string())?;
    st.ctx.connectors.invalidate(&name);
    Ok(Some(name))
}

/// `verify_connector_by_id(id)` after the upload: its answer and its own
/// failures are not looked at.
async fn verify_after(st: &ConnectorsState, id: i64, name: &str) {
    let Some(verifier) = st.verifiers.get(name) else {
        if !PYTHON_VERIFIED.contains(&name) {
            tracing::error!("Connector type {name} is not supported");
        }
        return;
    };
    if let Some(outcome) = verifier.verify(&st.ctx.connectors, name).await {
        let now = Utc::now().naive_utc();
        if let Err(e) = crate::services::write_verified(
            &st.ctx.db,
            i32::try_from(id).unwrap_or_default(),
            outcome.connection_successful,
            now,
        )
        .await
        {
            tracing::error!("Failed to create ConnectorResponse object: {e}");
        }
        st.ctx.connectors.invalidate(name);
    }
}

/// `POST /upload/{connector_identifier}` (`get_current_user(scopes=["admin"])`).
pub async fn upload(
    State(st): State<ConnectorsState>,
    Path(identifier): Path<String>,
    WithUpload(_admin, file): WithUpload<ScopedUser<AdminOnly>>,
) -> ApiResult {
    let file = file?;
    let id = resolve(&st, &identifier).await?;
    if !file.filename.ends_with(".yaml") {
        return Err(ApiError::bad_request("Only .yaml files are allowed."));
    }
    match save(&st, id, &file.filename, &file.data).await {
        Ok(Some(name)) => {
            verify_after(&st, id, &name).await;
            Ok(Json(serde_json::json!({
                "success": true,
                "message": "File uploaded successfully",
            }))
            .into_response())
        }
        Ok(None) => {
            tracing::error!("Failed to upload file: 500: Failed to upload file");
            Err(failed())
        }
        Err(e) => {
            tracing::error!("Failed to upload file: {e}");
            Err(failed())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_read_as_int_reads_them() {
        assert_eq!(py_int("5"), Some(5));
        assert_eq!(py_int(" +6 "), Some(6));
        assert_eq!(py_int("0_5"), Some(5));
        assert_eq!(py_int("\u{0665}"), Some(5));
        assert_eq!(py_int("5_"), None);
        assert_eq!(py_int("Velociraptor"), None);
        assert_eq!(py_int(""), None);
    }

    /// werkzeug's own examples, and its edges.
    #[test]
    fn file_names_are_secured_as_werkzeug_secures_them() {
        for (input, want) in [
            ("My cool movie.mov", "My_cool_movie.mov"),
            ("../../../etc/passwd", "etc_passwd"),
            (
                "i contain cool \u{fc}ml\u{e4}uts.txt",
                "i_contain_cool_umlauts.txt",
            ),
            ("api.config.yaml", "api.config.yaml"),
            ("._x.yaml_.", "x.yaml"),
            ("a\x1cb.yaml", "a_b.yaml"),
            ("\u{ff21}.yaml", "A.yaml"),
            ("...yaml", "yaml"),
            ("$%.yaml", "yaml"),
        ] {
            assert_eq!(secure_filename(input), want, "{input:?}");
        }
    }
}
