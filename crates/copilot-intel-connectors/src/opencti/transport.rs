//! The OpenCTI GraphQL transport — port of `utils/universal.py`.
//!
//! Everything CoPilot asks OpenCTI goes through [`send_graphql_request`]
//! (one document) or [`paginate_graphql`] (a Relay connection walked page by
//! page), over httpx 0.28 as Python sends it (`copilot_threat_intel::httpx`):
//! `POST <url>/graphql` with `Authorization: Bearer <key>`, `Content-Type`
//! and `Accept: application/json`, the body `{"query", "variables"}` as
//! compact JSON, certificates **not verified** (`verify=False`: an OpenCTI
//! next to CoPilot usually serves a self-signed certificate), a 30 s timeout
//! (15 s for the connector check).
//!
//! OpenCTI reports failure as HTTP 200 with an `errors` array, so any
//! `errors` entry is a failure — checked before the status code. The answer
//! is Python's envelope (`success`, `message`, `data`, `errors`); what
//! `_post_graphql`'s `except httpx.HTTPError` does not catch (an `InvalidURL`,
//! the header-encoding `UnicodeEncodeError`, an `errors` array whose items
//! are not objects) is raised as a [`PyExc`].

use std::time::Duration;

use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_db::connectors::{ConnectorCache, ConnectorRow};
use copilot_threat_intel::httpx::{self, HttpxError};
use copilot_upstream::py::{PyExc, PyResult, iterate, len};
use http::Method;

use crate::py::{dict, get, get_or, int, join, or_dict, or_list, s, set, strip};

/// The connector row's name.
pub const CONNECTOR: &str = "OpenCTI";
/// `GRAPHQL_PATH`.
pub const GRAPHQL_PATH: &str = "/graphql";
/// `DEFAULT_TIMEOUT` (30 s).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// The connector check's timeout (`httpx.AsyncClient(verify=False, timeout=15.0)`).
pub const VERIFY_TIMEOUT: Duration = Duration::from_secs(15);
/// `DEFAULT_PAGE_SIZE`.
pub const DEFAULT_PAGE_SIZE: i64 = 100;

/// `build_graphql_url(connector_url)`: the platform URL or the endpoint
/// itself, both work.
pub fn build_graphql_url(connector_url: &str) -> String {
    let base = strip(connector_url).trim_end_matches('/');
    if base.ends_with(GRAPHQL_PATH) {
        base.to_string()
    } else {
        format!("{base}{GRAPHQL_PATH}")
    }
}

fn platform(graphql_url: &str) -> String {
    graphql_url[..graphql_url.len() - GRAPHQL_PATH.len()].to_string()
}

/// `resolve_platform_url(connector_url, public_url)` (#1221): the public URL
/// in `connector_extra_data` when it is an absolute http(s) URL, else the
/// connector URL. `urlparse`'s `ValueError` (an unbalanced `[`, a bracketed
/// host that is no IPv6 address, NFKC) is raised.
pub fn resolve_platform_url(connector_url: &str, public_url: Option<&str>) -> PyResult<String> {
    let candidate = strip(public_url.unwrap_or(""));
    if !candidate.is_empty() {
        let parsed = copilot_webauthn::origin::urlsplit(candidate).map_err(PyExc::ValueError)?;
        if matches!(parsed.scheme.as_str(), "http" | "https") && !parsed.netloc.is_empty() {
            return Ok(platform(&build_graphql_url(candidate)));
        }
        tracing::warn!("Ignoring the OpenCTI public URL: it is not an absolute http(s) URL");
    }
    Ok(platform(&build_graphql_url(connector_url)))
}

/// `_build_headers(api_key)`.
fn headers(api_key: Option<&str>) -> [(&'static str, String); 3] {
    [
        ("Authorization", format!("Bearer {}", api_key.unwrap_or(""))),
        ("Content-Type", "application/json".into()),
        ("Accept", "application/json".into()),
    ]
}

/// `repr(e)` of an httpx exception.
pub fn httpx_repr(e: &HttpxError) -> String {
    format!("{}({})", e.class, str_repr(&e.message))
}

/// `format_graphql_errors(errors)`: one line, each error's code kept.
pub fn format_graphql_errors(errors: &PyValue) -> PyResult<String> {
    let mut parts = Vec::new();
    for error in iterate(errors)? {
        let message = get_or(&error, "message", s("Unknown error"))?;
        let extensions = or_dict(get(&error, "extensions")?);
        let mut code = get(&extensions, "code")?;
        if !code.truthy() {
            code = get(&error, "name")?;
        }
        parts.push(if code.truthy() {
            s(format!("{} ({})", message.py_str(), code.py_str()))
        } else {
            message
        });
    }
    join("; ", &parts)
}

/// The envelope `_post_graphql` and `send_graphql_request` return.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    /// `success`.
    pub success: bool,
    /// `message`.
    pub message: String,
    /// `data`: GraphQL's `data` (kept on a failure: a partial answer).
    pub data: PyValue,
    /// `errors`: the raw GraphQL errors, `[]` otherwise.
    pub errors: PyValue,
}

impl Envelope {
    fn failure(message: impl Into<String>, data: PyValue) -> Self {
        Self {
            success: false,
            message: message.into(),
            data,
            errors: PyValue::List(Vec::new()),
        }
    }

    /// The dict Python returns.
    pub fn to_py(&self) -> PyValue {
        dict(vec![
            ("success", PyValue::Bool(self.success)),
            ("message", s(self.message.clone())),
            ("data", self.data.clone()),
            ("errors", self.errors.clone()),
        ])
    }
}

/// `_post_graphql(client, attributes, query, variables)`.
pub async fn post_graphql(
    row: &ConnectorRow,
    query: &str,
    variables: PyValue,
    timeout: Duration,
) -> PyResult<Envelope> {
    let url = build_graphql_url(&row.connector_url);
    let mut req = httpx::Request::new(Method::POST, url.clone())
        .verify(false)
        .timeout(timeout);
    for (name, value) in headers(row.connector_api_key.as_deref()) {
        req = req.header(name, Some(&value));
    }
    let req = req.json(dict(vec![("query", s(query)), ("variables", variables)]));
    let response = match httpx::send(req).await {
        Ok(r) => r,
        Err(e) if e.is_http_error() => {
            let repr = httpx_repr(&e);
            tracing::error!("OpenCTI request to {url} failed: {repr}");
            return Ok(Envelope::failure(
                format!("Failed to reach OpenCTI at {url}: {repr}"),
                PyValue::None,
            ));
        }
        Err(e) => return Err(e.into_py()),
    };
    let Ok(body) = response.json() else {
        tracing::error!(
            "OpenCTI returned a non-JSON response ({}) from {url}",
            response.status
        );
        return Ok(Envelope::failure(
            format!(
                "OpenCTI returned a non-JSON response with status {}",
                response.status
            ),
            PyValue::None,
        ));
    };
    if !matches!(body, PyValue::Dict(_)) {
        return Ok(Envelope::failure(
            "OpenCTI returned an unexpected response shape",
            PyValue::None,
        ));
    }
    let errors = or_list(get(&body, "errors")?);
    let data = get(&body, "data")?;
    if errors.truthy() {
        let message = format_graphql_errors(&errors)?;
        tracing::error!("OpenCTI GraphQL error: {message}");
        return Ok(Envelope {
            success: false,
            message: format!("OpenCTI GraphQL error: {message}"),
            data,
            errors,
        });
    }
    if response.status >= 400 {
        tracing::error!("OpenCTI returned HTTP {} from {url}", response.status);
        return Ok(Envelope::failure(
            format!("OpenCTI returned HTTP {}", response.status),
            data,
        ));
    }
    Ok(Envelope {
        success: true,
        message: "Successfully retrieved data".into(),
        data,
        errors: PyValue::List(Vec::new()),
    })
}

fn db_error(e: copilot_db::DbError) -> PyExc {
    PyExc::Other("OperationalError", e.to_string())
}

/// `_get_attributes(connector_name)`.
pub async fn connector_row(cache: &ConnectorCache, name: &str) -> PyResult<Option<ConnectorRow>> {
    cache.get(name).await.map_err(db_error)
}

/// `_missing_connector(connector_name)`.
fn missing_connector(name: &str) -> Envelope {
    tracing::error!("No {name} connector found in the database");
    Envelope::failure(
        format!("No {name} connector found in the database"),
        PyValue::None,
    )
}

/// `send_graphql_request(query, variables)` with the `OpenCTI` row.
pub async fn send_graphql_request(
    cache: &ConnectorCache,
    query: &str,
    variables: PyValue,
) -> PyResult<Envelope> {
    let Some(row) = connector_row(cache, CONNECTOR).await? else {
        return Ok(missing_connector(CONNECTOR));
    };
    post_graphql(&row, query, variables, DEFAULT_TIMEOUT).await
}

/// `_dig(data, path)`.
fn dig(data: &PyValue, path: &[&str]) -> PyValue {
    let mut current = data.clone();
    for key in path {
        match &current {
            PyValue::Dict(_) => current = current.get(key).cloned().unwrap_or(PyValue::None),
            _ => return PyValue::None,
        }
    }
    current
}

/// `cursor in seen_cursors` (a `set`: `TypeError` for an unhashable cursor).
fn seen(cursors: &[PyValue], cursor: &PyValue) -> PyResult<bool> {
    if matches!(cursor, PyValue::List(_) | PyValue::Dict(_)) {
        return Err(PyExc::TypeError(format!(
            "unhashable type: '{}'",
            copilot_upstream::py::type_name(cursor)
        )));
    }
    Ok(cursors
        .iter()
        .any(|c| copilot_upstream::py::py_eq(c, cursor)))
}

/// `paginate_graphql(query, connection_path, variables, page_size,
/// max_items)`: every node of a Relay connection (or the first
/// `max_items`), as the dict Python returns — `data` the nodes,
/// `global_count` the server's total; on a mid-walk failure the nodes
/// gathered so far. No route uses it yet; it is the transport later ports
/// build on.
pub async fn paginate_graphql(
    cache: &ConnectorCache,
    query: &str,
    connection_path: &[&str],
    variables: Option<PyValue>,
    page_size: i64,
    max_items: Option<i64>,
) -> PyResult<PyValue> {
    let Some(row) = connector_row(cache, CONNECTOR).await? else {
        return Ok(missing_connector(CONNECTOR).to_py());
    };
    let pages = |vars: PyValue| {
        let row = row.clone();
        let query = query.to_string();
        async move { post_graphql(&row, &query, vars, DEFAULT_TIMEOUT).await }
    };
    walk(pages, connection_path, variables, page_size, max_items).await
}

/// The walk of [`paginate_graphql`] over any page source (the vectors
/// drive it with recorded answers).
pub async fn walk<F, Fut>(
    mut post: F,
    connection_path: &[&str],
    variables: Option<PyValue>,
    page_size: i64,
    max_items: Option<i64>,
) -> PyResult<PyValue>
where
    F: FnMut(PyValue) -> Fut,
    Fut: std::future::Future<Output = PyResult<Envelope>>,
{
    let base = match variables {
        Some(PyValue::Dict(items)) => items,
        Some(v) if !v.truthy() => Vec::new(),
        None => Vec::new(),
        // `{**variables}` of anything but a mapping.
        Some(v) => {
            return Err(PyExc::TypeError(format!(
                "'{}' object is not a mapping",
                copilot_upstream::py::type_name(&v)
            )));
        }
    };
    let mut nodes: Vec<PyValue> = Vec::new();
    let mut after = PyValue::None;
    let mut global_count = PyValue::None;
    let mut cursors: Vec<PyValue> = Vec::new();
    let result =
        |success: bool, message: String, nodes: &[PyValue], errors: PyValue, gc: &PyValue| {
            dict(vec![
                ("success", PyValue::Bool(success)),
                ("message", s(message)),
                ("data", PyValue::List(nodes.to_vec())),
                ("errors", errors),
                ("global_count", gc.clone()),
            ])
        };
    loop {
        let collected = i64::try_from(nodes.len()).unwrap_or(i64::MAX);
        let first = match max_items {
            None => page_size,
            Some(max) => page_size.min(max - collected),
        };
        let mut vars = base.clone();
        set(&mut vars, "first", int(first));
        set(&mut vars, "after", after.clone());
        let response = post(PyValue::Dict(vars)).await?;
        if !response.success {
            return Ok(result(
                false,
                response.message,
                &nodes,
                response.errors,
                &global_count,
            ));
        }
        let connection = dig(&response.data, connection_path);
        if !matches!(connection, PyValue::Dict(_)) {
            let message = format!(
                "OpenCTI response has no connection at {}",
                connection_path.join(".")
            );
            tracing::error!("{message}");
            return Ok(result(
                false,
                message,
                &nodes,
                PyValue::List(Vec::new()),
                &global_count,
            ));
        }
        let page_info = or_dict(get(&connection, "pageInfo")?);
        if matches!(global_count, PyValue::None) {
            global_count = get(&page_info, "globalCount")?;
        }
        for edge in iterate(&or_list(get(&connection, "edges")?))? {
            if edge.truthy() && !matches!(get(&edge, "node")?, PyValue::None) {
                nodes.push(get(&edge, "node")?);
            }
        }
        let cursor = get(&page_info, "endCursor")?;
        if let Some(max) = max_items {
            if i64::try_from(nodes.len()).unwrap_or(i64::MAX) >= max {
                break;
            }
        }
        if !get(&page_info, "hasNextPage")?.truthy() || !cursor.truthy() || seen(&cursors, &cursor)?
        {
            break;
        }
        cursors.push(cursor.clone());
        after = cursor;
    }
    let count = len(&PyValue::List(nodes.clone()))?;
    Ok(result(
        true,
        format!("Retrieved {count} items"),
        &nodes,
        PyValue::List(Vec::new()),
        &global_count,
    ))
}

/// `verify_opencti_credentials(attributes)`: `{connectionSuccessful,
/// message}`; `Err` for what Python lets escape (the route then answers
/// `No connector found for ID`).
pub async fn verify_credentials(row: &ConnectorRow) -> PyResult<(bool, String)> {
    if strip(&row.connector_url).is_empty() {
        return Ok((false, "No OpenCTI URL is configured".into()));
    }
    let url = build_graphql_url(&row.connector_url);
    tracing::info!("Verifying the OpenCTI connection to {url}");
    let response = post_graphql(
        row,
        super::queries::VERIFY_QUERY,
        PyValue::Dict(Vec::new()),
        VERIFY_TIMEOUT,
    )
    .await?;
    if !response.success {
        return Ok((
            false,
            format!("Connection to {url} failed: {}", response.message),
        ));
    }
    let data = or_dict(response.data);
    let version = get(&or_dict(get(&data, "about")?), "version")?;
    let user = get(&or_dict(get(&data, "me")?), "name")?;
    if !version.truthy() {
        return Ok((
            false,
            format!("Connection to {url} failed: OpenCTI did not report a version"),
        ));
    }
    tracing::info!(
        "Connection to {url} successful (OpenCTI {}, user {})",
        version.py_str(),
        user.py_str()
    );
    Ok((
        true,
        format!(
            "OpenCTI connection successful (version {}, authenticated as {})",
            version.py_str(),
            user.py_str()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn urls_resolve_like_python() {
        for (input, want) in [
            ("http://opencti:8080", "http://opencti:8080/graphql"),
            ("http://opencti:8080/", "http://opencti:8080/graphql"),
            (
                " http://opencti:8080/graphql/ ",
                "http://opencti:8080/graphql",
            ),
            ("", "/graphql"),
            ("http://x///", "http://x/graphql"),
        ] {
            assert_eq!(build_graphql_url(input), want, "{input:?}");
        }
        assert_eq!(
            resolve_platform_url(
                "http://internal:8080/graphql",
                Some(" https://cti.example/ ")
            )
            .unwrap(),
            "https://cti.example"
        );
        assert_eq!(
            resolve_platform_url("http://internal:8080/", Some("cti.example")).unwrap(),
            "http://internal:8080"
        );
        assert_eq!(
            resolve_platform_url("http://internal:8080", Some("http://[::1")).unwrap_err(),
            PyExc::ValueError("Invalid IPv6 URL".into())
        );
    }

    #[test]
    fn graphql_errors_flatten_like_python() {
        let errors = loads(
            r#"[{"message": "You must be logged in", "extensions": {"code": "AUTH_REQUIRED"}},
                {"message": "bad", "name": "GRAPHQL_VALIDATION_FAILED"}, {}, {"message": 5, "name": "X"}]"#,
        )
        .unwrap();
        assert_eq!(
            format_graphql_errors(&errors).unwrap(),
            "You must be logged in (AUTH_REQUIRED); bad (GRAPHQL_VALIDATION_FAILED); Unknown error; 5 (X)"
        );
        assert!(format_graphql_errors(&loads(r#"[{"message": 5}]"#).unwrap()).is_err());
        assert!(format_graphql_errors(&loads(r#"["x"]"#).unwrap()).is_err());
    }
}
