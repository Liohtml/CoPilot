//! The Grafana client — port of `app/connectors/grafana/utils/universal.py`
//! (`create_grafana_client`) and of `grafana_client` 5.1's `GrafanaApi`
//! over niquests.
//!
//! **The client.** `create_grafana_client` reads the `Grafana` connector row
//! and builds `http://{user}:{password}@…?verify=false` (every `http://` of
//! the URL is replaced, `None` credentials print as `None`; a URL with
//! neither `http://` nor `https://` is `Invalid connector URL format`), which
//! `GrafanaApi.from_url` takes apart with `urlparse`: the credentials go to
//! HTTP Basic (UTF-8, as niquests encodes them), `verify=false` turns
//! certificate verification **off** (as in Python: Grafana in a SOCFortress
//! stack serves a self-signed certificate), and the API root is
//! `{scheme}://{host}[:{port}]/{path without leading /}api` — so a URL path
//! `/grafana` gives `/grafanaapi`, as the library builds it. [`build_api`]
//! reproduces that, its `ValueError`s included (`Port out of range 0-65535`,
//! `invalid truth value …`).
//!
//! **A request** ([`GrafanaClient::call`]) is `{api}{path}` with
//! `User-Agent: grafana-client/5.1.0`, a 5 s connect and read timeout, the
//! body as niquests sends `json=` (`application/json;charset=utf-8`); the
//! answer is read as `_extract_from_response` does: 5xx `Server Error N:
//! {message}`, 400 ``Bad Input: `{response}` ``, 401 `Unauthorized`, other
//! 4xx `Client Error N: {message}` (`message` from the JSON body, else its
//! text), 204 `None`, a `text/*` body as text, anything else as JSON
//! (`JSONDecodeError` otherwise). Transport failures read as urllib3(-future)
//! words them ([`copilot_upstream::http`]).

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_db::connectors::{ConnectorCache, ConnectorRow};
use copilot_upstream::http::{PyHttp, PyRequest, PyResponse};
use copilot_upstream::py::{PyExc, PyResult};
use http::Method;

/// The connector's name.
pub const CONNECTOR: &str = "Grafana";
/// `grafana_client`'s `DEFAULT_TIMEOUT` (connect and read).
pub const TIMEOUT: Duration = Duration::from_secs(5);
/// The library's `User-Agent`.
pub const USER_AGENT: &str = "grafana-client/5.1.0";

/// `GrafanaApi.from_url(…)`: where requests go and how they authenticate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrafanaApi {
    /// The API root (`http://host:3000/api`).
    pub url: String,
    /// HTTP Basic credentials (from the URL), if any.
    pub auth: Option<(String, String)>,
    /// Whether certificates are verified (`?verify=`).
    pub verify: bool,
}

/// The Grafana client.
#[derive(Debug, Clone)]
pub struct GrafanaClient {
    connectors: ConnectorCache,
    unverified: PyHttp,
    verified: PyHttp,
}

fn value_error(text: impl Into<String>) -> PyExc {
    PyExc::ValueError(text.into())
}

/// The parts of `urllib.parse.urlparse(url)` that `from_url` reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Parsed {
    scheme: String,
    netloc: String,
    path: String,
    query: String,
}

/// `urlparse(url)` (CPython 3.11).
fn urlparse(url: &str) -> PyResult<Parsed> {
    let url: String = url
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = url.as_str();
    let mut out = Parsed::default();
    if let Some(i) = rest.find(':') {
        let head = &rest[..i];
        if i > 0
            && head.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && head
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            out.scheme = head.to_ascii_lowercase();
            rest = &rest[i + 1..];
        }
    }
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        out.netloc = after[..end].to_string();
        rest = &after[end..];
        if out.netloc.contains('[') != out.netloc.contains(']') {
            return Err(value_error("Invalid IPv6 URL"));
        }
    }
    let rest = rest.split_once('#').map_or(rest, |(r, _)| r);
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    out.query = query.to_string();
    // `_splitparams`: `;params` of the last segment are not the path.
    let path = match path.rfind('/') {
        Some(slash) => match path[slash..].find(';') {
            Some(i) => &path[..slash + i],
            None => path,
        },
        None => path.split(';').next().unwrap_or(path),
    };
    out.path = path.to_string();
    Ok(out)
}

impl Parsed {
    fn userinfo(&self) -> Option<&str> {
        self.netloc.rfind('@').map(|i| &self.netloc[..i])
    }

    fn hostinfo(&self) -> &str {
        self.netloc
            .rfind('@')
            .map_or(self.netloc.as_str(), |i| &self.netloc[i + 1..])
    }

    fn username(&self) -> Option<&str> {
        self.userinfo().map(|u| u.split(':').next().unwrap_or(u))
    }

    fn password(&self) -> Option<&str> {
        self.userinfo()
            .and_then(|u| u.split_once(':').map(|(_, p)| p))
    }

    /// `(hostname, port text)`.
    fn host_and_port(&self) -> (Option<String>, Option<&str>) {
        let info = self.hostinfo();
        let (host, port) = match info.split_once('[') {
            Some((_, bracketed)) => {
                let (host, after) = bracketed.split_once(']').unwrap_or((bracketed, ""));
                (host, after.split_once(':').map(|(_, p)| p))
            }
            None => match info.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (info, None),
            },
        };
        let host = (!host.is_empty()).then(|| host.to_lowercase());
        (host, port.filter(|p| !p.is_empty()))
    }

    /// `.port`.
    fn port(&self) -> PyResult<Option<u32>> {
        let Some(port) = self.host_and_port().1 else {
            return Ok(None);
        };
        if !port.chars().all(|c| c.is_ascii_digit()) {
            return Err(value_error(format!(
                "Port could not be cast to integer value as {}",
                copilot_auth::pyvalue::str_repr(port)
            )));
        }
        match port.parse::<u32>() {
            Ok(n) if n <= 65535 => Ok(Some(n)),
            _ => Err(value_error("Port out of range 0-65535")),
        }
    }
}

/// `%XX` and `+` decoded (`parse_qs`'s unquoting).
fn unquote_plus(s: &str) -> String {
    let b = s.replace('+', " ").into_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| char::from(c).to_digit(16);
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(u8::try_from(h * 16 + l).unwrap_or(b'?'));
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `parse_qs(query).get(key, [None])[0]`.
fn first_query_value(query: &str, key: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .filter(|(_, v)| !v.is_empty())
        .find(|(k, _)| unquote_plus(k) == key)
        .map(|(_, v)| unquote_plus(v))
}

/// `grafana_client.util.as_bool`.
fn as_bool(value: &str) -> PyResult<bool> {
    match value.to_lowercase().as_str() {
        "y" | "yes" | "t" | "on" | "1" | "true" => Ok(true),
        "n" | "no" | "f" | "off" | "0" | "false" => Ok(false),
        _ => Err(value_error(format!("invalid truth value {value}"))),
    }
}

/// `construct_grafana_url(...)` then `GrafanaApi.from_url(...)`.
pub fn build_api(
    connector_url: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> PyResult<GrafanaApi> {
    let (user, pass) = (username.unwrap_or("None"), password.unwrap_or("None"));
    let mut url = if connector_url.contains("http://") {
        connector_url.replace("http://", &format!("http://{user}:{pass}@"))
    } else if connector_url.contains("https://") {
        connector_url.replace("https://", &format!("https://{user}:{pass}@"))
    } else {
        return Err(value_error("Invalid connector URL format"));
    };
    url.push_str("?verify=false");
    let parsed = urlparse(&url)?;
    let auth = parsed
        .username()
        .filter(|u| !u.is_empty())
        .map(|u| (u.to_string(), parsed.password().unwrap_or("").to_string()));
    let verify = match first_query_value(&parsed.query, "verify") {
        Some(v) => as_bool(&v)?,
        None => true,
    };
    let port = parsed.port()?;
    let host = parsed.host_and_port().0.unwrap_or_else(|| "None".into());
    let prefix = parsed.path.trim_start_matches('/');
    let url = match port {
        None => format!("{}://{host}/{prefix}api", parsed.scheme),
        Some(p) => format!("{}://{host}:{p}/{prefix}api", parsed.scheme),
    };
    Ok(GrafanaApi { url, auth, verify })
}

fn db_error(e: copilot_db::DbError) -> PyExc {
    PyExc::Other("OperationalError", e.to_string())
}

impl GrafanaClient {
    /// A client reading the connector row through `connectors`.
    pub fn new(connectors: ConnectorCache) -> Result<Self, reqwest::Error> {
        Ok(Self {
            connectors,
            unverified: PyHttp::niquests(TIMEOUT, false)?.with_timeout_text("5.0"),
            verified: PyHttp::niquests(TIMEOUT, true)?.with_timeout_text("5.0"),
        })
    }

    /// `get_connector_info_from_db(name)`.
    pub async fn row(&self, connector: &str) -> PyResult<Option<ConnectorRow>> {
        self.connectors.get(connector).await.map_err(db_error)
    }

    /// `create_grafana_client(connector)`: `HTTPException(500)` without a row
    /// or when the URL cannot be built.
    pub async fn create(&self, connector: &str) -> PyResult<GrafanaApi> {
        let row = self.row(connector).await?.ok_or_else(|| {
            PyExc::http(
                500,
                format!("No {connector} connector found in the database"),
            )
        })?;
        build_api(
            &row.connector_url,
            row.connector_username.as_deref(),
            row.connector_password.as_deref(),
        )
        .map_err(|e| {
            PyExc::http(
                500,
                format!("Failed to create Grafana client: {}", e.display()),
            )
        })
    }

    /// `client.<METHOD>(path, json=…, params=…)`: the decoded answer.
    pub async fn call(
        &self,
        api: &GrafanaApi,
        method: Method,
        path: &str,
        json: Option<PyValue>,
        params: Vec<(String, String)>,
    ) -> PyResult<PyValue> {
        let mut req = PyRequest::new(method, format!("{}{path}", api.url))
            .header("User-Agent", USER_AGENT)
            .params(params)
            .json(json);
        if let Some((user, password)) = &api.auth {
            req = req.basic(Some(user.clone()), Some(password.clone()));
        }
        let http = if api.verify {
            &self.verified
        } else {
            &self.unverified
        };
        let resp = match http.send(req).await {
            Ok(r) => r,
            // `except Timeout as e: raise GrafanaTimeoutError(0, None, str(e))`.
            Err(PyExc::Other("ReadTimeout" | "ConnectTimeout", text)) => {
                return Err(PyExc::Other("GrafanaTimeoutError", text));
            }
            Err(e) => return Err(e),
        };
        extract(&resp)
    }

    /// `organizations.list_organization()` (`GET /orgs`).
    pub async fn list_organizations(&self, api: &GrafanaApi) -> PyResult<PyValue> {
        self.call(api, Method::GET, "/orgs", None, Vec::new()).await
    }

    /// `user.switch_actual_user_organisation(id)` (`POST /user/using/{id}`).
    pub async fn switch_organization(&self, api: &GrafanaApi, org_id: &str) -> PyResult<PyValue> {
        self.call(
            api,
            Method::POST,
            &format!("/user/using/{org_id}"),
            None,
            Vec::new(),
        )
        .await
    }

    /// `search.search_dashboards()` (`GET /search`).
    pub async fn search_dashboards(&self, api: &GrafanaApi) -> PyResult<PyValue> {
        self.call(api, Method::GET, "/search", None, Vec::new())
            .await
    }

    /// `dashboard.get_dashboard(uid)` (`GET /dashboards/uid/{uid}`).
    pub async fn get_dashboard(&self, api: &GrafanaApi, uid: &str) -> PyResult<PyValue> {
        self.call(
            api,
            Method::GET,
            &format!("/dashboards/uid/{uid}"),
            None,
            Vec::new(),
        )
        .await
    }

    /// `dashboard.update_dashboard(payload)` (`POST /dashboards/db`).
    pub async fn update_dashboard(&self, api: &GrafanaApi, payload: PyValue) -> PyResult<PyValue> {
        self.call(
            api,
            Method::POST,
            "/dashboards/db",
            Some(payload),
            Vec::new(),
        )
        .await
    }

    /// `folder.get_all_folders()` (`GET /folders`).
    pub async fn get_all_folders(&self, api: &GrafanaApi) -> PyResult<PyValue> {
        self.call(api, Method::GET, "/folders", None, Vec::new())
            .await
    }

    /// `organizations.organization_user_add(org, user)`
    /// (`POST /orgs/{org}/users`).
    pub async fn add_organization_user(
        &self,
        api: &GrafanaApi,
        org_id: &str,
        user: PyValue,
    ) -> PyResult<PyValue> {
        self.call(
            api,
            Method::POST,
            &format!("/orgs/{org_id}/users"),
            Some(user),
            Vec::new(),
        )
        .await
    }
}

/// `GrafanaClient._extract_from_response(r, accept_empty_json=False)`.
pub fn extract(r: &PyResponse) -> PyResult<PyValue> {
    let status = r.status();
    if status >= 400 {
        let response = r.json().unwrap_or_else(|_| PyValue::Str(r.text()));
        let message = match &response {
            PyValue::Dict(items) => items
                .iter()
                .find(|(k, _)| k == "message")
                .map_or_else(|| r.text(), |(_, v)| v.py_str()),
            _ => r.text(),
        };
        if (500..600).contains(&status) {
            return Err(PyExc::Other(
                "GrafanaServerError",
                format!("Server Error {status}: {message}"),
            ));
        }
        if status == 400 {
            return Err(PyExc::Other(
                "GrafanaBadInputError",
                format!("Bad Input: `{}`", response.py_str()),
            ));
        }
        if status == 401 {
            return Err(PyExc::Other(
                "GrafanaUnauthorizedError",
                "Unauthorized".into(),
            ));
        }
        if status < 500 {
            return Err(PyExc::Other(
                "GrafanaClientError",
                format!("Client Error {status}: {message}"),
            ));
        }
    }
    if status == 204 {
        return Ok(PyValue::None);
    }
    let content_type = r
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if content_type.starts_with("text/") {
        return Ok(PyValue::Str(r.text()));
    }
    r.json()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_built_as_from_url_builds_them() {
        let api = build_api("http://grafana:3000", Some("admin"), Some("p:w@x")).unwrap();
        assert_eq!(
            api,
            GrafanaApi {
                url: "http://grafana:3000/api".into(),
                auth: Some(("admin".into(), "p:w@x".into())),
                verify: false,
            }
        );
        let api = build_api("https://G.example/grafana", None, None).unwrap();
        assert_eq!(api.url, "https://g.example/grafanaapi");
        assert_eq!(api.auth, Some(("None".into(), "None".into())));
        let api = build_api("http://g:3000/grafana/", Some(""), Some("pw")).unwrap();
        assert_eq!(
            (api.url.as_str(), api.auth),
            ("http://g:3000/grafana/api", None)
        );
        let api = build_api("http://g:3000?x=1", Some("u"), Some("p")).unwrap();
        assert!(api.verify, "the appended ?verify=false lands in x");
        assert_eq!(
            build_api("grafana:3000", Some("u"), Some("p"))
                .unwrap_err()
                .text(),
            "Invalid connector URL format"
        );
        assert_eq!(
            build_api("http://g:99999", Some("u"), Some("p"))
                .unwrap_err()
                .text(),
            "Port out of range 0-65535"
        );
        assert_eq!(
            build_api("http://g:x", Some("u"), Some("p"))
                .unwrap_err()
                .text(),
            "Port could not be cast to integer value as 'x'"
        );
        assert_eq!(
            build_api("http://g/?verify=maybe", Some("u"), Some("p"))
                .unwrap_err()
                .text(),
            "invalid truth value maybe?verify=false"
        );
        assert_eq!(
            build_api("http://", Some("u"), Some("p")).unwrap().url,
            "http://None/api"
        );
    }

    fn response(status: u16, ct: Option<&str>, body: &str) -> PyResponse {
        let mut headers = http::HeaderMap::new();
        if let Some(ct) = ct {
            headers.insert(http::header::CONTENT_TYPE, ct.parse().unwrap());
        }
        PyResponse::new(status, headers, body.to_string())
    }

    #[test]
    fn answers_are_read_like_the_library() {
        let j = Some("application/json");
        let text = |r: PyResponse| extract(&r).unwrap_err().text();
        assert_eq!(
            text(response(404, j, r#"{"message":"Dashboard not found"}"#)),
            "Client Error 404: Dashboard not found"
        );
        assert_eq!(
            text(response(400, j, r#"{"message":"bad","x":1}"#)),
            "Bad Input: `{'message': 'bad', 'x': 1}`"
        );
        assert_eq!(text(response(401, j, "{}")), "Unauthorized");
        assert_eq!(
            text(response(502, Some("text/html"), "<b>x</b>\n")),
            "Server Error 502: <b>x</b>\n"
        );
        assert_eq!(
            text(response(500, j, r#"{"message":5}"#)),
            "Server Error 500: 5"
        );
        assert_eq!(text(response(403, None, "")), "Client Error 403: ");
        assert_eq!(
            text(response(200, j, "not")),
            "Expecting value: line 1 column 1 (char 0)"
        );
        assert_eq!(extract(&response(204, None, "")).unwrap(), PyValue::None);
        assert_eq!(
            extract(&response(200, Some("text/plain"), "hi")).unwrap(),
            PyValue::Str("hi".into())
        );
    }
}
