//! `requests` 2.33 (over the venv's urllib3 2.x) as the Wazuh manager
//! helpers call it: `requests.get(url, params=…, headers=…, verify=False,
//! timeout=60)` and friends.
//!
//! What goes out is what `PreparedRequest` builds: the URL through urllib3's
//! `parse_url` (scheme and host lower-cased, dot segments removed, invalid
//! characters percent-encoded, existing escapes upper-cased), the parameters
//! `urlencode`d after any query the URL already carries (`str()` of each
//! value, so `True`/`False`), and the whole re-quoted by `requote_uri`.
//! `Authorization: Basic` is `user:password` in Latin-1, a `None` user or
//! password becoming the text `None`. The exceptions' `str()` is what the
//! services put into their messages: `HTTPError` (`404 Client Error: Not
//! Found for url: …`), `ConnectionError` (urllib3's `Max retries exceeded`
//! sentence; the connection object's address is
//! `copilot_upstream::http::OBJECT_ADDRESS`, there being no Python object),
//! and the JSON decoder's (`Expecting value: line 1 column
//! 1 (char 0)`). `requests_vectors.json` (`scripts/gen-requests-vectors.py`)
//! pins the URL preparation.

use std::sync::OnceLock;

use base64::Engine;
use regex::Regex;

use copilot_auth::pyvalue::str_repr;
use copilot_upstream::http::OBJECT_ADDRESS;
use copilot_web::pyurl::{quote, quote_plus};

/// `requests.utils.default_user_agent()` of the venv.
pub const USER_AGENT: &str = "python-requests/2.33.1";
/// `requests.utils.DEFAULT_ACCEPT_ENCODING`.
pub const ACCEPT_ENCODING: &str = "gzip, deflate";

const UNRESERVED: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-~";
const SUB_DELIMS: &str = "!$&'()*+,;=";

fn userinfo_chars() -> String {
    format!("{UNRESERVED}{SUB_DELIMS}:")
}

fn path_chars() -> String {
    format!("{}@/", userinfo_chars())
}

fn query_chars() -> String {
    format!("{}?", path_chars())
}

static URI_RE: OnceLock<Option<Regex>> = OnceLock::new();
static SCHEME_RE: OnceLock<Option<Regex>> = OnceLock::new();
static HOST_PORT_RE: OnceLock<Option<Regex>> = OnceLock::new();
static IPV4_RE: OnceLock<Option<Regex>> = OnceLock::new();
static IPV6_ADDRZ_RE: OnceLock<Option<Regex>> = OnceLock::new();
static ZONE_ID_RE: OnceLock<Option<Regex>> = OnceLock::new();
static PERCENT_RE: OnceLock<Option<Regex>> = OnceLock::new();

const IPV4_PAT: &str = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}";
const REG_NAME_PAT: &str = r"(?:[^\[\]%:/?#]|%[a-fA-F0-9]{2})*";

fn ipv6_pat() -> String {
    let hex = "[0-9A-Fa-f]{1,4}";
    let ls32 = format!("(?:{hex}:{hex}|{IPV4_PAT})");
    let variations = [
        format!("(?:{hex}:){{6}}{ls32}"),
        format!("::(?:{hex}:){{5}}{ls32}"),
        format!("(?:{hex})?::(?:{hex}:){{4}}{ls32}"),
        format!("(?:(?:{hex}:)?{hex})?::(?:{hex}:){{3}}{ls32}"),
        format!("(?:(?:{hex}:){{0,2}}{hex})?::(?:{hex}:){{2}}{ls32}"),
        format!("(?:(?:{hex}:){{0,3}}{hex})?::{hex}:{ls32}"),
        format!("(?:(?:{hex}:){{0,4}}{hex})?::{ls32}"),
        format!("(?:(?:{hex}:){{0,5}}{hex})?::{hex}"),
        format!("(?:(?:{hex}:){{0,6}}{hex})?::"),
    ];
    format!("(?:{})", variations.join("|"))
}

fn zone_id_pat() -> String {
    r"(?:%25|%)(?:[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._\-~]|%[a-fA-F0-9]{2})+"
        .to_string()
}

fn ipv6_addrz_pat() -> String {
    format!(r"\[{}(?:{})?\]", ipv6_pat(), zone_id_pat())
}

fn re(
    slot: &'static OnceLock<Option<Regex>>,
    pattern: impl FnOnce() -> String,
) -> Option<&'static Regex> {
    slot.get_or_init(|| Regex::new(&pattern()).ok()).as_ref()
}

fn uri_re() -> Option<&'static Regex> {
    re(&URI_RE, || {
        r"(?s)^(?:([a-zA-Z][a-zA-Z0-9+.-]*):)?(?://([^\\/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$"
            .to_string()
    })
}

fn scheme_re() -> Option<&'static Regex> {
    re(&SCHEME_RE, || r"^(?:[a-zA-Z][a-zA-Z0-9+-]*:|/)".to_string())
}

fn host_port_re() -> Option<&'static Regex> {
    re(&HOST_PORT_RE, || {
        format!(
            "(?s)^({REG_NAME_PAT}|{IPV4_PAT}|{})(?::0*?(|0|[1-9][0-9]{{0,4}}))?$",
            ipv6_addrz_pat()
        )
    })
}

fn ipv4_re() -> Option<&'static Regex> {
    re(&IPV4_RE, || format!("^{IPV4_PAT}$"))
}

fn ipv6_addrz_re() -> Option<&'static Regex> {
    re(&IPV6_ADDRZ_RE, || format!("^{}$", ipv6_addrz_pat()))
}

fn zone_id_re() -> Option<&'static Regex> {
    re(&ZONE_ID_RE, || format!(r"({})\]$", zone_id_pat()))
}

fn percent_re() -> Option<&'static Regex> {
    re(&PERCENT_RE, || "%[a-fA-F0-9]{2}".to_string())
}

/// `_encode_invalid_chars(component, allowed)`.
fn encode_invalid_chars(component: &str, allowed: &str) -> String {
    let (normalized, encodings) = match percent_re() {
        Some(p) => {
            let n = p.find_iter(component).count();
            (
                p.replace_all(component, |c: &regex::Captures<'_>| c[0].to_uppercase())
                    .into_owned(),
                n,
            )
        }
        None => (component.to_string(), 0),
    };
    let bytes = normalized.as_bytes();
    let all_encoded = encodings == bytes.iter().filter(|b| **b == b'%').count();
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if (all_encoded && b == b'%') || (b < 128 && allowed.as_bytes().contains(&b)) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `_remove_path_dot_segments(path)`.
fn remove_dot_segments(path: &str) -> String {
    let mut output: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        if segment == "." {
            continue;
        }
        if segment != ".." {
            output.push(segment);
        } else {
            output.pop();
        }
    }
    if path.starts_with('/') && output.first().is_none_or(|s| !s.is_empty()) {
        output.insert(0, "");
    }
    if path.ends_with("/.") || path.ends_with("/..") {
        output.push("");
    }
    output.join("/")
}

/// `_normalize_host(host, scheme)` (only called for http(s) or no scheme).
fn normalize_host(host: &str) -> Result<String, ()> {
    if host.is_empty() {
        return Ok(String::new());
    }
    if ipv6_addrz_re().is_some_and(|r| r.is_match(host)) {
        if let Some(m) = zone_id_re()
            .and_then(|r| r.captures(host))
            .and_then(|c| c.get(1))
        {
            let (start, end) = (m.start(), m.end());
            let zone = &host[start..end];
            let zone = if zone.starts_with("%25") && zone != "%25" {
                &zone[3..]
            } else {
                &zone[1..]
            };
            let zone = encode_invalid_chars(zone, UNRESERVED);
            return Ok(format!(
                "{}%{zone}{}",
                host[..start].to_lowercase(),
                &host[end..]
            ));
        }
        return Ok(host.to_lowercase());
    }
    if ipv4_re().is_some_and(|r| r.is_match(host)) {
        return Ok(host.to_string());
    }
    let mut labels = Vec::new();
    for label in host.split('.') {
        if label.is_ascii() {
            labels.push(label.to_ascii_lowercase());
        } else {
            // The `idna` package's UTS #46 processing; this crate's IDNA
            // differs on labels Python's strict mode rejects.
            labels.push(idna::domain_to_ascii_strict(&label.to_lowercase()).map_err(|_| ())?);
        }
    }
    Ok(labels.join("."))
}

struct ParsedUrl {
    scheme: Option<String>,
    auth: Option<String>,
    host: Option<String>,
    port: Option<u32>,
    path: Option<String>,
    query: Option<String>,
    fragment: Option<String>,
}

/// urllib3's `parse_url`; `Err` is `LocationParseError`.
fn parse_url(url: &str) -> Result<ParsedUrl, ()> {
    let src = if scheme_re().is_some_and(|r| r.is_match(url)) {
        url.to_string()
    } else {
        format!("//{url}")
    };
    let caps = uri_re().and_then(|r| r.captures(&src)).ok_or(())?;
    let group = |i: usize| caps.get(i).map(|m| m.as_str().to_string());
    let scheme = group(1).map(|s| s.to_ascii_lowercase());
    let normalize = scheme
        .as_deref()
        .is_none_or(|s| s == "http" || s == "https");
    let authority = group(2);
    let mut path = group(3);
    let mut query = group(4);
    let mut fragment = group(5);
    let (mut auth, mut host, mut port) = (None, None, None);
    if let Some(a) = authority.filter(|a| !a.is_empty()) {
        let (user, host_port) = match a.rfind('@') {
            Some(i) => (Some(a[..i].to_string()), a[i + 1..].to_string()),
            None => (None, a.clone()),
        };
        auth = user.filter(|u| !u.is_empty());
        let hp = host_port_re()
            .and_then(|r| r.captures(&host_port))
            .ok_or(())?;
        host = hp.get(1).map(|m| m.as_str().to_string());
        port = hp
            .get(2)
            .map(|m| m.as_str().to_string())
            .filter(|p| !p.is_empty());
        if normalize {
            auth = auth.map(|a| encode_invalid_chars(&a, &userinfo_chars()));
        }
    }
    let port = match port {
        Some(p) => {
            let n: u32 = p.parse().map_err(|_| ())?;
            if n > 65535 {
                return Err(());
            }
            Some(n)
        }
        None => None,
    };
    if normalize {
        host = match host {
            Some(h) => Some(normalize_host(&h)?),
            None => None,
        };
    }
    if normalize {
        if let Some(p) = path.as_deref().filter(|p| !p.is_empty()) {
            path = Some(encode_invalid_chars(&remove_dot_segments(p), &path_chars()));
        }
        if let Some(q) = query.as_deref().filter(|q| !q.is_empty()) {
            query = Some(encode_invalid_chars(q, &query_chars()));
        }
        if let Some(f) = fragment.as_deref().filter(|f| !f.is_empty()) {
            fragment = Some(encode_invalid_chars(f, &query_chars()));
        }
    }
    if path.as_deref().is_none_or(str::is_empty) {
        path = if query.is_some() || fragment.is_some() {
            Some(String::new())
        } else {
            None
        };
    }
    if let Some(p) = path.as_mut() {
        if !p.is_empty() && !p.starts_with('/') {
            p.insert(0, '/');
        }
    }
    Ok(ParsedUrl {
        scheme,
        auth,
        host,
        port,
        path,
        query,
        fragment,
    })
}

/// `unquote_unreserved(uri)`; `Err` is `InvalidURL`.
fn unquote_unreserved(uri: &str) -> Result<String, ()> {
    let mut parts = uri.split('%');
    let mut out = parts.next().unwrap_or_default().to_string();
    for part in parts {
        let h: String = part.chars().take(2).collect();
        if h.chars().count() == 2 && h.chars().all(char::is_alphanumeric) {
            let code = u32::from_str_radix(&h, 16).map_err(|_| ())?;
            match char::from_u32(code).filter(|c| UNRESERVED.contains(*c)) {
                Some(c) => {
                    out.push(c);
                    out.push_str(&part[h.len()..]);
                }
                None => {
                    out.push('%');
                    out.push_str(part);
                }
            }
        } else {
            out.push('%');
            out.push_str(part);
        }
    }
    Ok(out)
}

/// `requote_uri(uri)`.
fn requote_uri(uri: &str) -> String {
    match unquote_unreserved(uri) {
        Ok(u) => quote(&u, "!#$%&'()*+,/:;=?@[]~"),
        Err(()) => quote(uri, "!#$&'()*+,/:;=?@[]~"),
    }
}

/// Why `requests` refused a URL (all end the manager call the same way).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlError(pub String);

/// `PreparedRequest.prepare_url(url, params)`, then the adapter lookup.
/// `params` are `(name, str(value))` in the dict's order.
pub fn prepare_url(url: &str, params: &[(String, String)]) -> Result<String, UrlError> {
    let url = url.trim_start_matches(copilot_web::form::is_py_space);
    if url.contains(':') && !url.to_lowercase().starts_with("http") {
        return Err(UrlError(format!(
            "No connection adapters were found for {}",
            str_repr(url)
        )));
    }
    let parsed = parse_url(url).map_err(|()| UrlError(format!("Failed to parse: {url}")))?;
    let Some(scheme) = parsed.scheme.filter(|s| !s.is_empty()) else {
        return Err(UrlError(format!(
            "Invalid URL {}: No scheme supplied. Perhaps you meant https://{url}?",
            str_repr(url)
        )));
    };
    let Some(host) = parsed.host.filter(|h| !h.is_empty()) else {
        return Err(UrlError(format!(
            "Invalid URL {}: No host supplied",
            str_repr(url)
        )));
    };
    if host.starts_with('*') || host.starts_with('.') {
        return Err(UrlError("URL has an invalid label.".into()));
    }
    let mut netloc = parsed.auth.map(|a| format!("{a}@")).unwrap_or_default();
    netloc.push_str(&host);
    if let Some(p) = parsed.port.filter(|p| *p != 0) {
        netloc.push_str(&format!(":{p}"));
    }
    let path = parsed
        .path
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "/".into());
    let encoded = params
        .iter()
        .map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v)))
        .collect::<Vec<_>>()
        .join("&");
    let query = match (parsed.query, encoded.is_empty()) {
        (Some(q), false) if !q.is_empty() => Some(format!("{q}&{encoded}")),
        (_, false) => Some(encoded),
        (q, true) => q,
    };
    // `urlunparse`; empty query and fragment are dropped.
    let mut out = format!("{scheme}://{netloc}{path}");
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        out.push('?');
        out.push_str(&q);
    }
    if let Some(f) = parsed.fragment.filter(|f| !f.is_empty()) {
        out.push('#');
        out.push_str(&f);
    }
    let out = requote_uri(&out);
    let lower = out.to_lowercase();
    if !lower.starts_with("https://") && !lower.starts_with("http://") {
        return Err(UrlError(format!(
            "No connection adapters were found for {}",
            str_repr(&out)
        )));
    }
    Ok(out)
}

/// `str(value)` of a parameter as `urlencode` writes it.
pub fn param_bool(b: bool) -> String {
    if b { "True" } else { "False" }.to_string()
}

/// `_basic_auth_str(username, password)`; `None` when either is not
/// Latin-1 (the `UnicodeEncodeError` the caller swallows).
pub fn basic_auth(username: Option<&str>, password: Option<&str>) -> Option<String> {
    let user = latin1(username.unwrap_or("None"))?;
    let pass = latin1(password.unwrap_or("None"))?;
    let mut raw = user;
    raw.push(b':');
    raw.extend(pass);
    Some(format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    ))
}

fn latin1(s: &str) -> Option<Vec<u8>> {
    s.chars().map(|c| u8::try_from(u32::from(c)).ok()).collect()
}

/// `Response.raise_for_status()`'s message, or `None` below 400 / from 600.
pub fn http_error(status: u16, reason: &str, url: &str) -> Option<String> {
    match status {
        400..=499 => Some(format!("{status} Client Error: {reason} for url: {url}")),
        500..=599 => Some(format!("{status} Server Error: {reason} for url: {url}")),
        _ => None,
    }
}

/// The scheme, host and port urllib3's pool reports in its errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// `https`?
    pub tls: bool,
    /// Host as in the URL (IPv6 without brackets).
    pub host: String,
    /// Port (the scheme's default if none).
    pub port: u16,
    /// `path_url`: path and query, no fragment.
    pub path_url: String,
}

/// `HTTPConnectionPool(host=…, port=…)` facts of a prepared URL.
pub fn origin(prepared: &str) -> Option<Origin> {
    let u = url::Url::parse(prepared).ok()?;
    let tls = u.scheme() == "https";
    let host = u
        .host_str()?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = u.port().unwrap_or(if tls { 443 } else { 80 });
    // From the prepared text (the `url` crate would re-normalize it).
    let after_scheme = prepared.split_once("://").map_or("", |(_, r)| r);
    let rest = after_scheme.find('/').map_or("/", |i| &after_scheme[i..]);
    let path_url = rest.split('#').next().unwrap_or("/").to_string();
    Some(Origin {
        tls,
        host,
        port,
        path_url,
    })
}

/// What kept a connection from being made (urllib3's `reason`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectFailure {
    /// `NewConnectionError`: the socket's `OSError` text.
    Refused(String),
    /// `NameResolutionError`: `getaddrinfo`'s text.
    Resolve(String),
    /// `ConnectTimeoutError`, after this many seconds.
    Timeout(u64),
}

/// A connection that could not be made, as `str(requests.ConnectionError)`
/// (or `ConnectTimeout`).
pub fn connection_error(origin: &Origin, failure: &ConnectFailure) -> String {
    let kind = if origin.tls { "HTTPS" } else { "HTTP" };
    let conn = format!("<urllib3.connection.{kind}Connection object at {OBJECT_ADDRESS}>");
    let cause = match failure {
        ConnectFailure::Refused(os) => format!(
            "NewConnectionError({})",
            str_repr(&format!(
                "{conn}: Failed to establish a new connection: {os}"
            ))
        ),
        ConnectFailure::Resolve(os) => format!(
            "NameResolutionError({})",
            str_repr(&format!(
                "{conn}: Failed to resolve {} ({os})",
                str_repr(&origin.host)
            ))
        ),
        ConnectFailure::Timeout(s) => format!(
            "ConnectTimeoutError({conn}, {})",
            str_repr(&format!(
                "Connection to {} timed out. (connect timeout={s})",
                origin.host
            ))
        ),
    };
    format!(
        "{kind}ConnectionPool(host={}, port={}): Max retries exceeded with url: {} (Caused by \
         {cause})",
        str_repr(&origin.host),
        origin.port,
        origin.path_url
    )
}

/// A read that took longer than the timeout.
pub fn read_timeout(origin: &Origin, seconds: u64) -> String {
    let kind = if origin.tls { "HTTPS" } else { "HTTP" };
    format!(
        "{kind}ConnectionPool(host={}, port={}): Read timed out. (read timeout={seconds})",
        str_repr(&origin.host),
        origin.port
    )
}

/// `Response.text`: the charset of the Content-Type, else Latin-1 for
/// `text/*`, UTF-8 for `application/json`, else (charset_normalizer's
/// guess in Python) UTF-8; undecodable bytes replaced.
pub fn decode_text(content_type: Option<&str>, body: &[u8]) -> String {
    let encoding = content_type.and_then(|ct| {
        let mut parts = ct.split(';');
        let mime = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
        let charset = parts.find_map(|p| {
            let (k, v) = p.split_once('=')?;
            (k.trim().eq_ignore_ascii_case("charset"))
                .then(|| v.trim().trim_matches(|c| c == '\'' || c == '"').to_string())
        });
        charset.or_else(|| {
            if mime.contains("text") {
                Some("iso-8859-1".into())
            } else if mime.contains("application/json") {
                Some("utf-8".into())
            } else {
                None
            }
        })
    });
    let norm = encoding
        .as_deref()
        .map(|e| e.to_ascii_lowercase().replace(['-', ' '], "_"));
    match norm.as_deref() {
        Some("iso_8859_1" | "iso8859_1" | "latin_1" | "latin1" | "l1" | "8859" | "cp819") => {
            body.iter().map(|b| char::from(*b)).collect()
        }
        _ => String::from_utf8_lossy(body).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn prepared_urls_match_requests() {
        let doc: Value = serde_json::from_str(include_str!("requests_vectors.json")).unwrap();
        let cases = doc["prepare_url"].as_array().unwrap();
        assert!(cases.len() > 50);
        for case in cases {
            let url = case["url"].as_str().unwrap();
            let params: Vec<(String, String)> = case["params"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    (
                        p[0].as_str().unwrap().to_string(),
                        p[1].as_str().unwrap().to_string(),
                    )
                })
                .collect();
            let got = prepare_url(url, &params);
            match case.get("prepared").and_then(Value::as_str) {
                Some(expected) => assert_eq!(got, Ok(expected.to_string()), "{url} {params:?}"),
                None => assert!(got.is_err(), "{url} {params:?}: {got:?}"),
            }
        }
    }

    #[test]
    fn basic_auth_matches_requests() {
        assert_eq!(
            basic_auth(None, Some("pä")).as_deref(),
            Some("Basic Tm9uZTpw5A==")
        );
        assert_eq!(basic_auth(Some("u"), Some("€")), None);
    }

    #[test]
    fn errors_read_as_requests_words_them() {
        let o = origin("http://127.0.0.1:1/x?a=1#f").unwrap();
        assert_eq!(
            connection_error(
                &o,
                &ConnectFailure::Refused("[Errno 111] Connection refused".into())
            ),
            "HTTPConnectionPool(host='127.0.0.1', port=1): Max retries exceeded with url: /x?a=1 \
             (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7f0000000000>: \
             Failed to establish a new connection: [Errno 111] Connection refused'))"
        );
        assert_eq!(
            http_error(404, "Not Found", "http://h/x").as_deref(),
            Some("404 Client Error: Not Found for url: http://h/x")
        );
        assert_eq!(http_error(302, "Found", "http://h/x"), None);
        assert_eq!(decode_text(Some("text/plain"), b"\xe4"), "ä");
        assert_eq!(decode_text(Some("application/xml"), "ä".as_bytes()), "ä");
    }
}
