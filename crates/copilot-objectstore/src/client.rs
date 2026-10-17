//! The S3 client: one [`Minio`] is one miniopy-async `Minio` instance (what
//! `create_session()` returns), over an aiohttp `RetryClient`.
//!
//! **Requests** go out as miniopy-async 1.23.5 builds them and aiohttp 3.13
//! sends them, path-style: the headers `_build_headers` adds (`Host`,
//! `User-Agent: MinIO (<system>; <machine>) miniopy-async/1.23.5`,
//! `Content-Length` when there is a body, `x-amz-content-sha256` — the body's
//! SHA-256 over HTTP, `UNSIGNED-PAYLOAD` plus `Content-MD5` over HTTPS —,
//! `x-amz-date`), SigV4 over all of them but `User-Agent` ([`crate::sigv4`]),
//! then aiohttp's own `Accept: */*`, `Accept-Encoding: gzip, deflate`,
//! `Content-Length: 0` for a body-less `PUT`/`POST`/`DELETE` and
//! `Content-Type: application/octet-stream` for a `PUT`/`POST` without one.
//! Without an access key requests are anonymous (no signature, `Content-MD5`
//! on bodies), as the library does.
//!
//! **Region discovery** is the library's: the first call on a bucket asks
//! `GET /<bucket>?location=` (signed for `us-east-1`) and caches the answer
//! in this instance only — Python builds a new client for every operation,
//! and the operations here do too ([`crate::ObjectStore::session`]).
//!
//! **Retries** are `aiohttp_retry`'s `ExponentialRetry(attempts=5,
//! factor=0.2)`: an answer with a status of 500 or more is asked again, up to
//! five times, after 0.02 s, 0.004 s, …; a transport error is never retried.
//! Timeouts are the library's: five minutes to connect, five minutes between
//! reads. Proxies are not used (aiohttp's `trust_env=False`); certificates are
//! verified against `SSL_CERT_FILE` when set, else the bundled Mozilla roots
//! (`certifi`).
//!
//! **Failures** are the library's exceptions with their texts
//! ([`crate::error`]): `S3Error` from an XML error body or, for a body-less
//! answer (`HEAD`), from the status (`NoSuchKey` / `NoSuchBucket` /
//! `AccessDenied` / …, with the `x-amz-request-id` and `x-amz-id-2`
//! headers); `InvalidResponseError` for a non-XML error answer;
//! `ServerError` for a status the library has no word for; aiohttp's
//! `Cannot connect to host …` for a refused connection.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use futures::StreamExt;
use md5::{Digest, Md5};

use copilot_auth::pyvalue::str_repr;
use copilot_upstream::py::PyExc;

use crate::endpoint::{self, Endpoint, QueryParams};
use crate::error::{MinioError, S3Error, utf8};
use crate::sigv4::{self, Credentials};
use crate::xml;

/// miniopy-async's version, in its `User-Agent`.
pub const LIBRARY_VERSION: &str = "1.23.5";
/// `MIN_PART_SIZE` (5 MiB): `fput_object` uploads anything larger in parts.
pub const MIN_PART_SIZE: usize = 5 * 1024 * 1024;
/// `MAX_MULTIPART_COUNT`.
pub const MAX_MULTIPART_COUNT: usize = 10_000;
/// `num_parallel_uploads`.
pub const PARALLEL_UPLOADS: usize = 3;
/// `ExponentialRetry(attempts=5)`.
pub const ATTEMPTS: u32 = 5;
/// `ClientTimeout(connect=300, sock_read=300)`.
pub const TIMEOUT: Duration = Duration::from_secs(300);
/// A listing that says it is truncated but never moves on would page for
/// ever in Python; this one stops here.
pub const MAX_LIST_PAGES: usize = 100_000;

const S3_NAMESPACE: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// `MinIO (<platform.system()>; <platform.machine()>) miniopy-async/1.23.5`.
pub fn user_agent() -> String {
    let system = match std::env::consts::OS {
        "linux" => "Linux",
        "macos" => "Darwin",
        "windows" => "Windows",
        "freebsd" => "FreeBSD",
        other => other,
    };
    let machine = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "arm64",
        ("windows", "x86_64") => "AMD64",
        (_, arch) => arch,
    };
    format!("MinIO ({system}; {machine}) miniopy-async/{LIBRARY_VERSION}")
}

/// A request body as `_build_headers` sees it.
#[derive(Debug, Clone)]
pub enum Body {
    /// `None`.
    None,
    /// `bytes` (truthy only when non-empty).
    Bytes(Vec<u8>),
    /// An open file (always truthy: its size is the `Content-Length`).
    File(Vec<u8>),
}

impl Body {
    fn data(&self) -> &[u8] {
        match self {
            Body::None => &[],
            Body::Bytes(b) | Body::File(b) => b,
        }
    }

    /// `if body:`.
    fn truthy(&self) -> bool {
        match self {
            Body::None => false,
            Body::Bytes(b) => !b.is_empty(),
            Body::File(_) => true,
        }
    }
}

/// `md5sum_hash`: base64 of the MD5 (`None` for no body).
pub fn md5_base64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(Md5::digest(data))
}

/// An answer, read whole.
#[derive(Debug, Clone)]
pub struct S3Response {
    /// Status.
    pub status: u16,
    /// Headers.
    pub headers: http::HeaderMap,
    /// Body (decoded from `gzip`/`deflate` as aiohttp does).
    pub body: Bytes,
}

impl S3Response {
    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
    }
}

/// `stat_object`'s `Object` (what the operations read of it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectStat {
    /// `size` (`Content-Length`).
    pub size: i64,
    /// `etag`.
    pub etag: String,
    /// `content_type`.
    pub content_type: Option<String>,
}

/// One listed name (`obj.object_name`): an object or a common prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// The name (URL-decoded).
    pub object_name: String,
    /// `size` (`None` for a prefix).
    pub size: Option<i64>,
    /// `last_modified` as listed (`None` for a prefix).
    pub last_modified: Option<String>,
}

/// What every client of one store shares.
#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) endpoint: Endpoint,
    pub(crate) credentials: Option<Credentials>,
    pub(crate) http: reqwest::Client,
    pub(crate) user_agent: String,
}

/// One client instance (`create_session()`): its own region cache.
#[derive(Debug)]
pub struct Minio {
    shared: Arc<Shared>,
    region_map: Mutex<HashMap<String, String>>,
}

/// `check_bucket_name(name, strict, s3_check=False)`.
pub fn check_bucket_name(name: &str, strict: bool) -> Result<(), MinioError> {
    // `re.match(...$)`: `$` also matches before a final newline.
    let full =
        |test: &dyn Fn(&str) -> bool| test(name) || name.strip_suffix('\n').is_some_and(test);
    let bucket_like = |s: &str, extra: &[u8], any_case: bool| {
        let b = s.as_bytes();
        let edge = |c: u8| {
            c.is_ascii_digit() || c.is_ascii_lowercase() || (any_case && c.is_ascii_uppercase())
        };
        (3..=63).contains(&b.len())
            && edge(b[0])
            && edge(b[b.len() - 1])
            && b[1..b.len() - 1]
                .iter()
                .all(|&c| edge(c) || extra.contains(&c))
    };
    let ok = if strict {
        full(&|s| bucket_like(s, b".-", false))
    } else {
        full(&|s| bucket_like(s, b"_.-:", true))
    };
    if !ok {
        return Err(MinioError::value(format!("invalid bucket name {name}")));
    }
    let octet = |s: &str| {
        !s.is_empty()
            && s.len() <= 3
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s.len() == 1 || !s.starts_with('0'))
            && s.parse::<u16>().is_ok_and(|n| n <= 255)
    };
    let ipv4 = |s: &str| {
        let parts: Vec<&str> = s.split('.').collect();
        parts.len() == 4 && parts.iter().all(|p| octet(p))
    };
    if full(&ipv4) {
        return Err(MinioError::value(format!(
            "bucket name {name} must not be formatted as an IP address"
        )));
    }
    if ["..", ".-", "-."].iter().any(|x| name.contains(x)) {
        return Err(MinioError::value(format!(
            "bucket name {name} contains invalid successive characters"
        )));
    }
    if name.ends_with("-s3alias") || name.ends_with("--ol-s3") {
        return Err(MinioError::value(format!(
            "bucket name {name} must not start with 'xn--' and must not end with '--s3alias' \
             or '--ol-s3'"
        )));
    }
    Ok(())
}

/// `check_object_name`.
pub fn check_object_name(name: &str) -> Result<(), MinioError> {
    if copilot_web::form::py_strip(name).is_empty() {
        return Err(MinioError::value(""));
    }
    if name.split('/').any(|t| t == "." || t == "..") {
        return Err(MinioError::value(
            "object name with '.' or '..' path segment is not supported",
        ));
    }
    Ok(())
}

/// `time.from_http_header`: does the value parse?
fn http_date_ok(value: &str) -> bool {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    let (Some(day), Some(sep), Some(rest)) = (value.get(..3), value.get(3..5), value.get(5..))
    else {
        return false;
    };
    if value.len() != 29 || !DAYS.contains(&day) || sep != ", " {
        return false;
    }
    chrono::NaiveDateTime::parse_from_str(rest, "%d %b %Y %H:%M:%S GMT").is_ok_and(|t| {
        use chrono::Datelike;
        DAYS.get(t.weekday().num_days_from_monday() as usize) == Some(&day)
    })
}

/// `time.from_iso8601utc`: does the value parse?
fn iso_ok(value: &str) -> bool {
    chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.fZ").is_ok()
        || chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%SZ").is_ok()
}

fn int_text(value: &str) -> Option<i64> {
    let t = copilot_web::form::py_strip(value).replace('_', "");
    t.parse::<i64>().ok()
}

fn address_text(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(a) => format!("({}, {})", str_repr(&a.ip().to_string()), a.port()),
        SocketAddr::V6(a) => format!(
            "({}, {}, {}, {})",
            str_repr(&a.ip().to_string()),
            a.port(),
            a.flowinfo(),
            a.scope_id()
        ),
    }
}

fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut source = e.source();
    while let Some(s) = source {
        parts.push(s.to_string());
        source = s.source();
    }
    parts.join(": ")
}

impl Minio {
    pub(crate) fn new(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            region_map: Mutex::new(HashMap::new()),
        }
    }

    fn cached_region(&self, bucket: &str) -> Option<String> {
        self.region_map.lock().ok()?.get(bucket).cloned()
    }

    fn set_region(&self, bucket: &str, region: &str) {
        if let Ok(mut map) = self.region_map.lock() {
            map.insert(bucket.to_string(), region.to_string());
        }
    }

    fn forget_region(&self, bucket: &str) {
        if let Ok(mut map) = self.region_map.lock() {
            map.remove(bucket);
        }
    }

    fn connector_error(&self, strerror: &str) -> MinioError {
        let e = &self.shared.endpoint;
        MinioError::Py(PyExc::Other(
            if strerror == "Name or service not known" {
                "ClientConnectorDNSError"
            } else {
                "ClientConnectorError"
            },
            format!(
                "Cannot connect to host {}:{} ssl:default [{strerror}]",
                e.host, e.port
            ),
        ))
    }

    /// The addresses aiohttp would connect to (for the refused-connection
    /// text), or its DNS error.
    async fn resolve(&self) -> Result<Vec<SocketAddr>, MinioError> {
        let e = &self.shared.endpoint;
        if let Ok(ip) = e.host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, e.port)]);
        }
        match tokio::net::lookup_host((e.host.as_str(), e.port)).await {
            Ok(addrs) => Ok(addrs.collect()),
            Err(err) => {
                let text = err.to_string();
                let reason = text
                    .strip_prefix("failed to lookup address information: ")
                    .unwrap_or(&text)
                    .to_string();
                Err(self.connector_error(&reason))
            }
        }
    }

    fn transport_error(&self, e: &reqwest::Error, addrs: &[SocketAddr]) -> MinioError {
        let chain = error_chain(e);
        if e.is_connect() {
            if chain.contains("Address family not supported") {
                return self.connector_error("Address family not supported by protocol");
            }
            if chain.contains("certificate") || chain.contains("InvalidCertificate") {
                return MinioError::Py(PyExc::Other(
                    "ClientConnectorCertificateError",
                    format!(
                        "Cannot connect to host {}:{} ssl:True [SSLCertVerificationError: {chain}]",
                        self.shared.endpoint.host, self.shared.endpoint.port
                    ),
                ));
            }
            let addr = addrs
                .first()
                .copied()
                .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], self.shared.endpoint.port)));
            return self.connector_error(&format!("Connect call failed {}", address_text(&addr)));
        }
        if e.is_timeout() {
            return MinioError::Py(PyExc::Other(
                "SocketTimeoutError",
                "Timeout on reading data from socket".into(),
            ));
        }
        if chain.contains("connection closed before message completed")
            || chain.contains("IncompleteMessage")
            || chain.contains("connection reset")
        {
            return MinioError::Py(PyExc::Other(
                "ServerDisconnectedError",
                "Server disconnected".into(),
            ));
        }
        MinioError::Py(PyExc::Other("ClientError", chain))
    }

    /// One HTTP exchange (aiohttp's `request` through `RetryClient`).
    async fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &Body,
    ) -> Result<S3Response, MinioError> {
        let addrs = self.resolve().await?;
        let method_value = http::Method::from_bytes(method.as_bytes())
            .map_err(|_| MinioError::value(format!("invalid method {method}")))?;
        let mut header_map = http::HeaderMap::new();
        for (name, value) in headers {
            if value.contains(['\r', '\n']) {
                return Err(MinioError::value(
                    "Newline or carriage return character detected in HTTP status message or \
                     header. This is a potential security issue.",
                ));
            }
            let name = http::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| MinioError::value(format!("invalid header name {name}")))?;
            let value = http::HeaderValue::from_bytes(value.as_bytes())
                .map_err(|_| MinioError::value(format!("invalid header value {value}")))?;
            header_map.append(name, value);
        }
        let data = body.data().to_vec();
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut request = self
                .shared
                .http
                .request(method_value.clone(), url)
                .headers(header_map.clone());
            if !matches!(body, Body::None) || matches!(method, "PUT" | "POST" | "DELETE" | "PATCH")
            {
                request = request.body(data.clone());
            }
            let response = request
                .send()
                .await
                .map_err(|e| self.transport_error(&e, &addrs))?;
            let status = response.status().as_u16();
            if status >= 500 && attempt < ATTEMPTS {
                drop(response);
                let wait = 0.1 * 0.2_f64.powi(i32::try_from(attempt).unwrap_or(1));
                tokio::time::sleep(Duration::from_secs_f64(wait.min(30.0))).await;
                continue;
            }
            let response_headers = response.headers().clone();
            let raw = response
                .bytes()
                .await
                .map_err(|e| self.transport_error(&e, &addrs))?;
            let body = decode_content(&response_headers, raw)?;
            return Ok(S3Response {
                status,
                headers: response_headers,
                body,
            });
        }
    }

    /// `_build_headers` + `sign_v4_s3` + what aiohttp adds.
    fn build_headers(
        &self,
        method: &str,
        path: &str,
        query: &str,
        region: &str,
        passed: Vec<(String, String)>,
        body: &Body,
    ) -> Vec<(String, String)> {
        let mut headers = passed;
        let md5_added = headers.iter().any(|(k, _)| k == "Content-MD5");
        headers.push(("Host".into(), self.shared.endpoint.netloc.clone()));
        headers.push(("User-Agent".into(), self.shared.user_agent.clone()));
        if body.truthy() {
            headers.push(("Content-Length".into(), body.data().len().to_string()));
        }
        let md5_value = |b: &Body| match b {
            Body::None => None,
            other => Some(md5_base64(other.data())),
        };
        let (sha256, md5sum) = match &self.shared.credentials {
            Some(_) if self.shared.endpoint.https => (
                Some("UNSIGNED-PAYLOAD".to_string()),
                if md5_added { None } else { md5_value(body) },
            ),
            Some(_) => (Some(sigv4::sha256_hex(body.data())), None),
            None => (None, if md5_added { None } else { md5_value(body) }),
        };
        if let Some(m) = md5sum {
            headers.push(("Content-MD5".into(), m));
        }
        if let Some(s) = &sha256 {
            headers.push(("x-amz-content-sha256".into(), s.clone()));
        }
        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        headers.push(("x-amz-date".into(), amz_date.clone()));
        if let Some(creds) = &self.shared.credentials {
            let auth = sigv4::authorization(
                method,
                path,
                query,
                region,
                &headers,
                creds,
                sha256.as_deref().unwrap_or_default(),
                &amz_date,
            );
            headers.push(("Authorization".into(), auth));
        }
        // aiohttp's own headers, unsigned.
        headers.push(("Accept".into(), "*/*".into()));
        headers.push(("Accept-Encoding".into(), "gzip, deflate".into()));
        let has = |h: &[(String, String)], name: &str| {
            h.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
        };
        if matches!(body, Body::None)
            && !matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE")
            && !has(&headers, "content-length")
        {
            headers.push(("Content-Length".into(), "0".into()));
        }
        if matches!(method, "PUT" | "POST" | "PATCH") && !has(&headers, "content-type") {
            headers.push(("Content-Type".into(), "application/octet-stream".into()));
        }
        headers
    }

    /// `_handle_redirect_response`.
    fn redirect_words(
        &self,
        method: &str,
        bucket: Option<&str>,
        response: &S3Response,
        retry: bool,
    ) -> (Option<String>, Option<String>) {
        let (code, message) = match response.status {
            301 => ("PermanentRedirect", "Moved Permanently"),
            307 => ("Redirect", "Temporary redirect"),
            400 => ("BadRequest", "Bad request"),
            _ => return (None, None),
        };
        let region = response.header("x-amz-bucket-region");
        let mut message = message.to_string();
        if let Some(r) = region.as_deref().filter(|r| !r.is_empty()) {
            message = format!("{message}; use region {r}");
        }
        if retry
            && region.as_deref().is_some_and(|r| !r.is_empty())
            && method == "HEAD"
            && bucket.is_some_and(|b| {
                !b.is_empty() && self.cached_region(b).is_some_and(|r| !r.is_empty())
            })
        {
            return (Some("RetryHead".into()), None);
        }
        (Some(code.into()), Some(message))
    }

    /// `_url_open`.
    #[allow(clippy::too_many_arguments)]
    async fn url_open(
        &self,
        method: &str,
        region: &str,
        bucket: Option<&str>,
        object: Option<&str>,
        body: &Body,
        headers: Vec<(String, String)>,
        query: &QueryParams,
    ) -> Result<S3Response, MinioError> {
        if let Some(reason) = &self.shared.endpoint.unsupported {
            return Err(MinioError::value(reason.clone()));
        }
        let (path, query_string) = endpoint::build(bucket, object, query);
        let headers = self.build_headers(method, &path, &query_string, region, headers, body);
        let scheme = if self.shared.endpoint.https {
            "https"
        } else {
            "http"
        };
        let url = if query_string.is_empty() {
            format!("{scheme}://{}{path}", self.shared.endpoint.netloc)
        } else {
            format!(
                "{scheme}://{}{path}?{query_string}",
                self.shared.endpoint.netloc
            )
        };
        let response = self.send(method, &url, &headers, body).await?;
        if matches!(response.status, 200 | 204 | 206) {
            return Ok(response);
        }
        let content_type = response.header("content-type");
        let is_xml = content_type
            .as_deref()
            .unwrap_or_default()
            .split(';')
            .any(|t| t == "application/xml");
        let data = &response.body;
        if method != "HEAD" && !is_xml {
            if response.status == 304 && data.is_empty() {
                return Err(MinioError::Py(PyExc::Other(
                    "ServerError",
                    format!("server failed with HTTP status code {}", response.status),
                )));
            }
            let body_text = if data.is_empty() {
                "None".to_string()
            } else {
                utf8(data)?
            };
            return Err(MinioError::Py(PyExc::Other(
                "InvalidResponseError",
                format!(
                    "non-XML response from server; Response code: {}, Content-Type: {}, Body: {body_text}",
                    response.status,
                    content_type.as_deref().unwrap_or("None")
                ),
            )));
        }
        if data.is_empty() && method != "HEAD" {
            return Err(MinioError::Py(PyExc::Other(
                "InvalidResponseError",
                format!(
                    "non-XML response from server; Response code: {}, Content-Type: {}, Body: None",
                    response.status,
                    content_type.as_deref().unwrap_or("None")
                ),
            )));
        }
        let error = if !data.is_empty() {
            let text = utf8(data)?;
            let doc = xml::parse(&text).map_err(|e| PyExc::Other("ParseError", e))?;
            S3Error {
                code: doc.findtext("Code"),
                message: doc.findtext("Message"),
                resource: doc.findtext("Resource"),
                request_id: doc.findtext("RequestId"),
                host_id: doc.findtext("HostId"),
                bucket_name: doc.findtext("BucketName"),
                object_name: doc.findtext("Key"),
                unretried: None,
            }
        } else {
            let mut unretried = None;
            let (code, message) = match response.status {
                301 | 307 | 400 => {
                    let words = self.redirect_words(method, bucket, &response, true);
                    if words.0.as_deref() == Some("RetryHead") {
                        unretried = Some(self.redirect_words(method, bucket, &response, false));
                    }
                    words
                }
                403 => (Some("AccessDenied".into()), Some("Access denied".into())),
                404 => {
                    if object.is_some_and(|o| !o.is_empty()) {
                        (
                            Some("NoSuchKey".into()),
                            Some("Object does not exist".into()),
                        )
                    } else if bucket.is_some_and(|b| !b.is_empty()) {
                        (
                            Some("NoSuchBucket".into()),
                            Some("Bucket does not exist".into()),
                        )
                    } else {
                        (
                            Some("ResourceNotFound".into()),
                            Some("Request resource not found".into()),
                        )
                    }
                }
                405 | 501 => (
                    Some("MethodNotAllowed".into()),
                    Some("The specified method is not allowed against this resource".into()),
                ),
                409 => {
                    if bucket.is_some_and(|b| !b.is_empty()) {
                        (
                            Some("NoSuchBucket".into()),
                            Some("Bucket does not exist".into()),
                        )
                    } else {
                        (
                            Some("ResourceConflict".into()),
                            Some("Request resource conflicts".into()),
                        )
                    }
                }
                _ => (None, None),
            };
            if code.is_none() {
                return Err(MinioError::Py(PyExc::Other(
                    "ServerError",
                    format!("server failed with HTTP status code {}", response.status),
                )));
            }
            S3Error {
                code,
                message,
                resource: Some(path.clone()),
                request_id: response.header("x-amz-request-id"),
                host_id: response.header("x-amz-id-2"),
                bucket_name: bucket.map(str::to_string),
                object_name: object.map(str::to_string),
                unretried,
            }
        };
        if matches!(error.code.as_deref(), Some("NoSuchBucket" | "RetryHead")) {
            if let Some(b) = bucket {
                self.forget_region(b);
            }
        }
        Err(MinioError::S3(Box::new(error)))
    }

    /// `_get_region`.
    async fn get_region(&self, bucket: Option<&str>) -> Result<String, MinioError> {
        let Some(bucket) = bucket.filter(|b| !b.is_empty()) else {
            return Ok("us-east-1".into());
        };
        if self.shared.credentials.is_none() {
            return Ok("us-east-1".into());
        }
        if let Some(region) = self.cached_region(bucket).filter(|r| !r.is_empty()) {
            return Ok(region);
        }
        let response = self
            .url_open(
                "GET",
                "us-east-1",
                Some(bucket),
                None,
                &Body::None,
                Vec::new(),
                &vec![("location".into(), vec![String::new()])],
            )
            .await?;
        let text = utf8(&response.body)?;
        let doc = xml::parse(&text).map_err(|e| PyExc::Other("ParseError", e))?;
        let region = match doc.text.as_deref() {
            None | Some("") => "us-east-1".to_string(),
            Some("EU") => "eu-west-1".to_string(),
            Some(other) => other.to_string(),
        };
        self.set_region(bucket, &region);
        Ok(region)
    }

    /// `_execute`: the region, then the request, retried once on
    /// `RetryHead`.
    async fn execute(
        &self,
        method: &str,
        bucket: Option<&str>,
        object: Option<&str>,
        body: &Body,
        headers: Vec<(String, String)>,
        query: &QueryParams,
    ) -> Result<S3Response, MinioError> {
        let region = self.get_region(bucket).await?;
        match self
            .url_open(
                method,
                &region,
                bucket,
                object,
                body,
                headers.clone(),
                query,
            )
            .await
        {
            Err(MinioError::S3(e)) if e.code.as_deref() == Some("RetryHead") => {}
            other => return other,
        }
        match self
            .url_open(method, &region, bucket, object, body, headers, query)
            .await
        {
            Err(MinioError::S3(e)) if e.code.as_deref() == Some("RetryHead") => {
                // `exc.copy(*_handle_redirect_response(method, bucket, exc.response))`.
                let (code, message) = e.unretried.clone().unwrap_or((None, None));
                Err(MinioError::S3(Box::new(e.copy(code, message))))
            }
            other => other,
        }
    }

    /// `bucket_exists`.
    pub async fn bucket_exists(&self, bucket: &str) -> Result<bool, MinioError> {
        check_bucket_name(bucket, false)?;
        match self
            .execute(
                "HEAD",
                Some(bucket),
                None,
                &Body::None,
                Vec::new(),
                &Vec::new(),
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(e) if e.code() == Some("NoSuchBucket") => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// `make_bucket(bucket)` (no location, no object lock).
    pub async fn make_bucket(&self, bucket: &str) -> Result<(), MinioError> {
        check_bucket_name(bucket, true)?;
        let location = "us-east-1";
        self.url_open(
            "PUT",
            location,
            Some(bucket),
            None,
            &Body::None,
            Vec::new(),
            &Vec::new(),
        )
        .await?;
        self.set_region(bucket, location);
        Ok(())
    }

    /// `_put_object`: the ETag.
    async fn put(
        &self,
        bucket: &str,
        object: &str,
        body: &Body,
        headers: Vec<(String, String)>,
        query: &QueryParams,
    ) -> Result<String, MinioError> {
        let response = self
            .execute("PUT", Some(bucket), Some(object), body, headers, query)
            .await?;
        Ok(response.header("etag").unwrap_or_default().replace('"', ""))
    }

    /// `fput_object(bucket, object, <file holding data>, content_type)`:
    /// one `PUT` up to 5 MiB, a multipart upload (three parts at a time)
    /// above.
    pub async fn fput_object(
        &self,
        bucket: &str,
        object: &str,
        data: &[u8],
        content_type: Option<&str>,
    ) -> Result<(), MinioError> {
        check_bucket_name(bucket, false)?;
        check_object_name(object)?;
        let content_type = content_type
            .filter(|c| !c.is_empty())
            .unwrap_or("application/octet-stream")
            .to_string();
        let headers = vec![("Content-Type".to_string(), content_type.clone())];
        if data.is_empty() {
            self.put(
                bucket,
                object,
                &Body::File(Vec::new()),
                headers,
                &Vec::new(),
            )
            .await?;
            return Ok(());
        }
        let length = data.len();
        let part_size =
            length.div_ceil(MAX_MULTIPART_COUNT).div_ceil(MIN_PART_SIZE) * MIN_PART_SIZE;
        let part_count = length.div_ceil(part_size);
        if part_count == 1 {
            self.put(
                bucket,
                object,
                &Body::Bytes(data.to_vec()),
                headers,
                &Vec::new(),
            )
            .await?;
            return Ok(());
        }
        let upload_id = self
            .create_multipart_upload(bucket, object, headers)
            .await?;
        let result = self
            .upload_parts(bucket, object, data, part_size, part_count, &upload_id)
            .await;
        let result = match result {
            Ok(parts) => {
                self.complete_multipart_upload(bucket, object, &upload_id, &parts)
                    .await
            }
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            self.execute(
                "DELETE",
                Some(bucket),
                Some(object),
                &Body::None,
                Vec::new(),
                &vec![("uploadId".into(), vec![upload_id.clone()])],
            )
            .await?;
            return Err(e);
        }
        Ok(())
    }

    async fn create_multipart_upload(
        &self,
        bucket: &str,
        object: &str,
        headers: Vec<(String, String)>,
    ) -> Result<String, MinioError> {
        let response = self
            .execute(
                "POST",
                Some(bucket),
                Some(object),
                &Body::None,
                headers,
                &vec![("uploads".into(), vec![String::new()])],
            )
            .await?;
        let text = utf8(&response.body)?;
        let doc = xml::parse(&text).map_err(|e| PyExc::Other("ParseError", e))?;
        doc.findtext_strict("UploadId").map_err(MinioError::value)
    }

    async fn upload_parts(
        &self,
        bucket: &str,
        object: &str,
        data: &[u8],
        part_size: usize,
        part_count: usize,
        upload_id: &str,
    ) -> Result<Vec<(usize, String)>, MinioError> {
        let uploads = futures::stream::iter((1..=part_count).map(|number| {
            let start = (number - 1) * part_size;
            let end = if number == part_count {
                data.len()
            } else {
                start + part_size
            };
            let chunk = data[start..end].to_vec();
            async move {
                let query = vec![
                    ("partNumber".to_string(), vec![number.to_string()]),
                    ("uploadId".to_string(), vec![upload_id.to_string()]),
                ];
                self.put(bucket, object, &Body::Bytes(chunk), Vec::new(), &query)
                    .await
                    .map(|etag| (number, etag))
            }
        }))
        .buffer_unordered(PARALLEL_UPLOADS);
        futures::pin_mut!(uploads);
        let mut parts = Vec::with_capacity(part_count);
        while let Some(result) = uploads.next().await {
            parts.push(result?);
        }
        parts.sort_by_key(|(n, _)| *n);
        Ok(parts)
    }

    async fn complete_multipart_upload(
        &self,
        bucket: &str,
        object: &str,
        upload_id: &str,
        parts: &[(usize, String)],
    ) -> Result<(), MinioError> {
        let mut body = format!("<CompleteMultipartUpload xmlns=\"{S3_NAMESPACE}\">");
        for (number, etag) in parts {
            body.push_str(&format!(
                "<Part><PartNumber>{number}</PartNumber><ETag>{}</ETag></Part>",
                et_escape(&format!("\"{etag}\""))
            ));
        }
        body.push_str("</CompleteMultipartUpload>");
        let body = body.into_bytes();
        let headers = vec![
            ("Content-Type".to_string(), "application/xml".to_string()),
            ("Content-MD5".to_string(), md5_base64(&body)),
        ];
        let response = self
            .execute(
                "POST",
                Some(bucket),
                Some(object),
                &Body::Bytes(body),
                headers,
                &vec![("uploadId".into(), vec![upload_id.to_string()])],
            )
            .await?;
        let text = utf8(&response.body)?;
        xml::parse(&text).map_err(|e| PyExc::Other("ParseError", e))?;
        Ok(())
    }

    /// `stat_object`.
    pub async fn stat_object(&self, bucket: &str, object: &str) -> Result<ObjectStat, MinioError> {
        check_bucket_name(bucket, false)?;
        check_object_name(object)?;
        let response = self
            .execute(
                "HEAD",
                Some(bucket),
                Some(object),
                &Body::None,
                Vec::new(),
                &Vec::new(),
            )
            .await?;
        if let Some(lm) = response.header("last-modified") {
            if !http_date_ok(&lm) {
                return Err(MinioError::value(format!(
                    "time data {lm} does not match HTTP header format"
                )));
            }
        }
        let length = response
            .header("content-length")
            .unwrap_or_else(|| "0".into());
        let size = int_text(&length).ok_or_else(|| {
            MinioError::value(format!(
                "invalid literal for int() with base 10: {}",
                str_repr(&length)
            ))
        })?;
        Ok(ObjectStat {
            size,
            etag: response.header("etag").unwrap_or_default().replace('"', ""),
            content_type: response.header("content-type"),
        })
    }

    /// `get_object(bucket, object, offset)` read whole. `range` is the
    /// `Range` header the call sends: the data store passes an aiohttp
    /// session where the library takes `offset`, so Python asks for
    /// `bytes=<aiohttp.client.ClientSession object at 0x…>-`, which MinIO
    /// ignores ([`SESSION_AS_OFFSET_RANGE`]).
    pub async fn get_object(
        &self,
        bucket: &str,
        object: &str,
        range: Option<&str>,
    ) -> Result<Bytes, MinioError> {
        check_bucket_name(bucket, false)?;
        check_object_name(object)?;
        let headers = range
            .map(|r| vec![("Range".to_string(), r.to_string())])
            .unwrap_or_default();
        let response = self
            .execute(
                "GET",
                Some(bucket),
                Some(object),
                &Body::None,
                headers,
                &Vec::new(),
            )
            .await?;
        Ok(response.body)
    }

    /// `remove_object`.
    pub async fn remove_object(&self, bucket: &str, object: &str) -> Result<(), MinioError> {
        check_bucket_name(bucket, false)?;
        check_object_name(object)?;
        self.execute(
            "DELETE",
            Some(bucket),
            Some(object),
            &Body::None,
            Vec::new(),
            &Vec::new(),
        )
        .await?;
        Ok(())
    }

    /// `list_buckets()`: the names of every bucket the credentials see, as
    /// `ListAllMyBucketsResult.fromxml` reads them (a missing `<Buckets>` or
    /// `<Name>` and a `CreationDate` `from_iso8601utc` refuses are its
    /// `ValueError`s).
    pub async fn list_buckets(&self) -> Result<Vec<String>, MinioError> {
        let response = self
            .execute("GET", None, None, &Body::None, Vec::new(), &Vec::new())
            .await?;
        let text = utf8(&response.body)?;
        let doc = xml::parse(&text).map_err(|e| PyExc::Other("ParseError", e))?;
        let buckets = doc
            .find("Buckets")
            .ok_or_else(|| MinioError::value("XML element <Buckets> not found"))?;
        let mut names = Vec::new();
        for bucket in buckets.findall("Bucket") {
            let name = bucket.findtext_strict("Name").map_err(MinioError::value)?;
            if let Some(created) = bucket.findtext("CreationDate").filter(|c| !c.is_empty()) {
                if !iso_ok(&created) {
                    return Err(MinioError::value(format!(
                        "time data {} does not match format '%Y-%m-%dT%H:%M:%SZ'",
                        str_repr(&created)
                    )));
                }
            }
            names.push(name);
        }
        Ok(names)
    }

    /// `list_objects(bucket, prefix, recursive)`, every page (ListObjectsV2,
    /// `encoding-type=url`, 1000 keys a page).
    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        recursive: bool,
    ) -> Result<Vec<Listed>, MinioError> {
        check_bucket_name(bucket, false)?;
        let mut continuation: Option<String> = None;
        let mut out = Vec::new();
        for _ in 0..MAX_LIST_PAGES {
            let mut query: QueryParams = vec![("list-type".into(), vec!["2".into()])];
            // `_list_objects` reuses its `start_after` for the parsed token, so
            // every later page also asks `start-after=<token>`.
            if let Some(token) = continuation.as_ref().filter(|t| !t.is_empty()) {
                query.push(("continuation-token".into(), vec![token.clone()]));
                query.push(("start-after".into(), vec![token.clone()]));
            }
            query.push((
                "delimiter".into(),
                vec![if recursive { String::new() } else { "/".into() }],
            ));
            query.push(("encoding-type".into(), vec!["url".into()]));
            query.push(("max-keys".into(), vec!["1000".into()]));
            query.push((
                "prefix".into(),
                vec![prefix.unwrap_or_default().to_string()],
            ));
            let response = self
                .execute("GET", Some(bucket), None, &Body::None, Vec::new(), &query)
                .await?;
            let text = utf8(&response.body)?;
            let (objects, truncated, token) = parse_list(&text)?;
            out.extend(objects);
            if !truncated {
                return Ok(out);
            }
            continuation = token;
        }
        Ok(out)
    }
}

/// `parse_list_objects`: the names in the order the library yields them,
/// whether the listing is truncated, and the next continuation token.
fn parse_list(text: &str) -> Result<(Vec<Listed>, bool, Option<String>), MinioError> {
    let doc = xml::parse(text).map_err(|e| PyExc::Other("ParseError", e))?;
    doc.findtext_strict("Name").map_err(MinioError::value)?;
    let url = doc.findtext("EncodingType").as_deref() == Some("url");
    let decode = |s: String| {
        if url {
            copilot_web::form::unquote_plus(&s)
        } else {
            s
        }
    };
    let mut objects = Vec::new();
    let from_xml = |e: &xml::Element| -> Result<Listed, MinioError> {
        let last_modified = e.findtext("LastModified");
        if let Some(lm) = &last_modified {
            if !iso_ok(lm) {
                return Err(MinioError::value(format!(
                    "time data {} does not match format '%Y-%m-%dT%H:%M:%SZ'",
                    str_repr(lm)
                )));
            }
        }
        let size = match e.findtext("Size") {
            None => None,
            Some(s) => Some(int_text(&s).ok_or_else(|| {
                MinioError::value(format!(
                    "invalid literal for int() with base 10: {}",
                    str_repr(&s)
                ))
            })?),
        };
        let key = e.findtext_strict("Key").map_err(MinioError::value)?;
        Ok(Listed {
            object_name: decode(key),
            size,
            last_modified,
        })
    };
    for c in doc.findall("Contents") {
        objects.push(from_xml(c)?);
    }
    let marker = objects.last().map(|o| o.object_name.clone());
    for v in doc.findall("Version") {
        objects.push(from_xml(v)?);
    }
    for p in doc.findall("CommonPrefixes") {
        let prefix = p.findtext_strict("Prefix").map_err(MinioError::value)?;
        objects.push(Listed {
            object_name: decode(prefix),
            size: None,
            last_modified: None,
        });
    }
    for d in doc.findall("DeleteMarker") {
        objects.push(from_xml(d)?);
    }
    let truncated = doc
        .findtext("IsTruncated")
        .unwrap_or_default()
        .to_lowercase()
        == "true";
    let key_marker = doc.findtext("NextKeyMarker").map(|k| {
        if url && !k.is_empty() {
            copilot_web::form::unquote_plus(&k)
        } else {
            k
        }
    });
    let mut token = doc.findtext("NextContinuationToken");
    if key_marker.is_some() {
        token = key_marker;
    }
    if token.is_none() {
        token = doc.findtext("NextMarker").map(|m| {
            if url && !m.is_empty() {
                copilot_web::form::unquote_plus(&m)
            } else {
                m
            }
        });
    }
    if token.is_none() && truncated {
        token = marker;
    }
    Ok((objects, truncated, token))
}

/// ElementTree's text escaping with `encoding=None` (us-ascii: other
/// characters as character references).
fn et_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c if c.is_ascii() => out.push(c),
            c => out.push_str(&format!("&#{};", u32::from(c))),
        }
    }
    out
}

/// The body as aiohttp hands it over: `gzip`/`deflate` decoded.
fn decode_content(headers: &http::HeaderMap, raw: Bytes) -> Result<Bytes, MinioError> {
    use std::io::Read;
    let encoding = headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let failed = || {
        MinioError::Py(PyExc::Other(
            "ClientPayloadError",
            format!("400, message='Can not decode content-encoding: {encoding}'"),
        ))
    };
    let mut out = Vec::new();
    match encoding.as_str() {
        "gzip" | "x-gzip" => {
            flate2::read::MultiGzDecoder::new(&raw[..])
                .read_to_end(&mut out)
                .map_err(|_| failed())?;
        }
        "deflate" => {
            let zlib = raw.len() >= 2
                && raw[0] & 0x0f == 8
                && (u16::from(raw[0]) * 256 + u16::from(raw[1])) % 31 == 0;
            let result = if zlib {
                flate2::read::ZlibDecoder::new(&raw[..]).read_to_end(&mut out)
            } else {
                flate2::read::DeflateDecoder::new(&raw[..]).read_to_end(&mut out)
            };
            result.map_err(|_| failed())?;
        }
        _ => return Ok(raw),
    }
    Ok(Bytes::from(out))
}

/// The `Range` header Python's data store sends with every download:
/// `get_object(bucket, object, session)` puts the aiohttp session where the
/// library takes `offset`. The object's address differs between any two
/// Python processes; this one is fixed (as `copilot-upstream` fixes
/// urllib3's).
pub const SESSION_AS_OFFSET_RANGE: &str =
    "bytes=<aiohttp.client.ClientSession object at 0x7f0000000000>-";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_names_are_checked_like_minio() {
        assert!(check_bucket_name("copilot-cases", true).is_ok());
        assert!(check_bucket_name("Copilot_Cases:x", false).is_ok());
        assert!(check_bucket_name("abc\n", false).is_ok());
        let text = |r: Result<(), MinioError>| r.unwrap_err().into_py().text();
        assert_eq!(
            text(check_bucket_name("ab", false)),
            "invalid bucket name ab"
        );
        assert_eq!(
            text(check_bucket_name("Abc", true)),
            "invalid bucket name Abc"
        );
        assert_eq!(
            text(check_bucket_name("192.168.1.1", false)),
            "bucket name 192.168.1.1 must not be formatted as an IP address"
        );
        assert_eq!(
            text(check_bucket_name("a..b", false)),
            "bucket name a..b contains invalid successive characters"
        );
        assert_eq!(
            text(check_bucket_name("bucket-s3alias", false)),
            "bucket name bucket-s3alias must not start with 'xn--' and must not end with \
             '--s3alias' or '--ol-s3'"
        );
        assert!(check_bucket_name("xn--abc", false).is_ok());
        assert_eq!(text(check_object_name("  ")), "");
        assert_eq!(
            text(check_object_name("a/../b")),
            "object name with '.' or '..' path segment is not supported"
        );
    }

    #[test]
    fn listings_parse_like_parse_list_objects() {
        let page = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult \
            xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>b</Name><Prefix></Prefix>\
            <EncodingType>url</EncodingType><IsTruncated>true</IsTruncated>\
            <NextContinuationToken>tok</NextContinuationToken><Contents><Key>a+b%2Bc</Key>\
            <LastModified>2026-01-02T03:04:05.000Z</LastModified><Size>3</Size></Contents>\
            <CommonPrefixes><Prefix>x%2F/</Prefix></CommonPrefixes></ListBucketResult>";
        let (objects, truncated, token) = parse_list(page).unwrap();
        let names: Vec<&str> = objects.iter().map(|o| o.object_name.as_str()).collect();
        assert_eq!(names, ["a b+c", "x//"]);
        assert!(truncated);
        assert_eq!(token.as_deref(), Some("tok"));
        assert!(parse_list("<ListBucketResult/>").is_err());
    }

    #[test]
    fn user_agent_names_the_library() {
        assert!(user_agent().starts_with("MinIO ("));
        assert!(user_agent().ends_with(") miniopy-async/1.23.5"));
        if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            assert_eq!(user_agent(), "MinIO (Linux; x86_64) miniopy-async/1.23.5");
        }
    }

    #[test]
    fn http_dates_and_part_sizes() {
        assert!(http_date_ok("Fri, 02 Jan 2026 03:04:05 GMT"));
        assert!(!http_date_ok("Mon, 02 Jan 2026 03:04:05 GMT"));
        assert!(!http_date_ok("garbage"));
        let length = MIN_PART_SIZE + 7;
        let part = length.div_ceil(MAX_MULTIPART_COUNT).div_ceil(MIN_PART_SIZE) * MIN_PART_SIZE;
        assert_eq!((part, length.div_ceil(part)), (MIN_PART_SIZE, 2));
        assert_eq!(et_escape("\"a&b\""), "\"a&amp;b\"");
    }
}
