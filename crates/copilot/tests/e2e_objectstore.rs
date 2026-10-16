//! End-to-end tests of the MinIO routes (`copilot-objectstore` and
//! `copilot-incidents`' datastore module): case files, case report
//! templates, `DELETE /case/{case_id}`, customer report download and delete,
//! and `/api/agent_data_store`, through the production router on a real
//! MySQL, MinIO replaced by an in-process S3 stand-in.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13310/copilot \
//!   cargo test -p copilot --test e2e_objectstore -- --test-threads=1
//! ```
//!
//! The stand-in listens on `OBJECTSTORE_E2E_S3_PORT` (default 5779) for the
//! whole run and also plays the legacy backend (paths under `/api/`);
//! `S3_CLOSED_PORT` (default 5778) is a port nothing listens on, for the
//! unreachable-MinIO checks. It keeps buckets in memory, answers the calls
//! the client makes (bucket location, head/create bucket, put/head/get/
//! delete object, multipart uploads, ListObjectsV2 two entries a page), and
//! recomputes every request's SigV4 signature from what arrived on the wire.
//! Python's side of the same requests is `rust_parity_objectstore_e2e.py`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use http::StatusCode;
use serde_json::{Value, json};

#[macro_use]
mod common;
use common::*;

mod s3 {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::{Arc, Mutex, OnceLock};

    use axum::body::Bytes;
    use axum::extract::DefaultBodyLimit;
    use axum::response::{IntoResponse, Response};
    use http::{HeaderMap, Method, StatusCode, Uri};

    use copilot_objectstore::sigv4::{self, Credentials};
    use copilot_objectstore::web::py_unquote;

    pub const ACCESS_KEY: &str = "e2e-minio";
    pub const SECRET_KEY: &str = "e2e-minio-secret";
    /// Entries per ListObjectsV2 page, so every listing pages.
    const PAGE: usize = 2;
    const NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

    /// One request as it arrived.
    #[derive(Debug, Clone)]
    pub struct Seen {
        pub method: String,
        pub path: String,
        pub query: String,
        pub user_agent: String,
        pub range: Option<String>,
        pub signature: &'static str,
    }

    struct Upload {
        bucket: String,
        key: String,
        content_type: String,
        parts: BTreeMap<u32, Vec<u8>>,
    }

    #[derive(Default)]
    struct State {
        buckets: BTreeMap<String, BTreeMap<String, (Vec<u8>, String)>>,
        uploads: HashMap<String, Upload>,
        /// `(method, decoded path)` answered 500 `InternalError`.
        failing: BTreeSet<(String, String)>,
        seen: Vec<Seen>,
        next_upload: u64,
    }

    pub struct StandIn {
        state: Mutex<State>,
    }

    static STANDIN: OnceLock<Arc<StandIn>> = OnceLock::new();

    pub fn port() -> u16 {
        std::env::var("OBJECTSTORE_E2E_S3_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(5779)
    }

    pub fn closed_port() -> u16 {
        std::env::var("S3_CLOSED_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(5778)
    }

    /// The stand-in, started on first use on a runtime of its own (each
    /// test has its own runtime, which ends with the test).
    pub fn get() -> Arc<StandIn> {
        STANDIN
            .get_or_init(|| {
                let standin = Arc::new(StandIn {
                    state: Mutex::new(State::default()),
                });
                for bucket in [
                    "copilot-cases",
                    "copilot-case-report-templates",
                    "velociraptor-artifacts",
                    "incident-management-reports",
                ] {
                    standin.make_bucket(bucket);
                }
                let listener =
                    std::net::TcpListener::bind(("127.0.0.1", port())).expect("bind the stand-in");
                listener.set_nonblocking(true).unwrap();
                let served = standin.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()
                        .unwrap();
                    rt.block_on(async move {
                        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                        let app = axum::Router::new()
                            .fallback(
                                move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| {
                                    let s = served.clone();
                                    async move { s.handle(&method, &uri, &headers, &body) }
                                },
                            )
                            .layer(DefaultBodyLimit::disable());
                        axum::serve(listener, app).await.unwrap();
                    });
                });
                standin
            })
            .clone()
    }

    impl StandIn {
        pub fn make_bucket(&self, bucket: &str) {
            self.state
                .lock()
                .unwrap()
                .buckets
                .entry(bucket.to_string())
                .or_default();
        }

        pub fn put(&self, bucket: &str, key: &str, data: &[u8], content_type: &str) {
            self.state
                .lock()
                .unwrap()
                .buckets
                .entry(bucket.to_string())
                .or_default()
                .insert(key.to_string(), (data.to_vec(), content_type.to_string()));
        }

        pub fn object(&self, bucket: &str, key: &str) -> Option<(Vec<u8>, String)> {
            self.state
                .lock()
                .unwrap()
                .buckets
                .get(bucket)
                .and_then(|b| b.get(key))
                .cloned()
        }

        pub fn fail(&self, method: &str, path: &str) {
            self.state
                .lock()
                .unwrap()
                .failing
                .insert((method.to_string(), path.to_string()));
        }

        pub fn heal(&self) {
            self.state.lock().unwrap().failing.clear();
        }

        /// The requests since the last call.
        pub fn take(&self) -> Vec<Seen> {
            std::mem::take(&mut self.state.lock().unwrap().seen)
        }

        fn handle(&self, method: &Method, uri: &Uri, headers: &HeaderMap, body: &[u8]) -> Response {
            let raw_path = uri.path().to_string();
            let raw_query = uri.query().unwrap_or("").to_string();
            if raw_path.starts_with("/api/") {
                // The legacy backend.
                return axum::Json(serde_json::json!({
                    "from": "python", "method": method.as_str(), "path": raw_path,
                }))
                .into_response();
            }
            let header = |name: &str| {
                headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            let signature = verify(method.as_str(), &raw_path, &raw_query, headers);
            let path = py_unquote(&raw_path);
            let mut state = self.state.lock().unwrap();
            state.seen.push(Seen {
                method: method.to_string(),
                path: path.clone(),
                query: raw_query.clone(),
                user_agent: header("user-agent").unwrap_or_default(),
                range: header("range"),
                signature,
            });
            let head = method == Method::HEAD;
            if state.failing.contains(&(method.to_string(), path.clone())) {
                return error(500, "InternalError", &path, None, None, head);
            }
            if signature != "ok" {
                return error(403, "SignatureDoesNotMatch", &path, None, None, head);
            }
            let sent = header("x-amz-content-sha256").unwrap_or_default();
            if sent != "UNSIGNED-PAYLOAD" && sent != sigv4::sha256_hex(body) {
                return error(400, "XAmzContentSHA256Mismatch", &path, None, None, head);
            }
            let query = parse_query(&raw_query);
            let (bucket, key) = match path[1..].split_once('/') {
                Some((b, k)) => (b.to_string(), k.to_string()),
                None => (path[1..].to_string(), String::new()),
            };
            if key.is_empty() {
                if method == Method::PUT && query.is_empty() {
                    if state.buckets.contains_key(&bucket) {
                        return error(
                            409,
                            "BucketAlreadyOwnedByYou",
                            &path,
                            Some(&bucket),
                            None,
                            false,
                        );
                    }
                    state.buckets.insert(bucket.clone(), BTreeMap::new());
                    return (StatusCode::OK, [("Location", format!("/{bucket}"))]).into_response();
                }
                let Some(objects) = state.buckets.get(&bucket) else {
                    return error(404, "NoSuchBucket", &path, Some(&bucket), None, head);
                };
                if method == Method::GET && query.contains_key("location") {
                    return xml(format!(
                        "<LocationConstraint xmlns=\"{NS}\"></LocationConstraint>"
                    ));
                }
                if head {
                    return StatusCode::OK.into_response();
                }
                if method == Method::GET && query.get("list-type").map(String::as_str) == Some("2")
                {
                    return xml(list_v2(&bucket, objects, &query));
                }
                return error(501, "NotImplemented", &path, Some(&bucket), None, false);
            }
            if !state.buckets.contains_key(&bucket) {
                return error(404, "NoSuchBucket", &path, Some(&bucket), None, head);
            }
            if method == Method::POST && query.contains_key("uploads") {
                state.next_upload += 1;
                let id = format!("upload{}", state.next_upload);
                state.uploads.insert(
                    id.clone(),
                    Upload {
                        bucket: bucket.clone(),
                        key: key.clone(),
                        content_type: header("content-type")
                            .unwrap_or_else(|| "application/octet-stream".into()),
                        parts: BTreeMap::new(),
                    },
                );
                return xml(format!(
                    "<InitiateMultipartUploadResult xmlns=\"{NS}\"><Bucket>{}</Bucket><Key>{}\
                     </Key><UploadId>{id}</UploadId></InitiateMultipartUploadResult>",
                    escape(&bucket),
                    escape(&key)
                ));
            }
            if let Some(id) = query.get("uploadId").cloned() {
                if !state.uploads.contains_key(&id) {
                    return error(404, "NoSuchUpload", &path, Some(&bucket), Some(&key), head);
                }
                if method == Method::PUT {
                    let number: u32 = query
                        .get("partNumber")
                        .and_then(|n| n.parse().ok())
                        .unwrap_or_default();
                    if let Some(up) = state.uploads.get_mut(&id) {
                        up.parts.insert(number, body.to_vec());
                    }
                    let etag = format!("\"{}\"", etag(body));
                    return (StatusCode::OK, [("ETag", etag)]).into_response();
                }
                if method == Method::DELETE {
                    state.uploads.remove(&id);
                    return StatusCode::NO_CONTENT.into_response();
                }
                let Some(up) = state.uploads.remove(&id) else {
                    return error(404, "NoSuchUpload", &path, Some(&bucket), Some(&key), false);
                };
                let listed = String::from_utf8_lossy(body).into_owned();
                let mut data = Vec::new();
                for chunk in listed.split("<PartNumber>").skip(1) {
                    let number: u32 = chunk
                        .split('<')
                        .next()
                        .and_then(|n| n.parse().ok())
                        .unwrap_or_default();
                    data.extend_from_slice(up.parts.get(&number).map_or(&[][..], |p| p));
                }
                state
                    .buckets
                    .entry(up.bucket.clone())
                    .or_default()
                    .insert(up.key.clone(), (data, up.content_type));
                return xml(format!(
                    "<CompleteMultipartUploadResult xmlns=\"{NS}\"><Bucket>{}</Bucket><Key>{}</Key>\
                     <ETag>&#34;0-1&#34;</ETag></CompleteMultipartUploadResult>",
                    escape(&up.bucket),
                    escape(&up.key)
                ));
            }
            let objects = state.buckets.entry(bucket.clone()).or_default();
            if method == Method::PUT {
                let content_type =
                    header("content-type").unwrap_or_else(|| "binary/octet-stream".into());
                let etag = format!("\"{}\"", etag(body));
                objects.insert(key, (body.to_vec(), content_type));
                return (StatusCode::OK, [("ETag", etag)]).into_response();
            }
            if method == Method::DELETE {
                objects.remove(&key);
                return StatusCode::NO_CONTENT.into_response();
            }
            let Some((data, content_type)) = objects.get(&key).cloned() else {
                return error(404, "NoSuchKey", &path, Some(&bucket), Some(&key), head);
            };
            let etag = format!("\"{}\"", etag(&data));
            let meta = [
                ("Content-Type", content_type),
                ("ETag", etag),
                ("Last-Modified", "Fri, 02 Jan 2026 03:04:05 GMT".to_string()),
            ];
            if head {
                return (
                    StatusCode::OK,
                    meta,
                    [("Content-Length", data.len().to_string())],
                )
                    .into_response();
            }
            // MinIO ignores a `Range` it cannot parse (the client's names an
            // aiohttp session): the whole object.
            (StatusCode::OK, meta, data).into_response()
        }
    }

    fn etag(data: &[u8]) -> String {
        sigv4::sha256_hex(data)[..32].to_string()
    }

    fn to_hex(s: &str) -> String {
        s.bytes().map(|b| format!("{b:02x}")).collect()
    }

    fn from_hex(s: &str) -> String {
        let bytes: Vec<u8> = (0..s.len() / 2)
            .filter_map(|i| s.get(2 * i..2 * i + 2))
            .filter_map(|h| u8::from_str_radix(h, 16).ok())
            .collect();
        String::from_utf8(bytes).unwrap_or_default()
    }

    fn parse_query(raw: &str) -> HashMap<String, String> {
        raw.split('&')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                (py_unquote(k), py_unquote(v))
            })
            .collect()
    }

    /// The signature recomputed from the received method, path, query and
    /// the headers the request says it signed.
    fn verify(method: &str, path: &str, query: &str, headers: &HeaderMap) -> &'static str {
        let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
            return "anonymous";
        };
        let field = |name: &str| {
            auth.split(", ").find_map(|p| {
                p.split_once(&format!("{name}="))
                    .map(|(_, v)| v.to_string())
            })
        };
        let (Some(credential), Some(signed)) = (field("Credential"), field("SignedHeaders")) else {
            return "malformed";
        };
        let credential = credential.trim_start_matches("AWS4-HMAC-SHA256 ");
        let mut scope = credential.split('/');
        let (Some(access), _, Some(region)) = (scope.next(), scope.next(), scope.next()) else {
            return "malformed";
        };
        if access != ACCESS_KEY {
            return "unknown access key";
        }
        let mut signed_headers = Vec::new();
        for name in signed.split(';') {
            let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) else {
                return "signed header not sent";
            };
            signed_headers.push((name.to_string(), value.to_string()));
        }
        let get = |n: &str| {
            headers
                .get(n)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        let expected = sigv4::authorization(
            method,
            path,
            query,
            region,
            &signed_headers,
            &Credentials {
                access_key: ACCESS_KEY.into(),
                secret_key: SECRET_KEY.into(),
            },
            &get("x-amz-content-sha256"),
            &get("x-amz-date"),
        );
        if expected == auth {
            "ok"
        } else {
            "bad signature"
        }
    }

    fn escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&#34;")
            .replace('\'', "&#39;")
    }

    /// MinIO's `s3URLEncode` (`encoding-type=url`).
    fn url_encode(s: &str) -> String {
        let mut out = String::new();
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || b"-_./*".contains(&b) {
                out.push(char::from(b));
            } else if b == b' ' {
                out.push('+');
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    fn xml(body: String) -> Response {
        (
            StatusCode::OK,
            [("Content-Type", "application/xml")],
            format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{body}"),
        )
            .into_response()
    }

    fn error(
        status: u16,
        code: &str,
        resource: &str,
        bucket: Option<&str>,
        key: Option<&str>,
        head: bool,
    ) -> Response {
        let status = StatusCode::from_u16(status).unwrap();
        if head {
            return status.into_response();
        }
        let mut body = format!("<Error><Code>{code}</Code><Message>{code}</Message>");
        if let Some(k) = key {
            body.push_str(&format!("<Key>{}</Key>", escape(k)));
        }
        if let Some(b) = bucket {
            body.push_str(&format!("<BucketName>{}</BucketName>", escape(b)));
        }
        body.push_str(&format!(
            "<Resource>{}</Resource><RequestId>E2E</RequestId><HostId>e2e</HostId></Error>",
            escape(resource)
        ));
        (
            status,
            [("Content-Type", "application/xml")],
            format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{body}"),
        )
            .into_response()
    }

    fn list_v2(
        bucket: &str,
        objects: &BTreeMap<String, (Vec<u8>, String)>,
        query: &HashMap<String, String>,
    ) -> String {
        let empty = String::new();
        let prefix = query.get("prefix").unwrap_or(&empty);
        let delimiter = query.get("delimiter").unwrap_or(&empty);
        let start = match query.get("continuation-token") {
            Some(t) => from_hex(t),
            None => query.get("start-after").cloned().unwrap_or_default(),
        };
        let mut entries: Vec<(bool, String)> = Vec::new();
        let mut prefixes = BTreeSet::new();
        for k in objects.keys() {
            if !k.starts_with(prefix.as_str()) || *k <= start {
                continue;
            }
            let rest = &k[prefix.len()..];
            match rest
                .find(delimiter.as_str())
                .filter(|_| !delimiter.is_empty())
            {
                Some(at) => {
                    let common = format!("{prefix}{}", &rest[..at + delimiter.len()]);
                    if common > start && prefixes.insert(common.clone()) {
                        entries.push((false, common));
                    }
                }
                None => entries.push((true, k.clone())),
            }
        }
        let truncated = entries.len() > PAGE;
        entries.truncate(PAGE);
        let enc = |s: &str| {
            if query.get("encoding-type").map(String::as_str) == Some("url") {
                url_encode(s)
            } else {
                s.to_string()
            }
        };
        let mut out = format!(
            "<ListBucketResult xmlns=\"{NS}\"><Name>{}</Name><Prefix>{}</Prefix>\
             <KeyCount>{}</KeyCount><MaxKeys>1000</MaxKeys>",
            escape(bucket),
            escape(&enc(prefix)),
            entries.len()
        );
        if !delimiter.is_empty() {
            out.push_str(&format!(
                "<Delimiter>{}</Delimiter>",
                escape(&enc(delimiter))
            ));
        }
        out.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
        if truncated {
            if let Some((_, last)) = entries.last() {
                out.push_str(&format!(
                    "<NextContinuationToken>{}</NextContinuationToken>",
                    to_hex(last)
                ));
            }
        }
        for (is_key, name) in &entries {
            if *is_key {
                let size = objects.get(name).map_or(0, |o| o.0.len());
                out.push_str(&format!(
                    "<Contents><Key>{}</Key><LastModified>2026-01-02T03:04:05.000Z</LastModified>\
                     <ETag>&#34;e&#34;</ETag><Size>{size}</Size><StorageClass>STANDARD\
                     </StorageClass></Contents>",
                    escape(&enc(name))
                ));
            }
        }
        for (is_key, name) in &entries {
            if !*is_key {
                out.push_str(&format!(
                    "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                    escape(&enc(name))
                ));
            }
        }
        out.push_str("</ListBucketResult>");
        out
    }
}

const P: &str = "/api/incidents/db_operations";
const CR: &str = "/api/incidents/customer_reports";
const DS: &str = "/api/agent_data_store";

fn env_for(port: u16) -> String {
    format!(
        "COPILOT_MINIO_ENDPOINT=127.0.0.1:{port}\nMINIO_ROOT_USER={}\nMINIO_ROOT_PASSWORD={}\n\
         COPILOT_LEGACY_URL=http://127.0.0.1:{}\n",
        s3::ACCESS_KEY,
        s3::SECRET_KEY,
        s3::port()
    )
}

/// A form field: its name, `Some((filename, content type))` for a file, the
/// data.
type Part<'a> = (&'a str, Option<(&'a str, &'a str)>, &'a [u8]);

/// A `multipart/form-data` body of those fields.
fn multipart(parts: &[Part<'_>]) -> (String, Vec<u8>) {
    let boundary = "e2e-objectstore-boundary";
    let mut body = Vec::new();
    for (name, file, data) in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        match file {
            Some((filename, content_type)) => body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n\
                     Content-Type: {content_type}\r\n\r\n"
                )
                .as_bytes(),
            ),
            None => body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            ),
        }
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

struct Raw {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

impl Raw {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

/// A request whose response headers and bytes the test reads.
async fn raw(
    h: &Harness,
    method: &str,
    uri: &str,
    token: Option<&str>,
    content_type: Option<&str>,
    body: Vec<u8>,
) -> Raw {
    use tower::ServiceExt;
    let mut b = http::Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    if let Some(ct) = content_type {
        b = b.header("content-type", ct);
    }
    let resp = h
        .router
        .clone()
        .oneshot(b.body(axum::body::Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), 64 << 20)
        .await
        .unwrap()
        .to_vec();
    Raw {
        status,
        headers,
        body,
    }
}

/// A browser's download: `Accept-Encoding: gzip, deflate, br`.
async fn gzip_get(h: &Harness, uri: &str, token: &str) -> Raw {
    use tower::ServiceExt;
    let req = http::Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("accept-encoding", "gzip, deflate, br")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = h.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), 64 << 20)
        .await
        .unwrap()
        .to_vec();
    Raw {
        status,
        headers,
        body,
    }
}

/// What `gzip.GzipFile(compresslevel=9)` writes first: magic, deflate, no
/// flags (then `mtime`), `XFL` 2, `OS` 255.
fn is_python_gzip(body: &[u8]) -> bool {
    body.len() > 18 && body[..4] == [0x1f, 0x8b, 8, 0] && body[8..10] == [2, 255]
}

async fn upload(h: &Harness, uri: &str, token: &str, parts: &[Part<'_>]) -> Raw {
    let (ct, body) = multipart(parts);
    raw(h, "POST", uri, Some(token), Some(&ct), body).await
}

struct Tokens {
    admin: String,
    analyst: String,
    portal: String,
    admin_id: i64,
    portal_id: i64,
}

async fn tokens(h: &Harness) -> Tokens {
    let s = &h.suffix;
    let id =
        |name: &str| format!("SELECT CAST(id AS SIGNED) FROM `user` WHERE username = '{name}{s}'");
    Tokens {
        admin: h.token(&format!("admin{s}"), "admin"),
        analyst: h.token(&format!("analyst{s}"), "analyst"),
        portal: h.token(&format!("portal{s}"), "customer_user"),
        admin_id: h.scalar_i64(&id("admin")).await,
        portal_id: h.scalar_i64(&id("portal")).await,
    }
}

async fn case(h: &Harness, customer: &str) -> i64 {
    h.exec(&format!(
        "INSERT INTO incident_management_case (case_name, case_description, case_creation_time, \
         case_status, customer_code, notification_invoked_number, escalated) VALUES \
         ('e2e case', 'd', '2026-01-02 03:04:05', 'OPEN', '{customer}', 0, 0)"
    ))
    .await
}

async fn add_case_file(h: &Harness, case_id: i64, file_name: &str) -> i64 {
    h.exec(&format!(
        "INSERT INTO incident_management_case_datastore (case_id, bucket_name, object_key, \
         file_name, content_type, file_size, upload_time, file_hash) VALUES ({case_id}, \
         'copilot-cases', '{case_id}/{file_name}', '{file_name}', 'text/plain', 4, \
         '2026-01-02 03:04:05', 'h')"
    ))
    .await
}

/// The audit sink writes on a task of its own.
async fn eventually(h: &Harness, sql: &str, want: i64) {
    for _ in 0..50 {
        if h.scalar_i64(sql).await == want {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(h.scalar_i64(sql).await, want, "{sql}");
}

fn all_signed(seen: &[s3::Seen]) {
    for r in seen {
        assert_eq!(r.signature, "ok", "{r:?}");
        assert_eq!(
            r.user_agent,
            copilot_objectstore::client::user_agent(),
            "{r:?}"
        );
    }
}

fn calls(seen: &[s3::Seen]) -> Vec<String> {
    seen.iter()
        .map(|r| {
            if r.query.is_empty() {
                format!("{} {}", r.method, r.path)
            } else {
                format!("{} {}?{}", r.method, r.path, r.query)
            }
        })
        .collect()
}

#[tokio::test]
async fn case_files_upload_download_and_delete() {
    let standin = s3::get();
    let h = harness_or_skip!(None, &env_for(s3::port()));
    h.seed().await;
    let t = tokens(&h).await;
    let s = h.suffix.clone();
    let acme_case = case(&h, &format!("acme{s}")).await;
    let beta_case = case(&h, &format!("beta{s}")).await;
    standin.take();

    // A portal user may upload to their own customer's case.
    let r = upload(
        &h,
        &format!("{P}/case/data-store/upload?case_id={acme_case}"),
        &t.portal,
        &[("file", Some(("notes é.txt", "text/plain")), b"data")],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let body = r.json();
    let stored = &body["case_data_store"];
    let keys: Vec<&str> = stored
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "case_id",
            "bucket_name",
            "object_key",
            "file_name",
            "content_type",
            "file_size",
            "file_hash",
            "id",
            "upload_time"
        ]
    );
    assert_eq!(
        stored["object_key"],
        json!(format!("{acme_case}/notes é.txt"))
    );
    assert_eq!(stored["file_size"], json!(4));
    assert_eq!(
        stored["file_hash"],
        json!(copilot_objectstore::sigv4::sha256_hex(b"data"))
    );
    assert_eq!(
        (body["success"].clone(), body["message"].clone()),
        (json!(true), json!("File uploaded successfully"))
    );
    assert_eq!(
        standin.object("copilot-cases", &format!("{acme_case}/notes é.txt")),
        Some((b"data".to_vec(), "text/plain".to_string()))
    );
    let seen = standin.take();
    all_signed(&seen);
    assert_eq!(
        calls(&seen),
        [
            "GET /copilot-cases?location=".to_string(),
            format!("PUT /copilot-cases/{acme_case}/notes é.txt"),
        ]
    );
    eventually(
        &h,
        &format!(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'datastore.file_create' \
         AND entity_id = 'notes é.txt' AND customer_code = 'acme{s}'"
        ),
        1,
    )
    .await;

    // The same name twice; another tenant's case; no file.
    let r = upload(
        &h,
        &format!("{P}/case/data-store/upload?case_id={acme_case}"),
        &t.analyst,
        &[("file", Some(("notes é.txt", "text/plain")), b"again")],
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::BAD_REQUEST,
            json!({"message": "File name already exists for this case", "success": false})
        )
    );
    let r = upload(
        &h,
        &format!("{P}/case/data-store/upload?case_id={beta_case}"),
        &t.portal,
        &[("file", Some(("x.txt", "text/plain")), b"x")],
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.json());
    let r = upload(
        &h,
        &format!("{P}/case/data-store/upload?case_id={acme_case}"),
        &t.portal,
        &[("other", None, b"x")],
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(standin.take().is_empty(), "refused before MinIO");

    // Download: the bytes, the row's type, Python's disposition, chunked.
    let name = "notes%20%C3%A9.txt";
    let r = raw(
        &h,
        "GET",
        &format!("{P}/case/data-store/download/{acme_case}/{name}"),
        Some(&t.portal),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, b"data");
    assert_eq!(r.header("content-type"), Some("text/plain; charset=utf-8"));
    assert_eq!(r.header("content-length"), None);
    // `notes é.txt` is latin-1: Starlette sends the byte 0xE9.
    assert_eq!(
        r.headers.get("content-disposition").unwrap().as_bytes(),
        b"attachment; filename=notes \xe9.txt"
    );
    let seen = standin.take();
    all_signed(&seen);
    assert_eq!(
        calls(&seen),
        [
            "GET /copilot-cases?location=".to_string(),
            format!("HEAD /copilot-cases/{acme_case}/notes é.txt"),
            format!("GET /copilot-cases/{acme_case}/notes é.txt"),
        ]
    );
    assert_eq!(
        seen[2].range.as_deref(),
        Some("bytes=<aiohttp.client.ClientSession object at 0x7f0000000000>-")
    );
    assert_eq!(r.header("vary"), Some("Accept-Encoding"));
    // GZipMiddleware gzips every streamed download a browser asks for,
    // however small.
    let g = gzip_get(
        &h,
        &format!("{P}/case/data-store/download/{acme_case}/{name}"),
        &t.portal,
    )
    .await;
    assert_eq!(g.status, StatusCode::OK);
    assert_eq!(g.header("content-encoding"), Some("gzip"));
    assert_eq!(g.header("vary"), Some("Accept-Encoding"));
    assert!(is_python_gzip(&g.body), "{:?}", g.body);
    standin.take();

    // A row whose object is gone: the bucket is listed, then a 404.
    add_case_file(&h, acme_case, "gone.txt").await;
    let r = raw(
        &h,
        "GET",
        &format!("{P}/case/data-store/download/{acme_case}/gone.txt"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::NOT_FOUND,
            json!({
                "message": format!("File {acme_case}/gone.txt not found in bucket copilot-cases"),
                "success": false
            })
        )
    );
    let seen = standin.take();
    all_signed(&seen);
    assert!(
        calls(&seen)
            .iter()
            .any(|c| c.starts_with("GET /copilot-cases?") && c.contains("list-type=2")),
        "{seen:?}"
    );

    // A name Starlette cannot send as latin-1: the ValueError handler's 400.
    standin.put(
        "copilot-cases",
        &format!("{acme_case}/€.txt"),
        b"eur",
        "text/plain",
    );
    add_case_file(&h, acme_case, "€.txt").await;
    let r = raw(
        &h,
        "GET",
        &format!("{P}/case/data-store/download/{acme_case}/%E2%82%AC.txt"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.json());
    assert!(
        r.json()["message"]
            .as_str()
            .unwrap()
            .starts_with("'latin-1' codec can't encode character '\\u20ac'"),
        "{:?}",
        r.json()
    );

    // A path with an encoded `/` is Python's.
    let r = raw(
        &h,
        "GET",
        &format!("{P}/case/data-store/download/{acme_case}/a%2Fb"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.json()["from"], json!("python"), "{:?}", r.json());
    standin.take();

    // Delete: admin/analyst only, then MinIO, then the row.
    let r = raw(
        &h,
        "DELETE",
        &format!("{P}/case/data-store/{acme_case}/{name}"),
        Some(&t.portal),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = raw(
        &h,
        "DELETE",
        &format!("{P}/case/data-store/{acme_case}/{name}"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::OK,
            json!({"message": "File deleted successfully", "success": true})
        )
    );
    assert_eq!(
        standin.object("copilot-cases", &format!("{acme_case}/notes é.txt")),
        None
    );
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM incident_management_case_datastore WHERE case_id = {acme_case} \
             AND file_name = 'notes é.txt'"
        ))
        .await,
        0
    );
    let seen = standin.take();
    all_signed(&seen);
    assert_eq!(
        calls(&seen),
        [
            "GET /copilot-cases?location=".to_string(),
            format!("HEAD /copilot-cases/{acme_case}/notes é.txt"),
            format!("DELETE /copilot-cases/{acme_case}/notes é.txt"),
        ]
    );
    let r = raw(
        &h,
        "DELETE",
        &format!("{P}/case/data-store/{acme_case}/{name}"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::NOT_FOUND,
            json!({"message": "File not found", "success": false})
        )
    );
}

#[tokio::test]
async fn case_delete_keeps_pythons_order() {
    let standin = s3::get();
    let h = harness_or_skip!(None, &env_for(s3::port()));
    let (acme_alert, _) = h.seed().await;
    let t = tokens(&h).await;
    let s = h.suffix.clone();

    // Every file's object present: comments, links, tasks, events, files, case.
    let whole = case(&h, &format!("acme{s}")).await;
    h.exec(&format!(
        "INSERT INTO incident_management_casealertlink (case_id, alert_id) VALUES ({whole}, {acme_alert})"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO incident_management_case_comment (case_id, comment, user_name, created_at) \
         VALUES ({whole}, 'hi', 'u', UTC_TIMESTAMP())"
    ))
    .await;
    for f in ["a.txt", "b.txt"] {
        add_case_file(&h, whole, f).await;
        standin.put(
            "copilot-cases",
            &format!("{whole}/{f}"),
            b"data",
            "text/plain",
        );
    }
    standin.take();
    let r = raw(
        &h,
        "DELETE",
        &format!("{P}/case/{whole}"),
        Some(&t.portal),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "analysts only");
    let r = raw(
        &h,
        "DELETE",
        &format!("{P}/case/{whole}"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::OK,
            json!({"message": "Case deleted successfully", "success": true})
        )
    );
    for (table, column) in [
        ("incident_management_case", "id"),
        ("incident_management_casealertlink", "case_id"),
        ("incident_management_case_comment", "case_id"),
        ("incident_management_case_datastore", "case_id"),
    ] {
        assert_eq!(
            h.scalar_i64(&format!(
                "SELECT COUNT(*) FROM {table} WHERE {column} = {whole}"
            ))
            .await,
            0,
            "{table}"
        );
    }
    assert_eq!(
        standin.object("copilot-cases", &format!("{whole}/a.txt")),
        None
    );
    assert_eq!(
        standin.object("copilot-cases", &format!("{whole}/b.txt")),
        None
    );
    let seen = standin.take();
    all_signed(&seen);
    assert_eq!(
        calls(&seen),
        [
            "GET /copilot-cases?location=".to_string(),
            format!("HEAD /copilot-cases/{whole}/a.txt"),
            format!("DELETE /copilot-cases/{whole}/a.txt"),
            "GET /copilot-cases?location=".to_string(),
            format!("HEAD /copilot-cases/{whole}/b.txt"),
            format!("DELETE /copilot-cases/{whole}/b.txt"),
        ]
    );

    // The second file's object is missing: its row stays, the case's
    // foreign key refuses the delete — after the first file's commit took
    // the comments and links with it.
    let partial = case(&h, &format!("acme{s}")).await;
    h.exec(&format!(
        "INSERT INTO incident_management_case_comment (case_id, comment, user_name, created_at) \
         VALUES ({partial}, 'hi', 'u', UTC_TIMESTAMP())"
    ))
    .await;
    add_case_file(&h, partial, "a.txt").await;
    standin.put(
        "copilot-cases",
        &format!("{partial}/a.txt"),
        b"data",
        "text/plain",
    );
    add_case_file(&h, partial, "missing.txt").await;
    let r = raw(
        &h,
        "DELETE",
        &format!("{P}/case/{partial}"),
        Some(&t.admin),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    let message = r.json()["message"].as_str().unwrap().to_string();
    assert!(
        message.starts_with(
            "Failed to delete case: (pymysql.err.IntegrityError) (1451, 'Cannot delete or update \
             a parent row: a foreign key constraint fails"
        ),
        "{message}"
    );
    assert!(
        message.ends_with(&format!(
            "\n[SQL: DELETE FROM incident_management_case WHERE incident_management_case.id = \
             %s]\n[parameters: ({partial},)]\n(Background on this error at: \
             https://sqlalche.me/e/20/gkpj)"
        )),
        "{message}"
    );
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM incident_management_case WHERE id = {partial}"
        ))
        .await,
        1
    );
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM incident_management_case_comment WHERE case_id = {partial}"
        ))
        .await,
        0,
        "committed with the first file"
    );
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM incident_management_case_datastore WHERE case_id = {partial}"
        ))
        .await,
        1,
        "the missing object's row"
    );
    standin.take();

    // A static path under `/case/` is FastAPI's `{case_id}` for a DELETE.
    let r = raw(
        &h,
        "DELETE",
        &format!("{P}/case/status"),
        Some(&t.admin),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

    h.exec(&format!(
        "DELETE FROM incident_management_case_datastore WHERE case_id = {partial}"
    ))
    .await;
}

#[tokio::test]
async fn report_templates_upload_list_download_delete() {
    let standin = s3::get();
    let h = harness_or_skip!(None, &env_for(s3::port()));
    h.seed().await;
    let t = tokens(&h).await;
    let s = h.suffix.clone();
    const T: &str = "/api/incidents/db_operations/case-report-template";
    let docx_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    let name = format!("tpl{s}.docx");
    let docx: &[u8] = b"PK\x03\x04 a zip";

    for (file, data, message) in [
        (
            "t.txt".to_string(),
            &b"x"[..],
            "Invalid file type. Only .docx and .html files are allowed.",
        ),
        (
            name.clone(),
            &b"not a zip"[..],
            "File content does not match a valid .docx document.",
        ),
        (
            format!("tpl{s}.html"),
            &b"PK\x03\x04"[..],
            "File content does not match a valid .html document.",
        ),
    ] {
        let r = upload(
            &h,
            &format!("{T}/upload"),
            &t.admin,
            &[("file", Some((&file, docx_type)), data)],
        )
        .await;
        assert_eq!(
            (r.status, r.json()),
            (
                StatusCode::BAD_REQUEST,
                json!({"message": message, "success": false})
            ),
            "{file}"
        );
    }
    let r = upload(
        &h,
        &format!("{T}/upload"),
        &t.portal,
        &[("file", Some((&name, docx_type)), docx)],
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(standin.take().is_empty());

    let r = upload(
        &h,
        &format!("{T}/upload"),
        &t.analyst,
        &[("file", Some((&name, docx_type)), docx)],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let body = r.json();
    let keys: Vec<&str> = body["case_report_template_data_store"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "report_template_name",
            "bucket_name",
            "object_key",
            "file_name",
            "content_type",
            "file_size",
            "file_hash",
            "id",
            "upload_time"
        ]
    );
    assert_eq!(
        standin.object("copilot-case-report-templates", &name),
        Some((docx.to_vec(), docx_type.to_string()))
    );
    let r = upload(
        &h,
        &format!("{T}/upload"),
        &t.analyst,
        &[("file", Some((&name, docx_type)), docx)],
    )
    .await;
    assert_eq!(
        r.json(),
        json!({"message": "File name already exists for this template", "success": false})
    );

    // The listing pages (two names a page) and names the bucket's top level.
    standin.put(
        "copilot-case-report-templates",
        &format!("other{s}.html"),
        b"<p>",
        "text/html",
    );
    for extra in ["x1", "x2", "x3"] {
        standin.put(
            "copilot-case-report-templates",
            &format!("dir{s}/{extra}"),
            b"x",
            "text/plain",
        );
    }
    standin.take();
    let r = raw(&h, "GET", T, Some(&t.analyst), None, Vec::new()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let names = r.json()["case_report_template_data_store"].clone();
    let names: Vec<&str> = names
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(names.contains(&name.as_str()), "{names:?}");
    assert_eq!(
        names.iter().filter(|n| **n == format!("dir{s}/")).count(),
        1,
        "{names:?}"
    );
    let seen = standin.take();
    all_signed(&seen);
    assert!(
        seen.iter()
            .filter(|r| r.query.contains("list-type=2"))
            .count()
            >= 2,
        "two names a page: {seen:?}"
    );
    assert!(
        seen.iter()
            .filter(|r| r.query.contains("list-type=2"))
            .skip(1)
            .all(|r| r.query.contains("continuation-token=") && r.query.contains("start-after=")),
        "later pages carry both: {seen:?}"
    );

    let r = raw(
        &h,
        "GET",
        &format!("{T}/download/{name}"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, docx);
    assert_eq!(r.header("content-type"), Some(docx_type));
    assert_eq!(
        r.header("content-disposition"),
        Some(format!("attachment; filename={name}").as_str())
    );

    // A HEAD answered 500 is retried, five attempts in all, then a 404.
    standin.take();
    standin.fail("HEAD", &format!("/copilot-case-report-templates/{name}"));
    let r = raw(
        &h,
        "GET",
        &format!("{T}/download/{name}"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    standin.heal();
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{:?}", r.json());
    let seen = standin.take();
    assert_eq!(
        seen.iter().filter(|r| r.method == "HEAD").count(),
        5,
        "{seen:?}"
    );

    let r = raw(
        &h,
        "DELETE",
        &format!("{T}/{name}"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::OK,
            json!({"message": "File deleted successfully", "success": true})
        )
    );
    assert_eq!(standin.object("copilot-case-report-templates", &name), None);
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM incident_management_case_report_template_datastore \
             WHERE file_name = '{name}'"
        ))
        .await,
        0
    );
    let r = raw(
        &h,
        "DELETE",
        &format!("{T}/{name}"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::NOT_FOUND,
            json!({"message": "File not found", "success": false})
        )
    );
}

#[tokio::test]
async fn customer_reports_download_and_delete() {
    let standin = s3::get();
    let h = harness_or_skip!(None, &env_for(s3::port()));
    h.seed().await;
    let t = tokens(&h).await;
    let s = h.suffix.clone();
    let report = |customer: String,
                  by: i64,
                  role: &'static str,
                  status: &'static str,
                  visible: i32| {
        let h = &h;
        let s = s.clone();
        async move {
            let id = h
                .exec(&format!(
                    "INSERT INTO incident_management_customer_reports (report_name, customer_code, \
                     bucket_name, object_key, file_name, file_size, file_hash, generated_at, \
                     generated_by, generated_by_role, date_from, date_to, filters_json, total_alerts, \
                     total_cases, open_cases, closed_cases, status, visible_to_customer) VALUES \
                     ('R {s}', '{customer}', 'incident-management-reports', 'pending', 'r.pdf', 4, \
                     'h', '2026-03-05 10:00:00', {by}, '{role}', '2026-02-01 00:00:00', \
                     '2026-02-28 00:00:00', '{{}}', 0, 0, 0, 0, '{status}', {visible})"
                ))
                .await;
            let key = format!("reports/{id}.pdf");
            h.exec(&format!(
                "UPDATE incident_management_customer_reports SET object_key = '{key}' WHERE id = {id}"
            ))
            .await;
            (id, key)
        }
    };
    let acme = format!("acme{s}");
    let (hidden, hidden_key) = report(acme.clone(), t.admin_id, "admin", "completed", 0).await;
    standin.put(
        "incident-management-reports",
        &hidden_key,
        b"%PDF",
        "application/pdf",
    );

    let r = raw(
        &h,
        "GET",
        &format!("{CR}/{hidden}/download"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.body, b"%PDF");
    assert_eq!(r.header("content-type"), Some("application/pdf"));
    assert_eq!(
        r.header("content-disposition"),
        Some("attachment; filename=\"r.pdf\"")
    );
    let r = raw(
        &h,
        "GET",
        &format!("{CR}/{hidden}/download"),
        Some(&t.portal),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::FORBIDDEN,
            json!({"message": "This report is not available.", "success": false})
        )
    );
    let (own, own_key) = report(acme.clone(), t.portal_id, "customer_user", "completed", 0).await;
    standin.put(
        "incident-management-reports",
        &own_key,
        b"%PDF",
        "application/pdf",
    );
    let r = raw(
        &h,
        "GET",
        &format!("{CR}/{own}/download"),
        Some(&t.portal),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "a portal user's own report");

    let (running, _) = report(acme.clone(), t.admin_id, "admin", "generating", 1).await;
    let r = raw(
        &h,
        "GET",
        &format!("{CR}/{running}/download"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        r.json(),
        json!({"message": "Report is not ready to download (status: generating)", "success": false})
    );
    let (beta, _) = report(format!("beta{s}"), t.admin_id, "admin", "completed", 1).await;
    let r = raw(
        &h,
        "GET",
        &format!("{CR}/{beta}/download"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::FORBIDDEN,
            json!({"message": format!("Access denied to customer beta{s}"), "success": false})
        )
    );
    let (lost, _) = report(acme.clone(), t.admin_id, "admin", "completed", 1).await;
    let r = raw(
        &h,
        "GET",
        &format!("{CR}/{lost}/download"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "RuntimeError: a bare 500"
    );
    let r = raw(
        &h,
        "GET",
        &format!("{CR}/99999999/download"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        r.json(),
        json!({"message": "Report with ID 99999999 not found", "success": false})
    );

    // Delete: an admin or the creator; a file MinIO cannot remove is only logged.
    let r = raw(
        &h,
        "DELETE",
        &format!("{CR}/{hidden}"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::FORBIDDEN,
            json!({"message": "Only an admin or the report creator can delete this report", "success": false})
        )
    );
    let r = raw(
        &h,
        "DELETE",
        &format!("{CR}/{own}"),
        Some(&t.portal),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::OK,
            json!({
                "success": true,
                "message": format!("Report 'R {s}' deleted successfully"),
                "report_id": own,
                "report_name": format!("R {s}"),
                "customer_code": acme,
            })
        )
    );
    assert_eq!(
        standin.object("incident-management-reports", &own_key),
        None
    );
    let r = raw(
        &h,
        "DELETE",
        &format!("{CR}/{lost}"),
        Some(&t.admin),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    for id in [own, lost] {
        assert_eq!(
            h.scalar_i64(&format!(
                "SELECT COUNT(*) FROM incident_management_customer_reports WHERE id = {id}"
            ))
            .await,
            0
        );
    }
    all_signed(&standin.take());
    h.exec(&format!(
        "DELETE FROM incident_management_customer_reports WHERE id IN ({hidden}, {running}, {beta})"
    ))
    .await;
}

#[tokio::test]
async fn agent_artifacts_follow_the_agents_tenant() {
    let standin = s3::get();
    let h = harness_or_skip!(None, &env_for(s3::port()));
    h.seed().await;
    let t = tokens(&h).await;
    let s = h.suffix.clone();
    for c in ["acme", "beta"] {
        h.exec(&format!(
            "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, \
             wazuh_last_seen, velociraptor_id, wazuh_agent_version, wazuh_agent_status, \
             customer_code, quarantined) VALUES ('{c}-ag{s}', '10.0.0.1', 'linux', '{c}-host{s}', \
             'l', 0, UTC_TIMESTAMP(), 'C.1', 'v4', 'active', '{c}{s}', 0)"
        ))
        .await;
    }
    let artifact = |agent: String, file: &'static str| {
        let h = &h;
        async move {
            h.exec(&format!(
                "INSERT INTO agent_datastore (agent_id, velociraptor_id, artifact_name, flow_id, \
                 collection_time, bucket_name, object_key, file_name, content_type, file_size, \
                 file_hash, uploaded_by, notes, status) VALUES ('{agent}', 'C.1', \
                 'Generic.Collect', 'F.1', '2026-01-02 03:04:05', 'velociraptor-artifacts', \
                 'ignored', '{file}', 'application/zip', 3, 'h', NULL, 'n', 'completed')"
            ))
            .await
        }
    };
    let acme_agent = format!("acme-ag{s}");
    let beta_agent = format!("beta-ag{s}");
    let a1 = artifact(acme_agent.clone(), "c.zip").await;
    let b1 = artifact(beta_agent.clone(), "c.zip").await;
    standin.put(
        "velociraptor-artifacts",
        &format!("{acme_agent}/F.1/c.zip"),
        b"zip",
        "application/zip",
    );
    standin.take();

    let r = raw(
        &h,
        "GET",
        &format!("{DS}/agent/{acme_agent}/artifacts"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.json()["total"], json!(1));
    assert_eq!(
        r.json()["data"][0]["customer_code"],
        json!(format!("acme{s}"))
    );
    for agent in [beta_agent.clone(), format!("nobody{s}")] {
        let r = raw(
            &h,
            "GET",
            &format!("{DS}/agent/{agent}/artifacts"),
            Some(&t.analyst),
            None,
            Vec::new(),
        )
        .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{agent}: {:?}", r.json());
    }
    let r = raw(
        &h,
        "GET",
        &format!("{DS}/agent/{beta_agent}/artifacts/{b1}"),
        Some(&t.admin),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = raw(
        &h,
        "GET",
        &format!("{DS}/agent/{acme_agent}/artifacts/{b1}"),
        Some(&t.admin),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::NOT_FOUND,
            json!({"message": format!("Artifact {b1} not found for agent {acme_agent}"), "success": false})
        )
    );

    let r = raw(
        &h,
        "GET",
        &format!("{DS}/agent/{acme_agent}/artifacts/{a1}/download"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, b"zip");
    assert_eq!(r.header("content-type"), Some("application/zip"));
    assert_eq!(r.header("content-length"), Some("3"));
    assert_eq!(
        r.header("content-disposition"),
        Some("attachment; filename=c.zip")
    );
    let seen = standin.take();
    all_signed(&seen);
    assert_eq!(
        calls(&seen),
        [
            "GET /velociraptor-artifacts?location=".to_string(),
            format!("HEAD /velociraptor-artifacts/{acme_agent}/F.1/c.zip"),
            format!("GET /velociraptor-artifacts/{acme_agent}/F.1/c.zip"),
        ]
    );

    // Gzipped, its `Content-Length` dropped (Starlette's streaming branch).
    let g = gzip_get(
        &h,
        &format!("{DS}/agent/{acme_agent}/artifacts/{a1}/download"),
        &t.analyst,
    )
    .await;
    assert_eq!(g.header("content-encoding"), Some("gzip"));
    assert_eq!(g.header("content-length"), None);
    assert!(is_python_gzip(&g.body), "{:?}", g.body);
    standin.take();

    // Delete is admin only.
    let r = raw(
        &h,
        "DELETE",
        &format!("{DS}/agent/{acme_agent}/artifacts/{a1}"),
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = raw(
        &h,
        "DELETE",
        &format!("{DS}/agent/{acme_agent}/artifacts/{a1}"),
        Some(&t.admin),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::OK,
            json!({"success": true, "message": format!("Artifact {a1} deleted successfully")})
        )
    );
    assert_eq!(
        standin.object("velociraptor-artifacts", &format!("{acme_agent}/F.1/c.zip")),
        None
    );
    // Its object is gone now: the delete is the 404 of `delete_file`.
    let a2 = artifact(acme_agent.clone(), "c.zip").await;
    let r = raw(
        &h,
        "DELETE",
        &format!("{DS}/agent/{acme_agent}/artifacts/{a2}"),
        Some(&t.admin),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::NOT_FOUND,
            json!({
                "message": format!("File {acme_agent}/F.1/c.zip not found in bucket velociraptor-artifacts"),
                "success": false
            })
        )
    );

    // Upload: any bucket, created when missing; a large file goes in parts.
    let bucket = format!("e2e-upload-{s}");
    standin.take();
    let r = upload(
        &h,
        &format!("{DS}/upload"),
        &t.analyst,
        &[
            ("file", Some(("small.bin", "")), b"abc"),
            ("bucket_name", None, bucket.as_bytes()),
            ("object_name", None, b"dir/small.bin"),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(
        r.json(),
        json!({
            "success": true,
            "message": "File small.bin uploaded successfully",
            "bucket_name": bucket,
            "object_key": "dir/small.bin",
            "file_name": "small.bin",
            "file_size": 3,
            "file_hash": copilot_objectstore::sigv4::sha256_hex(b"abc"),
            "content_type": "application/octet-stream",
        })
    );
    let seen = standin.take();
    all_signed(&seen);
    assert_eq!(
        calls(&seen),
        [
            format!("GET /{bucket}?location="),
            format!("PUT /{bucket}"),
            format!("GET /{bucket}?location="),
            format!("PUT /{bucket}/dir/small.bin"),
        ]
    );
    let large: Vec<u8> = (0..(6 * 1024 * 1024 + 7))
        .map(|i| (i % 251) as u8)
        .collect();
    let r = upload(
        &h,
        &format!("{DS}/upload"),
        &t.admin,
        &[
            ("file", Some(("large.bin", "application/x-test")), &large),
            ("bucket_name", None, bucket.as_bytes()),
            ("object_name", None, b"large.bin"),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(
        standin.object(&bucket, "large.bin"),
        Some((large.clone(), "application/x-test".to_string()))
    );
    let seen = standin.take();
    all_signed(&seen);
    let methods: Vec<String> = calls(&seen)
        .into_iter()
        .map(|c| c.split('?').next().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        methods.iter().filter(|c| c.starts_with("PUT /")).count(),
        2,
        "{methods:?}"
    );
    assert!(
        seen.iter()
            .any(|r| r.method == "POST" && r.query == "uploads=")
    );
    assert!(
        seen.iter()
            .any(|r| r.method == "POST" && r.query.starts_with("uploadId="))
    );

    let r = upload(
        &h,
        &format!("{DS}/upload"),
        &t.portal,
        &[
            ("file", Some(("small.bin", "")), b"abc"),
            ("bucket_name", None, bucket.as_bytes()),
            ("object_name", None, b"x"),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "closed to portal users");
    let r = upload(
        &h,
        &format!("{DS}/upload"),
        &t.analyst,
        &[
            ("file", Some(("small.bin", "")), b"abc"),
            ("bucket_name", None, b"Bad_Bucket"),
            ("object_name", None, b"x"),
        ],
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"message": "Failed to upload file: invalid bucket name Bad_Bucket", "success": false})
        )
    );
    h.exec(&format!(
        "DELETE FROM agent_datastore WHERE agent_id IN ('{acme_agent}', '{beta_agent}')"
    ))
    .await;
    h.exec(&format!(
        "DELETE FROM agents WHERE agent_id IN ('{acme_agent}', '{beta_agent}')"
    ))
    .await;
}

#[tokio::test]
async fn unreachable_minio_fails_as_python_does() {
    let h = harness_or_skip!(None, &env_for(s3::closed_port()));
    h.seed().await;
    let t = tokens(&h).await;
    let port = s3::closed_port();
    let r = upload(
        &h,
        &format!("{DS}/upload"),
        &t.analyst,
        &[
            ("file", Some(("small.bin", "")), b"abc"),
            ("bucket_name", None, b"e2e-down"),
            ("object_name", None, b"x"),
        ],
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({
                "message": format!(
                    "Failed to upload file: Cannot connect to host 127.0.0.1:{port} ssl:default \
                     [Connect call failed ('127.0.0.1', {port})]"
                ),
                "success": false
            })
        )
    );
    let r = raw(
        &h,
        "GET",
        "/api/incidents/db_operations/case-report-template",
        Some(&t.analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR, "a bare 500");
}
