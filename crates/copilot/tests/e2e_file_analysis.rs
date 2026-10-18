//! End-to-end tests of File Analysis (`copilot-file-analysis`) against a real
//! MySQL, with stand-ins for MinIO (a stateful S3), the inspector, CAPE,
//! VirusTotal and Velociraptor (gRPC over mutual TLS).
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13308/copilot \
//!   cargo test -p copilot --test e2e_file_analysis -- --test-threads=1
//! ```
//!
//! Every stand-in listens on a port the OS picks. Agents are seeded with
//! explicit ids from 6650000 on (deleted by id afterwards); the jobs run on
//! the test's runtime and are polled until they settle.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use base64::Engine as _;
use http::Request as HttpRequest;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

const FA: &str = "/api/file-analysis";
const VT_KEY: &str = "vt-e2e-key";

// --- the S3 stand-in -------------------------------------------------------------------------

mod s3 {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use axum::body::Bytes;
    use axum::extract::DefaultBodyLimit;
    use axum::response::{IntoResponse, Response};
    use http::{HeaderMap, Method, StatusCode, Uri};

    use copilot_objectstore::web::py_unquote;

    const NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

    /// Objects by bucket and key: `(bytes, content type)`.
    pub type Buckets = BTreeMap<String, BTreeMap<String, (Vec<u8>, String)>>;

    /// A stateful S3 (path-style, no signature check: `rust_parity_*` verify those).
    #[derive(Clone, Default)]
    pub struct StandIn {
        pub buckets: Arc<Mutex<Buckets>>,
        pub requests: Arc<Mutex<Vec<(String, String)>>>,
        pub addr: String,
    }

    impl StandIn {
        pub async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut s = StandIn {
                addr: listener.local_addr().unwrap().to_string(),
                ..Default::default()
            };
            let served = s.clone();
            let app = axum::Router::new()
                .fallback(
                    move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| {
                        let s = served.clone();
                        async move { s.handle(&method, &uri, &headers, &body) }
                    },
                )
                .layer(DefaultBodyLimit::disable());
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            s.addr = s.addr.clone();
            s
        }

        pub fn env(&self) -> String {
            format!(
                "COPILOT_MINIO_ENDPOINT={}\nMINIO_ROOT_USER=e2e-fa\nMINIO_ROOT_PASSWORD=e2e-fa-secret\n",
                self.addr
            )
        }

        pub fn object(&self, bucket: &str, key: &str) -> Option<(Vec<u8>, String)> {
            self.buckets
                .lock()
                .unwrap()
                .get(bucket)
                .and_then(|b| b.get(key))
                .cloned()
        }

        pub fn keys(&self, bucket: &str) -> Vec<String> {
            self.buckets
                .lock()
                .unwrap()
                .get(bucket)
                .map(|b| b.keys().cloned().collect())
                .unwrap_or_default()
        }

        pub fn put(&self, bucket: &str, key: &str, data: &[u8]) {
            self.buckets
                .lock()
                .unwrap()
                .entry(bucket.into())
                .or_default()
                .insert(key.into(), (data.to_vec(), "application/json".into()));
        }

        fn handle(&self, method: &Method, uri: &Uri, headers: &HeaderMap, body: &[u8]) -> Response {
            let raw_query = uri.query().unwrap_or("").to_string();
            self.requests
                .lock()
                .unwrap()
                .push((method.to_string(), format!("{}?{raw_query}", uri.path())));
            let path = py_unquote(uri.path());
            let query: Vec<(String, String)> = raw_query
                .split('&')
                .filter(|p| !p.is_empty())
                .map(|p| {
                    let (k, v) = p.split_once('=').unwrap_or((p, ""));
                    (py_unquote(k), py_unquote(v))
                })
                .collect();
            let q = |name: &str| {
                query
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.clone())
            };
            let head = method == Method::HEAD;
            let (bucket, key) = match path[1..].split_once('/') {
                Some((b, k)) => (b.to_string(), k.to_string()),
                None => (path[1..].to_string(), String::new()),
            };
            let mut buckets = self.buckets.lock().unwrap();
            if key.is_empty() {
                if method == Method::PUT {
                    buckets.entry(bucket.clone()).or_default();
                    return (StatusCode::OK, [("Location", format!("/{bucket}"))]).into_response();
                }
                let Some(objects) = buckets.get(&bucket) else {
                    return error(404, "NoSuchBucket", head);
                };
                if q("location").is_some() {
                    return xml(format!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LocationConstraint \
                         xmlns=\"{NS}\"></LocationConstraint>"
                    ));
                }
                if q("list-type").as_deref() == Some("2") {
                    let prefix = q("prefix").unwrap_or_default();
                    let mut contents = String::new();
                    for (k, (data, _)) in objects.iter().filter(|(k, _)| k.starts_with(&prefix)) {
                        contents.push_str(&format!(
                            "<Contents><Key>{k}</Key><LastModified>2026-01-02T03:04:05.000Z\
                             </LastModified><ETag>&quot;e&quot;</ETag><Size>{}</Size>\
                             <StorageClass>STANDARD</StorageClass></Contents>",
                            data.len()
                        ));
                    }
                    return xml(format!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult \
                         xmlns=\"{NS}\"><Name>{bucket}</Name><Prefix>{prefix}</Prefix>\
                         <MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>{contents}\
                         </ListBucketResult>"
                    ));
                }
                return StatusCode::OK.into_response();
            }
            let Some(objects) = buckets.get_mut(&bucket) else {
                return error(404, "NoSuchBucket", head);
            };
            if method == Method::PUT {
                let ct = headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("binary/octet-stream")
                    .to_string();
                objects.insert(key, (body.to_vec(), ct));
                return (StatusCode::OK, [("ETag", "\"e\"")]).into_response();
            }
            if method == Method::DELETE {
                objects.remove(&key);
                return StatusCode::NO_CONTENT.into_response();
            }
            let Some((data, ct)) = objects.get(&key).cloned() else {
                return error(404, "NoSuchKey", head);
            };
            let meta = [
                ("Content-Type", ct),
                ("ETag", "\"e\"".to_string()),
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
            (StatusCode::OK, meta, data).into_response()
        }
    }

    fn xml(body: String) -> Response {
        (StatusCode::OK, [("Content-Type", "application/xml")], body).into_response()
    }

    fn error(status: u16, code: &str, head: bool) -> Response {
        let status = StatusCode::from_u16(status).unwrap();
        if head {
            return status.into_response();
        }
        (
            status,
            [("Content-Type", "application/xml")],
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{code}</Code>\
                 <Message>{code}</Message><RequestId>E2E</RequestId><HostId>e2e</HostId></Error>"
            ),
        )
            .into_response()
    }
}

// --- the inspector, CAPE and VirusTotal ------------------------------------------------------

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[derive(Default)]
struct Data {
    /// What `/inspect` answers (`previews_b64` included).
    inspector: Value,
    /// The inspector's status (429 = busy).
    inspector_status: u16,
    /// VirusTotal file reports by sha256.
    vt_files: BTreeMap<String, Value>,
    /// What an upload makes VirusTotal know.
    vt_after_upload: Option<(String, Value)>,
    /// The CAPE report of task 77.
    cape_report: Value,
    /// CAPE's screenshot zip.
    cape_zip: Vec<u8>,
}

#[derive(Clone, Default)]
struct Fake {
    data: Arc<Mutex<Data>>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Respond for Fake {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let path = req.url.path().to_string();
        self.seen.lock().unwrap().push(Seen {
            method: req.method.to_string(),
            path: path.clone(),
            headers: req
                .headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
                .collect(),
            body: req.body.clone(),
        });
        let mut data = self.data.lock().unwrap();
        let ok = |v: Value| ResponseTemplate::new(200).set_body_json(v);
        if path == "/inspect" {
            return ResponseTemplate::new(data.inspector_status.max(200))
                .set_body_json(data.inspector.clone());
        }
        // CAPE.
        if path == "/apiv2/cuckoo/status/" {
            return ok(json!({"error": false, "data": {"version": "2.4"}}));
        }
        if path.starts_with("/apiv2/tasks/search/sha256/") {
            return ok(json!({"error": false, "data": [{"id": 5, "status": "failed_analysis"}]}));
        }
        if path == "/apiv2/tasks/create/file/" {
            return ok(json!({"error": false, "data": {"task_ids": [77]}}));
        }
        if path == "/apiv2/tasks/view/77/" {
            return ok(json!({"data": {"status": "reported"}}));
        }
        if path == "/apiv2/tasks/get/report/77/json/" {
            return ok(data.cape_report.clone());
        }
        if path == "/apiv2/tasks/get/screenshot/77/" {
            return ResponseTemplate::new(200)
                .set_body_raw(data.cape_zip.clone(), "application/zip");
        }
        // VirusTotal.
        if let Some(rest) = path.strip_prefix("/api/v3/files/") {
            let (sha, behaviour) = match rest.strip_suffix("/behaviour_summary") {
                Some(s) => (s.to_string(), true),
                None => (rest.to_string(), false),
            };
            return match data.vt_files.get(&sha) {
                Some(_) if behaviour => ok(json!({"data": {"tags": ["DETECT_DEBUG_ENVIRONMENT"],
                    "mitre_attack_techniques": [{"id": "T1055", "signature_description": "inject"}]}})),
                Some(report) => {
                    ok(json!({"data": {"id": sha, "type": "file", "attributes": report}}))
                }
                None => ResponseTemplate::new(404).set_body_json(
                    json!({"error": {"code": "NotFoundError", "message": "not found"}}),
                ),
            };
        }
        if path == "/api/v3/files" && req.method.as_str() == "POST" {
            if let Some((sha, report)) = data.vt_after_upload.take() {
                data.vt_files.insert(sha, report);
            }
            return ok(json!({"data": {"type": "analysis", "id": "an-1"}}));
        }
        if path == "/api/v3/analyses/an-1" {
            return ok(json!({"data": {"id": "an-1", "type": "analysis",
                "attributes": {"status": "completed", "stats": {"malicious": 3}}}}));
        }
        ResponseTemplate::new(404).set_body_string(format!("no stand-in for {path}"))
    }
}

impl Fake {
    fn seen(&self, prefix: &str) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path.starts_with(prefix))
            .cloned()
            .collect()
    }
}

async fn fake() -> (MockServer, Fake) {
    let server = MockServer::start().await;
    let f = Fake::default();
    f.data.lock().unwrap().inspector_status = 200;
    Mock::given(any())
        .respond_with(f.clone())
        .mount(&server)
        .await;
    (server, f)
}

fn inspector_answer(sha: &str, filetype: &str, hint: &str) -> Value {
    json!({
        "sha256": sha,
        "filename": "evil.ps1",
        "customer_code": "ignored",
        "filetype": filetype,
        "size": 5,
        "hashes": {"md5": "m", "sha1": "s", "sha256": sha},
        "flags": ["encoded_powershell"],
        "verdict_hint": hint,
        "hardened": false,
        "iocs": {"urls": ["http://evil.example.com/x"]},
        "content": {"behaviors": [{"attack_id": "T1490", "technique": "Inhibit System Recovery",
            "severity": "malicious", "evidence": "vssadmin delete shadows"}]},
        "previews_b64": {"page-1.png": base64::engine::general_purpose::STANDARD.encode(b"\x89PNG-1")},
    })
}

fn vt_report(malicious: i64) -> Value {
    json!({
        "last_analysis_stats": {"malicious": malicious, "suspicious": 0, "undetected": 60, "harmless": 0},
        "popular_threat_classification": {"suggested_threat_label": "trojan.e2e/x"},
        "meaningful_name": "evil.ps1",
        "type_description": "Powershell",
        "names": ["evil.ps1"],
    })
}

fn sha(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

// --- the harness ------------------------------------------------------------------------------

struct Env {
    s3: s3::StandIn,
    fake: Fake,
    server: MockServer,
}

impl Env {
    async fn start() -> Self {
        let s3 = s3::StandIn::start().await;
        let (server, fake) = fake().await;
        Env { s3, fake, server }
    }

    fn vars(&self, sandbox: &str, extra: &str) -> String {
        format!(
            "{}INSPECTOR_URL={}\nSANDBOX_BACKEND={sandbox}\nCAPE_API_URL={}/apiv2/\n\
             CAPE_API_TOKEN=cape-e2e\nCAPE_POLL_INTERVAL=1\nENRICHMENT_VT_POLL=1\n{extra}",
            self.s3.env(),
            self.server.uri(),
            self.server.uri()
        )
    }
}

/// The file-analysis router with VirusTotal on the stand-in (the harness'
/// `COPILOT_VIRUSTOTAL_URL`, set without touching the process environment).
fn router(h: &Harness, env: &Env) -> axum::Router {
    let mut st = h.app.file_analysis.clone();
    let mut ti = st.threat_intel.clone();
    let mut urls = (*ti.urls).clone();
    urls.virustotal = format!("{}/api/v3", env.server.uri());
    ti.urls = Arc::new(urls);
    st.threat_intel = ti;
    axum::Router::new().nest(FA, copilot_file_analysis::router(st))
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    content_type: Option<&str>,
    body: Vec<u8>,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut b = HttpRequest::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    if let Some(ct) = content_type {
        b = b.header("content-type", ct);
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 << 20)
        .await
        .unwrap();
    (status, headers, bytes.to_vec())
}

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let (ct, raw) = match body {
        Some(v) => (Some("application/json"), serde_json::to_vec(&v).unwrap()),
        None => (None, Vec::new()),
    };
    let (status, _, bytes) = send(app, method, uri, Some(token), ct, raw).await;
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, value)
}

const BOUNDARY: &str = "e2e-file-analysis-boundary";

fn multipart(fields: &[(&str, &str)], file: Option<(&str, &[u8])>) -> Vec<u8> {
    let mut body = Vec::new();
    for (k, v) in fields {
        body.extend(
            format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n")
                .as_bytes(),
        );
    }
    if let Some((name, data)) = file {
        body.extend(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend(data);
        body.extend(b"\r\n");
    }
    body.extend(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

async fn upload(
    app: &axum::Router,
    token: &str,
    fields: &[(&str, &str)],
    file: Option<(&str, &[u8])>,
) -> (u16, Value) {
    let (status, _, bytes) = send(
        app,
        "POST",
        &format!("{FA}/upload"),
        Some(token),
        Some(&format!("multipart/form-data; boundary={BOUNDARY}")),
        multipart(fields, file),
    )
    .await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Poll `GET /job/{id}` until it is `done` or `failed` and nothing else is
/// running.
async fn settle(app: &axum::Router, token: &str, job_id: &str) -> Value {
    for _ in 0..600 {
        let (status, body) = call(app, "GET", &format!("{FA}/job/{job_id}"), token, None).await;
        assert_eq!(status, 200, "{body}");
        let job = body["job"].clone();
        let settled = matches!(job["status"].as_str(), Some("done" | "failed"))
            && job["dynamic_status"].as_str() != Some("running");
        if settled {
            return job;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("job {job_id} did not settle");
}

async fn virustotal(h: &Harness) {
    h.exec("DELETE FROM connectors WHERE connector_name = 'VirusTotal'")
        .await;
    h.exec(&format!(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, \
         connector_username, connector_password, connector_api_key, connector_description, \
         connector_supports, connector_configured, connector_verified, connector_accepts_host_only, \
         connector_accepts_api_key, connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
         ('VirusTotal', '3', 'https://www.virustotal.com', '2026-01-02 03:04:05', NULL, NULL, '{VT_KEY}', \
         'desc', 'supports', 1, 1, 0, 1, 0, 0, 0, NULL, 1)"
    ))
    .await;
}

async fn cleanup(h: &Harness) {
    h.exec("DELETE FROM connectors WHERE connector_name IN ('VirusTotal', 'Velociraptor')")
        .await;
    h.exec("DELETE FROM agents WHERE id IN (6650001, 6650002, 6650003, 6650004)")
        .await;
}

fn result_key(code: &str, sha: &str) -> String {
    format!("{code}/{sha}/result.json")
}

fn stored(env: &Env, key: &str) -> Value {
    let (data, _) = env
        .s3
        .object("file-analysis", key)
        .unwrap_or_else(|| panic!("no {key}"));
    serde_json::from_slice(&data).unwrap()
}

// --- the tests --------------------------------------------------------------------------------

#[tokio::test]
async fn upload_runs_the_pipeline_and_stores_what_python_stores() {
    let env = Env::start().await;
    let h = harness_or_skip!(None, &env.vars("none", ""));
    h.seed().await;
    cleanup(&h).await;
    virustotal(&h).await;
    let app = router(&h, &env);
    let acme = h.code("acme");
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let sample = format!("Write-Host {}", h.suffix).into_bytes();
    let digest = sha(&sample);
    {
        let mut d = env.fake.data.lock().unwrap();
        d.inspector = inspector_answer(&digest, "script", "suspicious");
        d.vt_files.insert(digest.clone(), vt_report(7));
    }

    let (status, body) = upload(
        &app,
        &analyst,
        &[("customer_code", &acme), ("sandbox", "false")],
        Some(("evil.ps1", &sample)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["success"], true);
    assert_eq!(body["message"], "analysis queued");
    let job_id = body["job_id"].as_str().unwrap().to_string();
    assert_eq!(job_id.len(), 32);
    let job = settle(&app, &analyst, &job_id).await;
    assert_eq!(job["status"], "done", "{job}");
    assert_eq!(job["static_status"], "done");
    assert_eq!(job["dynamic_status"], Value::Null);
    assert_eq!(job["sandbox_enabled"], false);
    assert_eq!(job["hardened"], false);
    assert_eq!(
        job["verdict"], "malicious",
        "VirusTotal 7/67 is over the threshold"
    );
    assert_eq!(job["filename"], "evil.ps1");
    assert_eq!(job["sha256"], digest);
    assert_eq!(job["customer_code"], acme);
    assert_eq!(job["source"], "upload");

    // The inspector: one multipart POST, the job as `json.dumps` writes it.
    let calls = env.fake.seen("/inspect");
    assert_eq!(calls.len(), 1);
    let text = calls[0].text();
    assert!(
        text.contains(&format!(
            "name=\"job\"\r\n\r\n{{\"sha256\": \"{digest}\", \"filename\": \"evil.ps1\", \
             \"customer_code\": \"{acme}\", \"context\": {{}}}}\r\n"
        )),
        "{text}"
    );
    assert!(
        text.contains(
            "name=\"sample\"; filename=\"sample\"\r\nContent-Type: application/octet-stream"
        ),
        "{text}"
    );
    // VirusTotal: the hash, then the deep intel (the report again and the
    // behaviour summary).
    let vt: Vec<String> = env
        .fake
        .seen("/api/v3")
        .iter()
        .map(|s| s.path.clone())
        .collect();
    assert_eq!(
        vt,
        vec![
            format!("/api/v3/files/{digest}"),
            format!("/api/v3/files/{digest}"),
            format!("/api/v3/files/{digest}/behaviour_summary"),
        ]
    );
    assert_eq!(env.fake.seen("/api/v3")[0].header("x-apikey"), Some(VT_KEY));

    // What is stored, and where.
    let keys = env.s3.keys("file-analysis");
    let mut want = vec![
        format!("jobs/{job_id}.json"),
        format!("{acme}/{digest}/previews/page-1.png"),
        result_key(&acme, &digest),
        format!("{acme}/{digest}/summary.json"),
    ];
    want.sort();
    assert_eq!(keys, want);
    let (png, ct) = env
        .s3
        .object(
            "file-analysis",
            &format!("{acme}/{digest}/previews/page-1.png"),
        )
        .unwrap();
    assert_eq!(
        (png.as_slice(), ct.as_str()),
        (&b"\x89PNG-1"[..], "image/png")
    );
    let (raw, ct) = env
        .s3
        .object("file-analysis", &format!("jobs/{job_id}.json"))
        .unwrap();
    assert_eq!(ct, "application/json");
    let raw = String::from_utf8(raw).unwrap();
    assert!(
        raw.starts_with(&format!(
            "{{\"job_id\": \"{job_id}\", \"sha256\": \"{digest}\""
        )),
        "{raw}"
    );
    let result = stored(&env, &result_key(&acme, &digest));
    assert_eq!(result["engine_version"], 15);
    assert_eq!(result["preview_urls"], json!(["page-1.png"]));
    assert!(result["inspector"].get("previews_b64").is_none());
    assert_eq!(result["reputation"]["found"], true);
    assert_eq!(result["reputation"]["malicious"], 7);
    assert_eq!(result["reputation"]["total"], 67);
    assert_eq!(result["reputation"]["family"], "trojan.e2e/x");
    assert!(result["reputation"]["intel"].is_object());
    assert_eq!(
        result["verdict_reason"],
        "static inspection: suspicious; VirusTotal 7/67"
    );
    let summary = stored(&env, &format!("{acme}/{digest}/summary.json"));
    assert_eq!(summary["job_id"], job_id);
    assert_eq!(summary["vt_malicious"], 7);

    // The routes reading it back.
    let (status, body) = call(
        &app,
        "GET",
        &format!("{FA}/result/{job_id}"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["job"]["job_id"], job_id);
    assert_eq!(body["result"]["sandbox"], Value::Null);
    let (status, headers, bytes) = send(
        &app,
        "GET",
        &format!("{FA}/result/{job_id}/preview/page-1.png"),
        Some(&analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(bytes, b"\x89PNG-1");
    assert!(
        headers.contains(&("content-type".into(), "image/png".into())),
        "{headers:?}"
    );
    let (status, body) = call(
        &app,
        "GET",
        &format!("{FA}/result/{job_id}/preview/other.png"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(
        (status, body["message"].clone()),
        (404, json!("preview not found"))
    );
    let (status, body) = call(
        &app,
        "GET",
        &format!("{FA}/history?customer_code={acme}"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["message"], "1 analyses");
    assert_eq!(body["items"][0]["job_id"], job_id);
    assert_eq!(body["items"][0]["vt_total"], 67);
    let (status, body) = call(
        &app,
        "GET",
        &format!("{FA}/search/{digest}?customer_code={acme}"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        json!({"success": true, "message": "cache hit", "job_id": job_id})
    );
    let (_, body) = call(
        &app,
        "GET",
        &format!("{FA}/search/{digest}"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(
        body,
        json!({"success": true, "message": "customer_code required for cache lookup", "job_id": null})
    );

    // The same bytes again: the cached job, no second inspection.
    let (status, body) = upload(
        &app,
        &analyst,
        &[("customer_code", &acme)],
        Some(("again.ps1", &sample)),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["job_id"], job_id);
    assert_eq!(env.fake.seen("/inspect").len(), 1);

    // The PDF report: wkhtmltopdf as pdfkit runs it.
    let (status, body) = call(
        &app,
        "GET",
        &format!("{FA}/result/{job_id}/cape-report"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(
        (status, body["message"].clone()),
        (404, json!("this analysis has no detonation report"))
    );

    // Delete: the job, the result, the summary and the preview.
    let (status, body) = call(
        &app,
        "DELETE",
        &format!("{FA}/analysis/{job_id}"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": "analysis deleted", "removed": 4})
    );
    assert!(env.s3.keys("file-analysis").is_empty());
    let (status, body) = call(&app, "GET", &format!("{FA}/job/{job_id}"), &analyst, None).await;
    assert_eq!(
        (status, body["message"].clone()),
        (404, json!("job not found"))
    );
    cleanup(&h).await;
}

#[tokio::test]
async fn reputation_off_and_a_detached_upload() {
    let env = Env::start().await;
    let h = harness_or_skip!(None, &env.vars("none", ""));
    h.seed().await;
    cleanup(&h).await;
    virustotal(&h).await;
    let app = router(&h, &env);
    let acme = h.code("acme");
    let admin = h.token(&format!("admin{}", h.suffix), "admin");

    // `off`: nothing is asked of VirusTotal.
    let first = format!("off {}", h.suffix).into_bytes();
    env.fake.data.lock().unwrap().inspector = inspector_answer(&sha(&first), "text", "clean");
    let (_, body) = upload(
        &app,
        &admin,
        &[("customer_code", &acme), ("reputation_mode", "off")],
        Some(("a.txt", &first)),
    )
    .await;
    let job = settle(&app, &admin, body["job_id"].as_str().unwrap()).await;
    assert_eq!(job["verdict"], "clean");
    let result = stored(&env, &result_key(&acme, &sha(&first)));
    assert_eq!(
        result["reputation"],
        json!({"source": "virustotal", "skipped": true, "note": "VirusTotal was turned off for this analysis."})
    );
    assert_eq!(result["verdict_reason"], "");
    assert!(env.fake.seen("/api/v3").is_empty());

    // `upload` on a hash VirusTotal does not know: the placeholder, then the
    // detached upload patches the result and the job.
    let second = format!("upload {}", h.suffix).into_bytes();
    let digest = sha(&second);
    {
        let mut d = env.fake.data.lock().unwrap();
        d.inspector = inspector_answer(&digest, "text", "clean");
        d.vt_after_upload = Some((digest.clone(), vt_report(9)));
    }
    let (_, body) = upload(
        &app,
        &admin,
        &[("customer_code", &acme), ("reputation_mode", "upload")],
        Some(("b.bin", &second)),
    )
    .await;
    let job_id = body["job_id"].as_str().unwrap().to_string();
    settle(&app, &admin, &job_id).await;
    let mut patched = Value::Null;
    for _ in 0..200 {
        patched = stored(&env, &result_key(&acme, &digest));
        if patched["reputation"]["found"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(patched["reputation"]["found"], true, "{patched}");
    assert_eq!(patched["reputation"]["submitted"], true);
    assert_eq!(patched["reputation"]["malicious"], 9);
    assert_eq!(patched["job"]["verdict"], "malicious");
    assert_eq!(patched["verdict_reason"], "VirusTotal 9/69");
    let job = stored(&env, &format!("jobs/{job_id}.json"));
    assert_eq!(job["verdict"], "malicious");
    let posts = env.fake.seen("/api/v3/files");
    let upload = posts.iter().find(|s| s.method == "POST").unwrap();
    assert!(
        upload.text().contains(
            "name=\"file\"; filename=\"b.bin\"\r\nContent-Type: application/octet-stream"
        ),
        "{}",
        upload.text()
    );
    assert_eq!(upload.header("x-apikey"), Some(VT_KEY));
    assert_eq!(upload.header("accept"), Some("application/json"));
    cleanup(&h).await;
}

#[tokio::test]
async fn tenancy_and_validation() {
    let env = Env::start().await;
    let h = harness_or_skip!(None, &env.vars("none", ""));
    h.seed().await;
    let app = router(&h, &env);
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let portal = h.token(&format!("portal{}", h.suffix), "customer_user");
    let job = |id: &str, code: &str| {
        json!({"job_id": id, "sha256": "f".repeat(64), "filename": "x", "customer_code": code,
               "source": "upload", "status": "done", "static_status": "done"})
    };
    let beta_job = format!("beta{}", h.suffix);
    env.s3.put(
        "file-analysis",
        &format!("jobs/{beta_job}.json"),
        job(&beta_job, &beta).to_string().as_bytes(),
    );
    let orphan = format!("orphan{}", h.suffix);
    env.s3.put(
        "file-analysis",
        &format!("jobs/{orphan}.json"),
        json!({"job_id": orphan, "customer_code": null})
            .to_string()
            .as_bytes(),
    );

    for path in [
        format!("{FA}/job/{beta_job}"),
        format!("{FA}/result/{beta_job}"),
        format!("{FA}/result/{beta_job}/cape-report"),
        format!("{FA}/result/{beta_job}/report.pdf"),
        format!("{FA}/result/{beta_job}/preview/x.png"),
        format!("{FA}/job/{orphan}"),
        format!("{FA}/history?customer_code={beta}"),
        format!("{FA}/velociraptor/agents?customer_code={beta}"),
        format!("{FA}/search/{}?customer_code={beta}", "f".repeat(64)),
    ] {
        let (status, body) = call(&app, "GET", &path, &analyst, None).await;
        assert_eq!(status, 403, "{path}: {body}");
    }
    let (status, _) = call(
        &app,
        "DELETE",
        &format!("{FA}/analysis/{beta_job}"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(status, 403);
    assert!(
        env.s3
            .object("file-analysis", &format!("jobs/{beta_job}.json"))
            .is_some()
    );
    let (status, body) = call(
        &app,
        "GET",
        &format!("{FA}/job/nope{}", h.suffix),
        &analyst,
        None,
    )
    .await;
    assert_eq!(
        (status, body["message"].clone()),
        (404, json!("job not found"))
    );
    let (status, _) = call(
        &app,
        "GET",
        &format!("{FA}/history?customer_code={acme}"),
        &portal,
        None,
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = send(
        &app,
        "GET",
        &format!("{FA}/history?customer_code={acme}"),
        None,
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(status, 401);

    // The required query parameter, reported by the dependency and the endpoint.
    let (status, body) = call(&app, "GET", &format!("{FA}/history"), &analyst, None).await;
    assert_eq!(status, 422);
    assert_eq!(body["details"].as_array().unwrap().len(), 2, "{body}");
    let (status, body) = call(
        &app,
        "GET",
        &format!("{FA}/history?customer_code={acme}&limit=x"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(status, 422, "{body}");

    // Uploads and submissions are filed under a customer the caller sees.
    let (status, _) = upload(
        &app,
        &analyst,
        &[("customer_code", &beta)],
        Some(("x", b"x")),
    )
    .await;
    assert_eq!(status, 403);
    let (status, body) = upload(&app, &analyst, &[("customer_code", &acme)], None).await;
    assert_eq!(status, 422, "{body}");
    let (status, body) = upload(
        &app,
        &analyst,
        &[("customer_code", &acme), ("sandbox", "maybe")],
        Some(("x", b"x")),
    )
    .await;
    assert_eq!(status, 422, "{body}");
    let (status, body) = upload(
        &app,
        &analyst,
        &[("customer_code", &acme), ("reputation_mode", "all")],
        Some(("x", b"x")),
    )
    .await;
    assert_eq!(
        (status, body["message"].clone()),
        (400, json!("reputation_mode must be off|lookup|upload"))
    );
    let submit = |b: Value| {
        let app = app.clone();
        let analyst = analyst.clone();
        async move { call(&app, "POST", &format!("{FA}/submit"), &analyst, Some(b)).await }
    };
    let (status, _) = submit(json!({"source": "host_path", "customer_code": beta, "client_id": "C.1", "target_path": "/x"})).await;
    assert_eq!(status, 403);
    let (status, body) = submit(json!({"source": "upload", "customer_code": acme})).await;
    assert_eq!(
        (status, body["message"].clone()),
        (400, json!("use /upload for source=upload"))
    );
    let (status, body) =
        submit(json!({"source": "host_path", "customer_code": acme, "target_path": "/x"})).await;
    assert_eq!(
        (status, body["message"].clone()),
        (
            400,
            json!("host_path source requires hostname or client_id")
        )
    );
    let (status, body) =
        submit(json!({"source": "host_path", "customer_code": acme, "client_id": "C.1"})).await;
    assert_eq!(
        (status, body["message"].clone()),
        (400, json!("host_path source requires target_path"))
    );
    let (status, body) =
        submit(json!({"source": "host_path", "customer_code": acme, "tiers": ["x"]})).await;
    assert_eq!(status, 422, "{body}");
    let (status, _, _) = send(
        &app,
        "POST",
        &format!("{FA}/submit"),
        Some(&analyst),
        Some("application/json"),
        b"{".to_vec(),
    )
    .await;
    assert_eq!(status, 422);
    // §4: another tenant's endpoint is refused before anything runs.
    let (status, body) = submit(json!({"source": "host_path", "customer_code": acme, "client_id": "C.nobody", "target_path": "/x"})).await;
    assert_eq!(
        (status, body["message"].clone()),
        (403, json!("Access denied to client C.nobody"))
    );
    let (status, body) = call(
        &app,
        "POST",
        &format!("{FA}/velociraptor/enumerate"),
        &analyst,
        Some(json!({"customer_code": beta, "client_id": "C.1", "target_path": "/x"})),
    )
    .await;
    assert_eq!(status, 403, "{body}");
}

#[tokio::test]
async fn host_path_collects_through_velociraptor() {
    use copilot_velociraptor::testing::{Answer, StandIn};
    let env = Env::start().await;
    let velo = StandIn::start(|args| {
        let vql = args.query[0].vql.clone();
        if vql.starts_with("SELECT os_info.system AS os FROM clients()") {
            Answer::rows(&[r#"[{"os": "linux"}]"#])
        } else if vql.starts_with("SELECT collect_client(") && vql.contains("/gone") {
            Answer::rows(&[r#"[{"Flow": {"flow_id": "F.GONE"}}]"#])
        } else if vql.starts_with("SELECT collect_client(") {
            Answer::rows(&[r#"[{"Flow": {"flow_id": "F.E2E"}}]"#])
        } else if vql.starts_with("SELECT * FROM uploads(") && vql.contains("F.GONE") {
            Answer::rows(&["[]"])
        } else if vql.starts_with("SELECT * FROM uploads(") {
            Answer::rows(&[r#"[{"vfs_path": "/clients/C.e2eaaa/collections/F.E2E/uploads/auto/etc/hostname", "client_path": "/etc/hostname", "file_size": 9}]"#])
        } else if vql.starts_with("SELECT read_file(") {
            Answer::rows(&[r#"[{"Data": "e2e-host\n"}]"#])
        } else if vql.starts_with("SELECT * FROM source(") {
            Answer::rows(&[r#"[{"OSPath": "/etc/hostname", "Size": 9, "Hash": {"SHA256": "abc"}}, {"Path": "C:\\x\\y.txt"}]"#])
        } else if vql
            .starts_with("SELECT client_id, last_seen_at FROM clients(search='host:e2e-a')")
            || vql.starts_with("SELECT client_id, last_seen_at FROM clients()")
        {
            Answer::rows(&[r#"[{"client_id": "C.e2eaaa", "last_seen_at": 4102444800000000}]"#])
        } else {
            Answer::rows(&["[]"])
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let config = velo.write_api_config(dir.path());
    let h = harness_or_skip!(None, &env.vars("none", "FILE_ANALYSIS_COLLECT_TIMEOUT=1\n"));
    h.seed().await;
    cleanup(&h).await;
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    for (id, host, code, client) in [
        (6650001, "e2e-a", Some(acme.as_str()), "C.e2eaaa"),
        (6650002, "e2e-b", Some(beta.as_str()), "C.e2ebbb"),
        (6650003, "e2e-orphan", None, "C.e2eccc"),
    ] {
        sqlx::query(
            "INSERT INTO agents (id, agent_id, ip_address, os, hostname, label, critical_asset, \
             wazuh_last_seen, velociraptor_id, wazuh_agent_version, wazuh_agent_status, \
             customer_code, quarantined, velociraptor_id_pinned) VALUES (?, ?, '10.0.0.1', \
             'Ubuntu', ?, 'grp', 0, '2026-10-15 08:00:00', ?, 'v4', 'active', ?, 0, 0)",
        )
        .bind(id)
        .bind(format!("{}{id}", h.suffix))
        .bind(host)
        .bind(client)
        .bind(code)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
    h.exec(&format!(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, \
         connector_username, connector_password, connector_api_key, connector_description, \
         connector_supports, connector_configured, connector_verified, connector_accepts_host_only, \
         connector_accepts_api_key, connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
         ('Velociraptor', '3', 'https://velo', '2026-01-02 03:04:05', NULL, NULL, '{config}', 'desc', \
         'supports', 1, 1, 0, 0, 0, 1, 0, NULL, 1)"
    ))
    .await;
    let app = router(&h, &env);
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let data = b"e2e-host\n";
    env.fake.data.lock().unwrap().inspector = inspector_answer(&sha(data), "text", "clean");

    // The agent list: the customer's, then (for an admin) the unassigned ones.
    let (status, body) = call(
        &app,
        "GET",
        &format!("{FA}/velociraptor/agents?customer_code={acme}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let hosts: Vec<(Value, Value, Value)> = body["agents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["hostname"].clone(),
                a["online"].clone(),
                a["unassigned"].clone(),
            )
        })
        .collect();
    assert_eq!(
        hosts,
        vec![
            (json!("e2e-a"), json!(true), json!(false)),
            (json!("e2e-orphan"), json!(false), json!(true))
        ]
    );
    // §4: a scoped analyst is not shown unassigned endpoints.
    let (_, body) = call(
        &app,
        "GET",
        &format!("{FA}/velociraptor/agents?customer_code={acme}"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(body["agents"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["message"], format!("1 agents for {acme}"));

    // Enumerate: the source rows as MatchInfo.
    let (status, body) = call(
        &app,
        "POST",
        &format!("{FA}/velociraptor/enumerate"),
        &analyst,
        Some(json!({"customer_code": acme, "client_id": "C.e2eaaa", "target_path": "/etc/host*"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": "2 match(es)", "matches": [
            {"path": "/etc/hostname", "name": "hostname", "size": 9, "sha256": "abc"},
            {"path": "C:\\x\\y.txt", "name": "y.txt", "size": 0, "sha256": ""}]})
    );
    // §4: another tenant's client, by id or by hostname.
    let (status, _) = call(
        &app,
        "POST",
        &format!("{FA}/velociraptor/enumerate"),
        &analyst,
        Some(json!({"customer_code": acme, "client_id": "C.e2ebbb", "target_path": "/x"})),
    )
    .await;
    assert_eq!(status, 403);
    let (status, body) = call(
        &app,
        "POST",
        &format!("{FA}/submit"),
        &analyst,
        Some(json!({"source": "host_path", "customer_code": acme, "hostname": "e2e-b", "target_path": "/x"})),
    )
    .await;
    assert_eq!(
        (status, body["message"].clone()),
        (403, json!("Access denied to host e2e-b"))
    );

    // A collection by hostname: the file's own name and hash.
    let before = velo.vql().len();
    let (status, body) = call(
        &app,
        "POST",
        &format!("{FA}/submit"),
        &analyst,
        Some(json!({"source": "host_path", "customer_code": acme, "hostname": "e2e-a", "target_path": "/etc/hostname"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let job = settle(&app, &analyst, body["job_id"].as_str().unwrap()).await;
    assert_eq!(job["status"], "done", "{job}");
    assert_eq!(job["filename"], "hostname");
    assert_eq!(job["sha256"], sha(data));
    assert_eq!(job["source"], "host_path");
    let vql = velo.vql()[before..].to_vec();
    assert!(
        vql[0].starts_with("SELECT client_id, last_seen_at FROM clients(search='host:e2e-a')"),
        "{vql:?}"
    );
    assert!(
        vql.iter().any(|q| q.starts_with(
            "SELECT collect_client(client_id='C.e2eaaa', artifacts=['Linux.Search.FileFinder'], \
             env=dict(SearchFilesGlob='/etc/hostname', Upload_File='Y', Calculate_Hash='Y'))"
        )),
        "{vql:?}"
    );
    let inspected = env.fake.seen("/inspect");
    assert!(
        inspected
            .last()
            .unwrap()
            .text()
            .contains("\"filename\": \"hostname\"")
    );

    // A file the endpoint no longer has: the job fails as Python's does.
    let (status, body) = call(
        &app,
        "POST",
        &format!("{FA}/submit"),
        &analyst,
        Some(json!({"source": "host_path", "customer_code": acme, "client_id": "C.e2eaaa", "target_path": "/gone"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let job = settle(&app, &analyst, body["job_id"].as_str().unwrap()).await;
    assert_eq!(job["status"], "failed", "{job}");
    assert_eq!(job["static_status"], "failed");
    assert_eq!(job["error"], "sample could not be retrieved (file gone?)");

    // §4: an id that is not a Velociraptor client id never reaches a VQL
    // collection (Python interpolated it into `collect_client(...)`).
    let before = velo.vql().len();
    let (status, body) = call(
        &app,
        "POST",
        &format!("{FA}/submit"),
        &admin,
        Some(json!({"source": "host_path", "customer_code": acme, "client_id": "C.1', artifacts=['X", "target_path": "/x"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let job = settle(&app, &admin, body["job_id"].as_str().unwrap()).await;
    assert_eq!(job["status"], "failed", "{job}");
    assert!(
        velo.vql()[before..]
            .iter()
            .all(|q| !q.starts_with("SELECT collect_client(")),
        "{:?}",
        velo.vql()
    );
    cleanup(&h).await;
}

/// A zip of `names` (stored, no compression).
fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in entries {
        let offset = out.len() as u32;
        let crc = crc32(data);
        let local = |sig: u32| {
            let mut h = Vec::new();
            h.extend(sig.to_le_bytes());
            h
        };
        let mut header = local(0x0403_4b50);
        header.extend(20u16.to_le_bytes());
        header.extend(0u16.to_le_bytes());
        header.extend(0u16.to_le_bytes());
        header.extend(0u32.to_le_bytes());
        header.extend(crc.to_le_bytes());
        header.extend((data.len() as u32).to_le_bytes());
        header.extend((data.len() as u32).to_le_bytes());
        header.extend((name.len() as u16).to_le_bytes());
        header.extend(0u16.to_le_bytes());
        header.extend(name.as_bytes());
        out.extend(&header);
        out.extend(*data);
        let mut c = local(0x0201_4b50);
        c.extend(20u16.to_le_bytes());
        c.extend(20u16.to_le_bytes());
        c.extend(0u16.to_le_bytes());
        c.extend(0u16.to_le_bytes());
        c.extend(0u32.to_le_bytes());
        c.extend(crc.to_le_bytes());
        c.extend((data.len() as u32).to_le_bytes());
        c.extend((data.len() as u32).to_le_bytes());
        c.extend((name.len() as u16).to_le_bytes());
        c.extend([0u8; 12]);
        c.extend(offset.to_le_bytes());
        c.extend(name.as_bytes());
        central.extend(c);
    }
    let start = out.len() as u32;
    out.extend(&central);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0u8; 4]);
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((central.len() as u32).to_le_bytes());
    out.extend(start.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for b in data {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[tokio::test]
async fn detonation_cape_report_and_the_pdf() {
    let env = Env::start().await;
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("argv.txt");
    let wrapper = dir.path().join("wkhtmltopdf");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {rec}\nfor last; do :; done\nprev=''\n\
             for a; do if [ \"$a\" = \"$last\" ]; then break; fi; prev=$a; done\n\
             cp \"$prev\" {rec}.html\nprintf '%%PDF-1.4 e2e' > \"$last\"\n",
            rec = record.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let h = harness_or_skip!(
        None,
        &env.vars(
            "remote",
            &format!("COPILOT_WKHTMLTOPDF={}\n", wrapper.display())
        )
    );
    h.seed().await;
    cleanup(&h).await;
    let app = router(&h, &env);
    let acme = h.code("acme");
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let sample = format!("vssadmin delete shadows {}", h.suffix).into_bytes();
    let digest = sha(&sample);
    let report = json!({
        "info": {"id": 77, "duration": 42, "machine": {"name": "capewin", "platform": "windows"}},
        "malscore": 6.5,
        "signatures": [{"name": "deletes_shadow_copies", "severity": 4, "description": "Deletes shadow copies"},
                       {"name": "antivm_generic_disk", "severity": 2}],
        "network": {"hosts": ["1.2.3.4"], "tcp": [{"dst": "1.2.3.4", "dport": 443}]},
        "behavior": {"processes": [{"process_name": "powershell.exe", "process_id": 10, "parent_id": 1}]},
    });
    {
        let mut d = env.fake.data.lock().unwrap();
        d.inspector = inspector_answer(&digest, "script", "suspicious");
        d.cape_report = report.clone();
        d.cape_zip = zip(&[
            ("shots/0002.jpg", b"jpeg-2"),
            ("shots/0001.jpg", b"jpeg-1"),
            ("notes.txt", b"x"),
        ]);
    }
    let (status, body) = upload(
        &app,
        &analyst,
        &[("customer_code", &acme), ("reputation_mode", "off")],
        Some(("ransom.ps1", &sample)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let job_id = body["job_id"].as_str().unwrap().to_string();
    let job = settle(&app, &analyst, &job_id).await;
    assert_eq!(job["sandbox_enabled"], true, "{job}");
    assert_eq!(job["dynamic_status"], "done", "{job}");
    assert_eq!(job["verdict"], "malicious");
    // CAPE: status, the sha search (a failed task is not reused), the submit.
    let cape: Vec<String> = env
        .fake
        .seen("/apiv2")
        .iter()
        .map(|s| s.path.clone())
        .collect();
    assert_eq!(
        cape,
        vec![
            "/apiv2/cuckoo/status/".to_string(),
            format!("/apiv2/tasks/search/sha256/{digest}/"),
            "/apiv2/tasks/create/file/".to_string(),
            "/apiv2/tasks/view/77/".to_string(),
            "/apiv2/tasks/get/report/77/json/".to_string(),
        ]
    );
    let created = &env.fake.seen("/apiv2/tasks/create")[0];
    assert_eq!(created.header("authorization"), Some("Token cape-e2e"));
    let text = created.text();
    for part in [
        "name=\"package\"\r\n\r\n\r\n".to_string(),
        format!("name=\"custom\"\r\n\r\n{acme}|upload\r\n"),
        "name=\"timeout\"\r\n\r\n120\r\n".to_string(),
        "name=\"file\"; filename=\"ransom.ps1\"\r\nContent-Type: application/octet-stream"
            .to_string(),
    ] {
        assert!(text.contains(&part), "{part:?} in {text}");
    }
    let result = stored(&env, &result_key(&acme, &digest));
    assert_eq!(result["sandbox"]["task_id"], 77);
    assert_eq!(result["sandbox"]["machine"], "capewin (windows)");
    assert_eq!(result["sandbox"]["verdict"], "malicious");
    assert_eq!(
        result["verdict_reason"],
        "static inspection: suspicious; sandbox: signature at severity 4"
    );

    // The raw report, from CAPE.
    let (status, body) = call(
        &app,
        "GET",
        &format!("{FA}/result/{job_id}/cape-report"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, report);

    // The PDF: the screenshots fetched, the HTML rendered, pdfkit's command line.
    let (status, headers, bytes) = send(
        &app,
        "GET",
        &format!("{FA}/result/{job_id}/report.pdf"),
        Some(&analyst),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&bytes));
    assert_eq!(bytes, b"%PDF-1.4 e2e");
    let header = |n: &str| headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(header("content-type").as_deref(), Some("application/pdf"));
    assert_eq!(
        header("content-disposition"),
        Some(format!(
            "attachment; filename=\"file-analysis-{}.pdf\"",
            &digest[..12]
        ))
    );
    assert_eq!(header("content-length").as_deref(), Some("12"));
    assert!(header("etag").is_some() && header("last-modified").is_some());
    let argv: Vec<String> = std::fs::read_to_string(&record)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(
        argv[..13],
        [
            "--disable-local-file-access",
            "--footer-right",
            "[page]/[topage]",
            "--footer-font-size",
            "7",
            "--footer-spacing",
            "4",
            "--margin-top",
            "14mm",
            "--margin-bottom",
            "16mm",
            "--encoding",
            "UTF-8",
        ]
    );
    assert_eq!(argv[13], "--quiet");
    assert!(
        argv[14].ends_with(".html") && argv[15] == argv[14].replace(".html", ".pdf"),
        "{argv:?}"
    );
    assert!(
        !std::path::Path::new(&argv[14]).exists(),
        "the temporary HTML is removed"
    );
    let html = std::fs::read_to_string(format!("{}.html", record.display())).unwrap();
    assert!(html.contains("evil.ps1"), "the inspector's file name");
    assert!(html.contains("deletes_shadow_copies"));
    let shot = base64::engine::general_purpose::STANDARD.encode(b"jpeg-1");
    assert!(html.contains(&format!("data:image/jpeg;base64,{shot}")));
    let first = html.find(&shot).unwrap();
    let second = html
        .find(&base64::engine::general_purpose::STANDARD.encode(b"jpeg-2"))
        .unwrap();
    assert!(first < second, "screenshots in name order");
    // A range of it, as Starlette's FileResponse answers one.
    let (status, headers, bytes) = {
        let mut b = HttpRequest::builder()
            .method("GET")
            .uri(format!("{FA}/result/{job_id}/report.pdf"))
            .header("authorization", format!("Bearer {analyst}"))
            .header("range", "bytes=0-3");
        b = b.header("accept-encoding", "identity");
        let resp = app
            .clone()
            .oneshot(b.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_string()))
            .collect();
        (
            status,
            headers,
            axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .unwrap(),
        )
    };
    assert_eq!(status, 206);
    assert_eq!(&bytes[..], b"%PDF");
    assert!(
        headers.contains(&("content-range".into(), "bytes 0-3/12".into())),
        "{headers:?}"
    );
    cleanup(&h).await;
}

#[tokio::test]
async fn without_a_sandbox_the_cape_report_is_a_502() {
    let env = Env::start().await;
    let h = harness_or_skip!(
        None,
        &env.vars("none", "COPILOT_WKHTMLTOPDF=/nonexistent/wkhtmltopdf\n")
    );
    h.seed().await;
    let app = router(&h, &env);
    let acme = h.code("acme");
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let id = format!("cape{}", h.suffix);
    let digest = "e".repeat(64);
    env.s3.put(
        "file-analysis",
        &format!("jobs/{id}.json"),
        json!({"job_id": id, "sha256": digest, "customer_code": acme})
            .to_string()
            .as_bytes(),
    );
    env.s3.put(
        "file-analysis",
        &result_key(&acme, &digest),
        json!({"job": {"job_id": id, "customer_code": acme}, "sandbox": {"task_id": 9}})
            .to_string()
            .as_bytes(),
    );
    let (status, body) = call(
        &app,
        "GET",
        &format!("{FA}/result/{id}/cape-report"),
        &admin,
        None,
    )
    .await;
    assert_eq!(
        (status, body["message"].clone()),
        (
            502,
            json!("could not fetch the CAPE report: SANDBOX_BACKEND=none: detonation is disabled")
        )
    );
    let (status, body) = call(
        &app,
        "GET",
        &format!("{FA}/result/{id}/report.pdf"),
        &admin,
        None,
    )
    .await;
    assert_eq!(status, 500, "{body}");
    assert_eq!(
        body["message"],
        "could not generate the PDF report: Failed to convert HTML to PDF: No valid wkhtmltopdf \
         executable found. Ensure wkhtmltopdf is installed and accessible."
    );
    let (status, body) = call(&app, "GET", &format!("{FA}/result/{id}"), &admin, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["inspector"], json!({}));
    assert_eq!(body["result"]["job"]["status"], "pending");
}
