//! End-to-end tests of the agents' report routers (`copilot-agent-reports`:
//! `/api/vulnerabilities`, `/api/sca`, `/api/syscollector`) and the
//! Velociraptor collections that store into MinIO (`POST
//! /api/artifacts/collect`, `…/collect/file/agent/{agent_id}`), through the
//! production router on a real MySQL.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13307/copilot \
//!   cargo test -p copilot --test e2e_agent_reports -- --test-threads=1
//! ```
//!
//! Stand-ins, each on the port its variable names:
//!
//! - `AGENT_REPORTS_E2E_UPSTREAM_PORT` (default 5737): the Wazuh indexer and
//!   manager, the CoPilot-SCA repository on GitHub, by path;
//! - `AGENT_REPORTS_E2E_S3_PORT` (5738): MinIO, in memory, every SigV4
//!   signature recomputed from what arrived;
//! - `AGENT_REPORTS_E2E_VELO_PORT` (5739): Velociraptor (`copilot-velociraptor`'s
//!   gRPC stand-in over mutual TLS).
//!
//! The tests borrow the `Wazuh-Indexer`, `Wazuh-Manager` and `Velociraptor`
//! connector rows (created when missing, restored afterwards).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use axum::body::Body;
use http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

use copilot_velociraptor::testing::{Answer, StandIn};

#[macro_use]
mod common;
use common::*;

fn port(var: &str, default: u16) -> u16 {
    std::env::var(var)
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(default)
}

fn upstream_port() -> u16 {
    port("AGENT_REPORTS_E2E_UPSTREAM_PORT", 5737)
}

fn velo_port() -> u16 {
    port("AGENT_REPORTS_E2E_VELO_PORT", 5739)
}

mod s3 {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, Mutex, OnceLock};

    use axum::body::Bytes;
    use axum::extract::DefaultBodyLimit;
    use axum::response::{IntoResponse, Response};
    use http::{HeaderMap, Method, StatusCode, Uri};

    use copilot_objectstore::sigv4::{self, Credentials};
    use copilot_objectstore::web::py_unquote;

    pub const ACCESS_KEY: &str = "e2e-reports";
    pub const SECRET_KEY: &str = "e2e-reports-secret";
    const NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

    #[derive(Default)]
    struct State {
        buckets: BTreeMap<String, BTreeMap<String, (Vec<u8>, String)>>,
        bad_signatures: usize,
    }

    pub struct StandIn {
        state: Mutex<State>,
    }

    static STANDIN: OnceLock<Arc<StandIn>> = OnceLock::new();

    pub fn port() -> u16 {
        super::port("AGENT_REPORTS_E2E_S3_PORT", 5738)
    }

    /// Started once for the whole run, on a runtime of its own.
    pub fn get() -> Arc<StandIn> {
        STANDIN
            .get_or_init(|| {
                let standin = Arc::new(StandIn {
                    state: Mutex::new(State::default()),
                });
                let listener = std::net::TcpListener::bind(("127.0.0.1", port())).expect("bind");
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
        pub fn object(&self, bucket: &str, key: &str) -> Option<(Vec<u8>, String)> {
            self.state
                .lock()
                .unwrap()
                .buckets
                .get(bucket)
                .and_then(|b| b.get(key))
                .cloned()
        }

        pub fn bad_signatures(&self) -> usize {
            self.state.lock().unwrap().bad_signatures
        }

        fn handle(&self, method: &Method, uri: &Uri, headers: &HeaderMap, body: &[u8]) -> Response {
            let raw_path = uri.path().to_string();
            let raw_query = uri.query().unwrap_or("").to_string();
            let mut state = self.state.lock().unwrap();
            let head = method == Method::HEAD;
            if verify(method.as_str(), &raw_path, &raw_query, headers) != "ok" {
                state.bad_signatures += 1;
                return error(403, "SignatureDoesNotMatch", head);
            }
            let path = py_unquote(&raw_path);
            let query: HashMap<String, String> = raw_query
                .split('&')
                .filter(|p| !p.is_empty())
                .map(|p| {
                    let (k, v) = p.split_once('=').unwrap_or((p, ""));
                    (py_unquote(k), py_unquote(v))
                })
                .collect();
            let (bucket, key) = match path[1..].split_once('/') {
                Some((b, k)) => (b.to_string(), k.to_string()),
                None => (path[1..].to_string(), String::new()),
            };
            if key.is_empty() {
                if method == Method::PUT {
                    state.buckets.entry(bucket.clone()).or_default();
                    return (StatusCode::OK, [("Location", format!("/{bucket}"))]).into_response();
                }
                if !state.buckets.contains_key(&bucket) {
                    return error(404, "NoSuchBucket", head);
                }
                if query.contains_key("location") {
                    return (
                        StatusCode::OK,
                        [("Content-Type", "application/xml")],
                        format!(
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LocationConstraint \
                             xmlns=\"{NS}\"></LocationConstraint>"
                        ),
                    )
                        .into_response();
                }
                return StatusCode::OK.into_response();
            }
            let Some(objects) = state.buckets.get_mut(&bucket) else {
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
        let (Some(_), _, Some(region)) = (scope.next(), scope.next(), scope.next()) else {
            return "malformed";
        };
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

fn env() -> String {
    s3::get();
    format!(
        "COPILOT_MINIO_ENDPOINT=127.0.0.1:{}\nMINIO_ROOT_USER={}\nMINIO_ROOT_PASSWORD={}\n",
        s3::port(),
        s3::ACCESS_KEY,
        s3::SECRET_KEY
    )
}

// --- the upstream stand-in ----------------------------------------------------------

/// One request the upstream stand-in received.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    query: String,
    body: Value,
}

#[derive(Default)]
struct Data {
    /// Vulnerability documents (`_source` included).
    vulns: Vec<Value>,
    /// Package-inventory documents.
    packages: Vec<Value>,
    /// `GET /sca/{agent_id}`'s `affected_items`, by agent id.
    sca: Vec<(String, Value)>,
    /// `GET /syscollector/{agent_id}/packages`'s `affected_items`.
    syscollector: Vec<(String, Value)>,
    /// The CoPilot-SCA files, by path.
    github: Vec<(String, u16, String)>,
}

#[derive(Clone, Default)]
struct Upstream {
    data: Arc<Mutex<Data>>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

/// Every `agent.name` / `agent.id` value a query names.
fn named(query: &Value, field: &str, out: &mut Vec<String>) {
    match query {
        Value::Object(map) => {
            for (k, v) in map {
                if k == field {
                    match v {
                        Value::String(s) => out.push(s.clone()),
                        Value::Array(items) => {
                            out.extend(items.iter().filter_map(|i| i.as_str().map(str::to_string)))
                        }
                        _ => {}
                    }
                }
                named(v, field, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|i| named(i, field, out)),
        _ => {}
    }
}

fn filtered(docs: &[Value], query: &Value, field: &str, pointer: &str) -> Vec<Value> {
    let mut names = Vec::new();
    named(query, field, &mut names);
    docs.iter()
        .filter(|d| {
            names.is_empty()
                || d.pointer(pointer)
                    .and_then(Value::as_str)
                    .is_some_and(|n| names.iter().any(|x| x == n))
        })
        .cloned()
        .collect()
}

impl Respond for Upstream {
    fn respond(&self, req: &wiremock::Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        let path = req.url.path().to_string();
        let query = req.url.query().unwrap_or("").to_string();
        let method = req.method.to_string();
        self.seen.lock().unwrap().push(Seen {
            method: method.clone(),
            path: path.clone(),
            query: query.clone(),
            body: body.clone(),
        });
        let data = self.data.lock().unwrap();
        let ok = |v: Value| ResponseTemplate::new(200).set_body_json(v);
        if let Some((_, status, text)) = data.github.iter().find(|(p, _, _)| *p == path) {
            return ResponseTemplate::new(*status).set_body_string(text.clone());
        }
        if path == "/security/user/authenticate" {
            return ok(json!({"data": {"token": "tok"}, "error": 0}));
        }
        if let Some(agent) = path.strip_prefix("/sca/") {
            return match data.sca.iter().find(|(a, _)| a == agent) {
                Some((_, items)) => ok(json!({"data": {"affected_items": items}, "error": 0})),
                None => ResponseTemplate::new(400).set_body_json(
                    json!({"title": "Wazuh Cluster Error", "detail": "Unknown node ID", "error": 3022}),
                ),
            };
        }
        if let Some(rest) = path.strip_prefix("/syscollector/") {
            let agent = rest.trim_end_matches("/packages");
            let items = data
                .syscollector
                .iter()
                .find(|(a, _)| a == agent)
                .map(|(_, i)| i.clone())
                .unwrap_or(json!([]));
            let n = items.as_array().map_or(0, Vec::len);
            return ok(
                json!({"data": {"affected_items": items, "total_affected_items": n}, "error": 0}),
            );
        }
        if path == "/*/_alias" {
            return ok(json!({
                "wazuh-states-vulnerabilities-e2e": {"aliases": {}},
                "wazuh-alerts-e2e": {"aliases": {}}
            }));
        }
        if path == "/_search/scroll" {
            return if method == "DELETE" {
                ok(json!({"succeeded": true, "num_freed": 1}))
            } else {
                ok(json!({"_scroll_id": "scroll-2", "hits": {"hits": []}}))
            };
        }
        if path.starts_with("/wazuh-states-inventory-packages-") {
            let hits = filtered(&data.packages, &body, "agent.id", "/_source/agent/id");
            let hits = filtered(&hits, &body, "package.name", "/_source/package/name");
            return ok(json!({"hits": {"total": {"value": hits.len()}, "hits": hits}}));
        }
        let hits = filtered(&data.vulns, &body, "agent.name", "/_source/agent/name");
        if path.ends_with("/_count") {
            return ok(json!({"count": hits.len()}));
        }
        if body.get("aggs").is_some() {
            let mut buckets: Vec<(String, usize)> = Vec::new();
            for h in &hits {
                let sev = h
                    .pointer("/_source/vulnerability/severity")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                match buckets.iter_mut().find(|(k, _)| *k == sev) {
                    Some(b) => b.1 += 1,
                    None => buckets.push((sev, 1)),
                }
            }
            let buckets: Vec<Value> = buckets
                .into_iter()
                .map(|(k, n)| json!({"key": k, "doc_count": n}))
                .collect();
            return ok(json!({
                "hits": {"total": {"value": hits.len()}, "hits": []},
                "aggregations": {"severity_counts": {"buckets": buckets}}
            }));
        }
        if query.contains("scroll=") {
            return ok(json!({"_scroll_id": "scroll-1", "hits": {"hits": hits}}));
        }
        ok(json!({"hits": {"total": {"value": hits.len()}, "hits": hits}}))
    }
}

impl Upstream {
    fn take(&self) -> Vec<Seen> {
        std::mem::take(&mut self.seen.lock().unwrap())
    }
}

/// The upstream stand-in on its assigned port (retried while the previous
/// test's server lets the port go).
async fn upstream() -> (MockServer, Upstream) {
    let mut tries = 0;
    let listener = loop {
        match std::net::TcpListener::bind(("127.0.0.1", upstream_port())) {
            Ok(l) => break l,
            Err(_) if tries < 50 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => panic!("bind the upstream stand-in: {e}"),
        }
    };
    let server = MockServer::builder().listener(listener).start().await;
    let up = Upstream::default();
    Mock::given(any())
        .respond_with(up.clone())
        .mount(&server)
        .await;
    (server, up)
}

// --- rows -------------------------------------------------------------------------------

/// An agent of `customer`; returns its `agent_id`.
async fn agent(
    h: &Harness,
    key: &str,
    hostname: &str,
    os: &str,
    customer: &str,
    velociraptor_id: Option<&str>,
) -> String {
    let agent_id = format!("{}{key}", h.suffix);
    sqlx::query(
        "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, \
         velociraptor_id, velociraptor_last_seen, wazuh_agent_version, wazuh_agent_status, \
         velociraptor_agent_version, customer_code, quarantined, velociraptor_org, velociraptor_id_pinned) \
         VALUES (?, '10.0.0.1', ?, ?, 'grp', 0, '2026-10-15 08:00:00', ?, NULL, 'Wazuh v4.9.0', \
         'active', NULL, ?, 0, 'root', 0)",
    )
    .bind(&agent_id)
    .bind(os)
    .bind(hostname)
    .bind(velociraptor_id)
    .bind(customer)
    .execute(h.db.pool())
    .await
    .unwrap();
    agent_id
}

/// A connector row's URL, user name, password and API key.
type ConnectorValues = (String, Option<String>, Option<String>, Option<String>);
/// A connector row: its id, URL, user name, password and API key.
type ConnectorRow = (i64, String, Option<String>, Option<String>, Option<String>);
/// The connectors pointed at a stand-in, with what each held (`None`: created).
type Borrowed = Vec<(i64, Option<ConnectorValues>)>;

/// Point the named connector at a stand-in (created when missing); what to
/// give back.
async fn borrow(
    h: &Harness,
    out: &mut Borrowed,
    name: &str,
    url: &str,
    user: Option<&str>,
    pass: Option<&str>,
    key: Option<&str>,
) {
    let existing: Option<ConnectorRow> = sqlx::query_as(
        "SELECT id, connector_url, connector_username, connector_password, connector_api_key \
             FROM connectors WHERE connector_name = ? ORDER BY id LIMIT 1",
    )
    .bind(name)
    .fetch_optional(h.db.pool())
    .await
    .unwrap();
    match existing {
        Some((id, u, us, pw, k)) => {
            sqlx::query(
                "UPDATE connectors SET connector_url = ?, connector_username = ?, \
                 connector_password = ?, connector_api_key = ? WHERE id = ?",
            )
            .bind(url)
            .bind(user)
            .bind(pass)
            .bind(key)
            .bind(id)
            .execute(h.db.pool())
            .await
            .unwrap();
            out.push((id, Some((u, us, pw, k))));
        }
        None => {
            let id = sqlx::query(
                "INSERT INTO connectors (connector_name, connector_type, connector_url, \
                 connector_last_updated, connector_username, connector_password, connector_api_key, \
                 connector_description, connector_supports, connector_configured, connector_verified, \
                 connector_accepts_host_only, connector_accepts_api_key, \
                 connector_accepts_username_password, connector_accepts_file, \
                 connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
                 (?, '4.8', ?, '2026-01-02 03:04:05', ?, ?, ?, 'desc', 'supports', 1, 1, 0, 0, 1, 1, 0, \
                 NULL, 1)",
            )
            .bind(name)
            .bind(url)
            .bind(user)
            .bind(pass)
            .bind(key)
            .execute(h.db.pool())
            .await
            .unwrap()
            .last_insert_id();
            out.push((i64::try_from(id).unwrap(), None));
        }
    }
}

async fn give_back(h: &Harness, borrowed: Borrowed) {
    for (id, old) in borrowed {
        match old {
            Some((u, us, pw, k)) => {
                sqlx::query(
                    "UPDATE connectors SET connector_url = ?, connector_username = ?, \
                     connector_password = ?, connector_api_key = ? WHERE id = ?",
                )
                .bind(u)
                .bind(us)
                .bind(pw)
                .bind(k)
                .bind(id)
                .execute(h.db.pool())
                .await
                .unwrap();
            }
            None => {
                h.exec(&format!(
                    "DELETE FROM connectorhistory WHERE connector_id = {id}"
                ))
                .await;
                h.exec(&format!("DELETE FROM connectors WHERE id = {id}"))
                    .await;
            }
        }
    }
}

async fn wazuh(h: &Harness, out: &mut Borrowed) {
    let url = format!("http://127.0.0.1:{}", upstream_port());
    borrow(
        h,
        out,
        "Wazuh-Indexer",
        &url,
        Some("indexer"),
        Some("pw"),
        None,
    )
    .await;
    borrow(
        h,
        out,
        "Wazuh-Manager",
        &url,
        Some("wazuh"),
        Some("pw"),
        None,
    )
    .await;
}

async fn cleanup(h: &Harness) {
    let s = &h.suffix;
    for sql in [
        format!("DELETE FROM agent_vulnerabilities WHERE agent_id LIKE '{s}%'"),
        format!("DELETE FROM vulnerability_reports WHERE customer_code LIKE '%{s}'"),
        format!("DELETE FROM sca_reports WHERE customer_code LIKE '%{s}'"),
        format!("DELETE FROM agent_datastore WHERE agent_id LIKE '{s}%'"),
        format!("DELETE FROM agents WHERE agent_id LIKE '{s}%'"),
        format!("DELETE FROM audit_log WHERE entity_type = 'agent' AND entity_id LIKE '%{s}'"),
    ] {
        h.exec(&sql).await;
    }
}

fn vuln(id: &str, agent_name: &str, cve: &str, severity: &str, package: &str) -> Value {
    json!({
        "_id": id,
        "_index": "wazuh-states-vulnerabilities-e2e",
        "_source": {
            "agent": {"name": agent_name, "id": "001"},
            "package": {"name": package, "version": "1.0", "architecture": "amd64"},
            "vulnerability": {
                "id": cve, "severity": severity, "description": format!("{cve} in {package}"),
                "detected_at": "2026-10-01T10:00:00Z", "published_at": "2026-09-01T00:00:00Z",
                "reference": "https://a.example, https://b.example",
                "score": {"base": 7.5}
            }
        }
    })
}

/// A raw `GET` through the production router: status, headers, body.
async fn raw(h: &Harness, uri: &str, token: &str) -> (StatusCode, http::HeaderMap, Vec<u8>) {
    let req = Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = h.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), 16 << 20)
        .await
        .unwrap();
    (status, headers, bytes.to_vec())
}

// --- /api/vulnerabilities ---------------------------------------------------------------

#[tokio::test]
async fn vulnerability_sync_stats_and_deletes_follow_the_hosts_tenant() {
    let h = harness_or_skip!(None, &env());
    h.seed().await;
    cleanup(&h).await;
    let s = h.suffix.clone();
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let web = format!("web-{s}");
    let db = format!("db-{s}");
    let a1 = agent(&h, "a1", &web, "Ubuntu", &acme, None).await;
    let b1 = agent(&h, "b1", &db, "Ubuntu", &beta, None).await;
    let (_server, up) = upstream().await;
    up.data.lock().unwrap().vulns = vec![
        vuln("v1", &web, "CVE-2026-0001", "High", "openssl"),
        vuln("v2", &web, "CVE-2026-0002", "Critical", "bash"),
        vuln("v3", &db, "CVE-2026-0003", "Low", "zlib"),
    ];
    let mut borrowed = Borrowed::new();
    wazuh(&h, &mut borrowed).await;
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");

    let path = format!("/api/vulnerabilities/sync/agent/{web}");
    let (status, body) = h.call("POST", &path, Some(&analyst), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": format!("Successfully synced 2 vulnerabilities for agent {web} (0"),
               "synced_count": 2, "errors": []})
    );
    let seen = up.take();
    let search = seen
        .iter()
        .find(|r| r.path == "/wazuh-states-vulnerabilities-e2e/_search")
        .expect("the agent's scroll");
    assert_eq!(search.method, "POST");
    assert_eq!(search.query, "scroll=2m&size=1000");
    assert_eq!(
        search.body,
        json!({"query": {"bool": {"must": [{"match": {"agent.name": web}}]}}})
    );
    let rows = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM agent_vulnerabilities WHERE agent_id = '{a1}' AND customer_code = '{acme}'"
        ))
        .await;
    assert_eq!(rows, 2);
    // Once more: the rows are updated, not duplicated.
    let (status, body) = h.call("POST", &path, Some(&analyst), None).await;
    assert_eq!(
        (status.as_u16(), body["synced_count"].clone()),
        (200, json!(2))
    );
    let rows = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM agent_vulnerabilities WHERE agent_id = '{a1}'"
        ))
        .await;
    assert_eq!(rows, 2);

    // §4: another tenant's host is refused before the indexer is asked.
    up.take();
    let (status, body) = h
        .call(
            "POST",
            &format!("/api/vulnerabilities/sync/agent/{db}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (403, json!(format!("Access denied to host {db}")))
    );
    assert!(up.take().is_empty());
    let (status, body) = h
        .call(
            "POST",
            &format!("/api/vulnerabilities/sync/customer/{beta}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 403, "{body}");
    let (status, body) = h
        .call(
            "POST",
            &format!("/api/vulnerabilities/sync/customer/{beta}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["message"],
        json!(format!(
            "Completed vulnerability sync for 1 agents using batch mode (size: 100) (customer: {beta})"
        ))
    );

    // §4: one agent's rows are read through the caller's customers.
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/vulnerabilities/agent/{b1}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["vulnerabilities"], json!([]));
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/vulnerabilities/agent/{a1}?severity=Critical"),
            Some(&analyst),
            None,
        )
        .await;
    let listed = body["vulnerabilities"].as_array().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["cve_id"], "CVE-2026-0002");
    assert_eq!(listed[0]["customer_code"], json!(acme));

    let (status, body) = h
        .call(
            "GET",
            &format!("/api/vulnerabilities/stats?customer_code={beta}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (403, json!(format!("Access denied to customer {beta}")))
    );
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/vulnerabilities/stats?customer_code={acme}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total_vulnerabilities"], 2);
    assert_eq!(body["critical_count"], 1);
    assert_eq!(body["high_count"], 1);

    let (status, _) = h
        .call(
            "DELETE",
            &format!("/api/vulnerabilities/delete?agent_name={web}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 403, "deleting is admin's");
    let (status, body) = h
        .call("DELETE", "/api/vulnerabilities/delete", Some(&admin), None)
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (
            400,
            json!("To delete ALL vulnerabilities, you must set confirm_delete_all=true")
        )
    );
    let (status, body) = h
        .call(
            "DELETE",
            &format!("/api/vulnerabilities/delete?agent_name={web}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["deleted_count"], 2);

    let (status, body) = h
        .call(
            "POST",
            "/api/vulnerabilities/sync?batch_size=0",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 422, "{body}");

    give_back(&h, borrowed).await;
    cleanup(&h).await;
}

#[tokio::test]
async fn vulnerability_search_and_reports_stay_in_the_callers_customers() {
    let h = harness_or_skip!(None, &env());
    h.seed().await;
    cleanup(&h).await;
    let s = h.suffix.clone();
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let web = format!("web-{s}");
    let db = format!("db-{s}");
    agent(&h, "a1", &web, "Ubuntu", &acme, None).await;
    agent(&h, "b1", &db, "Ubuntu", &beta, None).await;
    let (_server, up) = upstream().await;
    up.data.lock().unwrap().vulns = vec![
        vuln("v1", &web, "CVE-2026-0001", "High", "openssl"),
        vuln("v3", &db, "CVE-2026-0003", "Low", "zlib"),
    ];
    let mut borrowed = Borrowed::new();
    wazuh(&h, &mut borrowed).await;
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let admin = h.token(&format!("admin{s}"), "admin");

    let (status, body) = h
        .call(
            "GET",
            "/api/vulnerabilities/search?include_epss=false&page_size=10",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total_count"], 1);
    assert_eq!(body["vulnerabilities"][0]["agent_name"], json!(web));
    assert_eq!(body["vulnerabilities"][0]["customer_code"], json!(acme));
    assert_eq!(body["critical_count"], 0);
    assert_eq!(body["high_count"], 1);
    let seen = up.take();
    let count = seen.iter().find(|r| r.path.ends_with("/_count")).unwrap();
    assert_eq!(
        count.body,
        json!({"query": {"bool": {"must": [{"terms": {"agent.name": [web]}}]}}}),
        "the analyst's hosts only"
    );
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/vulnerabilities/search?include_epss=false&customer_codes={beta}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total_count"], 0);
    assert_eq!(
        body["message"],
        json!(format!("Access denied to customer {beta}"))
    );

    // A report: the CSV in MinIO, the row, the download, the delete.
    let (status, body) = h
        .call(
            "POST",
            "/api/vulnerabilities/reports/generate",
            Some(&analyst),
            Some(json!({"customer_code": beta, "report_name": "nope"})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        (body["success"].clone(), body["message"].clone()),
        (
            json!(false),
            json!(format!("Access denied to customer {beta}"))
        )
    );
    let name = format!("vulns-{s}");
    let (status, body) = h
        .call(
            "POST",
            "/api/vulnerabilities/reports/generate",
            Some(&analyst),
            Some(json!({"customer_code": acme, "report_name": name})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["success"], true, "{body}");
    let report = &body["report"];
    assert_eq!(report["total_vulnerabilities"], 1);
    assert_eq!(report["high_count"], 1);
    assert_eq!(report["filters_applied"], json!({"include_epss": false}));
    let id = report["id"].as_i64().unwrap();
    assert_eq!(
        report["download_url"],
        json!(format!("/api/v1/vulnerabilities/reports/{id}/download"))
    );
    let key = format!("{acme}/{name}.csv");
    let (csv, ct) = s3::get()
        .object("vulnerability-reports", &key)
        .expect("stored");
    assert_eq!(ct, "text/csv");
    let csv = String::from_utf8(csv).unwrap();
    assert!(
        csv.starts_with(
            "CVE ID,Severity,Title,Agent Name,Customer Code,Package Name,Package Version,\
             Package Architecture,Detected At,Published At,Base Score,References\r\n"
        ),
        "{csv}"
    );
    assert!(csv.contains("CVE-2026-0001,High,"), "{csv}");

    let (status, body) = h
        .call(
            "GET",
            &format!("/api/vulnerabilities/reports?customer_codes={beta}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["message"],
        json!(format!("Access denied to customer {beta}"))
    );
    let (_, body) = h
        .call("GET", "/api/vulnerabilities/reports", Some(&analyst), None)
        .await;
    assert!(
        body["reports"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == id)
    );
    let (status, headers, bytes) = raw(
        &h,
        &format!("/api/vulnerabilities/reports/{id}/download"),
        &analyst,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(headers["content-type"], "text/csv; charset=utf-8");
    assert_eq!(
        headers["content-disposition"],
        format!("attachment; filename=\"{name}.csv\"").as_str()
    );
    assert_eq!(String::from_utf8(bytes).unwrap(), csv);
    let portal = h.token(&format!("portal{s}"), "customer_user");
    let (status, _, _) = raw(
        &h,
        &format!("/api/vulnerabilities/reports/{id}/download"),
        &portal,
    )
    .await;
    assert_eq!(status, 403, "the reports are the SOC's");

    // The background report: queued, then completed by the task.
    let (status, body) = h
        .call(
            "POST",
            "/api/vulnerabilities/reports/generate/background",
            Some(&admin),
            Some(json!({"customer_code": acme, "report_name": format!("bg-{s}")})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "processing");
    let queued = body["report_id"].as_i64().unwrap();
    let mut done = String::new();
    for _ in 0..50 {
        let st: String = sqlx::query_scalar(&format!(
            "SELECT status FROM vulnerability_reports WHERE id = {queued}"
        ))
        .fetch_one(h.db.pool())
        .await
        .unwrap();
        if st != "processing" {
            done = st;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(done, "completed");

    let (status, body) = h
        .call(
            "DELETE",
            &format!("/api/vulnerabilities/reports/{id}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        s3::get().object("vulnerability-reports", &key).is_none(),
        "the file went with the row"
    );
    let (status, body) = h
        .call(
            "DELETE",
            &format!("/api/vulnerabilities/reports/{id}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (404, json!(format!("Report with ID {id} not found")))
    );
    assert_eq!(s3::get().bad_signatures(), 0);

    give_back(&h, borrowed).await;
    cleanup(&h).await;
}

// --- /api/sca -----------------------------------------------------------------------------

/// `GET` on any router (for the routers built around a stand-in).
async fn get_on(router: &axum::Router, uri: &str, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 16 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned())),
    )
}

fn sca_policy(id: &str, name: &str, score: i64) -> Value {
    json!({
        "policy_id": id, "name": name, "description": format!("{name} benchmark"),
        "total_checks": 10, "pass": score / 10, "fail": 10 - score / 10, "invalid": 0,
        "score": score, "start_scan": "2026-10-01T00:00:00Z", "end_scan": "2026-10-01T00:05:00Z",
        "references": null, "hash_file": "abc"
    })
}

#[tokio::test]
async fn sca_overview_stats_stream_and_reports() {
    let h = harness_or_skip!(None, &env());
    h.seed().await;
    cleanup(&h).await;
    let s = h.suffix.clone();
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let a1 = agent(&h, "a1", &format!("web-{s}"), "Ubuntu", &acme, None).await;
    let a2 = agent(&h, "a2", &format!("app-{s}"), "Ubuntu", &acme, None).await;
    let a3 = agent(&h, "a3", &format!("new-{s}"), "Ubuntu", &acme, None).await;
    agent(&h, "b1", &format!("db-{s}"), "Ubuntu", &beta, None).await;
    let (_server, up) = upstream().await;
    up.data.lock().unwrap().sca = vec![
        (
            a1.clone(),
            json!([
                sca_policy("cis_ubuntu", "CIS Ubuntu", 80),
                sca_policy("cis_ssh", "CIS SSH", 60)
            ]),
        ),
        (
            a2.clone(),
            json!([sca_policy("cis_ubuntu", "CIS Ubuntu", 40)]),
        ),
    ];
    let mut borrowed = Borrowed::new();
    wazuh(&h, &mut borrowed).await;
    let analyst = h.token(&format!("analyst{s}"), "analyst");

    let (status, body) = h
        .call("GET", "/api/sca/overview?page_size=2", Some(&analyst), None)
        .await;
    assert_eq!(status, 200, "{body}");
    let ids: Vec<(String, i64)> = body["sca_results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["agent_id"].as_str().unwrap().to_string(),
                r["score"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        ids,
        [(a2.clone(), 40), (a1.clone(), 60)],
        "lowest agent first"
    );
    let first = body["sca_results"][0].as_object().unwrap();
    assert_eq!(
        first.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "agent_id",
            "agent_name",
            "customer_code",
            "policy_id",
            "policy_name",
            "description",
            "total_checks",
            "pass",
            "fail",
            "invalid",
            "score",
            "start_scan",
            "end_scan",
            "references",
            "hash_file"
        ]
    );
    assert_eq!(body["total_count"], 3);
    assert_eq!(body["total_pages"], 2);
    assert_eq!(body["has_next"], true);
    assert_eq!(body["average_score"], 60.0);
    assert_eq!(body["filters_applied"], json!({"customer_codes": [acme]}));
    let asked: Vec<String> = up
        .take()
        .into_iter()
        .filter(|r| r.path.starts_with("/sca/"))
        .map(|r| r.path)
        .collect();
    assert_eq!(asked.len(), 3, "acme's three agents only: {asked:?}");
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/sca/overview?customer_codes={beta}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["message"], "No accessible customers");
    let (status, body) = h
        .call(
            "GET",
            "/api/sca/overview?min_score=101",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 422, "{body}");

    let (status, body) = h.call("GET", "/api/sca/stats", Some(&analyst), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total_agents_with_sca"], 2);
    assert_eq!(body["total_policies"], 2);
    assert_eq!(body["by_customer"], json!({}), "one customer in scope");

    // The event stream.
    let (status, headers, bytes) = raw(&h, "/api/sca/overview/stream", &analyst).await;
    assert_eq!(status, 200);
    assert_eq!(headers["content-type"], "text/event-stream; charset=utf-8");
    assert_eq!(headers["cache-control"], "no-cache");
    assert_eq!(headers["x-accel-buffering"], "no");
    assert!(headers.get("content-encoding").is_none());
    let text = String::from_utf8(bytes).unwrap();
    let frames: Vec<(String, Value)> = text
        .split("\n\n")
        .filter(|f| !f.is_empty())
        .map(|f| {
            let (event, data) = f.split_once('\n').unwrap();
            (
                event.trim_start_matches("event: ").to_string(),
                serde_json::from_str(data.trim_start_matches("data: ")).unwrap(),
            )
        })
        .collect();
    let events: Vec<&str> = frames.iter().map(|(e, _)| e.as_str()).collect();
    assert_eq!(events[0], "start");
    assert_eq!(frames[0].1["total_agents"], 3);
    assert_eq!(events.iter().filter(|e| **e == "agent_result").count(), 2);
    assert_eq!(events.iter().filter(|e| **e == "agent_empty").count(), 1);
    assert_eq!(events[events.len() - 2], "progress");
    assert_eq!(frames[frames.len() - 2].1["percent_complete"], 100.0);
    let done = &frames.last().unwrap().1;
    assert_eq!(frames.last().unwrap().0, "complete");
    assert_eq!(done["total_results"], 3);
    assert_eq!(done["agents_successful"], 2);
    assert_eq!(
        done["message"],
        "Completed SCA collection: 3 results from 2 agents"
    );
    let (_, _, bytes) = raw(
        &h,
        &format!("/api/sca/overview/stream?customer_codes={beta}"),
        &analyst,
    )
    .await;
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        "event: complete\ndata: {\"results\": [], \"message\": \"No accessible customers\"}\n\n"
    );
    let _ = a3;

    // A report.
    let name = format!("sca-{s}");
    let (status, body) = h
        .call(
            "POST",
            "/api/sca/reports/generate",
            Some(&analyst),
            Some(json!({"customer_code": acme, "report_name": name, "min_score": 50})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["success"], true, "{body}");
    let report = &body["report"];
    assert_eq!(report["total_policies"], 2);
    assert_eq!(report["filters_applied"], json!({"min_score": 50}));
    assert_eq!(report["error_message"], Value::Null);
    let id = report["id"].as_i64().unwrap();
    let (csv, _) = s3::get()
        .object("sca-reports", &format!("{acme}/{name}.csv"))
        .expect("stored");
    let csv = String::from_utf8(csv).unwrap();
    assert!(
        csv.starts_with("Agent ID,Agent Name,Customer Code,Policy ID,"),
        "{csv}"
    );
    assert_eq!(csv.lines().count(), 3);
    let (status, headers, bytes) =
        raw(&h, &format!("/api/sca/reports/{id}/download"), &analyst).await;
    assert_eq!(status, 200);
    assert_eq!(headers["content-type"], "text/csv; charset=utf-8");
    assert_eq!(
        headers["content-disposition"],
        format!("attachment; filename={name}.csv").as_str()
    );
    assert_eq!(String::from_utf8(bytes).unwrap(), csv);
    let (status, body) = h
        .call(
            "POST",
            "/api/sca/reports/generate",
            Some(&analyst),
            Some(json!({"customer_code": beta})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["error"], "Insufficient permissions");
    let (status, body) = h
        .call(
            "POST",
            "/api/sca/reports/generate",
            Some(&analyst),
            Some(json!({"customer_code": acme, "max_score": 200})),
        )
        .await;
    assert_eq!(status, 422, "{body}");
    let (status, body) = h
        .call(
            "DELETE",
            &format!("/api/sca/reports/{id}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body),
        (
            200,
            json!({"success": true, "message": format!("Successfully deleted report '{name}'")})
        )
    );
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/sca/reports/{id}/download"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (404, json!("Report not found"))
    );
    assert_eq!(s3::get().bad_signatures(), 0);

    give_back(&h, borrowed).await;
    cleanup(&h).await;
}

#[tokio::test]
async fn sca_policies_and_the_package_registry() {
    let h = harness_or_skip!(None, &env());
    h.seed().await;
    cleanup(&h).await;
    let s = h.suffix.clone();
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let a1 = agent(&h, "a1", &format!("web-{s}"), "Ubuntu", &acme, None).await;
    let b1 = agent(&h, "b1", &format!("db-{s}"), "Ubuntu", &beta, None).await;
    let (_server, up) = upstream().await;
    let index = json!({
        "version": "1.2", "last_updated": "2026-10-01",
        "policies": [
            {"id": "cis_apache_24", "name": "CIS Apache 2.4", "description": "d", "file": "apache/cis_apache_24.yml",
             "application": "apache", "app_version": "2.4", "platform": "linux", "cis_version": "2.0.0"},
            {"id": "cis_nginx", "name": "CIS NGINX", "description": "d", "file": "nginx/cis_nginx.yml",
             "application": "nginx", "app_version": "1", "platform": "linux", "cis_version": "1.0.0"}
        ]
    });
    {
        let mut d = up.data.lock().unwrap();
        d.github = vec![
            ("/index.json".into(), 200, index.to_string()),
            (
                "/apache/cis_apache_24.yml".into(),
                200,
                "policy:\n  id: cis_apache_24\n".into(),
            ),
            ("/nginx/cis_nginx.yml".into(), 404, "404: Not Found".into()),
        ];
        d.packages = vec![
            json!({"_index": "wazuh-states-inventory-packages-e2e", "_id": "p1",
                   "_source": {"agent": {"id": a1, "name": "web"}, "package": {"name": "apache2", "version": "2.4.58", "architecture": "amd64"}}}),
            json!({"_index": "wazuh-states-inventory-packages-e2e", "_id": "p2",
                   "_source": {"agent": {"id": b1, "name": "db"}, "package": {"name": "apache2-bin", "version": "2.4.58", "architecture": "amd64"}}}),
        ];
    }
    let mut borrowed = Borrowed::new();
    wazuh(&h, &mut borrowed).await;
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let admin = h.token(&format!("admin{s}"), "admin");
    let state = copilot_agent_reports::AgentReportsState {
        sca_repo: copilot_agent_reports::sca::policies::ScaRepo::new(format!(
            "http://127.0.0.1:{}",
            upstream_port()
        ))
        .unwrap(),
        ..h.app.agent_reports.clone()
    };
    let sca = copilot_agent_reports::sca::router(state);

    let (status, body) = get_on(&sca, "/policies", &analyst).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["version"], "1.2");
    assert_eq!(
        body["message"],
        "Successfully fetched 2 available SCA policies"
    );
    let (status, body) = get_on(&sca, "/policies/cis_nginx/metadata", &analyst).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["policy"]["file"], "nginx/cis_nginx.yml");
    let (status, body) = get_on(&sca, "/policies/cis_apache_24", &analyst).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["content"], "policy:\n  id: cis_apache_24\n");
    assert_eq!(
        body["message"],
        "Successfully fetched policy 'CIS Apache 2.4'"
    );
    let (status, body) = get_on(&sca, "/policies/cis_nginx", &analyst).await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(
        body["message"],
        format!(
            "Failed to fetch SCA policy file from GitHub: Client error '404 Not Found' for url \
             'http://127.0.0.1:{}/nginx/cis_nginx.yml'\nFor more information check: \
             https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/404",
            upstream_port()
        )
    );
    let (status, body) = get_on(&sca, "/policies/missing", &analyst).await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (
            404,
            json!("SCA policy 'missing' not found in the CoPilot-SCA repository index")
        )
    );
    let seen = up.take();
    let github = seen.iter().find(|r| r.path == "/index.json").unwrap();
    assert_eq!(github.method, "GET");

    let (status, body) = get_on(&sca, "/packages/registry", &analyst).await;
    assert_eq!(status, 200);
    assert_eq!(body["total"], 6);
    assert_eq!(body["entries"][0]["key"], "apache");
    let (status, body) = get_on(&sca, "/packages/registry/nope/agents", &analyst).await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (
            404,
            json!(
                "Registry key 'nope' not found. Valid keys: apache, nginx, iis, mysql, postgresql, sqlserver"
            )
        )
    );
    let (status, body) = get_on(&sca, "/packages/registry/apache/agents", &analyst).await;
    assert_eq!(status, 200, "{body}");
    let matched: Vec<&str> = body["matched_agents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["agent_id"].as_str().unwrap())
        .collect();
    assert_eq!(matched, [a1.as_str()], "another tenant's agent is dropped");
    assert_eq!(body["total"], 1);
    assert_eq!(
        body["message"], "Found 1 agent-package combinations for 'Apache HTTP Server'",
        "§4: the message counts the caller's matches"
    );
    assert_eq!(body["applicable_policies"][0]["id"], "cis_apache_24");
    let search = up
        .take()
        .into_iter()
        .find(|r| r.path == "/wazuh-states-inventory-packages-*/_search")
        .unwrap();
    assert_eq!(search.query, "size=10000");
    let (_, body) = get_on(&sca, "/packages/registry/apache/agents", &admin).await;
    assert_eq!(body["total"], 2);

    // The repository unreachable: the 502 with httpx's text.
    let state = copilot_agent_reports::AgentReportsState {
        sca_repo: copilot_agent_reports::sca::policies::ScaRepo::new("http://127.0.0.1:1").unwrap(),
        ..h.app.agent_reports.clone()
    };
    let (status, body) = get_on(
        &copilot_agent_reports::sca::router(state),
        "/policies",
        &analyst,
    )
    .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (
            502,
            json!("Failed to fetch SCA policies index: All connection attempts failed")
        )
    );

    give_back(&h, borrowed).await;
    cleanup(&h).await;
}

// --- /api/syscollector ---------------------------------------------------------------------

#[tokio::test]
async fn syscollector_packages_are_read_on_the_callers_agents() {
    let h = harness_or_skip!(None, &env());
    h.seed().await;
    cleanup(&h).await;
    let s = h.suffix.clone();
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let a1 = agent(&h, "a1", &format!("web-{s}"), "Ubuntu", &acme, None).await;
    let b1 = agent(&h, "b1", &format!("db-{s}"), "Ubuntu", &beta, None).await;
    let (_server, up) = upstream().await;
    {
        let mut d = up.data.lock().unwrap();
        d.syscollector = vec![(
            a1.clone(),
            json!([{"name": "openssl", "version": "3.0", "format": "deb", "size": 1024,
                    "agent_id": a1, "install_time": "2026-01-01"}]),
        )];
        d.packages = vec![
            json!({"_index": "wazuh-states-inventory-packages-e2e", "_id": "p1",
                   "_source": {"agent": {"id": a1, "name": "web", "groups": ["x"]}, "package": {"name": "openssl", "type": "deb"}}}),
            json!({"_index": "wazuh-states-inventory-packages-e2e", "_id": "p2",
                   "_source": {"agent": {"id": b1, "name": "db"}, "package": {"name": "openssl"}}}),
        ];
    }
    let mut borrowed = Borrowed::new();
    wazuh(&h, &mut borrowed).await;
    let portal = h.token(&format!("portal{s}"), "customer_user");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let admin = h.token(&format!("admin{s}"), "admin");

    let (status, body) = h
        .call(
            "GET",
            &format!("/api/syscollector/{a1}/packages?select=name&select=version&q=name%3Dopenssl"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"packages": [{"architecture": null, "description": null, "format": "deb", "name": "openssl",
               "priority": null, "scan": null, "section": null, "size": 1024, "vendor": null, "version": "3.0",
               "agent_id": a1, "install_time": "2026-01-01"}],
               "total_affected_items": 1, "success": true,
               "message": format!("Successfully fetched 1 packages for agent {a1}")})
    );
    let asked = up
        .take()
        .into_iter()
        .find(|r| r.path.starts_with("/syscollector/"))
        .unwrap();
    assert_eq!(
        asked.query,
        "limit=500&offset=0&wait_for_complete=True&select=name%2Cversion&q=name%3Dopenssl"
    );
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/syscollector/{b1}/packages"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (
            404,
            json!(format!(
                "Agent with agent_id {b1} not found or access denied"
            ))
        )
    );
    let (status, _) = h
        .call(
            "GET",
            &format!("/api/syscollector/{a1}/packages?limit=0"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(status, 422);

    // §4: the indexer search covers the caller's agents only.
    let (status, body) = h
        .call(
            "GET",
            "/api/syscollector/search/packages?package_name=ssl",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total"], 1);
    assert_eq!(body["packages"][0]["_id"], "p1");
    assert_eq!(
        body["packages"][0]["agent"],
        json!({"id": a1, "name": "web", "version": null})
    );
    let search = up.take().pop().unwrap();
    assert_eq!(search.query, "size=500");
    let must = search.body["query"]["bool"]["must"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(
        must[0],
        json!({"wildcard": {"package.name": {"value": "*ssl*", "case_insensitive": true}}})
    );
    let mut owned: Vec<String> = must[1]["terms"]["agent.id"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    owned.sort();
    assert!(owned.contains(&a1) && !owned.contains(&b1), "{owned:?}");
    let (status, body) = h
        .call(
            "GET",
            "/api/syscollector/search/packages",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        up.take().pop().unwrap().body,
        json!({"query": {"match_all": {}}})
    );
    let (status, _) = h
        .call(
            "GET",
            "/api/syscollector/search/packages",
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(status, 403, "the search is the SOC's");

    give_back(&h, borrowed).await;
    cleanup(&h).await;
}

// --- Velociraptor collections ---------------------------------------------------------------

/// Standard base64.
fn b64(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[tokio::test]
async fn velociraptor_collections_store_their_pack_in_minio() {
    let h = harness_or_skip!(None, &env());
    h.seed().await;
    cleanup(&h).await;
    let s = h.suffix.clone();
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let client_id = format!("C.{s}");
    let host = format!("win-{s}");
    let a1 = agent(
        &h,
        "a1",
        &host,
        "Microsoft Windows 11",
        &acme,
        Some(&client_id),
    )
    .await;
    let b1 = agent(
        &h,
        "b1",
        &format!("other-{s}"),
        "Ubuntu",
        &beta,
        Some(&format!("C.{s}b")),
    )
    .await;
    let pack: Vec<u8> = (0..200u8).collect();
    let encoded = b64(&pack);
    let definitions = r#"[{"name": "Windows.System.Pslist", "description": "ps",
        "parameters": [{"name": "ProcessRegex"}, {"name": "Fast"}]},
        {"name": "Windows.Forensics.Usn", "description": "usn"}]"#
        .to_string();
    let velo = StandIn::start_at(velo_port(), move |args| {
        let vql = args.query[0].vql.clone();
        if vql.starts_with("SELECT name,description,parameters FROM artifact_definitions()") {
            let all: Vec<Value> = serde_json::from_str(&definitions).unwrap();
            let picked: Vec<Value> = match vql.split_once("WHERE name = '") {
                Some((_, rest)) => {
                    let name = rest.trim_end_matches('\'');
                    all.into_iter().filter(|d| d["name"] == name).collect()
                }
                None => all,
            };
            Answer::rows(&[&Value::Array(picked).to_string()])
        } else if vql.starts_with("SELECT collect_client(") {
            let call = vql
                .strip_prefix("SELECT ")
                .and_then(|v| v.strip_suffix(" FROM scope()"))
                .unwrap()
                .to_string();
            Answer::rows(&[&json!([{ call: {"flow_id": "F.ABC", "request": {}} }]).to_string()])
        } else if vql.starts_with("SELECT * FROM watch_monitoring") {
            Answer::rows(&[r#"[{"FlowId": "F.ABC"}]"#])
        } else if vql.starts_with("SELECT * FROM source(") {
            Answer::rows(&[r#"[{"Pid": 4, "Name": "System"}]"#])
        } else if vql.starts_with("SELECT os_info.hostname") {
            Answer::rows(&[r#"[{"Hostname": "WIN-E2E"}]"#])
        } else if vql.starts_with("SELECT create_flow_download(") {
            Answer::rows(&[r#"[{"create_flow_download": "downloads/x"}]"#])
        } else if vql.contains("offset=0,") {
            Answer::rows(&[&json!([{ "Data": encoded }]).to_string()])
        } else {
            Answer::rows(&["[]"])
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let config = velo.write_api_config(dir.path());
    let mut borrowed = Borrowed::new();
    borrow(
        &h,
        &mut borrowed,
        "Velociraptor",
        "https://velo",
        None,
        None,
        Some(&config),
    )
    .await;
    let analyst = h.token(&format!("analyst{s}"), "analyst");

    let body = json!({"hostname": host, "artifact_name": "Windows.System.Pslist",
                      "parameters": {"env": [{"key": "ProcessRegex", "value": "it's"}]}});
    let (status, resp) = h
        .call("POST", "/api/artifacts/collect", Some(&analyst), Some(body))
        .await;
    assert_eq!(status, 200, "{resp}");
    let zip = format!("WIN-E2E-{client_id}-F.ABC.zip");
    let key = format!("{a1}/F.ABC/{zip}");
    assert_eq!(
        resp,
        json!({"message": "Successfully executed query", "success": true,
               "results": [{"Pid": 4, "Name": "System"}],
               "file_info": {"success": true,
                             "message": "Successfully fetched file from Velociraptor and uploaded to MinIO",
                             "bucket_name": "velociraptor-artifacts", "object_key": key, "file_name": zip,
                             "file_size": 200,
                             "file_hash": copilot_objectstore::sigv4::sha256_hex(&pack)}})
    );
    let vql = velo.vql();
    assert!(
        vql.contains(&format!(
            "SELECT collect_client(org_id='root', client_id='{client_id}', \
         artifacts=['Windows.System.Pslist'], env=dict(`ProcessRegex`='it\\'s')) FROM scope()"
        )),
        "{vql:#?}"
    );
    assert!(
        vql.contains(&format!(
            "SELECT create_flow_download(client_id='{client_id}', flow_id='F.ABC', wait=true, \
         format='json', expand_sparse=false, name='WIN-E2E-{client_id}-F.ABC') FROM scope()"
        )),
        "{vql:#?}"
    );
    assert!(
        vql.contains(&format!(
            "SELECT base64encode(string=read_file(accessor='fs', \
         filename='/downloads/{client_id}/F.ABC/{zip}', offset=0, length=1048576)) AS Data \
         FROM scope()"
        )),
        "{vql:#?}"
    );
    let (stored, ct) = s3::get()
        .object("velociraptor-artifacts", &key)
        .expect("uploaded");
    assert_eq!((stored, ct.as_str()), (pack.clone(), "application/zip"));
    let row: (String, String, String, i64, String) = sqlx::query_as(&format!(
        "SELECT velociraptor_id, artifact_name, flow_id, CAST(file_size AS SIGNED), status \
         FROM agent_datastore WHERE agent_id = '{a1}'"
    ))
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            client_id.clone(),
            "Windows.System.Pslist".to_string(),
            "F.ABC".to_string(),
            200,
            "completed".to_string()
        )
    );
    let mut audited = 0;
    for _ in 0..20 {
        audited = h
            .scalar_i64(&format!(
                "SELECT COUNT(*) FROM audit_log WHERE action = 'artifact.collect' AND entity_id = '{host}'"
            ))
            .await;
        if audited > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(audited, 1);

    // The checks before Velociraptor is asked to run anything.
    let (status, resp) = h
        .call(
            "POST",
            "/api/artifacts/collect",
            Some(&analyst),
            Some(
                json!({"hostname": host, "artifact_name": "Windows.System.Pslist",
                        "parameters": {"Nope": "1"}}),
            ),
        )
        .await;
    assert_eq!(
        (status.as_u16(), resp["message"].clone()),
        (
            400,
            json!(
                "Parameter 'Nope' is not valid for artifact Windows.System.Pslist. Valid parameters: Fast, ProcessRegex"
            )
        )
    );
    let (status, resp) = h
        .call(
            "POST",
            "/api/artifacts/collect",
            Some(&analyst),
            Some(
                json!({"hostname": host, "artifact_name": "Windows.Forensics.Usn",
                        "parameters": {"X": "1"}}),
            ),
        )
        .await;
    assert_eq!(
        (status.as_u16(), resp["message"].clone()),
        (
            400,
            json!("Artifact Windows.Forensics.Usn does not accept any parameters")
        )
    );
    let (status, resp) = h
        .call(
            "POST",
            "/api/artifacts/collect",
            Some(&analyst),
            Some(json!({"hostname": host, "artifact_name": "Linux.Sys.Users"})),
        )
        .await;
    assert_eq!(
        (status.as_u16(), resp["message"].clone()),
        (
            400,
            json!(format!(
                "Artifact name Linux.Sys.Users does not apply for hostname {host} or does not exist"
            ))
        )
    );
    let (status, resp) = h
        .call(
            "POST",
            "/api/artifacts/collect",
            Some(&analyst),
            Some(json!({"hostname": format!("other-{s}"), "artifact_name": "Linux.Sys.Users"})),
        )
        .await;
    assert_eq!(
        (status.as_u16(), resp["message"].clone()),
        (403, json!(format!("Access denied to host other-{s}")))
    );
    let (status, _) = h
        .call(
            "POST",
            "/api/artifacts/collect",
            Some(&analyst),
            Some(json!({"hostname": host, "parameters": {"x": 1}})),
        )
        .await;
    assert_eq!(status, 422);

    // Stored only: no rows read.
    velo.requests.lock().unwrap().clear();
    let (status, resp) = h
        .call(
            "POST",
            "/api/artifacts/collect",
            Some(&analyst),
            Some(
                json!({"hostname": host, "artifact_name": "Windows.Forensics.Usn",
                        "data_store_only": true}),
            ),
        )
        .await;
    assert_eq!(status, 200, "{resp}");
    assert_eq!(
        resp["message"],
        "Artifact collected and stored successfully. Results not retrieved."
    );
    assert_eq!(resp["results"], Value::Null);
    assert!(
        !velo
            .vql()
            .iter()
            .any(|q| q.starts_with("SELECT * FROM source(")),
        "{:?}",
        velo.vql()
    );

    // The file collection, by agent id.
    velo.requests.lock().unwrap().clear();
    let (status, resp) = h
        .call(
            "POST",
            &format!("/api/artifacts/collect/file/agent/{a1}"),
            Some(&analyst),
            Some(json!({"file": "Users\\Admin\\x.txt"})),
        )
        .await;
    assert_eq!(status, 200, "{resp}");
    assert_eq!(resp["file_info"]["object_key"], json!(key));
    let vql = velo.vql();
    assert!(
        vql.contains(&format!(
            "SELECT collect_client(org_id='root', client_id='{client_id}', \
         artifacts=['Generic.Collectors.File'], spec=dict(`Generic.Collectors.File`=dict(\
         `collectionSpec`='Glob\nUsers\\\\Admin\\\\x.txt\n', `Root`='C:'))) FROM scope()"
        )),
        "{vql:#?}"
    );
    let (status, resp) = h
        .call(
            "POST",
            &format!("/api/artifacts/collect/file/agent/{b1}"),
            Some(&analyst),
            Some(json!({"file": "/etc/passwd"})),
        )
        .await;
    assert_eq!(
        (status.as_u16(), resp["message"].clone()),
        (403, json!(format!("Access denied to agent {b1}")))
    );
    let (status, _) = h
        .call(
            "POST",
            &format!("/api/artifacts/collect/file/agent/{a1}"),
            Some(&analyst),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, 422);
    let (status, resp) = h
        .call(
            "POST",
            "/api/artifacts/collect/file/agent/nobody",
            Some(&h.token(&format!("admin{s}"), "admin")),
            Some(json!({"file": "/etc/passwd"})),
        )
        .await;
    assert_eq!(
        (status.as_u16(), resp["message"].clone()),
        (404, json!("Agent with ID nobody not found"))
    );
    // A GET of a POST route's path is Starlette's `GET /{os_prefix}`, not a 405.
    for segment in ["collect", "command", "quarantine"] {
        let (status, resp) = h
            .call(
                "GET",
                &format!("/api/artifacts/{segment}"),
                Some(&analyst),
                None,
            )
            .await;
        assert_eq!(
            (status.as_u16(), resp["message"].clone()),
            (400, json!(format!("OS prefix {segment} does not exist.")))
        );
    }
    assert_eq!(s3::get().bad_signatures(), 0);

    give_back(&h, borrowed).await;
    cleanup(&h).await;
}
