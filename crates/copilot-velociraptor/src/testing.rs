//! A Velociraptor API stand-in for tests (feature `testing`): `proto.API/Query`
//! over HTTP/2 with mutual TLS, the way a Velociraptor server serves it, with
//! a fixed CA, server and client certificate (valid until 2099). Every
//! request is recorded; the answer is a function of the request.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;

use crate::grpc::Code;
use crate::proto::{VqlCollectorArgs, VqlResponse};

/// The CA every stand-in certificate is signed by.
pub const CA_PEM: &str = include_str!("testing/ca.pem");
/// The server's certificate (`VelociraptorServer`).
pub const SERVER_PEM: &str = include_str!("testing/server.pem");
/// Its key.
pub const SERVER_KEY: &str = include_str!("testing/server.key");
/// The API client's certificate (`api`).
pub const CLIENT_PEM: &str = include_str!("testing/client.pem");
/// Its key.
pub const CLIENT_KEY: &str = include_str!("testing/client.key");

/// What the stand-in answers one request with.
#[derive(Debug, Clone)]
pub enum Answer {
    /// These `VQLResponse`s, then status OK.
    Responses(Vec<VqlResponse>),
    /// No message, this status.
    Status(Code, String),
    /// Never answer (deadline tests).
    Hang,
}

impl Answer {
    /// One `Response` chunk per JSON text.
    pub fn rows(chunks: &[&str]) -> Self {
        Answer::Responses(
            chunks
                .iter()
                .map(|c| VqlResponse {
                    response: (*c).to_string(),
                    ..Default::default()
                })
                .collect(),
        )
    }
}

type Handler = dyn Fn(&VqlCollectorArgs) -> Answer + Send + Sync;
/// The requests a stand-in received, each with its `grpc-timeout`.
pub type Recorded = Arc<Mutex<Vec<(VqlCollectorArgs, Option<String>)>>>;

/// A running stand-in.
#[derive(Clone)]
pub struct StandIn {
    /// Where it listens.
    pub addr: SocketAddr,
    /// Every request it received, in order (with its `grpc-timeout`).
    pub requests: Recorded,
}

impl StandIn {
    /// Start one answering with `answer`.
    pub async fn start(
        answer: impl Fn(&VqlCollectorArgs) -> Answer + Send + Sync + 'static,
    ) -> Self {
        Self::start_at(0, answer).await
    }

    /// Start one on `127.0.0.1:port` (a suite's assigned port; `0` picks a
    /// free one). A port the previous test's stand-in is still releasing is
    /// retried for up to five seconds.
    pub async fn start_at(
        port: u16,
        answer: impl Fn(&VqlCollectorArgs) -> Answer + Send + Sync + 'static,
    ) -> Self {
        let answer: Arc<Handler> = Arc::new(answer);
        let mut tries = 0;
        let listener = loop {
            match TcpListener::bind(("127.0.0.1", port)).await {
                Ok(l) => break l,
                Err(_) if tries < 50 => {
                    tries += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(e) => panic!("bind 127.0.0.1:{port}: {e}"),
            }
        };
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(CA_PEM.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .unwrap();
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(SERVER_PEM.as_bytes())
                .collect::<Result<_, _>>()
                .unwrap();
        let key = PrivateKeyDer::from_pem_slice(SERVER_KEY.as_bytes()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let recorded = Arc::clone(&requests);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let answer = Arc::clone(&answer);
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let service = service_fn(move |req: http::Request<hyper::body::Incoming>| {
                        let answer = Arc::clone(&answer);
                        let recorded = Arc::clone(&recorded);
                        async move { Ok::<_, Infallible>(serve(req, &*answer, &recorded).await) }
                    });
                    let _ = http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        Self { addr, requests }
    }

    /// The recorded requests' messages.
    pub fn messages(&self) -> Vec<VqlCollectorArgs> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|(m, _)| m.clone())
            .collect()
    }

    /// The recorded VQL texts.
    pub fn vql(&self) -> Vec<String> {
        self.messages()
            .iter()
            .flat_map(|m| m.query.iter().map(|q| q.vql.clone()))
            .collect()
    }

    /// Write an `api.config.yaml` pointing here into `dir`; returns its path.
    pub fn write_api_config(&self, dir: &std::path::Path) -> String {
        let indent = |pem: &str| pem.lines().map(|l| format!("  {l}\n")).collect::<String>();
        let body = format!(
            "ca_certificate: |\n{}client_cert: |\n{}client_private_key: |\n{}api_connection_string: {}\nname: api\npinned_server_name: VelociraptorServer\n",
            indent(CA_PEM),
            indent(CLIENT_PEM),
            indent(CLIENT_KEY),
            self.addr
        );
        let path = dir.join("api.config.yaml");
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }
}

type Body = StreamBody<futures::stream::Iter<std::vec::IntoIter<Result<Frame<Bytes>, Infallible>>>>;

fn frames(frames: Vec<Frame<Bytes>>) -> Body {
    StreamBody::new(futures::stream::iter(
        frames.into_iter().map(Ok).collect::<Vec<_>>(),
    ))
}

fn trailers(code: Code, message: &str) -> Frame<Bytes> {
    let mut t = http::HeaderMap::new();
    t.insert("grpc-status", code.value().to_string().parse().unwrap());
    if !message.is_empty() {
        let encoded: String = message
            .bytes()
            .map(|b| {
                if (0x20..0x7f).contains(&b) && b != b'%' {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        t.insert("grpc-message", encoded.parse().unwrap());
    }
    Frame::trailers(t)
}

async fn serve(
    req: http::Request<hyper::body::Incoming>,
    answer: &Handler,
    recorded: &Mutex<Vec<(VqlCollectorArgs, Option<String>)>>,
) -> http::Response<Body> {
    let timeout = req
        .headers()
        .get("grpc-timeout")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let path = req.uri().path().to_string();
    let mut body = req.into_body().collect().await.unwrap().to_bytes();
    let response = |frames_: Vec<Frame<Bytes>>| {
        http::Response::builder()
            .header("content-type", "application/grpc")
            .body(frames(frames_))
            .unwrap()
    };
    if path != "/proto.API/Query" || body.len() < 5 {
        return response(vec![trailers(Code::Unimplemented, "Method not found!")]);
    }
    body.advance(5);
    let args = VqlCollectorArgs::decode(&body).unwrap_or_default();
    recorded.lock().unwrap().push((args.clone(), timeout));
    match answer(&args) {
        Answer::Responses(rs) => {
            let mut out = Vec::new();
            for r in rs {
                let msg = r.encode();
                let mut f = Vec::with_capacity(msg.len() + 5);
                f.push(0);
                f.extend_from_slice(&(msg.len() as u32).to_be_bytes());
                f.extend_from_slice(&msg);
                out.push(Frame::data(Bytes::from(f)));
            }
            out.push(trailers(Code::Ok, ""));
            response(out)
        }
        Answer::Status(code, message) => response(vec![trailers(code, &message)]),
        Answer::Hang => {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            response(vec![trailers(Code::Ok, "")])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Service, Timeouts};
    use crate::config::ApiConfig;

    #[tokio::test]
    async fn queries_go_over_mutual_tls() {
        let stand_in = StandIn::start(|args| {
            if args.query[0].vql.contains("deny") {
                Answer::Status(
                    Code::PermissionDenied,
                    "Permission denied: user api requires permission ANY_QUERY".into(),
                )
            } else if args.query[0].vql.contains("hang") {
                Answer::Hang
            } else {
                Answer::rows(&[r#"[{"a": 1}]"#, r#"[{"a": 2, "é": "ü"}]"#])
            }
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let path = stand_in.write_api_config(dir.path());
        let cfg = ApiConfig::load(Some(&path)).unwrap();
        let svc = Service::from_config(cfg, Timeouts { query: 2, flow: 3 });
        let rows = svc
            .execute_query("SELECT 1", Some("O1"), None)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        let (msg, timeout) = stand_in.requests.lock().unwrap()[0].clone();
        assert_eq!(msg.org_id, "O1");
        assert_eq!(msg.max_wait, 1);
        assert_eq!(timeout.as_deref(), Some("2S"));
        let denied = svc
            .execute_query("deny", crate::client::ROOT, None)
            .await
            .unwrap_err();
        assert_eq!(
            denied.text(),
            "Velociraptor denied the query for org 'root': Permission denied: user api requires \
             permission ANY_QUERY. The Velociraptor API user CoPilot authenticates as needs a role \
             in each org, not just root. Grant it on the Velociraptor server with: SELECT \
             user_grant(user='<copilot api user>', roles='administrator', orgs=['root']) FROM scope()"
        );
        let slow = svc
            .execute_query("hang", crate::client::ROOT, None)
            .await
            .unwrap_err();
        assert!(
            slow.text()
                .starts_with("Velociraptor did not respond within 2s."),
            "{slow:?}"
        );
        assert!(slow.text().contains("Raise VELOCIRAPTOR_QUERY_TIMEOUT"));
    }

    #[tokio::test]
    async fn the_server_certificate_itself_may_be_the_root() {
        // BoringSSL's partial chain: grpc accepts a pinned server certificate.
        let stand_in = StandIn::start(|_| Answer::rows(&["[1]"])).await;
        let dir = tempfile::tempdir().unwrap();
        let path = stand_in.write_api_config(dir.path());
        let mut cfg = ApiConfig::load(Some(&path)).unwrap();
        cfg.ca_certificate = SERVER_PEM.to_string();
        let svc = Service::from_config(cfg, Timeouts { query: 2, flow: 3 });
        let rows = svc
            .execute_query("SELECT 1", crate::client::ROOT, None)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn a_server_of_another_ca_is_refused() {
        let stand_in = StandIn::start(|_| Answer::rows(&["[]"])).await;
        let dir = tempfile::tempdir().unwrap();
        let path = stand_in.write_api_config(dir.path());
        let mut cfg = ApiConfig::load(Some(&path)).unwrap();
        // The client's own certificate is not a CA: nothing chains to it.
        cfg.ca_certificate = CLIENT_PEM.to_string();
        let svc = Service::from_config(cfg, Timeouts { query: 2, flow: 3 });
        let err = svc
            .execute_query("SELECT 1", crate::client::ROOT, None)
            .await
            .unwrap_err();
        assert!(
            err.text().starts_with(&format!(
                "Failed to execute query: failed to connect to all addresses; last error: UNKNOWN: ipv4:{}: Tls handshake failed (TSI_PROTOCOL_FAILURE): SSL_ERROR_SSL: error:1000007d:SSL routines:OPENSSL_internal:CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate: OK",
                stand_in.addr
            )),
            "{err:?}"
        );
    }
}
