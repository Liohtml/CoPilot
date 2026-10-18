//! The wire side of the sync indexer client: what elasticsearch-py's
//! `Urllib3HttpConnection` sends through urllib3 2.x — the request line,
//! `Host` and `Accept-Encoding: identity` (http.client's `putrequest`), the
//! `Content-Length` (`0` on a body-less POST/PUT/PATCH, none on a body-less
//! GET/HEAD/DELETE: `body_to_chunks`), then the connection's own headers and
//! nothing else (reqwest would add `Accept: */*` to every request), over HTTP/1.1 with
//! ALPN `http/1.1` and, as `verify_certs=False`, no certificate check.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use reqwest::Method;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// An answer.
#[derive(Debug)]
pub(crate) struct Answer {
    /// Status code.
    pub status: u16,
    /// `Content-Type`.
    pub content_type: Option<String>,
    /// The body.
    pub body: Bytes,
}

/// Why no answer came.
#[derive(Debug)]
pub(crate) enum Failure {
    /// A socket error (refused, reset, unresolvable, the connect timeout).
    Io(std::io::Error),
    /// The read timeout.
    ReadTimeout,
    /// Anything else (TLS, HTTP framing), as its text.
    Other(String),
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// `verify_certs=False`: any certificate, the handshake's signatures still
/// checked.
#[derive(Debug)]
struct Unverified(Arc<CryptoProvider>);

impl ServerCertVerifier for Unverified {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(Unverified(provider)))
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Ok(Arc::new(config))
        })
        .clone()
}

/// The `Host` header http.client writes: the port only when it is not the
/// scheme's, an IPv6 address in brackets.
fn host_header(tls: bool, host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if (tls && port == 443) || (!tls && port == 80) {
        host
    } else {
        format!("{host}:{port}")
    }
}

/// One request on a new connection. `headers` are the connection's
/// (elasticsearch-py's), sent after `Host` and `Accept-Encoding`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send(
    method: &Method,
    tls: bool,
    host: &str,
    port: u16,
    path_and_query: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<Answer, Failure> {
    let tcp = match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(Failure::Io(e)),
        Err(_) => {
            return Err(Failure::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out",
            )));
        }
    };
    let stream: Box<dyn Stream> = if tls {
        let config = tls_config().map_err(Failure::Other)?;
        let name =
            ServerName::try_from(host.to_string()).map_err(|e| Failure::Other(e.to_string()))?;
        let connector = tokio_rustls::TlsConnector::from(config);
        match tokio::time::timeout(timeout, connector.connect(name, tcp)).await {
            Ok(Ok(s)) => Box::new(s),
            Ok(Err(e)) => return Err(Failure::Io(e)),
            Err(_) => return Err(Failure::ReadTimeout),
        }
    } else {
        Box::new(tcp)
    };
    let (mut sender, conn) = http1::handshake::<_, Full<Bytes>>(TokioIo::new(stream))
        .await
        .map_err(|e| Failure::Other(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut req = http::Request::builder()
        .method(method.clone())
        .uri(path_and_query)
        .header("host", host_header(tls, host, port))
        .header("accept-encoding", "identity");
    // urllib3 2.x writes `Content-Length` right after `putrequest`'s two,
    // before the connection's own headers.
    let payload = match body {
        Some(b) => {
            req = req.header("content-length", b.len().to_string());
            Bytes::copy_from_slice(b)
        }
        None => {
            if matches!(*method, Method::POST | Method::PUT | Method::PATCH) {
                req = req.header("content-length", "0");
            }
            Bytes::new()
        }
    };
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req
        .body(Full::new(payload))
        .map_err(|e| Failure::Other(e.to_string()))?;
    let exchange = async {
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| Failure::Other(e.to_string()))?;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| Failure::Other(e.to_string()))?
            .to_bytes();
        Ok(Answer {
            status,
            content_type,
            body,
        })
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| Failure::ReadTimeout)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// The request head one `send` writes, read off a plain TCP listener.
    fn head_of(method: Method, body: Option<&'static [u8]>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            )
            .unwrap();
            String::from_utf8(buf).unwrap()
        });
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let answer = rt
            .block_on(send(
                &method,
                false,
                "127.0.0.1",
                port,
                "/*/_alias?expand_wildcards=open",
                &[("connection", "keep-alive"), ("user-agent", "ua")],
                body,
                Duration::from_secs(5),
            ))
            .unwrap();
        assert_eq!((answer.status, &answer.body[..]), (200, &b"{}"[..]));
        server.join().unwrap().to_ascii_lowercase()
    }

    #[test]
    fn urllib3_sends_no_accept_and_its_own_lengths() {
        let get = head_of(Method::GET, None);
        assert!(
            get.starts_with("get /*/_alias?expand_wildcards=open http/1.1\r\n"),
            "{get}"
        );
        assert!(get.contains("host: 127.0.0.1:"), "{get}");
        assert!(get.contains("accept-encoding: identity\r\n"), "{get}");
        assert!(!get.contains("\r\naccept:"), "{get}");
        assert!(!get.contains("content-length"), "{get}");
        assert!(!head_of(Method::DELETE, None).contains("content-length"));
        assert!(head_of(Method::POST, None).contains("content-length: 0\r\n"));
        assert!(head_of(Method::POST, Some(b"{}")).contains("content-length: 2\r\n"));
        assert!(
            head_of(Method::POST, Some(b"{}"))
                .contains("accept-encoding: identity\r\ncontent-length: 2\r\n"),
            "urllib3 writes Content-Length before the connection's headers"
        );
    }

    #[test]
    fn hosts_name_their_port_unless_it_is_the_schemes() {
        assert_eq!(host_header(false, "es", 9200), "es:9200");
        assert_eq!(host_header(true, "es", 443), "es");
        assert_eq!(host_header(false, "::1", 80), "[::1]");
    }
}
