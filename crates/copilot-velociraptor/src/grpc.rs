//! The gRPC transport — what `grpc.secure_channel(api_connection_string,
//! ssl_channel_credentials(ca, key, cert), [("grpc.ssl_target_name_override",
//! "VelociraptorServer")])` does for one server-streaming call.
//!
//! - **TLS** is mutual and pinned to the config's CA: the server must present
//!   a certificate for `VelociraptorServer` (the name every Velociraptor server
//!   certificate carries, whatever address it listens on) signed by
//!   `ca_certificate` — or be one of its certificates, BoringSSL's partial
//!   chain (`pinned`) — and the client presents `client_cert` /
//!   `client_private_key`. `VelociraptorServer` is also the SNI, as with the
//!   target-name override. ALPN `h2`.
//! - **HTTP/2** framing as gRPC specifies it: `POST /proto.API/Query`,
//!   `content-type: application/grpc`, `te: trailers`, the deadline as
//!   `grpc-timeout`, each message length-prefixed; the status comes from the
//!   trailers (`grpc-status`, a percent-encoded `grpc-message`).
//! - **Failures** carry grpc's status codes and, where the client produces
//!   them, grpc-core's texts: a refused connection is `UNAVAILABLE: failed to
//!   connect to all addresses; last error: UNKNOWN: ipv4:127.0.0.1:8001:
//!   Failed to connect to remote host: Connection refused`, an expired
//!   deadline `DEADLINE_EXCEEDED: Deadline Exceeded`, an answer over 4 MiB
//!   `RESOURCE_EXHAUSTED` (grpc's default receive limit). A server's own
//!   status and message pass through unchanged.
//!
//! One connection per call: Python keeps a channel per service instance and
//! creates an instance per operation, which is the same on the wire.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::TcpStream;

use crate::config::ApiConfig;
use crate::pinned::PartialChainVerifier;

/// The name every Velociraptor server certificate is issued for.
pub const SERVER_NAME: &str = "VelociraptorServer";
/// grpc's default maximum receive message length.
pub const MAX_RECEIVE_MESSAGE_LENGTH: usize = 4 * 1024 * 1024;

/// gRPC status codes (`grpc.StatusCode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// 0.
    Ok,
    /// 1.
    Cancelled,
    /// 2.
    Unknown,
    /// 3.
    InvalidArgument,
    /// 4.
    DeadlineExceeded,
    /// 5.
    NotFound,
    /// 6.
    AlreadyExists,
    /// 7.
    PermissionDenied,
    /// 8.
    ResourceExhausted,
    /// 9.
    FailedPrecondition,
    /// 10.
    Aborted,
    /// 11.
    OutOfRange,
    /// 12.
    Unimplemented,
    /// 13.
    Internal,
    /// 14.
    Unavailable,
    /// 15.
    DataLoss,
    /// 16.
    Unauthenticated,
}

impl Code {
    /// From the numeric `grpc-status` (unknown values are `UNKNOWN`).
    pub fn from_i32(n: i32) -> Self {
        match n {
            0 => Self::Ok,
            1 => Self::Cancelled,
            3 => Self::InvalidArgument,
            4 => Self::DeadlineExceeded,
            5 => Self::NotFound,
            6 => Self::AlreadyExists,
            7 => Self::PermissionDenied,
            8 => Self::ResourceExhausted,
            9 => Self::FailedPrecondition,
            10 => Self::Aborted,
            11 => Self::OutOfRange,
            12 => Self::Unimplemented,
            13 => Self::Internal,
            14 => Self::Unavailable,
            15 => Self::DataLoss,
            16 => Self::Unauthenticated,
            _ => Self::Unknown,
        }
    }

    /// The number.
    pub fn value(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::Cancelled => 1,
            Self::Unknown => 2,
            Self::InvalidArgument => 3,
            Self::DeadlineExceeded => 4,
            Self::NotFound => 5,
            Self::AlreadyExists => 6,
            Self::PermissionDenied => 7,
            Self::ResourceExhausted => 8,
            Self::FailedPrecondition => 9,
            Self::Aborted => 10,
            Self::OutOfRange => 11,
            Self::Unimplemented => 12,
            Self::Internal => 13,
            Self::Unavailable => 14,
            Self::DataLoss => 15,
            Self::Unauthenticated => 16,
        }
    }

    /// `StatusCode.<NAME>`'s name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Cancelled => "CANCELLED",
            Self::Unknown => "UNKNOWN",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Aborted => "ABORTED",
            Self::OutOfRange => "OUT_OF_RANGE",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Internal => "INTERNAL",
            Self::Unavailable => "UNAVAILABLE",
            Self::DataLoss => "DATA_LOSS",
            Self::Unauthenticated => "UNAUTHENTICATED",
        }
    }
}

/// A failed call: `grpc.RpcError`'s `code()` and `details()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    /// `e.code()`.
    pub code: Code,
    /// `e.details()`.
    pub details: String,
    /// The peer of a status the server sent (`ipv4:127.0.0.1:8001`), empty
    /// for one the client produced.
    pub peer: String,
}

impl RpcError {
    /// A status the client produced.
    pub fn local(code: Code, details: impl Into<String>) -> Self {
        Self {
            code,
            details: details.into(),
            peer: String::new(),
        }
    }

    /// `str(e)`: grpc's `_MultiThreadedRendezvous` text, which pyvelociraptor
    /// callers that catch `Exception` (the connector check) put into their
    /// message. Its `debug_error_string` names the peer for a status the
    /// server sent after answering (none for a trailers-only answer or a
    /// failure of the client's own); grpc-core prints its two keys in hash
    /// order, which varies from one error to the next, so this text always
    /// puts `grpc_status` first.
    pub fn rendezvous_str(&self) -> String {
        format!(
            "<_MultiThreadedRendezvous of RPC that terminated with:\n\tstatus = StatusCode.{}\n\tdetails = \"{}\"\n\tdebug_error_string = \"UNKNOWN:Error received from peer {} {{grpc_status:{}, grpc_message:\"{}\"}}\"\n>",
            self.code.name(),
            self.details,
            self.peer,
            self.code.value(),
            self.details,
        )
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.name(), self.details)
    }
}

/// A call that ended early: the transport's failure, or the message
/// handler's.
#[derive(Debug, Clone, PartialEq)]
pub enum CallError<E> {
    /// The RPC failed.
    Rpc(RpcError),
    /// The handler refused a message.
    Handler(E),
}

/// `host` and `port` of a gRPC target (`dns:` scheme, default port 443).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Host name or address (IPv6 without brackets).
    pub host: String,
    /// Port.
    pub port: u16,
}

/// Parse `api_connection_string` the way grpc's `dns:` resolver splits it.
pub fn parse_target(target: &str) -> Result<Target, RpcError> {
    let raw = target.strip_prefix("dns:///").unwrap_or(target);
    let invalid = || {
        RpcError::local(
            Code::Unavailable,
            format!("DNS resolution failed for {target}: UNKNOWN: unparseable host:port"),
        )
    };
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or_else(invalid)?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| invalid())?,
            None if after.is_empty() => 443,
            None => return Err(invalid()),
        };
        return Ok(Target {
            host: host.to_string(),
            port,
        });
    }
    match raw.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Ok(Target {
            host: host.to_string(),
            port: port.parse().map_err(|_| invalid())?,
        }),
        Some(_) => Ok(Target {
            host: raw.to_string(),
            port: 443,
        }),
        None if raw.is_empty() => Err(invalid()),
        None => Ok(Target {
            host: raw.to_string(),
            port: 443,
        }),
    }
}

/// grpc's name for an address (`ipv4:1.2.3.4:5`, `ipv6:[::1]:5`).
pub fn address_name(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(a) => format!("ipv4:{}:{}", a.ip(), a.port()),
        SocketAddr::V6(a) => format!("ipv6:[{}]:{}", a.ip(), a.port()),
    }
}

/// grpc-core's text for a TLS handshake the client gave up on (BoringSSL's
/// verification errors), or for a connection the server closed during it.
fn handshake_failure(addr: &SocketAddr, e: &std::io::Error) -> RpcError {
    use rustls::{CertificateError, Error};
    let rustls_error = e.get_ref().and_then(|inner| inner.downcast_ref::<Error>());
    let reason = match rustls_error {
        Some(Error::InvalidCertificate(CertificateError::UnknownIssuer)) => {
            "unable to get local issuer certificate"
        }
        Some(Error::InvalidCertificate(CertificateError::Expired)) => "certificate has expired",
        Some(Error::InvalidCertificate(CertificateError::NotValidYet)) => {
            "certificate is not yet valid"
        }
        Some(Error::InvalidCertificate(_)) => "certificate verify failed",
        Some(Error::AlertReceived(_)) | None => {
            return RpcError::local(
                Code::Unavailable,
                format!(
                    "failed to connect to all addresses; last error: UNAVAILABLE: {}: Socket closed",
                    address_name(addr)
                ),
            );
        }
        Some(other) => {
            return unavailable(addr, &format!("Tls handshake failed: {other}"));
        }
    };
    unavailable(
        addr,
        &format!(
            "Tls handshake failed (TSI_PROTOCOL_FAILURE): SSL_ERROR_SSL: error:1000007d:SSL \
             routines:OPENSSL_internal:CERTIFICATE_VERIFY_FAILED: {reason}: OK"
        ),
    )
}

fn unavailable(addr: &SocketAddr, why: &str) -> RpcError {
    RpcError::local(
        Code::Unavailable,
        format!(
            "failed to connect to all addresses; last error: UNKNOWN: {}: {why}",
            address_name(addr)
        ),
    )
}

/// The rustls client config of an API config; `Err` is why it cannot be
/// built (an unreadable PEM).
pub fn tls_config(cfg: &ApiConfig) -> Result<rustls::ClientConfig, String> {
    let mut roots = RootCertStore::empty();
    let mut pinned = Vec::new();
    for cert in CertificateDer::pem_slice_iter(cfg.ca_certificate.as_bytes()) {
        let cert = cert.map_err(|e| format!("Cannot load server root certificates: {e:?}"))?;
        pinned.push(cert.clone());
        roots
            .add(cert)
            .map_err(|e| format!("Cannot load server root certificates: {e}"))?;
    }
    if roots.is_empty() {
        return Err("Could not load any root certificate.".into());
    }
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cfg.client_cert.as_bytes())
            .collect::<Result<_, _>>()
            .map_err(|e| format!("Invalid cert chain file: {e:?}"))?;
    if chain.is_empty() {
        return Err("Invalid cert chain file.".into());
    }
    let key = PrivateKeyDer::from_pem_slice(cfg.client_private_key.as_bytes())
        .map_err(|_| "Invalid private key.".to_string())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = PartialChainVerifier::new(roots, pinned, Arc::clone(&provider))?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(chain, key)
        .map_err(|e| format!("Invalid private key: {e}"))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

/// `%XX` in a `grpc-message` decoded (invalid sequences kept as sent).
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok());
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The status grpc assigns a non-200 HTTP answer.
fn http_status_code(status: u16) -> Code {
    match status {
        400 => Code::Internal,
        401 => Code::Unauthenticated,
        403 => Code::PermissionDenied,
        404 => Code::Unimplemented,
        429 | 502 | 503 | 504 => Code::Unavailable,
        _ => Code::Unknown,
    }
}

async fn connect(
    target: &Target,
    tls: &mut Option<Result<Arc<rustls::ClientConfig>, String>>,
    cfg: &ApiConfig,
) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, SocketAddr), RpcError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|e| {
            RpcError::local(
                Code::Unavailable,
                format!(
                    "DNS resolution failed for {}:{}: {}",
                    target.host,
                    target.port,
                    crate::config::strerror(&e)
                ),
            )
        })?
        .collect();
    let mut last: Option<RpcError> = None;
    for addr in addrs {
        let tcp = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) => {
                last = Some(unavailable(
                    &addr,
                    &format!(
                        "Failed to connect to remote host: {}",
                        crate::config::strerror(&e)
                    ),
                ));
                continue;
            }
        };
        let _ = tcp.set_nodelay(true);
        let config = match tls.get_or_insert_with(|| tls_config(cfg).map(Arc::new)) {
            Ok(c) => Arc::clone(c),
            Err(e) => {
                tracing::error!("Cannot build the TLS client config: {e}");
                return Err(unavailable(&addr, "Failed to create security handshaker."));
            }
        };
        let name = ServerName::try_from(SERVER_NAME)
            .map_err(|e| RpcError::local(Code::Internal, e.to_string()))?;
        match tokio_rustls::TlsConnector::from(config)
            .connect(name, tcp)
            .await
        {
            Ok(stream) => return Ok((stream, addr)),
            Err(e) => {
                last = Some(handshake_failure(&addr, &e));
            }
        }
    }
    Err(last.unwrap_or_else(|| {
        RpcError::local(
            Code::Unavailable,
            format!(
                "DNS resolution failed for {}:{}: no addresses",
                target.host, target.port
            ),
        )
    }))
}

/// `ceil(a / b)` for positive values.
fn div_up(a: u64, b: u64) -> u64 {
    a.div_ceil(b)
}

/// The `grpc-timeout` header as grpc-core writes it (`Timeout::FromMillis`
/// and `Encode`): the remaining time rounded *up* to the coarsest unit that
/// keeps three significant digits, and a whole number of minutes or hours
/// written as such (`5S`, `5010m`, `30S`, `30100m`, `1M`, `301S`, `1H`).
/// grpc-core reads the remaining time off its clock when the call starts,
/// usually a millisecond over the timeout Python asked for; this encodes the
/// timeout itself.
fn grpc_timeout(timeout: Duration) -> String {
    let millis = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    if millis == 0 {
        return "1n".into();
    }
    if millis < 1000 {
        return format!("{millis}m");
    }
    if millis < 10_000 {
        let value = div_up(millis, 10);
        if value % 100 != 0 {
            return format!("{value}0m");
        }
    } else if millis < 100_000 {
        let value = div_up(millis, 100);
        if value % 10 != 0 {
            return format!("{value}00m");
        }
    }
    let seconds = div_up(millis, 1000);
    if seconds < 1000 {
        if seconds % 60 != 0 {
            return format!("{seconds}S");
        }
    } else if seconds < 10_000 {
        let value = div_up(seconds, 10);
        if (value * 10) % 60 != 0 {
            return format!("{value}0S");
        }
    } else if seconds < 100_000 {
        let value = div_up(seconds, 100);
        if (value * 100) % 60 != 0 {
            return format!("{value}00S");
        }
    }
    let minutes = div_up(seconds, 60);
    if minutes < 1000 {
        if minutes % 60 != 0 {
            return format!("{minutes}M");
        }
    } else if minutes < 10_000 {
        let value = div_up(minutes, 10);
        if (value * 10) % 60 != 0 {
            return format!("{value}0M");
        }
    }
    let hours = div_up(minutes, 60);
    if hours < 10_000 {
        format!("{hours}H")
    } else {
        format!("{}0H", div_up(hours, 10).min(9_999))
    }
}

/// The status in a header map (trailers, or the headers of a trailers-only
/// answer); `None` when there is none.
fn status_of(headers: &http::HeaderMap, peer: &str) -> Option<RpcError> {
    let raw = headers.get("grpc-status")?.to_str().ok()?;
    let code = raw
        .trim()
        .parse::<i32>()
        .map_or(Code::Unknown, Code::from_i32);
    let details = headers
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .map(percent_decode)
        .unwrap_or_default();
    Some(RpcError {
        code,
        details,
        peer: peer.to_string(),
    })
}

/// One server-streaming call: `request` (an encoded message) to `method`
/// (`/proto.API/Query`); `on_message` receives each answer in order. The
/// deadline covers the whole call, connection included.
pub async fn server_streaming<E>(
    cfg: &ApiConfig,
    method: &str,
    request: Vec<u8>,
    timeout: Duration,
    on_message: impl FnMut(Bytes) -> Result<(), E>,
) -> Result<(), CallError<E>> {
    match tokio::time::timeout(timeout, call(cfg, method, request, timeout, on_message)).await {
        Ok(result) => result,
        Err(_) => Err(CallError::Rpc(RpcError::local(
            Code::DeadlineExceeded,
            "Deadline Exceeded",
        ))),
    }
}

async fn call<E>(
    cfg: &ApiConfig,
    method: &str,
    request: Vec<u8>,
    timeout: Duration,
    mut on_message: impl FnMut(Bytes) -> Result<(), E>,
) -> Result<(), CallError<E>> {
    let rpc = |e: RpcError| CallError::Rpc(e);
    let target = parse_target(&cfg.api_connection_string).map_err(rpc)?;
    let mut tls = None;
    let (stream, addr) = connect(&target, &mut tls, cfg).await.map_err(rpc)?;
    let peer = address_name(&addr);
    // The server dropping the connection before it answered (a client
    // certificate it refused is only noticed here under TLS 1.3).
    let closed_early = |e: hyper::Error| {
        tracing::error!("Velociraptor closed the connection: {e}");
        rpc(RpcError::local(
            Code::Unavailable,
            format!(
                "failed to connect to all addresses; last error: UNAVAILABLE: {peer}: Socket closed"
            ),
        ))
    };
    let socket_closed = |why: String| rpc(RpcError::local(Code::Unavailable, why));
    let (mut sender, conn) = http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Full<Bytes>>(TokioIo::new(stream))
        .await
        .map_err(closed_early)?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut frame = Vec::with_capacity(request.len() + 5);
    frame.push(0);
    frame.extend_from_slice(
        &u32::try_from(request.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    frame.extend_from_slice(&request);
    let authority = if cfg.api_connection_string.starts_with("dns:///") {
        &cfg.api_connection_string["dns:///".len()..]
    } else {
        cfg.api_connection_string.as_str()
    };
    let req = http::Request::post(format!("https://{authority}{method}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-timeout", grpc_timeout(timeout))
        .header("user-agent", "copilot-rs grpc")
        .body(Full::new(Bytes::from(frame)))
        .map_err(|e| rpc(RpcError::local(Code::Internal, e.to_string())))?;
    let outcome = async {
        let resp = sender
            .send_request(req)
            .await
            .map_err(closed_early)?;
        if let Some(status) = status_of(resp.headers(), "") {
            // Trailers-only: no message follows (and grpc names no peer).
            return match status.code {
                Code::Ok => Ok(()),
                _ => Err(rpc(status)),
            };
        }
        if resp.status() != http::StatusCode::OK {
            let code = http_status_code(resp.status().as_u16());
            return Err(rpc(RpcError::local(
                code,
                format!(
                    "Received http2 header with status: {}",
                    resp.status().as_u16()
                ),
            )));
        }
        let mut body = resp.into_body();
        let mut buf = BytesMut::new();
        loop {
            let Some(frame) = body.frame().await else {
                return Err(rpc(RpcError::local(Code::Unknown, "Stream removed")));
            };
            let frame = frame.map_err(|e| {
                tracing::error!("Velociraptor stream failed: {e}");
                socket_closed("Socket closed".into())
            })?;
            match frame.into_data() {
                Ok(data) => {
                    buf.extend_from_slice(&data);
                    while buf.len() >= 5 {
                        let compressed = buf[0];
                        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
                        if len > MAX_RECEIVE_MESSAGE_LENGTH {
                            return Err(rpc(RpcError::local(
                                Code::ResourceExhausted,
                                format!(
                                    "Received message larger than max ({len} vs. {MAX_RECEIVE_MESSAGE_LENGTH})"
                                ),
                            )));
                        }
                        if buf.len() < 5 + len {
                            break;
                        }
                        buf.advance(5);
                        let message = buf.split_to(len).freeze();
                        if compressed != 0 {
                            return Err(rpc(RpcError::local(
                                Code::Internal,
                                "Unexpected compressed message",
                            )));
                        }
                        on_message(message).map_err(CallError::Handler)?;
                    }
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        return match status_of(&trailers, &peer) {
                            Some(s) if s.code == Code::Ok => Ok(()),
                            Some(s) => Err(rpc(s)),
                            None => Err(rpc(RpcError::local(
                                Code::Unknown,
                                "Stream removed",
                            ))),
                        };
                    }
                }
            }
        }
    }
    .await;
    driver.abort();
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_parse_like_the_dns_resolver() {
        assert_eq!(
            parse_target("127.0.0.1:8001").unwrap(),
            Target {
                host: "127.0.0.1".into(),
                port: 8001
            }
        );
        assert_eq!(
            parse_target("dns:///velo.example:8001").unwrap(),
            Target {
                host: "velo.example".into(),
                port: 8001
            }
        );
        assert_eq!(parse_target("velo.example").unwrap().port, 443);
        assert_eq!(
            parse_target("[::1]:8001").unwrap(),
            Target {
                host: "::1".into(),
                port: 8001
            }
        );
        assert!(parse_target("host:notaport").is_err());
        assert!(parse_target("").is_err());
    }

    #[test]
    fn messages_and_statuses() {
        assert_eq!(percent_decode("a%20b%zz%"), "a b%zz%");
        assert_eq!(percent_decode("caf%C3%A9"), "café");
        // What grpcio sends for these timeouts when its clock reads them
        // exactly (`context.time_remaining()` on a grpcio server).
        for (ms, header) in [
            (999, "999m"),
            (1000, "1S"),
            (5000, "5S"),
            (5001, "5010m"),
            (30_000, "30S"),
            (30_001, "30100m"),
            (60_000, "1M"),
            (100_001, "101S"),
            (300_000, "5M"),
            (300_001, "301S"),
            (1_000_001, "1010S"),
            (3_600_000, "1H"),
        ] {
            assert_eq!(grpc_timeout(Duration::from_millis(ms)), header, "{ms}");
        }
        assert_eq!(Code::from_i32(14), Code::Unavailable);
        assert_eq!(Code::from_i32(99), Code::Unknown);
        let e = RpcError::local(Code::Unavailable, "x");
        assert_eq!(
            e.rendezvous_str(),
            "<_MultiThreadedRendezvous of RPC that terminated with:\n\tstatus = StatusCode.UNAVAILABLE\n\tdetails = \"x\"\n\tdebug_error_string = \"UNKNOWN:Error received from peer  {grpc_status:14, grpc_message:\"x\"}\"\n>"
        );
        let sent = RpcError {
            peer: "ipv4:127.0.0.1:8001".into(),
            ..RpcError::local(Code::PermissionDenied, "no")
        };
        assert!(
            sent.rendezvous_str()
                .contains("from peer ipv4:127.0.0.1:8001 {grpc_status:7, grpc_message:\"no\"}")
        );
    }

    #[tokio::test]
    async fn a_refused_connection_reads_like_grpc_core() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let cfg = ApiConfig {
            ca_certificate: String::new(),
            client_cert: String::new(),
            client_private_key: String::new(),
            api_connection_string: format!("127.0.0.1:{port}"),
        };
        let err = server_streaming(
            &cfg,
            "/proto.API/Query",
            Vec::new(),
            Duration::from_secs(5),
            |_| Ok::<(), ()>(()),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err,
            CallError::Rpc(RpcError::local(
                Code::Unavailable,
                format!(
                    "failed to connect to all addresses; last error: UNKNOWN: ipv4:127.0.0.1:{port}: Failed to connect to remote host: Connection refused"
                )
            ))
        );
    }
}
