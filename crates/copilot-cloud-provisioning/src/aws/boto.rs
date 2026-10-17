//! The four botocore 1.43 calls the AWS validation makes — `sts
//! GetCallerIdentity`, `s3 HeadBucket`, `ListObjectsV2` and `GetObject` — as
//! boto3 sends them and as it reads the answers:
//!
//! - **the endpoint**: `AWS_ENDPOINT_URL_STS` / `AWS_ENDPOINT_URL_S3`, else
//!   `AWS_ENDPOINT_URL` (path-style S3), else the partition's — STS
//!   regional, S3 virtual-hosted for a DNS-label bucket (`s3.amazonaws.com`
//!   in `us-east-1`), path-style otherwise;
//! - **the request**: the operation's URL, query and headers in botocore's
//!   order, SigV4 over the same canonical request (S3 with
//!   `UNSIGNED-PAYLOAD`), `amz-sdk-invocation-id` / `amz-sdk-request`, the
//!   user agent with its `m/` feature list; on the wire `Host` and
//!   `Accept-Encoding: identity` first, title-cased as urllib3-future
//!   writes them;
//! - **the retries**: standard mode, three attempts (`max_attempts=2`
//!   retries), transient statuses and codes, throttling codes and
//!   transport errors, `random() * 2**(attempt-1)` seconds apart; S3's
//!   region redirector (a wrong region's 301/400/`PermanentRedirect`/
//!   `AuthorizationHeaderMalformed`, the region from the header, the error
//!   body or a nested `HeadBucket`), its per-client cache; S3's 200 with an
//!   error body counted as a 500;
//! - **the answers**: query-protocol and rest-xml parsing of what the
//!   validation reads, the generic, status-only and body errors
//!   (`ClientError`'s `Code`, `Message` and headers), `ResponseParserError`,
//!   `encoding-type=url` decoding, and the transport exceptions' texts.
//!
//! Not reproduced (not provoked by any test): `LastModified` values dateutil
//! would refuse, S3 Express buckets, FIPS / dual-stack / accelerate
//! endpoints, the retry quota (500 tokens per client, never exhausted by
//! these calls), the environment's proxies (AWS is reached directly, §4), the
//! user agent's interpreter patch version (`lang/python#3.11`)
//! and its `m/` order (a set's: process-dependent in Python).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use chrono::{NaiveDateTime, Utc};
use copilot_integrations::etree::{self, Element};
use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// boto3's and botocore's version.
pub const BOTO_VERSION: &str = "1.43.6";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(15);
/// `max_attempts=2` retries: three attempts in all.
pub const MAX_ATTEMPTS: u32 = 3;

/// The two services.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// STS (query protocol).
    Sts,
    /// S3 (rest-xml).
    S3,
}

impl Service {
    fn signing_name(self) -> &'static str {
        match self {
            Service::Sts => "sts",
            Service::S3 => "s3",
        }
    }
}

/// An exception a call ends in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BotoError {
    /// `botocore.exceptions.ClientError`.
    Client(ClientError),
    /// A transport failure (`EndpointConnectionError`, `ConnectTimeoutError`,
    /// `ReadTimeoutError`, `ConnectionClosedError`, `ProxyConnectionError`):
    /// its class and `str()`.
    Network(&'static str, String),
    /// Any other `BotoCoreError` (`InvalidRegionError`, `SSLError`,
    /// `HTTPClientError`): its class and `str()`.
    Core(&'static str, String),
    /// `ResponseParserError` (not a `BotoCoreError`).
    Parser(String),
    /// A `ValueError` raised while parsing (`int()` of a `Size`).
    Value(String),
    /// A `KeyError` (`member["Key"]` while decoding): its `str()`.
    Key(String),
    /// The `AttributeError` the retry handler raises reading the `Code` of
    /// an `Error` that parsed as text.
    Attribute(String),
}

/// A parsed error value (`_replace_nodes`: a node's text, or a dict of its
/// children).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// `node.text` (`None` for an empty element).
    Text(Option<String>),
    /// The children by tag.
    Dict(Vec<(String, Node)>),
}

impl Node {
    /// `str(value)`.
    pub fn py_str(&self) -> String {
        match self {
            Node::Text(Some(t)) => t.clone(),
            Node::Text(None) => "None".into(),
            Node::Dict(_) => self.py_repr(),
        }
    }

    fn py_repr(&self) -> String {
        match self {
            Node::Text(Some(t)) => copilot_auth::pyvalue::PyValue::Str(t.clone()).py_repr(),
            Node::Text(None) => "None".into(),
            Node::Dict(items) => format!(
                "{{{}}}",
                items
                    .iter()
                    .map(|(k, v)| format!(
                        "{}: {}",
                        copilot_auth::pyvalue::PyValue::Str(k.clone()).py_repr(),
                        v.py_repr()
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Dict(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            Node::Text(_) => None,
        }
    }
}

/// `ClientError.response`: what the validation reads of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientError {
    /// `response["Error"]`: a dict (a body's text in odd answers).
    pub error: Option<Node>,
    /// `response["ResponseMetadata"]["HTTPHeaders"]` (lower-case names).
    pub headers: Vec<(String, String)>,
}

impl ClientError {
    /// `str(err.response.get("Error", {}).get("Code", ""))`; `Err` is the
    /// `AttributeError` of a text `Error`.
    pub fn code(&self) -> Result<String, String> {
        self.field("Code")
    }

    /// `str(err.response.get("Error", {}).get("Message", ""))`.
    pub fn message(&self) -> Result<String, String> {
        self.field("Message")
    }

    fn field(&self, name: &str) -> Result<String, String> {
        match &self.error {
            None => Ok(String::new()),
            Some(Node::Text(_)) => Err("'str' object has no attribute 'get'".into()),
            Some(n @ Node::Dict(_)) => Ok(n.get(name).map_or(String::new(), Node::py_str)),
        }
    }

    /// `HTTPHeaders.get(name)`.
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }

    /// `error.get("Code")` as the retry checks read it: only a text.
    fn retry_code(&self) -> Option<&str> {
        match self.error.as_ref()?.get("Code")? {
            Node::Text(Some(t)) => Some(t.as_str()),
            _ => None,
        }
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// `http.client.responses[status]`.
pub fn status_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a Teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "",
    }
}

// --- partitions and endpoints ------------------------------------------------------

struct Partition {
    names: &'static [&'static str],
    prefix: &'static [&'static str],
    dns_suffix: &'static str,
}

/// `partitions.json`'s partitions, in order: the region regex as the
/// prefixes it allows (`^(prefix)\-\w+\-\d+$`), the explicit (global)
/// region names.
const PARTITIONS: &[Partition] = &[
    Partition {
        names: &["aws-global"],
        prefix: &["us", "eu", "ap", "sa", "ca", "me", "af", "il", "mx"],
        dns_suffix: "amazonaws.com",
    },
    Partition {
        names: &["aws-cn-global"],
        prefix: &["cn"],
        dns_suffix: "amazonaws.com.cn",
    },
    Partition {
        names: &[],
        prefix: &["eusc-de"],
        dns_suffix: "amazonaws.eu",
    },
    Partition {
        names: &["aws-iso-global"],
        prefix: &["us-iso"],
        dns_suffix: "c2s.ic.gov",
    },
    Partition {
        names: &["aws-iso-b-global"],
        prefix: &["us-isob"],
        dns_suffix: "sc2s.sgov.gov",
    },
    Partition {
        names: &["aws-iso-e-global"],
        prefix: &["eu-isoe"],
        dns_suffix: "cloud.adc-e.uk",
    },
    Partition {
        names: &["aws-iso-f-global"],
        prefix: &["us-isof"],
        dns_suffix: "csp.hci.ic.gov",
    },
    Partition {
        names: &["aws-us-gov-global"],
        prefix: &["us-gov"],
        dns_suffix: "amazonaws.com",
    },
];

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `re.match(regionRegex, region)` for `^(prefix)\-\w+\-\d+$` (`$` also
/// before a final newline).
fn region_matches(prefix: &str, region: &str) -> bool {
    let region = region.strip_suffix('\n').unwrap_or(region);
    let Some(rest) = region.strip_prefix(prefix) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix('-') else {
        return false;
    };
    // `\w+` then `\-\d+`: the last `-` splits them (`\w` has no `-`).
    let Some((word, digits)) = rest.rsplit_once('-') else {
        return false;
    };
    !word.is_empty()
        && word.chars().all(is_word_char)
        && !digits.is_empty()
        && digits
            .chars()
            .all(|c| copilot_jinja::unicode::decimal_value(c).is_some())
}

/// `aws.partition(region)`'s `dnsSuffix`.
fn dns_suffix(region: &str) -> &'static str {
    for p in PARTITIONS {
        if p.names.contains(&region) {
            return p.dns_suffix;
        }
    }
    // The listed regions all match their partition's regex.
    for p in PARTITIONS {
        if p.prefix.iter().any(|pre| region_matches(pre, region)) {
            return p.dns_suffix;
        }
    }
    PARTITIONS[0].dns_suffix
}

/// `validate_region_name(region)`
/// (`^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$`).
pub fn valid_region(region: &str) -> bool {
    let r = region.strip_suffix('\n').unwrap_or(region);
    let all_digits = !r.is_empty() && r.chars().all(|c| c.is_ascii_digit());
    !all_digits
        && !r.starts_with('-')
        && !r.ends_with('-')
        && r.chars().count() <= 63
        && r.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// `InvalidRegionError(region_name=region)`.
pub fn invalid_region(region: &str) -> BotoError {
    BotoError::Core(
        "InvalidRegionError",
        format!("Provided region_name '{region}' doesn't match a supported format."),
    )
}

/// `aws.isVirtualHostableS3Bucket(bucket, false)`.
fn virtual_hostable(bucket: &str) -> bool {
    let len = bucket.chars().count();
    let ipv4 = bucket.split('.').count() == 4
        && bucket
            .split('.')
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    len >= 3
        && bucket.to_lowercase() == bucket
        && !ipv4
        && !bucket.contains('.')
        && len <= 63
        && !bucket.starts_with('-')
        && !bucket.ends_with('-')
        && bucket
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// The endpoint override botocore reads from the environment:
/// `AWS_ENDPOINT_URL_STS` / `AWS_ENDPOINT_URL_S3`, else `AWS_ENDPOINT_URL`.
pub fn endpoint_override(
    service: Service,
    env: &copilot_core::cloud_env::CloudEnv,
) -> Option<String> {
    let own = match service {
        Service::Sts => env.aws_endpoint_url_sts.clone(),
        Service::S3 => env.aws_endpoint_url_s3.clone(),
    };
    own.or_else(|| env.aws_endpoint_url.clone())
}

/// The request URL's origin and path for an operation.
fn base_url(service: Service, region: &str, bucket: Option<&str>, over: Option<&str>) -> String {
    if let Some(o) = over {
        let o = o.trim_end_matches('/');
        return match bucket {
            Some(b) => format!("{o}/{b}"),
            None => format!("{o}/"),
        };
    }
    let suffix = dns_suffix(region);
    match (service, bucket) {
        (Service::Sts, _) => format!("https://sts.{region}.{suffix}/"),
        (Service::S3, Some(b)) if virtual_hostable(b) => {
            if region == "us-east-1" {
                format!("https://{b}.s3.amazonaws.com/")
            } else {
                format!("https://{b}.s3.{region}.{suffix}/")
            }
        }
        (Service::S3, b) => {
            let host = if region == "us-east-1" {
                "https://s3.amazonaws.com".to_string()
            } else {
                format!("https://s3.{region}.{suffix}")
            };
            format!("{host}/{}", b.unwrap_or_default())
        }
    }
}

// --- quoting ----------------------------------------------------------------------

/// `urllib.parse.quote(value, safe)` (UTF-8).
pub fn quote(value: &str, safe: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        let c = b as char;
        if b.is_ascii_alphanumeric() || "_.-~".contains(c) || safe.contains(c) {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// --- the operations ----------------------------------------------------------------

/// One operation's input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// `sts.get_caller_identity()`.
    GetCallerIdentity,
    /// `s3.head_bucket(Bucket=…)`.
    HeadBucket {
        /// `Bucket`.
        bucket: String,
    },
    /// `s3.list_objects_v2(Bucket=…, Prefix=…, **extra)`: `extra` in the
    /// call's keyword order (`Delimiter` or `MaxKeys`).
    ListObjectsV2 {
        /// `Bucket`.
        bucket: String,
        /// `Prefix`.
        prefix: String,
        /// `Delimiter`.
        delimiter: Option<String>,
        /// `MaxKeys`.
        max_keys: Option<i64>,
    },
    /// `s3.get_object(Bucket=…, Key=…, Range=…)`.
    GetObject {
        /// `Bucket`.
        bucket: String,
        /// `Key`.
        key: String,
        /// `Range`.
        range: String,
    },
}

impl Operation {
    /// The operation's name.
    pub fn name(&self) -> &'static str {
        match self {
            Operation::GetCallerIdentity => "GetCallerIdentity",
            Operation::HeadBucket { .. } => "HeadBucket",
            Operation::ListObjectsV2 { .. } => "ListObjectsV2",
            Operation::GetObject { .. } => "GetObject",
        }
    }

    fn bucket(&self) -> Option<&str> {
        match self {
            Operation::GetCallerIdentity => None,
            Operation::HeadBucket { bucket }
            | Operation::ListObjectsV2 { bucket, .. }
            | Operation::GetObject { bucket, .. } => Some(bucket),
        }
    }
}

/// One request as sent: method, URL, headers (wire order, `Host` and
/// `Accept-Encoding` first), body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireRequest {
    /// Method.
    pub method: &'static str,
    /// The full URL (what the transport errors name).
    pub url: String,
    /// Headers in order.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

/// One answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireAnswer {
    /// Status.
    pub status: u16,
    /// Headers, lower-case names, repeated ones joined with `, `.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

/// How a request failed to get an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Refused, unreachable, unresolvable: `EndpointConnectionError`.
    Connect,
    /// The connect timeout.
    ConnectTimeout,
    /// The read timeout.
    ReadTimeout,
    /// Closed before an answer: `ConnectionClosedError`.
    Closed,
    /// The TLS handshake failed: `SSLError` with its text.
    Tls(String),
}

/// Where requests go: the network, or (tests) a script.
#[derive(Clone)]
pub enum Transport {
    /// The network.
    Network,
    /// Scripted answers, one per request, and the requests sent.
    Script(Arc<Mutex<Script>>),
}

/// A test transport's script.
#[derive(Debug, Default)]
pub struct Script {
    /// The answers, in order (an exhausted script answers `200` and no
    /// body).
    pub answers: VecDeque<Result<WireAnswer, TransportError>>,
    /// The requests sent.
    pub seen: Vec<WireRequest>,
}

/// What a client's calls need beyond the operation: the clock, the
/// invocation ids and the retry delays (fixed in tests).
#[derive(Clone)]
pub struct Hooks {
    /// The signing time.
    pub now: fn() -> NaiveDateTime,
    /// `str(uuid.uuid4())`.
    pub invocation_id: fn() -> String,
    /// Whether retries wait (`random() * 2**(attempt-1)` seconds).
    pub sleep: bool,
}

impl Default for Hooks {
    fn default() -> Self {
        Self {
            now: || Utc::now().naive_utc(),
            invocation_id: || uuid::Uuid::new_v4().to_string(),
            sleep: true,
        }
    }
}

/// `boto3.Session(key, secret).client(service, region_name=region,
/// config=Config(connect_timeout=5, read_timeout=15, retries={"max_attempts":
/// 2, "mode": "standard"}))`.
#[derive(Clone)]
pub struct Client {
    service: Service,
    region: String,
    access_key: String,
    secret_key: String,
    endpoint: Option<String>,
    transport: Transport,
    hooks: Hooks,
    /// The S3 redirector's bucket → region cache.
    redirects: Arc<Mutex<Vec<(String, String)>>>,
}

/// One attempt's answer: its status (as parsed), headers and reading.
type Answered = (u16, Vec<(String, String)>, Result<Output, BotoError>);

/// A parsed success.
#[derive(Debug, Clone, PartialEq)]
pub enum Output {
    /// `GetCallerIdentity`: `Account`, when present.
    Identity {
        /// `Account` (`None` when absent).
        account: Option<String>,
    },
    /// `HeadBucket`: the answer's headers.
    Head {
        /// `ResponseMetadata.HTTPHeaders`.
        headers: Vec<(String, String)>,
    },
    /// `ListObjectsV2`.
    List(ListOutput),
    /// `GetObject` (its body is closed unread).
    Object,
}

/// One `Contents` entry: what the validation reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// `Key` (absent: `item["Key"]` is the `KeyError`).
    pub key: Option<String>,
    /// `Size`.
    pub size: Option<i64>,
    /// `StorageClass`.
    pub storage_class: Option<String>,
}

/// A `ListObjectsV2` answer: `Contents`, `CommonPrefixes` (their `Prefix`,
/// `None` where absent).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListOutput {
    /// `Contents` (`None` when absent).
    pub contents: Option<Vec<Object>>,
    /// `CommonPrefixes` (`None` when absent).
    pub common_prefixes: Option<Vec<Option<String>>>,
}

impl Client {
    /// A client for `service` in `region` (`validate_region_name` first),
    /// at the endpoint override when there is one.
    pub fn new(
        service: Service,
        region: &str,
        (access_key, secret_key): (&str, &str),
        endpoint: Option<String>,
        transport: Transport,
        hooks: Hooks,
    ) -> Result<Self, BotoError> {
        if !valid_region(region) {
            return Err(invalid_region(region));
        }
        Ok(Self {
            service,
            region: region.to_string(),
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
            endpoint,
            transport,
            hooks,
            redirects: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// The user agent of this client's requests.
    pub fn user_agent(&self) -> String {
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|r| r.trim().to_string())
            .unwrap_or_default();
        let metrics = if self.endpoint.is_some() {
            "E,N,Z,b,e"
        } else {
            "E,Z,b,e"
        };
        format!(
            "Boto3/{BOTO_VERSION} md/Botocore#{BOTO_VERSION} ua/2.1 os/linux#{release} \
             md/arch#{} lang/python#3.11 md/pyimpl#CPython m/{metrics} cfg/retry-mode#standard \
             Botocore/{BOTO_VERSION}",
            std::env::consts::ARCH
        )
    }

    fn cached_region(&self, bucket: &str) -> Option<String> {
        let cache = self.redirects.lock().unwrap_or_else(|e| e.into_inner());
        cache
            .iter()
            .find(|(b, _)| b == bucket)
            .map(|(_, r)| r.clone())
    }

    fn remember(&self, bucket: &str, region: &str) {
        let mut cache = self.redirects.lock().unwrap_or_else(|e| e.into_inner());
        match cache.iter_mut().find(|(b, _)| b == bucket) {
            Some(slot) => slot.1 = region.to_string(),
            None => cache.push((bucket.to_string(), region.to_string())),
        }
    }

    /// The URL of an operation in `region`.
    fn url(&self, op: &Operation, region: &str) -> String {
        let base = base_url(self.service, region, op.bucket(), self.endpoint.as_deref());
        match op {
            Operation::GetCallerIdentity | Operation::HeadBucket { .. } => base,
            Operation::ListObjectsV2 {
                prefix,
                delimiter,
                max_keys,
                ..
            } => {
                let mut query = vec![
                    "list-type=2".to_string(),
                    format!("prefix={}", quote(prefix, "-_.~")),
                ];
                if let Some(d) = delimiter {
                    query.push(format!("delimiter={}", quote(d, "-_.~")));
                }
                if let Some(m) = max_keys {
                    query.push(format!("max-keys={m}"));
                }
                query.push("encoding-type=url".into());
                let base = if base.ends_with('/')
                    && self.endpoint.is_none()
                    && op.bucket().is_some_and(virtual_hostable)
                {
                    base
                } else {
                    base.trim_end_matches('/').to_string()
                };
                format!("{base}?{}", query.join("&"))
            }
            Operation::GetObject { key, .. } => {
                let quoted = quote(key, "/~");
                if base.ends_with('/') {
                    format!("{base}{quoted}")
                } else {
                    format!("{base}/{quoted}")
                }
            }
        }
    }

    /// The signed request of one attempt.
    fn request(
        &self,
        op: &Operation,
        region: &str,
        invocation: &str,
        attempt: u32,
        ttl: Option<&str>,
    ) -> WireRequest {
        let url = self.url(op, region);
        let now = (self.hooks.now)();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let parsed = split_url(&url);
        let host_sign = parsed.sign_host.clone();
        let body: Vec<u8> = match op {
            Operation::GetCallerIdentity => b"Action=GetCallerIdentity&Version=2011-06-15".to_vec(),
            _ => Vec::new(),
        };
        // Headers before signing, in botocore's order.
        let mut headers: Vec<(String, String)> = Vec::new();
        match op {
            Operation::GetCallerIdentity => headers.push((
                "Content-Type".into(),
                "application/x-www-form-urlencoded; charset=utf-8".into(),
            )),
            Operation::GetObject { range, .. } => {
                headers.push(("Range".into(), range.clone()));
                headers.push(("x-amz-checksum-mode".into(), "ENABLED".into()));
            }
            _ => {}
        }
        headers.push(("User-Agent".into(), self.user_agent()));
        headers.push(("X-Amz-Date".into(), amz_date.clone()));
        let payload_hash = match self.service {
            Service::S3 => {
                headers.push(("X-Amz-Content-SHA256".into(), "UNSIGNED-PAYLOAD".into()));
                "UNSIGNED-PAYLOAD".to_string()
            }
            Service::Sts => hex::encode(Sha256::digest(&body)),
        };
        // `headers_to_sign`: every header but the blacklist, and `host`.
        let mut to_sign: Vec<(String, String)> = headers
            .iter()
            .filter(|(k, _)| {
                !matches!(
                    k.to_ascii_lowercase().as_str(),
                    "expect" | "transfer-encoding" | "user-agent" | "x-amzn-trace-id"
                )
            })
            .map(|(k, v)| (k.to_ascii_lowercase(), canonical_value(v)))
            .collect();
        to_sign.push(("host".into(), host_sign));
        to_sign.sort_by(|a, b| a.0.cmp(&b.0));
        let signed_headers = to_sign
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical_headers: String = to_sign.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let canonical_path = match self.service {
            Service::S3 => parsed.path.clone(),
            Service::Sts => quote(&normalize_url_path(&parsed.path), "/~"),
        };
        let canonical_request = format!(
            "{}\n{canonical_path}\n{}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
            op_method(op),
            canonical_query(&parsed.query),
        );
        let scope = format!(
            "{date}/{region}/{}/aws4_request",
            self.service.signing_name()
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let signature = sign(
            &self.secret_key,
            &date,
            region,
            self.service.signing_name(),
            &string_to_sign,
        );
        headers.push((
            "Authorization".into(),
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, \
                 Signature={signature}",
                self.access_key
            ),
        ));
        headers.push(("amz-sdk-invocation-id".into(), invocation.to_string()));
        headers.push((
            "amz-sdk-request".into(),
            match (attempt, ttl) {
                (1, _) => "attempt=1".to_string(),
                (_, Some(ttl)) => format!("ttl={ttl}; attempt={attempt}; max={MAX_ATTEMPTS}"),
                (_, None) => format!("attempt={attempt}; max={MAX_ATTEMPTS}"),
            },
        ));
        if !body.is_empty() {
            headers.push(("Content-Length".into(), body.len().to_string()));
        }
        let mut wire = vec![
            ("Host".to_string(), parsed.host_header.clone()),
            ("Accept-Encoding".to_string(), "identity".to_string()),
        ];
        wire.extend(headers.into_iter().map(|(k, v)| (title_case(&k), v)));
        WireRequest {
            method: op_method(op),
            url,
            headers: wire,
            body,
        }
    }

    async fn send(&self, req: &WireRequest) -> Result<WireAnswer, TransportError> {
        match &self.transport {
            Transport::Network => network_send(req).await,
            Transport::Script(script) => {
                let mut s = script.lock().unwrap_or_else(|e| e.into_inner());
                s.seen.push(req.clone());
                s.answers.pop_front().unwrap_or(Ok(WireAnswer {
                    status: 200,
                    headers: Vec::new(),
                    body: Vec::new(),
                }))
            }
        }
    }

    /// One call, its retries and redirects included.
    pub fn call<'a>(
        &'a self,
        op: &'a Operation,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Output, BotoError>> + Send + 'a>>
    {
        Box::pin(async move { self.call_inner(op).await })
    }

    async fn call_inner(&self, op: &Operation) -> Result<Output, BotoError> {
        let invocation = (self.hooks.invocation_id)();
        let mut region = op
            .bucket()
            .and_then(|b| self.cached_region(b))
            .unwrap_or_else(|| self.region.clone());
        let mut redirected = false;
        let mut attempt = 1u32;
        // `retries_context["ttl"]`: set from the `Date` of an answer that is
        // retried, kept through later attempts.
        let mut ttl: Option<String> = None;
        loop {
            let req = self.request(op, &region, &invocation, attempt, ttl.as_deref());
            let outcome = self.send(&req).await;
            let mut response: Option<Answered> = None;
            let mut exception: Option<BotoError> = None;
            match outcome {
                Err(e) => exception = Some(transport_error(e, &req.url)),
                Ok(answer) => {
                    let mut status = answer.status;
                    // `_handle_200_error`: S3's non-streaming answers.
                    if self.service == Service::S3
                        && status == 200
                        && !matches!(op, Operation::GetObject { .. })
                        && !answer.body.is_empty()
                        && looks_like_error(&answer.body)
                    {
                        status = 500;
                    }
                    let parsed = self.parse(op, status, &answer);
                    match parsed {
                        Err(BotoError::Parser(t)) => exception = Some(BotoError::Parser(t)),
                        other => response = Some((status, answer.headers.clone(), other)),
                    }
                }
            }
            // `needs-retry`: the standard retry handler reads
            // `response["Error"].get("Code")` first — an `Error` that is text
            // is its `AttributeError`.
            if let Some((_, _, Err(BotoError::Client(ce)))) = &response {
                if matches!(ce.error, Some(Node::Text(_))) {
                    return Err(BotoError::Attribute(
                        "'str' object has no attribute 'get'".into(),
                    ));
                }
            }
            // Then the retry decision and (S3) the redirector.
            let retryable = attempt < MAX_ATTEMPTS
                && match (&exception, &response) {
                    (Some(e), _) => matches!(
                        e,
                        BotoError::Network(..) | BotoError::Core("SSLError" | "HTTPClientError", _)
                    ),
                    (None, Some((status, _, Err(BotoError::Client(ce))))) => {
                        retryable_error(*status, ce.retry_code())
                    }
                    _ => false,
                };
            let mut redirect = false;
            if self.service == Service::S3 && !redirected {
                if let Some((status, headers, Err(BotoError::Client(ce)))) = &response {
                    if let Some(new_region) = self.redirect_region(op, *status, headers, ce).await?
                    {
                        region = new_region;
                        redirected = true;
                        redirect = true;
                    }
                }
            }
            if retryable || redirect {
                if let Some((_, headers, _)) = &response {
                    if let Some(t) = header(headers, "date").and_then(|d| self.retry_ttl(d)) {
                        ttl = Some(t);
                    }
                }
                if retryable && self.hooks.sleep {
                    let base = f64::from(2u32.pow(attempt - 1));
                    let delay = rand::random::<f64>() * base;
                    tokio::time::sleep(Duration::from_secs_f64(delay.min(20.0))).await;
                }
                attempt += 1;
                continue;
            }
            if let Some(e) = exception {
                return Err(e);
            }
            return match response {
                Some((_, _, result)) => result,
                None => Err(BotoError::Core("HTTPClientError", "no response".into())),
            };
        }
    }

    /// `Endpoint._calculate_ttl`: the local time plus the read timeout,
    /// corrected by the skew the answer's `Date` shows; `None` when the date
    /// does not parse (`%a, %d %b %Y %H:%M:%S %Z`).
    fn retry_ttl(&self, date: &str) -> Option<String> {
        let received = (self.hooks.now)();
        let local = (self.hooks.now)();
        let (stamp, zone) = date.rsplit_once(' ')?;
        if !matches!(zone, "GMT" | "UTC") {
            return None;
        }
        let server = NaiveDateTime::parse_from_str(stamp, "%a, %d %b %Y %H:%M:%S").ok()?;
        let ttl = local + chrono::Duration::from_std(READ_TIMEOUT).ok()? + (server - received);
        Some(ttl.format("%Y%m%dT%H%M%SZ").to_string())
    }

    /// `S3RegionRedirectorv2.redirect_from_error`: the region to retry in.
    async fn redirect_region(
        &self,
        op: &Operation,
        status: u16,
        headers: &[(String, String)],
        ce: &ClientError,
    ) -> Result<Option<String>, BotoError> {
        let code_str = ce
            .error
            .as_ref()
            .and_then(|e| e.get("Code"))
            .map(Node::py_str);
        let code_is = |c: &str| code_str.as_deref() == Some(c);
        let special_head_bucket = (code_is("301") || code_is("400"))
            && matches!(op, Operation::HeadBucket { .. })
            && header(headers, "x-amz-bucket-region").is_some();
        let error_region = ce.error.as_ref().and_then(|e| e.get("Region"));
        let wrong_signing_region =
            code_is("AuthorizationHeaderMalformed") && error_region.is_some();
        let redirect_status = matches!(status, 301 | 302 | 307);
        let permanent = code_is("PermanentRedirect");
        let opt_in = code_is("IllegalLocationConstraintException");
        if !(special_head_bucket || wrong_signing_region || permanent || redirect_status || opt_in)
        {
            return Ok(None);
        }
        let Some(bucket) = op.bucket() else {
            return Ok(None);
        };
        // `get_bucket_region(bucket, response)`.
        let region: Option<String> = if let Some(r) = header(headers, "x-amz-bucket-region") {
            Some(r.to_string())
        } else if let Some(r) =
            error_region.filter(|r| !matches!(r, Node::Text(None)) && !r.py_str().is_empty())
        {
            Some(r.py_str())
        } else {
            let head = Operation::HeadBucket {
                bucket: bucket.to_string(),
            };
            match self.call(&head).await {
                Ok(Output::Head { headers }) => {
                    header(&headers, "x-amz-bucket-region").map(str::to_string)
                }
                Ok(_) => None,
                Err(BotoError::Client(e)) => e.header("x-amz-bucket-region").map(str::to_string),
                Err(other) => return Err(other),
            }
        };
        if let Some(r) = &region {
            if !valid_region(r) {
                return Err(invalid_region(r));
            }
        }
        let Some(region) = region else {
            return Ok(None);
        };
        self.remember(bucket, &region);
        Ok(Some(region))
    }

    /// The answer as botocore's parser reads it.
    fn parse(&self, op: &Operation, status: u16, answer: &WireAnswer) -> Result<Output, BotoError> {
        if status >= 301 {
            return Err(BotoError::Client(self.parse_error(status, answer)?));
        }
        match op {
            Operation::GetCallerIdentity => {
                let root = parse_xml(&answer.body)?;
                let result = name_to_nodes(&root)
                    .into_iter()
                    .find(|(k, _)| k == "GetCallerIdentityResult")
                    .map(|(_, v)| v)
                    .ok_or_else(|| BotoError::Key("'GetCallerIdentityResult'".into()))?;
                let first = &result[0];
                let account = name_to_nodes(first)
                    .into_iter()
                    .find(|(k, _)| k == "Account")
                    .map(|(_, v)| v[0].text.clone().unwrap_or_default());
                Ok(Output::Identity { account })
            }
            Operation::HeadBucket { .. } => Ok(Output::Head {
                headers: answer.headers.clone(),
            }),
            Operation::GetObject { .. } => Ok(Output::Object),
            Operation::ListObjectsV2 { .. } => parse_list(&answer.body).map(Output::List),
        }
    }

    fn parse_error(&self, status: u16, answer: &WireAnswer) -> Result<ClientError, BotoError> {
        let headers = answer.headers.clone();
        let generic = || ClientError {
            error: Some(Node::Dict(vec![
                ("Code".into(), Node::Text(Some(status.to_string()))),
                (
                    "Message".into(),
                    Node::Text(Some(status_phrase(status).to_string())),
                ),
            ])),
            headers: headers.clone(),
        };
        // `_is_generic_error_response`.
        if status >= 500 {
            let body = py_strip_bytes(&answer.body);
            if body.is_empty() || body.starts_with(b"<html>") {
                return Ok(generic());
            }
        }
        match self.service {
            Service::Sts => {
                let root = parse_xml(&answer.body)?;
                let mut parsed = replace_nodes(&name_to_nodes(&root));
                if let Some(i) = parsed.iter().position(|(k, _)| k == "Errors") {
                    let (_, errors) = parsed.remove(i);
                    if let Node::Dict(items) = errors {
                        for (k, v) in items {
                            match parsed.iter_mut().find(|(pk, _)| *pk == k) {
                                Some(slot) => slot.1 = v,
                                None => parsed.push((k, v)),
                            }
                        }
                    }
                }
                let error = parsed
                    .iter()
                    .find(|(k, _)| k == "Error")
                    .map(|(_, v)| v.clone());
                Ok(ClientError { error, headers })
            }
            Service::S3 => {
                if answer.body.is_empty() {
                    return Ok(generic());
                }
                let Ok(root) = parse_xml(&answer.body) else {
                    return Ok(generic());
                };
                let parsed = replace_nodes(&name_to_nodes(&root));
                if local_name(&root.tag) == "Error" {
                    let parsed: Vec<(String, Node)> = parsed
                        .into_iter()
                        .filter(|(k, _)| k != "RequestId" && k != "HostId")
                        .collect();
                    return Ok(ClientError {
                        error: Some(Node::Dict(parsed)),
                        headers,
                    });
                }
                // `merge_dicts({'Error': {'Message': '', 'Code': ''}}, parsed)`.
                let mut error = Node::Dict(vec![
                    ("Message".into(), Node::Text(Some(String::new()))),
                    ("Code".into(), Node::Text(Some(String::new()))),
                ]);
                if let Some((_, value)) = parsed.iter().find(|(k, _)| k == "Error") {
                    match (value, &mut error) {
                        (Node::Dict(items), Node::Dict(base)) => {
                            for (k, v) in items {
                                match base.iter_mut().find(|(bk, _)| bk == k) {
                                    Some(slot) => slot.1 = v.clone(),
                                    None => base.push((k.clone(), v.clone())),
                                }
                            }
                        }
                        (other, _) => error = other.clone(),
                    }
                }
                Ok(ClientError {
                    error: Some(error),
                    headers,
                })
            }
        }
    }
}

fn op_method(op: &Operation) -> &'static str {
    match op {
        Operation::GetCallerIdentity => "POST",
        Operation::HeadBucket { .. } => "HEAD",
        Operation::ListObjectsV2 { .. } | Operation::GetObject { .. } => "GET",
    }
}

/// The standard retry conditions for an answer.
fn retryable_error(status: u16, code: Option<&str>) -> bool {
    const TRANSIENT_CODES: &[&str] = &[
        "RequestTimeout",
        "RequestTimeoutException",
        "PriorRequestNotComplete",
    ];
    const THROTTLED_CODES: &[&str] = &[
        "Throttling",
        "ThrottlingException",
        "ThrottledException",
        "RequestThrottledException",
        "TooManyRequestsException",
        "ProvisionedThroughputExceededException",
        "TransactionInProgressException",
        "RequestLimitExceeded",
        "BandwidthLimitExceeded",
        "LimitExceededException",
        "RequestThrottled",
        "SlowDown",
        "PriorRequestNotComplete",
        "EC2ThrottledException",
    ];
    code.is_some_and(|c| TRANSIENT_CODES.contains(&c) || THROTTLED_CODES.contains(&c))
        || matches!(status, 500 | 502 | 503 | 504)
}

fn transport_error(e: TransportError, url: &str) -> BotoError {
    match e {
        TransportError::Connect => BotoError::Network(
            "EndpointConnectionError",
            format!("Could not connect to the endpoint URL: \"{url}\""),
        ),
        TransportError::ConnectTimeout => BotoError::Network(
            "ConnectTimeoutError",
            format!("Connect timeout on endpoint URL: \"{url}\""),
        ),
        TransportError::ReadTimeout => BotoError::Network(
            "ReadTimeoutError",
            format!("Read timeout on endpoint URL: \"{url}\""),
        ),
        TransportError::Closed => BotoError::Network(
            "ConnectionClosedError",
            format!(
                "Connection was closed before we received a valid response from endpoint URL: \
                 \"{url}\"."
            ),
        ),
        TransportError::Tls(text) => BotoError::Core(
            "SSLError",
            format!("SSL validation failed for {url} {text}"),
        ),
    }
}

fn py_strip_bytes(b: &[u8]) -> &[u8] {
    let is_space = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let start = b.iter().position(|c| !is_space(c)).unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !is_space(c))
        .map_or(start, |i| i + 1);
    &b[start..end.max(start)]
}

/// `_looks_like_special_case_error(200, body)`: not XML, or an `<Error>`.
fn looks_like_error(body: &[u8]) -> bool {
    match parse_xml(body) {
        Err(_) => true,
        Ok(root) => root.tag == "Error",
    }
}

/// `' '.join(value.split())`.
fn canonical_value(v: &str) -> String {
    v.split(etree::py_is_space)
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `canonical_query_string`: the pairs sorted by key, then value.
fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(&str, &str)> = query
        .split('&')
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// `normalize_url_path(path)` (dot segments resolved).
fn normalize_url_path(path: &str) -> String {
    if path.is_empty() {
        return "/".into();
    }
    let mut out: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            p => out.push(p),
        }
    }
    let mut joined = format!("/{}", out.join("/"));
    if path.ends_with('/') && joined != "/" {
        joined.push('/');
    }
    joined
}

fn sign(secret: &str, date: &str, region: &str, service: &str, string_to_sign: &str) -> String {
    fn hmac(key: &[u8], msg: &str) -> Vec<u8> {
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
            return Vec::new();
        };
        mac.update(msg.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }
    let k_date = hmac(format!("AWS4{secret}").as_bytes(), date);
    let k_region = hmac(&k_date, region);
    let k_service = hmac(&k_region, service);
    let k_signing = hmac(&k_service, "aws4_request");
    hex::encode(hmac(&k_signing, string_to_sign))
}

/// urllib3-future's header names: each `-`-separated word capitalised.
fn title_case(name: &str) -> String {
    name.split('-')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_ascii_uppercase().to_string() + &c.as_str().to_ascii_lowercase(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

struct SplitUrl {
    tls: bool,
    host: String,
    port: u16,
    path: String,
    query: String,
    /// `Host` as written (the port unless the scheme's default).
    host_header: String,
    /// `_canonical_host(url)`.
    sign_host: String,
}

fn split_url(url: &str) -> SplitUrl {
    let (scheme, rest) = url.split_once("://").unwrap_or(("https", url));
    let tls = scheme.eq_ignore_ascii_case("https");
    let (authority, path_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (path, query) = match path_query.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (path_query.to_string(), String::new()),
    };
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => (authority.to_string(), if tls { 443 } else { 80 }),
        },
        _ => (authority.to_string(), if tls { 443 } else { 80 }),
    };
    let default = (tls && port == 443) || (!tls && port == 80);
    let host_header = if default {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let sign_host = if default {
        host.to_lowercase()
    } else {
        authority.to_string()
    };
    SplitUrl {
        tls,
        host: host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string(),
        port,
        path,
        query,
        host_header,
        sign_host,
    }
}

// --- XML ---------------------------------------------------------------------------

/// `_parse_xml_string_to_dom(body)` (UTF-8, comments dropped); `Err` is the
/// `ResponseParserError`.
fn parse_xml(body: &[u8]) -> Result<Element, BotoError> {
    let failure = |e: String| {
        BotoError::Parser(format!(
            "Unable to parse response ({e}), invalid XML received. Further retries may succeed:\n{}",
            copilot_auth::pyvalue::bytes_repr(body)
        ))
    };
    match std::str::from_utf8(body) {
        Ok(text) => etree::fromstring(text).map_err(|e| failure(e.to_string())),
        Err(err) => {
            let valid = &body[..err.valid_up_to()];
            let text = String::from_utf8_lossy(valid);
            let line = text.matches('\n').count() + 1;
            let column = text.rsplit('\n').next().unwrap_or_default().chars().count();
            Err(failure(format!(
                "not well-formed (invalid token): line {line}, column {column}"
            )))
        }
    }
}

/// `_node_tag(node)`: the tag without its `{namespace}`.
fn local_name(tag: &str) -> &str {
    match tag.strip_prefix('{').and_then(|r| r.split_once('}')) {
        Some((_, local)) => local,
        None => tag,
    }
}

/// `_build_name_to_xml_node(parent)`: the children by tag, repeated tags
/// as lists.
fn name_to_nodes(parent: &Element) -> Vec<(String, Vec<Element>)> {
    let mut out: Vec<(String, Vec<Element>)> = Vec::new();
    for child in &parent.children {
        if child.is_comment() {
            continue;
        }
        let key = local_name(&child.tag).to_string();
        match out.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(child.clone()),
            None => out.push((key, vec![child.clone()])),
        }
    }
    out
}

/// `_replace_nodes(parsed)`.
fn replace_nodes(parsed: &[(String, Vec<Element>)]) -> Vec<(String, Node)> {
    parsed
        .iter()
        .map(|(k, nodes)| {
            let value = if nodes.len() > 1 || nodes[0].children.iter().any(|c| !c.is_comment()) {
                // A list (repeated tag) reads its first element's children.
                Node::Dict(replace_nodes(&name_to_nodes(&nodes[0])))
            } else {
                Node::Text(nodes[0].text.clone())
            };
            (k.clone(), value)
        })
        .collect()
}

/// `int(text)` as `_handle_integer` runs it.
fn py_int(text: &str) -> Result<i64, BotoError> {
    let value = copilot_upstream::py::int_of(&copilot_auth::pyvalue::PyValue::Str(text.into()))
        .map_err(|e| BotoError::Value(e.text()))?;
    value
        .parse::<i64>()
        .map_err(|_| BotoError::Value(format!("invalid literal for int() with base 10: '{text}'")))
}

fn text_of(nodes: &[Element]) -> String {
    nodes[0].text.clone().unwrap_or_default()
}

/// `ListObjectsV2Output` as the rest-xml parser and
/// `decode_list_object_v2` read it.
fn parse_list(body: &[u8]) -> Result<ListOutput, BotoError> {
    if body.is_empty() {
        return Ok(ListOutput::default());
    }
    let root = parse_xml(body)?;
    let members = name_to_nodes(&root);
    let get = |name: &str| members.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    let mut out = ListOutput::default();
    let mut encoding: Option<String> = None;
    // Members in the shape's order: `IsTruncated`, `Contents`, …, `MaxKeys`,
    // `CommonPrefixes`, `EncodingType`, `KeyCount`.
    if let Some(nodes) = get("Contents") {
        let mut items = Vec::new();
        for node in nodes {
            let fields = name_to_nodes(node);
            let field = |name: &str| fields.iter().find(|(k, _)| k == name).map(|(_, v)| v);
            let key = field("Key").map(|v| text_of(v));
            let size = match field("Size") {
                Some(v) => Some(py_int(&text_of(v))?),
                None => None,
            };
            let storage_class = field("StorageClass").map(|v| text_of(v));
            items.push(Object {
                key,
                size,
                storage_class,
            });
        }
        out.contents = Some(items);
    }
    if let Some(nodes) = get("MaxKeys") {
        py_int(&text_of(nodes))?;
    }
    if let Some(nodes) = get("CommonPrefixes") {
        out.common_prefixes = Some(
            nodes
                .iter()
                .map(|n| {
                    let fields = name_to_nodes(n);
                    fields
                        .iter()
                        .find(|(k, _)| k == "Prefix")
                        .map(|(_, v)| text_of(v))
                })
                .collect(),
        );
    }
    if let Some(nodes) = get("EncodingType") {
        encoding = Some(text_of(nodes));
    }
    if let Some(nodes) = get("KeyCount") {
        py_int(&text_of(nodes))?;
    }
    if encoding.as_deref() == Some("url") {
        if let Some(items) = &mut out.contents {
            for item in items {
                let Some(k) = &item.key else {
                    return Err(BotoError::Key("'Key'".into()));
                };
                item.key = Some(copilot_web::form::unquote_plus(k));
            }
        }
        if let Some(prefixes) = &mut out.common_prefixes {
            for p in prefixes {
                let Some(v) = p.as_deref() else {
                    return Err(BotoError::Key("'Prefix'".into()));
                };
                *p = Some(copilot_web::form::unquote_plus(v));
            }
        }
    }
    Ok(out)
}

// --- the network ---------------------------------------------------------------------

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Ok(Arc::new(config))
        })
        .clone()
}

async fn network_send(req: &WireRequest) -> Result<WireAnswer, TransportError> {
    let url = split_url(&req.url);
    let tcp = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((url.host.as_str(), url.port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => return Err(TransportError::Connect),
        Err(_) => return Err(TransportError::ConnectTimeout),
    };
    let stream: Box<dyn Stream> = if url.tls {
        let config = tls_config().map_err(TransportError::Tls)?;
        let name = rustls::pki_types::ServerName::try_from(url.host.clone())
            .map_err(|e| TransportError::Tls(e.to_string()))?;
        let connector = tokio_rustls::TlsConnector::from(config);
        match tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp)).await {
            Ok(Ok(s)) => Box::new(s),
            Ok(Err(e)) => return Err(TransportError::Tls(e.to_string())),
            Err(_) => return Err(TransportError::ConnectTimeout),
        }
    } else {
        Box::new(tcp)
    };
    let (mut sender, conn) = http1::Builder::new()
        .title_case_headers(true)
        .handshake::<_, Full<Bytes>>(TokioIo::new(stream))
        .await
        .map_err(|_| TransportError::Closed)?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let path_query = if url.query.is_empty() {
        url.path.clone()
    } else {
        format!("{}?{}", url.path, url.query)
    };
    let mut builder = http::Request::builder().method(req.method).uri(path_query);
    for (k, v) in &req.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let request = builder
        .body(Full::new(Bytes::from(req.body.clone())))
        .map_err(|_| TransportError::Closed)?;
    let exchange = async {
        let resp = sender
            .send_request(request)
            .await
            .map_err(|_| TransportError::Closed)?;
        let status = resp.status().as_u16();
        let mut headers: Vec<(String, String)> = Vec::new();
        for (k, v) in resp.headers() {
            let value = String::from_utf8_lossy(v.as_bytes()).into_owned();
            match headers.iter_mut().find(|(n, _)| n == k.as_str()) {
                Some(slot) => {
                    slot.1.push_str(", ");
                    slot.1.push_str(&value);
                }
                None => headers.push((k.as_str().to_string(), value)),
            }
        }
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|_| TransportError::Closed)?
            .to_bytes()
            .to_vec();
        Ok(WireAnswer {
            status,
            headers,
            body,
        })
    };
    tokio::time::timeout(READ_TIMEOUT, exchange)
        .await
        .map_err(|_| TransportError::ReadTimeout)?
}

#[cfg(test)]
#[path = "boto_tests.rs"]
pub(crate) mod tests;
