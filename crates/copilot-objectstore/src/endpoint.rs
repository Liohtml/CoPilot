//! Where requests go: miniopy-async's `BaseURL` (`helpers.py`) over
//! CPython's `urllib.parse.urlsplit`, for the path-style URLs a MinIO
//! endpoint gets, and `quote` / `queryencode`.
//!
//! `Minio(endpoint)` parses `http[s]://` + endpoint and refuses, with these
//! `ValueError` texts, a path, query, fragment, user name, password or a port
//! that is not a number (`invalid port`); the default port of the scheme is
//! dropped from the `Host`. An Amazon S3 or Aliyun OSS host would switch the
//! library to virtual-hosted style and AWS's region rules, which this port
//! does not reproduce: such an endpoint is refused on every call (it cannot
//! serve S3 on the `:9000` CoPilot appends anyway).

use std::net::IpAddr;

/// A parsed endpoint (`BaseURL` for a non-AWS host).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// `secure`.
    pub https: bool,
    /// `url.netloc`: the `Host` header and the URL authority.
    pub netloc: String,
    /// `url.hostname`, without brackets (aiohttp's connection key host).
    pub host: String,
    /// The port connected to.
    pub port: u16,
    /// Why requests to this host are refused, if they are.
    pub unsupported: Option<String>,
}

/// `Minio(endpoint, secure=…)._base_url`, or the `ValueError` text.
/// `urlsplit` first strips leading C0 controls and spaces and removes tab,
/// CR and LF anywhere.
pub fn parse(endpoint: &str, secure: bool) -> Result<Endpoint, String> {
    let raw = format!("{}{endpoint}", if secure { "https://" } else { "http://" });
    let cleaned: String = raw
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    // The scheme is ours; what follows `//` up to `/`, `?` or `#` is the netloc.
    let after = cleaned
        .split_once("//")
        .map(|(_, rest)| rest)
        .unwrap_or_default();
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let netloc = &after[..end];
    let tail = &after[end..];
    if (netloc.contains('[') && !netloc.contains(']'))
        || (netloc.contains(']') && !netloc.contains('['))
    {
        return Err("Invalid IPv6 URL".into());
    }
    let hostinfo = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
    if netloc.contains('[') {
        check_bracketed(hostinfo)?;
    }
    let (fragment, before_fragment) = match tail.split_once('#') {
        Some((before, frag)) => (frag, before),
        None => ("", tail),
    };
    let (path, query) = match before_fragment.split_once('?') {
        Some((p, q)) => (p, q),
        None => (before_fragment, ""),
    };
    let (hostname, port_text) = host_and_port(hostinfo);
    if !path.is_empty() && path != "/" {
        return Err("path in endpoint is not allowed".into());
    }
    if !query.is_empty() {
        return Err("query in endpoint is not allowed".into());
    }
    if !fragment.is_empty() {
        return Err("fragment in endpoint is not allowed".into());
    }
    let port = match port_text {
        None => None,
        Some(p) => {
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid port".into());
            }
            match p.parse::<u32>() {
                Ok(n) if n <= 65535 => Some(u16::try_from(n).unwrap_or(0)),
                _ => return Err("invalid port".into()),
            }
        }
    };
    if let Some((userinfo, _)) = netloc.rsplit_once('@') {
        let (user, password) = match userinfo.split_once(':') {
            Some((u, p)) => (u, Some(p)),
            None => (userinfo, None),
        };
        if !user.is_empty() {
            return Err("username in endpoint is not allowed".into());
        }
        if password.is_some_and(|p| !p.is_empty()) {
            return Err("password in endpoint is not allowed".into());
        }
    }
    let host = lower_host(&hostname);
    let default_port = if secure { 443 } else { 80 };
    let netloc = if port == Some(default_port) {
        host.clone()
    } else {
        netloc.to_string()
    };
    let unsupported = aws_or_aliyun(&host).then(|| {
        format!(
            "{host} is an Amazon S3 or Aliyun OSS endpoint: virtual-hosted-style requests are not \
             supported by this build"
        )
    });
    Ok(Endpoint {
        https: secure,
        netloc,
        host,
        port: port.unwrap_or(default_port),
        unsupported,
    })
}

/// `SplitResult._hostinfo`: the host (brackets removed) and the port text
/// (`None` when absent or empty).
fn host_and_port(hostinfo: &str) -> (String, Option<&str>) {
    let (host, port) = if let Some((_, bracketed)) = hostinfo.split_once('[') {
        let (host, rest) = bracketed.split_once(']').unwrap_or((bracketed, ""));
        let port = rest.split_once(':').map_or("", |(_, p)| p);
        (host.to_string(), port)
    } else {
        match hostinfo.split_once(':') {
            Some((h, p)) => (h.to_string(), p),
            None => (hostinfo.to_string(), ""),
        }
    };
    (host, (!port.is_empty()).then_some(port))
}

/// `SplitResult.hostname`: lower-cased, but not an IPv6 zone id.
fn lower_host(host: &str) -> String {
    match host.split_once('%') {
        Some((h, zone)) => format!("{}%{zone}", h.to_lowercase()),
        None => host.to_lowercase(),
    }
}

/// `_check_bracketed_netloc` / `_check_bracketed_host` (CPython 3.11).
fn check_bracketed(hostinfo: &str) -> Result<(), String> {
    let Some((before, bracketed)) = hostinfo.split_once('[') else {
        return Ok(());
    };
    if !before.is_empty() {
        return Err("Invalid IPv6 URL".into());
    }
    let (host, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
    if !port.is_empty() && !port.starts_with(':') {
        return Err("Invalid IPv6 URL".into());
    }
    if let Some(rest) = host.strip_prefix('v') {
        let valid = rest.split_once('.').is_some_and(|(hex, tail)| {
            !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) && !tail.is_empty()
        });
        if !valid {
            return Err("IPvFuture address is invalid".into());
        }
        return Ok(());
    }
    let address = host.split_once('%').map_or(host, |(a, _)| a);
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => Err("An IPv4 address cannot be in brackets".into()),
        Ok(IpAddr::V6(_)) => Ok(()),
        Err(_) => Err(format!(
            "{} does not appear to be an IPv4 or IPv6 address",
            copilot_auth::pyvalue::str_repr(host)
        )),
    }
}

/// `_AWS_ENDPOINT_REGEX` (`.*\.amazonaws\.com(|\.cn)$`, any case) — which
/// also covers the ELB form — and the `aliyuncs.com` suffix.
fn aws_or_aliyun(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h.ends_with(".amazonaws.com") || h.ends_with(".amazonaws.com.cn") || h.ends_with("aliyuncs.com")
}

/// `urllib.parse.quote(s, safe)`: UTF-8, `A-Za-z0-9_.-~` and `safe` kept.
pub fn quote(s: &str, safe: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(b, b'_' | b'.' | b'-' | b'~')
            || (b.is_ascii() && safe.as_bytes().contains(&b));
        if keep {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `queryencode`: [`quote`] with nothing safe.
pub fn queryencode(s: &str) -> String {
    quote(s, "")
}

/// Query parameters as `_execute` takes them (`DictType`): each key with
/// one value or several.
pub type QueryParams = Vec<(String, Vec<String>)>;

/// `BaseURL.build` for a path-style endpoint: the path (`/bucket[/quoted
/// object]`) and the query (keys sorted, each key's values sorted, all
/// `queryencode`d).
pub fn build(bucket: Option<&str>, object: Option<&str>, query: &QueryParams) -> (String, String) {
    let mut keys: Vec<&(String, Vec<String>)> = query.iter().collect();
    keys.sort_by(|a, b| a.0.cmp(&b.0));
    let mut parts = Vec::new();
    for (key, values) in keys {
        let mut values: Vec<&String> = values.iter().collect();
        values.sort();
        for value in values {
            parts.push(format!("{}={}", queryencode(key), queryencode(value)));
        }
    }
    let mut path = "/".to_string();
    if let Some(bucket) = bucket.filter(|b| !b.is_empty()) {
        path = format!("/{bucket}");
        if let Some(object) = object.filter(|o| !o.is_empty()) {
            if !path.ends_with('/') {
                path.push('/');
            }
            path.push_str(&quote(object, "/"));
        }
    }
    (path, parts.join("&"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_parse_like_minio() {
        let e = parse("copilot-minio:9000", false).unwrap();
        assert_eq!(e.netloc, "copilot-minio:9000");
        assert_eq!(
            (e.host.as_str(), e.port, e.https),
            ("copilot-minio", 9000, false)
        );
        assert_eq!(parse("Host:80", false).unwrap().netloc, "host");
        assert_eq!(parse("Host:443", true).unwrap().netloc, "host");
        assert_eq!(parse("Host:443", false).unwrap().netloc, "Host:443");
        assert_eq!(parse("[::1]:9000", false).unwrap().host, "::1");
        assert_eq!(parse(":9000", false).unwrap().netloc, ":9000");
        assert_eq!(parse("h:080", false).unwrap().port, 80);
        for (input, error) in [
            ("http://x:9000", "path in endpoint is not allowed"),
            ("x:abc:9000", "invalid port"),
            ("x:9000:9000", "invalid port"),
            ("x:99999", "invalid port"),
            ("x/y:9000", "path in endpoint is not allowed"),
            ("u@x:9000", "username in endpoint is not allowed"),
            (":p@x:9000", "password in endpoint is not allowed"),
            ("x?q:9000", "query in endpoint is not allowed"),
            ("x#f:9000", "fragment in endpoint is not allowed"),
            (
                "[abc]:9000",
                "'abc' does not appear to be an IPv4 or IPv6 address",
            ),
            ("[127.0.0.1]:9000", "An IPv4 address cannot be in brackets"),
            ("x[::1]:9000", "Invalid IPv6 URL"),
            ("[::1:9000", "Invalid IPv6 URL"),
        ] {
            assert_eq!(parse(input, false).unwrap_err(), error, "{input}");
        }
        assert!(
            parse("bucket.s3.amazonaws.com:9000", false)
                .unwrap()
                .unsupported
                .is_some()
        );
        assert_eq!(parse("h\t:9000", false).unwrap().netloc, "h:9000");
    }

    #[test]
    fn urls_build_like_base_url() {
        let q = vec![
            ("prefix".to_string(), vec!["5/".to_string()]),
            ("list-type".to_string(), vec!["2".to_string()]),
            ("delimiter".to_string(), vec![String::new()]),
        ];
        assert_eq!(
            build(Some("copilot-cases"), None, &q),
            (
                "/copilot-cases".to_string(),
                "delimiter=&list-type=2&prefix=5%2F".to_string()
            )
        );
        assert_eq!(
            build(Some("b"), Some("1/a b+c~é.txt"), &Vec::new()).0,
            "/b/1/a%20b%2Bc~%C3%A9.txt"
        );
        assert_eq!(build(None, None, &Vec::new()).0, "/");
    }
}
