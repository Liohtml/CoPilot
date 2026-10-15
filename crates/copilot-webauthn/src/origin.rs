//! Relying-party configuration and origin checks — the helpers at the top
//! of `app/auth/services/passkey.py`, with Python's `urlparse` underneath.
//!
//! - `WEBAUTHN_ORIGINS` (else `WEBAUTHN_ORIGIN`): comma-separated, each
//!   stripped of whitespace and trailing `/`; passkeys are configured when at
//!   least one origin is set.
//! - The request's `Origin` header picks the allowed origin: an exact match;
//!   a loopback origin whose `localhost`/`127.0.0.1` twin is allowed; or,
//!   with a single allowed origin, that one whatever the header says.
//! - The RP ID is `localhost` for loopback origins, else `WEBAUTHN_RP_ID`,
//!   else the origin's host; browsers refuse passkeys on `127.0.0.1`, which
//!   is refused with a pointer to `localhost`.

use unicode_normalization::UnicodeNormalization;

use copilot_auth::pyvalue::str_repr;

/// The `WEBAUTHN_*` settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingParty {
    origins: Vec<String>,
    rp_id: String,
    rp_name: String,
}

fn py_strip(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

impl RelyingParty {
    /// From the raw environment values (`None` = unset).
    pub fn from_env(
        origins: Option<&str>,
        origin: Option<&str>,
        rp_id: Option<&str>,
        rp_name: Option<&str>,
    ) -> Self {
        let raw = origins.or(origin).unwrap_or("");
        let origins = raw
            .split(',')
            .filter(|o| !py_strip(o).is_empty())
            .map(|o| py_strip(o).trim_end_matches('/').to_string())
            .collect();
        Self {
            origins,
            rp_id: py_strip(rp_id.unwrap_or("")).to_string(),
            rp_name: py_strip(rp_name.unwrap_or("SOCFortress CoPilot")).to_string(),
        }
    }

    /// `_get_rp_name()`.
    pub fn rp_name(&self) -> &str {
        &self.rp_name
    }

    /// `is_passkey_configured()` (`_get_rp_id()` can raise on a malformed
    /// first origin).
    pub fn is_configured(&self) -> Result<bool, String> {
        if !self.rp_id.is_empty() {
            return Ok(!self.origins.is_empty());
        }
        if let Some(first) = self.origins.first() {
            urlsplit(first)?;
        }
        Ok(!self.origins.is_empty())
    }

    /// `resolve_request_origin(request_origin)`.
    pub fn resolve_request_origin(&self, request: Option<&str>) -> Result<String, String> {
        if self.origins.is_empty() {
            return Err(
                "WebAuthn is not configured. Set WEBAUTHN_ORIGINS and WEBAUTHN_RP_ID.".into(),
            );
        }
        if let Some(request) = request.filter(|r| !r.is_empty()) {
            let normalized = request.trim_end_matches('/');
            if self.origins.iter().any(|o| o == normalized) {
                return Ok(normalized.to_string());
            }
            let parsed = urlsplit(normalized)?;
            if matches!(
                parsed.hostname().as_deref(),
                Some("localhost" | "127.0.0.1")
            ) {
                let port_suffix = match parsed.port()? {
                    Some(p) if p != 0 => format!(":{p}"),
                    _ => String::new(),
                };
                let scheme = if parsed.scheme.is_empty() {
                    "http"
                } else {
                    &parsed.scheme
                };
                for host in ["localhost", "127.0.0.1"] {
                    let alias = format!("{scheme}://{host}{port_suffix}");
                    if self.origins.contains(&alias) {
                        return Ok(normalized.to_string());
                    }
                }
            }
        }
        if self.origins.len() == 1 {
            return Ok(self.origins[0].clone());
        }
        Err("Request origin is not allowed for WebAuthn.".into())
    }

    /// `_get_rp_id_for_origin(origin)`.
    pub fn rp_id_for_origin(&self, origin: &str) -> Result<String, String> {
        let hostname = urlsplit(origin)?
            .hostname()
            .unwrap_or_else(|| "localhost".into());
        if hostname == "localhost" || hostname == "127.0.0.1" {
            return Ok("localhost".into());
        }
        let explicit = &self.rp_id;
        if !explicit.is_empty()
            && (hostname == *explicit || hostname.ends_with(&format!(".{explicit}")))
        {
            return Ok(explicit.clone());
        }
        Ok(if explicit.is_empty() {
            hostname
        } else {
            explicit.clone()
        })
    }

    /// `_ensure_passkey_origin(origin)`.
    pub fn ensure_passkey_origin(&self, origin: &str) -> Result<(), String> {
        let parsed = urlsplit(origin)?;
        if parsed.hostname().as_deref() != Some("127.0.0.1") {
            return Ok(());
        }
        let port_suffix = match parsed.port()? {
            Some(p) if p != 0 => format!(":{p}"),
            _ => String::new(),
        };
        let scheme = if parsed.scheme.is_empty() {
            "http"
        } else {
            &parsed.scheme
        };
        Err(format!(
            "Passkeys do not work on 127.0.0.1. Open {scheme}://localhost{port_suffix} in your browser instead."
        ))
    }
}

/// The parts of `urllib.parse.urlsplit` these checks read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Split {
    /// Lower-cased scheme (empty when there is none).
    pub scheme: String,
    /// `netloc`.
    pub netloc: String,
}

impl Split {
    fn hostinfo(&self) -> (String, Option<String>) {
        let hostinfo = self
            .netloc
            .rsplit_once('@')
            .map_or(self.netloc.as_str(), |(_, h)| h);
        let (hostname, port) = match hostinfo.split_once('[') {
            Some((_, bracketed)) => {
                let (host, rest) = bracketed.split_once(']').unwrap_or((bracketed, ""));
                (host, rest.split_once(':').map_or("", |(_, p)| p))
            }
            None => hostinfo.split_once(':').unwrap_or((hostinfo, "")),
        };
        (
            hostname.to_string(),
            (!port.is_empty()).then(|| port.to_string()),
        )
    }

    /// `.hostname`: lower-cased (but not an IPv6 zone), `None` when empty.
    pub fn hostname(&self) -> Option<String> {
        let (hostname, _) = self.hostinfo();
        if hostname.is_empty() {
            return None;
        }
        Some(match hostname.split_once('%') {
            Some((host, zone)) => format!("{}%{zone}", host.to_lowercase()),
            None => hostname.to_lowercase(),
        })
    }

    /// `.port`, with Python's `ValueError` texts.
    pub fn port(&self) -> Result<Option<u32>, String> {
        let Some(port) = self.hostinfo().1 else {
            return Ok(None);
        };
        if !port.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!(
                "Port could not be cast to integer value as {}",
                str_repr(&port)
            ));
        }
        match port.parse::<u64>() {
            Ok(p) if p <= 65535 => Ok(Some(p as u32)),
            _ => Err("Port out of range 0-65535".into()),
        }
    }
}

fn check_bracketed_host(hostname: &str) -> Result<(), String> {
    if let Some(rest) = hostname.strip_prefix('v') {
        let valid = rest.split_once('.').is_some_and(|(hex, tail)| {
            !hex.is_empty()
                && hex.chars().all(|c| c.is_ascii_hexdigit())
                && !tail.is_empty()
                && !tail.contains('\n')
        });
        return if valid {
            Ok(())
        } else {
            Err("IPvFuture address is invalid".into())
        };
    }
    if hostname.parse::<std::net::Ipv4Addr>().is_ok() {
        return Err("An IPv4 address cannot be in brackets".into());
    }
    let address = match hostname.split_once('%') {
        Some((address, zone)) if !zone.is_empty() && !zone.contains('%') => Some(address),
        Some(_) => None,
        None => Some(hostname),
    };
    if address.is_some_and(|a| a.parse::<std::net::Ipv6Addr>().is_ok()) {
        return Ok(());
    }
    Err(format!(
        "{} does not appear to be an IPv4 or IPv6 address",
        str_repr(hostname)
    ))
}

fn check_netloc(netloc: &str) -> Result<(), String> {
    if netloc.is_ascii() {
        return Ok(());
    }
    let n: String = netloc
        .chars()
        .filter(|c| !matches!(c, '@' | ':' | '#' | '?'))
        .collect();
    let normalized: String = n.nfkc().collect();
    if n == normalized || !normalized.contains(['/', '?', '#', '@', ':']) {
        return Ok(());
    }
    Err(format!(
        "netloc '{netloc}' contains invalid characters under NFKC normalization"
    ))
}

/// `urllib.parse.urlsplit(url)` (CPython 3.11), as far as scheme and netloc.
pub fn urlsplit(url: &str) -> Result<Split, String> {
    let url: String = url
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut scheme = String::new();
    let mut rest = url.as_str();
    if let Some(i) = url.find(':') {
        let candidate = &url[..i];
        if i > 0
            && candidate.as_bytes()[0].is_ascii_alphabetic()
            && candidate
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            scheme = candidate.to_ascii_lowercase();
            rest = &url[i + 1..];
        }
    }
    let mut netloc = String::new();
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        netloc = after[..end].to_string();
        let (open, close) = (netloc.contains('['), netloc.contains(']'));
        if open != close {
            return Err("Invalid IPv6 URL".into());
        }
        if open {
            let host_port = netloc.rsplit_once('@').map_or(netloc.as_str(), |(_, h)| h);
            let hostname = match host_port.split_once('[') {
                Some((before, bracketed)) => {
                    if !before.is_empty() {
                        return Err("Invalid IPv6 URL".into());
                    }
                    let (host, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
                    if !port.is_empty() && !port.starts_with(':') {
                        return Err("Invalid IPv6 URL".into());
                    }
                    host
                }
                None => host_port.split_once(':').map_or(host_port, |(h, _)| h),
            };
            check_bracketed_host(hostname)?;
        }
    }
    check_netloc(&netloc)?;
    Ok(Split { scheme, netloc })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_urlsplit_parts() {
        let s = urlsplit("https://User@Example.COM:8443/x").unwrap();
        assert_eq!(s.scheme, "https");
        assert_eq!(s.hostname().as_deref(), Some("example.com"));
        assert_eq!(s.port().unwrap(), Some(8443));
        assert_eq!(
            urlsplit("http://localhost:abc")
                .unwrap()
                .port()
                .unwrap_err(),
            "Port could not be cast to integer value as 'abc'"
        );
        assert_eq!(urlsplit("http://[::1").unwrap_err(), "Invalid IPv6 URL");
        assert_eq!(
            urlsplit("http://[1.2.3.4]").unwrap_err(),
            "An IPv4 address cannot be in brackets"
        );
        assert_eq!(
            urlsplit("http://[foo]").unwrap_err(),
            "'foo' does not appear to be an IPv4 or IPv6 address"
        );
        assert_eq!(urlsplit("null").unwrap().hostname(), None);
    }
}
