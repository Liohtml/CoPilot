//! The Event Shipper — port of `app/connectors/event_shipper/utils/universal.py`
//! and `app/integrations/utils/event_shipper.py` over `asyncgelf.GelfTcp`.
//!
//! A message is one GELF frame on a fresh TCP connection to the `Event
//! Shipper` connector (`connector_url` is the host, `connector_extra_data`
//! the port), NUL-terminated:
//!
//! ```text
//! {"version": 1.1, "host": "<getfqdn()>", "short_message": "<json.dumps(message)>", "level": 1}\0
//! ```
//!
//! As in asyncgelf, a connection that cannot be made is *not* an error (the
//! library returns the exception's `repr()` instead of raising), so the
//! caller is told the message was forwarded either way; only a missing
//! connector row fails.
//!
//! The port is `str(connector_extra_data)`, which `asyncio.open_connection`
//! reads two ways ([`resolve_port`]): for an IP-literal host with Python's
//! `int()` (`_ipaddr_info`; outside 0–65535 the connect raises and nothing is
//! sent), for a host name through `getaddrinfo` — glibc's `strtoul` (leading
//! blanks and a sign accepted, the value cut to 16 bits by `htons`), else a
//! service name from `/etc/services`.

use std::sync::OnceLock;

use copilot_auth::pyvalue::PyValue;
use copilot_db::connectors::ConnectorCache;
use copilot_upstream::json::{Dumps, py_dumps_allow_nan};
use copilot_upstream::py::{PyExc, PyResult};
use tokio::io::AsyncWriteExt;

/// The connector row's name.
pub const CONNECTOR_NAME: &str = "Event Shipper";

/// `socket.getfqdn()`: the host name, resolved through `/etc/hosts` and back
/// (`gethostbyaddr`), the first of the canonical name and its aliases that
/// contains a dot, else the canonical name; the bare host name when it is
/// not in `/etc/hosts` (where Python would also ask DNS).
pub fn getfqdn() -> String {
    static FQDN: OnceLock<String> = OnceLock::new();
    FQDN.get_or_init(|| {
        let name = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .or_else(|_| std::fs::read_to_string("/etc/hostname"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
        fqdn_from_hosts(&name, &hosts)
    })
    .clone()
}

/// [`getfqdn`] over a given `/etc/hosts`.
pub fn fqdn_from_hosts(name: &str, hosts: &str) -> String {
    let lines: Vec<Vec<&str>> = hosts
        .lines()
        .map(|l| l.split('#').next().unwrap_or_default())
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        .filter(|f| f.len() >= 2)
        .collect();
    let Some(addr) = lines
        .iter()
        .find(|f| f[1..].iter().any(|n| n.eq_ignore_ascii_case(name)))
        .map(|f| f[0])
    else {
        return name.to_string();
    };
    let Some(entry) = lines.iter().find(|f| f[0] == addr) else {
        return name.to_string();
    };
    let canonical = entry[1];
    entry[1..]
        .iter()
        .find(|n| n.contains('.'))
        .unwrap_or(&canonical)
        .to_string()
}

/// The GELF frame for `message` (`GelfBase.make` + `json.dumps` + NUL).
/// asyncgelf calls `json.dumps` with its defaults, so a `NaN` or an infinity
/// in the message is written as `NaN` / `Infinity`, not refused.
pub fn frame(message: &PyValue, host: &str) -> PyResult<Vec<u8>> {
    let short = py_dumps_allow_nan(message, Dumps::DEFAULT);
    let gelf = PyValue::Dict(vec![
        ("version".into(), PyValue::Float(1.1)),
        ("host".into(), PyValue::Str(host.to_string())),
        ("short_message".into(), PyValue::Str(short)),
        ("level".into(), PyValue::Int("1".into())),
    ]);
    let mut bytes = py_dumps_allow_nan(&gelf, Dumps::DEFAULT).into_bytes();
    bytes.push(0);
    Ok(bytes)
}

/// The port `asyncio.open_connection(host, port)` connects to for the port
/// text `port`, or `None` when it raises (nothing is sent).
pub fn resolve_port(host: &str, port: &str) -> Option<u16> {
    let services = std::fs::read_to_string("/etc/services").unwrap_or_default();
    resolve_port_with(host, port, &services)
}

/// [`resolve_port`] over a given `/etc/services`.
pub fn resolve_port_with(host: &str, port: &str, services: &str) -> Option<u16> {
    let literal = !host.contains('%')
        && (host.parse::<std::net::Ipv4Addr>().is_ok()
            || host.parse::<std::net::Ipv6Addr>().is_ok());
    if port.is_empty() {
        // `_ipaddr_info`'s `''` → 0, and glibc's empty service: port 0.
        return Some(0);
    }
    if literal {
        // `int(port)`, then `connect()`'s 0–65535 check (`OverflowError`).
        return python_int(port).and_then(|n| u16::try_from(n).ok());
    }
    match strtoul_port(port) {
        Some(Ok(n)) => Some(n),
        Some(Err(())) => None,
        None => service_port(port, services),
    }
}

/// glibc's numeric service: `Some(Ok(htons(num)))`, `Some(Err)` for a number
/// that turns negative as an `int` (looked up by name, never found), `None`
/// when the text is not a number.
fn strtoul_port(text: &str) -> Option<Result<u16, ()>> {
    let rest = text.trim_start_matches([' ', '\t', '\n', '\u{b}', '\u{c}', '\r']);
    let (negative, digits) = match rest.as_bytes().first() {
        Some(b'-') => (true, &rest[1..]),
        Some(b'+') => (false, &rest[1..]),
        _ => (false, rest),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let magnitude = digits.parse::<u64>().unwrap_or(u64::MAX);
    let value = if negative && magnitude != u64::MAX {
        magnitude.wrapping_neg()
    } else {
        magnitude
    };
    // `gaih_service.num` is an `int`.
    let num = value as u32 as i32;
    if num < 0 {
        return Some(Err(()));
    }
    Some(Ok((num as u32 & 0xffff) as u16))
}

/// `getservbyname(name, "tcp")` over an `/etc/services` text.
fn service_port(name: &str, services: &str) -> Option<u16> {
    for line in services.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let mut fields = line.split_whitespace();
        let (Some(official), Some(spec)) = (fields.next(), fields.next()) else {
            continue;
        };
        let Some((number, proto)) = spec.split_once('/') else {
            continue;
        };
        if proto != "tcp" {
            continue;
        }
        if official == name || fields.any(|alias| alias == name) {
            return number.parse::<u16>().ok();
        }
    }
    None
}

/// Python's `int(text)` (base 10): surrounding whitespace, a sign, single
/// underscores between digits.
fn python_int(text: &str) -> Option<i64> {
    copilot_core::config::python_int(text)
}

/// `event_shipper(message)`: `message` is `EventShipperPayload.to_dict()`.
pub async fn ship(connectors: &ConnectorCache, message: &PyValue) -> PyResult<()> {
    let row = connectors
        .get(CONNECTOR_NAME)
        .await
        .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?
        .ok_or_else(|| {
            PyExc::http(
                500,
                "Failed to initialize GelfLogger: 'NoneType' object is not subscriptable",
            )
        })?;
    let host = row.connector_url.clone();
    let port = row
        .connector_extra_data
        .clone()
        .unwrap_or_else(|| "None".into());
    let bytes = frame(message, &getfqdn())?;
    let Some(port) = resolve_port(&host, &port) else {
        tracing::warn!(port, "event shipper port cannot be resolved; nothing sent");
        return Ok(());
    };
    match tokio::net::TcpStream::connect((host.as_str(), port)).await {
        Ok(mut stream) => {
            if let Err(e) = stream.write_all(&bytes).await {
                tracing::warn!(err = %e, "event shipper write failed");
            }
            let _ = stream.shutdown().await;
        }
        Err(e) => {
            // asyncgelf returns `repr(e)` here rather than raising.
            tracing::warn!(err = %e, host, port, "event shipper connection failed");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn fqdn_resolution_follows_gethostbyaddr() {
        let hosts = "127.0.0.1 localhost\n127.0.0.1 runsc\n127.0.0.1 vm\n";
        assert_eq!(fqdn_from_hosts("vm", hosts), "localhost");
        let hosts = "172.18.0.5 abc123 abc123.copilot.local # docker\n";
        assert_eq!(fqdn_from_hosts("abc123", hosts), "abc123.copilot.local");
        assert_eq!(fqdn_from_hosts("other", hosts), "other");
    }

    #[test]
    fn ports_are_read_as_asyncio_reads_them() {
        let services = "http\t\t80/tcp\t\twww # WorldWideWeb\nsyslog 514/udp\n";
        for (host, port, want) in [
            ("127.0.0.1", "12201", Some(12201)),
            ("127.0.0.1", " 12201 ", Some(12201)),
            ("127.0.0.1", "+1_2201", Some(12201)),
            ("127.0.0.1", "77737", None),
            ("127.0.0.1", "-1", None),
            ("127.0.0.1", "http", None),
            ("::1", "12201", Some(12201)),
            ("127.0.0.1", "", Some(0)),
            ("graylog", "12201", Some(12201)),
            ("graylog", " +12201", Some(12201)),
            ("graylog", "12201 ", None),
            ("graylog", "77737", Some(12201)),
            ("graylog", "-1", None),
            ("graylog", "-4294967296", Some(0)),
            ("graylog", "99999999999999999999999", None),
            ("graylog", "http", Some(80)),
            ("graylog", "www", Some(80)),
            ("graylog", "syslog", None),
            ("graylog", "None", None),
            ("fe80::1%eth0", "12201", Some(12201)),
        ] {
            assert_eq!(
                resolve_port_with(host, port, services),
                want,
                "{host} {port:?}"
            );
        }
    }

    #[test]
    fn frame_writes_non_finite_floats_as_json_dumps_does() {
        let message = loads(r#"{"a": NaN, "b": Infinity, "c": -Infinity}"#).unwrap();
        let bytes = frame(&message, "h").unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\"version\": 1.1, \"host\": \"h\", \"short_message\": \"{\\\"a\\\": NaN, \\\"b\\\": \
             Infinity, \\\"c\\\": -Infinity}\", \"level\": 1}\0"
        );
    }

    #[test]
    fn frame_is_asyncgelf_s() {
        let message = loads(r#"{"integration": "x", "customer_code": "c", "u": "é"}"#).unwrap();
        let bytes = frame(&message, "localhost").unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\"version\": 1.1, \"host\": \"localhost\", \"short_message\": \"{\\\"integration\\\": \
             \\\"x\\\", \\\"customer_code\\\": \\\"c\\\", \\\"u\\\": \\\"\\\\u00e9\\\"}\", \"level\": 1}\0"
        );
    }
}
