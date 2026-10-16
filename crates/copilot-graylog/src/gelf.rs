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

use std::sync::OnceLock;

use copilot_auth::pyvalue::PyValue;
use copilot_db::connectors::ConnectorCache;
use copilot_upstream::json::{Dumps, py_dumps};
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
pub fn frame(message: &PyValue, host: &str) -> PyResult<Vec<u8>> {
    let short = py_dumps(message, Dumps::DEFAULT).map_err(|e| PyExc::ValueError(e.to_string()))?;
    let gelf = PyValue::Dict(vec![
        ("version".into(), PyValue::Float(1.1)),
        ("host".into(), PyValue::Str(host.to_string())),
        ("short_message".into(), PyValue::Str(short)),
        ("level".into(), PyValue::Int("1".into())),
    ]);
    let mut bytes = py_dumps(&gelf, Dumps::DEFAULT)
        .map_err(|e| PyExc::ValueError(e.to_string()))?
        .into_bytes();
    bytes.push(0);
    Ok(bytes)
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
    let Ok(port) = port.parse::<u16>() else {
        tracing::warn!(port, "event shipper port is not a number; nothing sent");
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
