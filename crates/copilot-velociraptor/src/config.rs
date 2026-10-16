//! The API client config — `pyvelociraptor.LoadConfigFile` and what
//! `UniversalService.setup_grpc_channel_and_stub` reads from it.
//!
//! The `Velociraptor` connector row's `connector_api_key` is not a key but
//! the **path** of an `api.config.yaml` (written by `velociraptor config
//! api_client`) on the host running the backend. The file holds the CA
//! certificate, the API user's certificate and key, and the server's
//! `host:port`. It is read again for every service instance, as in Python,
//! so a rotated file takes effect on the next call.
//!
//! Failures read as Python's: the file errors wrapped in pyvelociraptor's
//! `TypeError("Unable to parse config file from …: …")`, then the subscript
//! and `.encode()` errors of the fields, in the order Python touches them.

use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_upstream::py::{PyExc, PyResult, type_name};

/// What the gRPC channel is built from.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiConfig {
    /// `ca_certificate` (PEM): the only root the server is checked against.
    pub ca_certificate: String,
    /// `client_cert` (PEM): the API user's certificate.
    pub client_cert: String,
    /// `client_private_key` (PEM).
    pub client_private_key: String,
    /// `api_connection_string`: the gRPC target (`host:port`).
    pub api_connection_string: String,
}

impl std::fmt::Debug for ApiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiConfig")
            .field("api_connection_string", &self.api_connection_string)
            .finish_non_exhaustive()
    }
}

/// `open(path).read()`'s failure as `str(OSError)`.
pub fn open_error(path: &str, e: &std::io::Error) -> String {
    let (errno, text) = match e.kind() {
        std::io::ErrorKind::NotFound => (2, "No such file or directory"),
        std::io::ErrorKind::PermissionDenied => (13, "Permission denied"),
        std::io::ErrorKind::IsADirectory => (21, "Is a directory"),
        _ => match e.raw_os_error() {
            Some(n) => return format!("[Errno {n}] {}: {}", strerror(e), str_repr(path)),
            None => return e.to_string(),
        },
    };
    format!("[Errno {errno}] {text}: {}", str_repr(path))
}

/// The OS message without Rust's ` (os error N)` suffix.
pub fn strerror(e: &std::io::Error) -> String {
    let s = e.to_string();
    match s.rfind(" (os error ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

/// `open(path).read()` in text mode: UTF-8 (the image's locale) with
/// universal newlines; `Err` is `str()` of the exception.
pub fn read_text(path: &str) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| open_error(path, &e))?;
    let text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(e) => return Err(unicode_decode_error(e.as_bytes(), e.utf8_error())),
    };
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}

/// CPython's `UnicodeDecodeError` text for bytes that are not UTF-8.
fn unicode_decode_error(bytes: &[u8], e: std::str::Utf8Error) -> String {
    let pos = e.valid_up_to();
    let first = bytes.get(pos).copied().unwrap_or(0);
    let reason = match e.error_len() {
        None => "unexpected end of data",
        Some(_) if (0xc2..=0xf4).contains(&first) => "invalid continuation byte",
        Some(_) => "invalid start byte",
    };
    if e.error_len().is_none() && bytes.len() - pos > 1 {
        return format!(
            "'utf-8' codec can't decode bytes in position {pos}-{}: {reason}",
            bytes.len() - 1
        );
    }
    format!("'utf-8' codec can't decode byte 0x{first:02x} in position {pos}: {reason}")
}

/// `yaml.safe_load(text)` as a Python value.
pub fn safe_load(text: &str) -> Result<PyValue, String> {
    let value: yaml_serde::Value = yaml_serde::from_str(text).map_err(|e| e.to_string())?;
    Ok(from_yaml(&value))
}

fn from_yaml(v: &yaml_serde::Value) -> PyValue {
    use yaml_serde::Value;
    match v {
        Value::Null => PyValue::None,
        Value::Bool(b) => PyValue::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                PyValue::Int(i.to_string())
            } else if let Some(u) = n.as_u64() {
                PyValue::Int(u.to_string())
            } else {
                PyValue::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Value::String(s) => PyValue::Str(s.clone()),
        Value::Sequence(items) => PyValue::List(items.iter().map(from_yaml).collect()),
        Value::Mapping(map) => PyValue::Dict(
            map.iter()
                .map(|(k, v)| (from_yaml(k).py_str(), from_yaml(v)))
                .collect(),
        ),
        Value::Tagged(t) => from_yaml(&t.value),
    }
}

/// `LoadConfigFile(config_file)`: the parsed YAML, after the
/// `"ENCRYPTED" in config["client_private_key"]` check.
///
/// `None` falls back to `$VELOCIRAPTOR_API_FILE`, then
/// `$HOME/.pyvelociraptorrc`, as pyvelociraptor does. An encrypted key
/// would make Python prompt for a password on the server's terminal; here it
/// is refused.
pub fn load_config_file(config_file: Option<&str>) -> PyResult<PyValue> {
    let path = match config_file {
        Some(p) => p.to_string(),
        None => match std::env::var("VELOCIRAPTOR_API_FILE") {
            Ok(p) => p,
            Err(_) => match std::env::var("HOME") {
                Ok(home) => join(&home, ".pyvelociraptorrc"),
                Err(_) => {
                    return Err(PyExc::TypeError(
                        "expected str, bytes or os.PathLike object, not NoneType".into(),
                    ));
                }
            },
        },
    };
    let config = read_text(&path)
        .and_then(|t| safe_load(&t))
        .map_err(|e| PyExc::TypeError(format!("Unable to parse config file from {path}: {e}")))?;
    let key = subscript(&config, "client_private_key")?;
    if contains(key, "ENCRYPTED")? {
        return Err(PyExc::Other(
            "EOFError",
            "the client_private_key of the API config is encrypted".into(),
        ));
    }
    Ok(config)
}

/// `os.path.join(a, b)`.
fn join(a: &str, b: &str) -> String {
    if a.is_empty() || a.ends_with('/') {
        format!("{a}{b}")
    } else {
        format!("{a}/{b}")
    }
}

/// `config[key]` for a `yaml.safe_load` result.
pub fn subscript<'a>(v: &'a PyValue, key: &str) -> PyResult<&'a PyValue> {
    match v {
        PyValue::Dict(items) => items
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .ok_or_else(|| PyExc::key_error(key)),
        PyValue::Str(_) => Err(PyExc::TypeError(
            "string indices must be integers, not 'str'".into(),
        )),
        PyValue::List(_) => Err(PyExc::TypeError(
            "list indices must be integers or slices, not str".into(),
        )),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not subscriptable",
            type_name(other)
        ))),
    }
}

/// `needle in v`.
fn contains(v: &PyValue, needle: &str) -> PyResult<bool> {
    match v {
        PyValue::Str(s) => Ok(s.contains(needle)),
        PyValue::List(items) => Ok(items.iter().any(|i| i.as_str() == Some(needle))),
        PyValue::Dict(items) => Ok(items.iter().any(|(k, _)| k == needle)),
        other => Err(PyExc::TypeError(format!(
            "argument of type '{}' is not iterable",
            type_name(other)
        ))),
    }
}

/// `v.encode("utf8")`.
fn encoded(v: &PyValue) -> PyResult<String> {
    match v {
        PyValue::Str(s) => Ok(s.clone()),
        other => Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'encode'",
            type_name(other)
        ))),
    }
}

impl ApiConfig {
    /// What `setup_grpc_channel_and_stub` reads, in its order: the three
    /// PEMs (`.encode("utf8")`), then the target.
    pub fn from_loaded(config: &PyValue) -> PyResult<Self> {
        let ca_certificate = encoded(subscript(config, "ca_certificate")?)?;
        let client_private_key = encoded(subscript(config, "client_private_key")?)?;
        let client_cert = encoded(subscript(config, "client_cert")?)?;
        let api_connection_string = match subscript(config, "api_connection_string")? {
            PyValue::Str(s) => s.clone(),
            other => {
                return Err(PyExc::TypeError(format!(
                    "expected bytes, {} found",
                    type_name(other)
                )));
            }
        };
        Ok(Self {
            ca_certificate,
            client_cert,
            client_private_key,
            api_connection_string,
        })
    }

    /// `LoadConfigFile(path)` then [`ApiConfig::from_loaded`].
    pub fn load(path: Option<&str>) -> PyResult<Self> {
        Self::from_loaded(&load_config_file(path)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &tempfile::TempDir, name: &str, body: &[u8]) -> String {
        let p = dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn a_config_file_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            &dir,
            "api.config.yaml",
            b"ca_certificate: |\r\n  -----BEGIN CERTIFICATE-----\r\n  AAA\r\n  -----END CERTIFICATE-----\r\n\
              client_cert: |\n  CERT\nclient_private_key: |\n  KEY\napi_connection_string: 127.0.0.1:8001\nname: api\n",
        );
        let cfg = ApiConfig::load(Some(&path)).unwrap();
        assert_eq!(cfg.api_connection_string, "127.0.0.1:8001");
        assert_eq!(
            cfg.ca_certificate,
            "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
        );
        assert_eq!(cfg.client_private_key, "KEY\n");
    }

    #[test]
    fn failures_read_as_python() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.yaml").to_string_lossy().into_owned();
        assert_eq!(
            ApiConfig::load(Some(&missing)).unwrap_err().text(),
            format!(
                "Unable to parse config file from {missing}: [Errno 2] No such file or directory: '{missing}'"
            )
        );
        let d = dir.path().to_string_lossy().into_owned();
        assert_eq!(
            ApiConfig::load(Some(&d)).unwrap_err().text(),
            format!("Unable to parse config file from {d}: [Errno 21] Is a directory: '{d}'")
        );
        let empty = write(&dir, "empty.yaml", b"");
        assert_eq!(
            ApiConfig::load(Some(&empty)).unwrap_err(),
            PyExc::TypeError("'NoneType' object is not subscriptable".into())
        );
        let scalar = write(&dir, "scalar.yaml", b"just text\n");
        assert_eq!(
            ApiConfig::load(Some(&scalar)).unwrap_err().text(),
            "string indices must be integers, not 'str'"
        );
        let nokey = write(&dir, "nokey.yaml", b"ca_certificate: x\n");
        assert_eq!(
            ApiConfig::load(Some(&nokey)).unwrap_err(),
            PyExc::KeyError("'client_private_key'".into())
        );
        let noca = write(&dir, "noca.yaml", b"client_private_key: k\n");
        assert_eq!(
            ApiConfig::load(Some(&noca)).unwrap_err(),
            PyExc::KeyError("'ca_certificate'".into())
        );
        let intca = write(
            &dir,
            "intca.yaml",
            b"client_private_key: k\nca_certificate: 5\n",
        );
        assert_eq!(
            ApiConfig::load(Some(&intca)).unwrap_err().text(),
            "'int' object has no attribute 'encode'"
        );
        let intkey = write(&dir, "intkey.yaml", b"client_private_key: 5\n");
        assert_eq!(
            ApiConfig::load(Some(&intkey)).unwrap_err().text(),
            "argument of type 'int' is not iterable"
        );
        let latin = write(&dir, "latin.yaml", b"name: caf\xe9\n");
        assert_eq!(
            ApiConfig::load(Some(&latin)).unwrap_err().text(),
            format!(
                "Unable to parse config file from {latin}: 'utf-8' codec can't decode byte 0xe9 in position 9: invalid continuation byte"
            )
        );
        let bad = write(&dir, "bad.yaml", b"name: \xff\n");
        assert!(
            ApiConfig::load(Some(&bad))
                .unwrap_err()
                .text()
                .ends_with("can't decode byte 0xff in position 6: invalid start byte")
        );
        // Recorded with CPython 3.11's `bytes.decode("utf-8")`.
        for (bytes, want) in [
            (
                &b"ab\xe2\x82"[..],
                "'utf-8' codec can't decode bytes in position 2-3: unexpected end of data",
            ),
            (
                b"ab\xe2",
                "'utf-8' codec can't decode byte 0xe2 in position 2: unexpected end of data",
            ),
            (
                b"\xc0\x80",
                "'utf-8' codec can't decode byte 0xc0 in position 0: invalid start byte",
            ),
            (
                b"\xed\xa0\x80",
                "'utf-8' codec can't decode byte 0xed in position 0: invalid continuation byte",
            ),
        ] {
            let e = std::str::from_utf8(bytes).unwrap_err();
            assert_eq!(unicode_decode_error(bytes, e), want);
        }
    }
}
