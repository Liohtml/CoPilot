//! The files the Mimecast SIEM collection keeps, where Python keeps them:
//! next to `app/integrations/mimecast/services/mimecast.py`, in its module
//! directory (`COPILOT_MIMECAST_DIR`, [`DEFAULT_DIR`] in the backend's
//! image).
//!
//! - `checkpoint/mimecast_<code>.checkpoint` — the SIEM page token
//!   (`get_checkpoint_filename`: the directory and an empty file created
//!   when missing; read and written as text, UTF-8);
//! - `logs/<code>/` — a download, extracted (`get_log_file_path`), each
//!   file's lines shipped and the file deleted (`process_log_file`), then
//!   the directory removed (`delete_log_directory`).
//!
//! Text is read as Python's text mode reads it: UTF-8 (a bad byte is the
//! `UnicodeDecodeError`, a `ValueError`) with universal newlines.

use std::path::{Path, PathBuf};

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::py::PyExc;
use copilot_web::form::py_strip;

use crate::error::{Fail, FailResult};

/// Python's module directory in the backend's image.
pub const DEFAULT_DIR: &str = "/opt/copilot/backend/app/integrations/mimecast";

/// `OSError` as Python words it (`[Errno 13] Permission denied: '…'`).
pub fn os_error(e: &std::io::Error, path: &Path) -> Fail {
    let code = e.raw_os_error().unwrap_or(0);
    let text = e.to_string();
    let reason = text.split(" (os error").next().unwrap_or(&text).to_string();
    Fail::other(
        "OSError",
        format!(
            "[Errno {code}] {reason}: {}",
            copilot_auth::pyvalue::str_repr(&path.display().to_string())
        ),
    )
}

/// The `strerror` of an `OSError` (`delete_log_directory`'s message).
pub fn strerror(e: &std::io::Error) -> String {
    let text = e.to_string();
    text.split(" (os error").next().unwrap_or(&text).to_string()
}

/// One customer's files.
#[derive(Debug, Clone)]
pub struct CustomerFiles {
    /// `checkpoint/mimecast_<code>.checkpoint`.
    pub checkpoint: PathBuf,
    /// `logs/<code>`.
    pub log_dir: PathBuf,
}

/// The customer's paths under `root`. A code that would leave the module
/// directory (empty, `.`, `..`, or holding `/` or a NUL) is refused before
/// anything is created: Python joins it as it comes, so its `logs/..`
/// would be the module directory itself, which `delete_log_directory`
/// then removes (RUST_MIGRATION.md §4, not provoked).
pub fn customer_files(root: &Path, code: &str) -> FailResult<CustomerFiles> {
    if code.is_empty() || code == "." || code == ".." || code.contains(['/', '\0']) {
        return Err(Fail::Py(PyExc::http(
            400,
            format!("Invalid customer code for the Mimecast files: {code}"),
        )));
    }
    Ok(CustomerFiles {
        checkpoint: root
            .join("checkpoint")
            .join(format!("mimecast_{code}.checkpoint")),
        log_dir: root.join("logs").join(code),
    })
}

impl CustomerFiles {
    /// `get_checkpoint_filename` then `get_log_file_path`: the two
    /// directories and the empty checkpoint, each created when missing.
    pub fn prepare(&self) -> FailResult<()> {
        if let Some(dir) = self.checkpoint.parent() {
            if !dir.exists() {
                std::fs::create_dir_all(dir).map_err(|e| os_error(&e, dir))?;
            }
        }
        if !self.checkpoint.exists() {
            std::fs::write(&self.checkpoint, b"").map_err(|e| os_error(&e, &self.checkpoint))?;
        }
        if !self.log_dir.exists() {
            std::fs::create_dir_all(&self.log_dir).map_err(|e| os_error(&e, &self.log_dir))?;
        }
        Ok(())
    }
}

/// `UnicodeDecodeError`'s text for `bytes` failing at `err` (positions
/// relative to `bytes`).
pub fn utf8_error_text(bytes: &[u8], err: &std::str::Utf8Error) -> String {
    let at = err.valid_up_to();
    let first = bytes.get(at).copied().unwrap_or_default();
    match err.error_len() {
        None => {
            let end = bytes.len() - 1;
            if end == at {
                format!(
                    "'utf-8' codec can't decode byte 0x{first:02x} in position {at}: unexpected \
                     end of data"
                )
            } else {
                format!(
                    "'utf-8' codec can't decode bytes in position {at}-{end}: unexpected end of \
                     data"
                )
            }
        }
        Some(_) => {
            let reason = if matches!(first, 0x80..=0xC1 | 0xF5..=0xFF) {
                "invalid start byte"
            } else {
                "invalid continuation byte"
            };
            format!("'utf-8' codec can't decode byte 0x{first:02x} in position {at}: {reason}")
        }
    }
}

/// Universal newlines: `\r\n` and `\r` read as `\n`.
pub fn translate_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// `open(path, "r").read()`.
pub fn read_text(path: &Path) -> FailResult<String> {
    let bytes = std::fs::read(path).map_err(|e| os_error(&e, path))?;
    match std::str::from_utf8(&bytes) {
        Ok(text) => Ok(translate_newlines(text)),
        Err(e) => Err(Fail::Py(PyExc::ValueError(utf8_error_text(&bytes, &e)))),
    }
}

/// `open(path, "w").write(text)`.
pub fn write_text(path: &Path, text: &str) -> FailResult<()> {
    std::fs::write(path, text.as_bytes()).map_err(|e| os_error(&e, path))
}

/// `for line in open(path, "r", encoding="utf-8")`: the lines (each with its
/// `\n`), and the `UnicodeDecodeError` that stops the loop. Python decodes
/// the file 8192 bytes at a time, so the lines before the chunk holding a
/// bad byte are read (and shipped) before it fails; the error's position is
/// counted from that chunk.
pub fn read_lines(path: &Path) -> FailResult<(Vec<String>, Option<Fail>)> {
    const CHUNK: usize = 8192;
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return Err(os_error(&e, path)),
    };
    let (text, failure) = match std::str::from_utf8(&bytes) {
        Ok(text) => (translate_newlines(text), None),
        Err(e) => {
            let chunk_start = e.valid_up_to() / CHUNK * CHUNK;
            let chunk = &bytes[chunk_start..];
            let text = String::from_utf8_lossy(&bytes[..chunk_start]).into_owned();
            let message = match std::str::from_utf8(chunk) {
                Err(inner) => utf8_error_text(chunk, &inner),
                Ok(_) => utf8_error_text(&bytes, &e),
            };
            // Only whole lines before the failing chunk are read.
            let text = translate_newlines(&text);
            let complete = text.rfind('\n').map_or(0, |i| i + 1);
            (
                text[..complete].to_string(),
                Some(Fail::Py(PyExc::ValueError(message))),
            )
        }
    };
    let mut lines: Vec<String> = text.split_inclusive('\n').map(str::to_string).collect();
    if failure.is_some() {
        lines.retain(|l| l.ends_with('\n'));
    }
    Ok((lines, failure))
}

/// `convert_to_json(line)`: `k=v` pairs split on `|`, each side
/// `str.strip()`ped; a later pair of the same key replaces the value in
/// the first one's place.
pub fn convert_to_json(line: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for pair in line.split('|') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let (key, value) = (py_strip(key).to_string(), py_strip(value).to_string());
        match out.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = value,
            None => out.push((key, value)),
        }
    }
    out
}

/// `EventShipperPayload(customer_code=…, integration="mimecast",
/// version="1.0", **fields).to_dict()`: the two declared fields, then the
/// extras in the order given; a field naming one of the three keywords is
/// the call's `TypeError`.
pub fn event_payload(code: &str, fields: Vec<(String, PyValue)>) -> FailResult<PyValue> {
    let mut out = vec![
        ("integration".to_string(), PyValue::Str("mimecast".into())),
        ("customer_code".to_string(), PyValue::Str(code.into())),
        ("version".to_string(), PyValue::Str("1.0".into())),
    ];
    for (key, value) in fields {
        if matches!(key.as_str(), "customer_code" | "integration" | "version") {
            return Err(Fail::other(
                "TypeError",
                format!(
                    "app.integrations.utils.schema.EventShipperPayload() got multiple values for \
                     keyword argument '{key}'"
                ),
            ));
        }
        out.push((key, value));
    }
    Ok(PyValue::Dict(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_split_as_python_reads_them() {
        assert_eq!(
            convert_to_json(" a = 1 | b=2=3|junk| a=4\n"),
            vec![("a".into(), "4".into()), ("b".into(), "2=3".into())]
        );
        assert_eq!(convert_to_json("\n"), Vec::<(String, String)>::new());
        assert_eq!(translate_newlines("a\r\nb\rc\n"), "a\nb\nc\n");
    }

    #[test]
    fn decode_errors_read_as_cpython_s() {
        let check = |b: &[u8], want: &str| {
            let e = std::str::from_utf8(b).expect_err("bad");
            assert_eq!(utf8_error_text(b, &e), want);
        };
        check(
            b"ab\xff",
            "'utf-8' codec can't decode byte 0xff in position 2: invalid start byte",
        );
        check(
            b"\xe2\x28\xa1",
            "'utf-8' codec can't decode byte 0xe2 in position 0: invalid continuation byte",
        );
        check(
            b"x\xe2\x82",
            "'utf-8' codec can't decode bytes in position 1-2: unexpected end of data",
        );
        check(
            b"x\xe2",
            "'utf-8' codec can't decode byte 0xe2 in position 1: unexpected end of data",
        );
    }

    #[test]
    fn a_code_cannot_leave_the_directory() {
        let root = Path::new("/m");
        assert!(customer_files(root, "..").is_err());
        assert!(customer_files(root, "a/b").is_err());
        assert!(customer_files(root, "").is_err());
        let f = customer_files(root, "00002").expect("ok");
        assert_eq!(
            f.checkpoint,
            Path::new("/m/checkpoint/mimecast_00002.checkpoint")
        );
        assert_eq!(f.log_dir, Path::new("/m/logs/00002"));
    }

    #[test]
    fn payload_keeps_python_s_order_and_refuses_a_keyword_twice() {
        let p = event_payload("c", vec![("x".into(), PyValue::Str("1".into()))]).expect("ok");
        assert_eq!(
            p.py_repr(),
            "{'integration': 'mimecast', 'customer_code': 'c', 'version': '1.0', 'x': '1'}"
        );
        assert!(event_payload("c", vec![("version".into(), PyValue::None)]).is_err());
    }
}
