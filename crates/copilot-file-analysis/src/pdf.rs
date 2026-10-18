//! `convert_html_to_pdf` of `app/incidents/services/reports_pdf.py` over
//! pdfkit 1.0: the rendered HTML in a `NamedTemporaryFile(suffix=".html")`,
//! the first readable wkhtmltopdf of pdfkit's Linux search (`/usr/bin`,
//! `/usr/local/bin`), its command line as pdfkit builds it
//! (`--disable-local-file-access`, the caller's options in order, `--quiet`,
//! the input and output paths) and pdfkit's reading of the outcome, every
//! failure as `Failed to convert HTML to PDF: …`.
//!
//! The shared wkhtmltopdf runner of this wave lives in another crate; this
//! private module is to be folded into it at merge. Unlike Python, the two
//! temporary files are removed once the PDF is read (Python leaves both in
//! the temporary directory).

use std::path::PathBuf;
use std::process::Stdio;
use std::time::SystemTime;

use rand::Rng as _;

/// pdfkit's search path on Linux.
const CANDIDATES: &[&str] = &["/usr/bin/wkhtmltopdf", "/usr/local/bin/wkhtmltopdf"];

/// A generated PDF.
#[derive(Debug, Clone)]
pub struct Pdf {
    /// Its bytes.
    pub data: Vec<u8>,
    /// The file's modification time (Starlette's `ETag` / `Last-Modified`).
    pub mtime: SystemTime,
}

/// `tempfile.gettempdir()`.
fn temp_dir() -> PathBuf {
    for var in ["TMPDIR", "TEMP", "TMP"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() && std::path::Path::new(&v).is_dir() {
                return PathBuf::from(v);
            }
        }
    }
    PathBuf::from("/tmp")
}

/// `NamedTemporaryFile(delete=False, suffix=".html")`: `tmp` + 8 of
/// `_RandomNameSequence`'s characters.
fn named_temporary(content: &[u8]) -> std::io::Result<PathBuf> {
    use std::io::Write as _;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
    let dir = temp_dir();
    for _ in 0..100 {
        let mut rng = rand::thread_rng();
        let name: String = (0..8)
            .map(|_| char::from(CHARS[rng.gen_range(0..CHARS.len())]))
            .collect();
        let path = dir.join(format!("tmp{name}.html"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                f.write_all(content)?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "No usable temporary file name found",
    ))
}

/// pdfkit's `handle_error(exit_code, stderr)`.
fn handle_error(code: i32, stderr: &str) -> Result<(), String> {
    if code == 0 {
        return Ok(());
    }
    let lines = copilot_jinja::unicode::splitlines(stderr, false);
    if lines.len() > 1 && crate::py::strip(&lines[lines.len() - 2]) == "Done" {
        return Ok(());
    }
    if stderr.contains("cannot connect to X server") {
        return Err(format!(
            "{stderr}\nYou will need to run wkhtmltopdf within a \"virtual\" X server.\nGo to the \
             link below for more information\nhttps://github.com/JazzCore/python-pdfkit/wiki/Using-wkhtmltopdf-without-X-server"
        ));
    }
    if stderr.contains("Error") {
        return Err(format!("wkhtmltopdf reported an error:\n{stderr}"));
    }
    let msg = if stderr.is_empty() {
        "Unknown Error"
    } else {
        stderr
    };
    Err(format!(
        "wkhtmltopdf exited with non-zero code {code}. error:\n{msg}"
    ))
}

/// pdfkit's `codecs.open(path, encoding="utf-8").read(4)`: 4-byte reads
/// until four characters are decoded, a `UnicodeDecodeError` on an invalid
/// sequence among the bytes read (an incomplete one waits for the next read).
fn utf8_head(data: &[u8]) -> Result<(), String> {
    let (mut pos, mut chars) = (0usize, 0usize);
    let mut pending: Vec<u8> = Vec::new();
    while chars < 4 {
        let end = (pos + 4).min(data.len());
        let fresh = &data[pos..end];
        pos = end;
        let mut buf = std::mem::take(&mut pending);
        buf.extend_from_slice(fresh);
        if buf.is_empty() {
            break;
        }
        match std::str::from_utf8(&buf) {
            Ok(text) => chars += text.chars().count(),
            Err(e) => {
                let valid = e.valid_up_to();
                let Some(len) = e.error_len() else {
                    // An incomplete sequence at the end: kept for the next read.
                    chars += String::from_utf8_lossy(&buf[..valid]).chars().count();
                    pending = buf[valid..].to_vec();
                    if fresh.is_empty() {
                        break;
                    }
                    continue;
                };
                let first = buf[valid];
                let reason = if (0xC2..=0xF4).contains(&first) {
                    "invalid continuation byte"
                } else {
                    "invalid start byte"
                };
                return Err(if len == 1 {
                    format!(
                        "'utf-8' codec can't decode byte 0x{first:02x} in position {valid}: {reason}"
                    )
                } else {
                    format!(
                        "'utf-8' codec can't decode bytes in position {valid}-{}: {reason}",
                        valid + len - 1
                    )
                });
            }
        }
        if fresh.is_empty() {
            break;
        }
    }
    Ok(())
}

/// `render_html_template`'s file, then `convert_html_to_pdf(html_path,
/// extra_options)`: the PDF, or the `RuntimeError`'s text.
pub async fn html_to_pdf(
    html: &str,
    options: &[(&str, &str)],
    binary: Option<&str>,
) -> Result<Pdf, String> {
    let html_path = named_temporary(html.as_bytes()).map_err(|e| e.to_string())?;
    let outcome = convert(&html_path, options, binary).await;
    let _ = std::fs::remove_file(&html_path);
    outcome
}

async fn convert(
    html_path: &std::path::Path,
    options: &[(&str, &str)],
    binary: Option<&str>,
) -> Result<Pdf, String> {
    let fail = |e: String| format!("Failed to convert HTML to PDF: {e}");
    let html = html_path.to_string_lossy().into_owned();
    let pdf_path = html.replace(".html", ".pdf");
    let candidates: Vec<&str> = match binary {
        Some(b) => vec![b],
        None => CANDIDATES.to_vec(),
    };
    let Some(wkhtmltopdf) = candidates
        .into_iter()
        .find(|p| std::fs::File::open(p).is_ok())
    else {
        return Err(fail(
            "No valid wkhtmltopdf executable found. Ensure wkhtmltopdf is installed and \
             accessible."
                .into(),
        ));
    };
    let mut args: Vec<String> = vec!["--disable-local-file-access".into()];
    for (k, v) in options {
        let key = if k.contains("--") {
            k.to_lowercase()
        } else {
            format!("--{}", k.to_lowercase())
        };
        if key == "--disable-local-file-access" {
            continue;
        }
        args.push(key);
        if !v.is_empty() {
            args.push((*v).to_string());
        }
    }
    args.push("--quiet".into());
    args.push(html.clone());
    args.push(pdf_path.clone());
    let child = tokio::process::Command::new(wkhtmltopdf)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            fail(format!(
                "[Errno {}] {}: {}",
                e.raw_os_error().unwrap_or(0),
                copilot_velociraptor::config::strerror(&e),
                copilot_auth::pyvalue::str_repr(wkhtmltopdf)
            ))
        })?;
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| fail(e.to_string()))?;
    let raw = if output.stderr.is_empty() {
        output.stdout
    } else {
        output.stderr
    };
    let stderr = String::from_utf8_lossy(&raw).into_owned();
    let code = output.status.code().unwrap_or(-1);
    let result = handle_error(code, &stderr).map_err(fail).and_then(|()| {
        let data = std::fs::read(&pdf_path).map_err(|e| {
            let mut line = vec![wkhtmltopdf.to_string()];
            line.extend(args.iter().cloned());
            fail(format!(
                "Command failed: {}\nCheck whhtmltopdf output without 'quiet' option\n{} ",
                line.join(" "),
                copilot_velociraptor::config::open_error(&pdf_path, &e)
            ))
        })?;
        utf8_head(&data).map_err(fail)?;
        if data.is_empty() {
            // Raised inside pdfkit's `try`, so wrapped by its own `except`.
            let mut line = vec![wkhtmltopdf.to_string()];
            line.extend(args.iter().cloned());
            let inner = format!(
                "Command failed: {}\nCheck whhtmltopdf output without 'quiet' option",
                line.join(" ")
            );
            return Err(fail(format!("{inner}\n{inner} ")));
        }
        let mtime = std::fs::metadata(&pdf_path)
            .and_then(|m| m.modified())
            .unwrap_or_else(|_| SystemTime::now());
        Ok(Pdf { data, mtime })
    });
    let _ = std::fs::remove_file(&pdf_path);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdfkit_reads_four_characters() {
        assert!(utf8_head(b"%PDF-1.4\n%\xe2\xe3").is_ok());
        assert!(utf8_head(b"%PDF\xff").is_ok());
        assert!(utf8_head(b"").is_ok());
        assert_eq!(
            utf8_head(b"\xffPDF").unwrap_err(),
            "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"
        );
        assert_eq!(
            utf8_head(b"ab\xe2(c").unwrap_err(),
            "'utf-8' codec can't decode byte 0xe2 in position 2: invalid continuation byte"
        );
        assert_eq!(
            utf8_head(b"a\xf0\x9f\x98(").unwrap_err(),
            "'utf-8' codec can't decode bytes in position 0-2: invalid continuation byte"
        );
        assert!(utf8_head(b"abc\xe2\x82\xac").is_ok());
    }

    #[test]
    fn pdfkit_reads_the_exit_like_python() {
        assert!(handle_error(0, "").is_ok());
        // pdfkit reads `Done` on the second-to-last line only.
        assert!(handle_error(1, "Loading\nDone\nExit with code 1 due to network error").is_ok());
        assert_eq!(
            handle_error(1, "Loading\nDone\n").unwrap_err(),
            "wkhtmltopdf exited with non-zero code 1. error:\nLoading\nDone\n"
        );
        assert_eq!(
            handle_error(1, "Error: boom").unwrap_err(),
            "wkhtmltopdf reported an error:\nError: boom"
        );
        assert_eq!(
            handle_error(2, "").unwrap_err(),
            "wkhtmltopdf exited with non-zero code 2. error:\nUnknown Error"
        );
    }
}
