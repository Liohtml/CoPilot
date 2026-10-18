//! `reports_pdf.convert_html_to_pdf` over pdfkit 1.0: the `wkhtmltopdf`
//! binary found as the platform branch finds it, the argument list
//! `PDFKit.command(path)` builds, `to_pdf`'s error handling, and the
//! `RuntimeError("Failed to convert HTML to PDF: …")` every failure becomes.
//!
//! The binary: the first of the platform's two paths (`/usr/bin/wkhtmltopdf`,
//! `/usr/local/bin/wkhtmltopdf` on Linux) that `open()` accepts — a readable
//! file, not a directory. `COPILOT_WKHTMLTOPDF` names one binary instead,
//! for the parity harness (a recording wrapper), never production.
//!
//! The arguments: the binary, then the options in insertion order (`--` +
//! the lower-cased key, then its value unless it is `None`), `--quiet`, the
//! input file and the output file. `disable-local-file-access` always comes
//! first and cannot be dropped (GHSA-7q83-228r-wfh5).
//!
//! The run: stdin piped and closed, the process's environment, stdout and
//! stderr read; a non-zero exit is an error unless the second-to-last line
//! of stderr (or stdout when stderr is empty) is `Done`; then the output's
//! first four characters are read as UTF-8 — a missing or empty file is
//! `Command failed: …`.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::io::AsyncWriteExt as _;

use crate::tempfile;

/// `COPILOT_WKHTMLTOPDF`: the binary the parity harness records with.
pub const BINARY_OVERRIDE: &str = "COPILOT_WKHTMLTOPDF";

/// The paths `convert_html_to_pdf` tries on this platform.
pub fn platform_paths() -> &'static [&'static str] {
    if cfg!(target_os = "windows") {
        &[
            r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe",
            r"C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe",
        ]
    } else if cfg!(target_os = "macos") {
        &[
            "/usr/local/bin/wkhtmltopdf",
            "/opt/homebrew/bin/wkhtmltopdf",
        ]
    } else if cfg!(target_os = "linux") {
        &["/usr/bin/wkhtmltopdf", "/usr/local/bin/wkhtmltopdf"]
    } else {
        &[]
    }
}

/// `pdfkit.configuration(wkhtmltopdf=path)` succeeds: `open(path)` works.
fn openable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| !m.is_dir()) && std::fs::File::open(path).is_ok()
}

/// The binary `convert_html_to_pdf` settles on, if any.
pub fn find_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(BINARY_OVERRIDE).filter(|v| !v.is_empty()) {
        let path = PathBuf::from(path);
        return openable(&path).then_some(path);
    }
    platform_paths()
        .iter()
        .map(PathBuf::from)
        .find(|p| openable(p))
}

/// One pdfkit option: `None` is a flag without a value.
pub type PdfOption = (&'static str, Option<String>);

/// The options `convert_html_to_pdf(html_path, extra_options)` hands pdfkit:
/// `disable-local-file-access` first, then the extra ones in order (a second
/// `disable-local-file-access` only re-asserted, never removed).
pub fn options(extra: &[PdfOption]) -> Vec<PdfOption> {
    let mut out: Vec<PdfOption> = vec![("disable-local-file-access", None)];
    for (key, value) in extra {
        match out.iter_mut().find(|(k, _)| k == key) {
            Some(slot) => slot.1 = value.clone(),
            None => out.push((key, value.clone())),
        }
    }
    if let Some(slot) = out
        .iter_mut()
        .find(|(k, _)| *k == "disable-local-file-access")
    {
        slot.1 = None;
    }
    out
}

/// `PDFKit(html_path, "file", options=…).command(pdf_path)`.
pub fn command(binary: &str, opts: &[PdfOption], input: &str, output: &str) -> Vec<String> {
    let mut args = vec![binary.to_string()];
    for (key, value) in opts {
        let key = if key.contains("--") {
            key.to_lowercase()
        } else {
            format!("--{}", key.to_lowercase())
        };
        args.push(key);
        if let Some(v) = value.as_ref().filter(|v| !v.is_empty()) {
            args.push(v.clone());
        }
    }
    args.push("--quiet".into());
    args.push(input.to_string());
    args.push(output.to_string());
    args
}

/// `PDFKit.handle_error(exit_code, stderr)`.
fn handle_error(exit_code: i32, stderr: &str) -> Result<(), String> {
    if exit_code == 0 {
        return Ok(());
    }
    let lines = py_splitlines(stderr);
    if lines.len() > 1 && py_strip(lines[lines.len() - 2]) == "Done" {
        return Ok(());
    }
    if stderr.contains("cannot connect to X server") {
        return Err(format!(
            "{stderr}\nYou will need to run wkhtmltopdf within a \"virtual\" X server.\nGo to the \
             link below for more information\n\
             https://github.com/JazzCore/python-pdfkit/wiki/Using-wkhtmltopdf-without-X-server"
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
        "wkhtmltopdf exited with non-zero code {exit_code}. error:\n{msg}"
    ))
}

/// `str.splitlines()` (the line boundaries Python knows).
fn py_splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let boundary = matches!(
            c,
            '\n' | '\r'
                | '\u{0b}'
                | '\u{0c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if boundary {
            out.push(&s[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' {
                if let Some(&(j, '\n')) = chars.peek() {
                    chars.next();
                    end = j + 1;
                }
            }
            start = end;
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// `str.strip()`.
fn py_strip(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// `codecs.open(path, encoding="utf-8").read(4)`: up to four characters,
/// read four bytes at a time.
fn read_four_chars(path: &Path) -> Result<String, ReadFailure> {
    let data = std::fs::read(path).map_err(ReadFailure::Io)?;
    let mut buffer: Vec<u8> = Vec::new();
    let mut chars = String::new();
    let mut pos = 0;
    while chars.chars().count() < 4 {
        let chunk = &data[pos..(pos + 4).min(data.len())];
        pos += chunk.len();
        buffer.extend_from_slice(chunk);
        if buffer.is_empty() {
            break;
        }
        match std::str::from_utf8(&buffer) {
            Ok(s) => {
                chars.push_str(s);
                buffer.clear();
            }
            Err(e) => {
                let valid = e.valid_up_to();
                if let Some(bad) = e.error_len() {
                    return Err(ReadFailure::Decode(decode_error(&buffer, valid, bad)));
                }
                chars.push_str(std::str::from_utf8(&buffer[..valid]).unwrap_or_default());
                buffer.drain(..valid);
                if chunk.is_empty() {
                    // `final=True` at the end of the data: what is left is truncated.
                    return Err(ReadFailure::Decode(format!(
                        "'utf-8' codec can't decode byte 0x{:02x} in position {}: unexpected end \
                         of data",
                        buffer[0], valid
                    )));
                }
            }
        }
        if chunk.is_empty() {
            break;
        }
    }
    Ok(chars.chars().take(4).collect())
}

/// CPython's `UnicodeDecodeError` text for an invalid sequence.
fn decode_error(buffer: &[u8], valid: usize, bad: usize) -> String {
    let byte = buffer[valid];
    let reason = if bad == 1 && !(0xc2..=0xf4).contains(&byte) {
        "invalid start byte"
    } else {
        "invalid continuation byte"
    };
    if bad == 1 {
        format!("'utf-8' codec can't decode byte 0x{byte:02x} in position {valid}: {reason}")
    } else {
        format!(
            "'utf-8' codec can't decode bytes in position {valid}-{}: {reason}",
            valid + bad - 1
        )
    }
}

enum ReadFailure {
    Io(std::io::Error),
    Decode(String),
}

/// `str(OSError)` for a failed `open()`.
fn os_error_text(e: &std::io::Error, path: &Path) -> String {
    let (errno, text) = match e.kind() {
        std::io::ErrorKind::NotFound => (2, "No such file or directory"),
        std::io::ErrorKind::PermissionDenied => (13, "Permission denied"),
        _ => {
            return format!(
                "[Errno {}] {}: {}",
                e.raw_os_error().unwrap_or(0),
                e,
                py_quote_path(path)
            );
        }
    };
    format!("[Errno {errno}] {text}: {}", py_quote_path(path))
}

fn py_quote_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    if s.contains('\'') && !s.contains('"') {
        format!("\"{s}\"")
    } else {
        format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
    }
}

/// What a conversion did: the argument list (whatever happened) and the
/// failure text, `Failed to convert HTML to PDF: …` included.
#[derive(Debug, Clone)]
pub struct Conversion {
    /// `PDFKit.command(path)` — empty when no binary was found.
    pub args: Vec<String>,
    /// The PDF's path (`html_path.replace(".html", ".pdf")`).
    pub pdf_path: PathBuf,
}

/// `convert_html_to_pdf(html_path, extra_options)`: the PDF's path, or the
/// `RuntimeError`'s text.
pub async fn convert_html_to_pdf(html_path: &Path, extra: &[PdfOption]) -> Result<PathBuf, String> {
    let html = html_path.to_string_lossy().into_owned();
    let pdf_path = PathBuf::from(html.replace(".html", ".pdf"));
    run(&html, &pdf_path, extra)
        .await
        .map(|()| pdf_path)
        .map_err(|e| format!("Failed to convert HTML to PDF: {e}"))
}

async fn run(html: &str, pdf_path: &Path, extra: &[PdfOption]) -> Result<(), String> {
    let binary = find_binary().ok_or_else(|| {
        "No valid wkhtmltopdf executable found. Ensure wkhtmltopdf is installed and accessible."
            .to_string()
    })?;
    // `Source(html_path, "file")`.
    if !Path::new(html).exists() {
        return Err(format!("No such file: {html}"));
    }
    let pdf = pdf_path.to_string_lossy().into_owned();
    let args = command(&binary.to_string_lossy(), &options(extra), html, &pdf);
    let mut child = tokio::process::Command::new(&args[0])
        .args(&args[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| os_error_text(&e, &binary))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.shutdown().await;
    }
    let output = child.wait_with_output().await.map_err(|e| e.to_string())?;
    let raw = if output.stderr.is_empty() {
        output.stdout
    } else {
        output.stderr
    };
    let stderr = String::from_utf8_lossy(&raw).into_owned();
    let exit_code = output.status.code().unwrap_or_else(|| {
        // A signal: `Popen.returncode` is its negative number.
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            output.status.signal().map_or(-1, |s| -s)
        }
        #[cfg(not(unix))]
        {
            -1
        }
    });
    handle_error(exit_code, &stderr)?;
    let joined = args.join(" ");
    match read_four_chars(pdf_path) {
        Ok(text) if text.is_empty() => {
            let inner = format!(
                "Command failed: {joined}\nCheck whhtmltopdf output without 'quiet' option"
            );
            Err(format!(
                "Command failed: {joined}\nCheck whhtmltopdf output without 'quiet' option\n{inner} "
            ))
        }
        Ok(_) => Ok(()),
        Err(ReadFailure::Io(e)) => Err(format!(
            "Command failed: {joined}\nCheck whhtmltopdf output without 'quiet' option\n{} ",
            os_error_text(&e, pdf_path)
        )),
        Err(ReadFailure::Decode(text)) => Err(text),
    }
}

/// `customer_report.html_to_pdf_bytes(rendered_html, brand, tlp)`: the page
/// written to a temporary `.html`, converted with the report chrome (the
/// footer drawn on every page, the margins, 96 dpi without smart
/// shrinking), read back; both files removed whatever happened.
pub async fn html_to_pdf_bytes(
    rendered_html: &str,
    brand: &str,
    tlp: &str,
) -> Result<Vec<u8>, String> {
    let html_path =
        tempfile::named(".html", rendered_html.as_bytes()).map_err(|e| e.to_string())?;
    let result = async {
        let pdf_path = convert_html_to_pdf(&html_path, &report_options(brand, tlp)).await?;
        let read = std::fs::read(&pdf_path).map_err(|e| os_error_text(&e, &pdf_path));
        tempfile::remove(&pdf_path);
        read
    }
    .await;
    tempfile::remove(&html_path);
    // The PDF of a failed conversion may be left behind: `finally` removes it too.
    tempfile::remove(&PathBuf::from(
        html_path.to_string_lossy().replace(".html", ".pdf"),
    ));
    result
}

/// `html_to_pdf_bytes`' `extra_options`.
pub fn report_options(brand: &str, tlp: &str) -> Vec<PdfOption> {
    let s = |v: &str| Some(v.to_string());
    vec![
        ("footer-left", Some(format!("{brand}  ·  {tlp}"))),
        ("footer-right", s("[page] / [topage]")),
        ("footer-font-size", s("8")),
        ("footer-font-name", s("Helvetica")),
        ("footer-spacing", s("4")),
        ("margin-top", s("16mm")),
        ("margin-bottom", s("16mm")),
        ("margin-left", s("14mm")),
        ("margin-right", s("14mm")),
        ("encoding", s("UTF-8")),
        ("disable-smart-shrinking", None),
        ("dpi", s("96")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_is_pdfkits() {
        let args = command(
            "/usr/bin/wkhtmltopdf",
            &options(&report_options("B", "TLP:RED")),
            "/t/a.html",
            "/t/a.pdf",
        );
        assert_eq!(
            args,
            [
                "/usr/bin/wkhtmltopdf",
                "--disable-local-file-access",
                "--footer-left",
                "B  ·  TLP:RED",
                "--footer-right",
                "[page] / [topage]",
                "--footer-font-size",
                "8",
                "--footer-font-name",
                "Helvetica",
                "--footer-spacing",
                "4",
                "--margin-top",
                "16mm",
                "--margin-bottom",
                "16mm",
                "--margin-left",
                "14mm",
                "--margin-right",
                "14mm",
                "--encoding",
                "UTF-8",
                "--disable-smart-shrinking",
                "--dpi",
                "96",
                "--quiet",
                "/t/a.html",
                "/t/a.pdf",
            ]
        );
        assert_eq!(
            command("w", &options(&[]), "i", "o"),
            ["w", "--disable-local-file-access", "--quiet", "i", "o"]
        );
        // A caller cannot turn local file access back on, nor move it.
        let opts = options(&[
            ("dpi", Some("1".into())),
            ("disable-local-file-access", Some("x".into())),
        ]);
        assert_eq!(opts[0], ("disable-local-file-access", None));
        assert_eq!(opts.len(), 2);
    }

    #[test]
    fn errors_are_pdfkits() {
        assert_eq!(handle_error(0, "anything"), Ok(()));
        assert_eq!(
            handle_error(
                1,
                "Loading\nDone\nExit with code 1 due to network error: X\n"
            ),
            Ok(())
        );
        assert!(handle_error(1, "Loading\nDone\n").is_err());
        assert_eq!(
            handle_error(1, "Error: Failed to load x").unwrap_err(),
            "wkhtmltopdf reported an error:\nError: Failed to load x"
        );
        assert_eq!(
            handle_error(2, "").unwrap_err(),
            "wkhtmltopdf exited with non-zero code 2. error:\nUnknown Error"
        );
        assert!(
            handle_error(1, "cannot connect to X server")
                .unwrap_err()
                .contains("virtual")
        );
    }

    #[test]
    fn splitlines_is_pythons() {
        assert_eq!(py_splitlines("a\r\nb\rc\n"), ["a", "b", "c"]);
        assert_eq!(py_splitlines("a\n\nb"), ["a", "", "b"]);
        assert!(py_splitlines("").is_empty());
    }

    #[tokio::test]
    async fn a_real_conversion_when_the_binary_is_here() {
        if find_binary().is_none() {
            return;
        }
        let pdf = html_to_pdf_bytes(
            "<html><body><p>héllo</p></body></html>",
            "CoPilot",
            "TLP:RED",
        )
        .await
        .unwrap();
        assert!(pdf.starts_with(b"%PDF-"));
    }
}
