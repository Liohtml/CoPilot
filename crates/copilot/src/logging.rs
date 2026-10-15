//! Logging: `tracing-subscriber` with an `EnvFilter` (`RUST_LOG`, else the
//! backend's `LOG_LEVEL`), text or JSON (`COPILOT_LOG_FORMAT=json`), and
//! redaction of every line before it is written — the pattern Talon uses
//! (`talon::logging`), reduced to what CoPilot logs can carry: bearer
//! tokens, JWTs, and the configured secret values themselves.

use std::io::{self, Write};
use std::sync::Arc;

use regex::Regex;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

/// Replaces secrets in log text.
#[derive(Debug)]
pub struct Redactor {
    secrets: Vec<String>,
    patterns: Vec<(Regex, &'static str)>,
}

impl Redactor {
    /// A redactor that also masks these literal values (≥ 6 chars).
    pub fn new(secrets: Vec<String>) -> Self {
        // Static, known-good expressions: compilation cannot fail.
        let compile = |re: &str| Regex::new(re).ok();
        let patterns = [
            (
                compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
                "Bearer [REDACTED:bearer]",
            ),
            (
                compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
                "[REDACTED:jwt]",
            ),
            (
                compile(r#"(?i)("?(?:password|api_key|x-api-key|secret)"?\s*[:=]\s*"?)[^"\s,}]+"#),
                "${1}[REDACTED]",
            ),
        ]
        .into_iter()
        .filter_map(|(re, rep)| re.map(|r| (r, rep)))
        .collect();
        let mut secrets: Vec<String> = secrets.into_iter().filter(|s| s.len() >= 6).collect();
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        Self { secrets, patterns }
    }

    /// Redact one string.
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for s in &self.secrets {
            if out.contains(s.as_str()) {
                out = out.replace(s.as_str(), "[REDACTED]");
            }
        }
        for (re, rep) in &self.patterns {
            out = re.replace_all(&out, *rep).into_owned();
        }
        out
    }
}

/// [`MakeWriter`] that redacts every event.
#[derive(Clone)]
pub struct RedactingMakeWriter {
    redactor: Arc<Redactor>,
}

impl<'a> MakeWriter<'a> for RedactingMakeWriter {
    type Writer = RedactingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            buf: Vec::with_capacity(256),
            redactor: Arc::clone(&self.redactor),
        }
    }
}

/// Buffers one formatted event; redacts and writes it on drop.
pub struct RedactingWriter {
    buf: Vec<u8>,
    redactor: Arc<Redactor>,
}

impl Write for RedactingWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for RedactingWriter {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let text = String::from_utf8_lossy(&self.buf);
        let clean = self.redactor.redact(&text);
        let mut out = io::stdout().lock();
        let _ = out.write_all(clean.as_bytes());
    }
}

fn default_filter(log_level: Option<&str>) -> String {
    let level = match log_level.map(|l| l.trim().to_ascii_lowercase()).as_deref() {
        Some("debug") => "debug",
        Some("warning" | "warn") => "warn",
        Some("error" | "critical") => "error",
        Some("trace") => "trace",
        _ => "info",
    };
    format!("{level},sqlx=warn,hyper=warn,reqwest=warn")
}

/// Install the global subscriber. A second call is a no-op.
pub fn init(json: bool, log_level: Option<&str>, redactor: Redactor) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_filter(log_level)))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let writer = RedactingMakeWriter {
        redactor: Arc::new(redactor),
    };
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_target(true);
    let result = if json {
        builder
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .try_init()
    } else {
        builder.with_ansi(false).try_init()
    };
    if result.is_err() {
        eprintln!("logging already initialised");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_tokens_and_secrets() {
        let r = Redactor::new(vec!["hunter2-secret".into(), "abc".into()]);
        let line = "auth=Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.sig pw=hunter2-secret abc";
        let out = r.redact(line);
        assert!(!out.contains("eyJhbGci"));
        assert!(!out.contains("hunter2-secret"));
        assert!(
            out.contains("abc"),
            "short values are not treated as secrets"
        );
        let jwt = r.redact("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln");
        assert_eq!(jwt, "token [REDACTED:jwt]");
        assert_eq!(
            r.redact(r#"{"password": "x1y2z3"}"#),
            r#"{"password": "[REDACTED]"}"#
        );
    }

    #[test]
    fn level_mapping() {
        assert!(default_filter(Some("INFO")).starts_with("info,"));
        assert!(default_filter(Some("WARNING")).starts_with("warn,"));
        assert!(default_filter(None).starts_with("info,"));
    }
}
