//! A .docx template rendered as docxtpl 0.20.2 renders it over python-docx
//! 1.2 and lxml 6 (libxml2 2.14): the package read and written back part by
//! part as python-docx does, the body's XML patched by docxtpl's regular
//! expressions, rendered through copilot-jinja and put back.
//!
//! Pinned by `src/docx_vectors.json` (`scripts/gen-docx-vectors.py`: every
//! member of the documents Python writes for a set of templates and
//! contexts, the bundled `case_report_jinja_template.docx` included).

pub mod docxtpl;
pub mod opc;
pub mod pyre;
pub mod xml;
pub mod zip;

use copilot_jinja::{Data, Environment};

/// A failure of the rendering.
#[derive(Debug, Clone, PartialEq)]
pub enum DocxError {
    /// A `ValueError` (FastAPI's handler answers 400 with its text).
    Value(String),
    /// Anything else: a bare 500.
    Internal(String),
    /// The rendered body is not well-formed XML beyond the characters XML
    /// refuses: lxml's recovering parser (libxml2's repair, not ported)
    /// would still make a document of it.
    Recover(String),
}

impl std::fmt::Display for DocxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value(m) | Self::Internal(m) | Self::Recover(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for DocxError {}

/// `bytes.decode("utf-8")`'s `UnicodeDecodeError` text, or `None` when the
/// bytes are valid.
pub fn utf8_decode_error(bytes: &[u8]) -> Option<String> {
    let e = std::str::from_utf8(bytes).err()?;
    let start = e.valid_up_to();
    let (end, reason) = match e.error_len() {
        None => (bytes.len(), "unexpected end of data"),
        Some(n) => {
            let first = bytes[start];
            let bad_start = n == 1 && ((0x80..=0xc1).contains(&first) || first >= 0xf5);
            (
                start + n,
                if bad_start {
                    "invalid start byte"
                } else {
                    "invalid continuation byte"
                },
            )
        }
    };
    Some(if end - start == 1 {
        format!(
            "'utf-8' codec can't decode byte 0x{:02x} in position {start}: {reason}",
            bytes[start]
        )
    } else {
        format!(
            "'utf-8' codec can't decode bytes in position {start}-{}: {reason}",
            end - 1
        )
    })
}

/// The moments a rendering stamps: the zip members' local time and, for a
/// template without core properties, their `modified` (UTC).
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    /// `time.localtime()` (the members' date and time).
    pub local: chrono::NaiveDateTime,
    /// `datetime.now(timezone.utc)`.
    pub utc: chrono::DateTime<chrono::Utc>,
}

impl Clock {
    /// Now.
    pub fn now() -> Self {
        Self {
            local: chrono::Local::now().naive_local(),
            utc: chrono::Utc::now(),
        }
    }
}

/// The package's members after `DocxTemplate(path).render(context,
/// jinja_env)`, in the order `save` writes them.
pub fn render_members(
    template: &[u8],
    path: &str,
    env: &Environment,
    vars: &[(String, Data)],
    clock: Clock,
) -> Result<Vec<(String, Vec<u8>)>, DocxError> {
    let mut t = docxtpl::Template::open(template, path)?;
    t.render(env, vars, clock.utc)?;
    Ok(t.package.members())
}

/// `DocxTemplate(path).render(context, jinja_env)` then `save()`: the
/// .docx's bytes.
pub fn render(
    template: &[u8],
    path: &str,
    env: &Environment,
    vars: &[(String, Data)],
    clock: Clock,
) -> Result<Vec<u8>, DocxError> {
    let mut t = docxtpl::Template::open(template, path)?;
    t.render(env, vars, clock.utc)?;
    t.package.save(clock.local)
}
