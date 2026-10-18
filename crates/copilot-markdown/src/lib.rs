//! # copilot-markdown — CoPilot's Markdown → HTML for notification emails
//!
//! A port of `app/notifications/utils/markdown_html.py`: markdown-it-py
//! 4.2.0's `gfm-like` preset with `html=False`, `linkify=False` and
//! `typographer=False`, rendered with the inline-styled table, cell,
//! blockquote and code rules that module installs, wrapped in one styled
//! `<div>`. AI investigation reports reach customers' inboxes through it,
//! so the output must be the bytes the Python backend produced: the parser
//! is a line-by-line port (code-point positions, Python's `str.strip()`,
//! `unicodedata` punctuation, `mdurl`, CPython's punycode), pinned by
//! `markdown_vectors.json` (`scripts/gen-markdown-vectors.py`). The
//! character tables come from `scripts/gen-markdown-tables.py`.
//!
//! markdown-it-py raises `IndexError` on a handful of inputs (a heading
//! check that reads past the end of a blockquote's last line); the port
//! reports those as [`Error`] so callers can fail the way Python's did.

#![warn(missing_docs)]

mod block;
mod entity;
mod inline;
mod pystr;
mod render;
mod tables;
mod token;
mod url;

use std::cell::Cell;

/// `_TABLE_STYLE`.
pub const TABLE_STYLE: &str = "border-collapse:collapse;width:100%;margin:16px 0;font-size:14px";
/// `_TH_STYLE`.
pub const TH_STYLE: &str =
    "border:1px solid #d1d5db;padding:6px 10px;background:#f3f4f6;text-align:left;font-weight:600";
/// `_TD_STYLE`.
pub const TD_STYLE: &str = "border:1px solid #d1d5db;padding:6px 10px;vertical-align:top";
/// `_PRE_STYLE`.
pub const PRE_STYLE: &str =
    "background:#f3f4f6;padding:12px;border-radius:6px;overflow-x:auto;font-size:13px";
/// `_CODE_STYLE`.
pub const CODE_STYLE: &str = "background:#f3f4f6;padding:2px 4px;border-radius:3px;font-size:13px";
/// `_BLOCKQUOTE_STYLE`.
pub const BLOCKQUOTE_STYLE: &str =
    "border-left:3px solid #d1d5db;margin:16px 0;padding:0 0 0 16px;color:#4b5563";
/// `_WRAPPER_STYLE`.
pub const WRAPPER_STYLE: &str = "font-family:system-ui,-apple-system,Segoe UI,sans-serif;\
                                 font-size:14px;line-height:1.6;color:#374151";

/// `options.maxNesting` of the preset.
pub(crate) const MAX_NESTING: i32 = 20;

/// The `IndexError` markdown-it-py raises on a few malformed inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;

impl Error {
    /// `type(e).__name__`.
    pub const TYPE_NAME: &'static str = "IndexError";
}

impl std::fmt::Display for Error {
    /// `str(e)`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("string index out of range")
    }
}

impl std::error::Error for Error {}

/// `normalize`: `\r\n` and `\r` become `\n`, NUL becomes U+FFFD.
fn normalize(src: &str) -> String {
    src.replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\0', "\u{fffd}")
}

/// `_RENDERER.render(source)`: the HTML of `source`, unwrapped.
pub fn render(source: &str) -> Result<String, Error> {
    let src = normalize(source);
    let error = Cell::new(false);
    let mut env = block::Env::default();
    let mut tokens = {
        let mut state = block::StateBlock::new(&src, &mut env, &error);
        state.parse();
        std::mem::take(&mut state.tokens)
    };
    for t in tokens.iter_mut().filter(|t| t.ty == "inline") {
        let children = inline::parse(&t.content, &env, &error);
        t.children = Some(inline::text_join(children));
    }
    if error.get() {
        return Err(Error);
    }
    Ok(render::render(&tokens))
}

/// `markdown_to_html(source)`: rendered and wrapped in the styled `<div>`;
/// an empty or blank source is an empty string, not an empty wrapper. The
/// result is HTML-safe (`Markup` in Python): raw HTML in the source is
/// escaped.
pub fn markdown_to_html(source: &str) -> Result<String, Error> {
    if pystr::py_strip(source).is_empty() {
        return Ok(String::new());
    }
    Ok(format!(
        "<div style=\"{WRAPPER_STYLE}\">{}</div>",
        render(source)?
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Vector {
        source: String,
        html: Option<String>,
        error: Option<String>,
    }

    /// The generator stores the inline styles as markers.
    fn expand_styles(html: &str) -> String {
        html.replace("§T", TABLE_STYLE)
            .replace("§H", TH_STYLE)
            .replace("§D", TD_STYLE)
            .replace("§P", PRE_STYLE)
            .replace("§C", CODE_STYLE)
            .replace("§B", BLOCKQUOTE_STYLE)
    }

    /// Every case generated from markdown-it-py by
    /// `scripts/gen-markdown-vectors.py`.
    #[test]
    fn matches_markdown_it_py() {
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("markdown_vectors.json")).unwrap();
        let mut failures = Vec::new();
        for v in &vectors {
            let ours = render(&v.source);
            let wrapped = markdown_to_html(&v.source);
            match (&ours, &wrapped) {
                (Ok(inner), Ok(w)) if pystr::py_strip(&v.source).is_empty() => assert_eq!(w, ""),
                (Ok(inner), Ok(w)) => {
                    assert_eq!(*w, format!("<div style=\"{WRAPPER_STYLE}\">{inner}</div>"))
                }
                (Err(_), Err(_)) => {}
                _ => panic!("render and markdown_to_html disagree on {:?}", v.source),
            }
            let ok = match (&ours, &v.html, &v.error) {
                (Ok(h), Some(expected), _) => *h == expand_styles(expected),
                (Err(e), None, Some(expected)) => format!("{}: {e}", Error::TYPE_NAME) == *expected,
                _ => false,
            };
            if !ok {
                failures.push(format!(
                    "source {:?}\n  python {:?}\n  rust   {:?}",
                    v.source,
                    v.html.as_ref().or(v.error.as_ref()),
                    ours
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} differ:\n{}",
            failures.len(),
            vectors.len(),
            failures
                .iter()
                .take(15)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    #[test]
    fn blank_is_empty() {
        assert_eq!(markdown_to_html(" \n\t").unwrap(), "");
        assert_eq!(markdown_to_html("> | a |\n> | - |\n>"), Err(Error));
    }
}
