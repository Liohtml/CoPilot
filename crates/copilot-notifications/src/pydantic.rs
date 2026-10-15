//! Pydantic's `ValidationError` text — what CoPilot puts in a 400/422 when a
//! channel config is refused (`Invalid config for channel 'webhook': 1
//! validation error for WebhookConfig …`) or a stored row does not fit its
//! read model (the backend's `ValueError` handler answers with `str(e)`).
//!
//! The layout is pydantic-core's `Display` for `ValidationError`:
//!
//! ```text
//! 2 validation errors for WebhookConfig
//! headers.a
//!   Input should be a valid string [type=string_type, input_value=1, input_type=int]
//!     For further information visit https://errors.pydantic.dev/2.13/v/string_type
//! ```
//!
//! `input_value` is the value's `repr()`, cut to its first 25 and last 24
//! characters around `...` when longer than 50. Pinned by
//! `config_vectors.json` (`scripts/gen-notification-vectors.py`).

use copilot_auth::pyvalue::PyValue;

/// The `major.minor` of the Pydantic release CoPilot runs (the error links
/// name it).
pub const PYDANTIC_VERSION: &str = "2.13";

/// One location element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loc {
    /// A field or dict key.
    Key(String),
    /// A list index.
    Index(usize),
}

/// One Pydantic error.
#[derive(Debug, Clone, PartialEq)]
pub struct PyError {
    /// Where (`headers.a`, `to.0`).
    pub loc: Vec<Loc>,
    /// Pydantic's error type (`string_type`, `value_error`, …).
    pub kind: &'static str,
    /// The message (`Value error, …` for a validator's `ValueError`).
    pub msg: String,
    /// The offending input.
    pub input: PyValue,
}

impl PyError {
    /// Build one.
    pub fn new(loc: Vec<Loc>, kind: &'static str, msg: impl Into<String>, input: PyValue) -> Self {
        Self {
            loc,
            kind,
            msg: msg.into(),
            input,
        }
    }
}

/// `type(value).__name__` of a `json.loads` value.
pub fn input_type(v: &PyValue) -> &'static str {
    match v {
        PyValue::None => "NoneType",
        PyValue::Bool(_) => "bool",
        PyValue::Int(_) => "int",
        PyValue::Float(_) => "float",
        PyValue::Str(_) => "str",
        PyValue::List(_) => "list",
        PyValue::Dict(_) => "dict",
    }
}

/// The `input_value=` part: `repr()`, truncated like pydantic-core — by
/// UTF-8 bytes, the head floored and the tail's start raised to a character
/// boundary.
pub fn input_value(v: &PyValue) -> String {
    let repr = v.py_repr();
    let len = repr.len();
    if len <= 50 {
        return repr;
    }
    let mut head = 25;
    while !repr.is_char_boundary(head) {
        head -= 1;
    }
    let mut tail = len - 24;
    while !repr.is_char_boundary(tail) {
        tail += 1;
    }
    format!("{}...{}", &repr[..head], &repr[tail..])
}

/// `str(ValidationError)` for `title` (the model's name).
pub fn format(title: &str, errors: &[PyError]) -> String {
    let n = errors.len();
    let mut out = format!(
        "{n} validation error{} for {title}",
        if n == 1 { "" } else { "s" }
    );
    for e in errors {
        out.push('\n');
        if !e.loc.is_empty() {
            let loc: Vec<String> = e
                .loc
                .iter()
                .map(|l| match l {
                    Loc::Key(k) => k.clone(),
                    Loc::Index(i) => i.to_string(),
                })
                .collect();
            out.push_str(&loc.join("."));
            out.push('\n');
        }
        out.push_str(&format!(
            "  {} [type={}, input_value={}, input_type={}]\n    For further information visit \
             https://errors.pydantic.dev/{PYDANTIC_VERSION}/v/{}",
            e.msg,
            e.kind,
            input_value(&e.input),
            input_type(&e.input),
            e.kind
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_keeps_25_and_24_characters() {
        let long = PyValue::Str("y".repeat(100));
        let shown = input_value(&long);
        assert_eq!(shown.chars().count(), 52);
        let wide = input_value(&PyValue::List(vec![PyValue::Str("é".repeat(60))]));
        assert_eq!(wide, format!("['{}...{}']", "é".repeat(11), "é".repeat(11)));
        assert!(shown.starts_with("'yyyyyyyyyyyyyyyyyyyyyyyy..."));
        assert!(shown.ends_with("...yyyyyyyyyyyyyyyyyyyyyyy'"));
        assert_eq!(input_value(&PyValue::Str("y".repeat(48))).len(), 50);
    }

    #[test]
    fn one_and_many_errors() {
        let e = PyError::new(
            vec![Loc::Key("url".into())],
            "string_type",
            "Input should be a valid string",
            PyValue::Int("5".into()),
        );
        assert_eq!(
            format("WebhookConfig", std::slice::from_ref(&e)),
            "1 validation error for WebhookConfig\nurl\n  Input should be a valid string \
             [type=string_type, input_value=5, input_type=int]\n    For further information \
             visit https://errors.pydantic.dev/2.13/v/string_type"
        );
        assert!(format("X", &[e.clone(), e]).starts_with("2 validation errors for X\n"));
    }
}
