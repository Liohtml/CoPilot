//! Errors are Python exceptions: a type name and `str(e)`.

use std::fmt;

/// A Python exception raised while compiling or rendering a template, as
/// CoPilot reports it: `type(e).__name__` and `str(e)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// `type(e).__name__` (`UndefinedError`, `TemplateSyntaxError`, …).
    pub kind: &'static str,
    /// `str(e)`.
    pub message: String,
}

impl Error {
    /// An exception of the given type.
    pub fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// `TypeError`.
    pub fn type_error(message: impl Into<String>) -> Self {
        Self::new("TypeError", message)
    }

    /// `ValueError`.
    pub fn value_error(message: impl Into<String>) -> Self {
        Self::new("ValueError", message)
    }

    /// `UndefinedError`.
    pub fn undefined(message: impl Into<String>) -> Self {
        Self::new("UndefinedError", message)
    }

    /// `TemplateSyntaxError`.
    pub fn syntax(message: impl Into<String>) -> Self {
        Self::new("TemplateSyntaxError", message)
    }

    /// `TemplateAssertionError`.
    pub fn assertion(message: impl Into<String>) -> Self {
        Self::new("TemplateAssertionError", message)
    }

    /// `TemplateRuntimeError`.
    pub fn runtime(message: impl Into<String>) -> Self {
        Self::new("TemplateRuntimeError", message)
    }

    /// `FilterArgumentError`.
    pub fn filter_argument(message: impl Into<String>) -> Self {
        Self::new("FilterArgumentError", message)
    }

    /// `ZeroDivisionError`.
    pub fn zero_division(message: impl Into<String>) -> Self {
        Self::new("ZeroDivisionError", message)
    }

    /// `OverflowError`.
    pub fn overflow(message: impl Into<String>) -> Self {
        Self::new("OverflowError", message)
    }

    /// `IndexError`.
    pub fn index(message: impl Into<String>) -> Self {
        Self::new("IndexError", message)
    }

    /// `KeyError(key)`: `str()` of a `KeyError` is the key's `repr()`.
    pub fn key(repr: impl Into<String>) -> Self {
        Self::new("KeyError", repr)
    }

    /// `MemoryError`: a result this engine refuses to build.
    pub fn memory() -> Self {
        Self::new("MemoryError", "")
    }

    /// A Python attribute or construct this port does not implement. Python
    /// would have answered; the template has to use something else.
    pub fn unsupported(what: impl Into<String>) -> Self {
        Self::new(
            "NotImplementedError",
            format!(
                "{} is not supported by CoPilot's template engine",
                what.into()
            ),
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for Error {}

/// Result of every fallible operation.
pub type Result<T> = std::result::Result<T, Error>;
