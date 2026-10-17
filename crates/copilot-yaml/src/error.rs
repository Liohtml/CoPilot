//! `yaml/error.py` and `ReaderError` (`yaml/reader.py`): the exceptions
//! `yaml.safe_load` raises, and the Python exceptions its constructor lets
//! escape.

use std::fmt;
use std::rc::Rc;

/// `yaml.error.Mark`: where something happened, with the buffer for the
/// snippet `str(mark)` prints.
#[derive(Debug, Clone)]
pub struct Mark {
    /// `"<unicode string>"` for a `str` input.
    pub name: &'static str,
    /// Code points from the start.
    pub index: usize,
    /// 0-based line.
    pub line: usize,
    /// 0-based column.
    pub column: usize,
    pub(crate) buffer: Rc<Vec<char>>,
    pub(crate) pointer: usize,
}

const BREAKS_OR_END: &[char] = &['\0', '\r', '\n', '\u{85}', '\u{2028}', '\u{2029}'];

impl Mark {
    /// `get_snippet(indent=4, max_length=75)`.
    fn snippet(&self) -> String {
        let indent = 4usize;
        // `self.pointer - start > max_length / 2 - 1` with max_length 75: 36.5.
        let half = |n: usize| n * 2 > 73;
        let buf = &self.buffer;
        let mut head = "";
        let mut start = self.pointer;
        while start > 0 && !BREAKS_OR_END.contains(&buf[start - 1]) {
            start -= 1;
            if half(self.pointer - start) {
                head = " ... ";
                start += 5;
                break;
            }
        }
        let mut tail = "";
        let mut end = self.pointer;
        while end < buf.len() && !BREAKS_OR_END.contains(&buf[end]) {
            end += 1;
            if half(end - self.pointer) {
                tail = " ... ";
                end -= 5;
                break;
            }
        }
        let snippet: String = if start <= end {
            buf[start..end].iter().collect()
        } else {
            String::new()
        };
        format!(
            "{}{head}{snippet}{tail}\n{}^",
            " ".repeat(indent),
            " ".repeat(indent + self.pointer - start + head.len())
        )
    }

    fn same_place(&self, other: &Mark) -> bool {
        self.name == other.name && self.line == other.line && self.column == other.column
    }
}

impl fmt::Display for Mark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "  in \"{}\", line {}, column {}:\n{}",
            self.name,
            self.line + 1,
            self.column + 1,
            self.snippet()
        )
    }
}

/// Which `MarkedYAMLError` subclass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkedKind {
    /// `yaml.scanner.ScannerError`.
    Scanner,
    /// `yaml.parser.ParserError`.
    Parser,
    /// `yaml.composer.ComposerError`.
    Composer,
    /// `yaml.constructor.ConstructorError`.
    Constructor,
}

impl MarkedKind {
    /// The class name.
    pub fn name(self) -> &'static str {
        match self {
            MarkedKind::Scanner => "ScannerError",
            MarkedKind::Parser => "ParserError",
            MarkedKind::Composer => "ComposerError",
            MarkedKind::Constructor => "ConstructorError",
        }
    }
}

/// `yaml.error.MarkedYAMLError`.
#[derive(Debug, Clone)]
pub struct MarkedError {
    /// The subclass.
    pub kind: MarkedKind,
    /// `context`.
    pub context: Option<String>,
    /// `context_mark`.
    pub context_mark: Option<Mark>,
    /// `problem`.
    pub problem: Option<String>,
    /// `problem_mark`.
    pub problem_mark: Option<Mark>,
    /// `note`.
    pub note: Option<String>,
}

impl MarkedError {
    pub(crate) fn new(
        kind: MarkedKind,
        context: Option<&str>,
        context_mark: Option<Mark>,
        problem: impl Into<String>,
        problem_mark: Option<Mark>,
    ) -> Self {
        Self {
            kind,
            context: context.map(str::to_string),
            context_mark,
            problem: Some(problem.into()),
            problem_mark,
            note: None,
        }
    }
}

impl fmt::Display for MarkedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut lines: Vec<String> = Vec::new();
        if let Some(c) = &self.context {
            lines.push(c.clone());
        }
        if let Some(cm) = &self.context_mark {
            let differs = match (&self.problem, &self.problem_mark) {
                (Some(_), Some(pm)) => !cm.same_place(pm),
                _ => true,
            };
            if differs {
                lines.push(cm.to_string());
            }
        }
        if let Some(p) = &self.problem {
            lines.push(p.clone());
        }
        if let Some(pm) = &self.problem_mark {
            lines.push(pm.to_string());
        }
        if let Some(n) = &self.note {
            lines.push(n.clone());
        }
        f.write_str(&lines.join("\n"))
    }
}

/// `yaml.reader.ReaderError` for a `str` input (a character the reader
/// does not accept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderError {
    /// `position` (code points).
    pub position: usize,
    /// `ord(character)`.
    pub character: u32,
}

impl fmt::Display for ReaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unacceptable character #x{:04x}: special characters are not allowed\n  in \"<unicode \
             string>\", position {}",
            self.character, self.position
        )
    }
}

/// A `yaml.YAMLError`.
#[derive(Debug, Clone)]
pub enum YamlError {
    /// `ReaderError`.
    Reader(ReaderError),
    /// A `MarkedYAMLError` subclass.
    Marked(Box<MarkedError>),
}

impl YamlError {
    /// `type(e).__name__`.
    pub fn class(&self) -> &'static str {
        match self {
            YamlError::Reader(_) => "ReaderError",
            YamlError::Marked(m) => m.kind.name(),
        }
    }

    /// `getattr(e, "problem", e)` as an f-string prints it: the problem of
    /// a marked error (`None` prints as `None`), the whole text of a reader
    /// error.
    pub fn problem_text(&self) -> String {
        match self {
            YamlError::Reader(r) => r.to_string(),
            YamlError::Marked(m) => m.problem.clone().unwrap_or_else(|| "None".into()),
        }
    }

    /// The 1-based line of `problem_mark`, if there is one.
    pub fn problem_line(&self) -> Option<usize> {
        match self {
            YamlError::Reader(_) => None,
            YamlError::Marked(m) => m.problem_mark.as_ref().map(|mk| mk.line + 1),
        }
    }
}

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            YamlError::Reader(r) => r.fmt(f),
            YamlError::Marked(m) => m.fmt(f),
        }
    }
}

/// A Python exception the loader let escape (not a `YAMLError`): `int()`'s
/// and `datetime`'s `ValueError`s, the bool table's `KeyError`, `value[0]`'s
/// `IndexError`, …
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyException {
    /// `type(e).__name__`.
    pub class: &'static str,
    /// `str(e)`.
    pub message: String,
}

impl PyException {
    pub(crate) fn new(class: &'static str, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
        }
    }

    pub(crate) fn value_error(message: impl Into<String>) -> Self {
        Self::new("ValueError", message)
    }

    /// `isinstance(e, ValueError)`.
    pub fn is_value_error(&self) -> bool {
        matches!(self.class, "ValueError" | "UnicodeDecodeError")
    }
}

/// What `yaml.safe_load` raised.
#[derive(Debug, Clone)]
pub enum LoadError {
    /// A `yaml.YAMLError`.
    Yaml(YamlError),
    /// Anything else.
    Python(PyException),
}

impl LoadError {
    /// A state PyYAML's own code would `assert` against.
    pub(crate) fn internal(what: &str) -> Self {
        LoadError::Python(PyException::new("AssertionError", what.to_string()))
    }

    /// `type(e).__name__`.
    pub fn class(&self) -> &'static str {
        match self {
            LoadError::Yaml(y) => y.class(),
            LoadError::Python(p) => p.class,
        }
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Yaml(y) => y.fmt(f),
            LoadError::Python(p) => f.write_str(&p.message),
        }
    }
}

impl From<MarkedError> for LoadError {
    fn from(e: MarkedError) -> Self {
        LoadError::Yaml(YamlError::Marked(Box::new(e)))
    }
}

impl From<PyException> for LoadError {
    fn from(e: PyException) -> Self {
        LoadError::Python(e)
    }
}
