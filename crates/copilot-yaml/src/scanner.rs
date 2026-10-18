//! `yaml/scanner.py` and `yaml/tokens.py`, line by line: tokens are produced
//! lazily, as the parser asks for them, so an error surfaces exactly where
//! PyYAML's does.

use crate::error::{LoadError, Mark, MarkedError, MarkedKind, PyException};
use crate::reader::Reader;
use crate::repr::str_repr;

/// A directive's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectiveValue {
    /// `%YAML major.minor`: the numbers as `int()` reads their digits.
    Yaml(String, String),
    /// `%TAG handle prefix`.
    Tag(String, String),
    /// Any other directive.
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TokenKind {
    Directive {
        name: String,
        value: DirectiveValue,
    },
    DocumentStart,
    DocumentEnd,
    StreamStart,
    StreamEnd,
    BlockSequenceStart,
    BlockMappingStart,
    BlockEnd,
    FlowSequenceStart,
    FlowMappingStart,
    FlowSequenceEnd,
    FlowMappingEnd,
    Key,
    Value,
    BlockEntry,
    FlowEntry,
    Alias(String),
    Anchor(String),
    /// `(handle, suffix)`.
    Tag(Option<String>, String),
    Scalar {
        value: String,
        plain: bool,
        style: Option<char>,
    },
}

impl TokenKind {
    /// `Token.id`.
    pub(crate) fn id(&self) -> &'static str {
        match self {
            TokenKind::Directive { .. } => "<directive>",
            TokenKind::DocumentStart => "<document start>",
            TokenKind::DocumentEnd => "<document end>",
            TokenKind::StreamStart => "<stream start>",
            TokenKind::StreamEnd => "<stream end>",
            TokenKind::BlockSequenceStart => "<block sequence start>",
            TokenKind::BlockMappingStart => "<block mapping start>",
            TokenKind::BlockEnd => "<block end>",
            TokenKind::FlowSequenceStart => "[",
            TokenKind::FlowMappingStart => "{",
            TokenKind::FlowSequenceEnd => "]",
            TokenKind::FlowMappingEnd => "}",
            TokenKind::Key => "?",
            TokenKind::Value => ":",
            TokenKind::BlockEntry => "-",
            TokenKind::FlowEntry => ",",
            TokenKind::Alias(_) => "<alias>",
            TokenKind::Anchor(_) => "<anchor>",
            TokenKind::Tag(..) => "<tag>",
            TokenKind::Scalar { .. } => "<scalar>",
        }
    }
}

/// The token classes `check_token` compares against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum T {
    Directive,
    DocumentStart,
    DocumentEnd,
    StreamEnd,
    BlockSequenceStart,
    BlockMappingStart,
    BlockEnd,
    FlowSequenceStart,
    FlowMappingStart,
    FlowSequenceEnd,
    FlowMappingEnd,
    Key,
    Value,
    BlockEntry,
    FlowEntry,
    Alias,
    Anchor,
    Tag,
    Scalar,
}

impl TokenKind {
    fn is(&self, t: T) -> bool {
        matches!(
            (self, t),
            (TokenKind::Directive { .. }, T::Directive)
                | (TokenKind::DocumentStart, T::DocumentStart)
                | (TokenKind::DocumentEnd, T::DocumentEnd)
                | (TokenKind::StreamEnd, T::StreamEnd)
                | (TokenKind::BlockSequenceStart, T::BlockSequenceStart)
                | (TokenKind::BlockMappingStart, T::BlockMappingStart)
                | (TokenKind::BlockEnd, T::BlockEnd)
                | (TokenKind::FlowSequenceStart, T::FlowSequenceStart)
                | (TokenKind::FlowMappingStart, T::FlowMappingStart)
                | (TokenKind::FlowSequenceEnd, T::FlowSequenceEnd)
                | (TokenKind::FlowMappingEnd, T::FlowMappingEnd)
                | (TokenKind::Key, T::Key)
                | (TokenKind::Value, T::Value)
                | (TokenKind::BlockEntry, T::BlockEntry)
                | (TokenKind::FlowEntry, T::FlowEntry)
                | (TokenKind::Alias(_), T::Alias)
                | (TokenKind::Anchor(_), T::Anchor)
                | (TokenKind::Tag(..), T::Tag)
                | (TokenKind::Scalar { .. }, T::Scalar)
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Token {
    pub(crate) kind: TokenKind,
    pub(crate) start_mark: Mark,
    pub(crate) end_mark: Mark,
}

#[derive(Debug, Clone)]
struct SimpleKey {
    token_number: usize,
    required: bool,
    index: usize,
    line: usize,
    column: usize,
    mark: Mark,
}

type SResult<T> = Result<T, LoadError>;

fn scanner_error(
    context: Option<&str>,
    context_mark: Option<Mark>,
    problem: impl Into<String>,
    problem_mark: Mark,
) -> LoadError {
    MarkedError::new(
        MarkedKind::Scanner,
        context,
        context_mark,
        problem,
        Some(problem_mark),
    )
    .into()
}

fn char_repr(c: char) -> String {
    str_repr(&c.to_string())
}

const BLANK_OR_END: &str = "\0 \t\r\n\u{85}\u{2028}\u{2029}";
const BREAK_OR_END: &str = "\0\r\n\u{85}\u{2028}\u{2029}";
const BREAK_OR_END_SPACE: &str = "\0 \r\n\u{85}\u{2028}\u{2029}";
const BREAKS: &str = "\r\n\u{85}\u{2028}\u{2029}";

fn is_word(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'
}

fn is_hex(ch: char) -> bool {
    ch.is_ascii_hexdigit()
}

/// `yaml.scanner.Scanner`.
pub(crate) struct Scanner {
    pub(crate) r: Reader,
    done: bool,
    /// `flow_level`: Python's counter goes negative on a stray closing
    /// bracket, and a negative level counts as flow context.
    flow_level: isize,
    tokens: Vec<Token>,
    tokens_taken: usize,
    indent: isize,
    indents: Vec<isize>,
    allow_simple_key: bool,
    /// A dict keyed by flow level, in insertion order.
    possible_simple_keys: Vec<(isize, SimpleKey)>,
}

impl Scanner {
    pub(crate) fn new(r: Reader) -> Self {
        let mut s = Self {
            r,
            done: false,
            flow_level: 0,
            tokens: Vec::new(),
            tokens_taken: 0,
            indent: -1,
            indents: Vec::new(),
            allow_simple_key: true,
            possible_simple_keys: Vec::new(),
        };
        let mark = s.r.mark();
        s.tokens.push(Token {
            kind: TokenKind::StreamStart,
            start_mark: mark.clone(),
            end_mark: mark,
        });
        s
    }

    fn peek(&self, i: usize) -> char {
        self.r.peek(i)
    }

    fn mark(&self) -> Mark {
        self.r.mark()
    }

    // --- public methods -----------------------------------------------------

    pub(crate) fn check_token(&mut self, choices: &[T]) -> SResult<bool> {
        while self.need_more_tokens()? {
            self.fetch_more_tokens()?;
        }
        Ok(match self.tokens.first() {
            Some(t) => choices.is_empty() || choices.iter().any(|c| t.kind.is(*c)),
            None => false,
        })
    }

    pub(crate) fn peek_token(&mut self) -> SResult<Option<&Token>> {
        while self.need_more_tokens()? {
            self.fetch_more_tokens()?;
        }
        Ok(self.tokens.first())
    }

    pub(crate) fn get_token(&mut self) -> SResult<Option<Token>> {
        while self.need_more_tokens()? {
            self.fetch_more_tokens()?;
        }
        if self.tokens.is_empty() {
            return Ok(None);
        }
        self.tokens_taken += 1;
        Ok(Some(self.tokens.remove(0)))
    }

    // --- private methods ----------------------------------------------------

    fn need_more_tokens(&mut self) -> SResult<bool> {
        if self.done {
            return Ok(false);
        }
        if self.tokens.is_empty() {
            return Ok(true);
        }
        self.stale_possible_simple_keys()?;
        Ok(self.next_possible_simple_key() == Some(self.tokens_taken))
    }

    fn fetch_more_tokens(&mut self) -> SResult<()> {
        self.scan_to_next_token();
        self.stale_possible_simple_keys()?;
        self.unwind_indent(self.r.column as isize);
        let ch = self.peek(0);
        if ch == '\0' {
            return self.fetch_stream_end();
        }
        if ch == '%' && self.check_directive() {
            return self.fetch_directive();
        }
        if ch == '-' && self.check_document_start() {
            return self.fetch_document_indicator(TokenKind::DocumentStart);
        }
        if ch == '.' && self.check_document_end() {
            return self.fetch_document_indicator(TokenKind::DocumentEnd);
        }
        match ch {
            '[' => return self.fetch_flow_collection_start(TokenKind::FlowSequenceStart),
            '{' => return self.fetch_flow_collection_start(TokenKind::FlowMappingStart),
            ']' => return self.fetch_flow_collection_end(TokenKind::FlowSequenceEnd),
            '}' => return self.fetch_flow_collection_end(TokenKind::FlowMappingEnd),
            ',' => return self.fetch_flow_entry(),
            _ => {}
        }
        if ch == '-' && self.check_block_entry() {
            return self.fetch_block_entry();
        }
        if ch == '?' && self.check_key() {
            return self.fetch_key();
        }
        if ch == ':' && self.check_value() {
            return self.fetch_value();
        }
        match ch {
            '*' => return self.fetch_alias(),
            '&' => return self.fetch_anchor(),
            '!' => return self.fetch_tag(),
            '|' if self.flow_level == 0 => return self.fetch_block_scalar('|'),
            '>' if self.flow_level == 0 => return self.fetch_block_scalar('>'),
            '\'' => return self.fetch_flow_scalar('\''),
            '"' => return self.fetch_flow_scalar('"'),
            _ => {}
        }
        if self.check_plain() {
            return self.fetch_plain();
        }
        Err(scanner_error(
            Some("while scanning for the next token"),
            None,
            format!(
                "found character {} that cannot start any token",
                char_repr(ch)
            ),
            self.mark(),
        ))
    }

    // --- simple keys --------------------------------------------------------

    fn next_possible_simple_key(&self) -> Option<usize> {
        let mut min: Option<usize> = None;
        for (_, key) in &self.possible_simple_keys {
            if min.is_none_or(|m| key.token_number < m) {
                min = Some(key.token_number);
            }
        }
        min
    }

    fn stale_possible_simple_keys(&mut self) -> SResult<()> {
        let levels: Vec<isize> = self.possible_simple_keys.iter().map(|(l, _)| *l).collect();
        for level in levels {
            let Some(pos) = self
                .possible_simple_keys
                .iter()
                .position(|(l, _)| *l == level)
            else {
                continue;
            };
            let key = &self.possible_simple_keys[pos].1;
            if key.line != self.r.line || self.r.index - key.index > 1024 {
                if key.required {
                    return Err(scanner_error(
                        Some("while scanning a simple key"),
                        Some(key.mark.clone()),
                        "could not find expected ':'",
                        self.mark(),
                    ));
                }
                self.possible_simple_keys.remove(pos);
            }
        }
        Ok(())
    }

    fn save_possible_simple_key(&mut self) -> SResult<()> {
        let required = self.flow_level == 0 && self.indent == self.r.column as isize;
        if self.allow_simple_key {
            self.remove_possible_simple_key()?;
            let token_number = self.tokens_taken + self.tokens.len();
            let key = SimpleKey {
                token_number,
                required,
                index: self.r.index,
                line: self.r.line,
                column: self.r.column,
                mark: self.mark(),
            };
            match self
                .possible_simple_keys
                .iter()
                .position(|(l, _)| *l == self.flow_level)
            {
                Some(pos) => self.possible_simple_keys[pos].1 = key,
                None => self.possible_simple_keys.push((self.flow_level, key)),
            }
        }
        Ok(())
    }

    fn remove_possible_simple_key(&mut self) -> SResult<()> {
        if let Some(pos) = self
            .possible_simple_keys
            .iter()
            .position(|(l, _)| *l == self.flow_level)
        {
            let key = &self.possible_simple_keys[pos].1;
            if key.required {
                return Err(scanner_error(
                    Some("while scanning a simple key"),
                    Some(key.mark.clone()),
                    "could not find expected ':'",
                    self.mark(),
                ));
            }
            self.possible_simple_keys.remove(pos);
        }
        Ok(())
    }

    // --- indentation --------------------------------------------------------

    fn unwind_indent(&mut self, column: isize) {
        if self.flow_level != 0 {
            return;
        }
        while self.indent > column {
            let mark = self.mark();
            self.indent = self.indents.pop().unwrap_or(-1);
            self.tokens.push(Token {
                kind: TokenKind::BlockEnd,
                start_mark: mark.clone(),
                end_mark: mark,
            });
        }
    }

    fn add_indent(&mut self, column: isize) -> bool {
        if self.indent < column {
            self.indents.push(self.indent);
            self.indent = column;
            return true;
        }
        false
    }

    // --- fetchers -----------------------------------------------------------

    fn push(&mut self, kind: TokenKind, start_mark: Mark, end_mark: Mark) {
        self.tokens.push(Token {
            kind,
            start_mark,
            end_mark,
        });
    }

    fn fetch_stream_end(&mut self) -> SResult<()> {
        self.unwind_indent(-1);
        self.remove_possible_simple_key()?;
        self.allow_simple_key = false;
        self.possible_simple_keys.clear();
        let mark = self.mark();
        self.push(TokenKind::StreamEnd, mark.clone(), mark);
        self.done = true;
        Ok(())
    }

    fn fetch_directive(&mut self) -> SResult<()> {
        self.unwind_indent(-1);
        self.remove_possible_simple_key()?;
        self.allow_simple_key = false;
        let token = self.scan_directive()?;
        self.tokens.push(token);
        Ok(())
    }

    fn fetch_document_indicator(&mut self, kind: TokenKind) -> SResult<()> {
        self.unwind_indent(-1);
        self.remove_possible_simple_key()?;
        self.allow_simple_key = false;
        let start_mark = self.mark();
        self.r.forward(3);
        let end_mark = self.mark();
        self.push(kind, start_mark, end_mark);
        Ok(())
    }

    fn fetch_flow_collection_start(&mut self, kind: TokenKind) -> SResult<()> {
        self.save_possible_simple_key()?;
        self.flow_level += 1;
        self.allow_simple_key = true;
        let start_mark = self.mark();
        self.r.forward(1);
        let end_mark = self.mark();
        self.push(kind, start_mark, end_mark);
        Ok(())
    }

    fn fetch_flow_collection_end(&mut self, kind: TokenKind) -> SResult<()> {
        self.remove_possible_simple_key()?;
        self.flow_level -= 1;
        self.allow_simple_key = false;
        let start_mark = self.mark();
        self.r.forward(1);
        let end_mark = self.mark();
        self.push(kind, start_mark, end_mark);
        Ok(())
    }

    fn fetch_flow_entry(&mut self) -> SResult<()> {
        self.allow_simple_key = true;
        self.remove_possible_simple_key()?;
        let start_mark = self.mark();
        self.r.forward(1);
        let end_mark = self.mark();
        self.push(TokenKind::FlowEntry, start_mark, end_mark);
        Ok(())
    }

    fn fetch_block_entry(&mut self) -> SResult<()> {
        if self.flow_level == 0 {
            if !self.allow_simple_key {
                return Err(scanner_error(
                    None,
                    None,
                    "sequence entries are not allowed here",
                    self.mark(),
                ));
            }
            if self.add_indent(self.r.column as isize) {
                let mark = self.mark();
                self.push(TokenKind::BlockSequenceStart, mark.clone(), mark);
            }
        }
        self.allow_simple_key = true;
        self.remove_possible_simple_key()?;
        let start_mark = self.mark();
        self.r.forward(1);
        let end_mark = self.mark();
        self.push(TokenKind::BlockEntry, start_mark, end_mark);
        Ok(())
    }

    fn fetch_key(&mut self) -> SResult<()> {
        if self.flow_level == 0 {
            if !self.allow_simple_key {
                return Err(scanner_error(
                    None,
                    None,
                    "mapping keys are not allowed here",
                    self.mark(),
                ));
            }
            if self.add_indent(self.r.column as isize) {
                let mark = self.mark();
                self.push(TokenKind::BlockMappingStart, mark.clone(), mark);
            }
        }
        self.allow_simple_key = self.flow_level == 0;
        self.remove_possible_simple_key()?;
        let start_mark = self.mark();
        self.r.forward(1);
        let end_mark = self.mark();
        self.push(TokenKind::Key, start_mark, end_mark);
        Ok(())
    }

    fn fetch_value(&mut self) -> SResult<()> {
        if let Some(pos) = self
            .possible_simple_keys
            .iter()
            .position(|(l, _)| *l == self.flow_level)
        {
            let (_, key) = self.possible_simple_keys.remove(pos);
            let at = key.token_number - self.tokens_taken;
            self.tokens.insert(
                at,
                Token {
                    kind: TokenKind::Key,
                    start_mark: key.mark.clone(),
                    end_mark: key.mark.clone(),
                },
            );
            if self.flow_level == 0 && self.add_indent(key.column as isize) {
                self.tokens.insert(
                    at,
                    Token {
                        kind: TokenKind::BlockMappingStart,
                        start_mark: key.mark.clone(),
                        end_mark: key.mark,
                    },
                );
            }
            self.allow_simple_key = false;
        } else {
            if self.flow_level == 0 && !self.allow_simple_key {
                return Err(scanner_error(
                    None,
                    None,
                    "mapping values are not allowed here",
                    self.mark(),
                ));
            }
            if self.flow_level == 0 && self.add_indent(self.r.column as isize) {
                let mark = self.mark();
                self.push(TokenKind::BlockMappingStart, mark.clone(), mark);
            }
            self.allow_simple_key = self.flow_level == 0;
            self.remove_possible_simple_key()?;
        }
        let start_mark = self.mark();
        self.r.forward(1);
        let end_mark = self.mark();
        self.push(TokenKind::Value, start_mark, end_mark);
        Ok(())
    }

    fn fetch_alias(&mut self) -> SResult<()> {
        self.save_possible_simple_key()?;
        self.allow_simple_key = false;
        let token = self.scan_anchor(true)?;
        self.tokens.push(token);
        Ok(())
    }

    fn fetch_anchor(&mut self) -> SResult<()> {
        self.save_possible_simple_key()?;
        self.allow_simple_key = false;
        let token = self.scan_anchor(false)?;
        self.tokens.push(token);
        Ok(())
    }

    fn fetch_tag(&mut self) -> SResult<()> {
        self.save_possible_simple_key()?;
        self.allow_simple_key = false;
        let token = self.scan_tag()?;
        self.tokens.push(token);
        Ok(())
    }

    fn fetch_block_scalar(&mut self, style: char) -> SResult<()> {
        self.allow_simple_key = true;
        self.remove_possible_simple_key()?;
        let token = self.scan_block_scalar(style)?;
        self.tokens.push(token);
        Ok(())
    }

    fn fetch_flow_scalar(&mut self, style: char) -> SResult<()> {
        self.save_possible_simple_key()?;
        self.allow_simple_key = false;
        let token = self.scan_flow_scalar(style)?;
        self.tokens.push(token);
        Ok(())
    }

    fn fetch_plain(&mut self) -> SResult<()> {
        self.save_possible_simple_key()?;
        self.allow_simple_key = false;
        let token = self.scan_plain()?;
        self.tokens.push(token);
        Ok(())
    }

    // --- checkers -----------------------------------------------------------

    fn check_directive(&self) -> bool {
        self.r.column == 0
    }

    fn check_document_start(&self) -> bool {
        self.r.column == 0 && self.r.prefix(3) == "---" && BLANK_OR_END.contains(self.peek(3))
    }

    fn check_document_end(&self) -> bool {
        self.r.column == 0 && self.r.prefix(3) == "..." && BLANK_OR_END.contains(self.peek(3))
    }

    fn check_block_entry(&self) -> bool {
        BLANK_OR_END.contains(self.peek(1))
    }

    fn check_key(&self) -> bool {
        self.flow_level != 0 || BLANK_OR_END.contains(self.peek(1))
    }

    fn check_value(&self) -> bool {
        self.flow_level != 0 || BLANK_OR_END.contains(self.peek(1))
    }

    fn check_plain(&self) -> bool {
        let ch = self.peek(0);
        !"\0 \t\r\n\u{85}\u{2028}\u{2029}-?:,[]{}#&*!|>'\"%@`".contains(ch)
            || (!BLANK_OR_END.contains(self.peek(1))
                && (ch == '-' || (self.flow_level == 0 && "?:".contains(ch))))
    }

    // --- scanners -----------------------------------------------------------

    fn scan_to_next_token(&mut self) {
        if self.r.index == 0 && self.peek(0) == '\u{FEFF}' {
            self.r.forward(1);
        }
        let mut found = false;
        while !found {
            while self.peek(0) == ' ' {
                self.r.forward(1);
            }
            if self.peek(0) == '#' {
                while !BREAK_OR_END.contains(self.peek(0)) {
                    self.r.forward(1);
                }
            }
            if !self.scan_line_break().is_empty() {
                if self.flow_level == 0 {
                    self.allow_simple_key = true;
                }
            } else {
                found = true;
            }
        }
    }

    fn scan_directive(&mut self) -> SResult<Token> {
        let start_mark = self.mark();
        self.r.forward(1);
        let name = self.scan_directive_name(&start_mark)?;
        let value;
        let end_mark;
        if name == "YAML" {
            let (major, minor) = self.scan_yaml_directive_value(&start_mark)?;
            value = DirectiveValue::Yaml(major, minor);
            end_mark = self.mark();
        } else if name == "TAG" {
            let (handle, prefix) = self.scan_tag_directive_value(&start_mark)?;
            value = DirectiveValue::Tag(handle, prefix);
            end_mark = self.mark();
        } else {
            value = DirectiveValue::None;
            end_mark = self.mark();
            while !BREAK_OR_END.contains(self.peek(0)) {
                self.r.forward(1);
            }
        }
        self.scan_directive_ignored_line(&start_mark)?;
        Ok(Token {
            kind: TokenKind::Directive { name, value },
            start_mark,
            end_mark,
        })
    }

    fn directive_error(&self, start_mark: &Mark, problem: String) -> LoadError {
        scanner_error(
            Some("while scanning a directive"),
            Some(start_mark.clone()),
            problem,
            self.mark(),
        )
    }

    fn scan_directive_name(&mut self, start_mark: &Mark) -> SResult<String> {
        let mut length = 0;
        let mut ch = self.peek(length);
        while is_word(ch) {
            length += 1;
            ch = self.peek(length);
        }
        if length == 0 {
            return Err(self.directive_error(
                start_mark,
                format!(
                    "expected alphabetic or numeric character, but found {}",
                    char_repr(ch)
                ),
            ));
        }
        let value = self.r.prefix(length);
        self.r.forward(length);
        let ch = self.peek(0);
        if !BREAK_OR_END_SPACE.contains(ch) {
            return Err(self.directive_error(
                start_mark,
                format!(
                    "expected alphabetic or numeric character, but found {}",
                    char_repr(ch)
                ),
            ));
        }
        Ok(value)
    }

    fn scan_yaml_directive_value(&mut self, start_mark: &Mark) -> SResult<(String, String)> {
        while self.peek(0) == ' ' {
            self.r.forward(1);
        }
        let major = self.scan_yaml_directive_number(start_mark)?;
        if self.peek(0) != '.' {
            return Err(self.directive_error(
                start_mark,
                format!(
                    "expected a digit or '.', but found {}",
                    char_repr(self.peek(0))
                ),
            ));
        }
        self.r.forward(1);
        let minor = self.scan_yaml_directive_number(start_mark)?;
        if !BREAK_OR_END_SPACE.contains(self.peek(0)) {
            return Err(self.directive_error(
                start_mark,
                format!(
                    "expected a digit or ' ', but found {}",
                    char_repr(self.peek(0))
                ),
            ));
        }
        Ok((major, minor))
    }

    fn scan_yaml_directive_number(&mut self, start_mark: &Mark) -> SResult<String> {
        let ch = self.peek(0);
        if !ch.is_ascii_digit() {
            return Err(self.directive_error(
                start_mark,
                format!("expected a digit, but found {}", char_repr(ch)),
            ));
        }
        let mut length = 0;
        while self.peek(length).is_ascii_digit() {
            length += 1;
        }
        let digits = self.r.prefix(length);
        self.r.forward(length);
        let trimmed = digits.trim_start_matches('0');
        Ok(if trimmed.is_empty() {
            "0".to_string()
        } else {
            trimmed.to_string()
        })
    }

    fn scan_tag_directive_value(&mut self, start_mark: &Mark) -> SResult<(String, String)> {
        while self.peek(0) == ' ' {
            self.r.forward(1);
        }
        let handle = self.scan_tag_handle("directive", start_mark)?;
        if self.peek(0) != ' ' {
            return Err(self.directive_error(
                start_mark,
                format!("expected ' ', but found {}", char_repr(self.peek(0))),
            ));
        }
        while self.peek(0) == ' ' {
            self.r.forward(1);
        }
        let prefix = self.scan_tag_uri("directive", start_mark)?;
        if !BREAK_OR_END_SPACE.contains(self.peek(0)) {
            return Err(self.directive_error(
                start_mark,
                format!("expected ' ', but found {}", char_repr(self.peek(0))),
            ));
        }
        Ok((handle, prefix))
    }

    fn scan_directive_ignored_line(&mut self, start_mark: &Mark) -> SResult<()> {
        while self.peek(0) == ' ' {
            self.r.forward(1);
        }
        if self.peek(0) == '#' {
            while !BREAK_OR_END.contains(self.peek(0)) {
                self.r.forward(1);
            }
        }
        let ch = self.peek(0);
        if !BREAK_OR_END.contains(ch) {
            return Err(self.directive_error(
                start_mark,
                format!(
                    "expected a comment or a line break, but found {}",
                    char_repr(ch)
                ),
            ));
        }
        self.scan_line_break();
        Ok(())
    }

    fn scan_anchor(&mut self, alias: bool) -> SResult<Token> {
        let start_mark = self.mark();
        let name = if alias { "alias" } else { "anchor" };
        self.r.forward(1);
        let mut length = 0;
        let mut ch = self.peek(length);
        while is_word(ch) {
            length += 1;
            ch = self.peek(length);
        }
        let error = |s: &Self, ch: char| {
            scanner_error(
                Some(&format!("while scanning an {name}")),
                Some(start_mark.clone()),
                format!(
                    "expected alphabetic or numeric character, but found {}",
                    char_repr(ch)
                ),
                s.mark(),
            )
        };
        if length == 0 {
            return Err(error(self, ch));
        }
        let value = self.r.prefix(length);
        self.r.forward(length);
        let ch = self.peek(0);
        if !"\0 \t\r\n\u{85}\u{2028}\u{2029}?:,]}%@`".contains(ch) {
            return Err(error(self, ch));
        }
        let end_mark = self.mark();
        Ok(Token {
            kind: if alias {
                TokenKind::Alias(value)
            } else {
                TokenKind::Anchor(value)
            },
            start_mark,
            end_mark,
        })
    }

    fn scan_tag(&mut self) -> SResult<Token> {
        let start_mark = self.mark();
        let mut ch = self.peek(1);
        let handle;
        let suffix;
        if ch == '<' {
            handle = None;
            self.r.forward(2);
            suffix = self.scan_tag_uri("tag", &start_mark)?;
            if self.peek(0) != '>' {
                return Err(scanner_error(
                    Some("while parsing a tag"),
                    Some(start_mark.clone()),
                    format!("expected '>', but found {}", char_repr(self.peek(0))),
                    self.mark(),
                ));
            }
            self.r.forward(1);
        } else if BLANK_OR_END.contains(ch) {
            handle = None;
            suffix = "!".to_string();
            self.r.forward(1);
        } else {
            let mut length = 1;
            let mut use_handle = false;
            while !BREAK_OR_END_SPACE.contains(ch) {
                if ch == '!' {
                    use_handle = true;
                    break;
                }
                length += 1;
                ch = self.peek(length);
            }
            if use_handle {
                handle = Some(self.scan_tag_handle("tag", &start_mark)?);
            } else {
                handle = Some("!".to_string());
                self.r.forward(1);
            }
            suffix = self.scan_tag_uri("tag", &start_mark)?;
        }
        let ch = self.peek(0);
        if !BREAK_OR_END_SPACE.contains(ch) {
            return Err(scanner_error(
                Some("while scanning a tag"),
                Some(start_mark),
                format!("expected ' ', but found {}", char_repr(ch)),
                self.mark(),
            ));
        }
        let end_mark = self.mark();
        Ok(Token {
            kind: TokenKind::Tag(handle, suffix),
            start_mark,
            end_mark,
        })
    }

    fn scan_block_scalar(&mut self, style: char) -> SResult<Token> {
        let folded = style == '>';
        let mut chunks = String::new();
        let start_mark = self.mark();
        self.r.forward(1);
        let (chomping, increment) = self.scan_block_scalar_indicators(&start_mark)?;
        self.scan_block_scalar_ignored_line(&start_mark)?;
        let mut min_indent = self.indent + 1;
        if min_indent < 1 {
            min_indent = 1;
        }
        let indent: isize;
        let (mut breaks, mut end_mark) = match increment {
            None => {
                let (breaks, max_indent, end_mark) = self.scan_block_scalar_indentation();
                indent = min_indent.max(max_indent as isize);
                (breaks, end_mark)
            }
            Some(inc) => {
                indent = min_indent + inc as isize - 1;
                self.scan_block_scalar_breaks(indent)
            }
        };
        let mut line_break = String::new();
        while self.r.column as isize == indent && self.peek(0) != '\0' {
            chunks.push_str(&breaks.concat());
            let leading_non_space = !" \t".contains(self.peek(0));
            let mut length = 0;
            while !BREAK_OR_END.contains(self.peek(length)) {
                length += 1;
            }
            chunks.push_str(&self.r.prefix(length));
            self.r.forward(length);
            line_break = self.scan_line_break();
            let (b, m) = self.scan_block_scalar_breaks(indent);
            breaks = b;
            end_mark = m;
            if self.r.column as isize == indent && self.peek(0) != '\0' {
                if folded
                    && line_break == "\n"
                    && leading_non_space
                    && !" \t".contains(self.peek(0))
                {
                    if breaks.is_empty() {
                        chunks.push(' ');
                    }
                } else {
                    chunks.push_str(&line_break);
                }
            } else {
                break;
            }
        }
        if chomping != Some(false) {
            chunks.push_str(&line_break);
        }
        if chomping == Some(true) {
            chunks.push_str(&breaks.concat());
        }
        Ok(Token {
            kind: TokenKind::Scalar {
                value: chunks,
                plain: false,
                style: Some(style),
            },
            start_mark,
            end_mark,
        })
    }

    fn block_error(&self, start_mark: &Mark, problem: String) -> LoadError {
        scanner_error(
            Some("while scanning a block scalar"),
            Some(start_mark.clone()),
            problem,
            self.mark(),
        )
    }

    fn scan_block_scalar_indicators(
        &mut self,
        start_mark: &Mark,
    ) -> SResult<(Option<bool>, Option<u32>)> {
        let mut chomping = None;
        let mut increment = None;
        let mut ch = self.peek(0);
        if ch == '+' || ch == '-' {
            chomping = Some(ch == '+');
            self.r.forward(1);
            ch = self.peek(0);
            if ch.is_ascii_digit() {
                let inc = ch as u32 - '0' as u32;
                if inc == 0 {
                    return Err(self.block_error(
                        start_mark,
                        "expected indentation indicator in the range 1-9, but found 0".into(),
                    ));
                }
                increment = Some(inc);
                self.r.forward(1);
            }
        } else if ch.is_ascii_digit() {
            let inc = ch as u32 - '0' as u32;
            if inc == 0 {
                return Err(self.block_error(
                    start_mark,
                    "expected indentation indicator in the range 1-9, but found 0".into(),
                ));
            }
            increment = Some(inc);
            self.r.forward(1);
            ch = self.peek(0);
            if ch == '+' || ch == '-' {
                chomping = Some(ch == '+');
                self.r.forward(1);
            }
        }
        let ch = self.peek(0);
        if !BREAK_OR_END_SPACE.contains(ch) {
            return Err(self.block_error(
                start_mark,
                format!(
                    "expected chomping or indentation indicators, but found {}",
                    char_repr(ch)
                ),
            ));
        }
        Ok((chomping, increment))
    }

    fn scan_block_scalar_ignored_line(&mut self, start_mark: &Mark) -> SResult<()> {
        while self.peek(0) == ' ' {
            self.r.forward(1);
        }
        if self.peek(0) == '#' {
            while !BREAK_OR_END.contains(self.peek(0)) {
                self.r.forward(1);
            }
        }
        let ch = self.peek(0);
        if !BREAK_OR_END.contains(ch) {
            return Err(self.block_error(
                start_mark,
                format!(
                    "expected a comment or a line break, but found {}",
                    char_repr(ch)
                ),
            ));
        }
        self.scan_line_break();
        Ok(())
    }

    fn scan_block_scalar_indentation(&mut self) -> (Vec<String>, usize, Mark) {
        let mut chunks = Vec::new();
        let mut max_indent = 0;
        let mut end_mark = self.mark();
        while " \r\n\u{85}\u{2028}\u{2029}".contains(self.peek(0)) {
            if self.peek(0) != ' ' {
                chunks.push(self.scan_line_break());
                end_mark = self.mark();
            } else {
                self.r.forward(1);
                if self.r.column > max_indent {
                    max_indent = self.r.column;
                }
            }
        }
        (chunks, max_indent, end_mark)
    }

    fn scan_block_scalar_breaks(&mut self, indent: isize) -> (Vec<String>, Mark) {
        let mut chunks = Vec::new();
        let mut end_mark = self.mark();
        while (self.r.column as isize) < indent && self.peek(0) == ' ' {
            self.r.forward(1);
        }
        while BREAKS.contains(self.peek(0)) {
            chunks.push(self.scan_line_break());
            end_mark = self.mark();
            while (self.r.column as isize) < indent && self.peek(0) == ' ' {
                self.r.forward(1);
            }
        }
        (chunks, end_mark)
    }

    fn scan_flow_scalar(&mut self, style: char) -> SResult<Token> {
        let double = style == '"';
        let mut chunks = String::new();
        let start_mark = self.mark();
        let quote = self.peek(0);
        self.r.forward(1);
        self.scan_flow_scalar_non_spaces(double, &start_mark, &mut chunks)?;
        while self.peek(0) != quote {
            self.scan_flow_scalar_spaces(double, &start_mark, &mut chunks)?;
            self.scan_flow_scalar_non_spaces(double, &start_mark, &mut chunks)?;
        }
        self.r.forward(1);
        let end_mark = self.mark();
        Ok(Token {
            kind: TokenKind::Scalar {
                value: chunks,
                plain: false,
                style: Some(style),
            },
            start_mark,
            end_mark,
        })
    }

    fn scan_flow_scalar_non_spaces(
        &mut self,
        double: bool,
        start_mark: &Mark,
        chunks: &mut String,
    ) -> SResult<()> {
        loop {
            let mut length = 0;
            while !"'\"\\\0 \t\r\n\u{85}\u{2028}\u{2029}".contains(self.peek(length)) {
                length += 1;
            }
            if length > 0 {
                chunks.push_str(&self.r.prefix(length));
                self.r.forward(length);
            }
            let ch = self.peek(0);
            if !double && ch == '\'' && self.peek(1) == '\'' {
                chunks.push('\'');
                self.r.forward(2);
            } else if (double && ch == '\'') || (!double && (ch == '"' || ch == '\\')) {
                chunks.push(ch);
                self.r.forward(1);
            } else if double && ch == '\\' {
                self.r.forward(1);
                let ch = self.peek(0);
                if let Some(rep) = escape_replacement(ch) {
                    chunks.push(rep);
                    self.r.forward(1);
                } else if let Some(length) = escape_code_length(ch) {
                    self.r.forward(1);
                    for k in 0..length {
                        if !is_hex(self.peek(k)) {
                            return Err(scanner_error(
                                Some("while scanning a double-quoted scalar"),
                                Some(start_mark.clone()),
                                format!(
                                    "expected escape sequence of {length} hexadecimal numbers, \
                                     but found {}",
                                    char_repr(self.peek(k))
                                ),
                                self.mark(),
                            ));
                        }
                    }
                    let code = u32::from_str_radix(&self.r.prefix(length), 16).unwrap_or(0);
                    match char::from_u32(code) {
                        Some(c) => chunks.push(c),
                        // A lone surrogate: Python keeps it; a Rust string
                        // cannot (U+FFFD instead).
                        None if (0xD800..=0xDFFF).contains(&code) => chunks.push('\u{FFFD}'),
                        None => {
                            return Err(PyException::value_error(
                                "chr() arg not in range(0x110000)",
                            )
                            .into());
                        }
                    }
                    self.r.forward(length);
                } else if BREAKS.contains(ch) {
                    self.scan_line_break();
                    self.scan_flow_scalar_breaks(double, start_mark, chunks)?;
                } else {
                    return Err(scanner_error(
                        Some("while scanning a double-quoted scalar"),
                        Some(start_mark.clone()),
                        format!("found unknown escape character {}", char_repr(ch)),
                        self.mark(),
                    ));
                }
            } else {
                return Ok(());
            }
        }
    }

    fn scan_flow_scalar_spaces(
        &mut self,
        double: bool,
        start_mark: &Mark,
        chunks: &mut String,
    ) -> SResult<()> {
        let mut length = 0;
        while " \t".contains(self.peek(length)) {
            length += 1;
        }
        let whitespaces = self.r.prefix(length);
        self.r.forward(length);
        let ch = self.peek(0);
        if ch == '\0' {
            return Err(scanner_error(
                Some("while scanning a quoted scalar"),
                Some(start_mark.clone()),
                "found unexpected end of stream",
                self.mark(),
            ));
        } else if BREAKS.contains(ch) {
            let line_break = self.scan_line_break();
            let mut breaks = String::new();
            let n = self.scan_flow_scalar_breaks(double, start_mark, &mut breaks)?;
            if line_break != "\n" {
                chunks.push_str(&line_break);
            } else if n == 0 {
                chunks.push(' ');
            }
            chunks.push_str(&breaks);
        } else {
            chunks.push_str(&whitespaces);
        }
        Ok(())
    }

    /// The breaks appended to `chunks`; returns how many.
    fn scan_flow_scalar_breaks(
        &mut self,
        _double: bool,
        start_mark: &Mark,
        chunks: &mut String,
    ) -> SResult<usize> {
        let mut n = 0;
        loop {
            let prefix = self.r.prefix(3);
            if (prefix == "---" || prefix == "...") && BLANK_OR_END.contains(self.peek(3)) {
                return Err(scanner_error(
                    Some("while scanning a quoted scalar"),
                    Some(start_mark.clone()),
                    "found unexpected document separator",
                    self.mark(),
                ));
            }
            while " \t".contains(self.peek(0)) {
                self.r.forward(1);
            }
            if BREAKS.contains(self.peek(0)) {
                chunks.push_str(&self.scan_line_break());
                n += 1;
            } else {
                return Ok(n);
            }
        }
    }

    fn scan_plain(&mut self) -> SResult<Token> {
        let mut chunks = String::new();
        let start_mark = self.mark();
        let mut end_mark = start_mark.clone();
        let indent = self.indent + 1;
        let mut spaces: Vec<String> = Vec::new();
        loop {
            let mut length = 0;
            if self.peek(0) == '#' {
                break;
            }
            loop {
                let ch = self.peek(length);
                let after = self.peek(length + 1);
                if BLANK_OR_END.contains(ch)
                    || (ch == ':'
                        && (BLANK_OR_END.contains(after)
                            || (self.flow_level != 0 && ",[]{}".contains(after))))
                    || (self.flow_level != 0 && ",?[]{}".contains(ch))
                {
                    break;
                }
                length += 1;
            }
            if length == 0 {
                break;
            }
            self.allow_simple_key = false;
            chunks.push_str(&spaces.concat());
            chunks.push_str(&self.r.prefix(length));
            self.r.forward(length);
            end_mark = self.mark();
            match self.scan_plain_spaces() {
                None => break,
                Some(s) => {
                    spaces = s;
                    if spaces.is_empty()
                        || self.peek(0) == '#'
                        || (self.flow_level == 0 && (self.r.column as isize) < indent)
                    {
                        break;
                    }
                }
            }
        }
        Ok(Token {
            kind: TokenKind::Scalar {
                value: chunks,
                plain: true,
                style: None,
            },
            start_mark,
            end_mark,
        })
    }

    /// `None` is Python's bare `return` (a document separator follows).
    fn scan_plain_spaces(&mut self) -> Option<Vec<String>> {
        let mut chunks = Vec::new();
        let mut length = 0;
        while self.peek(length) == ' ' {
            length += 1;
        }
        let whitespaces = self.r.prefix(length);
        self.r.forward(length);
        let ch = self.peek(0);
        if BREAKS.contains(ch) {
            let line_break = self.scan_line_break();
            self.allow_simple_key = true;
            let prefix = self.r.prefix(3);
            if (prefix == "---" || prefix == "...") && BLANK_OR_END.contains(self.peek(3)) {
                return None;
            }
            let mut breaks = Vec::new();
            while " \r\n\u{85}\u{2028}\u{2029}".contains(self.peek(0)) {
                if self.peek(0) == ' ' {
                    self.r.forward(1);
                } else {
                    breaks.push(self.scan_line_break());
                    let prefix = self.r.prefix(3);
                    if (prefix == "---" || prefix == "...") && BLANK_OR_END.contains(self.peek(3)) {
                        return None;
                    }
                }
            }
            if line_break != "\n" {
                chunks.push(line_break);
            } else if breaks.is_empty() {
                chunks.push(" ".to_string());
            }
            chunks.extend(breaks);
        } else if !whitespaces.is_empty() {
            chunks.push(whitespaces);
        }
        Some(chunks)
    }

    fn scan_tag_handle(&mut self, name: &str, start_mark: &Mark) -> SResult<String> {
        let ch = self.peek(0);
        if ch != '!' {
            return Err(scanner_error(
                Some(&format!("while scanning a {name}")),
                Some(start_mark.clone()),
                format!("expected '!', but found {}", char_repr(ch)),
                self.mark(),
            ));
        }
        let mut length = 1;
        let mut ch = self.peek(length);
        if ch != ' ' {
            while is_word(ch) {
                length += 1;
                ch = self.peek(length);
            }
            if ch != '!' {
                self.r.forward(length);
                return Err(scanner_error(
                    Some(&format!("while scanning a {name}")),
                    Some(start_mark.clone()),
                    format!("expected '!', but found {}", char_repr(ch)),
                    self.mark(),
                ));
            }
            length += 1;
        }
        let value = self.r.prefix(length);
        self.r.forward(length);
        Ok(value)
    }

    fn scan_tag_uri(&mut self, name: &str, start_mark: &Mark) -> SResult<String> {
        let mut chunks = String::new();
        let mut any = false;
        let mut length = 0;
        let mut ch = self.peek(length);
        while ch.is_ascii_alphanumeric() || "-;/?:@&=+$,_.!~*'()[]%".contains(ch) {
            if ch == '%' {
                chunks.push_str(&self.r.prefix(length));
                self.r.forward(length);
                length = 0;
                chunks.push_str(&self.scan_uri_escapes(name, start_mark)?);
                any = true;
            } else {
                length += 1;
            }
            ch = self.peek(length);
        }
        if length > 0 {
            chunks.push_str(&self.r.prefix(length));
            self.r.forward(length);
            any = true;
        }
        if !any {
            return Err(scanner_error(
                Some(&format!("while parsing a {name}")),
                Some(start_mark.clone()),
                format!("expected URI, but found {}", char_repr(ch)),
                self.mark(),
            ));
        }
        Ok(chunks)
    }

    fn scan_uri_escapes(&mut self, name: &str, start_mark: &Mark) -> SResult<String> {
        let mut codes: Vec<u8> = Vec::new();
        let mark = self.mark();
        while self.peek(0) == '%' {
            self.r.forward(1);
            for k in 0..2 {
                if !is_hex(self.peek(k)) {
                    return Err(scanner_error(
                        Some(&format!("while scanning a {name}")),
                        Some(start_mark.clone()),
                        format!(
                            "expected URI escape sequence of 2 hexadecimal numbers, but found {}",
                            char_repr(self.peek(k))
                        ),
                        self.mark(),
                    ));
                }
            }
            codes.push(u8::from_str_radix(&self.r.prefix(2), 16).unwrap_or(0));
            self.r.forward(2);
        }
        match String::from_utf8(codes.clone()) {
            Ok(s) => Ok(s),
            Err(_) => Err(scanner_error(
                Some(&format!("while scanning a {name}")),
                Some(start_mark.clone()),
                crate::pyint::utf8_decode_error(&codes),
                mark,
            )),
        }
    }

    fn scan_line_break(&mut self) -> String {
        let ch = self.peek(0);
        if "\r\n\u{85}".contains(ch) {
            if self.r.prefix(2) == "\r\n" {
                self.r.forward(2);
            } else {
                self.r.forward(1);
            }
            return "\n".into();
        }
        if ch == '\u{2028}' || ch == '\u{2029}' {
            self.r.forward(1);
            return ch.to_string();
        }
        String::new()
    }
}

fn escape_replacement(ch: char) -> Option<char> {
    Some(match ch {
        '0' => '\0',
        'a' => '\x07',
        'b' => '\x08',
        't' | '\t' => '\x09',
        'n' => '\x0A',
        'v' => '\x0B',
        'f' => '\x0C',
        'r' => '\x0D',
        'e' => '\x1B',
        ' ' => ' ',
        '"' => '"',
        '\\' => '\\',
        '/' => '/',
        'N' => '\u{85}',
        '_' => '\u{A0}',
        'L' => '\u{2028}',
        'P' => '\u{2029}',
        _ => return None,
    })
}

fn escape_code_length(ch: char) -> Option<usize> {
    match ch {
        'x' => Some(2),
        'u' => Some(4),
        'U' => Some(8),
        _ => None,
    }
}
