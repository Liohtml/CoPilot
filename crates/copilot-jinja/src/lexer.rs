//! Jinja2's lexer (`jinja2/lexer.py`) for the default environment: `{% %}`,
//! `{{ }}`, `{# #}`, no line statements, no `trim_blocks`/`lstrip_blocks`, the
//! trailing newline dropped. Tokens are produced lazily, so a lexing error
//! surfaces when the parser reaches it, as in Python.

use std::collections::VecDeque;
use std::rc::Rc;

use num_bigint_dig::BigInt;
use num_traits::Zero;

use crate::error::{Error, Result};
use crate::pyrepr;
use crate::unicode;

/// A token's type and value.
#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `/`
    Div,
    /// `//`
    FloorDiv,
    /// `*`
    Mul,
    /// `%`
    Mod,
    /// `**`
    Pow,
    /// `~`
    Tilde,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `>`
    Gt,
    /// `>=`
    GtEq,
    /// `<`
    Lt,
    /// `<=`
    LtEq,
    /// `=`
    Assign,
    /// `.`
    Dot,
    /// `:`
    Colon,
    /// `|`
    Pipe,
    /// `,`
    Comma,
    /// `;`
    Semicolon,
    /// An integer literal.
    Integer(BigInt),
    /// A float literal.
    Float(f64),
    /// A name.
    Name(Rc<str>),
    /// A string literal, unescaped.
    Str(Rc<str>),
    /// Template text.
    Data(Rc<str>),
    /// `{%`
    BlockBegin,
    /// `%}`
    BlockEnd,
    /// `{{`
    VariableBegin,
    /// `}}`
    VariableEnd,
    /// Before the first token.
    Initial,
    /// The end.
    Eof,
}

impl Tok {
    /// The token's type name (`token.type`).
    pub fn type_name(&self) -> &'static str {
        match self {
            Tok::Add => "add",
            Tok::Sub => "sub",
            Tok::Div => "div",
            Tok::FloorDiv => "floordiv",
            Tok::Mul => "mul",
            Tok::Mod => "mod",
            Tok::Pow => "pow",
            Tok::Tilde => "tilde",
            Tok::LBracket => "lbracket",
            Tok::RBracket => "rbracket",
            Tok::LParen => "lparen",
            Tok::RParen => "rparen",
            Tok::LBrace => "lbrace",
            Tok::RBrace => "rbrace",
            Tok::Eq => "eq",
            Tok::Ne => "ne",
            Tok::Gt => "gt",
            Tok::GtEq => "gteq",
            Tok::Lt => "lt",
            Tok::LtEq => "lteq",
            Tok::Assign => "assign",
            Tok::Dot => "dot",
            Tok::Colon => "colon",
            Tok::Pipe => "pipe",
            Tok::Comma => "comma",
            Tok::Semicolon => "semicolon",
            Tok::Integer(_) => "integer",
            Tok::Float(_) => "float",
            Tok::Name(_) => "name",
            Tok::Str(_) => "string",
            Tok::Data(_) => "data",
            Tok::BlockBegin => "block_begin",
            Tok::BlockEnd => "block_end",
            Tok::VariableBegin => "variable_begin",
            Tok::VariableEnd => "variable_end",
            Tok::Initial => "initial",
            Tok::Eof => "eof",
        }
    }

    /// The name, for a name token.
    pub fn name(&self) -> Option<&str> {
        match self {
            Tok::Name(n) => Some(n),
            _ => None,
        }
    }

    /// `token.test("name:<value>")`.
    pub fn is_name(&self, value: &str) -> bool {
        self.name() == Some(value)
    }
}

/// A token and its line.
#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    /// The line it starts on.
    pub lineno: usize,
    /// The token.
    pub tok: Tok,
}

/// `_describe_token_type`.
pub fn describe_type(type_name: &str) -> String {
    let op = match type_name {
        "add" => "+",
        "sub" => "-",
        "div" => "/",
        "floordiv" => "//",
        "mul" => "*",
        "mod" => "%",
        "pow" => "**",
        "tilde" => "~",
        "lbracket" => "[",
        "rbracket" => "]",
        "lparen" => "(",
        "rparen" => ")",
        "lbrace" => "{",
        "rbrace" => "}",
        "eq" => "==",
        "ne" => "!=",
        "gt" => ">",
        "gteq" => ">=",
        "lt" => "<",
        "lteq" => "<=",
        "assign" => "=",
        "dot" => ".",
        "colon" => ":",
        "pipe" => "|",
        "comma" => ",",
        "semicolon" => ";",
        "comment_begin" => "begin of comment",
        "comment_end" => "end of comment",
        "comment" | "linecomment" => "comment",
        "block_begin" => "begin of statement block",
        "block_end" => "end of statement block",
        "variable_begin" => "begin of print statement",
        "variable_end" => "end of print statement",
        "linestatement_begin" => "begin of line statement",
        "linestatement_end" => "end of line statement",
        "data" => "template data / text",
        "eof" => "end of template",
        other => other,
    };
    op.to_string()
}

/// `describe_token`.
pub fn describe(tok: &Tok) -> String {
    match tok {
        Tok::Name(n) => n.to_string(),
        other => describe_type(other.type_name()),
    }
}

/// `describe_token_expr`: `"name:endfor"` → `endfor`, `"block_end"` → its text.
pub fn describe_expr(expr: &str) -> String {
    match expr.split_once(':') {
        Some(("name", value)) => value.to_string(),
        Some((ty, _)) => describe_type(ty),
        None => describe_type(expr),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Root,
    Raw,
    Comment,
    Block,
    Variable,
}

/// The lazy token generator (`Lexer.tokeniter` + `Lexer.wrap`).
pub struct Lexer {
    src: Vec<char>,
    pos: usize,
    lineno: usize,
    stack: Vec<State>,
    balancing: Vec<char>,
    pending: VecDeque<Token>,
    done: bool,
}

/// `TemplateSyntaxError` at a line (the line is not part of `str(e)` once
/// Jinja has translated the error).
fn syntax(msg: impl Into<String>) -> Error {
    Error::syntax(msg)
}

impl Lexer {
    /// A lexer over `source`.
    pub fn new(source: &str) -> Self {
        // `newline_re.split(source)[::2]`, the trailing empty line dropped.
        let mut lines: Vec<String> = Vec::new();
        let mut cur = String::new();
        let mut chars = source.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\r' => {
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    lines.push(std::mem::take(&mut cur));
                }
                '\n' => lines.push(std::mem::take(&mut cur)),
                c => cur.push(c),
            }
        }
        lines.push(cur);
        if lines.last().is_some_and(String::is_empty) {
            lines.pop();
        }
        let src: Vec<char> = lines.join("\n").chars().collect();
        Self {
            src,
            pos: 0,
            lineno: 1,
            stack: vec![State::Root],
            balancing: Vec::new(),
            pending: VecDeque::new(),
            done: false,
        }
    }

    fn at(&self, i: usize, s: &str) -> bool {
        s.chars()
            .enumerate()
            .all(|(k, c)| self.src.get(i + k) == Some(&c))
    }

    fn text(&self, a: usize, b: usize) -> String {
        self.src[a..b].iter().collect()
    }

    fn push(&mut self, tok: Tok) {
        self.pending.push_back(Token {
            lineno: self.lineno,
            tok,
        });
    }

    /// The next token, `None` at the end.
    pub fn next_token(&mut self) -> Result<Option<Token>> {
        loop {
            if let Some(t) = self.pending.pop_front() {
                return Ok(Some(t));
            }
            if self.done {
                return Ok(None);
            }
            if let Err(e) = self.step() {
                self.done = true;
                self.pending.clear();
                return Err(e);
            }
        }
    }

    /// One regex match of the current state.
    fn step(&mut self) -> Result<()> {
        match *self.stack.last().unwrap_or(&State::Root) {
            State::Root => self.step_root(),
            State::Raw => self.step_raw(),
            State::Comment => self.step_comment(),
            State::Block | State::Variable => self.step_tag(),
        }
    }

    /// `\s*` from `i`.
    fn skip_ws(&self, mut i: usize) -> usize {
        while i < self.src.len() && unicode::is_space(self.src[i]) {
            i += 1;
        }
        i
    }

    /// `(\-|\+|)` at `i`.
    fn sign(&self, i: usize) -> (char, usize) {
        match self.src.get(i) {
            Some('-') => ('-', i + 1),
            Some('+') => ('+', i + 1),
            _ => ('\0', i),
        }
    }

    /// The root rule's delimiter at `p`: (state, sign, end).
    fn delimiter_at(&self, p: usize) -> Option<(State, char, usize)> {
        if self.at(p, "{%") {
            // raw_begin: {%(\-|\+|)\s*raw\s*(?:\-%\}\s*|%\})
            let (sign, i) = self.sign(p + 2);
            let i = self.skip_ws(i);
            if self.at(i, "raw") {
                let j = self.skip_ws(i + 3);
                if self.at(j, "-%}") {
                    return Some((State::Raw, sign, self.skip_ws(j + 3)));
                }
                if self.at(j, "%}") {
                    return Some((State::Raw, sign, j + 2));
                }
            }
        }
        if self.at(p, "{{") {
            let (sign, i) = self.sign(p + 2);
            return Some((State::Variable, sign, i));
        }
        if self.at(p, "{#") {
            let (sign, i) = self.sign(p + 2);
            return Some((State::Comment, sign, i));
        }
        if self.at(p, "{%") {
            let (sign, i) = self.sign(p + 2);
            return Some((State::Block, sign, i));
        }
        None
    }

    /// Text before a tag, stripped by a `-` sign, then the line count.
    fn emit_data(&mut self, start: usize, end: usize, sign: char) {
        let mut text = self.text(start, end);
        let mut stripped_newlines = 0;
        if sign == '-' {
            let kept = text.trim_end_matches(unicode::is_space).len();
            stripped_newlines = text[kept..].matches('\n').count();
            text.truncate(kept);
        }
        if !text.is_empty() {
            let lines = text.matches('\n').count();
            self.push(Tok::Data(Rc::from(text)));
            self.lineno += lines;
        }
        self.lineno += stripped_newlines;
    }

    fn step_root(&mut self) -> Result<()> {
        if self.pos >= self.src.len() {
            self.done = true;
            return Ok(());
        }
        let mut p = self.pos;
        while p < self.src.len() {
            if let Some((state, sign, end)) = self.delimiter_at(p) {
                self.emit_data(self.pos, p, sign);
                let delim = self.text(p, end);
                match state {
                    State::Variable => self.push(Tok::VariableBegin),
                    State::Block => self.push(Tok::BlockBegin),
                    // Comment and raw begin tokens are dropped by `wrap`.
                    _ => {}
                }
                self.lineno += delim.matches('\n').count();
                self.stack.push(state);
                self.pos = end;
                return Ok(());
            }
            p += 1;
        }
        // `.+`: the rest is text.
        let rest = self.text(self.pos, self.src.len());
        let lines = rest.matches('\n').count();
        self.push(Tok::Data(Rc::from(rest)));
        self.lineno += lines;
        self.pos = self.src.len();
        Ok(())
    }

    fn step_raw(&mut self) -> Result<()> {
        // (.*?)((?:\{%(\-|\+|))\s*endraw\s*(?:\+%\}|\-%\}\s*|%\}))
        let mut p = self.pos;
        while p < self.src.len() {
            if self.at(p, "{%") {
                let (sign, i) = self.sign(p + 2);
                let i = self.skip_ws(i);
                if self.at(i, "endraw") {
                    let j = self.skip_ws(i + 6);
                    let end = if self.at(j, "+%}") {
                        Some(j + 3)
                    } else if self.at(j, "-%}") {
                        Some(self.skip_ws(j + 3))
                    } else if self.at(j, "%}") {
                        Some(j + 2)
                    } else {
                        None
                    };
                    if let Some(end) = end {
                        self.emit_data(self.pos, p, sign);
                        let tag = self.text(p, end);
                        self.lineno += tag.matches('\n').count();
                        self.stack.pop();
                        self.pos = end;
                        return Ok(());
                    }
                }
            }
            p += 1;
        }
        Err(syntax("Missing end of raw directive"))
    }

    fn step_comment(&mut self) -> Result<()> {
        // (.*?)((?:\+\#\}|\-\#\}\s*|\#\}))
        let mut p = self.pos;
        while p < self.src.len() {
            let end = if self.at(p, "+#}") {
                Some(p + 3)
            } else if self.at(p, "-#}") {
                Some(self.skip_ws(p + 3))
            } else if self.at(p, "#}") {
                Some(p + 2)
            } else {
                None
            };
            if let Some(end) = end {
                let all = self.text(self.pos, end);
                self.lineno += all.matches('\n').count();
                self.stack.pop();
                self.pos = end;
                return Ok(());
            }
            p += 1;
        }
        Err(syntax("Missing end of comment tag"))
    }

    fn step_tag(&mut self) -> Result<()> {
        let state = *self.stack.last().unwrap_or(&State::Block);
        let pos = self.pos;
        // The end of the tag, unless brackets are open.
        if self.balancing.is_empty() {
            let end = if state == State::Block {
                if self.at(pos, "+%}") {
                    Some(pos + 3)
                } else if self.at(pos, "-%}") {
                    Some(self.skip_ws(pos + 3))
                } else if self.at(pos, "%}") {
                    Some(pos + 2)
                } else {
                    None
                }
            } else if self.at(pos, "-}}") {
                Some(self.skip_ws(pos + 3))
            } else if self.at(pos, "}}") {
                Some(pos + 2)
            } else {
                None
            };
            if let Some(end) = end {
                let all = self.text(pos, end);
                self.push(if state == State::Block {
                    Tok::BlockEnd
                } else {
                    Tok::VariableEnd
                });
                self.lineno += all.matches('\n').count();
                self.stack.pop();
                self.pos = end;
                return Ok(());
            }
        }
        if pos >= self.src.len() {
            self.done = true;
            return Ok(());
        }
        // whitespace
        let ws_end = self.skip_ws(pos);
        if ws_end > pos {
            let ws = self.text(pos, ws_end);
            self.lineno += ws.matches('\n').count();
            self.pos = ws_end;
            return Ok(());
        }
        if let Some(end) = self.match_float(pos) {
            let raw: String = self.text(pos, end).replace('_', "");
            if let Some(c) = raw.chars().find(|c| !c.is_ascii()) {
                // `ast.literal_eval` rejects non-ASCII digits.
                return Err(Error::new(
                    "SyntaxError",
                    format!("invalid character '{c}' (U+{:04X})", c as u32),
                ));
            }
            let f: f64 = raw.parse().unwrap_or(f64::INFINITY);
            self.push(Tok::Float(f));
            self.pos = end;
            return Ok(());
        }
        if let Some((end, value)) = self.match_integer(pos) {
            self.push(Tok::Integer(value));
            self.pos = end;
            return Ok(());
        }
        let mut end = pos;
        while end < self.src.len() && unicode::is_name_char(self.src[end]) {
            end += 1;
        }
        if end > pos {
            let name = self.text(pos, end);
            if !unicode::is_identifier(&name) {
                return Err(syntax("Invalid character in identifier"));
            }
            self.push(Tok::Name(Rc::from(name)));
            self.pos = end;
            return Ok(());
        }
        if let Some(end) = self.match_string(pos) {
            let raw = self.text(pos + 1, end - 1);
            let lines = raw.matches('\n').count();
            let value = unescape_string(&raw)?;
            self.push(Tok::Str(Rc::from(value)));
            self.lineno += lines;
            self.pos = end;
            return Ok(());
        }
        if let Some((tok, len)) = self.match_operator(pos) {
            let c = self.src[pos];
            match c {
                '{' => self.balancing.push('}'),
                '(' => self.balancing.push(')'),
                '[' => self.balancing.push(']'),
                '}' | ')' | ']' => match self.balancing.pop() {
                    None => return Err(syntax(format!("unexpected '{c}'"))),
                    Some(expected) if expected != c => {
                        return Err(syntax(format!("unexpected '{c}', expected '{expected}'")));
                    }
                    Some(_) => {}
                },
                _ => {}
            }
            self.push(tok);
            self.pos = pos + len;
            return Ok(());
        }
        Err(syntax(format!(
            "unexpected char {} at {pos}",
            pyrepr::str_repr(&self.src[pos].to_string())
        )))
    }

    /// `(\d+_)*\d+` from `i`: the end, if at least one digit.
    fn digit_group(&self, i: usize) -> Option<usize> {
        let mut j = i;
        if !self.src.get(j).is_some_and(|c| unicode::is_decimal(*c)) {
            return None;
        }
        loop {
            while self.src.get(j).is_some_and(|c| unicode::is_decimal(*c)) {
                j += 1;
            }
            if self.src.get(j) == Some(&'_')
                && self.src.get(j + 1).is_some_and(|c| unicode::is_decimal(*c))
            {
                j += 1;
                continue;
            }
            return Some(j);
        }
    }

    fn match_float(&self, pos: usize) -> Option<usize> {
        if pos > 0 && self.src[pos - 1] == '.' {
            return None;
        }
        let int_end = self.digit_group(pos)?;
        // (\.(\d+_)*\d+)?e[+\-]?(\d+_)*\d+
        let exp_at = |i: usize| -> Option<usize> {
            if !matches!(self.src.get(i), Some('e' | 'E')) {
                return None;
            }
            let mut j = i + 1;
            if matches!(self.src.get(j), Some('+' | '-')) {
                j += 1;
            }
            self.digit_group(j)
        };
        if self.src.get(int_end) == Some(&'.') {
            if let Some(frac_end) = self.digit_group(int_end + 1) {
                if let Some(end) = exp_at(frac_end) {
                    return Some(end);
                }
            }
        }
        if let Some(end) = exp_at(int_end) {
            return Some(end);
        }
        // \.(\d+_)*\d+
        if self.src.get(int_end) == Some(&'.') {
            return self.digit_group(int_end + 1);
        }
        None
    }

    fn match_integer(&self, pos: usize) -> Option<(usize, BigInt)> {
        let c0 = *self.src.get(pos)?;
        let prefixed = |radix: u32, letter: char| -> Option<(usize, BigInt)> {
            if c0 != '0'
                || !self
                    .src
                    .get(pos + 1)
                    .is_some_and(|c| c.eq_ignore_ascii_case(&letter))
            {
                return None;
            }
            let digit = |c: char| -> Option<u32> {
                match radix {
                    16 => unicode::decimal_value(c).or_else(|| match c.to_ascii_lowercase() {
                        c @ 'a'..='f' => Some(c as u32 - 'a' as u32 + 10),
                        _ => None,
                    }),
                    _ => c.to_digit(radix),
                }
            };
            let mut j = pos + 2;
            let mut value = BigInt::zero();
            let mut any = false;
            loop {
                let k = if self.src.get(j) == Some(&'_') {
                    j + 1
                } else {
                    j
                };
                match self.src.get(k).and_then(|c| digit(*c)) {
                    Some(d) => {
                        value = value * radix + d;
                        any = true;
                        j = k + 1;
                    }
                    None => break,
                }
            }
            any.then_some((j, value))
        };
        if let Some(r) = prefixed(2, 'b')
            .or_else(|| prefixed(8, 'o'))
            .or_else(|| prefixed(16, 'x'))
        {
            return Some(r);
        }
        if ('1'..='9').contains(&c0) {
            // [1-9](_?\d)*
            let mut j = pos + 1;
            let mut value = BigInt::from(c0 as u32 - '0' as u32);
            loop {
                let k = if self.src.get(j) == Some(&'_') {
                    j + 1
                } else {
                    j
                };
                match self.src.get(k).and_then(|c| unicode::decimal_value(*c)) {
                    Some(d) => {
                        value = value * 10u32 + d;
                        j = k + 1;
                    }
                    None => break,
                }
            }
            return Some((j, value));
        }
        if c0 == '0' {
            // 0(_?0)*
            let mut j = pos + 1;
            loop {
                let k = if self.src.get(j) == Some(&'_') {
                    j + 1
                } else {
                    j
                };
                if self.src.get(k) == Some(&'0') {
                    j = k + 1;
                } else {
                    break;
                }
            }
            return Some((j, BigInt::zero()));
        }
        None
    }

    fn match_string(&self, pos: usize) -> Option<usize> {
        let quote = *self.src.get(pos)?;
        if quote != '\'' && quote != '"' {
            return None;
        }
        let mut j = pos + 1;
        while j < self.src.len() {
            match self.src[j] {
                '\\' => {
                    if j + 1 >= self.src.len() {
                        return None;
                    }
                    j += 2;
                }
                c if c == quote => return Some(j + 1),
                _ => j += 1,
            }
        }
        None
    }

    fn match_operator(&self, pos: usize) -> Option<(Tok, usize)> {
        let two = [
            ("//", Tok::FloorDiv),
            ("**", Tok::Pow),
            ("==", Tok::Eq),
            ("!=", Tok::Ne),
            (">=", Tok::GtEq),
            ("<=", Tok::LtEq),
        ];
        for (s, t) in two {
            if self.at(pos, s) {
                return Some((t, 2));
            }
        }
        let tok = match self.src[pos] {
            '+' => Tok::Add,
            '-' => Tok::Sub,
            '/' => Tok::Div,
            '*' => Tok::Mul,
            '%' => Tok::Mod,
            '~' => Tok::Tilde,
            '[' => Tok::LBracket,
            ']' => Tok::RBracket,
            '(' => Tok::LParen,
            ')' => Tok::RParen,
            '{' => Tok::LBrace,
            '}' => Tok::RBrace,
            '>' => Tok::Gt,
            '<' => Tok::Lt,
            '=' => Tok::Assign,
            '.' => Tok::Dot,
            ':' => Tok::Colon,
            '|' => Tok::Pipe,
            ',' => Tok::Comma,
            ';' => Tok::Semicolon,
            _ => return None,
        };
        Some((tok, 1))
    }
}

/// A string literal's value: `value.encode("ascii", "backslashreplace")
/// .decode("unicode-escape")`, with the decoder's reason as the error.
pub fn unescape_string(raw: &str) -> Result<String> {
    let mut ascii = String::with_capacity(raw.len());
    for c in raw.chars() {
        let n = c as u32;
        if n < 0x80 {
            ascii.push(c);
        } else if n <= 0xff {
            ascii.push_str(&format!("\\x{n:02x}"));
        } else if n <= 0xffff {
            ascii.push_str(&format!("\\u{n:04x}"));
        } else {
            ascii.push_str(&format!("\\U{n:08x}"));
        }
    }
    let b: Vec<char> = ascii.chars().collect();
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c != '\\' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        let Some(&e) = b.get(i) else {
            return Err(syntax("\\ at end of string"));
        };
        i += 1;
        match e {
            '\n' => {}
            '\\' => out.push('\\'),
            '\'' => out.push('\''),
            '"' => out.push('"'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            't' => out.push('\t'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            'v' => out.push('\u{b}'),
            'a' => out.push('\u{7}'),
            '0'..='7' => {
                let mut x = e as u32 - '0' as u32;
                for _ in 0..2 {
                    match b.get(i) {
                        Some(d @ '0'..='7') => {
                            x = x * 8 + (*d as u32 - '0' as u32);
                            i += 1;
                        }
                        _ => break,
                    }
                }
                out.push(char::from_u32(x).unwrap_or('\u{fffd}'));
            }
            'x' | 'u' | 'U' => {
                let (count, message) = match e {
                    'x' => (2, "truncated \\xXX escape"),
                    'u' => (4, "truncated \\uXXXX escape"),
                    _ => (8, "truncated \\UXXXXXXXX escape"),
                };
                let mut x: u32 = 0;
                for k in 0..count {
                    match b.get(i + k).and_then(|c| c.to_digit(16)) {
                        Some(d) => x = x.saturating_mul(16).saturating_add(d),
                        None => return Err(syntax(message)),
                    }
                }
                i += count;
                if x > 0x10ffff {
                    return Err(syntax("illegal Unicode character"));
                }
                match char::from_u32(x) {
                    Some(c) => out.push(c),
                    None => return Err(Error::unsupported("A lone surrogate in a string literal")),
                }
            }
            'N' => return Err(Error::unsupported("A \\N{...} escape in a string literal")),
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    Ok(out)
}

/// The token stream the parser reads (`TokenStream`).
pub struct TokenStream {
    lexer: Lexer,
    pushed: VecDeque<Token>,
    /// The current token.
    pub current: Token,
}

impl TokenStream {
    /// A stream positioned on the first token.
    pub fn new(source: &str) -> Result<Self> {
        let mut s = Self {
            lexer: Lexer::new(source),
            pushed: VecDeque::new(),
            current: Token {
                lineno: 1,
                tok: Tok::Initial,
            },
        };
        s.next()?;
        Ok(s)
    }

    /// `bool(stream)`: tokens are left.
    pub fn has_more(&self) -> bool {
        !self.pushed.is_empty() || self.current.tok != Tok::Eof
    }

    /// Advances, returning the token that was current.
    pub fn next(&mut self) -> Result<Token> {
        let rv = self.current.clone();
        if let Some(t) = self.pushed.pop_front() {
            self.current = t;
        } else if self.current.tok != Tok::Eof {
            match self.lexer.next_token()? {
                Some(t) => self.current = t,
                None => {
                    self.current = Token {
                        lineno: self.current.lineno,
                        tok: Tok::Eof,
                    };
                }
            }
        }
        Ok(rv)
    }

    /// `look()`: the token after the current one.
    pub fn look(&mut self) -> Result<Token> {
        let old = self.next()?;
        let result = self.current.clone();
        self.pushed.push_back(result.clone());
        self.current = old;
        Ok(result)
    }

    /// `skip(n)`.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        for _ in 0..n {
            self.next()?;
        }
        Ok(())
    }

    /// `skip_if(type)` for a token type name.
    pub fn skip_if_type(&mut self, ty: &str) -> Result<bool> {
        if self.current.tok.type_name() == ty {
            self.next()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// `skip_if("name:<value>")`.
    pub fn skip_if_name(&mut self, value: &str) -> Result<bool> {
        if self.current.tok.is_name(value) {
            self.next()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// `expect(type)`.
    pub fn expect_type(&mut self, ty: &str) -> Result<Token> {
        if self.current.tok.type_name() != ty {
            return Err(self.expect_error(&describe_expr(ty)));
        }
        self.next()
    }

    /// `expect("name:<value>")`.
    pub fn expect_name(&mut self, value: &str) -> Result<Token> {
        if !self.current.tok.is_name(value) {
            return Err(self.expect_error(value));
        }
        self.next()
    }

    fn expect_error(&self, expected: &str) -> Error {
        let expected = pyrepr::str_repr(expected);
        if self.current.tok == Tok::Eof {
            return syntax(format!("unexpected end of template, expected {expected}."));
        }
        syntax(format!(
            "expected token {expected}, got {}",
            pyrepr::str_repr(&describe(&self.current.tok))
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(src: &str) -> Vec<Tok> {
        let mut l = Lexer::new(src);
        let mut out = Vec::new();
        while let Some(t) = l.next_token().unwrap() {
            out.push(t.tok);
        }
        out
    }

    #[test]
    fn lexes_like_jinja() {
        assert_eq!(
            tokens("a {{- x }} b\n"),
            vec![
                Tok::Data(Rc::from("a")),
                Tok::VariableBegin,
                Tok::Name(Rc::from("x")),
                Tok::VariableEnd,
                Tok::Data(Rc::from(" b")),
            ]
        );
        assert_eq!(
            tokens("{{ 1_000 0x1f 1.5e3 }}"),
            vec![
                Tok::VariableBegin,
                Tok::Integer(BigInt::from(1000)),
                Tok::Integer(BigInt::from(31)),
                Tok::Float(1500.0),
                Tok::VariableEnd,
            ]
        );
        assert_eq!(
            tokens("{% raw %}{{ x }}{% endraw %}"),
            vec![Tok::Data(Rc::from("{{ x }}"))]
        );
        assert_eq!(unescape_string("a\\tb\\x41\\u00e9").unwrap(), "a\tbAé");
        assert_eq!(unescape_string("\\é").unwrap(), "\\xe9");
    }
}
