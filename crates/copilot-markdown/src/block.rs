//! The block parser (`parser_block.py`, `rules_block/*`) with the rules the
//! `gfm-like` preset enables: table, code, fence, blockquote, hr, list,
//! reference, heading, lheading and paragraph (`html_block` is enabled but
//! inert with `html=False`). Positions are code-point indices, as in Python.

use std::cell::Cell;
use std::collections::HashMap;

use crate::MAX_NESTING;
use crate::entity::unescape_all;
use crate::pystr::{is_str_space, normalize_reference, py_strip, slice};
use crate::token::Token;
use crate::url::{normalize_link, validate_link};

/// A reference definition (`env["references"][label]`).
#[derive(Debug, Clone)]
pub(crate) struct Reference {
    /// `href`.
    pub href: String,
    /// `title`.
    pub title: String,
}

/// `env`: only `references` is read back.
#[derive(Debug, Default)]
pub(crate) struct Env {
    /// `None` until the first definition (`"references" not in env`).
    pub references: Option<HashMap<String, Reference>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    Table,
    Code,
    Fence,
    Blockquote,
    Hr,
    List,
    Reference,
    Heading,
    Lheading,
    Paragraph,
}

const ALL: [Rule; 10] = [
    Rule::Table,
    Rule::Code,
    Rule::Fence,
    Rule::Blockquote,
    Rule::Hr,
    Rule::List,
    Rule::Reference,
    Rule::Heading,
    Rule::Lheading,
    Rule::Paragraph,
];
/// `getRules("paragraph")` (and `"reference"`): `html_block` left out, it
/// never matches.
const TERM_PARAGRAPH: [Rule; 6] = [
    Rule::Table,
    Rule::Fence,
    Rule::Blockquote,
    Rule::Hr,
    Rule::List,
    Rule::Heading,
];
const TERM_BLOCKQUOTE: [Rule; 5] = [
    Rule::Fence,
    Rule::Blockquote,
    Rule::Hr,
    Rule::List,
    Rule::Heading,
];
const TERM_LIST: [Rule; 3] = [Rule::Fence, Rule::Blockquote, Rule::Hr];

/// The line marks' fake last entry keeps bounds checks away, as in Python.
pub(crate) struct StateBlock<'a> {
    src: Vec<char>,
    env: &'a mut Env,
    error: &'a Cell<bool>,
    pub tokens: Vec<Token>,
    b_marks: Vec<usize>,
    e_marks: Vec<usize>,
    t_shift: Vec<usize>,
    s_count: Vec<i64>,
    bs_count: Vec<i64>,
    blk_indent: i64,
    line: usize,
    line_max: usize,
    tight: bool,
    list_indent: i64,
    parent_type: &'static str,
    level: i32,
}

impl<'a> StateBlock<'a> {
    pub(crate) fn new(src: &str, env: &'a mut Env, error: &'a Cell<bool>) -> Self {
        let src: Vec<char> = src.chars().collect();
        let mut s = Self {
            src,
            env,
            error,
            tokens: Vec::new(),
            b_marks: Vec::new(),
            e_marks: Vec::new(),
            t_shift: Vec::new(),
            s_count: Vec::new(),
            bs_count: Vec::new(),
            blk_indent: 0,
            line: 0,
            line_max: 0,
            tight: false,
            list_indent: -1,
            parent_type: "root",
            level: 0,
        };
        let len = s.src.len();
        let (mut start, mut indent, mut offset) = (0usize, 0usize, 0i64);
        let mut indent_found = false;
        for pos in 0..len {
            let ch = s.src[pos];
            if !indent_found {
                if is_str_space(ch) {
                    indent += 1;
                    if ch == '\t' {
                        offset += 4 - offset % 4;
                    } else {
                        offset += 1;
                    }
                    continue;
                }
                indent_found = true;
            }
            if ch == '\n' || pos == len - 1 {
                let end = if ch == '\n' { pos } else { pos + 1 };
                s.b_marks.push(start);
                s.e_marks.push(end);
                s.t_shift.push(indent);
                s.s_count.push(offset);
                s.bs_count.push(0);
                indent_found = false;
                indent = 0;
                offset = 0;
                start = end + 1;
            }
        }
        s.b_marks.push(len);
        s.e_marks.push(len);
        s.t_shift.push(0);
        s.s_count.push(0);
        s.bs_count.push(0);
        s.line_max = s.b_marks.len() - 1;
        s
    }

    /// `state.src[pos]` where Python does not guard the index: out of range
    /// is an `IndexError`, reported once the parse is over.
    fn at(&self, pos: usize) -> char {
        match self.src.get(pos) {
            Some(&c) => c,
            None => {
                self.error.set(true);
                '\0'
            }
        }
    }

    fn push(&mut self, ty: &'static str, tag: &'static str, nesting: i8) -> &mut Token {
        let mut token = Token::new(ty, tag, nesting);
        token.block = true;
        if nesting < 0 {
            self.level -= 1;
        }
        token.level = self.level;
        if nesting > 0 {
            self.level += 1;
        }
        self.tokens.push(token);
        let last = self.tokens.len() - 1;
        &mut self.tokens[last]
    }

    fn push_inline(&mut self, content: String) {
        let t = self.push("inline", "", 0);
        t.content = content;
        t.children = Some(Vec::new());
    }

    fn is_empty(&self, line: usize) -> bool {
        self.b_marks[line] + self.t_shift[line] >= self.e_marks[line]
    }

    fn skip_empty_lines(&self, mut from: usize) -> usize {
        while from < self.line_max {
            if self.b_marks[from] + self.t_shift[from] < self.e_marks[from] {
                break;
            }
            from += 1;
        }
        from
    }

    fn skip_spaces(&self, mut pos: usize) -> usize {
        while self.src.get(pos).is_some_and(|&c| is_str_space(c)) {
            pos += 1;
        }
        pos
    }

    fn skip_spaces_back(&self, mut pos: usize, min: usize) -> usize {
        if pos <= min {
            return pos;
        }
        while pos > min {
            pos -= 1;
            if !is_str_space(self.src[pos]) {
                return pos + 1;
            }
        }
        pos
    }

    fn skip_chars(&self, mut pos: usize, ch: char) -> usize {
        while self.src.get(pos) == Some(&ch) {
            pos += 1;
        }
        pos
    }

    fn skip_chars_back(&self, mut pos: usize, ch: char, min: usize) -> usize {
        if pos <= min {
            return pos;
        }
        while pos > min {
            pos -= 1;
            if self.src[pos] != ch {
                return pos + 1;
            }
        }
        pos
    }

    fn get_lines(&self, begin: usize, end: usize, indent: i64, keep_last_lf: bool) -> String {
        if begin >= end {
            return String::new();
        }
        let mut out = String::new();
        for line in begin..end {
            let mut line_indent: i64 = 0;
            let line_start = self.b_marks[line];
            let mut first = line_start;
            let last = if line + 1 < end || keep_last_lf {
                self.e_marks[line] + 1
            } else {
                self.e_marks[line]
            };
            while first < last && line_indent < indent {
                let ch = self.at(first);
                if is_str_space(ch) {
                    if ch == '\t' {
                        line_indent += 4 - (line_indent + self.bs_count[line]).rem_euclid(4);
                    } else {
                        line_indent += 1;
                    }
                } else if first - line_start < self.t_shift[line] {
                    line_indent += 1;
                } else {
                    break;
                }
                first += 1;
            }
            if line_indent > indent {
                for _ in 0..(line_indent - indent) {
                    out.push(' ');
                }
            }
            out.push_str(&slice(&self.src, first, last));
        }
        out
    }

    fn is_code_block(&self, line: usize) -> bool {
        self.s_count[line] - self.blk_indent >= 4
    }

    fn get_line(&self, line: usize) -> String {
        slice(
            &self.src,
            self.b_marks[line] + self.t_shift[line],
            self.e_marks[line],
        )
    }

    /// `ParserBlock.tokenize`.
    pub(crate) fn tokenize(&mut self, start_line: usize, end_line: usize) {
        let mut line = start_line;
        let mut has_empty_lines = false;
        while line < end_line {
            line = self.skip_empty_lines(line);
            self.line = line;
            if line >= end_line {
                break;
            }
            if self.s_count[line] < self.blk_indent {
                break;
            }
            if self.level >= MAX_NESTING {
                self.line = end_line;
                break;
            }
            for rule in ALL {
                if self.run(rule, line, end_line, false) {
                    break;
                }
            }
            self.tight = !has_empty_lines;
            line = self.line;
            if line >= 1 && line - 1 < end_line && self.is_empty(line - 1) {
                has_empty_lines = true;
            }
            if line < end_line && self.is_empty(line) {
                has_empty_lines = true;
                line += 1;
                self.line = line;
            }
        }
    }

    /// The whole document (`ParserBlock.parse`).
    pub(crate) fn parse(&mut self) {
        if self.src.is_empty() {
            return;
        }
        let (line, max) = (self.line, self.line_max);
        self.tokenize(line, max);
    }

    fn run(&mut self, rule: Rule, start: usize, end: usize, silent: bool) -> bool {
        match rule {
            Rule::Table => self.table(start, end, silent),
            Rule::Code => self.code(start, end),
            Rule::Fence => self.fence(start, end, silent),
            Rule::Blockquote => self.blockquote(start, end, silent),
            Rule::Hr => self.hr(start, silent),
            Rule::List => self.list(start, end, silent),
            Rule::Reference => self.reference(start, silent),
            Rule::Heading => self.heading(start, silent),
            Rule::Lheading => self.lheading(start, end),
            Rule::Paragraph => self.paragraph(start),
        }
    }

    fn any_terminates(&mut self, rules: &[Rule], line: usize, end: usize) -> bool {
        rules.iter().any(|&r| self.run(r, line, end, true))
    }

    // -----------------------------------------------------------------------
    // table
    // -----------------------------------------------------------------------

    fn table(&mut self, start_line: usize, end_line: usize, silent: bool) -> bool {
        if start_line + 2 > end_line {
            return false;
        }
        let next_line = start_line + 1;
        if self.s_count[next_line] < self.blk_indent {
            return false;
        }
        if self.is_code_block(next_line) {
            return false;
        }
        let mut pos = self.b_marks[next_line] + self.t_shift[next_line];
        if pos >= self.e_marks[next_line] {
            return false;
        }
        let first = self.src[pos];
        pos += 1;
        if !matches!(first, '|' | '-' | ':') {
            return false;
        }
        if pos >= self.e_marks[next_line] {
            return false;
        }
        let second = self.src[pos];
        pos += 1;
        if !matches!(second, '|' | '-' | ':') && !is_str_space(second) {
            return false;
        }
        if first == '-' && is_str_space(second) {
            return false;
        }
        while pos < self.e_marks[next_line] {
            let ch = self.src[pos];
            if !matches!(ch, '|' | '-' | ':') && !is_str_space(ch) {
                return false;
            }
            pos += 1;
        }
        let line_text = self.get_line(start_line + 1);
        let columns: Vec<&str> = line_text.split('|').collect();
        let mut aligns: Vec<&'static str> = Vec::new();
        for (i, column) in columns.iter().enumerate() {
            let t = py_strip(column);
            if t.is_empty() {
                if i == 0 || i == columns.len() - 1 {
                    continue;
                }
                return false;
            }
            let core = t.strip_prefix(':').unwrap_or(t);
            let core = core.strip_suffix(':').unwrap_or(core);
            if core.is_empty() || !core.chars().all(|c| c == '-') {
                return false;
            }
            if t.ends_with(':') {
                aligns.push(if t.starts_with(':') {
                    "center"
                } else {
                    "right"
                });
            } else if t.starts_with(':') {
                aligns.push("left");
            } else {
                aligns.push("");
            }
        }
        let line_text = self.get_line(start_line);
        let line_text = py_strip(&line_text);
        if !line_text.contains('|') {
            return false;
        }
        if self.is_code_block(start_line) {
            return false;
        }
        let columns = trimmed_columns(line_text);
        let column_count = columns.len();
        if column_count == 0 || column_count != aligns.len() {
            return false;
        }
        if silent {
            return true;
        }
        let old_parent = self.parent_type;
        self.parent_type = "table";
        self.push("table_open", "table", 1);
        self.push("thead_open", "thead", 1);
        self.push("tr_open", "tr", 1);
        for (i, column) in columns.iter().enumerate() {
            let t = self.push("th_open", "th", 1);
            if !aligns[i].is_empty() {
                t.attr_set("style", format!("text-align:{}", aligns[i]));
            }
            self.push_inline(py_strip(column).to_string());
            self.push("th_close", "th", -1);
        }
        self.push("tr_close", "tr", -1);
        self.push("thead_close", "thead", -1);
        let mut autocompleted: i64 = 0;
        let mut next_line = start_line + 2;
        let mut tbody = false;
        while next_line < end_line {
            if self.s_count[next_line] < self.blk_indent {
                break;
            }
            if self.any_terminates(&TERM_BLOCKQUOTE, next_line, end_line) {
                break;
            }
            let line_text = self.get_line(next_line);
            let line_text = py_strip(&line_text).to_string();
            if line_text.is_empty() {
                break;
            }
            if self.is_code_block(next_line) {
                break;
            }
            let columns = trimmed_columns(&line_text);
            autocompleted += column_count as i64 - columns.len() as i64;
            if autocompleted > 0x10000 {
                break;
            }
            if next_line == start_line + 2 {
                self.push("tbody_open", "tbody", 1);
                tbody = true;
            }
            self.push("tr_open", "tr", 1);
            for (i, align) in aligns.iter().enumerate().take(column_count) {
                let t = self.push("td_open", "td", 1);
                if !align.is_empty() {
                    t.attr_set("style", format!("text-align:{align}"));
                }
                let content = columns
                    .get(i)
                    .map(|c| py_strip(c).to_string())
                    .unwrap_or_default();
                self.push_inline(content);
                self.push("td_close", "td", -1);
            }
            self.push("tr_close", "tr", -1);
            next_line += 1;
        }
        if tbody {
            self.push("tbody_close", "tbody", -1);
        }
        self.push("table_close", "table", -1);
        self.parent_type = old_parent;
        self.line = next_line;
        true
    }

    // -----------------------------------------------------------------------
    // code, fence
    // -----------------------------------------------------------------------

    fn code(&mut self, start_line: usize, end_line: usize) -> bool {
        if !self.is_code_block(start_line) {
            return false;
        }
        let mut next_line = start_line + 1;
        let mut last = next_line;
        while next_line < end_line {
            if self.is_empty(next_line) {
                next_line += 1;
                continue;
            }
            if self.is_code_block(next_line) {
                next_line += 1;
                last = next_line;
                continue;
            }
            break;
        }
        self.line = last;
        let content = self.get_lines(start_line, last, 4 + self.blk_indent, false) + "\n";
        let t = self.push("code_block", "code", 0);
        t.content = content;
        true
    }

    fn fence(&mut self, start_line: usize, end_line: usize, silent: bool) -> bool {
        let mut pos = self.b_marks[start_line] + self.t_shift[start_line];
        let mut maximum = self.e_marks[start_line];
        if self.is_code_block(start_line) {
            return false;
        }
        if pos + 3 > maximum {
            return false;
        }
        let marker = self.at(pos);
        if marker != '~' && marker != '`' {
            return false;
        }
        let mut mem = pos;
        pos = self.skip_chars(pos, marker);
        let len = pos - mem;
        if len < 3 {
            return false;
        }
        let markup = slice(&self.src, mem, pos);
        let params = slice(&self.src, pos, maximum);
        if marker == '`' && params.contains('`') {
            return false;
        }
        if silent {
            return true;
        }
        let mut next_line = start_line;
        let mut have_end = false;
        loop {
            next_line += 1;
            if next_line >= end_line {
                break;
            }
            pos = self.b_marks[next_line] + self.t_shift[next_line];
            mem = pos;
            maximum = self.e_marks[next_line];
            if pos < maximum && self.s_count[next_line] < self.blk_indent {
                break;
            }
            match self.src.get(pos) {
                None => break,
                Some(&c) if c != marker => continue,
                Some(_) => {}
            }
            if self.is_code_block(next_line) {
                continue;
            }
            pos = self.skip_chars(pos, marker);
            if pos - mem < len {
                continue;
            }
            pos = self.skip_spaces(pos);
            if pos < maximum {
                continue;
            }
            have_end = true;
            break;
        }
        let indent = self.s_count[start_line];
        self.line = next_line + usize::from(have_end);
        let content = self.get_lines(start_line + 1, next_line, indent, true);
        let t = self.push("fence", "code", 0);
        t.info = params;
        t.content = content;
        t.markup = markup;
        true
    }

    // -----------------------------------------------------------------------
    // blockquote
    // -----------------------------------------------------------------------

    fn blockquote(&mut self, start_line: usize, end_line: usize, silent: bool) -> bool {
        let old_line_max = self.line_max;
        let mut pos = self.b_marks[start_line] + self.t_shift[start_line];
        let mut max = self.e_marks[start_line];
        if self.is_code_block(start_line) {
            return false;
        }
        if self.src.get(pos) != Some(&'>') {
            return false;
        }
        pos += 1;
        if silent {
            return true;
        }
        let mut initial = self.s_count[start_line] + 1;
        let mut offset = initial;
        let mut adjust_tab = false;
        let mut space_after_marker;
        match self.src.get(pos) {
            Some(' ') => {
                pos += 1;
                initial += 1;
                offset += 1;
                space_after_marker = true;
            }
            Some('\t') => {
                space_after_marker = true;
                if (self.bs_count[start_line] + offset).rem_euclid(4) == 3 {
                    pos += 1;
                    initial += 1;
                    offset += 1;
                } else {
                    adjust_tab = true;
                }
            }
            _ => space_after_marker = false,
        }
        let mut old_b_marks = vec![self.b_marks[start_line]];
        self.b_marks[start_line] = pos;
        while pos < max {
            let ch = self.src[pos];
            if !is_str_space(ch) {
                break;
            }
            if ch == '\t' {
                offset +=
                    4 - (offset + self.bs_count[start_line] + i64::from(adjust_tab)).rem_euclid(4);
            } else {
                offset += 1;
            }
            pos += 1;
        }
        let mut old_bs_count = vec![self.bs_count[start_line]];
        self.bs_count[start_line] = self.s_count[start_line] + 1 + i64::from(space_after_marker);
        let mut last_line_empty = pos >= max;
        let mut old_s_count = vec![self.s_count[start_line]];
        self.s_count[start_line] = offset - initial;
        let mut old_t_shift = vec![self.t_shift[start_line]];
        self.t_shift[start_line] = pos - self.b_marks[start_line];
        let old_parent = self.parent_type;
        self.parent_type = "blockquote";

        let mut next_line = start_line + 1;
        while next_line < end_line {
            let is_outdented = self.s_count[next_line] < self.blk_indent;
            pos = self.b_marks[next_line] + self.t_shift[next_line];
            max = self.e_marks[next_line];
            if pos >= max {
                break;
            }
            let evaluates_true = self.src[pos] == '>' && !is_outdented;
            pos += 1;
            if evaluates_true {
                initial = self.s_count[next_line] + 1;
                offset = initial;
                adjust_tab = false;
                match self.src.get(pos) {
                    Some(' ') => {
                        pos += 1;
                        initial += 1;
                        offset += 1;
                        space_after_marker = true;
                    }
                    Some('\t') => {
                        space_after_marker = true;
                        if (self.bs_count[next_line] + offset).rem_euclid(4) == 3 {
                            pos += 1;
                            initial += 1;
                            offset += 1;
                        } else {
                            adjust_tab = true;
                        }
                    }
                    _ => space_after_marker = false,
                }
                old_b_marks.push(self.b_marks[next_line]);
                self.b_marks[next_line] = pos;
                while pos < max {
                    let ch = self.src[pos];
                    if !is_str_space(ch) {
                        break;
                    }
                    if ch == '\t' {
                        offset += 4
                            - (offset + self.bs_count[next_line] + i64::from(adjust_tab))
                                .rem_euclid(4);
                    } else {
                        offset += 1;
                    }
                    pos += 1;
                }
                last_line_empty = pos >= max;
                old_bs_count.push(self.bs_count[next_line]);
                self.bs_count[next_line] =
                    self.s_count[next_line] + 1 + i64::from(space_after_marker);
                old_s_count.push(self.s_count[next_line]);
                self.s_count[next_line] = offset - initial;
                old_t_shift.push(self.t_shift[next_line]);
                self.t_shift[next_line] = pos - self.b_marks[next_line];
                next_line += 1;
                continue;
            }
            if last_line_empty {
                break;
            }
            if self.any_terminates(&TERM_BLOCKQUOTE, next_line, end_line) {
                self.line_max = next_line;
                if self.blk_indent != 0 {
                    old_b_marks.push(self.b_marks[next_line]);
                    old_bs_count.push(self.bs_count[next_line]);
                    old_t_shift.push(self.t_shift[next_line]);
                    old_s_count.push(self.s_count[next_line]);
                    self.s_count[next_line] -= self.blk_indent;
                }
                break;
            }
            old_b_marks.push(self.b_marks[next_line]);
            old_bs_count.push(self.bs_count[next_line]);
            old_t_shift.push(self.t_shift[next_line]);
            old_s_count.push(self.s_count[next_line]);
            self.s_count[next_line] = -1;
            next_line += 1;
        }
        let old_indent = self.blk_indent;
        self.blk_indent = 0;
        self.push("blockquote_open", "blockquote", 1).markup = ">".into();
        self.tokenize(start_line, next_line);
        self.push("blockquote_close", "blockquote", -1).markup = ">".into();
        self.line_max = old_line_max;
        self.parent_type = old_parent;
        for (i, &shift) in old_t_shift.iter().enumerate() {
            self.b_marks[i + start_line] = old_b_marks[i];
            self.t_shift[i + start_line] = shift;
            self.s_count[i + start_line] = old_s_count[i];
            self.bs_count[i + start_line] = old_bs_count[i];
        }
        self.blk_indent = old_indent;
        true
    }

    // -----------------------------------------------------------------------
    // hr, heading, lheading, paragraph
    // -----------------------------------------------------------------------

    fn hr(&mut self, start_line: usize, silent: bool) -> bool {
        let mut pos = self.b_marks[start_line] + self.t_shift[start_line];
        let maximum = self.e_marks[start_line];
        if self.is_code_block(start_line) {
            return false;
        }
        let Some(&marker) = self.src.get(pos) else {
            return false;
        };
        pos += 1;
        if !matches!(marker, '*' | '-' | '_') {
            return false;
        }
        let mut cnt = 1;
        while pos < maximum {
            let ch = self.src[pos];
            pos += 1;
            if ch != marker && !is_str_space(ch) {
                return false;
            }
            if ch == marker {
                cnt += 1;
            }
        }
        if cnt < 3 {
            return false;
        }
        if silent {
            return true;
        }
        self.line = start_line + 1;
        let t = self.push("hr", "hr", 0);
        t.markup = std::iter::repeat_n(marker, cnt + 1).collect();
        true
    }

    fn heading(&mut self, start_line: usize, silent: bool) -> bool {
        let mut pos = self.b_marks[start_line] + self.t_shift[start_line];
        let mut maximum = self.e_marks[start_line];
        if self.is_code_block(start_line) {
            return false;
        }
        let ch = self.at(pos);
        if ch != '#' || pos >= maximum {
            return false;
        }
        let mut level = 1;
        pos += 1;
        let mut ch = self.src.get(pos).copied();
        while ch == Some('#') && pos < maximum && level <= 6 {
            level += 1;
            pos += 1;
            ch = self.src.get(pos).copied();
        }
        if level > 6 || (pos < maximum && !ch.is_some_and(is_str_space)) {
            return false;
        }
        if silent {
            return true;
        }
        maximum = self.skip_spaces_back(maximum, pos);
        let tmp = self.skip_chars_back(maximum, '#', pos);
        if tmp > pos && is_str_space(self.src[tmp - 1]) {
            maximum = tmp;
        }
        self.line = start_line + 1;
        let tag = heading_tag(level);
        let markup: String = "########".chars().take(level).collect();
        self.push("heading_open", tag, 1).markup = markup.clone();
        let content = py_strip(&slice(&self.src, pos, maximum)).to_string();
        self.push_inline(content);
        self.push("heading_close", tag, -1).markup = markup;
        true
    }

    fn lheading(&mut self, start_line: usize, end_line: usize) -> bool {
        let mut level = 0;
        let mut next_line = start_line + 1;
        let mut marker = '\0';
        if self.is_code_block(start_line) {
            return false;
        }
        let old_parent = self.parent_type;
        // Python leaves this set when no underline is found (the paragraph
        // rule that runs next restores it to the same value).
        self.parent_type = "paragraph";
        while next_line < end_line && !self.is_empty(next_line) {
            if self.s_count[next_line] - self.blk_indent > 3 {
                next_line += 1;
                continue;
            }
            if self.s_count[next_line] >= self.blk_indent {
                let mut pos = self.b_marks[next_line] + self.t_shift[next_line];
                let maximum = self.e_marks[next_line];
                if pos < maximum {
                    let m = self.src[pos];
                    if m == '-' || m == '=' {
                        marker = m;
                        pos = self.skip_chars(pos, m);
                        pos = self.skip_spaces(pos);
                        if pos >= maximum {
                            level = if m == '=' { 1 } else { 2 };
                            break;
                        }
                    }
                }
            }
            if self.s_count[next_line] < 0 {
                next_line += 1;
                continue;
            }
            if self.any_terminates(&TERM_PARAGRAPH, next_line, end_line) {
                break;
            }
            next_line += 1;
        }
        if level == 0 {
            return false;
        }
        let content =
            py_strip(&self.get_lines(start_line, next_line, self.blk_indent, false)).to_string();
        self.line = next_line + 1;
        let tag = heading_tag(level);
        self.push("heading_open", tag, 1).markup = marker.to_string();
        self.push_inline(content);
        self.push("heading_close", tag, -1).markup = marker.to_string();
        self.parent_type = old_parent;
        true
    }

    fn paragraph(&mut self, start_line: usize) -> bool {
        let mut next_line = start_line + 1;
        let end_line = self.line_max;
        let old_parent = self.parent_type;
        self.parent_type = "paragraph";
        while next_line < end_line {
            if self.is_empty(next_line) {
                break;
            }
            if self.s_count[next_line] - self.blk_indent > 3 {
                next_line += 1;
                continue;
            }
            if self.s_count[next_line] < 0 {
                next_line += 1;
                continue;
            }
            if self.any_terminates(&TERM_PARAGRAPH, next_line, end_line) {
                break;
            }
            next_line += 1;
        }
        let content =
            py_strip(&self.get_lines(start_line, next_line, self.blk_indent, false)).to_string();
        self.line = next_line;
        self.push("paragraph_open", "p", 1);
        self.push_inline(content);
        self.push("paragraph_close", "p", -1);
        self.parent_type = old_parent;
        true
    }

    // -----------------------------------------------------------------------
    // list
    // -----------------------------------------------------------------------

    fn skip_bullet_list_marker(&self, line: usize) -> Option<usize> {
        let mut pos = self.b_marks[line] + self.t_shift[line];
        let maximum = self.e_marks[line];
        let marker = *self.src.get(pos)?;
        pos += 1;
        if !matches!(marker, '*' | '-' | '+') {
            return None;
        }
        if pos < maximum && !is_str_space(self.src[pos]) {
            return None;
        }
        Some(pos)
    }

    fn skip_ordered_list_marker(&self, line: usize) -> Option<usize> {
        let start = self.b_marks[line] + self.t_shift[line];
        let mut pos = start;
        let maximum = self.e_marks[line];
        if pos + 1 >= maximum {
            return None;
        }
        let ch = self.src[pos];
        pos += 1;
        if !ch.is_ascii_digit() {
            return None;
        }
        loop {
            if pos >= maximum {
                return None;
            }
            let ch = self.src[pos];
            pos += 1;
            if ch.is_ascii_digit() {
                if pos - start >= 10 {
                    return None;
                }
                continue;
            }
            if ch == ')' || ch == '.' {
                break;
            }
            return None;
        }
        if pos < maximum && !is_str_space(self.src[pos]) {
            return None;
        }
        Some(pos)
    }

    fn mark_tight_paragraphs(&mut self, idx: usize) {
        let level = self.level + 2;
        let mut i = idx + 2;
        let length = self.tokens.len().saturating_sub(2);
        while i < length {
            if self.tokens[i].level == level && self.tokens[i].ty == "paragraph_open" {
                self.tokens[i + 2].hidden = true;
                self.tokens[i].hidden = true;
                i += 2;
            }
            i += 1;
        }
    }

    fn list(&mut self, start_line: usize, end_line: usize, silent: bool) -> bool {
        let mut start_line = start_line;
        let mut tight = true;
        if self.is_code_block(start_line) {
            return false;
        }
        if self.list_indent >= 0
            && self.s_count[start_line] - self.list_indent >= 4
            && self.s_count[start_line] < self.blk_indent
        {
            return false;
        }
        let is_terminating_paragraph = silent
            && self.parent_type == "paragraph"
            && self.s_count[start_line] >= self.blk_indent;
        let is_ordered;
        let mut marker_value = 0u64;
        let mut start = 0usize;
        let mut pos_after_marker;
        if let Some(p) = self.skip_ordered_list_marker(start_line) {
            pos_after_marker = p;
            is_ordered = true;
            start = self.b_marks[start_line] + self.t_shift[start_line];
            marker_value = slice(&self.src, start, pos_after_marker - 1)
                .parse()
                .unwrap_or(0);
            if is_terminating_paragraph && marker_value != 1 {
                return false;
            }
        } else if let Some(p) = self.skip_bullet_list_marker(start_line) {
            pos_after_marker = p;
            is_ordered = false;
        } else {
            return false;
        }
        if is_terminating_paragraph
            && self.skip_spaces(pos_after_marker) >= self.e_marks[start_line]
        {
            return false;
        }
        let marker_char = self.src[pos_after_marker - 1];
        if silent {
            return true;
        }
        let list_tok_idx = self.tokens.len();
        if is_ordered {
            let t = self.push("ordered_list_open", "ol", 1);
            if marker_value != 1 {
                t.attr_set("start", marker_value.to_string());
            }
            t.markup = marker_char.to_string();
        } else {
            self.push("bullet_list_open", "ul", 1).markup = marker_char.to_string();
        }
        let mut next_line = start_line;
        let mut prev_empty_end = false;
        let old_parent = self.parent_type;
        self.parent_type = "list";
        while next_line < end_line {
            let mut pos = pos_after_marker;
            let maximum = self.e_marks[next_line];
            let initial = self.s_count[next_line] + pos_after_marker as i64
                - (self.b_marks[start_line] + self.t_shift[start_line]) as i64;
            let mut offset = initial;
            while pos < maximum {
                let ch = self.src[pos];
                if ch == '\t' {
                    offset += 4 - (offset + self.bs_count[next_line]).rem_euclid(4);
                } else if ch == ' ' {
                    offset += 1;
                } else {
                    break;
                }
                pos += 1;
            }
            let content_start = pos;
            let mut indent_after_marker = if content_start >= maximum {
                1
            } else {
                offset - initial
            };
            if indent_after_marker > 4 {
                indent_after_marker = 1;
            }
            let indent = initial + indent_after_marker;
            let info = if is_ordered {
                slice(&self.src, start, pos_after_marker - 1)
            } else {
                String::new()
            };
            let t = self.push("list_item_open", "li", 1);
            t.markup = marker_char.to_string();
            t.info = info;
            let old_tight = self.tight;
            let old_t_shift = self.t_shift[start_line];
            let old_s_count = self.s_count[start_line];
            let old_list_indent = self.list_indent;
            self.list_indent = self.blk_indent;
            self.blk_indent = indent;
            self.tight = true;
            self.t_shift[start_line] = content_start - self.b_marks[start_line];
            self.s_count[start_line] = offset;
            if content_start >= maximum && self.is_empty(start_line + 1) {
                self.line = (self.line + 2).min(end_line);
            } else {
                self.tokenize(start_line, end_line);
            }
            if !self.tight || prev_empty_end {
                tight = false;
            }
            prev_empty_end =
                self.line as i64 - start_line as i64 > 1 && self.is_empty(self.line - 1);
            self.blk_indent = self.list_indent;
            self.list_indent = old_list_indent;
            self.t_shift[start_line] = old_t_shift;
            self.s_count[start_line] = old_s_count;
            self.tight = old_tight;
            self.push("list_item_close", "li", -1).markup = marker_char.to_string();
            next_line = self.line;
            start_line = next_line;
            if next_line >= end_line {
                break;
            }
            if self.s_count[next_line] < self.blk_indent {
                break;
            }
            if self.is_code_block(start_line) {
                break;
            }
            if self.any_terminates(&TERM_LIST, next_line, end_line) {
                break;
            }
            if is_ordered {
                match self.skip_ordered_list_marker(next_line) {
                    Some(p) => pos_after_marker = p,
                    None => break,
                }
                start = self.b_marks[next_line] + self.t_shift[next_line];
            } else {
                match self.skip_bullet_list_marker(next_line) {
                    Some(p) => pos_after_marker = p,
                    None => break,
                }
            }
            if marker_char != self.src[pos_after_marker - 1] {
                break;
            }
        }
        if is_ordered {
            self.push("ordered_list_close", "ol", -1).markup = marker_char.to_string();
        } else {
            self.push("bullet_list_close", "ul", -1).markup = marker_char.to_string();
        }
        self.line = next_line;
        self.parent_type = old_parent;
        if tight {
            self.mark_tight_paragraphs(list_tok_idx);
        }
        true
    }

    // -----------------------------------------------------------------------
    // reference
    // -----------------------------------------------------------------------

    /// `getNextLine` (reference.py).
    fn get_next_line(&mut self, next_line: usize) -> Option<Vec<char>> {
        let end_line = self.line_max;
        if next_line >= end_line || self.is_empty(next_line) {
            return None;
        }
        let mut is_continuation = false;
        if self.is_code_block(next_line) {
            is_continuation = true;
        }
        if self.s_count[next_line] < 0 {
            is_continuation = true;
        }
        if !is_continuation {
            let old_parent = self.parent_type;
            self.parent_type = "reference";
            let terminate = self.any_terminates(&TERM_PARAGRAPH, next_line, end_line);
            self.parent_type = old_parent;
            if terminate {
                return None;
            }
        }
        let pos = self.b_marks[next_line] + self.t_shift[next_line];
        let maximum = self.e_marks[next_line];
        let end = (maximum + 1).min(self.src.len());
        Some(if pos < end {
            self.src[pos..end].to_vec()
        } else {
            Vec::new()
        })
    }

    fn reference(&mut self, start_line: usize, silent: bool) -> bool {
        let pos0 = self.b_marks[start_line] + self.t_shift[start_line];
        let max0 = self.e_marks[start_line];
        let mut next_line = start_line + 1;
        if self.is_code_block(start_line) {
            return false;
        }
        if self.at(pos0) != '[' {
            return false;
        }
        let end = (max0 + 1).min(self.src.len());
        let mut s: Vec<char> = if pos0 < end {
            self.src[pos0..end].to_vec()
        } else {
            Vec::new()
        };
        let mut maximum = s.len();
        let mut label_end = None;
        let mut pos = 1;
        while pos < maximum {
            let ch = s[pos];
            if ch == '[' {
                return false;
            } else if ch == ']' {
                label_end = Some(pos);
                break;
            } else if ch == '\n' {
                if let Some(more) = self.get_next_line(next_line) {
                    s.extend(more);
                    maximum = s.len();
                    next_line += 1;
                }
            } else if ch == '\\' {
                pos += 1;
                if pos < maximum && s[pos] == '\n' {
                    if let Some(more) = self.get_next_line(next_line) {
                        s.extend(more);
                        maximum = s.len();
                        next_line += 1;
                    }
                }
            }
            pos += 1;
        }
        let Some(label_end) = label_end else {
            return false;
        };
        if s.get(label_end + 1) != Some(&':') {
            return false;
        }
        pos = label_end + 2;
        while pos < maximum {
            let ch = s[pos];
            if ch == '\n' {
                if let Some(more) = self.get_next_line(next_line) {
                    s.extend(more);
                    maximum = s.len();
                    next_line += 1;
                }
            } else if !is_str_space(ch) {
                break;
            }
            pos += 1;
        }
        let Some(dest) = parse_link_destination(&s, pos, maximum) else {
            return false;
        };
        let href = normalize_link(&dest.text);
        if !validate_link(&href) {
            return false;
        }
        pos = dest.pos;
        let dest_end_pos = pos;
        let dest_end_line = next_line;
        let start = pos;
        while pos < maximum {
            let ch = s[pos];
            if ch == '\n' {
                if let Some(more) = self.get_next_line(next_line) {
                    s.extend(more);
                    maximum = s.len();
                    next_line += 1;
                }
            } else if !is_str_space(ch) {
                break;
            }
            pos += 1;
        }
        let mut title_res = parse_link_title(&s, pos, maximum, None);
        while title_res.can_continue {
            let Some(more) = self.get_next_line(next_line) else {
                break;
            };
            s.extend(more);
            pos = maximum;
            maximum = s.len();
            next_line += 1;
            title_res = parse_link_title(&s, pos, maximum, Some(&title_res));
        }
        let mut title;
        if pos < maximum && start != pos && title_res.ok {
            title = title_res.text.clone();
            pos = title_res.pos;
        } else {
            title = String::new();
            pos = dest_end_pos;
            next_line = dest_end_line;
        }
        while pos < maximum && is_str_space(s[pos]) {
            pos += 1;
        }
        if pos < maximum && s[pos] != '\n' && !title.is_empty() {
            title = String::new();
            pos = dest_end_pos;
            next_line = dest_end_line;
            while pos < maximum && is_str_space(s[pos]) {
                pos += 1;
            }
        }
        if pos < maximum && s[pos] != '\n' {
            return false;
        }
        let label = normalize_reference(&slice(&s, 1, label_end));
        if label.is_empty() {
            return false;
        }
        if silent {
            return true;
        }
        let refs = self.env.references.get_or_insert_with(HashMap::new);
        self.line = next_line;
        refs.entry(label).or_insert(Reference { href, title });
        true
    }
}

fn heading_tag(level: usize) -> &'static str {
    match level {
        1 => "h1",
        2 => "h2",
        3 => "h3",
        4 => "h4",
        5 => "h5",
        _ => "h6",
    }
}

/// `escapedSplit`: split on `|` that is not preceded by a backslash (the
/// backslash of an escaped pipe is dropped).
fn escaped_split(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut result = Vec::new();
    let mut pos = 0;
    let mut is_escaped = false;
    let mut last_pos = 0;
    let mut current = String::new();
    while pos < chars.len() {
        let ch = chars[pos];
        if ch == '|' {
            if !is_escaped {
                result.push(current.clone() + &slice(&chars, last_pos, pos));
                current.clear();
                last_pos = pos + 1;
            } else {
                current.push_str(&slice(&chars, last_pos, pos - 1));
                last_pos = pos;
            }
        }
        is_escaped = ch == '\\';
        pos += 1;
    }
    result.push(current + &slice(&chars, last_pos, chars.len()));
    result
}

/// `escapedSplit` minus an empty first and last column.
fn trimmed_columns(s: &str) -> Vec<String> {
    let mut columns = escaped_split(s);
    if columns.first().is_some_and(String::is_empty) {
        columns.remove(0);
    }
    if columns.last().is_some_and(String::is_empty) {
        columns.pop();
    }
    columns
}

/// `parseLinkDestination`'s successful result.
pub(crate) struct Destination {
    /// Unescaped destination.
    pub text: String,
    /// Position after it.
    pub pos: usize,
}

/// `parseLinkDestination(string, pos, maximum)`.
pub(crate) fn parse_link_destination(
    s: &[char],
    mut pos: usize,
    maximum: usize,
) -> Option<Destination> {
    let start = pos;
    if s.get(pos) == Some(&'<') {
        pos += 1;
        while pos < maximum {
            let c = s[pos];
            if c == '\n' || c == '<' {
                return None;
            }
            if c == '>' {
                return Some(Destination {
                    text: unescape_all(&slice(s, start + 1, pos)),
                    pos: pos + 1,
                });
            }
            if c == '\\' && pos + 1 < maximum {
                pos += 2;
                continue;
            }
            pos += 1;
        }
        return None;
    }
    let mut level = 0;
    while pos < maximum {
        let Some(&c) = s.get(pos) else { break };
        if c == ' ' {
            break;
        }
        if (c as u32) < 0x20 || c == '\u{7f}' {
            break;
        }
        if c == '\\' && pos + 1 < maximum {
            if s.get(pos + 1) == Some(&' ') {
                break;
            }
            pos += 2;
            continue;
        }
        if c == '(' {
            level += 1;
            if level > 32 {
                return None;
            }
        }
        if c == ')' {
            if level == 0 {
                break;
            }
            level -= 1;
        }
        pos += 1;
    }
    if start == pos || level != 0 {
        return None;
    }
    Some(Destination {
        text: unescape_all(&slice(s, start, pos)),
        pos,
    })
}

/// `parseLinkTitle`'s state.
#[derive(Debug, Clone, Default)]
pub(crate) struct Title {
    /// A valid title.
    pub ok: bool,
    /// May continue on the next line.
    pub can_continue: bool,
    /// Position after the closing marker.
    pub pos: usize,
    /// Unescaped title.
    pub text: String,
    /// Expected closing marker.
    marker: char,
}

/// `parseLinkTitle(string, start, maximum, prev_state)`.
pub(crate) fn parse_link_title(
    s: &[char],
    start: usize,
    maximum: usize,
    prev: Option<&Title>,
) -> Title {
    let mut start = start;
    let mut pos = start;
    let mut state = Title::default();
    match prev {
        Some(p) => {
            state.text = p.text.clone();
            state.marker = p.marker;
        }
        None => {
            if pos >= maximum {
                return state;
            }
            let marker = s.get(pos).copied().unwrap_or('\0');
            if marker != '"' && marker != '\'' && marker != '(' {
                return state;
            }
            start += 1;
            pos += 1;
            state.marker = if marker == '(' { ')' } else { marker };
        }
    }
    while pos < maximum {
        let code = s.get(pos).copied().unwrap_or('\0');
        if code == state.marker {
            state.pos = pos + 1;
            state.text.push_str(&unescape_all(&slice(s, start, pos)));
            state.ok = true;
            return state;
        } else if code == '(' && state.marker == ')' {
            return state;
        } else if code == '\\' && pos + 1 < maximum {
            pos += 1;
        }
        pos += 1;
    }
    state.can_continue = true;
    state.text.push_str(&unescape_all(&slice(s, start, pos)));
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaped_split_drops_the_backslash() {
        assert_eq!(
            escaped_split(r"| a \| b | c |"),
            vec!["", " a | b ", " c ", ""]
        );
    }
}
