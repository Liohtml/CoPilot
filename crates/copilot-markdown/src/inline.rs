//! The inline parser (`parser_inline.py`, `rules_inline/*`): text, newline,
//! escape, backticks, strikethrough, emphasis, link, image, autolink and
//! entity (`linkify` and `html_inline` are inert with their options off),
//! then `balance_pairs`, the strikethrough and emphasis post-processing and
//! `fragments_join`.

use std::cell::Cell;
use std::collections::HashMap;

use crate::MAX_NESTING;
use crate::block::{Env, parse_link_destination, parse_link_title};
use crate::entity::{is_valid_entity_code, lookup};
use crate::pystr::{
    is_md_ascii_punct, is_punct_char, is_py_space, is_str_space, is_white_space,
    normalize_reference, slice,
};
use crate::token::Token;
use crate::url::{normalize_link, normalize_link_text, validate_link};

#[derive(Debug, Clone, Copy)]
struct Delim {
    marker: char,
    length: i64,
    token: usize,
    end: i64,
    open: bool,
    close: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    Text,
    Newline,
    Escape,
    Backticks,
    Strikethrough,
    Emphasis,
    Link,
    Image,
    Autolink,
    Entity,
}

const RULES: [Rule; 10] = [
    Rule::Text,
    Rule::Newline,
    Rule::Escape,
    Rule::Backticks,
    Rule::Strikethrough,
    Rule::Emphasis,
    Rule::Link,
    Rule::Image,
    Rule::Autolink,
    Rule::Entity,
];

/// `_DEFAULT_TERMINATORS`.
fn is_terminator(c: char) -> bool {
    matches!(
        c,
        '\n' | '!'
            | '#'
            | '$'
            | '%'
            | '&'
            | '*'
            | '+'
            | '-'
            | ':'
            | '<'
            | '='
            | '>'
            | '@'
            | '['
            | '\\'
            | ']'
            | '^'
            | '_'
            | '`'
            | '{'
            | '}'
            | '~'
    )
}

/// The characters `escape` unescapes (`_ESCAPED`).
fn is_escaped(c: char) -> bool {
    is_md_ascii_punct(c)
}

struct StateInline<'a> {
    src: Vec<char>,
    env: &'a Env,
    error: &'a Cell<bool>,
    tokens: Vec<Token>,
    /// `tokens_meta`: the delimiter list an opening token started.
    tokens_meta: Vec<Option<usize>>,
    pos: usize,
    pos_max: usize,
    level: i32,
    pending: String,
    pending_level: i32,
    cache: HashMap<usize, usize>,
    lists: Vec<Vec<Delim>>,
    cur: usize,
    prev: Vec<usize>,
    backticks: HashMap<usize, usize>,
    backticks_scanned: bool,
    link_level: i32,
}

/// `ParserInline.parse(src)`.
pub(crate) fn parse(src: &str, env: &Env, error: &Cell<bool>) -> Vec<Token> {
    let chars: Vec<char> = src.chars().collect();
    let mut s = StateInline {
        pos_max: chars.len(),
        src: chars,
        env,
        error,
        tokens: Vec::new(),
        tokens_meta: Vec::new(),
        pos: 0,
        level: 0,
        pending: String::new(),
        pending_level: 0,
        cache: HashMap::new(),
        lists: vec![Vec::new()],
        cur: 0,
        prev: Vec::new(),
        backticks: HashMap::new(),
        backticks_scanned: false,
        link_level: 0,
    };
    s.tokenize();
    s.balance_pairs();
    s.strikethrough_post();
    s.emphasis_post();
    s.fragments_join();
    s.tokens
}

impl StateInline<'_> {
    fn at(&self, pos: usize) -> char {
        match self.src.get(pos) {
            Some(&c) => c,
            None => {
                self.error.set(true);
                '\0'
            }
        }
    }

    fn push_pending(&mut self) {
        let mut t = Token::new("text", "", 0);
        t.content = std::mem::take(&mut self.pending);
        t.level = self.pending_level;
        self.tokens.push(t);
    }

    fn push(&mut self, ty: &'static str, tag: &'static str, nesting: i8) -> &mut Token {
        if !self.pending.is_empty() {
            self.push_pending();
        }
        let mut token = Token::new(ty, tag, nesting);
        let mut meta = None;
        if nesting < 0 {
            self.level -= 1;
            self.cur = self.prev.pop().unwrap_or(0);
        }
        token.level = self.level;
        if nesting > 0 {
            self.level += 1;
            self.prev.push(self.cur);
            self.lists.push(Vec::new());
            self.cur = self.lists.len() - 1;
            meta = Some(self.cur);
        }
        self.pending_level = self.level;
        self.tokens.push(token);
        self.tokens_meta.push(meta);
        let last = self.tokens.len() - 1;
        &mut self.tokens[last]
    }

    /// `scanDelims(start, canSplitWord)` → `(can_open, can_close, length)`.
    fn scan_delims(&self, start: usize, can_split_word: bool) -> (bool, bool, usize) {
        let mut pos = start;
        let maximum = self.pos_max;
        let marker = self.at(start);
        let last_char = if start > 0 { self.at(start - 1) } else { ' ' };
        while pos < maximum && self.src[pos] == marker {
            pos += 1;
        }
        let count = pos - start;
        let next_char = if pos < maximum { self.src[pos] } else { ' ' };
        let is_last_punct = is_md_ascii_punct(last_char) || is_punct_char(last_char);
        let is_next_punct = is_md_ascii_punct(next_char) || is_punct_char(next_char);
        let is_last_ws = is_white_space(last_char);
        let is_next_ws = is_white_space(next_char);
        let left_flanking = !(is_next_ws || (is_next_punct && !(is_last_ws || is_last_punct)));
        let right_flanking = !(is_last_ws || (is_last_punct && !(is_next_ws || is_next_punct)));
        let can_open = left_flanking && (can_split_word || !right_flanking || is_last_punct);
        let can_close = right_flanking && (can_split_word || !left_flanking || is_next_punct);
        (can_open, can_close, count)
    }

    fn tokenize(&mut self) {
        let mut ok = false;
        let end = self.pos_max;
        while self.pos < end {
            if self.level < MAX_NESTING {
                for rule in RULES {
                    ok = self.run(rule, false);
                    if ok {
                        break;
                    }
                }
            }
            if ok {
                if self.pos >= end {
                    break;
                }
                continue;
            }
            let c = self.at(self.pos);
            self.pending.push(c);
            self.pos += 1;
        }
        if !self.pending.is_empty() {
            self.push_pending();
        }
    }

    fn skip_token(&mut self) {
        let pos = self.pos;
        if let Some(&p) = self.cache.get(&pos) {
            self.pos = p;
            return;
        }
        let mut ok = false;
        if self.level < MAX_NESTING {
            for rule in RULES {
                self.level += 1;
                ok = self.run(rule, true);
                self.level -= 1;
                if ok {
                    break;
                }
            }
        } else {
            self.pos = self.pos_max;
        }
        if !ok {
            self.pos += 1;
        }
        self.cache.insert(pos, self.pos);
    }

    fn run(&mut self, rule: Rule, silent: bool) -> bool {
        match rule {
            Rule::Text => self.text(silent),
            Rule::Newline => self.newline(silent),
            Rule::Escape => self.escape(silent),
            Rule::Backticks => self.backtick(silent),
            Rule::Strikethrough => self.strikethrough(silent),
            Rule::Emphasis => self.emphasis(silent),
            Rule::Link => self.link(silent),
            Rule::Image => self.image(silent),
            Rule::Autolink => self.autolink(silent),
            Rule::Entity => self.entity(silent),
        }
    }

    // -----------------------------------------------------------------------
    // rules
    // -----------------------------------------------------------------------

    fn text(&mut self, silent: bool) -> bool {
        // `terminator_re.search(src, pos)` looks at the whole source.
        let found = self
            .src
            .get(self.pos..)
            .and_then(|rest| rest.iter().position(|&c| is_terminator(c)))
            .map(|i| self.pos + i);
        let pos = found.unwrap_or(self.pos_max);
        if pos == self.pos {
            return false;
        }
        if !silent {
            let text = slice(&self.src, self.pos, pos);
            self.pending.push_str(&text);
        }
        self.pos = pos;
        true
    }

    fn newline(&mut self, silent: bool) -> bool {
        let mut pos = self.pos;
        if self.at(pos) != '\n' {
            return false;
        }
        let maximum = self.pos_max;
        if !silent {
            if self.pending.ends_with(' ') {
                let before = &self.pending[..self.pending.len() - 1];
                if before.ends_with(' ') {
                    let kept = self.pending.trim_end_matches(' ').len();
                    self.pending.truncate(kept);
                    self.push("hardbreak", "br", 0);
                } else {
                    self.pending.pop();
                    self.push("softbreak", "br", 0);
                }
            } else {
                self.push("softbreak", "br", 0);
            }
        }
        pos += 1;
        while pos < maximum && is_str_space(self.src[pos]) {
            pos += 1;
        }
        self.pos = pos;
        true
    }

    fn escape(&mut self, silent: bool) -> bool {
        let mut pos = self.pos;
        let maximum = self.pos_max;
        if self.at(pos) != '\\' {
            return false;
        }
        pos += 1;
        if pos >= maximum {
            return false;
        }
        let ch1 = self.src[pos];
        if ch1 == '\n' {
            if !silent {
                self.push("hardbreak", "br", 0);
            }
            pos += 1;
            while pos < maximum && is_str_space(self.src[pos]) {
                pos += 1;
            }
            self.pos = pos;
            return true;
        }
        let orig = format!("\\{ch1}");
        if !silent {
            let content = if is_escaped(ch1) {
                ch1.to_string()
            } else {
                orig.clone()
            };
            let t = self.push("text_special", "", 0);
            t.content = content;
            t.markup = orig;
            t.info = "escape".into();
        }
        self.pos = pos + 1;
        true
    }

    fn backtick(&mut self, silent: bool) -> bool {
        let mut pos = self.pos;
        if self.at(pos) != '`' {
            return false;
        }
        let start = pos;
        pos += 1;
        let maximum = self.pos_max;
        while pos < maximum && self.src[pos] == '`' {
            pos += 1;
        }
        let marker = slice(&self.src, start, pos);
        let opener_len = pos - start;
        if self.backticks_scanned && self.backticks.get(&opener_len).copied().unwrap_or(0) <= start
        {
            if !silent {
                self.pending.push_str(&marker);
            }
            self.pos += opener_len;
            return true;
        }
        let mut match_end = pos;
        // `str.index("`", matchEnd)` searches the whole source.
        while let Some(match_start) = self
            .src
            .get(match_end..)
            .and_then(|rest| rest.iter().position(|&c| c == '`'))
            .map(|i| match_end + i)
        {
            match_end = match_start + 1;
            while match_end < maximum && self.src[match_end] == '`' {
                match_end += 1;
            }
            let closer_len = match_end - match_start;
            if closer_len == opener_len {
                if !silent {
                    let mut content = slice(&self.src, pos, match_start).replace('\n', " ");
                    if content.starts_with(' ')
                        && content.ends_with(' ')
                        && !content.trim_matches(is_py_space).is_empty()
                    {
                        content = content[1..content.len() - 1].to_string();
                    }
                    let t = self.push("code_inline", "code", 0);
                    t.markup = marker;
                    t.content = content;
                }
                self.pos = match_end;
                return true;
            }
            self.backticks.insert(closer_len, match_start);
        }
        self.backticks_scanned = true;
        if !silent {
            self.pending.push_str(&marker);
        }
        self.pos += opener_len;
        true
    }

    fn strikethrough(&mut self, silent: bool) -> bool {
        let start = self.pos;
        let ch = self.at(start);
        if silent || ch != '~' {
            return false;
        }
        let (can_open, can_close, scanned_len) = self.scan_delims(self.pos, true);
        let mut length = scanned_len;
        if length < 2 {
            return false;
        }
        if length % 2 == 1 {
            self.push("text", "", 0).content = "~".into();
            length -= 1;
        }
        let mut i = 0;
        while i < length {
            self.push("text", "", 0).content = "~~".into();
            let token = self.tokens.len() - 1;
            self.lists[self.cur].push(Delim {
                marker: '~',
                length: 0,
                token,
                end: -1,
                open: can_open,
                close: can_close,
            });
            i += 2;
        }
        self.pos += scanned_len;
        true
    }

    fn emphasis(&mut self, silent: bool) -> bool {
        let start = self.pos;
        let marker = self.at(start);
        if silent || (marker != '_' && marker != '*') {
            return false;
        }
        let (can_open, can_close, length) = self.scan_delims(self.pos, marker == '*');
        for _ in 0..length {
            self.push("text", "", 0).content = marker.to_string();
            let token = self.tokens.len() - 1;
            self.lists[self.cur].push(Delim {
                marker,
                length: length as i64,
                token,
                end: -1,
                open: can_open,
                close: can_close,
            });
        }
        self.pos += length;
        true
    }

    /// `parseLinkLabel(state, start, disableNested)`.
    fn parse_link_label(&mut self, start: usize, disable_nested: bool) -> Option<usize> {
        let old_pos = self.pos;
        let mut found = false;
        self.pos = start + 1;
        let mut level = 1;
        while self.pos < self.pos_max {
            let marker = self.src[self.pos];
            if marker == ']' {
                level -= 1;
                if level == 0 {
                    found = true;
                    break;
                }
            }
            let prev_pos = self.pos;
            self.skip_token();
            if marker == '[' {
                if prev_pos + 1 == self.pos {
                    level += 1;
                } else if disable_nested {
                    self.pos = old_pos;
                    return None;
                }
            }
        }
        let label_end = found.then_some(self.pos);
        self.pos = old_pos;
        label_end
    }

    fn skip_ws(&self, mut pos: usize, maximum: usize) -> usize {
        while pos < maximum {
            let ch = self.src[pos];
            if !is_str_space(ch) && ch != '\n' {
                break;
            }
            pos += 1;
        }
        pos
    }

    /// The reference half of `link` / `image`: `Some((href, title, pos))`,
    /// or `None` to fail (`restore` says whether `state.pos` is reset).
    fn reference_target(
        &mut self,
        mut pos: usize,
        label_start: usize,
        label_end: usize,
    ) -> Result<(String, String, usize), bool> {
        let Some(refs) = self.env.references.as_ref() else {
            return Err(false);
        };
        let maximum = self.pos_max;
        let mut label: Option<String> = None;
        if pos < maximum && self.src[pos] == '[' {
            let start = pos + 1;
            match self.parse_link_label(pos, false) {
                Some(p) => {
                    label = Some(slice(&self.src, start, p));
                    pos = p + 1;
                }
                None => pos = label_end + 1,
            }
        } else {
            pos = label_end + 1;
        }
        let label = match label.filter(|l| !l.is_empty()) {
            Some(l) => l,
            None => slice(&self.src, label_start, label_end),
        };
        match refs.get(&normalize_reference(&label)) {
            Some(r) => Ok((r.href.clone(), r.title.clone(), pos)),
            None => Err(true),
        }
    }

    fn link(&mut self, silent: bool) -> bool {
        let mut href = String::new();
        let mut title = String::new();
        let old_pos = self.pos;
        let maximum = self.pos_max;
        let mut parse_reference = true;
        if self.at(self.pos) != '[' {
            return false;
        }
        let label_start = self.pos + 1;
        let Some(label_end) = self.parse_link_label(self.pos, true) else {
            return false;
        };
        let mut pos = label_end + 1;
        if pos < maximum && self.src[pos] == '(' {
            parse_reference = false;
            pos += 1;
            pos = self.skip_ws(pos, maximum);
            if pos >= maximum {
                return false;
            }
            if let Some(res) = parse_link_destination(&self.src, pos, self.pos_max) {
                href = normalize_link(&res.text);
                if validate_link(&href) {
                    pos = res.pos;
                } else {
                    href.clear();
                }
                let start = pos;
                pos = self.skip_ws(pos, maximum);
                let res = parse_link_title(&self.src, pos, self.pos_max, None);
                if pos < maximum && start != pos && res.ok {
                    title = res.text;
                    pos = res.pos;
                    pos = self.skip_ws(pos, maximum);
                }
            }
            if pos >= maximum || self.src[pos] != ')' {
                parse_reference = true;
            }
            pos += 1;
        }
        if parse_reference {
            match self.reference_target(pos, label_start, label_end) {
                Ok((h, t, p)) => {
                    href = h;
                    title = t;
                    pos = p;
                }
                Err(restore) => {
                    if restore {
                        self.pos = old_pos;
                    }
                    return false;
                }
            }
        }
        if !silent {
            self.pos = label_start;
            self.pos_max = label_end;
            let t = self.push("link_open", "a", 1);
            t.attr_set("href", href);
            if !title.is_empty() {
                t.attr_set("title", title);
            }
            self.link_level += 1;
            self.tokenize();
            self.link_level -= 1;
            self.push("link_close", "a", -1);
        }
        self.pos = pos;
        self.pos_max = maximum;
        true
    }

    fn image(&mut self, silent: bool) -> bool {
        let mut href = String::new();
        let old_pos = self.pos;
        let max = self.pos_max;
        if self.at(self.pos) != '!' {
            return false;
        }
        if self.pos + 1 < self.pos_max && self.src[self.pos + 1] != '[' {
            return false;
        }
        let label_start = self.pos + 2;
        let Some(label_end) = self.parse_link_label(self.pos + 1, false) else {
            return false;
        };
        let mut pos = label_end + 1;
        let title;
        if pos < max && self.src[pos] == '(' {
            pos += 1;
            pos = self.skip_ws(pos, max);
            if pos >= max {
                return false;
            }
            if let Some(res) = parse_link_destination(&self.src, pos, self.pos_max) {
                href = normalize_link(&res.text);
                if validate_link(&href) {
                    pos = res.pos;
                } else {
                    href.clear();
                }
            }
            let start = pos;
            pos = self.skip_ws(pos, max);
            let res = parse_link_title(&self.src, pos, self.pos_max, None);
            if pos < max && start != pos && res.ok {
                title = res.text;
                pos = res.pos;
                pos = self.skip_ws(pos, max);
            } else {
                title = String::new();
            }
            if pos >= max || self.src[pos] != ')' {
                self.pos = old_pos;
                return false;
            }
            pos += 1;
        } else {
            match self.reference_target(pos, label_start, label_end) {
                Ok((h, t, p)) => {
                    href = h;
                    title = t;
                    pos = p;
                }
                Err(restore) => {
                    if restore {
                        self.pos = old_pos;
                    }
                    return false;
                }
            }
        }
        if !silent {
            let content = slice(&self.src, label_start, label_end);
            let children = parse(&content, self.env, self.error);
            let t = self.push("image", "img", 0);
            t.attr_set("src", href);
            t.attr_set("alt", "");
            t.children = (!children.is_empty()).then_some(children);
            t.content = content;
            if !title.is_empty() {
                t.attr_set("title", title);
            }
        }
        self.pos = pos;
        self.pos_max = max;
        true
    }

    fn autolink(&mut self, silent: bool) -> bool {
        let mut pos = self.pos;
        if self.at(pos) != '<' {
            return false;
        }
        let start = self.pos;
        let maximum = self.pos_max;
        loop {
            pos += 1;
            if pos >= maximum {
                return false;
            }
            let ch = self.src[pos];
            if ch == '<' {
                return false;
            }
            if ch == '>' {
                break;
            }
        }
        let url_chars = self.src[start + 1..pos].to_vec();
        let url: String = url_chars.iter().collect();
        let full = if is_autolink(&url_chars) {
            normalize_link(&url)
        } else if is_email(&url_chars) {
            normalize_link(&format!("mailto:{url}"))
        } else {
            return false;
        };
        if !validate_link(&full) {
            return false;
        }
        if !silent {
            let t = self.push("link_open", "a", 1);
            t.attr_set("href", full);
            t.markup = "autolink".into();
            t.info = "auto".into();
            self.push("text", "", 0).content = normalize_link_text(&url);
            let t = self.push("link_close", "a", -1);
            t.markup = "autolink".into();
            t.info = "auto".into();
        }
        self.pos += url_chars.len() + 2;
        true
    }

    fn entity(&mut self, silent: bool) -> bool {
        let pos = self.pos;
        let maximum = self.pos_max;
        if self.at(pos) != '&' {
            return false;
        }
        if pos + 1 >= maximum {
            return false;
        }
        let rest = &self.src[pos..];
        if self.src[pos + 1] == '#' {
            // `^&#((?:x[a-f0-9]{1,6}|[0-9]{1,7}));` (case-insensitive)
            let (code, len) = if rest.get(2).is_some_and(|c| *c == 'x' || *c == 'X') {
                let n = rest[3..]
                    .iter()
                    .take(7)
                    .take_while(|c| c.is_ascii_hexdigit())
                    .count();
                if !(1..=6).contains(&n) || rest.get(3 + n) != Some(&';') {
                    return false;
                }
                let digits: String = rest[3..3 + n].iter().collect();
                (u64::from_str_radix(&digits, 16).unwrap_or(0), 4 + n)
            } else {
                let n = rest[2..]
                    .iter()
                    .take(8)
                    .take_while(|c| c.is_ascii_digit())
                    .count();
                if !(1..=7).contains(&n) || rest.get(2 + n) != Some(&';') {
                    return false;
                }
                let digits: String = rest[2..2 + n].iter().collect();
                (digits.parse::<u64>().unwrap_or(0), 3 + n)
            };
            if !silent {
                let content = if is_valid_entity_code(code) {
                    char::from_u32(code as u32).unwrap_or('\u{fffd}')
                } else {
                    '\u{fffd}'
                };
                let markup: String = rest[..len].iter().collect();
                let t = self.push("text_special", "", 0);
                t.content = content.to_string();
                t.markup = markup;
                t.info = "entity".into();
            }
            self.pos += len;
            return true;
        }
        // `^&([a-z][a-z0-9]{1,31});` (case-insensitive), a known name
        if !rest.get(1).is_some_and(char::is_ascii_alphabetic) {
            return false;
        }
        let n = rest[2..]
            .iter()
            .take(32)
            .take_while(|c| c.is_ascii_alphanumeric())
            .count();
        if !(1..=31).contains(&n) || rest.get(2 + n) != Some(&';') {
            return false;
        }
        let name: String = rest[1..2 + n].iter().collect();
        let Some(chars) = lookup(&name) else {
            return false;
        };
        let len = 3 + n;
        if !silent {
            let markup: String = rest[..len].iter().collect();
            let t = self.push("text_special", "", 0);
            t.content = chars.to_string();
            t.markup = markup;
            t.info = "entity".into();
        }
        self.pos += len;
        true
    }

    // -----------------------------------------------------------------------
    // post-processing
    // -----------------------------------------------------------------------

    /// The delimiter lists in Python's order: the root, then every opening
    /// token's.
    fn list_order(&self) -> Vec<usize> {
        std::iter::once(self.cur)
            .chain(self.tokens_meta.iter().flatten().copied())
            .collect()
    }

    fn balance_pairs(&mut self) {
        for li in self.list_order() {
            process_delimiters(&mut self.lists[li]);
        }
    }

    fn strikethrough_post(&mut self) {
        for li in self.list_order() {
            let delims = self.lists[li].clone();
            let mut lone_markers = Vec::new();
            for start in &delims {
                if start.marker != '~' || start.end == -1 {
                    continue;
                }
                let end = delims[start.end as usize];
                let markup = self.tokens[start.token].content.clone();
                let t = &mut self.tokens[start.token];
                t.ty = "s_open";
                t.tag = "s";
                t.nesting = 1;
                t.markup = markup.clone();
                t.content.clear();
                let t = &mut self.tokens[end.token];
                t.ty = "s_close";
                t.tag = "s";
                t.nesting = -1;
                t.markup = markup;
                t.content.clear();
                if end.token >= 1 {
                    let before = &self.tokens[end.token - 1];
                    if before.ty == "text" && before.content == "~" {
                        lone_markers.push(end.token - 1);
                    }
                }
            }
            while let Some(i) = lone_markers.pop() {
                let mut j = i + 1;
                while j < self.tokens.len() && self.tokens[j].ty == "s_close" {
                    j += 1;
                }
                j -= 1;
                if i != j {
                    self.tokens.swap(i, j);
                }
            }
        }
    }

    fn emphasis_post(&mut self) {
        for li in self.list_order() {
            let delims = &self.lists[li];
            let mut i = delims.len() as i64 - 1;
            while i >= 0 {
                let sd = delims[i as usize];
                if (sd.marker != '_' && sd.marker != '*') || sd.end == -1 {
                    i -= 1;
                    continue;
                }
                let ed = delims[sd.end as usize];
                let is_strong = i > 0 && {
                    let before = delims[i as usize - 1];
                    before.end == sd.end + 1
                        && before.marker == sd.marker
                        && before.token as i64 == sd.token as i64 - 1
                        && delims[(sd.end + 1) as usize].token == ed.token + 1
                };
                let ch = sd.marker;
                let markup: String = if is_strong {
                    [ch, ch].iter().collect()
                } else {
                    ch.to_string()
                };
                let (open, close, tag) = if is_strong {
                    ("strong_open", "strong_close", "strong")
                } else {
                    ("em_open", "em_close", "em")
                };
                let t = &mut self.tokens[sd.token];
                t.ty = open;
                t.tag = tag;
                t.nesting = 1;
                t.markup = markup.clone();
                t.content.clear();
                let t = &mut self.tokens[ed.token];
                t.ty = close;
                t.tag = tag;
                t.nesting = -1;
                t.markup = markup;
                t.content.clear();
                if is_strong {
                    let a = delims[i as usize - 1].token;
                    let b = delims[(sd.end + 1) as usize].token;
                    self.tokens[a].content.clear();
                    self.tokens[b].content.clear();
                    i -= 1;
                }
                i -= 1;
            }
        }
    }

    fn fragments_join(&mut self) {
        let mut level = 0;
        let maximum = self.tokens.len();
        let mut curr = 0;
        let mut last = 0;
        while curr < maximum {
            if self.tokens[curr].nesting < 0 {
                level -= 1;
            }
            self.tokens[curr].level = level;
            if self.tokens[curr].nesting > 0 {
                level += 1;
            }
            if self.tokens[curr].ty == "text"
                && curr + 1 < maximum
                && self.tokens[curr + 1].ty == "text"
            {
                let mut joined = self.tokens[curr].content.clone();
                curr += 1;
                while curr < maximum && self.tokens[curr].ty == "text" {
                    joined.push_str(&self.tokens[curr].content);
                    curr += 1;
                }
                let mut merged = self.tokens[curr - 1].clone();
                merged.content = joined;
                merged.level = level;
                self.tokens[last] = merged;
                last += 1;
                continue;
            }
            if curr != last {
                self.tokens[last] = self.tokens[curr].clone();
            }
            last += 1;
            curr += 1;
        }
        self.tokens.truncate(last);
    }
}

/// `processDelimiters`: pair each closer with the nearest valid opener.
fn process_delimiters(delims: &mut [Delim]) {
    if delims.is_empty() {
        return;
    }
    let mut openers_bottom: HashMap<char, [i64; 6]> = HashMap::new();
    let maximum = delims.len();
    let mut header_idx = 0usize;
    let mut last_token_idx: i64 = -2;
    let mut jumps: Vec<i64> = Vec::new();
    let mut closer_idx = 0usize;
    while closer_idx < maximum {
        jumps.push(0);
        let closer = delims[closer_idx];
        if delims[header_idx].marker != closer.marker || last_token_idx != closer.token as i64 - 1 {
            header_idx = closer_idx;
        }
        last_token_idx = closer.token as i64;
        if !closer.close {
            closer_idx += 1;
            continue;
        }
        let slot = (if closer.open { 3 } else { 0 }) + (closer.length % 3) as usize;
        let bottom = openers_bottom.entry(closer.marker).or_insert([-1; 6]);
        let min_opener_idx = bottom[slot];
        let mut opener_idx = header_idx as i64 - jumps[header_idx] - 1;
        let mut new_min = opener_idx;
        while opener_idx > min_opener_idx {
            let opener = delims[opener_idx as usize];
            if opener.marker != closer.marker {
                opener_idx -= jumps[opener_idx as usize] + 1;
                continue;
            }
            if opener.open && opener.end < 0 {
                let is_odd = (opener.close || closer.open)
                    && (opener.length + closer.length) % 3 == 0
                    && (opener.length % 3 != 0 || closer.length % 3 != 0);
                if !is_odd {
                    let last_jump = if opener_idx > 0 && !delims[opener_idx as usize - 1].open {
                        jumps[opener_idx as usize - 1] + 1
                    } else {
                        0
                    };
                    jumps[closer_idx] = closer_idx as i64 - opener_idx + last_jump;
                    jumps[opener_idx as usize] = last_jump;
                    delims[closer_idx].open = false;
                    delims[opener_idx as usize].end = closer_idx as i64;
                    delims[opener_idx as usize].close = false;
                    new_min = -1;
                    last_token_idx = -2;
                    break;
                }
            }
            opener_idx -= jumps[opener_idx as usize] + 1;
        }
        if new_min != -1 {
            let slot = (if delims[closer_idx].open { 3 } else { 0 })
                + (delims[closer_idx].length % 3) as usize;
            if let Some(bottom) = openers_bottom.get_mut(&closer.marker) {
                bottom[slot] = new_min;
            }
        }
        closer_idx += 1;
    }
}

/// `$` in Python matches at the end or before a final newline.
fn without_final_newline(s: &[char]) -> &[char] {
    match s.last() {
        Some('\n') => &s[..s.len() - 1],
        _ => s,
    }
}

/// `AUTOLINK_RE`: `^([a-zA-Z][a-zA-Z0-9+.\-]{1,31}):([^<>\x00-\x20]*)$`.
fn is_autolink(url: &[char]) -> bool {
    let check = |s: &[char]| {
        if !s.first().is_some_and(char::is_ascii_alphabetic) {
            return false;
        }
        let n = s[1..]
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
            .count();
        if !(1..=31).contains(&n) || s.get(1 + n) != Some(&':') {
            return false;
        }
        s[2 + n..]
            .iter()
            .all(|&c| c != '<' && c != '>' && (c as u32) > 0x20)
    };
    check(url) || (url.last() == Some(&'\n') && check(without_final_newline(url)))
}

fn is_email_local(c: char) -> bool {
    c.is_ascii_alphanumeric() || ".!#$%&'*+/=?^_`{|}~-".contains(c)
}

/// `EMAIL_RE`.
fn is_email(url: &[char]) -> bool {
    let check = |s: &[char]| {
        let Some(at) = s.iter().position(|&c| c == '@') else {
            return false;
        };
        let (local, domain) = (&s[..at], &s[at + 1..]);
        if local.is_empty() || !local.iter().all(|&c| is_email_local(c)) {
            return false;
        }
        domain.split(|&c| c == '.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.first().is_some_and(char::is_ascii_alphanumeric)
                && label.last().is_some_and(char::is_ascii_alphanumeric)
                && label.iter().all(|c| c.is_ascii_alphanumeric() || *c == '-')
        })
    };
    check(url) || (url.last() == Some(&'\n') && check(without_final_newline(url)))
}

/// `text_join` for one inline token's children.
pub(crate) fn text_join(children: Vec<Token>) -> Vec<Token> {
    let mut out: Vec<Token> = Vec::new();
    let mut iter = children.into_iter().peekable();
    while let Some(mut child) = iter.next() {
        if child.ty == "text_special" {
            child.ty = "text";
        }
        if child.ty == "text" && out.last().is_some_and(|t| t.ty == "text") {
            let mut joined = child.content;
            while let Some(next) = iter.peek() {
                if next.ty != "text" && next.ty != "text_special" {
                    break;
                }
                if let Some(next) = iter.next() {
                    joined.push_str(&next.content);
                }
            }
            if let Some(last) = out.last_mut() {
                last.content.push_str(&joined);
            }
        } else {
            out.push(child);
        }
    }
    out
}
