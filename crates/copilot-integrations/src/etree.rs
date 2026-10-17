//! The part of `xml.etree.ElementTree` the Office365 decommission uses on
//! the Wazuh manager's `ossec.conf`: `ET.fromstring(text)`, `findall`,
//! `find`, `Element.remove`, and `ET.tostring(root, encoding="utf-8")`.
//!
//! **Parsing** follows expat as `ET.XMLParser` drives it: one root element
//! (whitespace, comments and processing instructions around it), an XML
//! declaration only at the very start, line ends normalised to `\n`,
//! attribute values whitespace-normalised, the five predefined entities,
//! character references and the general entities of an internal DTD subset
//! expanded, CDATA read as text. Comments and processing instructions are
//! dropped (the default `TreeBuilder`), and text around them joins. Names
//! are namespace-resolved to `{uri}local` (expat's namespace mode). A
//! document expat would reject is a [`ParseError`] with expat's text and
//! position: the tag tokenized first, then `storeAtts`' checks (a duplicate
//! at its name, a bad character reference at its `&`, the rest at the tag),
//! an unclosed token at its start, an invalid one at the character expat
//! stops at, columns counted in characters (`expat_vectors.json`,
//! `scripts/gen-expat-vectors.py`, pins them against expat 2.6).
//!
//! **Serialising** is `_serialize_xml`: attributes in document order,
//! `_escape_attrib` / `_escape_cdata`, ` />` for an element with neither
//! text nor children, every tail written back, `ns0:`-style prefixes for
//! namespaced names (the well-known ones keep theirs) declared on the root,
//! sorted by prefix, and no XML declaration (`encoding="utf-8"`).
//!
//! `etree_vectors.json` (`scripts/gen-integrations-vectors.py`) pins both
//! halves against CPython 3.11.

use std::collections::HashMap;

/// One element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    /// `{uri}local`, or `local` outside any namespace.
    pub tag: String,
    /// The attributes, in document order (names namespace-resolved).
    pub attrib: Vec<(String, String)>,
    /// `text`: character data before the first child (`None` when none).
    pub text: Option<String>,
    /// `tail`: character data after the end tag (`None` when none).
    pub tail: Option<String>,
    /// The children, in order.
    pub children: Vec<Element>,
}

impl Element {
    /// `element.findall(tag)` for a plain tag: the direct children.
    pub fn findall(&self, tag: &str) -> Vec<usize> {
        self.children
            .iter()
            .enumerate()
            .filter(|(_, c)| c.tag == tag)
            .map(|(i, _)| i)
            .collect()
    }

    /// `element.find(tag)`: the first direct child named `tag`.
    pub fn find(&self, tag: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.tag == tag)
    }
}

/// `xml.etree.ElementTree.ParseError`: `str(e)`, expat's message and where
/// it stopped (`"mismatched tag: line 1, column 5"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";

fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r')
        || ('\u{20}'..='\u{D7FF}').contains(&c)
        || ('\u{E000}'..='\u{FFFD}').contains(&c)
        || c >= '\u{10000}'
}

fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == ':' || (!c.is_ascii() && c.is_alphabetic())
}

fn is_name_char(c: char) -> bool {
    is_name_start(c)
        || c.is_ascii_digit()
        || c == '-'
        || c == '.'
        || c == '\u{B7}'
        || (!c.is_ascii() && c.is_alphanumeric())
}

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

/// One element while it is open: its raw name and what has been built so
/// far.
struct Open {
    raw: String,
    element: Element,
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    entities: HashMap<String, String>,
    /// prefix → uri (`""` is the default namespace); a stack per scope.
    scopes: Vec<HashMap<String, String>>,
}

const INVALID: &str = "not well-formed (invalid token)";
const UNCLOSED: &str = "unclosed token";
const XML_DECL: &str = "XML declaration not well-formed";
const RESERVED_URI: &str = "prefix must not be bound to one of the reserved namespace names";

/// A start tag's attribute as the tokenizer saw it.
struct RawAttribute {
    name: String,
    /// Where its name starts (a duplicate is reported there).
    name_at: usize,
    /// The value between its quotes (`chars[start..end]`).
    start: usize,
    end: usize,
}

impl Parser {
    fn new(src: &str) -> Self {
        // Line ends: CR LF and lone CR become LF before anything else.
        let mut chars = Vec::with_capacity(src.len());
        let mut it = src.chars().peekable();
        while let Some(c) = it.next() {
            if c == '\r' {
                if it.peek() == Some(&'\n') {
                    it.next();
                }
                chars.push('\n');
            } else {
                chars.push(c);
            }
        }
        let mut root_scope = HashMap::new();
        root_scope.insert("xml".to_string(), XML_NS.to_string());
        Self {
            chars,
            pos: 0,
            entities: HashMap::new(),
            scopes: vec![root_scope],
        }
    }

    /// expat's error at character `at`: `"{message}: line {l}, column {c}"`
    /// (columns count characters; a line end resets them).
    fn fail<T>(&self, msg: &str, at: usize) -> Result<T, ParseError> {
        let mut line = 1;
        let mut column = 0;
        for c in self.chars.iter().take(at) {
            if *c == '\n' {
                line += 1;
                column = 0;
            } else {
                column += 1;
            }
        }
        Err(ParseError(format!("{msg}: line {line}, column {column}")))
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn starts_with(&self, s: &str) -> bool {
        (self.pos..)
            .zip(s.chars())
            .all(|(i, c)| self.chars.get(i) == Some(&c))
    }

    fn eat(&mut self, s: &str) -> bool {
        if self.starts_with(s) {
            self.pos += s.chars().count();
            true
        } else {
            false
        }
    }

    fn skip_space(&mut self) -> bool {
        let start = self.pos;
        while self.peek().is_some_and(is_space) {
            self.pos += 1;
        }
        self.pos > start
    }

    /// A name; the end of the input is the token starting at `token` left
    /// unclosed.
    fn name(&mut self, token: usize) -> Result<String, ParseError> {
        match self.peek() {
            Some(c) if is_name_start(c) => {}
            Some(_) => return self.fail(INVALID, self.pos),
            None => return self.fail(UNCLOSED, token),
        }
        let start = self.pos;
        while self.peek().is_some_and(is_name_char) {
            self.pos += 1;
        }
        Ok(self.chars[start..self.pos].iter().collect())
    }

    fn check_char(&self, c: char, at: usize) -> Result<(), ParseError> {
        if is_xml_char(c) {
            Ok(())
        } else {
            self.fail(INVALID, at)
        }
    }

    /// The next character must be `;` (or the token is unclosed).
    fn semicolon(&mut self, token: usize) -> Result<(), ParseError> {
        match self.peek() {
            Some(';') => {
                self.pos += 1;
                Ok(())
            }
            Some(_) => self.fail(INVALID, self.pos),
            None => self.fail(UNCLOSED, token),
        }
    }

    /// `&…;` after the `&` (at `amp`), as the tokenizer reads it: the
    /// reference's text, its syntax checked (`token`: what an end of input
    /// leaves unclosed).
    fn reference_syntax(&mut self, token: usize) -> Result<(), ParseError> {
        if self.eat("#") {
            let hex = self.eat("x");
            let start = self.pos;
            while self.peek().is_some_and(|c| {
                if hex {
                    c.is_ascii_hexdigit()
                } else {
                    c.is_ascii_digit()
                }
            }) {
                self.pos += 1;
            }
            if self.pos == start {
                return match self.peek() {
                    Some(_) => self.fail(INVALID, self.pos),
                    None => self.fail(UNCLOSED, token),
                };
            }
            return self.semicolon(token);
        }
        self.name(token)?;
        self.semicolon(token)
    }

    /// The replacement text of the reference `chars[amp..end]` (syntax
    /// already checked): a bad character number is reported at `amp`, an
    /// undefined entity at `undefined_at`.
    fn reference_value(
        &self,
        amp: usize,
        end: usize,
        undefined_at: usize,
    ) -> Result<String, ParseError> {
        let body: String = self.chars[amp + 1..end - 1].iter().collect();
        if let Some(number) = body.strip_prefix('#') {
            let (digits, radix) = match number.strip_prefix('x') {
                Some(h) => (h, 16),
                None => (number, 10),
            };
            let n = u32::from_str_radix(digits, radix).ok();
            return match n.and_then(char::from_u32).filter(|c| is_xml_char(*c)) {
                Some(c) => Ok(c.to_string()),
                None => self.fail("reference to invalid character number", amp),
            };
        }
        match body.as_str() {
            "lt" => Ok("<".into()),
            "gt" => Ok(">".into()),
            "amp" => Ok("&".into()),
            "apos" => Ok("'".into()),
            "quot" => Ok("\"".into()),
            other => self.expand_entity(other, 0, undefined_at),
        }
    }

    /// A general entity of the internal subset, its own references
    /// expanded (markup inside one is beyond this subset: a parse error).
    fn expand_entity(&self, name: &str, depth: usize, at: usize) -> Result<String, ParseError> {
        if depth > 32 {
            return self.fail("recursive entity reference", at);
        }
        let Some(value) = self.entities.get(name) else {
            return self.fail("undefined entity", at);
        };
        if value.contains('<') {
            return self.fail(INVALID, at);
        }
        let mut out = String::new();
        let mut rest = value.as_str();
        while let Some(i) = rest.find('&') {
            out.push_str(&rest[..i]);
            let after = &rest[i + 1..];
            let Some(end) = after.find(';') else {
                return self.fail(INVALID, at);
            };
            let inner = &after[..end];
            out.push_str(&match inner {
                "lt" => "<".to_string(),
                "gt" => ">".to_string(),
                "amp" => "&".to_string(),
                "apos" => "'".to_string(),
                "quot" => "\"".to_string(),
                other => self.expand_entity(other, depth + 1, at)?,
            });
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }

    /// After `<!--` (the comment starts at `start`).
    fn comment(&mut self, start: usize) -> Result<(), ParseError> {
        loop {
            if self.eat("-->") {
                return Ok(());
            }
            if self.starts_with("--") {
                let after = self.pos + 2;
                return if after < self.chars.len() {
                    self.fail(INVALID, after)
                } else {
                    self.fail(UNCLOSED, start)
                };
            }
            match self.peek() {
                Some(c) => {
                    self.check_char(c, self.pos)?;
                    self.pos += 1;
                }
                None => return self.fail(UNCLOSED, start),
            }
        }
    }

    /// After `<?` (the instruction starts at `start`).
    fn pi(&mut self, start: usize) -> Result<(), ParseError> {
        let target = self.name(start)?;
        if target == "xml" {
            return self.fail("XML or text declaration not at start of entity", start);
        }
        if target.eq_ignore_ascii_case("xml") || target.contains(':') {
            return self.fail(INVALID, self.pos);
        }
        if self.eat("?>") {
            return Ok(());
        }
        if self.peek().is_none() {
            return self.fail(UNCLOSED, start);
        }
        if !self.skip_space() {
            return self.fail(INVALID, self.pos);
        }
        loop {
            if self.eat("?>") {
                return Ok(());
            }
            match self.peek() {
                Some(c) => {
                    self.check_char(c, self.pos)?;
                    self.pos += 1;
                }
                None => return self.fail(UNCLOSED, start),
            }
        }
    }

    fn quoted(&mut self, token: usize) -> Result<String, ParseError> {
        let q = match self.peek() {
            Some(q @ ('"' | '\'')) => q,
            Some(_) => return self.fail(INVALID, self.pos),
            None => return self.fail(UNCLOSED, token),
        };
        self.pos += 1;
        let start = self.pos;
        while self.peek().is_some_and(|c| c != q) {
            self.pos += 1;
        }
        if self.peek().is_none() {
            return self.fail(UNCLOSED, token);
        }
        let v: String = self.chars[start..self.pos].iter().collect();
        self.pos += 1;
        Ok(v)
    }

    /// After `<?xml` (followed by a space or `?`); the declaration starts
    /// at `start`. A malformed one is reported where expat stops: the
    /// pseudo-attribute that is out of place, the character a value may
    /// not hold.
    fn xml_decl(&mut self, start: usize) -> Result<(), ParseError> {
        let mut seen: Vec<&str> = Vec::new();
        loop {
            let spaced = self.skip_space();
            let end_at = self.pos;
            if self.eat("?>") {
                if seen.first() != Some(&"version") {
                    return self.fail(XML_DECL, end_at);
                }
                return Ok(());
            }
            if self.peek().is_none() {
                return self.fail(UNCLOSED, start);
            }
            if !spaced {
                return self.fail(XML_DECL, self.pos);
            }
            let name_at = self.pos;
            if !self.peek().is_some_and(is_name_start) {
                return self.fail(XML_DECL, self.pos);
            }
            let name = self.name(start)?;
            self.skip_space();
            match self.peek() {
                Some('=') => self.pos += 1,
                Some(_) => return self.fail(XML_DECL, self.pos),
                None => return self.fail(UNCLOSED, start),
            }
            self.skip_space();
            match self.peek() {
                Some('"' | '\'') => {}
                Some(_) => return self.fail(XML_DECL, self.pos),
                None => return self.fail(UNCLOSED, start),
            }
            let value_at = self.pos + 1;
            let value = self.quoted(start)?;
            let first_bad = |ok: &dyn Fn(usize, char) -> bool| {
                value
                    .chars()
                    .enumerate()
                    .find(|(i, c)| !ok(*i, *c))
                    .map(|(i, _)| value_at + i)
            };
            match name.as_str() {
                "version" if seen.is_empty() => {
                    let bad = first_bad(&|_, c| c.is_ascii_alphanumeric() || "_.:-".contains(c));
                    if let Some(at) = bad {
                        return self.fail(XML_DECL, at);
                    }
                    if value.is_empty() {
                        return self.fail(XML_DECL, value_at);
                    }
                    seen.push("version");
                }
                "encoding" if seen == ["version"] => {
                    let bad = first_bad(&|i, c| {
                        if i == 0 {
                            c.is_ascii_alphabetic()
                        } else {
                            c.is_ascii_alphanumeric() || "._-".contains(c)
                        }
                    });
                    if let Some(at) = bad {
                        return self.fail(XML_DECL, at);
                    }
                    if value.is_empty() {
                        return self.fail(XML_DECL, value_at);
                    }
                    seen.push("encoding");
                }
                "standalone"
                    if seen.first() == Some(&"version") && !seen.contains(&"standalone") =>
                {
                    if value != "yes" && value != "no" {
                        return self.fail(XML_DECL, value_at);
                    }
                    seen.push("standalone");
                }
                _ => return self.fail(XML_DECL, name_at),
            }
        }
    }

    /// After `<!DOCTYPE` (the declaration starts at `start`).
    fn doctype(&mut self, start: usize) -> Result<(), ParseError> {
        if !self.skip_space() {
            return self.fail("syntax error", self.pos);
        }
        self.name(start)?;
        loop {
            self.skip_space();
            match self.peek() {
                Some('>') => {
                    self.pos += 1;
                    return Ok(());
                }
                Some('[') => {
                    self.pos += 1;
                    self.internal_subset(start)?;
                }
                Some('"' | '\'') => {
                    self.quoted(start)?;
                }
                Some(c) if is_name_start(c) => {
                    self.name(start)?;
                }
                Some(_) => return self.fail("syntax error", self.pos),
                None => return self.fail(UNCLOSED, start),
            }
        }
    }

    fn internal_subset(&mut self, start: usize) -> Result<(), ParseError> {
        loop {
            self.skip_space();
            let at = self.pos;
            if self.eat("]") {
                return Ok(());
            }
            if self.eat("<!--") {
                self.comment(at)?;
            } else if self.eat("<!ENTITY") {
                if !self.skip_space() {
                    return self.fail("syntax error", self.pos);
                }
                let parameter = self.eat("%");
                if parameter {
                    self.skip_space();
                }
                let name = self.name(at)?;
                self.skip_space();
                if matches!(self.peek(), Some('"' | '\'')) {
                    let raw = self.quoted(at)?;
                    if !parameter && !self.entities.contains_key(&name) {
                        let value = self.expand_literal(&raw, at)?;
                        self.entities.insert(name, value);
                    }
                }
                self.skip_to_decl_end(at)?;
            } else if self.eat("<?") {
                self.pi(at)?;
            } else if self.eat("<!") {
                self.skip_to_decl_end(at)?;
            } else if self.peek() == Some('%') {
                self.pos += 1;
                self.name(at)?;
                if !self.eat(";") {
                    return self.fail("syntax error", self.pos);
                }
            } else if self.peek().is_none() {
                return self.fail(UNCLOSED, start);
            } else {
                return self.fail("syntax error", self.pos);
            }
        }
    }

    fn skip_to_decl_end(&mut self, token: usize) -> Result<(), ParseError> {
        loop {
            match self.peek() {
                Some('>') => {
                    self.pos += 1;
                    return Ok(());
                }
                Some('"' | '\'') => {
                    self.quoted(token)?;
                }
                Some(_) => self.pos += 1,
                None => return self.fail(UNCLOSED, token),
            }
        }
    }

    /// Character and predefined references in an entity's literal value.
    fn expand_literal(&self, raw: &str, at: usize) -> Result<String, ParseError> {
        let mut sub = Parser::new(raw);
        sub.entities = self.entities.clone();
        let mut out = String::new();
        while let Some(c) = sub.peek() {
            let amp = sub.pos;
            sub.pos += 1;
            if c == '&' {
                if sub.reference_syntax(amp).is_err() {
                    return self.fail(INVALID, at);
                }
                if sub.chars.get(amp + 1) == Some(&'#') {
                    match sub.reference_value(amp, sub.pos, amp) {
                        Ok(v) => out.push_str(&v),
                        Err(_) => return self.fail("reference to invalid character number", at),
                    }
                } else {
                    // a general entity reference stays as written
                    out.extend(sub.chars[amp..sub.pos].iter());
                }
            } else {
                out.push(c);
            }
        }
        Ok(out)
    }

    /// An attribute value, as the tokenizer reads it: its quotes, no `<`,
    /// the characters and the references' syntax. Its text is expanded
    /// later ([`Parser::attribute_text`]).
    fn attribute_value(&mut self, tag: usize) -> Result<(usize, usize), ParseError> {
        let q = match self.peek() {
            Some(q @ ('"' | '\'')) => q,
            Some(_) => return self.fail(INVALID, self.pos),
            None => return self.fail(UNCLOSED, tag),
        };
        self.pos += 1;
        let start = self.pos;
        loop {
            match self.peek() {
                None => return self.fail(UNCLOSED, tag),
                Some(c) if c == q => {
                    let end = self.pos;
                    self.pos += 1;
                    return Ok((start, end));
                }
                Some('<') => return self.fail(INVALID, self.pos),
                Some('&') => {
                    self.pos += 1;
                    self.reference_syntax(tag)?;
                }
                Some(c) => {
                    self.check_char(c, self.pos)?;
                    self.pos += 1;
                }
            }
        }
    }

    /// `storeAtts`' normalisation of a value: references expanded (a bad
    /// character number at its `&`, an undefined entity at the tag) and
    /// whitespace made spaces.
    fn attribute_text(&self, start: usize, end: usize, tag: usize) -> Result<String, ParseError> {
        let mut out = String::new();
        let mut i = start;
        while i < end {
            let c = self.chars[i];
            if c == '&' {
                let close = (i..end)
                    .find(|j| self.chars[*j] == ';')
                    .map_or(end, |j| j + 1);
                out.push_str(&self.reference_value(i, close, tag)?);
                i = close;
            } else {
                out.push(if is_space(c) { ' ' } else { c });
                i += 1;
            }
        }
        Ok(out)
    }

    fn resolve(&self, raw: &str, attribute: bool, tag: usize) -> Result<String, ParseError> {
        let (prefix, local) = match raw.split_once(':') {
            Some((p, l)) => {
                if p.is_empty() || l.is_empty() || l.contains(':') {
                    return self.fail(INVALID, tag);
                }
                (p, l)
            }
            None => ("", raw),
        };
        if prefix.is_empty() && attribute {
            return Ok(local.to_string());
        }
        let uri = self
            .scopes
            .iter()
            .rev()
            .find_map(|s| s.get(prefix))
            .cloned();
        match uri {
            Some(u) if !u.is_empty() => Ok(format!("{{{u}}}{local}")),
            Some(_) | None if prefix.is_empty() => Ok(local.to_string()),
            _ => self.fail("unbound prefix", tag),
        }
    }

    /// `addBinding`'s checks of a namespace declaration.
    fn binding_error(prefix: Option<&str>, uri: &str) -> Option<&'static str> {
        if uri.is_empty() && prefix.is_some() {
            return Some("must not undeclare prefix");
        }
        if prefix == Some("xmlns") {
            return Some("reserved prefix (xmlns) must not be declared or undeclared");
        }
        let must_be_xml = prefix == Some("xml");
        let is_xml = uri == XML_NS;
        if must_be_xml != is_xml {
            return Some(if must_be_xml {
                "reserved prefix (xml) must not be undeclared or bound to another namespace name"
            } else {
                RESERVED_URI
            });
        }
        if uri == XMLNS_NS {
            return Some(RESERVED_URI);
        }
        None
    }

    /// `<` (at `tag`) already consumed, at the name: the tag tokenized
    /// first, then `storeAtts` — per attribute in order its duplicate, its
    /// value, its namespace binding; then the prefixed names.
    fn start_tag(&mut self, tag: usize) -> Result<(Open, bool), ParseError> {
        let raw = self.name(tag)?;
        let mut raw_attrs: Vec<RawAttribute> = Vec::new();
        let empty;
        loop {
            let spaced = self.skip_space();
            if self.eat("/>") {
                empty = true;
                break;
            }
            if self.eat(">") {
                empty = false;
                break;
            }
            if self.peek().is_none() {
                return self.fail(UNCLOSED, tag);
            }
            if !spaced {
                return self.fail(INVALID, self.pos);
            }
            let name_at = self.pos;
            let name = self.name(tag)?;
            self.skip_space();
            match self.peek() {
                Some('=') => self.pos += 1,
                Some(_) => return self.fail(INVALID, self.pos),
                None => return self.fail(UNCLOSED, tag),
            }
            self.skip_space();
            let (start, end) = self.attribute_value(tag)?;
            raw_attrs.push(RawAttribute {
                name,
                name_at,
                start,
                end,
            });
        }
        let mut scope = HashMap::new();
        let mut plain = Vec::new();
        for (i, attr) in raw_attrs.iter().enumerate() {
            if raw_attrs[..i].iter().any(|a| a.name == attr.name) {
                return self.fail("duplicate attribute", attr.name_at);
            }
            let value = self.attribute_text(attr.start, attr.end, tag)?;
            let prefix = if attr.name == "xmlns" {
                Some(None)
            } else {
                attr.name.strip_prefix("xmlns:").map(Some)
            };
            match prefix {
                Some(prefix) => {
                    if let Some(message) = Self::binding_error(prefix, &value) {
                        return self.fail(message, tag);
                    }
                    scope.insert(prefix.unwrap_or_default().to_string(), value);
                }
                None => plain.push((attr.name.clone(), value)),
            }
        }
        self.scopes.push(scope);
        let mut attrib: Vec<(String, String)> = Vec::new();
        for (name, value) in plain {
            let key = self.resolve(&name, true, tag)?;
            if attrib.iter().any(|(k, _)| *k == key) {
                return self.fail("duplicate attribute", tag);
            }
            attrib.push((key, value));
        }
        let element_tag = self.resolve(&raw, false, tag)?;
        Ok((
            Open {
                raw,
                element: Element {
                    tag: element_tag,
                    attrib,
                    text: None,
                    tail: None,
                    children: Vec::new(),
                },
            },
            empty,
        ))
    }

    /// `<!` in content (at `start`): a comment or a CDATA section, else the
    /// first character that cannot follow.
    fn markup_declaration(&mut self, start: usize, data: &mut String) -> Result<(), ParseError> {
        if self.eat("--") {
            return self.comment(start);
        }
        if self.peek() == Some('-') {
            return match self.chars.get(self.pos + 1) {
                Some(_) => self.fail(INVALID, self.pos + 1),
                None => self.fail(UNCLOSED, start),
            };
        }
        if self.peek() == Some('[') {
            for expected in "[CDATA[".chars() {
                match self.peek() {
                    Some(c) if c == expected => self.pos += 1,
                    Some(_) => return self.fail(INVALID, self.pos),
                    None => return self.fail(UNCLOSED, start),
                }
            }
            loop {
                if self.eat("]]>") {
                    return Ok(());
                }
                match self.peek() {
                    Some(c) => {
                        self.check_char(c, self.pos)?;
                        data.push(c);
                        self.pos += 1;
                    }
                    None => return self.fail("unclosed CDATA section", self.pos),
                }
            }
        }
        match self.peek() {
            Some(_) => self.fail(INVALID, self.pos),
            None => self.fail(UNCLOSED, start),
        }
    }

    /// `<!` after the root (not a comment): a declaration is junk, a
    /// malformed one an invalid token where expat's prolog tokenizer stops.
    fn epilog_declaration(&self, at: usize) -> Result<Element, ParseError> {
        let mut i = at + 2;
        match self.chars.get(i) {
            None => return self.fail(UNCLOSED, at),
            Some('-') => {
                return match self.chars.get(i + 1) {
                    None => self.fail(UNCLOSED, at),
                    Some(_) => self.fail(INVALID, i + 1),
                };
            }
            Some(c) if is_name_start(*c) => {}
            Some(_) => return self.fail(INVALID, i),
        }
        while self.chars.get(i).is_some_and(|c| is_name_char(*c)) {
            i += 1;
        }
        match self.chars.get(i) {
            None => self.fail(UNCLOSED, at),
            Some(c) if is_space(*c) => self.fail("junk after document element", at),
            Some(_) => self.fail(INVALID, i),
        }
    }

    fn parse(mut self) -> Result<Element, ParseError> {
        if self.peek() == Some('\u{FEFF}') {
            self.pos += 1;
        }
        if self.starts_with("<?xml")
            && self
                .chars
                .get(self.pos + 5)
                .is_some_and(|c| is_space(*c) || *c == '?')
        {
            let start = self.pos;
            self.pos += 5;
            self.xml_decl(start)?;
        }
        let mut doctype_seen = false;
        // Prolog.
        loop {
            self.skip_space();
            let at = self.pos;
            if self.eat("<!--") {
                self.comment(at)?;
            } else if self.eat("<?") {
                self.pi(at)?;
            } else if self.starts_with("<!DOCTYPE") {
                if doctype_seen {
                    return self.fail("syntax error", at);
                }
                doctype_seen = true;
                self.pos += 9;
                self.doctype(at)?;
            } else if self.peek() == Some('<') {
                break;
            } else if self.peek().is_none() {
                return self.fail("no element found", self.pos);
            } else {
                return self.fail("syntax error", at);
            }
        }
        // The root and its content.
        let root_at = self.pos;
        self.pos += 1;
        let (open, empty) = self.start_tag(root_at)?;
        let mut stack: Vec<Open> = Vec::new();
        let root = if empty {
            self.scopes.pop();
            open.element
        } else {
            stack.push(open);
            let mut finished: Option<Element> = None;
            let mut data = String::new();
            while finished.is_none() {
                let Some(c) = self.peek() else {
                    return self.fail("no element found", self.pos);
                };
                let at = self.pos;
                if c == '<' {
                    self.pos += 1;
                    match self.peek() {
                        None => return self.fail(UNCLOSED, at),
                        Some('!') => {
                            self.pos += 1;
                            self.markup_declaration(at, &mut data)?;
                        }
                        Some('?') => {
                            self.pos += 1;
                            self.pi(at)?;
                        }
                        Some('/') => {
                            self.pos += 1;
                            let name_at = self.pos;
                            let name = self.name(at)?;
                            self.skip_space();
                            match self.peek() {
                                Some('>') => self.pos += 1,
                                Some(_) => return self.fail(INVALID, self.pos),
                                None => return self.fail(UNCLOSED, at),
                            }
                            let Some(mut done) = stack.pop() else {
                                return self.fail(INVALID, at);
                            };
                            if done.raw != name {
                                return self.fail("mismatched tag", name_at);
                            }
                            flush(&mut data, &mut done.element);
                            self.scopes.pop();
                            match stack.last_mut() {
                                Some(parent) => parent.element.children.push(done.element),
                                None => finished = Some(done.element),
                            }
                        }
                        Some(_) => {
                            if let Some(parent) = stack.last_mut() {
                                flush(&mut data, &mut parent.element);
                            }
                            let (open, empty) = self.start_tag(at)?;
                            if empty {
                                self.scopes.pop();
                                if let Some(parent) = stack.last_mut() {
                                    parent.element.children.push(open.element);
                                }
                            } else {
                                stack.push(open);
                            }
                        }
                    }
                } else if c == '&' {
                    self.pos += 1;
                    self.reference_syntax(at)?;
                    let replacement = self.reference_value(at, self.pos, at)?;
                    data.push_str(&replacement);
                } else {
                    if self.starts_with("]]>") {
                        return self.fail(INVALID, self.pos + 2);
                    }
                    self.check_char(c, self.pos)?;
                    data.push(c);
                    self.pos += 1;
                }
            }
            match finished {
                Some(root) => root,
                None => return self.fail("no element found", self.pos),
            }
        };
        // Epilog.
        loop {
            self.skip_space();
            let at = self.pos;
            let Some(c) = self.peek() else {
                break;
            };
            if self.eat("<!--") {
                self.comment(at)?;
            } else if self.eat("<?") {
                self.pi(at)?;
            } else if self.starts_with("<!") {
                return self.epilog_declaration(at);
            } else if c == '<' {
                return match self.chars.get(at + 1) {
                    None => self.fail(UNCLOSED, at),
                    Some(n) if is_name_start(*n) => self.fail("junk after document element", at),
                    Some(_) => self.fail(INVALID, at + 1),
                };
            } else {
                self.check_char(c, at)?;
                return self.fail("junk after document element", at);
            }
        }
        Ok(root)
    }
}

/// `TreeBuilder._flush`: pending data becomes the text of the open element
/// (when it has no child yet) or the tail of its last child.
fn flush(data: &mut String, open: &mut Element) {
    if data.is_empty() {
        return;
    }
    let text = std::mem::take(data);
    match open.children.last_mut() {
        Some(last) => last.tail = Some(text),
        None => open.text = Some(text),
    }
}

/// `ET.fromstring(text)`.
pub fn fromstring(text: &str) -> Result<Element, ParseError> {
    Parser::new(text).parse()
}

fn escape_cdata(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_attrib(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\r', "&#13;")
        .replace('\n', "&#10;")
        .replace('\t', "&#09;")
}

fn well_known(uri: &str) -> Option<&'static str> {
    match uri {
        XML_NS => Some("xml"),
        "http://www.w3.org/1999/xhtml" => Some("html"),
        "http://www.w3.org/1999/02/22-rdf-syntax-ns#" => Some("rdf"),
        "http://schemas.xmlsoap.org/wsdl/" => Some("wsdl"),
        "http://www.w3.org/2001/XMLSchema" => Some("xs"),
        "http://www.w3.org/2001/XMLSchema-instance" => Some("xsi"),
        "http://purl.org/dc/elements/1.1/" => Some("dc"),
        _ => None,
    }
}

/// `_namespaces(elem)`: qualified name → serialised name, and uri → prefix.
struct Names {
    qnames: HashMap<String, String>,
    namespaces: Vec<(String, String)>,
}

impl Names {
    fn add(&mut self, qname: &str) {
        if self.qnames.contains_key(qname) {
            return;
        }
        let serialised = match qname.strip_prefix('{').and_then(|r| r.rsplit_once('}')) {
            Some((uri, local)) => {
                let prefix = match self.namespaces.iter().find(|(u, _)| u == uri) {
                    Some((_, p)) => p.clone(),
                    None => {
                        let prefix = well_known(uri)
                            .map(str::to_string)
                            .unwrap_or_else(|| format!("ns{}", self.namespaces.len()));
                        if prefix != "xml" {
                            self.namespaces.push((uri.to_string(), prefix.clone()));
                        }
                        prefix
                    }
                };
                if prefix.is_empty() {
                    local.to_string()
                } else {
                    format!("{prefix}:{local}")
                }
            }
            None => qname.to_string(),
        };
        self.qnames.insert(qname.to_string(), serialised);
    }

    fn collect(&mut self, e: &Element) {
        self.add(&e.tag);
        for (k, _) in &e.attrib {
            self.add(k);
        }
        for c in &e.children {
            self.collect(c);
        }
    }

    fn get<'a>(&'a self, qname: &'a str) -> &'a str {
        self.qnames.get(qname).map_or(qname, String::as_str)
    }
}

fn serialize(out: &mut String, e: &Element, names: &Names, root: bool) {
    let tag = names.get(&e.tag);
    out.push('<');
    out.push_str(tag);
    if root {
        let mut declared = names.namespaces.clone();
        declared.sort_by(|a, b| a.1.cmp(&b.1));
        for (uri, prefix) in declared {
            let k = if prefix.is_empty() {
                String::new()
            } else {
                format!(":{prefix}")
            };
            out.push_str(&format!(" xmlns{k}=\"{}\"", escape_attrib(&uri)));
        }
    }
    for (k, v) in &e.attrib {
        out.push_str(&format!(" {}=\"{}\"", names.get(k), escape_attrib(v)));
    }
    let text = e.text.as_deref().unwrap_or_default();
    if !text.is_empty() || !e.children.is_empty() {
        out.push('>');
        out.push_str(&escape_cdata(text));
        for c in &e.children {
            serialize(out, c, names, false);
        }
        out.push_str("</");
        out.push_str(tag);
        out.push('>');
    } else {
        out.push_str(" />");
    }
    if let Some(tail) = e.tail.as_deref() {
        out.push_str(&escape_cdata(tail));
    }
}

/// `ET.tostring(root, encoding="utf-8").decode("utf-8")`.
pub fn tostring(root: &Element) -> String {
    let mut names = Names {
        qnames: HashMap::new(),
        namespaces: Vec::new(),
    };
    names.collect(root);
    let mut out = String::new();
    // The root's own tail is not part of the document.
    let mut root = root.clone();
    root.tail = None;
    serialize(&mut out, &root, &names, true);
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn round_trip_keeps_layout_and_drops_comments() {
        let doc = "<?xml version=\"1.0\"?>\r\n<!-- c --><a x=\"1&amp;2\" y='q\"'>\n  <b>t &gt; u<!-- in --> v</b>\n  <c/>\n</a>\n";
        let root = fromstring(doc).unwrap();
        assert_eq!(
            tostring(&root),
            "<a x=\"1&amp;2\" y=\"q&quot;\">\n  <b>t &gt; u v</b>\n  <c />\n</a>"
        );
    }

    #[test]
    fn malformed_documents_are_parse_errors() {
        for doc in [
            "",
            "<a>",
            "<a></b>",
            "<a/><b/>",
            "<a>&nope;</a>",
            "<a x='1' x='2'/>",
            "<a>\u{1}</a>",
            "x<a/>",
            "<a><?xml version='1.0'?></a>",
            "<p:a/>",
            "<a>]]></a>",
            "<a><!-- -- --></a>",
        ] {
            assert!(fromstring(doc).is_err(), "{doc:?}");
        }
    }

    /// `ET.fromstring` against expat 2.6 (`scripts/gen-expat-vectors.py`):
    /// what it accepts, and each refusal's text and position.
    #[test]
    fn refusals_are_expats() {
        #[derive(serde::Deserialize)]
        struct Probe {
            text: String,
            error: Option<String>,
        }
        #[derive(serde::Deserialize)]
        struct Vectors {
            documents: Vec<Probe>,
        }
        let v: Vectors = serde_json::from_str(include_str!("expat_vectors.json")).unwrap();
        let mut failures = Vec::new();
        for probe in v.documents {
            let got = fromstring(&probe.text).err().map(|e| e.0);
            if got != probe.error {
                failures.push(format!(
                    "{:?}: python {:?}, rust {:?}",
                    probe.text, probe.error, got
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn attributes_are_normalised_and_namespaces_resolved() {
        let root = fromstring("<a xmlns:p=\"urn:x\" p:k=\"1\n2&#10;\"><p:b/></a>").unwrap();
        assert_eq!(
            root.attrib,
            vec![("{urn:x}k".to_string(), "1 2\n".to_string())]
        );
        assert_eq!(root.children[0].tag, "{urn:x}b");
        assert_eq!(
            tostring(&root),
            "<a xmlns:ns0=\"urn:x\" ns0:k=\"1 2&#10;\"><ns0:b /></a>"
        );
    }
}
