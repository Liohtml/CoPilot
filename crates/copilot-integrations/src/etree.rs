//! The part of `xml.etree.ElementTree` the Office365 and AWS flows use on
//! the Wazuh manager's `ossec.conf`: `ET.fromstring(text)` (and the
//! comment-keeping `XMLParser(target=TreeBuilder(insert_comments=True))`),
//! `findall`, `find`, `findtext`, `Element.remove` / `insert`,
//! `ET.tostring(…)` in its three encodings, `ET.indent` and the equality
//! `ET.canonicalize(…, strip_text=True)` gives.
//!
//! **Parsing** follows expat as `ET.XMLParser` drives it: one root element
//! (whitespace, comments and processing instructions around it), an XML
//! declaration only at the very start, line ends normalised to `\n`,
//! attribute values whitespace-normalised, the five predefined entities,
//! character references and the general entities of an internal DTD subset
//! expanded, CDATA read as text. Processing instructions are dropped, and so
//! are comments unless asked for ([`fromstring_with_comments`]); text around
//! a dropped node joins. Names are namespace-resolved to `{uri}local`
//! (expat's namespace mode). A document expat would reject is a
//! [`ParseError`] carrying expat's message and the position expat reports
//! (`junk after document element: line 6, column 0`), which the provisioning
//! flows put into their answers.
//!
//! **Serialising** is `_serialize_xml`: attributes in document order,
//! `_escape_attrib` / `_escape_cdata`, ` />` for an element with neither
//! text nor children, every tail written back, comments as `<!--…-->`,
//! `ns0:`-style prefixes for namespaced names (the well-known ones keep
//! theirs) declared on the element serialised, sorted by prefix, and no XML
//! declaration; `us-ascii` (`ET.tostring`'s default) writes every non-ASCII
//! character as a decimal character reference.
//!
//! `etree_vectors.json` (`scripts/gen-integrations-vectors.py`) and
//! `etree_expat_vectors.json` (`scripts/gen-remaining-provisioning-vectors.py`)
//! pin both halves against CPython 3.11 and its expat.

use std::collections::HashMap;
use std::fmt;

/// The tag of a comment node (`ET.Comment`): not a valid XML name, so no
/// `find`/`findall` ever matches it.
pub const COMMENT: &str = "!--";

/// One element (or, with the tag [`COMMENT`], one comment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    /// `{uri}local`, or `local` outside any namespace.
    pub tag: String,
    /// The attributes, in document order (names namespace-resolved).
    pub attrib: Vec<(String, String)>,
    /// `text`: character data before the first child (`None` when none);
    /// a comment's own text.
    pub text: Option<String>,
    /// `tail`: character data after the end tag (`None` when none).
    pub tail: Option<String>,
    /// The children, in order.
    pub children: Vec<Element>,
}

impl Element {
    /// `ET.Element(tag, attrib)`.
    pub fn new(tag: &str, attrib: Vec<(String, String)>) -> Self {
        Self {
            tag: tag.to_string(),
            attrib,
            text: None,
            tail: None,
            children: Vec::new(),
        }
    }

    /// `ET.SubElement(self, tag).text = text`: the new child's index.
    pub fn sub(&mut self, tag: &str, text: Option<&str>) -> usize {
        let mut child = Element::new(tag, Vec::new());
        child.text = text.map(str::to_string);
        self.children.push(child);
        self.children.len() - 1
    }

    /// Whether this node is a comment.
    pub fn is_comment(&self) -> bool {
        self.tag == COMMENT
    }

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

    /// `element.findtext(tag)`: the first such child's text (`""` when it
    /// has none), `None` without such a child.
    pub fn findtext(&self, tag: &str) -> Option<&str> {
        self.find(tag)
            .map(|c| c.text.as_deref().unwrap_or_default())
    }

    /// `element.get(key)`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.attrib
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// `element.iter()`: this node and every descendant, in document order.
    pub fn iter(&self) -> Vec<&Element> {
        let mut out = vec![self];
        for c in &self.children {
            out.extend(c.iter());
        }
        out
    }
}

/// `xml.etree.ElementTree.ParseError`: expat's message and position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// expat's error string (`mismatched tag`).
    pub message: String,
    /// 1-based line.
    pub line: usize,
    /// 0-based column, in characters.
    pub column: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: line {}, column {}",
            self.message, self.line, self.column
        )
    }
}

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";

const INVALID: &str = "not well-formed (invalid token)";
const UNCLOSED: &str = "unclosed token";

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

/// One element while it is open: its raw name, where its start tag began,
/// and what has been built so far.
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
    /// Keep comments (`TreeBuilder(insert_comments=True)`).
    comments: bool,
}

type Res<T> = Result<T, ParseError>;

impl Parser {
    fn new(src: &str, comments: bool) -> Self {
        // Line ends: CR LF and lone CR become LF before anything else (expat
        // counts either as one line end).
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
            comments,
        }
    }

    /// The error `message` at character `at`.
    fn fail<T>(&self, at: usize, message: &str) -> Res<T> {
        let at = at.min(self.chars.len());
        let mut line = 1;
        let mut start = 0;
        for (i, c) in self.chars[..at].iter().enumerate() {
            if *c == '\n' {
                line += 1;
                start = i + 1;
            }
        }
        Err(ParseError {
            message: message.to_string(),
            line,
            column: at - start,
        })
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn at(&self, i: usize) -> Option<char> {
        self.chars.get(i).copied()
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

    /// A name at the current position; `token` is where the enclosing
    /// markup began (an end of input there is an unclosed token).
    fn name(&mut self, token: usize) -> Res<String> {
        match self.peek() {
            Some(c) if is_name_start(c) => {}
            Some(_) => return self.fail(self.pos, INVALID),
            None => return self.fail(token, UNCLOSED),
        }
        let start = self.pos;
        while self.peek().is_some_and(is_name_char) {
            self.pos += 1;
        }
        Ok(self.chars[start..self.pos].iter().collect())
    }

    fn check_char(&self, c: char) -> Res<()> {
        if is_xml_char(c) {
            Ok(())
        } else {
            self.fail(self.pos, INVALID)
        }
    }

    /// `&…;` with the `&` at `amp` and the position after it: the
    /// replacement text.
    fn reference(&mut self, amp: usize) -> Res<String> {
        if self.eat("#") {
            let hex = self.eat("x");
            let start = self.pos;
            loop {
                match self.peek() {
                    None => return self.fail(amp, UNCLOSED),
                    Some(';') if self.pos > start => break,
                    Some(c) if (hex && c.is_ascii_hexdigit()) || (!hex && c.is_ascii_digit()) => {
                        self.pos += 1;
                    }
                    Some(_) => return self.fail(self.pos, INVALID),
                }
            }
            let digits: String = self.chars[start..self.pos].iter().collect();
            self.pos += 1;
            let n = u32::from_str_radix(&digits, if hex { 16 } else { 10 }).ok();
            return match n.and_then(char::from_u32).filter(|c| is_xml_char(*c)) {
                Some(c) => Ok(c.to_string()),
                None => self.fail(amp, "reference to invalid character number"),
            };
        }
        let name = self.name(amp)?;
        match self.peek() {
            Some(';') => self.pos += 1,
            Some(_) => return self.fail(self.pos, INVALID),
            None => return self.fail(amp, UNCLOSED),
        }
        match name.as_str() {
            "lt" => Ok("<".into()),
            "gt" => Ok(">".into()),
            "amp" => Ok("&".into()),
            "apos" => Ok("'".into()),
            "quot" => Ok("\"".into()),
            other => match self.expand_entity(other, 0) {
                Ok(v) => Ok(v),
                Err(message) => self.fail(amp, message),
            },
        }
    }

    /// A general entity of the internal subset, its own references
    /// expanded (markup inside one is beyond this subset: a parse error).
    fn expand_entity(&self, name: &str, depth: usize) -> Result<String, &'static str> {
        if depth > 32 {
            return Err("recursive entity reference");
        }
        let Some(value) = self.entities.get(name) else {
            return Err("undefined entity");
        };
        if value.contains('<') {
            return Err(INVALID);
        }
        let mut out = String::new();
        let mut rest = value.as_str();
        while let Some(at) = rest.find('&') {
            out.push_str(&rest[..at]);
            let after = &rest[at + 1..];
            let Some(end) = after.find(';') else {
                return Err(INVALID);
            };
            let inner = &after[..end];
            out.push_str(&match inner {
                "lt" => "<".to_string(),
                "gt" => ">".to_string(),
                "amp" => "&".to_string(),
                "apos" => "'".to_string(),
                "quot" => "\"".to_string(),
                other => self.expand_entity(other, depth + 1)?,
            });
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }

    /// After `<!--`, the `<` at `token`: the comment's text.
    fn comment(&mut self, token: usize) -> Res<String> {
        let start = self.pos;
        loop {
            if self.starts_with("--") {
                if self.at(self.pos + 2) == Some('>') {
                    let text: String = self.chars[start..self.pos].iter().collect();
                    self.pos += 3;
                    return Ok(text);
                }
                if self.at(self.pos + 2).is_none() {
                    return self.fail(token, UNCLOSED);
                }
                return self.fail(self.pos + 2, INVALID);
            }
            match self.peek() {
                Some(c) => {
                    self.check_char(c)?;
                    self.pos += 1;
                }
                None => return self.fail(token, UNCLOSED),
            }
        }
    }

    /// After `<?`, the `<` at `token`.
    fn pi(&mut self, token: usize) -> Res<()> {
        let target = self.name(token)?;
        if target.eq_ignore_ascii_case("xml") {
            return self.fail(token, "XML or text declaration not at start of entity");
        }
        if let Some(i) = target.find(':') {
            let colon = self.pos - target[i..].chars().count();
            return self.fail(colon, INVALID);
        }
        if self.eat("?>") {
            return Ok(());
        }
        match self.peek() {
            None => return self.fail(token, UNCLOSED),
            Some(c) if is_space(c) => {}
            Some(_) => return self.fail(self.pos, INVALID),
        }
        loop {
            if self.eat("?>") {
                return Ok(());
            }
            match self.peek() {
                Some(c) => {
                    self.check_char(c)?;
                    self.pos += 1;
                }
                None => return self.fail(token, UNCLOSED),
            }
        }
    }

    fn quoted(&mut self, token: usize) -> Res<String> {
        let q = match self.peek() {
            Some(q @ ('"' | '\'')) => q,
            None => return self.fail(token, UNCLOSED),
            _ => return self.fail(self.pos, INVALID),
        };
        self.pos += 1;
        let start = self.pos;
        while self.peek().is_some_and(|c| c != q) {
            self.pos += 1;
        }
        if self.peek().is_none() {
            return self.fail(token, UNCLOSED);
        }
        let v: String = self.chars[start..self.pos].iter().collect();
        self.pos += 1;
        Ok(v)
    }

    /// After `<?xml` followed by a space or `?`.
    fn xml_decl(&mut self) -> Res<()> {
        const BAD: &str = "XML declaration not well-formed";
        let mut seen: Vec<&str> = Vec::new();
        loop {
            let spaced = self.skip_space();
            if self.eat("?>") {
                break;
            }
            if self.peek().is_none() {
                return self.fail(0, UNCLOSED);
            }
            if !spaced {
                return self.fail(self.pos, BAD);
            }
            let at_name = self.pos;
            let name = match self.name(0) {
                Ok(n) => n,
                Err(_) => return self.fail(at_name, BAD),
            };
            self.skip_space();
            if !self.eat("=") {
                return self.fail(self.pos, BAD);
            }
            self.skip_space();
            let value_at = self.pos + 1;
            let value = match self.quoted(0) {
                Ok(v) => v,
                Err(e) if e.message == UNCLOSED => return Err(e),
                Err(_) => return self.fail(self.pos, BAD),
            };
            let ok = match name.as_str() {
                "version" => {
                    seen.is_empty()
                        && !value.is_empty()
                        && value
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c))
                }
                "encoding" => {
                    seen == ["version"]
                        && value
                            .chars()
                            .next()
                            .is_some_and(|c| c.is_ascii_alphabetic())
                        && value
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
                }
                "standalone" => {
                    seen.first().is_some_and(|f| *f == "version")
                        && !seen.contains(&"standalone")
                        && (value == "yes" || value == "no")
                }
                _ => return self.fail(at_name, BAD),
            };
            if !ok {
                return self.fail(value_at, BAD);
            }
            seen.push(match name.as_str() {
                "version" => "version",
                "encoding" => "encoding",
                _ => "standalone",
            });
        }
        if seen.first() != Some(&"version") {
            return self.fail(5, BAD);
        }
        Ok(())
    }

    /// After `<!DOCTYPE`, the `<` at `token`.
    fn doctype(&mut self, token: usize) -> Res<()> {
        if !self.skip_space() {
            return self.fail(self.pos, "syntax error");
        }
        self.name(token)?;
        loop {
            self.skip_space();
            match self.peek() {
                Some('>') => {
                    self.pos += 1;
                    return Ok(());
                }
                Some('[') => {
                    self.pos += 1;
                    self.internal_subset(token)?;
                }
                Some('"' | '\'') => {
                    self.quoted(token)?;
                }
                Some(c) if is_name_start(c) => {
                    self.name(token)?;
                }
                Some(_) => return self.fail(self.pos, "syntax error"),
                None => return self.fail(token, UNCLOSED),
            }
        }
    }

    fn internal_subset(&mut self, token: usize) -> Res<()> {
        loop {
            self.skip_space();
            if self.eat("]") {
                return Ok(());
            }
            let here = self.pos;
            if self.eat("<!--") {
                self.comment(here)?;
            } else if self.eat("<!ENTITY") {
                if !self.skip_space() {
                    return self.fail(self.pos, "syntax error");
                }
                let parameter = self.eat("%");
                if parameter {
                    self.skip_space();
                }
                let name = self.name(here)?;
                self.skip_space();
                if matches!(self.peek(), Some('"' | '\'')) {
                    let raw = self.quoted(here)?;
                    if !parameter && !self.entities.contains_key(&name) {
                        let value = self.expand_literal(&raw, here)?;
                        self.entities.insert(name, value);
                    }
                }
                self.skip_to_decl_end(here)?;
            } else if self.eat("<?") {
                self.pi(here)?;
            } else if self.eat("<!") {
                self.skip_to_decl_end(here)?;
            } else if self.peek() == Some('%') {
                self.pos += 1;
                self.name(here)?;
                if !self.eat(";") {
                    return self.fail(self.pos, "syntax error");
                }
            } else if self.peek().is_none() {
                return self.fail(token, UNCLOSED);
            } else {
                return self.fail(self.pos, "syntax error");
            }
        }
    }

    fn skip_to_decl_end(&mut self, token: usize) -> Res<()> {
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
                None => return self.fail(token, UNCLOSED),
            }
        }
    }

    /// Character and predefined references in an entity's literal value.
    fn expand_literal(&self, raw: &str, token: usize) -> Res<String> {
        let mut sub = Parser::new(raw, false);
        sub.entities = self.entities.clone();
        let mut out = String::new();
        while let Some(c) = sub.peek() {
            sub.pos += 1;
            if c == '&' {
                let amp = sub.pos - 1;
                if sub.peek() == Some('#') {
                    match sub.reference(amp) {
                        Ok(v) => out.push_str(&v),
                        Err(e) => return self.fail(token, &e.message),
                    }
                } else {
                    // a general entity reference stays as written
                    if sub.name(amp).is_err() || !sub.eat(";") {
                        return self.fail(token, INVALID);
                    }
                    out.extend(sub.chars[amp..sub.pos].iter());
                }
            } else {
                out.push(c);
            }
        }
        Ok(out)
    }

    /// An attribute value between its quotes, references expanded and
    /// whitespace normalised; the start tag's `<` at `token`. An undefined
    /// entity is reported at the start tag.
    fn attribute_value(&mut self, token: usize) -> Res<String> {
        let q = match self.peek() {
            Some(q @ ('"' | '\'')) => q,
            None => return self.fail(token, UNCLOSED),
            _ => return self.fail(self.pos, INVALID),
        };
        self.pos += 1;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return self.fail(token, UNCLOSED),
                Some(c) if c == q => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some('<') => return self.fail(self.pos, INVALID),
                Some('&') => {
                    let amp = self.pos;
                    self.pos += 1;
                    match self.reference(amp) {
                        Ok(r) => out.push_str(&r),
                        Err(e) if e.message == UNCLOSED => return self.fail(token, UNCLOSED),
                        Err(e) if e.message == "undefined entity" => {
                            return self.fail(token, "undefined entity");
                        }
                        Err(e) => return Err(e),
                    }
                }
                Some(c) => {
                    self.check_char(c)?;
                    self.pos += 1;
                    out.push(if is_space(c) { ' ' } else { c });
                }
            }
        }
    }

    fn resolve(&self, raw: &str, attribute: bool, token: usize) -> Res<String> {
        let (prefix, local) = match raw.split_once(':') {
            Some((p, l)) => {
                if p.is_empty() || l.is_empty() || l.contains(':') {
                    return self.fail(token, INVALID);
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
            _ => self.fail(token, "unbound prefix"),
        }
    }

    /// `<` already consumed (it is at `token`), at the name.
    fn start_tag(&mut self, token: usize) -> Res<(Open, bool)> {
        let raw = self.name(token)?;
        let mut raw_attrs: Vec<(String, String)> = Vec::new();
        let empty;
        loop {
            let spaced = self.skip_space();
            if self.starts_with("/") {
                match self.at(self.pos + 1) {
                    Some('>') => {
                        self.pos += 2;
                        empty = true;
                        break;
                    }
                    None => return self.fail(token, UNCLOSED),
                    Some(_) => return self.fail(self.pos + 1, INVALID),
                }
            }
            if self.eat(">") {
                empty = false;
                break;
            }
            if self.peek().is_none() {
                return self.fail(token, UNCLOSED);
            }
            if !spaced || !self.peek().is_some_and(is_name_start) {
                return self.fail(self.pos, INVALID);
            }
            let name_at = self.pos;
            let name = self.name(token)?;
            self.skip_space();
            match self.peek() {
                Some('=') => self.pos += 1,
                None => return self.fail(token, UNCLOSED),
                Some(_) => return self.fail(self.pos, INVALID),
            }
            self.skip_space();
            let value = self.attribute_value(token)?;
            if raw_attrs.iter().any(|(n, _)| *n == name) {
                return self.fail(name_at, "duplicate attribute");
            }
            raw_attrs.push((name, value));
        }
        // Namespace declarations first, then the names.
        let mut scope = HashMap::new();
        let mut plain = Vec::new();
        for (name, value) in raw_attrs {
            if name == "xmlns" {
                scope.insert(String::new(), value);
            } else if let Some(prefix) = name.strip_prefix("xmlns:") {
                if prefix == "xmlns" || (prefix == "xml" && value != XML_NS) {
                    return self.fail(
                        token,
                        "reserved prefix (xml) must not be undeclared or bound to another namespace name",
                    );
                }
                if value.is_empty() {
                    return self.fail(token, "must not undeclare prefix");
                }
                if value == XMLNS_NS || (value == XML_NS && prefix != "xml") {
                    return self.fail(
                        token,
                        "reserved prefix (xmlns) must not be declared or undeclared",
                    );
                }
                scope.insert(prefix.to_string(), value);
            } else {
                plain.push((name, value));
            }
        }
        self.scopes.push(scope);
        let tag = self.resolve(&raw, false, token)?;
        let mut attrib: Vec<(String, String)> = Vec::new();
        for (name, value) in plain {
            let key = self.resolve(&name, true, token)?;
            if attrib.iter().any(|(k, _)| *k == key) {
                return self.fail(token, "duplicate attribute");
            }
            attrib.push((key, value));
        }
        Ok((
            Open {
                raw,
                element: Element::new(&tag, attrib),
            },
            empty,
        ))
    }

    /// One token of expat's prolog tokenizer that is not markup, at a
    /// character that is neither whitespace nor `<`: `Ok(start)` for a
    /// complete name, literal or delimiter, the error where it breaks.
    fn prolog_token(&mut self) -> Res<usize> {
        let start = self.pos;
        let Some(c) = self.peek() else {
            return Ok(start);
        };
        if is_name_char(c) {
            while self.peek().is_some_and(is_name_char) {
                self.pos += 1;
            }
            return match self.peek() {
                None => Ok(start),
                Some(n)
                    if is_space(n)
                        || matches!(n, '>' | ')' | ',' | '|' | ']' | '%' | '+' | '*' | '?') =>
                {
                    Ok(start)
                }
                Some(_) => self.fail(self.pos, INVALID),
            };
        }
        if c == '"' || c == '\'' {
            self.pos += 1;
            while self.peek().is_some_and(|x| x != c) {
                self.pos += 1;
            }
            if self.peek().is_none() {
                return self.fail(start, UNCLOSED);
            }
            self.pos += 1;
            return match self.peek() {
                None => Ok(start),
                Some(n) if is_space(n) || matches!(n, '>' | '%' | '[') => Ok(start),
                Some(_) => self.fail(self.pos, INVALID),
            };
        }
        if matches!(c, '[' | ']' | '(' | ')' | '|' | ',' | '%' | '>') {
            return Ok(start);
        }
        self.fail(start, INVALID)
    }

    /// A comment in the content: kept (with `insert_comments`) as a child
    /// of the open element, the pending text flushed first.
    fn content_comment(&self, stack: &mut [Open], data: &mut String, text: String) {
        if !self.comments {
            return;
        }
        if let Some(parent) = stack.last_mut() {
            flush(data, &mut parent.element);
            let mut node = Element::new(COMMENT, Vec::new());
            node.text = Some(text);
            parent.element.children.push(node);
        }
    }

    fn parse(mut self) -> Res<Element> {
        if self.peek() == Some('\u{FEFF}') {
            self.pos += 1;
        }
        if self.starts_with("<?xml")
            && self
                .chars
                .get(self.pos + 5)
                .is_some_and(|c| is_space(*c) || *c == '?')
        {
            self.pos += 5;
            self.xml_decl()?;
        }
        let mut doctype_seen = false;
        // Prolog.
        loop {
            self.skip_space();
            let here = self.pos;
            if self.eat("<!--") {
                self.comment(here)?;
            } else if self.starts_with("<?") {
                self.pos += 2;
                self.pi(here)?;
            } else if self.starts_with("<!DOCTYPE") {
                if doctype_seen {
                    return self.fail(here, "syntax error");
                }
                doctype_seen = true;
                self.pos += 9;
                self.doctype(here)?;
            } else if self.starts_with("<!") {
                return self.fail(here + 2, INVALID);
            } else if self.peek() == Some('<') {
                break;
            } else if self.peek().is_none() {
                return self.fail(self.chars.len(), "no element found");
            } else {
                let start = self.prolog_token()?;
                return self.fail(start, "syntax error");
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
                    return self.fail(self.chars.len(), "no element found");
                };
                let here = self.pos;
                if c == '<' {
                    if self.eat("<!--") {
                        let text = self.comment(here)?;
                        self.content_comment(&mut stack, &mut data, text);
                    } else if self.eat("<![CDATA[") {
                        loop {
                            if self.eat("]]>") {
                                break;
                            }
                            match self.peek() {
                                Some(c) => {
                                    self.check_char(c)?;
                                    data.push(c);
                                    self.pos += 1;
                                }
                                None => {
                                    return self.fail(self.chars.len(), "unclosed CDATA section");
                                }
                            }
                        }
                    } else if self.eat("<?") {
                        self.pi(here)?;
                    } else if self.eat("</") {
                        let name = self.name(here)?;
                        self.skip_space();
                        match self.peek() {
                            Some('>') => self.pos += 1,
                            None => return self.fail(here, UNCLOSED),
                            Some(_) => return self.fail(self.pos, INVALID),
                        }
                        let Some(mut done) = stack.pop() else {
                            return self.fail(here, INVALID);
                        };
                        if done.raw != name {
                            return self.fail(here + 2, "mismatched tag");
                        }
                        flush(&mut data, &mut done.element);
                        self.scopes.pop();
                        match stack.last_mut() {
                            Some(parent) => parent.element.children.push(done.element),
                            None => finished = Some(done.element),
                        }
                    } else if self.eat("<!") {
                        return match self.peek() {
                            None => self.fail(here, UNCLOSED),
                            Some(_) => self.fail(here + 2, INVALID),
                        };
                    } else {
                        self.pos += 1;
                        if self.peek().is_none() {
                            return self.fail(here, UNCLOSED);
                        }
                        if let Some(parent) = stack.last_mut() {
                            flush(&mut data, &mut parent.element);
                        }
                        let (open, empty) = self.start_tag(here)?;
                        if empty {
                            self.scopes.pop();
                            if let Some(parent) = stack.last_mut() {
                                parent.element.children.push(open.element);
                            }
                        } else {
                            stack.push(open);
                        }
                    }
                } else if c == '&' {
                    self.pos += 1;
                    let replacement = self.reference(here)?;
                    data.push_str(&replacement);
                } else {
                    if self.starts_with("]]>") {
                        return self.fail(here + 2, INVALID);
                    }
                    self.check_char(c)?;
                    data.push(c);
                    self.pos += 1;
                }
            }
            match finished {
                Some(root) => root,
                None => return self.fail(self.chars.len(), "no element found"),
            }
        };
        // Epilog.
        loop {
            self.skip_space();
            let here = self.pos;
            if self.peek().is_none() {
                break;
            }
            if self.eat("<!--") {
                self.comment(here)?;
            } else if self.starts_with("<?") {
                self.pos += 2;
                match self.pi(here) {
                    Ok(()) => {}
                    Err(e) if e.message.starts_with("XML or text") => {
                        return self.fail(here, "junk after document element");
                    }
                    Err(e) => return Err(e),
                }
            } else if self.starts_with("</") {
                return self.fail(here + 1, INVALID);
            } else if self.peek() == Some('<') {
                return self.fail(here, "junk after document element");
            } else {
                let start = self.prolog_token()?;
                return self.fail(start, "junk after document element");
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
        Some(last) => match &mut last.tail {
            Some(tail) => tail.push_str(&text),
            None => last.tail = Some(text),
        },
        None => match &mut open.text {
            Some(t) => t.push_str(&text),
            None => open.text = Some(text),
        },
    }
}

/// `ET.fromstring(text)` (comments dropped).
pub fn fromstring(text: &str) -> Result<Element, ParseError> {
    Parser::new(text, false).parse()
}

/// `XMLParser(target=TreeBuilder(insert_comments=True))` fed `text`: the
/// root with its comments as [`COMMENT`] children.
pub fn fromstring_with_comments(text: &str) -> Result<Element, ParseError> {
    Parser::new(text, true).parse()
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
    fn of(e: &Element) -> Self {
        let mut names = Names {
            qnames: HashMap::new(),
            namespaces: Vec::new(),
        };
        names.collect(e);
        names
    }

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
        if e.is_comment() {
            return;
        }
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
    if e.is_comment() {
        out.push_str("<!--");
        out.push_str(e.text.as_deref().unwrap_or_default());
        out.push_str("-->");
    } else {
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
    }
    if let Some(tail) = e.tail.as_deref() {
        out.push_str(&escape_cdata(tail));
    }
}

/// `ET.tostring(element, encoding="unicode")`: the element, its tail
/// included.
pub fn tostring_unicode(e: &Element) -> String {
    let names = Names::of(e);
    let mut out = String::new();
    serialize(&mut out, e, &names, true);
    out
}

/// `ET.tostring(root, encoding="utf-8").decode("utf-8")` of a parsed root
/// (its tail, which a parsed root never has, left out).
pub fn tostring(root: &Element) -> String {
    let mut root = root.clone();
    root.tail = None;
    tostring_unicode(&root)
}

/// `ET.tostring(element).decode()`: `us-ascii` with every non-ASCII
/// character as a decimal character reference (the tail included).
pub fn tostring_ascii(e: &Element) -> String {
    let mut out = String::new();
    for c in tostring_unicode(e).chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            out.push_str(&format!("&#{};", u32::from(c)));
        }
    }
    out
}

/// `ET.indent(element, space, level)`.
pub fn indent(e: &mut Element, space: &str, level: usize) {
    if e.children.is_empty() {
        return;
    }
    let mut indentations = vec![format!("\n{}", space.repeat(level))];
    indent_children(e, 0, space, &mut indentations);
}

fn py_isspace_only(s: &str) -> bool {
    s.chars().all(py_is_space)
}

/// `str.isspace()` for one character (what `str.strip()` strips).
pub fn py_is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.strip()`.
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(py_is_space)
}

fn indent_children(e: &mut Element, level: usize, space: &str, indentations: &mut Vec<String>) {
    let child_level = level + 1;
    if indentations.len() <= child_level {
        let next = format!("{}{space}", indentations[level]);
        indentations.push(next);
    }
    let child_indentation = indentations[child_level].clone();
    if e.text.as_deref().is_none_or(py_isspace_only) {
        e.text = Some(child_indentation.clone());
    }
    for child in &mut e.children {
        if !child.children.is_empty() {
            indent_children(child, child_level, space, indentations);
        }
        if child.tail.as_deref().is_none_or(py_isspace_only) {
            child.tail = Some(child_indentation.clone());
        }
    }
    if let Some(last) = e.children.last_mut() {
        if last.tail.as_deref().is_some_and(py_isspace_only) {
            last.tail = Some(indentations[level].clone());
        }
    }
}

/// The equality `ET.canonicalize(ET.tostring(e, encoding="unicode"),
/// with_comments=…, strip_text=True)` gives: two elements have the same
/// canonical form exactly when their C14N 2.0 serialisations are equal
/// (the text written here is not C14N's own, only as discriminating).
/// `Err` is the parse error that re-reading the serialisation raises — a
/// tail with text in it is junk after the document element.
pub fn canonical(e: &Element, with_comments: bool) -> Result<String, ParseError> {
    if let Some(tail) = &e.tail {
        if let Some(k) = tail.find(|c: char| !is_space(c)) {
            let mut head = e.clone();
            head.tail = None;
            let before = tostring_unicode(&head);
            let full = format!("{before}{}", escape_cdata(tail));
            let at = before.chars().count() + escape_cdata(&tail[..k]).chars().count();
            return Parser::new(&full, false).fail(at, "junk after document element");
        }
    }
    let mut out = String::new();
    let mut data = String::new();
    c14n(e, with_comments, &mut out, &mut data, false);
    Ok(out)
}

fn c14n_flush(out: &mut String, data: &mut String, preserve: bool) {
    let text = std::mem::take(data);
    let text = if preserve {
        text.as_str()
    } else {
        py_strip(&text)
    };
    if !text.is_empty() {
        out.push_str(
            &text
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('\r', "&#xD;"),
        );
    }
}

fn c14n(e: &Element, with_comments: bool, out: &mut String, data: &mut String, preserve: bool) {
    if e.is_comment() {
        if with_comments {
            c14n_flush(out, data, preserve);
            out.push_str("<!--");
            out.push_str(e.text.as_deref().unwrap_or_default());
            out.push_str("-->");
        }
        return;
    }
    c14n_flush(out, data, preserve);
    let space_key = format!("{{{XML_NS}}}space");
    let preserve = match e.get(&space_key) {
        Some(v) => v == "preserve",
        None => preserve,
    };
    out.push('<');
    out.push_str(&e.tag);
    let mut attrib = e.attrib.clone();
    attrib.sort_by_key(|a| split_qname(&a.0));
    for (k, v) in &attrib {
        out.push(' ');
        out.push_str(k);
        out.push_str("=\"");
        out.push_str(
            &v.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('"', "&quot;")
                .replace('\t', "&#x9;")
                .replace('\n', "&#xA;")
                .replace('\r', "&#xD;"),
        );
        out.push('"');
    }
    out.push('>');
    if let Some(t) = &e.text {
        data.push_str(t);
    }
    for c in &e.children {
        c14n(c, with_comments, out, data, preserve);
        if let Some(t) = &c.tail {
            data.push_str(t);
        }
    }
    c14n_flush(out, data, preserve);
    out.push_str("</");
    out.push_str(&e.tag);
    out.push('>');
}

fn split_qname(q: &str) -> (String, String) {
    match q.strip_prefix('{').and_then(|r| r.split_once('}')) {
        Some((uri, local)) => (uri.to_string(), local.to_string()),
        None => (String::new(), q.to_string()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use serde_json::Value;

    #[test]
    fn round_trip_keeps_layout_and_drops_comments() {
        let doc = "<?xml version=\"1.0\"?>\r\n<!-- c --><a x=\"1&amp;2\" y='q\"'>\n  <b>t &gt; u<!-- in --> v</b>\n  <c/>\n</a>\n";
        let root = fromstring(doc).unwrap();
        assert_eq!(
            tostring(&root),
            "<a x=\"1&amp;2\" y=\"q&quot;\">\n  <b>t &gt; u v</b>\n  <c />\n</a>"
        );
        let kept = fromstring_with_comments(doc).unwrap();
        assert_eq!(
            tostring(&kept),
            "<a x=\"1&amp;2\" y=\"q&quot;\">\n  <b>t &gt; u<!-- in --> v</b>\n  <c />\n</a>"
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

    /// `etree_expat_vectors.json`: expat's verdict and message for every
    /// probe, the comment-keeping parse, `tostring` in its encodings,
    /// `ET.indent` and the C14N equality.
    #[test]
    fn expat_vectors() {
        let doc: Value = serde_json::from_str(include_str!("etree_expat_vectors.json")).unwrap();
        for v in doc["parse"].as_array().unwrap() {
            let input = v["doc"].as_str().unwrap();
            let got = match fromstring(input) {
                Ok(root) => format!("OK {}", tostring(&root)),
                Err(e) => e.to_string(),
            };
            assert_eq!(got, v["result"].as_str().unwrap(), "{input:?}");
        }
        for v in doc["comments"].as_array().unwrap() {
            let input = v["doc"].as_str().unwrap();
            let root = fromstring_with_comments(input).unwrap();
            assert_eq!(tostring(&root), v["unicode"].as_str().unwrap(), "{input:?}");
            assert_eq!(
                tostring_ascii(&root),
                v["ascii"].as_str().unwrap(),
                "{input:?}"
            );
            let mut indented = root.clone();
            indent(&mut indented, "  ", 1);
            assert_eq!(
                tostring(&indented),
                v["indent"].as_str().unwrap(),
                "{input:?}"
            );
        }
        for v in doc["canonical"].as_array().unwrap() {
            let a = fromstring_with_comments(v["a"].as_str().unwrap()).unwrap();
            let b = fromstring_with_comments(v["b"].as_str().unwrap()).unwrap();
            for (key, comments) in [("equal", false), ("equal_with_comments", true)] {
                let same = canonical(&a, comments).unwrap() == canonical(&b, comments).unwrap();
                assert_eq!(same, v[key].as_bool().unwrap(), "{} {key}", v["a"]);
            }
        }
    }
}
