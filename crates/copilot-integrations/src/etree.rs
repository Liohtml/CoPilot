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
//! document expat would reject is a [`ParseError`]; only the decision
//! matters to the caller (its message is replaced by a fixed one).
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

/// `xml.etree.ElementTree.ParseError` (its text approximates expat's).
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

fn err<T>(msg: &str) -> Result<T, ParseError> {
    Err(ParseError(msg.to_string()))
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

    fn name(&mut self) -> Result<String, ParseError> {
        match self.peek() {
            Some(c) if is_name_start(c) => {}
            Some(_) => return err("not well-formed (invalid token)"),
            None => return err("unclosed token"),
        }
        let start = self.pos;
        while self.peek().is_some_and(is_name_char) {
            self.pos += 1;
        }
        Ok(self.chars[start..self.pos].iter().collect())
    }

    fn check_char(c: char) -> Result<(), ParseError> {
        if is_xml_char(c) {
            Ok(())
        } else {
            err("not well-formed (invalid token)")
        }
    }

    /// `&…;` after the `&`: the replacement text.
    fn reference(&mut self) -> Result<String, ParseError> {
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
            let digits: String = self.chars[start..self.pos].iter().collect();
            if digits.is_empty() || !self.eat(";") {
                return err("not well-formed (invalid token)");
            }
            let n = u32::from_str_radix(&digits, if hex { 16 } else { 10 }).ok();
            return match n.and_then(char::from_u32).filter(|c| is_xml_char(*c)) {
                Some(c) => Ok(c.to_string()),
                None => err("reference to invalid character number"),
            };
        }
        let name = self.name()?;
        if !self.eat(";") {
            return err("not well-formed (invalid token)");
        }
        match name.as_str() {
            "lt" => Ok("<".into()),
            "gt" => Ok(">".into()),
            "amp" => Ok("&".into()),
            "apos" => Ok("'".into()),
            "quot" => Ok("\"".into()),
            other => self.expand_entity(other, 0),
        }
    }

    /// A general entity of the internal subset, its own references
    /// expanded (markup inside one is beyond this subset: a parse error).
    fn expand_entity(&self, name: &str, depth: usize) -> Result<String, ParseError> {
        if depth > 32 {
            return err("recursive entity reference");
        }
        let Some(value) = self.entities.get(name) else {
            return err("undefined entity");
        };
        if value.contains('<') {
            return err("not well-formed (invalid token)");
        }
        let mut out = String::new();
        let mut rest = value.as_str();
        while let Some(at) = rest.find('&') {
            out.push_str(&rest[..at]);
            let after = &rest[at + 1..];
            let Some(end) = after.find(';') else {
                return err("not well-formed (invalid token)");
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

    fn comment(&mut self) -> Result<(), ParseError> {
        // after "<!--"
        loop {
            if self.eat("-->") {
                return Ok(());
            }
            if self.starts_with("--") {
                return err("not well-formed (invalid token)");
            }
            match self.peek() {
                Some(c) => {
                    Self::check_char(c)?;
                    self.pos += 1;
                }
                None => return err("unclosed token"),
            }
        }
    }

    fn pi(&mut self) -> Result<(), ParseError> {
        // after "<?"
        let target = self.name()?;
        if target == "xml" {
            return err("XML or text declaration not at start of entity");
        }
        if target.contains(':') {
            return err("not well-formed (invalid token)");
        }
        if self.eat("?>") {
            return Ok(());
        }
        if !self.skip_space() {
            return err("not well-formed (invalid token)");
        }
        loop {
            if self.eat("?>") {
                return Ok(());
            }
            match self.peek() {
                Some(c) => {
                    Self::check_char(c)?;
                    self.pos += 1;
                }
                None => return err("unclosed token"),
            }
        }
    }

    fn quoted(&mut self) -> Result<String, ParseError> {
        let q = match self.peek() {
            Some(q @ ('"' | '\'')) => q,
            _ => return err("not well-formed (invalid token)"),
        };
        self.pos += 1;
        let start = self.pos;
        while self.peek().is_some_and(|c| c != q) {
            self.pos += 1;
        }
        if self.peek().is_none() {
            return err("unclosed token");
        }
        let v: String = self.chars[start..self.pos].iter().collect();
        self.pos += 1;
        Ok(v)
    }

    fn xml_decl(&mut self) -> Result<(), ParseError> {
        // after "<?xml" followed by a space
        let bad = || err("XML declaration not well-formed");
        let mut seen = Vec::new();
        loop {
            let spaced = self.skip_space();
            if self.eat("?>") {
                break;
            }
            if !spaced {
                return bad();
            }
            let name = match self.name() {
                Ok(n) => n,
                Err(_) => return bad(),
            };
            self.skip_space();
            if !self.eat("=") {
                return bad();
            }
            self.skip_space();
            let value = match self.quoted() {
                Ok(v) => v,
                Err(_) => return bad(),
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
                _ => false,
            };
            if !ok {
                return bad();
            }
            seen.push(match name.as_str() {
                "version" => "version",
                "encoding" => "encoding",
                _ => "standalone",
            });
        }
        if seen.first() != Some(&"version") {
            return bad();
        }
        Ok(())
    }

    fn doctype(&mut self) -> Result<(), ParseError> {
        // after "<!DOCTYPE"
        if !self.skip_space() {
            return err("syntax error");
        }
        self.name()?;
        loop {
            self.skip_space();
            match self.peek() {
                Some('>') => {
                    self.pos += 1;
                    return Ok(());
                }
                Some('[') => {
                    self.pos += 1;
                    self.internal_subset()?;
                }
                Some('"' | '\'') => {
                    self.quoted()?;
                }
                Some(c) if is_name_start(c) => {
                    self.name()?;
                }
                Some(_) => return err("syntax error"),
                None => return err("unclosed token"),
            }
        }
    }

    fn internal_subset(&mut self) -> Result<(), ParseError> {
        loop {
            self.skip_space();
            if self.eat("]") {
                return Ok(());
            }
            if self.eat("<!--") {
                self.comment()?;
            } else if self.eat("<!ENTITY") {
                if !self.skip_space() {
                    return err("syntax error");
                }
                let parameter = self.eat("%");
                if parameter {
                    self.skip_space();
                }
                let name = self.name()?;
                self.skip_space();
                if matches!(self.peek(), Some('"' | '\'')) {
                    let raw = self.quoted()?;
                    if !parameter && !self.entities.contains_key(&name) {
                        let value = self.expand_literal(&raw)?;
                        self.entities.insert(name, value);
                    }
                }
                self.skip_to_decl_end()?;
            } else if self.eat("<?") {
                self.pi()?;
            } else if self.eat("<!") {
                self.skip_to_decl_end()?;
            } else if self.peek() == Some('%') {
                self.pos += 1;
                self.name()?;
                if !self.eat(";") {
                    return err("syntax error");
                }
            } else if self.peek().is_none() {
                return err("unclosed token");
            } else {
                return err("syntax error");
            }
        }
    }

    fn skip_to_decl_end(&mut self) -> Result<(), ParseError> {
        loop {
            match self.peek() {
                Some('>') => {
                    self.pos += 1;
                    return Ok(());
                }
                Some('"' | '\'') => {
                    self.quoted()?;
                }
                Some(_) => self.pos += 1,
                None => return err("unclosed token"),
            }
        }
    }

    /// Character and predefined references in an entity's literal value.
    fn expand_literal(&self, raw: &str) -> Result<String, ParseError> {
        let mut sub = Parser::new(raw);
        sub.entities = self.entities.clone();
        let mut out = String::new();
        while let Some(c) = sub.peek() {
            sub.pos += 1;
            if c == '&' {
                if sub.peek() == Some('#') {
                    out.push_str(&sub.reference()?);
                } else {
                    // a general entity reference stays as written
                    let start = sub.pos - 1;
                    sub.name()?;
                    if !sub.eat(";") {
                        return err("not well-formed (invalid token)");
                    }
                    out.extend(sub.chars[start..sub.pos].iter());
                }
            } else {
                out.push(c);
            }
        }
        Ok(out)
    }

    /// An attribute value between its quotes, references expanded and
    /// whitespace normalised.
    fn attribute_value(&mut self) -> Result<String, ParseError> {
        let q = match self.peek() {
            Some(q @ ('"' | '\'')) => q,
            _ => return err("not well-formed (invalid token)"),
        };
        self.pos += 1;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return err("unclosed token"),
                Some(c) if c == q => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some('<') => return err("not well-formed (invalid token)"),
                Some('&') => {
                    self.pos += 1;
                    let replacement = self.reference()?;
                    out.push_str(&replacement);
                }
                Some(c) => {
                    Self::check_char(c)?;
                    self.pos += 1;
                    out.push(if is_space(c) { ' ' } else { c });
                }
            }
        }
    }

    fn resolve(&self, raw: &str, attribute: bool) -> Result<String, ParseError> {
        let (prefix, local) = match raw.split_once(':') {
            Some((p, l)) => {
                if p.is_empty() || l.is_empty() || l.contains(':') {
                    return err("not well-formed (invalid token)");
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
            _ => err("unbound prefix"),
        }
    }

    /// `<` already consumed, at the name.
    fn start_tag(&mut self) -> Result<(Open, bool), ParseError> {
        let raw = self.name()?;
        let mut raw_attrs: Vec<(String, String)> = Vec::new();
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
                return err("unclosed token");
            }
            if !spaced {
                return err("not well-formed (invalid token)");
            }
            let name = self.name()?;
            self.skip_space();
            if !self.eat("=") {
                return err("not well-formed (invalid token)");
            }
            self.skip_space();
            let value = self.attribute_value()?;
            if raw_attrs.iter().any(|(n, _)| *n == name) {
                return err("duplicate attribute");
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
                    return err(
                        "reserved prefix (xml) must not be undeclared or bound to another namespace name",
                    );
                }
                if value.is_empty() {
                    return err("must not undeclare prefix");
                }
                if value == XMLNS_NS || (value == XML_NS && prefix != "xml") {
                    return err("reserved prefix (xmlns) must not be declared or undeclared");
                }
                scope.insert(prefix.to_string(), value);
            } else {
                plain.push((name, value));
            }
        }
        self.scopes.push(scope);
        let tag = self.resolve(&raw, false)?;
        let mut attrib: Vec<(String, String)> = Vec::new();
        for (name, value) in plain {
            let key = self.resolve(&name, true)?;
            if attrib.iter().any(|(k, _)| *k == key) {
                return err("duplicate attribute");
            }
            attrib.push((key, value));
        }
        Ok((
            Open {
                raw,
                element: Element {
                    tag,
                    attrib,
                    text: None,
                    tail: None,
                    children: Vec::new(),
                },
            },
            empty,
        ))
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
            self.pos += 5;
            self.xml_decl()?;
        }
        let mut doctype_seen = false;
        // Prolog.
        loop {
            self.skip_space();
            if self.eat("<!--") {
                self.comment()?;
            } else if self.eat("<?") {
                self.pi()?;
            } else if self.starts_with("<!DOCTYPE") {
                if doctype_seen {
                    return err("syntax error");
                }
                doctype_seen = true;
                self.pos += 9;
                self.doctype()?;
            } else if self.peek() == Some('<') {
                break;
            } else if self.peek().is_none() {
                return err("no element found");
            } else {
                return err("syntax error");
            }
        }
        // The root and its content.
        self.pos += 1;
        let (open, empty) = self.start_tag()?;
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
                    return err("no element found");
                };
                if c == '<' {
                    if self.eat("<!--") {
                        self.comment()?;
                    } else if self.eat("<![CDATA[") {
                        loop {
                            if self.eat("]]>") {
                                break;
                            }
                            match self.peek() {
                                Some(c) => {
                                    Self::check_char(c)?;
                                    data.push(c);
                                    self.pos += 1;
                                }
                                None => return err("unclosed CDATA section"),
                            }
                        }
                    } else if self.eat("<?") {
                        self.pi()?;
                    } else if self.eat("</") {
                        let name = self.name()?;
                        self.skip_space();
                        if !self.eat(">") {
                            return err("not well-formed (invalid token)");
                        }
                        let Some(mut done) = stack.pop() else {
                            return err("not well-formed (invalid token)");
                        };
                        if done.raw != name {
                            return err("mismatched tag");
                        }
                        flush(&mut data, &mut done.element);
                        self.scopes.pop();
                        match stack.last_mut() {
                            Some(parent) => parent.element.children.push(done.element),
                            None => finished = Some(done.element),
                        }
                    } else if self.eat("<!") {
                        return err("syntax error");
                    } else {
                        self.pos += 1;
                        if let Some(parent) = stack.last_mut() {
                            flush(&mut data, &mut parent.element);
                        }
                        let (open, empty) = self.start_tag()?;
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
                    let replacement = self.reference()?;
                    data.push_str(&replacement);
                } else {
                    if self.starts_with("]]>") {
                        return err("not well-formed (invalid token)");
                    }
                    Self::check_char(c)?;
                    data.push(c);
                    self.pos += 1;
                }
            }
            finished.ok_or_else(|| ParseError("no element found".into()))?
        };
        // Epilog.
        loop {
            self.skip_space();
            if self.peek().is_none() {
                break;
            }
            if self.eat("<!--") {
                self.comment()?;
            } else if self.eat("<?") {
                self.pi()?;
            } else {
                return err("junk after document element");
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
