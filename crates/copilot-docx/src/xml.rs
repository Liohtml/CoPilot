//! The XML that python-docx and docxtpl see: lxml 6 over libxml2 2.14.
//!
//! A tree of elements keeping what libxml2 keeps (prefixes as written,
//! namespace declarations apart from the attributes, adjacent text merged),
//! parsed with `remove_blank_text` (libxml2's `areBlanks` heuristic) or
//! keeping every blank, and serialized as `etree.tostring` writes it: the
//! declarations before the attributes, `<a/>` for an element without
//! children, libxml2's escapes. A recovering parse (`recover=True`) only
//! drops the characters XML does not allow, as libxml2 does; any other
//! malformation is an error here ([`crate::DocxError::Recover`]: the report
//! route hands such a request to the Python backend).

use std::fmt::Write as _;

/// The namespace `xml:` is bound to without a declaration.
pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// One node of an element's content.
#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    /// An element.
    Element(Element),
    /// Character data (entity and character references decoded).
    Text(String),
    /// A comment.
    Comment(String),
    /// A processing instruction: target and data.
    Pi(String, String),
}

/// An attribute, its prefix as written and its namespace.
#[derive(Debug, Clone, PartialEq)]
pub struct Attr {
    /// The prefix as written.
    pub prefix: Option<String>,
    /// The local name.
    pub local: String,
    /// The namespace URI the prefix is bound to.
    pub ns: Option<String>,
    /// The value, normalized and decoded.
    pub value: String,
}

/// An element.
#[derive(Debug, Clone, PartialEq)]
pub struct Element {
    /// The prefix as written.
    pub prefix: Option<String>,
    /// The local name.
    pub local: String,
    /// The namespace URI.
    pub ns: Option<String>,
    /// `xmlns` / `xmlns:p` declarations, in document order.
    pub ns_defs: Vec<(Option<String>, String)>,
    /// The attributes, in document order.
    pub attrs: Vec<Attr>,
    /// The content.
    pub children: Vec<Node>,
}

/// A parse failure (lxml's `XMLSyntaxError`).
#[derive(Debug, Clone, PartialEq)]
pub struct XmlError(pub String);

impl std::fmt::Display for XmlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for XmlError {}

/// How a parse treats blanks and errors.
#[derive(Debug, Clone, Copy, Default)]
pub struct ParseOptions {
    /// `remove_blank_text=True`.
    pub remove_blank_text: bool,
    /// `recover=True` (only the invalid characters are recovered from).
    pub recover: bool,
}

impl Element {
    /// A new element with a namespace and a prefix.
    pub fn new(prefix: Option<&str>, local: &str, ns: Option<&str>) -> Self {
        Self {
            prefix: prefix.map(str::to_string),
            local: local.to_string(),
            ns: ns.map(str::to_string),
            ns_defs: Vec::new(),
            attrs: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Whether this element is `{ns}local`.
    pub fn is(&self, ns: &str, local: &str) -> bool {
        self.local == local && self.ns.as_deref() == Some(ns)
    }

    /// The qualified name as written.
    pub fn qname(&self) -> String {
        match &self.prefix {
            Some(p) => format!("{p}:{}", self.local),
            None => self.local.clone(),
        }
    }

    /// The child elements.
    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }

    /// `find(tag)`: the first child element `{ns}local`.
    pub fn find(&self, ns: &str, local: &str) -> Option<&Element> {
        self.elements().find(|e| e.is(ns, local))
    }

    /// `find(tag)`, mutably.
    pub fn find_mut(&mut self, ns: &str, local: &str) -> Option<&mut Element> {
        self.children.iter_mut().find_map(|n| match n {
            Node::Element(e) if e.is(ns, local) => Some(e),
            _ => None,
        })
    }

    /// `findall(tag)`: the child elements `{ns}local`.
    pub fn findall(&self, ns: &str, local: &str) -> Vec<&Element> {
        self.elements().filter(|e| e.is(ns, local)).collect()
    }

    /// `get(key)` of an attribute in a namespace (or none).
    pub fn get(&self, ns: Option<&str>, local: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.local == local && a.ns.as_deref() == ns)
            .map(|a| a.value.as_str())
    }

    /// `set(key, value)`: replaces the attribute in place, else appends it
    /// with `prefix` (lxml's `_findOrBuildNodeNs`).
    pub fn set(&mut self, ns: Option<&str>, prefix: Option<&str>, local: &str, value: &str) {
        if let Some(a) = self
            .attrs
            .iter_mut()
            .find(|a| a.local == local && a.ns.as_deref() == ns)
        {
            a.value = value.to_string();
            return;
        }
        self.attrs.push(Attr {
            prefix: prefix.map(str::to_string),
            local: local.to_string(),
            ns: ns.map(str::to_string),
            value: value.to_string(),
        });
    }

    /// `.text`: the leading text node, `None` when there is none.
    pub fn text(&self) -> Option<&str> {
        match self.children.first() {
            Some(Node::Text(t)) => Some(t),
            _ => None,
        }
    }

    /// `.text = value`: the leading text nodes replaced by one.
    pub fn set_text(&mut self, value: &str) {
        let keep = self
            .children
            .iter()
            .position(|n| !matches!(n, Node::Text(_)))
            .unwrap_or(self.children.len());
        self.children.drain(..keep);
        self.children.insert(0, Node::Text(value.to_string()));
    }

    /// Index paths (from this element, which is `[]`) of every element
    /// `{ns}local` in document order, this one included (`iter(tag)`).
    pub fn iter_paths(&self, ns: &str, local: &str) -> Vec<Vec<usize>> {
        let mut out = Vec::new();
        let mut path = Vec::new();
        collect_paths(self, ns, local, &mut path, &mut out);
        out
    }

    /// The element at an index path.
    pub fn at(&self, path: &[usize]) -> Option<&Element> {
        let mut cur = self;
        for &i in path {
            match cur.children.get(i) {
                Some(Node::Element(e)) => cur = e,
                _ => return None,
            }
        }
        Some(cur)
    }

    /// The element at an index path, mutably.
    pub fn at_mut(&mut self, path: &[usize]) -> Option<&mut Element> {
        let mut cur = self;
        for &i in path {
            match cur.children.get_mut(i) {
                Some(Node::Element(e)) => cur = e,
                _ => return None,
            }
        }
        Some(cur)
    }

    /// `remove(child)` of the `index`-th child: its tail text goes with it.
    pub fn remove_child(&mut self, index: usize) {
        if index >= self.children.len() {
            return;
        }
        let mut end = index + 1;
        while matches!(self.children.get(end), Some(Node::Text(_))) {
            end += 1;
        }
        self.children.drain(index..end);
    }
}

fn collect_paths(
    e: &Element,
    ns: &str,
    local: &str,
    path: &mut Vec<usize>,
    out: &mut Vec<Vec<usize>>,
) {
    if e.is(ns, local) {
        out.push(path.clone());
    }
    for (i, c) in e.children.iter().enumerate() {
        if let Node::Element(child) = c {
            path.push(i);
            collect_paths(child, ns, local, path, out);
            path.pop();
        }
    }
}

// ------------------------------------------------------------------ parse

/// Whether `c` is an XML 1.0 `Char`.
pub fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

fn is_name_start(c: char) -> bool {
    matches!(c, ':' | 'A'..='Z' | '_' | 'a'..='z'
        | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}'
        | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}'
        | '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}'
        | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}' | '\u{10000}'..='\u{EFFFF}')
}

fn is_name_char(c: char) -> bool {
    is_name_start(c)
        || matches!(c, '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
}

fn is_blank(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

/// Parses an XML document held in bytes (UTF-8, as every part of a .docx).
pub fn parse_bytes(data: &[u8], opts: ParseOptions) -> Result<Element, XmlError> {
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    let text = std::str::from_utf8(data)
        .map_err(|_| XmlError("Input is not proper UTF-8, indicate encoding !".into()))?;
    if let Some(decl) = declaration(text) {
        if let Some(enc) = pseudo_attr(decl, "encoding") {
            let e = enc.to_ascii_lowercase();
            if e != "utf-8" && e != "utf8" && e != "us-ascii" && e != "ascii" {
                return Err(XmlError(format!("Unsupported encoding: {enc}")));
            }
        }
    }
    parse_str(text, opts)
}

fn declaration(text: &str) -> Option<&str> {
    let rest = text.strip_prefix("<?xml")?;
    if !rest.starts_with(|c: char| is_blank(c)) {
        return None;
    }
    let end = rest.find("?>")?;
    Some(&rest[..end])
}

fn pseudo_attr<'a>(decl: &'a str, name: &str) -> Option<&'a str> {
    let i = decl.find(name)?;
    let rest = decl[i + name.len()..].trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let q = rest.chars().next()?;
    if q != '"' && q != '\'' {
        return None;
    }
    let body = &rest[1..];
    let end = body.find(q)?;
    Some(&body[..end])
}

/// Parses an XML document held in a string (lxml's `fromstring(str)`).
pub fn parse_str(text: &str, opts: ParseOptions) -> Result<Element, XmlError> {
    // XML's end-of-line handling.
    let normalized: Vec<char> = {
        let mut v = Vec::with_capacity(text.len());
        let mut it = text.chars().peekable();
        while let Some(c) = it.next() {
            if c == '\r' {
                if it.peek() == Some(&'\n') {
                    it.next();
                }
                v.push('\n');
            } else {
                v.push(c);
            }
        }
        v
    };
    let mut p = Parser {
        s: normalized,
        i: 0,
        opts,
        scopes: vec![vec![(Some("xml".to_string()), XML_NS.to_string())]],
    };
    p.document()
}

struct Parser {
    s: Vec<char>,
    i: usize,
    opts: ParseOptions,
    scopes: Vec<Vec<(Option<String>, String)>>,
}

struct Frame {
    el: Element,
    /// libxml2's `ctxt->space` for this element: -1, -2, 0 or 1.
    space: i8,
}

impl Parser {
    fn err<T>(&self, msg: &str) -> Result<T, XmlError> {
        Err(XmlError(msg.to_string()))
    }

    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }

    fn at(&self, lit: &str) -> bool {
        lit.chars()
            .enumerate()
            .all(|(k, c)| self.s.get(self.i + k) == Some(&c))
    }

    fn skip_blanks(&mut self) {
        while self.peek().is_some_and(is_blank) {
            self.i += 1;
        }
    }

    fn name(&mut self) -> Result<String, XmlError> {
        match self.peek() {
            Some(c) if is_name_start(c) => {}
            _ => return self.err("StartTag: invalid element name"),
        }
        let start = self.i;
        while self.peek().is_some_and(is_name_char) {
            self.i += 1;
        }
        Ok(self.s[start..self.i].iter().collect())
    }

    fn document(&mut self) -> Result<Element, XmlError> {
        if self.at("<?xml") && self.s.get(5).is_some_and(|c| is_blank(*c)) {
            match self.find("?>") {
                Some(end) => self.i = end + 2,
                None => return self.err("parsing XML declaration: '?>' expected"),
            }
        }
        loop {
            self.skip_blanks();
            if self.at("<!--") {
                self.comment()?;
            } else if self.at("<?") {
                self.pi()?;
            } else if self.at("<!DOCTYPE") {
                return self.err("DOCTYPE is not supported");
            } else if self.at("<") {
                break;
            } else if self.peek().is_none() {
                return self.err("Document is empty");
            } else {
                return self.err("Start tag expected, '<' not found");
            }
        }
        let root = self.element()?;
        loop {
            self.skip_blanks();
            if self.peek().is_none() {
                break;
            }
            if self.at("<!--") {
                self.comment()?;
            } else if self.at("<?") {
                self.pi()?;
            } else {
                return self.err("Extra content at the end of the document");
            }
        }
        Ok(root)
    }

    fn find(&self, lit: &str) -> Option<usize> {
        let pat: Vec<char> = lit.chars().collect();
        let mut j = self.i;
        while j + pat.len() <= self.s.len() {
            if self.s[j..j + pat.len()] == pat[..] {
                return Some(j);
            }
            j += 1;
        }
        None
    }

    fn comment(&mut self) -> Result<String, XmlError> {
        self.i += 4;
        let Some(end) = self.find("--") else {
            return self.err("Comment not terminated");
        };
        if self.s.get(end + 2) != Some(&'>') {
            return self.err("Double hyphen within comment");
        }
        let text: String = self.s[self.i..end].iter().collect();
        self.check_chars(&text)?;
        self.i = end + 3;
        Ok(text)
    }

    fn pi(&mut self) -> Result<(String, String), XmlError> {
        self.i += 2;
        let target = self.name()?;
        if target.eq_ignore_ascii_case("xml") {
            return self.err("XML declaration allowed only at the start of the document");
        }
        let Some(end) = self.find("?>") else {
            return self.err("ParsePI: PI not terminated");
        };
        let mut j = self.i;
        while j < end && is_blank(self.s[j]) {
            j += 1;
        }
        if j == self.i && j < end {
            return self.err("ParsePI: PI space expected");
        }
        let data: String = self.s[j..end].iter().collect();
        self.i = end + 2;
        Ok((target, data))
    }

    fn check_chars(&self, s: &str) -> Result<(), XmlError> {
        if s.chars().all(is_xml_char) {
            Ok(())
        } else {
            self.err("Char out of allowed range")
        }
    }

    fn resolve(&self, prefix: Option<&str>) -> Option<String> {
        for scope in self.scopes.iter().rev() {
            for (p, uri) in scope.iter().rev() {
                if p.as_deref() == prefix {
                    return if uri.is_empty() {
                        None
                    } else {
                        Some(uri.clone())
                    };
                }
            }
        }
        None
    }

    fn reference(&mut self) -> Result<String, XmlError> {
        // at '&'
        self.i += 1;
        if self.peek() == Some('#') {
            self.i += 1;
            let hex = self.peek() == Some('x');
            if hex {
                self.i += 1;
            }
            let start = self.i;
            while self.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                self.i += 1;
            }
            let digits: String = self.s[start..self.i].iter().collect();
            if self.peek() != Some(';') || digits.is_empty() {
                return self.err("CharRef: invalid decimal value");
            }
            self.i += 1;
            let value = if hex {
                u32::from_str_radix(&digits, 16).ok()
            } else if digits.chars().all(|c| c.is_ascii_digit()) {
                digits.parse::<u32>().ok()
            } else {
                None
            };
            match value.and_then(char::from_u32) {
                Some(c) if is_xml_char(c) => Ok(c.to_string()),
                _ => self.err("xmlParseCharRef: invalid xmlChar value"),
            }
        } else {
            let name = self
                .name()
                .or_else(|_| self.err("EntityRef: expecting ';'"))?;
            if self.peek() != Some(';') {
                return self.err("EntityRef: expecting ';'");
            }
            self.i += 1;
            match name.as_str() {
                "lt" => Ok("<".into()),
                "gt" => Ok(">".into()),
                "amp" => Ok("&".into()),
                "apos" => Ok("'".into()),
                "quot" => Ok("\"".into()),
                _ => Err(XmlError(format!("Entity '{name}' not defined"))),
            }
        }
    }

    fn attr_value(&mut self) -> Result<String, XmlError> {
        let q = match self.peek() {
            Some(c @ ('"' | '\'')) => c,
            _ => return self.err("AttValue: \" or ' expected"),
        };
        self.i += 1;
        let mut v = String::new();
        loop {
            match self.peek() {
                None => return self.err("AttValue: ' expected"),
                Some(c) if c == q => {
                    self.i += 1;
                    break;
                }
                Some('<') => return self.err("Unescaped '<' not allowed in attributes values"),
                Some('&') => v.push_str(&self.reference()?),
                Some(c) => {
                    self.i += 1;
                    if is_blank(c) {
                        v.push(' ');
                    } else if is_xml_char(c) {
                        v.push(c);
                    } else if self.opts.recover {
                        v.push('\u{FFFD}');
                    } else {
                        return self.err("invalid character in attribute value");
                    }
                }
            }
        }
        Ok(v)
    }

    /// Parses one element (at its `<`) with its content.
    fn element(&mut self) -> Result<Element, XmlError> {
        let mut stack: Vec<Frame> = Vec::new();
        loop {
            // At the `<` of a start tag.
            let parent_space = stack.last().map_or(-1, |f| f.space);
            let (el, empty, xml_space) = self.start_tag()?;
            let mut space = if parent_space == -2 { -1 } else { parent_space };
            if let Some(v) = xml_space {
                space = v;
            }
            if empty {
                self.scopes.pop();
                match stack.last_mut() {
                    Some(top) => top.el.children.push(Node::Element(el)),
                    None => return Ok(el),
                }
            } else {
                stack.push(Frame { el, space });
            }
            // The content up to the next start tag.
            loop {
                if self.at("</") {
                    self.i += 2;
                    let name = self.name()?;
                    self.skip_blanks();
                    if self.peek() != Some('>') {
                        return self.err("expected '>'");
                    }
                    self.i += 1;
                    let Some(frame) = stack.pop() else {
                        return self.err("internal: no open element");
                    };
                    if name != frame.el.qname() {
                        return Err(XmlError(format!(
                            "Opening and ending tag mismatch: {} and {name}",
                            frame.el.qname()
                        )));
                    }
                    self.scopes.pop();
                    match stack.last_mut() {
                        Some(parent) => parent.el.children.push(Node::Element(frame.el)),
                        None => return Ok(frame.el),
                    }
                    continue;
                }
                let Some(top) = stack.last_mut() else {
                    return self.err("internal: no open element");
                };
                if self.at("<!--") {
                    let c = self.comment()?;
                    top.el.children.push(Node::Comment(c));
                } else if self.at("<![CDATA[") {
                    // lxml's default `strip_cdata=True`: plain text.
                    self.i += 9;
                    let Some(end) = self.find("]]>") else {
                        return self.err("CData section not finished");
                    };
                    let text: String = self.s[self.i..end].iter().collect();
                    self.check_chars(&text)?;
                    self.i = end + 3;
                    push_text(&mut top.el, &text);
                } else if self.at("<?") {
                    let (t, d) = self.pi()?;
                    if let Some(top) = stack.last_mut() {
                        top.el.children.push(Node::Pi(t, d));
                    }
                } else if self.at("<!") {
                    return self.err("StartTag: invalid element name");
                } else if self.at("<") {
                    break;
                } else if self.peek() == Some('&') {
                    let t = self.reference()?;
                    if let Some(top) = stack.last_mut() {
                        push_text(&mut top.el, &t);
                    }
                } else if self.peek().is_none() {
                    return self.err("Premature end of data");
                } else {
                    self.char_data(&mut stack)?;
                }
            }
        }
    }

    /// A run of character data up to the next `<` or `&`, kept or dropped
    /// as libxml2's `xmlParseCharDataInternal` and `areBlanks` decide.
    fn char_data(&mut self, stack: &mut [Frame]) -> Result<(), XmlError> {
        let start = self.i;
        let mut run = String::new();
        while let Some(c) = self.peek() {
            if c == '<' || c == '&' {
                break;
            }
            if c == ']' && self.at("]]>") {
                return self.err("Sequence ']]>' not allowed in content");
            }
            self.i += 1;
            if is_xml_char(c) {
                run.push(c);
            } else if !self.opts.recover {
                return self.err("PCDATA invalid Char value");
            }
        }
        let Some(top) = stack.last_mut() else {
            return Ok(());
        };
        if run.is_empty() {
            return Ok(());
        }
        let raw_first_blank = self.s.get(start).copied().is_some_and(is_blank);
        let non_ascii = !run.is_ascii();
        if self.opts.remove_blank_text && (raw_first_blank || non_ascii) {
            if self.are_blanks(&top.el, top.space, &run) {
                return Ok(());
            }
            if top.space == -1 {
                top.space = -2;
            }
        }
        push_text(&mut top.el, &run);
        Ok(())
    }

    fn are_blanks(&self, node: &Element, space: i8, run: &str) -> bool {
        if space == 1 || space == -2 {
            return false;
        }
        if !run.chars().all(is_blank) {
            return false;
        }
        if self.peek() != Some('<') {
            return false;
        }
        if node.children.is_empty() && self.s.get(self.i + 1) == Some(&'/') {
            return false;
        }
        match node.children.last() {
            None => {}
            Some(Node::Text(_)) => return false,
            Some(_) => {
                if matches!(node.children.first(), Some(Node::Text(_))) {
                    return false;
                }
            }
        }
        true
    }

    /// A start tag: the element, whether it is empty, its `xml:space`.
    fn start_tag(&mut self) -> Result<(Element, bool, Option<i8>), XmlError> {
        self.i += 1; // '<'
        let qname = self.name()?;
        let mut raw_attrs: Vec<(String, String)> = Vec::new();
        let mut ns_defs: Vec<(Option<String>, String)> = Vec::new();
        let empty;
        loop {
            let had_blank = self.peek().is_some_and(is_blank);
            self.skip_blanks();
            match self.peek() {
                Some('>') => {
                    self.i += 1;
                    empty = false;
                    break;
                }
                Some('/') => {
                    if self.s.get(self.i + 1) != Some(&'>') {
                        return self.err("Couldn't find end of Start Tag");
                    }
                    self.i += 2;
                    empty = true;
                    break;
                }
                None => return self.err("Couldn't find end of Start Tag"),
                Some(_) => {
                    if !had_blank {
                        return self.err("attributes construct error");
                    }
                    let name = self.name()?;
                    self.skip_blanks();
                    if self.peek() != Some('=') {
                        return Err(XmlError(format!(
                            "Specification mandates value for attribute {name}"
                        )));
                    }
                    self.i += 1;
                    self.skip_blanks();
                    let value = self.attr_value()?;
                    if name == "xmlns" {
                        if ns_defs.iter().any(|(p, _)| p.is_none()) {
                            return self.err("Attribute xmlns redefined");
                        }
                        ns_defs.push((None, value));
                    } else if let Some(p) = name.strip_prefix("xmlns:") {
                        if value.is_empty() {
                            return Err(XmlError(format!(
                                "xmlns:{p}: Empty XML namespace is not allowed"
                            )));
                        }
                        if ns_defs.iter().any(|(q, _)| q.as_deref() == Some(p)) {
                            return Err(XmlError(format!("Attribute xmlns:{p} redefined")));
                        }
                        ns_defs.push((Some(p.to_string()), value));
                    } else {
                        if raw_attrs.iter().any(|(n, _)| *n == name) {
                            return Err(XmlError(format!("Attribute {name} redefined")));
                        }
                        raw_attrs.push((name, value));
                    }
                }
            }
        }
        self.scopes.push(ns_defs.clone());
        let (prefix, local) = split_qname(&qname);
        let ns = self.resolve(prefix.as_deref());
        if prefix.is_some() && ns.is_none() {
            return Err(XmlError(format!(
                "Namespace prefix {} on {local} is not defined",
                prefix.as_deref().unwrap_or_default()
            )));
        }
        let mut attrs = Vec::with_capacity(raw_attrs.len());
        let mut xml_space = None;
        for (name, value) in raw_attrs {
            let (ap, al) = split_qname(&name);
            let ans = match &ap {
                Some(p) => match self.resolve(Some(p)) {
                    Some(u) => Some(u),
                    None => {
                        return Err(XmlError(format!(
                            "Namespace prefix {p} for {al} on {local} is not defined"
                        )));
                    }
                },
                None => None,
            };
            if ans.is_some() && attrs.iter().any(|a: &Attr| a.local == al && a.ns == ans) {
                return Err(XmlError(format!(
                    "Namespaced Attribute {al} in '{}' redefined",
                    ans.unwrap_or_default()
                )));
            }
            if ans.as_deref() == Some(XML_NS) && al == "space" {
                xml_space = match value.as_str() {
                    "preserve" => Some(1),
                    "default" => Some(0),
                    _ => None,
                };
            }
            attrs.push(Attr {
                prefix: ap,
                local: al,
                ns: ans,
                value,
            });
        }
        let el = Element {
            prefix,
            local,
            ns,
            ns_defs,
            attrs,
            children: Vec::new(),
        };
        Ok((el, empty, xml_space))
    }
}

fn split_qname(name: &str) -> (Option<String>, String) {
    match name.split_once(':') {
        Some((p, l)) if !p.is_empty() && !l.is_empty() => (Some(p.to_string()), l.to_string()),
        _ => (None, name.to_string()),
    }
}

fn push_text(el: &mut Element, t: &str) {
    if let Some(Node::Text(last)) = el.children.last_mut() {
        last.push_str(t);
    } else {
        el.children.push(Node::Text(t.to_string()));
    }
}

// -------------------------------------------------------------- serialize

/// libxml2's text escaping (`xmlEscapeText` for content).
pub fn escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
}

/// libxml2's attribute escaping.
pub fn escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            '\t' => out.push_str("&#9;"),
            c => out.push(c),
        }
    }
}

fn write_ns_def(prefix: &Option<String>, uri: &str, out: &mut String) {
    match prefix {
        Some(p) => {
            let _ = write!(out, " xmlns:{p}=\"");
        }
        None => out.push_str(" xmlns=\""),
    }
    escape_attr(uri, out);
    out.push('"');
}

fn write_element(e: &Element, extra_ns: &[(Option<String>, String)], out: &mut String) {
    let qname = e.qname();
    out.push('<');
    out.push_str(&qname);
    for (p, u) in &e.ns_defs {
        write_ns_def(p, u, out);
    }
    for (p, u) in extra_ns {
        write_ns_def(p, u, out);
    }
    for a in &e.attrs {
        out.push(' ');
        if let Some(p) = &a.prefix {
            out.push_str(p);
            out.push(':');
        }
        out.push_str(&a.local);
        out.push_str("=\"");
        escape_attr(&a.value, out);
        out.push('"');
    }
    if e.children.is_empty() {
        out.push_str("/>");
        return;
    }
    out.push('>');
    for c in &e.children {
        write_node(c, out);
    }
    out.push_str("</");
    out.push_str(&qname);
    out.push('>');
}

fn write_node(n: &Node, out: &mut String) {
    match n {
        Node::Element(e) => write_element(e, &[], out),
        Node::Text(t) => escape_text(t, out),
        Node::Comment(t) => {
            out.push_str("<!--");
            out.push_str(t);
            out.push_str("-->");
        }
        Node::Pi(t, d) => {
            out.push_str("<?");
            out.push_str(t);
            if !d.is_empty() {
                out.push(' ');
                out.push_str(d);
            }
            out.push_str("?>");
        }
    }
}

/// `etree.tostring(root, encoding="unicode")` of a root element.
pub fn to_string(e: &Element) -> String {
    let mut out = String::new();
    write_element(e, &[], &mut out);
    out
}

/// `etree.tostring(el, encoding="unicode")` of an element below the root:
/// the declarations of its ancestors (nearest first) are copied onto it,
/// but for the prefixes it declares itself (`_copyParentNamespaces`).
pub fn to_string_in(e: &Element, ancestors: &[&[(Option<String>, String)]]) -> String {
    let mut extra: Vec<(Option<String>, String)> = Vec::new();
    for defs in ancestors {
        for (p, u) in defs.iter() {
            let known = e.ns_defs.iter().any(|(q, _)| q == p) || extra.iter().any(|(q, _)| q == p);
            if !known {
                extra.push((p.clone(), u.clone()));
            }
        }
    }
    let mut out = String::new();
    write_element(e, &extra, &mut out);
    out
}

/// `etree.tostring(root, encoding="UTF-8", standalone=True)`: python-docx's
/// `serialize_part_xml`.
pub fn serialize_part(e: &Element) -> Vec<u8> {
    let mut out = String::from("<?xml version='1.0' encoding='UTF-8' standalone='yes'?>\n");
    write_element(e, &[], &mut out);
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blanks(s: &str) -> String {
        to_string(
            &parse_str(
                s,
                ParseOptions {
                    remove_blank_text: true,
                    recover: false,
                },
            )
            .unwrap(),
        )
    }

    #[test]
    fn serializes_like_lxml() {
        let e = parse_str(
            "<a xmlns:w=\"u\" w:b=\"\u{e9}&#10;\t&lt;&gt;&quot;&apos;\">\u{e9}\r&gt;&amp;<c/><d></d></a>",
            ParseOptions::default(),
        )
        .unwrap();
        assert_eq!(
            to_string(&e),
            "<a xmlns:w=\"u\" w:b=\"\u{e9}&#10; &lt;&gt;&quot;'\">\u{e9}\n&gt;&amp;<c/><d/></a>"
        );
    }

    #[test]
    fn drops_blanks_as_libxml2() {
        assert_eq!(blanks("<a>\n  <b/>\n</a>"), "<a><b/></a>");
        assert_eq!(blanks("<a> </a>"), "<a> </a>");
        assert_eq!(blanks("<a>x<b/> </a>"), "<a>x<b/> </a>");
        assert_eq!(blanks("<a><b/> &amp;</a>"), "<a><b/> &amp;</a>");
        assert_eq!(
            blanks("<a xml:space=\"preserve\">\n<b/></a>"),
            "<a xml:space=\"preserve\">\n<b/></a>"
        );
    }

    #[test]
    fn recovers_invalid_characters() {
        let e = parse_str(
            "<a><b>x\u{b}y</b></a>",
            ParseOptions {
                remove_blank_text: false,
                recover: true,
            },
        )
        .unwrap();
        assert_eq!(to_string(&e), "<a><b>xy</b></a>");
    }
}
