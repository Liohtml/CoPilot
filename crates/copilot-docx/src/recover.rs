//! `etree.fromstring(text, etree.XMLParser(recover=True))`: libxml2 2.14's
//! parser in recovery mode, building the tree its SAX2 handlers build.
//!
//! docxtpl parses the rendered body this way (`fix_tables`), so a template
//! whose rendering breaks the XML — a conditional cutting across a table, a
//! stray `<` or `&`, a control character in a case field — is repaired the
//! way libxml2 repairs it. This is a port of the functions involved
//! (`xmlParseDocument`, `xmlParseElement`, `xmlParseContentInternal`,
//! `xmlParseStartTag2`, `xmlParseEndTag2`, `xmlParseAttValueInternal`,
//! `xmlParseCharDataInternal` and its complex half, `xmlParseReference`,
//! `xmlParseCharRef`, the name and QName parsers, comments, processing
//! instructions and CDATA sections) on the bytes of the text, with what the
//! tree builder does on each callback:
//!
//! - an error never stops the parse but sets `wellFormed = 0`, after which a
//!   predefined entity in content (`&amp;`, `&lt;`, …) is dropped
//!   (`xmlParseReference` returns before inlining it);
//! - an end tag closes the element open, whatever its name;
//! - a start tag without its `>` leaves an empty element, the text after it
//!   going to the parent;
//! - an undeclared prefix makes the name `p:x` in no namespace; duplicate
//!   attributes are all kept;
//! - text before a `]]>` in an ASCII run is lost, as the fast path loses it;
//! - the 257th nested element is dropped and the parse stops;
//! - nothing after the root element counts.
//!
//! Errors are only tracked as `wellFormed`; their texts are never shown.
//! What is not reproduced fails ([`RecoverError::Unsupported`]): a document
//! type or an XML declaration (a docx body has neither) and a character
//! reference to a surrogate, which libxml2 stores as invalid UTF-8.

use crate::xml::{Attr, Element, Node, XML_NS};

/// The XMLNS namespace, which no declaration may bind.
const XMLNS_NS: &[u8] = b"http://www.w3.org/2000/xmlns/";

/// The node stack's limit (`nodePush` without `XML_PARSE_HUGE`).
const MAX_DEPTH: usize = 256;

/// What the parse gives.
#[derive(Debug, Clone, PartialEq)]
pub enum Recovered {
    /// The root element.
    Root(Element),
    /// A document without a root element: `fromstring` returns `None`.
    NoRoot,
}

/// A parse that gives no document.
#[derive(Debug, Clone, PartialEq)]
pub enum RecoverError {
    /// lxml's `XMLSyntaxError` (`Document is empty`).
    Syntax(String),
    /// A construct this port does not reproduce.
    Unsupported(String),
}

impl std::fmt::Display for RecoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syntax(m) | Self::Unsupported(m) => f.write_str(m),
        }
    }
}

/// Parses `text` as lxml parses a `str` with `XMLParser(recover=True)`.
pub fn parse(text: &str) -> Result<Recovered, RecoverError> {
    let mut p = P {
        b: text.as_bytes(),
        i: 0,
        well_formed: true,
        stopped: false,
        stack: Vec::new(),
        ns: Vec::new(),
        elem_id: 0,
        root: None,
        unsupported: None,
    };
    let outcome = p.document();
    if let Some(m) = p.unsupported {
        return Err(RecoverError::Unsupported(m));
    }
    outcome?;
    Ok(match p.root {
        Some(root) => Recovered::Root(root),
        None => Recovered::NoRoot,
    })
}

/// An open element: its node and what the parser's name stack holds.
struct Open {
    el: Element,
    name: Vec<u8>,
    prefix: Option<Vec<u8>>,
    ns_nr: usize,
}

/// One namespace declaration in scope (`nsTab`).
struct NsDecl {
    prefix: Option<Vec<u8>>,
    uri: Vec<u8>,
    elem: u64,
}

/// An attribute as `xmlParseStartTag2` collects it.
struct RawAttr {
    name: Vec<u8>,
    prefix: Option<Vec<u8>>,
    ns: Option<Vec<u8>>,
    undefined: bool,
    value: String,
}

/// A parsed start tag (the node `xmlSAX2StartElementNs` built).
struct StartTag {
    el: Option<Element>,
    name: Vec<u8>,
    prefix: Option<Vec<u8>>,
    ns_nr: usize,
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
    well_formed: bool,
    /// `PARSER_STOPPED` (`xmlHaltParser`).
    stopped: bool,
    stack: Vec<Open>,
    ns: Vec<NsDecl>,
    /// `nsdb->elementId`.
    elem_id: u64,
    root: Option<Element>,
    unsupported: Option<String>,
}

/// `IS_CHAR`.
fn is_char(c: u32) -> bool {
    matches!(c, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

/// `IS_BYTE_CHAR`.
fn is_byte_char(c: u8) -> bool {
    matches!(c, 0x9 | 0xA | 0xD) || c >= 0x20
}

/// `IS_BLANK_CH`.
fn is_blank(c: u8) -> bool {
    matches!(c, 0x20 | 0x9 | 0xA | 0xD)
}

/// `xmlIsNameStartChar` (XML 1.0 fifth edition).
fn is_name_start(c: u32) -> bool {
    c != u32::from(b' ')
        && c != u32::from(b'>')
        && c != u32::from(b'/')
        && matches!(c,
            0x61..=0x7A | 0x41..=0x5A | 0x5F | 0x3A
            | 0xC0..=0xD6 | 0xD8..=0xF6 | 0xF8..=0x2FF | 0x370..=0x37D
            | 0x37F..=0x1FFF | 0x200C..=0x200D | 0x2070..=0x218F | 0x2C00..=0x2FEF
            | 0x3001..=0xD7FF | 0xF900..=0xFDCF | 0xFDF0..=0xFFFD | 0x10000..=0xEFFFF)
}

/// `xmlIsNameChar`.
fn is_name_char(c: u32) -> bool {
    is_name_start(c)
        || matches!(c, 0x30..=0x39 | 0x2D | 0x2E | 0xB7 | 0x300..=0x36F | 0x203F..=0x2040)
}

/// `test_char_data`: what the fast path of character data takes.
fn fast_char(c: u8) -> bool {
    c == 0x9 || ((0x20..=0x7F).contains(&c) && c != b'&' && c != b'<' && c != b']')
}

/// The predefined entities.
fn predefined(name: &[u8]) -> Option<&'static str> {
    match name {
        b"lt" => Some("<"),
        b"gt" => Some(">"),
        b"amp" => Some("&"),
        b"apos" => Some("'"),
        b"quot" => Some("\""),
        _ => None,
    }
}

fn text_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

impl P<'_> {
    /// The byte at `i + k` (`0` past the end, as libxml2's terminated
    /// buffer reads).
    fn at(&self, k: usize) -> u8 {
        self.b.get(self.i + k).copied().unwrap_or(0)
    }

    fn byte_at(&self, j: usize) -> u8 {
        self.b.get(j).copied().unwrap_or(0)
    }

    fn at_end(&self) -> bool {
        self.i >= self.b.len()
    }

    fn starts_with(&self, lit: &[u8]) -> bool {
        self.b.get(self.i..).is_some_and(|r| r.starts_with(lit))
    }

    /// A fatal error: the document is not well formed.
    fn fatal(&mut self) {
        self.well_formed = false;
    }

    fn halt(&mut self) {
        self.stopped = true;
    }

    fn unsupported(&mut self, what: &str) {
        if self.unsupported.is_none() {
            self.unsupported = Some(format!("lxml recover: {what} is not reproduced"));
        }
        self.halt();
    }

    /// `xmlSkipBlankChars`.
    fn skip_blanks(&mut self) -> usize {
        let start = self.i;
        while is_blank(self.at(0)) && !self.at_end() {
            self.i += 1;
        }
        self.i - start
    }

    /// `xmlCurrentChar`: the character at `i` and its length; a `\r` reads
    /// as `\n` (stepping over the `\r` of a `\r\n`), a NUL is an error.
    fn cur_char(&mut self) -> (u32, usize) {
        if self.at_end() {
            return (0, 0);
        }
        let c = self.b[self.i];
        if c < 0x80 {
            if c == b'\r' {
                if self.at(1) == b'\n' {
                    self.i += 1;
                }
                return (u32::from(b'\n'), 1);
            }
            if c == 0 {
                self.fatal();
                return (0, 1);
            }
            return (u32::from(c), 1);
        }
        let len = match c {
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            _ => 4,
        };
        let s = self.b.get(self.i..self.i + len).unwrap_or_default();
        let ch = std::str::from_utf8(s)
            .ok()
            .and_then(|t| t.chars().next())
            .map_or(0xFFFD, u32::from);
        (ch, len)
    }

    // ------------------------------------------------------------ tree

    /// The SAX2 `characters` callback: text appended to the open element.
    fn characters(&mut self, t: &str) {
        if self.stopped || t.is_empty() {
            return;
        }
        if let Some(top) = self.stack.last_mut() {
            push_text(&mut top.el, t);
        }
    }

    fn characters_bytes(&mut self, from: usize, to: usize) {
        let t = text_of(&self.b[from..to]);
        self.characters(&t);
    }

    fn character(&mut self, v: u32) {
        match char::from_u32(v) {
            Some(c) => self.characters(c.encode_utf8(&mut [0; 4])),
            None => self.unsupported("a character reference to a surrogate"),
        }
    }

    /// A node appended to the open element (or made the root).
    fn attach(&mut self, el: Element) {
        match self.stack.last_mut() {
            Some(top) => top.el.children.push(Node::Element(el)),
            None => {
                if self.root.is_none() {
                    self.root = Some(el);
                }
            }
        }
    }

    fn attach_node(&mut self, n: Node) {
        if self.stopped {
            return;
        }
        if let Some(top) = self.stack.last_mut() {
            top.el.children.push(n);
        }
    }

    /// The open element closed (`nodePop`, `namePop`, its declarations).
    fn pop(&mut self) {
        if let Some(top) = self.stack.pop() {
            let keep = self.ns.len().saturating_sub(top.ns_nr);
            self.ns.truncate(keep);
            self.attach(top.el);
        }
    }

    // ------------------------------------------------------- document

    /// `xmlParseDocument`.
    fn document(&mut self) -> Result<(), RecoverError> {
        if self.at(0) == 0 {
            return Err(RecoverError::Syntax("Document is empty".into()));
        }
        if self.starts_with(b"<?xml") && is_blank(self.at(5)) {
            self.unsupported("an XML declaration");
            return Ok(());
        }
        self.misc();
        if self.starts_with(b"<!DOCTYPE") {
            self.unsupported("a document type declaration");
            return Ok(());
        }
        if self.at(0) != b'<' {
            self.fatal();
            return Ok(());
        }
        self.element();
        Ok(())
    }

    /// `xmlParseMisc`: blanks, processing instructions and comments outside
    /// the root (their nodes are not the root's).
    fn misc(&mut self) {
        while !self.stopped {
            self.skip_blanks();
            if self.at(0) == b'<' && self.at(1) == b'?' {
                self.pi(false);
            } else if self.starts_with(b"<!--") {
                self.comment(false);
            } else {
                break;
            }
        }
    }

    /// `xmlParseElement`: the root and its content.
    fn element(&mut self) {
        if self.element_start() != 0 {
            return;
        }
        self.content(1);
        if self.at_end() {
            if self.well_formed {
                self.fatal();
            }
            self.collapse(0);
            return;
        }
        self.element_end();
        self.collapse(0);
    }

    /// Every open element above `depth` closed into its parent.
    fn collapse(&mut self, depth: usize) {
        while self.stack.len() > depth {
            self.pop();
        }
    }

    /// `xmlParseContentInternal` for the content of the element at
    /// `depth`.
    fn content(&mut self, depth: usize) {
        while !self.at_end() && !self.stopped {
            if self.at(0) == b'<' && self.at(1) == b'?' {
                self.pi(true);
            } else if self.starts_with(b"<![CDATA[") {
                self.cdata();
            } else if self.starts_with(b"<!--") {
                self.comment(true);
            } else if self.at(0) == b'<' {
                if self.at(1) == b'/' {
                    if self.stack.len() <= depth {
                        break;
                    }
                    self.element_end();
                } else {
                    self.element_start();
                }
            } else if self.at(0) == b'&' {
                self.reference();
            } else {
                self.char_data();
            }
        }
        if self.stack.len() > depth && self.at_end() && self.well_formed {
            self.fatal();
        }
        self.collapse(depth);
    }

    /// `xmlParseElementStart`: `-1` on an error, `0` for an open element,
    /// `1` for an empty one.
    fn element_start(&mut self) -> i32 {
        if self.stack.len() > MAX_DEPTH {
            self.fatal();
            self.halt();
            return -1;
        }
        let Some(tag) = self.start_tag() else {
            return -1;
        };
        if self.at(0) == b'/' && self.at(1) == b'>' {
            self.i += 2;
            if let Some(el) = tag.el {
                self.attach(el);
            }
            let keep = self.ns.len().saturating_sub(tag.ns_nr);
            self.ns.truncate(keep);
            return 1;
        }
        if self.at(0) == b'>' {
            self.i += 1;
            match tag.el {
                Some(el) => self.stack.push(Open {
                    el,
                    name: tag.name,
                    prefix: tag.prefix,
                    ns_nr: tag.ns_nr,
                }),
                None => {
                    // The node was refused (the depth limit halted the
                    // parse): nothing more is built.
                    let keep = self.ns.len().saturating_sub(tag.ns_nr);
                    self.ns.truncate(keep);
                }
            }
            return 0;
        }
        // "Couldn't find end of Start Tag": the element stays, empty.
        self.fatal();
        if let Some(el) = tag.el {
            self.attach(el);
        }
        let keep = self.ns.len().saturating_sub(tag.ns_nr);
        self.ns.truncate(keep);
        -1
    }

    /// `xmlParseElementEnd` / `xmlParseEndTag2`: closes the open element,
    /// whatever the end tag names.
    fn element_end(&mut self) {
        if self.stack.is_empty() {
            if self.at(0) == b'<' && self.at(1) == b'/' {
                self.i += 2;
            }
            return;
        }
        if self.at(0) != b'<' || self.at(1) != b'/' {
            // "expected '</'": the name is popped, the node stays.
            self.fatal();
            self.pop();
            return;
        }
        self.i += 2;
        let (name, prefix) = match self.stack.last() {
            Some(top) => (top.name.clone(), top.prefix.clone()),
            None => return,
        };
        let matched = match &prefix {
            None => self.name_and_compare(&name),
            Some(p) => self.qname_and_compare(&name, p),
        };
        self.skip_blanks();
        if self.at(0) != b'>' {
            self.fatal();
        } else {
            self.i += 1;
        }
        if !matched {
            self.fatal();
        }
        self.pop();
    }

    /// `xmlParseNameAndCompare`: whether the end tag's name is `other`.
    fn name_and_compare(&mut self, other: &[u8]) -> bool {
        let mut j = self.i;
        let mut k = 0;
        while self.byte_at(j) != 0 && k < other.len() && self.byte_at(j) == other[k] {
            j += 1;
            k += 1;
        }
        if k == other.len() && (self.byte_at(j) == b'>' || is_blank(self.byte_at(j))) {
            self.i = j;
            return true;
        }
        self.parse_name().as_deref() == Some(other)
    }

    /// `xmlParseQNameAndCompare`.
    fn qname_and_compare(&mut self, name: &[u8], prefix: &[u8]) -> bool {
        let mut j = self.i;
        let mut k = 0;
        while self.byte_at(j) != 0 && k < prefix.len() && self.byte_at(j) == prefix[k] {
            j += 1;
            k += 1;
        }
        if k == prefix.len() && self.byte_at(j) == b':' {
            j += 1;
            let mut m = 0;
            while self.byte_at(j) != 0 && m < name.len() && self.byte_at(j) == name[m] {
                j += 1;
                m += 1;
            }
            if m == name.len() && (self.byte_at(j) == b'>' || is_blank(self.byte_at(j))) {
                self.i = j;
                return true;
            }
        }
        match self.parse_qname() {
            None => false,
            Some((p2, l2)) => l2 == name && p2.as_deref() == Some(prefix),
        }
    }

    // ---------------------------------------------------------- names

    /// `xmlParseName`.
    fn parse_name(&mut self) -> Option<Vec<u8>> {
        let start = self.i;
        let c = self.at(0);
        if c.is_ascii_alphabetic() || c == b'_' || c == b':' {
            let mut j = start + 1;
            while {
                let d = self.byte_at(j);
                d.is_ascii_alphanumeric() || matches!(d, b'_' | b'-' | b':' | b'.')
            } {
                j += 1;
            }
            let d = self.byte_at(j);
            if d > 0 && d < 0x80 {
                self.i = j;
                return Some(self.b[start..j].to_vec());
            }
        }
        self.name_complex()
    }

    /// `xmlParseNameComplex`.
    fn name_complex(&mut self) -> Option<Vec<u8>> {
        let start = self.i;
        let (c, l) = self.cur_char();
        if !is_name_start(c) {
            return None;
        }
        let mut len = l;
        self.i += l;
        loop {
            let (c, l) = self.cur_char();
            if !is_name_char(c) {
                break;
            }
            len += l;
            self.i += l;
        }
        Some(self.b[start..start + len].to_vec())
    }

    /// `xmlParseNCName`.
    fn parse_ncname(&mut self) -> Option<Vec<u8>> {
        let start = self.i;
        let e = self.b.len();
        let c = self.at(0);
        if (c.is_ascii_alphabetic() || c == b'_') && start < e {
            let mut j = start + 1;
            while j < e && {
                let d = self.b[j];
                d.is_ascii_alphanumeric() || matches!(d, b'_' | b'-' | b'.')
            } {
                j += 1;
            }
            if j < e && self.b[j] > 0 && self.b[j] < 0x80 {
                self.i = j;
                return Some(self.b[start..j].to_vec());
            }
        }
        self.ncname_complex()
    }

    /// `xmlParseNCNameComplex`.
    fn ncname_complex(&mut self) -> Option<Vec<u8>> {
        let start = self.i;
        let (mut c, mut l) = self.cur_char();
        if !is_name_start(c) || c == u32::from(b':') {
            return None;
        }
        let mut len = 0;
        while is_name_char(c) && c != u32::from(b':') {
            len += l;
            self.i += l;
            (c, l) = self.cur_char();
        }
        Some(self.b[start..start + len].to_vec())
    }

    /// `xmlParseNmtoken`, its value unused.
    fn skip_nmtoken(&mut self) {
        let (mut c, mut l) = self.cur_char();
        while is_name_char(c) {
            self.i += l;
            (c, l) = self.cur_char();
        }
    }

    /// `xmlParseQNameHashed`: the prefix and the local name.
    fn parse_qname(&mut self) -> Option<(Option<Vec<u8>>, Vec<u8>)> {
        let start = self.i;
        let mut prefix = None;
        let mut is_ncname = false;
        let mut local = self.parse_ncname();
        if local.is_some() {
            is_ncname = true;
            if self.at(0) == b':' {
                self.i += 1;
                prefix = local.take();
                local = self.parse_ncname();
            }
        }
        match local {
            Some(l) if self.at(0) != b':' => Some((prefix, l)),
            _ => {
                if !is_ncname && self.at(0) != b':' {
                    return None;
                }
                self.skip_nmtoken();
                // "Failed to parse QName": the whole text is the name.
                Some((None, self.b[start..self.i].to_vec()))
            }
        }
    }

    // ------------------------------------------------------ start tag

    /// The newest declaration of `prefix` in scope.
    fn lookup(&self, prefix: Option<&[u8]>) -> Option<&NsDecl> {
        self.ns.iter().rev().find(|d| d.prefix.as_deref() == prefix)
    }

    /// `xmlParserNsPush`: `false` when not pushed.
    fn ns_push(&mut self, prefix: Option<Vec<u8>>, uri: Vec<u8>) -> bool {
        if prefix.as_deref() == Some(b"xml") {
            return false;
        }
        if let Some(old) = self.lookup(prefix.as_deref()) {
            if old.elem == self.elem_id {
                // "Attribute xmlns(:p) redefined"
                self.fatal();
                return false;
            }
        }
        self.ns.push(NsDecl {
            prefix,
            uri,
            elem: self.elem_id,
        });
        true
    }

    /// `xmlParseStartTag2` and the node `xmlSAX2StartElementNs` builds.
    fn start_tag(&mut self) -> Option<StartTag> {
        self.i += 1; // '<'
        self.elem_id += 1;
        let Some((prefix, local)) = self.parse_qname() else {
            // "StartTag: invalid element name"
            self.fatal();
            return None;
        };
        self.skip_blanks();
        let ns_base = self.ns.len();
        let mut atts: Vec<RawAttr> = Vec::new();
        while self.at(0) != b'>'
            && !(self.at(0) == b'/' && self.at(1) == b'>')
            && is_byte_char(self.at(0))
            && !self.stopped
        {
            let Some((aprefix, aname)) = self.parse_qname() else {
                // "error parsing attribute name"
                self.fatal();
                break;
            };
            self.skip_blanks();
            let value = if self.at(0) == b'=' {
                self.i += 1;
                self.skip_blanks();
                self.att_value()
            } else {
                // "Specification mandates value for attribute"
                self.fatal();
                None
            };
            if let Some(v) = value {
                self.declare_or_collect(aprefix, aname, v, &mut atts);
            }
            if self.at(0) == b'>' || (self.at(0) == b'/' && self.at(1) == b'>') {
                break;
            }
            if self.skip_blanks() == 0 {
                // "attributes construct error"
                self.fatal();
                break;
            }
        }
        let ns_nr = self.ns.len() - ns_base;
        self.resolve_attributes(&mut atts);
        let uri: Option<Vec<u8>> = match prefix.as_deref() {
            Some(b"xml") => Some(XML_NS.as_bytes().to_vec()),
            p => self
                .lookup(p)
                .map(|d| d.uri.clone())
                .filter(|u| !u.is_empty()),
        };
        let el = if self.stopped {
            None
        } else if self.stack.len() >= MAX_DEPTH {
            // `nodePush` refuses the node: "Excessive depth in document".
            self.fatal();
            self.halt();
            None
        } else {
            Some(self.build(&prefix, &local, uri.as_deref(), ns_base, atts))
        };
        Some(StartTag {
            el,
            name: local,
            prefix,
            ns_nr,
        })
    }

    /// An attribute: a namespace declaration, or one of the element's.
    fn declare_or_collect(
        &mut self,
        aprefix: Option<Vec<u8>>,
        aname: Vec<u8>,
        v: String,
        atts: &mut Vec<RawAttr>,
    ) {
        let uri = v.as_bytes().to_vec();
        if aprefix.is_none() && aname == b"xmlns" {
            if !uri.is_empty() && (uri == XML_NS.as_bytes() || uri == XMLNS_NS) {
                return;
            }
            self.ns_push(None, uri);
        } else if aprefix.as_deref() == Some(b"xmlns") {
            if aname == b"xml"
                || uri == XML_NS.as_bytes()
                || aname == b"xmlns"
                || uri == XMLNS_NS
                || uri.is_empty()
            {
                return;
            }
            self.ns_push(Some(aname), uri);
        } else {
            atts.push(RawAttr {
                name: aname,
                prefix: aprefix,
                ns: None,
                undefined: false,
                value: v,
            });
        }
    }

    /// The attributes' namespaces, then the uniqueness checks.
    fn resolve_attributes(&mut self, atts: &mut [RawAttr]) {
        for a in atts.iter_mut() {
            match a.prefix.as_deref() {
                None => {}
                Some(b"xml") => a.ns = Some(XML_NS.as_bytes().to_vec()),
                Some(p) => match self
                    .ns
                    .iter()
                    .rev()
                    .find(|d| d.prefix.as_deref() == Some(p))
                {
                    Some(d) => a.ns = Some(d.uri.clone()),
                    None => a.undefined = true,
                },
            }
        }
        if atts.len() <= 1 {
            return;
        }
        let mut num_dup = 0;
        let mut num_ns = 0;
        for j in 0..atts.len() {
            if atts[j].undefined {
                continue;
            }
            let first = (0..j).find(|&k| {
                !atts[k].undefined && atts[k].name == atts[j].name && atts[k].ns == atts[j].ns
            });
            if let Some(k) = first {
                if atts[k].prefix == atts[j].prefix {
                    self.fatal();
                    num_dup += 1;
                } else {
                    num_ns += 1;
                }
            }
        }
        if num_dup == 0 && num_ns > 1 {
            for j in 0..atts.len() {
                if atts[j].prefix.is_none() {
                    continue;
                }
                let dup = (0..j).any(|k| {
                    atts[k].prefix.is_some()
                        && atts[k].name == atts[j].name
                        && atts[k].prefix == atts[j].prefix
                });
                if dup {
                    self.fatal();
                }
            }
        }
    }

    /// The node `xmlSAX2StartElementNs` builds.
    fn build(
        &self,
        prefix: &Option<Vec<u8>>,
        local: &[u8],
        uri: Option<&[u8]>,
        ns_base: usize,
        atts: Vec<RawAttr>,
    ) -> Element {
        let ns_defs = self.ns[ns_base..]
            .iter()
            .map(|d| (d.prefix.as_deref().map(text_of), text_of(&d.uri)))
            .collect();
        let (el_prefix, el_local) = match (prefix, uri) {
            (Some(p), None) => (None, format!("{}:{}", text_of(p), text_of(local))),
            (p, _) => (p.as_deref().map(text_of), text_of(local)),
        };
        let attrs = atts
            .into_iter()
            .map(|a| match (&a.prefix, a.undefined) {
                (Some(p), true) => Attr {
                    prefix: None,
                    local: format!("{}:{}", text_of(p), text_of(&a.name)),
                    ns: None,
                    value: a.value,
                },
                _ => Attr {
                    prefix: a.prefix.as_deref().map(text_of),
                    local: text_of(&a.name),
                    ns: a.ns.as_deref().map(text_of),
                    value: a.value,
                },
            })
            .collect();
        Element {
            prefix: el_prefix,
            local: el_local,
            ns: uri.map(text_of),
            ns_defs,
            attrs,
            children: Vec::new(),
        }
    }

    /// `xmlParseAttValueInternal` (no DTD, so never normalized).
    fn att_value(&mut self) -> Option<String> {
        let quote = self.at(0);
        if quote != b'"' && quote != b'\'' {
            // "AttValue: \" or ' expected"
            self.fatal();
            return None;
        }
        self.i += 1;
        let mut buf = String::new();
        loop {
            if self.stopped {
                return None;
            }
            if self.at_end() {
                // "AttValue: ' expected"
                self.fatal();
                return None;
            }
            let c = self.b[self.i];
            if c >= 0x80 {
                let len = match c {
                    0xC0..=0xDF => 2,
                    0xE0..=0xEF => 3,
                    _ => 4,
                };
                if c == 0xEF && self.at(1) == 0xBF && self.at(2) >= 0xBE {
                    // U+FFFE and U+FFFF: reported, kept.
                    self.fatal();
                }
                let end = (self.i + len).min(self.b.len());
                buf.push_str(&text_of(&self.b[self.i..end]));
                self.i = end;
            } else if c != b'&' {
                if c > 0x20 {
                    if c == quote {
                        break;
                    }
                    if c == b'<' {
                        self.fatal();
                    }
                    buf.push(char::from(c));
                } else if !is_byte_char(c) {
                    self.fatal();
                    buf.push('\u{FFFD}');
                } else {
                    buf.push(' ');
                    if c == b'\r' && self.at(1) == b'\n' {
                        self.i += 1;
                    }
                }
                self.i += 1;
            } else if self.at(1) == b'#' {
                let val = self.char_ref();
                if val == 0 {
                    return None;
                }
                match char::from_u32(val) {
                    Some(ch) => buf.push(ch),
                    None => {
                        self.unsupported("a character reference to a surrogate");
                        return None;
                    }
                }
            } else {
                let Some(name) = self.entity_ref() else {
                    continue;
                };
                match predefined(&name) {
                    Some(s) => buf.push_str(s),
                    // "Entity 'x' not defined": dropped.
                    None => self.fatal(),
                }
            }
        }
        self.i += 1;
        Some(buf)
    }

    // ----------------------------------------------------- references

    /// `xmlParseCharRef`: the value, `0` on an error.
    fn char_ref(&mut self) -> u32 {
        let mut val: u32 = 0;
        let mut count: u32 = 0;
        if self.at(0) == b'&' && self.at(1) == b'#' && self.at(2) == b'x' {
            self.i += 3;
            while self.at(0) != b';' && !self.stopped {
                let before = count;
                count += 1;
                if before > 20 {
                    count = 0;
                }
                let d = self.at(0);
                if d.is_ascii_digit() {
                    val = val * 16 + u32::from(d - b'0');
                } else if (b'a'..=b'f').contains(&d) && count < 20 {
                    val = val * 16 + u32::from(d - b'a') + 10;
                } else if (b'A'..=b'F').contains(&d) && count < 20 {
                    val = val * 16 + u32::from(d - b'A') + 10;
                } else {
                    self.fatal();
                    val = 0;
                    break;
                }
                if val > 0x11_0000 {
                    val = 0x11_0000;
                }
                self.i += 1;
                count += 1;
            }
            if self.at(0) == b';' {
                self.i += 1;
            }
        } else if self.at(0) == b'&' && self.at(1) == b'#' {
            self.i += 2;
            while self.at(0) != b';' {
                let before = count;
                count += 1;
                if before > 20 {
                    count = 0;
                }
                let d = self.at(0);
                if d.is_ascii_digit() {
                    val = val * 10 + u32::from(d - b'0');
                } else {
                    self.fatal();
                    val = 0;
                    break;
                }
                if val > 0x11_0000 {
                    val = 0x11_0000;
                }
                self.i += 1;
                count += 1;
            }
            if self.at(0) == b';' {
                self.i += 1;
            }
        } else {
            if self.at(0) == b'&' {
                self.i += 1;
            }
            self.fatal();
        }
        if val >= 0x11_0000 {
            self.fatal();
            val = 0xFFFD;
        } else if !is_char(val) {
            self.fatal();
        }
        val
    }

    /// `xmlParseEntityRefInternal`: the name of `&name;`.
    fn entity_ref(&mut self) -> Option<Vec<u8>> {
        if self.at(0) != b'&' {
            return None;
        }
        self.i += 1;
        let Some(name) = self.parse_name() else {
            // "xmlParseEntityRef: no name"
            self.fatal();
            return None;
        };
        if self.at(0) != b';' {
            // "EntityRef: expecting ';'"
            self.fatal();
            return None;
        }
        self.i += 1;
        Some(name)
    }

    /// `xmlParseReference` in content.
    fn reference(&mut self) {
        if self.at(1) == b'#' {
            let v = self.char_ref();
            if v != 0 {
                self.character(v);
            }
            return;
        }
        let Some(name) = self.entity_ref() else {
            return;
        };
        match predefined(&name) {
            // "Entity 'x' not defined" (substituted: no reference node).
            None => self.fatal(),
            // Inlined only while the document is still well formed.
            Some(s) if self.well_formed => self.characters(s),
            Some(_) => {}
        }
    }

    // ------------------------------------------------- character data

    /// `xmlParseCharDataInternal` (not partial).
    fn char_data(&mut self) {
        let mut inp = self.i;
        loop {
            loop {
                while self.byte_at(inp) == 0x20 {
                    inp += 1;
                }
                if self.byte_at(inp) == 0x0A {
                    while self.byte_at(inp) == 0x0A {
                        inp += 1;
                    }
                    continue;
                }
                break;
            }
            if self.byte_at(inp) == b'<' {
                if inp > self.i {
                    let from = self.i;
                    self.i = inp;
                    self.characters_bytes(from, inp);
                }
                return;
            }
            loop {
                while fast_char(self.byte_at(inp)) {
                    inp += 1;
                }
                if self.byte_at(inp) == 0x0A {
                    while self.byte_at(inp) == 0x0A {
                        inp += 1;
                    }
                    continue;
                }
                if self.byte_at(inp) == b']' {
                    if self.byte_at(inp + 1) == b']' && self.byte_at(inp + 2) == b'>' {
                        // "Sequence ']]>' not allowed in content": the run
                        // so far is lost.
                        self.fatal();
                        self.i = inp + 1;
                        return;
                    }
                    inp += 1;
                    continue;
                }
                break;
            }
            if inp > self.i {
                let from = self.i;
                self.i = inp;
                self.characters_bytes(from, inp);
            }
            self.i = inp;
            if self.byte_at(inp) == 0x0D && self.byte_at(inp + 1) == 0x0A {
                self.i = inp + 1;
                inp += 2;
                if continues(self.byte_at(inp)) {
                    continue;
                }
                break;
            }
            if self.byte_at(inp) == b'<' || self.byte_at(inp) == b'&' {
                return;
            }
            inp = self.i;
            if !continues(self.byte_at(inp)) {
                break;
            }
        }
        self.char_data_complex();
    }

    /// `xmlParseCharDataComplex` (not partial).
    fn char_data_complex(&mut self) {
        let mut buf = String::new();
        let (mut cur, mut l) = self.cur_char();
        while cur != u32::from(b'<') && cur != u32::from(b'&') && is_char(cur) {
            if cur == u32::from(b']') && self.at(1) == b']' && self.at(2) == b'>' {
                self.fatal();
            }
            if let Some(ch) = char::from_u32(cur) {
                buf.push(ch);
            }
            self.i += l;
            (cur, l) = self.cur_char();
        }
        self.characters(&buf);
        if !self.at_end() && cur != u32::from(b'<') && cur != u32::from(b'&') {
            // "PCDATA invalid Char value": skipped.
            self.fatal();
            self.i += l.max(1);
        }
    }

    // ------------------------------------- comments, PIs and CDATA

    /// `xmlParseComment`; the node kept only in content.
    fn comment(&mut self, keep: bool) {
        self.i += 4;
        let mut buf = String::new();
        let mut inp = self.i;
        loop {
            if self.byte_at(inp) == 0x0A {
                while self.byte_at(inp) == 0x0A {
                    inp += 1;
                }
            }
            loop {
                while {
                    let c = self.byte_at(inp);
                    (c > b'-' && c <= 0x7F) || (0x20..b'-').contains(&c) || c == 0x09
                } {
                    inp += 1;
                }
                if self.byte_at(inp) == 0x0A {
                    while self.byte_at(inp) == 0x0A {
                        inp += 1;
                    }
                    continue;
                }
                buf.push_str(&text_of(&self.b[self.i..inp.min(self.b.len())]));
                self.i = inp;
                if self.byte_at(inp) == 0x0A {
                    inp += 1;
                }
                if self.byte_at(inp) == 0x0D && self.byte_at(inp + 1) == 0x0A {
                    self.i = inp + 1;
                    inp += 2;
                    continue;
                }
                inp = self.i;
                if self.byte_at(inp) == b'-' {
                    if self.byte_at(inp + 1) == b'-' {
                        if self.byte_at(inp + 2) == b'>' {
                            self.i += 3;
                            if keep {
                                self.attach_node(Node::Comment(buf));
                            }
                            return;
                        }
                        // "Double hyphen within comment"
                        self.fatal();
                        inp += 1;
                    }
                    inp += 1;
                    continue;
                }
                break;
            }
            let c = self.byte_at(inp);
            if !((0x20..=0x7F).contains(&c) || c == 0x09 || c == 0x0A) {
                break;
            }
        }
        self.comment_complex(buf, keep);
    }

    /// `xmlParseCommentComplex`.
    fn comment_complex(&mut self, mut buf: String, keep: bool) {
        let (q, ql) = self.cur_char();
        if q == 0 {
            self.fatal();
            return;
        }
        if !is_char(q) {
            self.fatal();
            return;
        }
        self.i += ql;
        let (r, rl) = self.cur_char();
        if r == 0 {
            self.fatal();
            return;
        }
        if !is_char(r) {
            self.fatal();
            return;
        }
        self.i += rl;
        let (mut q, mut r) = (q, r);
        let (mut cur, mut l) = self.cur_char();
        if cur == 0 {
            self.fatal();
            return;
        }
        while is_char(cur)
            && (cur != u32::from(b'>') || r != u32::from(b'-') || q != u32::from(b'-'))
        {
            if r == u32::from(b'-') && q == u32::from(b'-') {
                self.fatal();
            }
            if let Some(ch) = char::from_u32(q) {
                buf.push(ch);
            }
            q = r;
            r = cur;
            self.i += l;
            (cur, l) = self.cur_char();
        }
        if cur == 0 || !is_char(cur) {
            self.fatal();
            return;
        }
        self.i += 1;
        if keep {
            self.attach_node(Node::Comment(buf));
        }
    }

    /// `xmlParsePI`; the node kept only in content.
    fn pi(&mut self, keep: bool) {
        self.i += 2;
        let Some(target) = self.parse_name() else {
            // "xmlParsePI : no target name"
            self.fatal();
            return;
        };
        if target.len() >= 3 && target[..3].eq_ignore_ascii_case(b"xml") {
            let w3c = target == b"xml-stylesheet" || target == b"xml-model";
            if target.len() == 3 {
                self.fatal();
            } else if !w3c {
                // a warning
            }
        }
        let target_text = text_of(&target);
        if self.at(0) == b'?' && self.at(1) == b'>' {
            self.i += 2;
            if keep {
                self.attach_node(Node::Pi(target_text, None));
            }
            return;
        }
        if self.skip_blanks() == 0 {
            self.fatal();
        }
        let mut buf = String::new();
        let (mut cur, mut l) = self.cur_char();
        while is_char(cur) && (cur != u32::from(b'?') || self.at(1) != b'>') {
            if let Some(ch) = char::from_u32(cur) {
                buf.push(ch);
            }
            self.i += l;
            (cur, l) = self.cur_char();
        }
        if cur != u32::from(b'?') {
            // "ParsePI: PI never end"
            self.fatal();
            return;
        }
        self.i += 2;
        if keep {
            self.attach_node(Node::Pi(target_text, Some(buf)));
        }
    }

    /// `xmlParseCDSect` with `XML_PARSE_NOCDATA`: the content as text.
    fn cdata(&mut self) {
        self.i += 9;
        let (r, rl) = self.cur_char();
        if !is_char(r) {
            self.fatal();
            return;
        }
        self.i += rl;
        let (s, sl) = self.cur_char();
        if !is_char(s) {
            self.fatal();
            return;
        }
        self.i += sl;
        let (mut r, mut s) = (r, s);
        let mut buf = String::new();
        let (mut cur, mut l) = self.cur_char();
        while is_char(cur)
            && (r != u32::from(b']') || s != u32::from(b']') || cur != u32::from(b'>'))
        {
            if let Some(ch) = char::from_u32(r) {
                buf.push(ch);
            }
            r = s;
            s = cur;
            self.i += l;
            (cur, l) = self.cur_char();
        }
        if cur != u32::from(b'>') {
            // "CData section not finished"
            self.fatal();
            return;
        }
        self.i += l;
        self.characters(&buf);
    }
}

/// The loop condition of the fast path of character data.
fn continues(c: u8) -> bool {
    (0x20..=0x7F).contains(&c) || c == 0x09 || c == 0x0A
}

fn push_text(el: &mut Element, t: &str) {
    if let Some(Node::Text(last)) = el.children.last_mut() {
        last.push_str(t);
    } else {
        el.children.push(Node::Text(t.to_string()));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    fn vectors() -> Value {
        serde_json::from_str(include_str!("recover_vectors.json")).unwrap()
    }

    /// The outcome as the vectors write it.
    fn outcome(text: &str) -> Value {
        match parse(text) {
            Ok(Recovered::Root(root)) => serde_json::json!({ "out": crate::xml::to_string(&root) }),
            Ok(Recovered::NoRoot) => serde_json::json!({ "none": true }),
            Err(RecoverError::Syntax(_)) => serde_json::json!({ "error": "syntax" }),
            Err(RecoverError::Unsupported(_)) => serde_json::json!({ "error": "invalid-utf8" }),
        }
    }

    fn digest(v: Value) -> Value {
        match v.get("out").and_then(Value::as_str) {
            Some(out) => serde_json::json!({
                "sha256": hex::encode(Sha256::digest(out.as_bytes())),
                "len": out.len(),
            }),
            None => v,
        }
    }

    #[test]
    fn refuses_what_is_not_reproduced() {
        for text in [
            "<?xml version=\"1.0\"?><a/>",
            "<!DOCTYPE a><a/>",
            "<a>&#xD800;</a>",
            "<a b=\"&#xDFFF;\"/>",
        ] {
            assert!(
                matches!(parse(text), Err(RecoverError::Unsupported(_))),
                "{text}"
            );
        }
        assert!(matches!(parse(""), Err(RecoverError::Syntax(_))));
        assert_eq!(parse("text"), Ok(Recovered::NoRoot));
    }

    #[test]
    fn repairs_as_libxml2() {
        let v = vectors();
        for case in v["cases"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let mut want = case.clone();
            want.as_object_mut().unwrap().remove("input");
            assert_eq!(outcome(input), want, "{input:?}");
        }
    }

    /// Applies `[position, deleted, inserted]` (in characters).
    fn apply(text: &str, ops: &Value) -> String {
        let mut cur: Vec<char> = text.chars().collect();
        for op in ops.as_array().unwrap() {
            let at = usize::try_from(op[0].as_u64().unwrap()).unwrap();
            let del = usize::try_from(op[1].as_u64().unwrap()).unwrap();
            let ins: Vec<char> = op[2].as_str().unwrap().chars().collect();
            cur.splice(at..at + del, ins);
        }
        cur.into_iter().collect()
    }

    #[test]
    fn repairs_broken_bodies_as_libxml2() {
        let v = vectors();
        let mut n = 0;
        for body in v["bodies"].as_array().unwrap() {
            let base = body["base"].as_str().unwrap();
            for case in body["cases"].as_array().unwrap() {
                let text = apply(base, &case["ops"]);
                let mut want = case.clone();
                want.as_object_mut().unwrap().remove("ops");
                assert_eq!(
                    digest(outcome(&text)),
                    want,
                    "{} {}",
                    body["name"],
                    case["ops"]
                );
                n += 1;
            }
        }
        assert!(n > 500, "{n}");
    }
}
