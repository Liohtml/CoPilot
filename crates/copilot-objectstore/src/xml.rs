//! The little of `xml.etree.ElementTree` miniopy-async uses on S3 answers:
//! `fromstring`, an element's `tag` (`{namespace}local` once a default or
//! prefixed namespace applies), its `text` (character data before its first
//! child) and children, and `xml.py`'s namespace-aware `find` / `findall` /
//! `findtext`.
//!
//! Entities are the five predefined ones and character references; CDATA,
//! comments, processing instructions and a DOCTYPE without an internal subset
//! are skipped. A document expat would reject is a `ParseError` here too; its
//! text approximates expat's (`<reason>: line L, column C`), which no S3
//! server's answer has been seen to need.

/// One element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    /// `{namespace}local`, or `local` without a namespace.
    pub tag: String,
    /// `text`: `None` when no character data precedes the first child.
    pub text: Option<String>,
    /// The child elements, in order.
    pub children: Vec<Element>,
}

impl Element {
    /// `xml._get_namespace`.
    pub fn namespace(&self) -> &str {
        match (self.tag.find('{'), self.tag.find('}')) {
            (Some(start), Some(end)) if end > start => &self.tag[start + 1..end],
            _ => "",
        }
    }

    fn qualified(&self, name: &str) -> String {
        let ns = self.namespace();
        if ns.is_empty() {
            name.to_string()
        } else {
            format!("{{{ns}}}{name}")
        }
    }

    /// `xml.find(element, name)`: the first child named `name` in the
    /// element's own namespace.
    pub fn find(&self, name: &str) -> Option<&Element> {
        let wanted = self.qualified(name);
        self.children.iter().find(|c| c.tag == wanted)
    }

    /// `xml.findall(element, name)`.
    pub fn findall(&self, name: &str) -> Vec<&Element> {
        let wanted = self.qualified(name);
        self.children.iter().filter(|c| c.tag == wanted).collect()
    }

    /// `xml.findtext(element, name)`: `None` without such a child, else its
    /// text (`""` when it has none).
    pub fn findtext(&self, name: &str) -> Option<String> {
        self.find(name).map(|e| e.text.clone().unwrap_or_default())
    }

    /// `xml.findtext(element, name, True)`: `ValueError` text when missing.
    pub fn findtext_strict(&self, name: &str) -> Result<String, String> {
        self.findtext(name)
            .ok_or_else(|| format!("XML element <{name}> not found"))
    }
}

struct Parser<'a> {
    src: &'a str,
    pos: usize,
}

struct Raw {
    name: String,
    attrs: Vec<(String, String)>,
    text: Option<String>,
    children: Vec<Raw>,
}

impl<'a> Parser<'a> {
    fn error(&self, reason: &str) -> String {
        let before = &self.src[..self.pos.min(self.src.len())];
        let line = before.matches('\n').count() + 1;
        let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count());
        format!("{reason}: line {line}, column {column}")
    }

    fn rest(&self) -> &'a str {
        &self.src[self.pos..]
    }

    fn eat(&mut self, s: &str) -> bool {
        if self.rest().starts_with(s) {
            self.pos += s.len();
            true
        } else {
            false
        }
    }

    fn skip_space(&mut self) {
        let n = self.rest().len()
            - self
                .rest()
                .trim_start_matches([' ', '\t', '\r', '\n'])
                .len();
        self.pos += n;
    }

    fn skip_until(&mut self, end: &str, reason: &str) -> Result<(), String> {
        match self.rest().find(end) {
            Some(i) => {
                self.pos += i + end.len();
                Ok(())
            }
            None => {
                self.pos = self.src.len();
                Err(self.error(reason))
            }
        }
    }

    /// Prolog, comments, PIs and whitespace outside the root.
    fn misc(&mut self) -> Result<(), String> {
        loop {
            self.skip_space();
            if self.eat("<?") {
                self.skip_until("?>", "unclosed token")?;
            } else if self.eat("<!--") {
                self.skip_until("-->", "unclosed token")?;
            } else if self.rest().starts_with("<!DOCTYPE") {
                self.skip_until(">", "unclosed token")?;
            } else {
                return Ok(());
            }
        }
    }

    fn name(&mut self) -> Result<String, String> {
        let rest = self.rest();
        let end = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '>' | '=' | '<'))
            .unwrap_or(rest.len());
        if end == 0 {
            return Err(self.error("not well-formed (invalid token)"));
        }
        let name = rest[..end].to_string();
        self.pos += end;
        Ok(name)
    }

    fn decode(&self, raw: &str) -> Result<String, String> {
        let mut out = String::with_capacity(raw.len());
        let mut rest = raw;
        while let Some(i) = rest.find('&') {
            out.push_str(&rest[..i]);
            let after = &rest[i + 1..];
            let Some(end) = after.find(';') else {
                return Err(self.error("not well-formed (invalid token)"));
            };
            let entity = &after[..end];
            let c = match entity {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                e if e.starts_with("#x") => u32::from_str_radix(&e[2..], 16)
                    .ok()
                    .and_then(char::from_u32),
                e if e.starts_with('#') => e[1..].parse::<u32>().ok().and_then(char::from_u32),
                _ => return Err(self.error("undefined entity")),
            };
            match c {
                Some(c) => out.push(c),
                None => return Err(self.error("reference to invalid character number")),
            }
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }

    fn element(&mut self) -> Result<Raw, String> {
        if !self.eat("<") {
            return Err(self.error(if self.pos >= self.src.len() {
                "no element found"
            } else {
                "syntax error"
            }));
        }
        let name = self.name()?;
        let mut attrs = Vec::new();
        loop {
            self.skip_space();
            if self.eat("/>") {
                return Ok(Raw {
                    name,
                    attrs,
                    text: None,
                    children: Vec::new(),
                });
            }
            if self.eat(">") {
                break;
            }
            if self.pos >= self.src.len() {
                return Err(self.error("unclosed token"));
            }
            let attr = self.name()?;
            self.skip_space();
            if !self.eat("=") {
                return Err(self.error("not well-formed (invalid token)"));
            }
            self.skip_space();
            let quote = match self.rest().chars().next() {
                Some(q @ ('"' | '\'')) => q,
                _ => return Err(self.error("not well-formed (invalid token)")),
            };
            self.pos += 1;
            let Some(end) = self.rest().find(quote) else {
                return Err(self.error("unclosed token"));
            };
            let value = self.decode(&self.rest()[..end])?;
            self.pos += end + 1;
            attrs.push((attr, value));
        }
        let mut text: Option<String> = None;
        let mut children = Vec::new();
        loop {
            let rest = self.rest();
            if rest.is_empty() {
                return Err(self.error("no element found"));
            }
            if rest.starts_with("</") {
                self.pos += 2;
                let close = self.name()?;
                self.skip_space();
                if close != name || !self.eat(">") {
                    return Err(self.error("mismatched tag"));
                }
                return Ok(Raw {
                    name,
                    attrs,
                    text,
                    children,
                });
            }
            if rest.starts_with("<!--") {
                self.pos += 4;
                self.skip_until("-->", "unclosed token")?;
                continue;
            }
            if rest.starts_with("<![CDATA[") {
                self.pos += 9;
                let Some(end) = self.rest().find("]]>") else {
                    return Err(self.error("unclosed CDATA section"));
                };
                if children.is_empty() {
                    text.get_or_insert_with(String::new)
                        .push_str(&self.rest()[..end]);
                }
                self.pos += end + 3;
                continue;
            }
            if rest.starts_with("<?") {
                self.pos += 2;
                self.skip_until("?>", "unclosed token")?;
                continue;
            }
            if rest.starts_with('<') {
                children.push(self.element()?);
                continue;
            }
            let end = rest.find('<').unwrap_or(rest.len());
            let data = self.decode(&rest[..end])?;
            if children.is_empty() {
                text.get_or_insert_with(String::new).push_str(&data);
            }
            self.pos += end;
        }
    }
}

/// Resolve namespaces the way expat (namespace mode) and ElementTree do.
fn resolve(raw: Raw, scope: &[(String, String)]) -> Result<Element, String> {
    let mut scope = scope.to_vec();
    for (k, v) in &raw.attrs {
        if k == "xmlns" {
            scope.push((String::new(), v.clone()));
        } else if let Some(prefix) = k.strip_prefix("xmlns:") {
            scope.push((prefix.to_string(), v.clone()));
        }
    }
    let lookup = |prefix: &str| {
        scope
            .iter()
            .rev()
            .find(|(p, _)| p == prefix)
            .map(|(_, uri)| uri.clone())
    };
    let tag = match raw.name.split_once(':') {
        Some((prefix, local)) => match lookup(prefix) {
            Some(uri) if !uri.is_empty() => format!("{{{uri}}}{local}"),
            _ => return Err("unbound prefix: line 1, column 0".into()),
        },
        None => match lookup("") {
            Some(uri) if !uri.is_empty() => format!("{{{uri}}}{}", raw.name),
            _ => raw.name.clone(),
        },
    };
    let children = raw
        .children
        .into_iter()
        .map(|c| resolve(c, &scope))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Element {
        tag,
        text: raw.text,
        children,
    })
}

/// `ET.fromstring(text)`, or the `ParseError` text.
pub fn parse(text: &str) -> Result<Element, String> {
    let mut p = Parser { src: text, pos: 0 };
    p.misc()?;
    let root = p.element()?;
    p.misc()?;
    if p.pos < p.src.len() {
        return Err(p.error("junk after document element"));
    }
    resolve(root, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_documents_read_like_elementtree() {
        let doc = parse(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult \
             xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>b</Name>\
             <Contents><Key>a%2Bb</Key><ETag>&#34;x&#34;</ETag></Contents>\
             <IsTruncated>false</IsTruncated></ListBucketResult>",
        )
        .unwrap();
        assert_eq!(doc.namespace(), "http://s3.amazonaws.com/doc/2006-03-01/");
        assert_eq!(doc.findtext("Name").as_deref(), Some("b"));
        let contents = doc.findall("Contents");
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0].findtext("ETag").as_deref(), Some("\"x\""));
        assert_eq!(doc.findtext("Missing"), None);
        assert_eq!(
            doc.findtext_strict("UploadId").unwrap_err(),
            "XML element <UploadId> not found"
        );
        let loc = parse("<LocationConstraint xmlns=\"x\"></LocationConstraint>").unwrap();
        assert_eq!(loc.text, None);
        let err = parse("<Error><Code>NoSuchKey</Code></Error>").unwrap();
        assert_eq!(err.namespace(), "");
        assert_eq!(err.findtext("Code").as_deref(), Some("NoSuchKey"));
        assert_eq!(err.findtext("Key"), None);
        let empty = parse("<Error><Key></Key></Error>").unwrap();
        assert_eq!(empty.findtext("Key").as_deref(), Some(""));
    }

    #[test]
    fn malformed_documents_fail() {
        assert!(parse("").unwrap_err().starts_with("no element found"));
        assert!(parse("not xml").unwrap_err().starts_with("syntax error"));
        assert!(
            parse("<a><b></a>")
                .unwrap_err()
                .starts_with("mismatched tag")
        );
        assert!(
            parse("<a/>x")
                .unwrap_err()
                .starts_with("junk after document element")
        );
    }
}
