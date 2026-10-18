//! python-docx 1.2's OPC package: read by walking the relationships from
//! the package (`PackageReader`), each part an `XmlPart` (parsed with
//! `remove_blank_text`) when its content type is one python-docx registers,
//! a raw blob otherwise; written back as `PackageWriter` writes it.

use crate::xml::{self, Element, ParseOptions};
use crate::zip::{self, Archive};
use crate::{DocxError, utf8_decode_error};

/// `RT.IMAGE`.
pub const RT_IMAGE: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image";
/// `RT.OFFICE_DOCUMENT`.
pub const RT_OFFICE_DOCUMENT: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument";
/// `RT.CORE_PROPERTIES`.
pub const RT_CORE_PROPERTIES: &str =
    "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties";
/// `RT.HEADER`.
pub const RT_HEADER: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/header";
/// `RT.FOOTER`.
pub const RT_FOOTER: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer";
/// `CT.WML_DOCUMENT_MAIN`.
pub const CT_DOCUMENT_MAIN: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml";
/// `CT.OPC_CORE_PROPERTIES`.
pub const CT_CORE_PROPERTIES: &str = "application/vnd.openxmlformats-package.core-properties+xml";
/// The footnotes part's content type (rendered by docxtpl as a raw blob).
pub const CT_FOOTNOTES: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml";

const CT_NS: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
const PR_NS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";

/// The content types python-docx loads as `XmlPart`s.
const XML_PART_TYPES: [&str; 8] = [
    CT_CORE_PROPERTIES,
    "application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml",
    CT_DOCUMENT_MAIN,
    "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
];

/// `opc.spec.default_content_types`.
const DEFAULT_CONTENT_TYPES: [(&str, &str); 18] = [
    (
        "bin",
        "application/vnd.openxmlformats-officedocument.presentationml.printerSettings",
    ),
    (
        "bin",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.printerSettings",
    ),
    (
        "bin",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.printerSettings",
    ),
    ("bmp", "image/bmp"),
    ("emf", "image/x-emf"),
    ("fntdata", "application/x-fontdata"),
    ("gif", "image/gif"),
    ("jpe", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("jpg", "image/jpeg"),
    ("png", "image/png"),
    (
        "rels",
        "application/vnd.openxmlformats-package.relationships+xml",
    ),
    ("tif", "image/tiff"),
    ("tiff", "image/tiff"),
    ("wdp", "image/vnd.ms-photo"),
    ("wmf", "image/x-wmf"),
    (
        "xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ),
    ("xml", "application/xml"),
];

/// A part's content.
#[derive(Debug, Clone)]
pub enum Content {
    /// An `XmlPart`'s element.
    Xml(Element),
    /// A plain `Part`'s blob.
    Raw(Vec<u8>),
}

/// A relationship's target.
#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    /// A part of the package (its index).
    Part(usize),
    /// An external URI.
    External(String),
}

/// A relationship (`_Relationship`).
#[derive(Debug, Clone)]
pub struct Rel {
    /// `rId`.
    pub rid: String,
    /// The relationship type.
    pub reltype: String,
    /// The target.
    pub target: Target,
}

/// A part.
#[derive(Debug, Clone)]
pub struct Part {
    /// The part name (`PackURI`).
    pub partname: String,
    /// The content type.
    pub content_type: String,
    /// The content.
    pub content: Content,
    /// Its relationships, in `rId` insertion order (a dict).
    pub rels: Vec<Rel>,
}

impl Part {
    /// `part.blob`.
    pub fn blob(&self) -> Vec<u8> {
        match &self.content {
            Content::Xml(e) => xml::serialize_part(e),
            Content::Raw(b) => b.clone(),
        }
    }
}

/// A package.
#[derive(Debug, Clone)]
pub struct Package {
    /// The parts, in the order they were loaded.
    pub parts: Vec<Part>,
    /// The package's relationships.
    pub rels: Vec<Rel>,
}

fn internal(m: impl Into<String>) -> DocxError {
    DocxError::Internal(m.into())
}

// ----------------------------------------------------------- pack URIs

/// `posixpath.normpath`.
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let mut initial = usize::from(path.starts_with('/'));
    if path.starts_with("//") && !path.starts_with("///") {
        initial = 2;
    }
    let mut comps: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp != ".." || (initial == 0 && comps.is_empty()) || comps.last() == Some(&"..") {
            comps.push(comp);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let joined = comps.join("/");
    let out = format!("{}{}", "/".repeat(initial), joined);
    if out.is_empty() { ".".into() } else { out }
}

/// `posixpath.join(a, b)`.
fn join(a: &str, b: &str) -> String {
    if b.starts_with('/') {
        b.to_string()
    } else if a.is_empty() || a.ends_with('/') {
        format!("{a}{b}")
    } else {
        format!("{a}/{b}")
    }
}

/// `posixpath.split(p)`.
fn split(p: &str) -> (String, String) {
    let i = p.rfind('/').map_or(0, |i| i + 1);
    let (head, tail) = (&p[..i], &p[i..]);
    let head = if !head.is_empty() && head.chars().any(|c| c != '/') {
        head.trim_end_matches('/')
    } else {
        head
    };
    (head.to_string(), tail.to_string())
}

/// `PackURI.baseURI`.
pub fn base_uri(partname: &str) -> String {
    split(partname).0
}

/// `PackURI.ext` (without the dot).
pub fn ext(partname: &str) -> String {
    let sep = partname.rfind('/').map_or(-1, |i| i as i64);
    let Some(dot) = partname.rfind('.') else {
        return String::new();
    };
    if dot as i64 > sep {
        let mut idx = (sep + 1) as usize;
        while idx < dot {
            if &partname[idx..idx + 1] != "." {
                return partname[dot + 1..].to_string();
            }
            idx += 1;
        }
    }
    String::new()
}

/// `PackURI.rels_uri`.
pub fn rels_uri(partname: &str) -> String {
    let (base, filename) = split(partname);
    join(&join(&base, "_rels"), &format!("{filename}.rels"))
}

/// `PackURI.from_rel_ref(baseURI, ref)`.
pub fn from_rel_ref(base: &str, reference: &str) -> String {
    let joined = join(base, reference);
    // `abspath` of a path that is always absolute here.
    normpath(&joined)
}

/// `PackURI.relative_ref(baseURI)` (`posixpath.relpath`).
pub fn relative_ref(partname: &str, base: &str) -> String {
    if base == "/" {
        return partname[1..].to_string();
    }
    let norm = |p: &str| -> Vec<String> {
        normpath(p)
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    };
    let start = norm(base);
    let path = norm(partname);
    let common = start
        .iter()
        .zip(path.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let mut rel: Vec<String> =
        std::iter::repeat_n("..".to_string(), start.len() - common).collect();
    rel.extend(path[common..].iter().cloned());
    if rel.is_empty() {
        ".".into()
    } else {
        rel.join("/")
    }
}

// --------------------------------------------------------------- reading

struct SRel {
    rid: Option<String>,
    reltype: Option<String>,
    target_ref: Option<String>,
    external: bool,
    base: String,
}

impl SRel {
    fn target_partname(&self) -> Result<String, DocxError> {
        let Some(r) = &self.target_ref else {
            return Err(internal(
                "expected str, bytes or os.PathLike object, not NoneType",
            ));
        };
        Ok(from_rel_ref(&self.base, r))
    }
}

fn parse_part_xml(blob: &[u8]) -> Result<Element, DocxError> {
    xml::parse_bytes(
        blob,
        ParseOptions {
            remove_blank_text: true,
        },
    )
    .map_err(|e| internal(e.0))
}

fn read(archive: &Archive<'_>, partname: &str) -> Option<Result<Vec<u8>, DocxError>> {
    archive
        .read(&partname[1..])
        .map(|r| r.map_err(|e| internal(e.0)))
}

fn srels_for(archive: &Archive<'_>, partname: &str) -> Result<Vec<SRel>, DocxError> {
    let base = base_uri(partname);
    let Some(blob) = read(archive, &rels_uri(partname)) else {
        return Ok(Vec::new());
    };
    let root = parse_part_xml(&blob?)?;
    Ok(root
        .findall(PR_NS, "Relationship")
        .into_iter()
        .map(|r| SRel {
            rid: r.get(None, "Id").map(str::to_string),
            reltype: r.get(None, "Type").map(str::to_string),
            target_ref: r.get(None, "Target").map(str::to_string),
            external: r.get(None, "TargetMode").unwrap_or("Internal") == "External",
            base: base.clone(),
        })
        .collect())
}

struct SPart {
    partname: String,
    reltype: Option<String>,
    blob: Vec<u8>,
    srels: Vec<SRel>,
}

fn walk(
    archive: &Archive<'_>,
    srels: &[SRel],
    visited: &mut Vec<String>,
    out: &mut Vec<SPart>,
) -> Result<(), DocxError> {
    for srel in srels {
        if srel.external {
            continue;
        }
        let partname = srel.target_partname()?;
        if visited.contains(&partname) {
            continue;
        }
        visited.push(partname.clone());
        let part_srels = srels_for(archive, &partname)?;
        let Some(blob) = read(archive, &partname) else {
            return Err(internal(format!(
                "\"There is no item named '{}' in the archive\"",
                &partname[1..]
            )));
        };
        let blob = blob?;
        let index = out.len();
        out.push(SPart {
            partname,
            reltype: srel.reltype.clone(),
            blob,
            srels: Vec::new(),
        });
        walk(archive, &part_srels, visited, out)?;
        out[index].srels = part_srels;
    }
    Ok(())
}

impl Package {
    /// `Package.open(path)`: `path` only names the file in error messages.
    pub fn open(data: &[u8], path: &str) -> Result<Self, DocxError> {
        if !zip::is_zipfile(data) {
            return Err(internal(format!("Package not found at '{path}'")));
        }
        let archive = Archive::open(data).map_err(|e| internal(e.0))?;
        let Some(ct_blob) = read(&archive, "/[Content_Types].xml") else {
            return Err(internal(
                "\"There is no item named '[Content_Types].xml' in the archive\"",
            ));
        };
        let types = parse_part_xml(&ct_blob?)?;
        let mut overrides: Vec<(String, String)> = Vec::new();
        let mut defaults: Vec<(String, String)> = Vec::new();
        let attr_lower = |e: &Element, name: &str| -> Result<String, DocxError> {
            e.get(None, name)
                .map(str::to_lowercase)
                .ok_or_else(|| internal("'NoneType' object has no attribute 'lower'"))
        };
        for o in types.findall(CT_NS, "Override") {
            let key = attr_lower(o, "PartName")?;
            let value = o.get(None, "ContentType").unwrap_or_default().to_string();
            match overrides.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => overrides.push((key, value)),
            }
        }
        for d in types.findall(CT_NS, "Default") {
            let key = attr_lower(d, "Extension")?;
            let value = d.get(None, "ContentType").unwrap_or_default().to_string();
            match defaults.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => defaults.push((key, value)),
            }
        }
        let pkg_srels = srels_for(&archive, "/")?;
        let mut sparts = Vec::new();
        walk(&archive, &pkg_srels, &mut Vec::new(), &mut sparts)?;
        let mut parts = Vec::with_capacity(sparts.len());
        for sp in &sparts {
            let lower = sp.partname.to_lowercase();
            let content_type = if let Some((_, ct)) = overrides.iter().find(|(k, _)| *k == lower) {
                ct.clone()
            } else if let Some((_, ct)) = defaults
                .iter()
                .find(|(k, _)| *k == ext(&sp.partname).to_lowercase())
            {
                ct.clone()
            } else {
                return Err(internal(format!(
                    "\"no content type for partname '{}' in [Content_Types].xml\"",
                    sp.partname
                )));
            };
            let is_image = sp.reltype.as_deref() == Some(RT_IMAGE);
            let content = if !is_image && XML_PART_TYPES.contains(&content_type.as_str()) {
                Content::Xml(parse_part_xml(&sp.blob)?)
            } else {
                Content::Raw(sp.blob.clone())
            };
            parts.push(Part {
                partname: sp.partname.clone(),
                content_type,
                content,
                rels: Vec::new(),
            });
        }
        let mut pkg = Package {
            parts,
            rels: Vec::new(),
        };
        let index_of =
            |pkg: &Package, name: &str| pkg.parts.iter().position(|p| p.partname == name);
        let load =
            |pkg: &mut Package, source: Option<usize>, srel: &SRel| -> Result<(), DocxError> {
                let target = if srel.external {
                    Target::External(srel.target_ref.clone().unwrap_or_default())
                } else {
                    let name = srel.target_partname()?;
                    let Some(i) = index_of(pkg, &name) else {
                        return Err(internal(format!("'{name}'")));
                    };
                    Target::Part(i)
                };
                let rel = Rel {
                    rid: srel.rid.clone().unwrap_or_default(),
                    reltype: srel.reltype.clone().unwrap_or_default(),
                    target,
                };
                let rels = match source {
                    None => &mut pkg.rels,
                    Some(i) => &mut pkg.parts[i].rels,
                };
                match rels.iter_mut().find(|r| r.rid == rel.rid) {
                    Some(slot) => *slot = rel,
                    None => rels.push(rel),
                }
                Ok(())
            };
        for srel in &pkg_srels {
            load(&mut pkg, None, srel)?;
        }
        for (i, sp) in sparts.iter().enumerate() {
            for srel in &sp.srels {
                load(&mut pkg, Some(i), srel)?;
            }
        }
        Ok(pkg)
    }

    /// `rels.part_with_reltype(reltype)` of a relationship collection.
    pub fn part_with_reltype(rels: &[Rel], reltype: &str) -> Result<Option<usize>, DocxError> {
        let matching: Vec<&Rel> = rels.iter().filter(|r| r.reltype == reltype).collect();
        match matching.as_slice() {
            [] => Ok(None),
            [one] => match &one.target {
                Target::Part(i) => Ok(Some(*i)),
                Target::External(_) => Err(DocxError::Value(
                    "target_part property on _Relationship is undefined when target mode is External"
                        .into(),
                )),
            },
            _ => Err(DocxError::Value(format!(
                "multiple relationships of type '{reltype}' in collection"
            ))),
        }
    }

    /// `iter_parts()`: the parts reachable from the package, depth first.
    pub fn iter_parts(&self) -> Vec<usize> {
        let mut out = Vec::new();
        let mut visited = vec![false; self.parts.len()];
        self.walk_parts(&self.rels, &mut visited, &mut out);
        out
    }

    fn walk_parts(&self, rels: &[Rel], visited: &mut [bool], out: &mut Vec<usize>) {
        for rel in rels {
            let Target::Part(i) = rel.target else {
                continue;
            };
            if visited[i] {
                continue;
            }
            visited[i] = true;
            out.push(i);
            self.walk_parts(&self.parts[i].rels, visited, out);
        }
    }

    /// `rels.get_or_add(reltype, part)` on the package: a new `rId`.
    pub fn relate(&mut self, reltype: &str, part: usize) {
        if self
            .rels
            .iter()
            .any(|r| r.reltype == reltype && r.target == Target::Part(part))
        {
            return;
        }
        let mut n = 1;
        let rid = loop {
            let candidate = format!("rId{n}");
            if !self.rels.iter().any(|r| r.rid == candidate) {
                break candidate;
            }
            n += 1;
        };
        self.rels.push(Rel {
            rid,
            reltype: reltype.to_string(),
            target: Target::Part(part),
        });
    }

    /// `PackageWriter.write`: the archive's members and their bytes, in
    /// the order Python writes them.
    pub fn members(&self) -> Vec<(String, Vec<u8>)> {
        let order = self.iter_parts();
        let mut out = Vec::new();
        out.push((
            "[Content_Types].xml".to_string(),
            self.content_types(&order),
        ));
        out.push(("_rels/.rels".to_string(), self.rels_xml(&self.rels, "/")));
        for &i in &order {
            let part = &self.parts[i];
            out.push((part.partname[1..].to_string(), part.blob()));
            if !part.rels.is_empty() {
                out.push((
                    rels_uri(&part.partname)[1..].to_string(),
                    self.rels_xml(&part.rels, &base_uri(&part.partname)),
                ));
            }
        }
        out
    }

    /// The package written as a zip archive.
    pub fn save(&self, now_local: chrono::NaiveDateTime) -> Result<Vec<u8>, DocxError> {
        let mut w = zip::Writer::new(now_local);
        for (name, data) in self.members() {
            w.write(&name, &data).map_err(|e| internal(e.0))?;
        }
        Ok(w.finish())
    }

    fn content_types(&self, order: &[usize]) -> Vec<u8> {
        let mut defaults: Vec<(String, String)> = vec![
            (
                "rels".into(),
                "application/vnd.openxmlformats-package.relationships+xml".into(),
            ),
            ("xml".into(), "application/xml".into()),
        ];
        let mut overrides: Vec<(String, String)> = Vec::new();
        for &i in order {
            let part = &self.parts[i];
            let e = ext(&part.partname);
            let lower = e.to_lowercase();
            if DEFAULT_CONTENT_TYPES
                .iter()
                .any(|(x, ct)| *x == lower && *ct == part.content_type)
            {
                match defaults.iter_mut().find(|(k, _)| *k == lower) {
                    Some(slot) => slot.1 = part.content_type.clone(),
                    None => defaults.push((lower, part.content_type.clone())),
                }
            } else {
                match overrides.iter_mut().find(|(k, _)| *k == part.partname) {
                    Some(slot) => slot.1 = part.content_type.clone(),
                    None => overrides.push((part.partname.clone(), part.content_type.clone())),
                }
            }
        }
        defaults.sort_by(|a, b| a.0.cmp(&b.0));
        overrides.sort_by(|a, b| a.0.cmp(&b.0));
        let mut root = Element::new(None, "Types", Some(CT_NS));
        root.ns_defs.push((None, CT_NS.to_string()));
        for (ext, ct) in defaults {
            let mut d = Element::new(None, "Default", Some(CT_NS));
            d.set(None, None, "Extension", &ext);
            d.set(None, None, "ContentType", &ct);
            root.children.push(xml::Node::Element(d));
        }
        for (name, ct) in overrides {
            let mut o = Element::new(None, "Override", Some(CT_NS));
            o.set(None, None, "PartName", &name);
            o.set(None, None, "ContentType", &ct);
            root.children.push(xml::Node::Element(o));
        }
        xml::serialize_part(&root)
    }

    fn rels_xml(&self, rels: &[Rel], base: &str) -> Vec<u8> {
        let mut root = Element::new(None, "Relationships", Some(PR_NS));
        root.ns_defs.push((None, PR_NS.to_string()));
        for rel in rels {
            let mut r = Element::new(None, "Relationship", Some(PR_NS));
            r.set(None, None, "Id", &rel.rid);
            r.set(None, None, "Type", &rel.reltype);
            match &rel.target {
                Target::Part(i) => {
                    r.set(
                        None,
                        None,
                        "Target",
                        &relative_ref(&self.parts[*i].partname, base),
                    );
                }
                Target::External(t) => {
                    r.set(None, None, "Target", t);
                    r.set(None, None, "TargetMode", "External");
                }
            }
            root.children.push(xml::Node::Element(r));
        }
        xml::serialize_part(&root)
    }
}

/// `blob.decode("utf-8")`, a `UnicodeDecodeError` as the `ValueError` it is.
pub fn decode_utf8(blob: &[u8]) -> Result<String, DocxError> {
    match String::from_utf8(blob.to_vec()) {
        Ok(s) => Ok(s),
        Err(_) => Err(DocxError::Value(
            utf8_decode_error(blob).unwrap_or_default(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_uris_as_python() {
        assert_eq!(base_uri("/word/document.xml"), "/word");
        assert_eq!(base_uri("/a.xml"), "/");
        assert_eq!(
            rels_uri("/word/document.xml"),
            "/word/_rels/document.xml.rels"
        );
        assert_eq!(rels_uri("/"), "/_rels/.rels");
        assert_eq!(
            from_rel_ref("/word", "media/image1.png"),
            "/word/media/image1.png"
        );
        assert_eq!(
            from_rel_ref("/word", "../customXml/item1.xml"),
            "/customXml/item1.xml"
        );
        assert_eq!(from_rel_ref("/", "word/document.xml"), "/word/document.xml");
        assert_eq!(
            relative_ref("/customXml/item1.xml", "/word"),
            "../customXml/item1.xml"
        );
        assert_eq!(relative_ref("/word/media/a.png", "/word"), "media/a.png");
        assert_eq!(ext("/word/document.xml"), "xml");
        assert_eq!(ext("/word/.rels"), "");
        assert_eq!(ext("/word/a.b.PNG"), "PNG");
    }
}
