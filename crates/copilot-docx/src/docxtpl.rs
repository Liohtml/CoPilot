//! docxtpl 0.20.2's `DocxTemplate.render` and `save`, step by step: the
//! body's XML as lxml writes it, `patch_xml`'s regular expressions, Jinja
//! (`render_xml_part`), `resolve_listing`, `fix_tables`, `fix_docpr_ids`,
//! the body put back, the headers and footers, the core properties and the
//! footnotes.

use std::sync::OnceLock;

use copilot_jinja::{Data, Environment};
use fancy_regex::Regex;

use crate::DocxError;
use crate::opc::{self, Content, Package, Target};
use crate::pyre::{self, group};
use crate::recover::{self, RecoverError, Recovered};
use crate::xml::{self, Element, Node, ParseOptions};

const W_NS: &str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const WP_NS: &str = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing";
const DC_NS: &str = "http://purl.org/dc/elements/1.1/";
const CP_NS: &str = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties";
const DCTERMS_NS: &str = "http://purl.org/dc/terms/";
const XSI_NS: &str = "http://www.w3.org/2001/XMLSchema-instance";

struct Patterns {
    braces: Regex,
    tags: Regex,
    striptags: Regex,
    colspan: Regex,
    cellbg: Regex,
    empty_run: Regex,
    gridspan: Regex,
    shd: Regex,
    tcpr: Regex,
    preserve: Regex,
    r_tag: Regex,
    merge_prev: Regex,
    merge_next: Regex,
    ytags: Vec<Regex>,
    ycomments: Vec<Regex>,
    vm_tc: Regex,
    vm_inner: Regex,
    hm_tc: Regex,
    gridspan_val: Regex,
    hm: Regex,
    hm_inner: Regex,
    has_gridspan: Regex,
    clean: Regex,
    p_open: Regex,
    p_close: Regex,
    lst_p: Regex,
    lst_ppr: Regex,
    lst_r: Regex,
    lst_rpr: Regex,
    lst_t: Regex,
}

fn patterns() -> Result<&'static Patterns, DocxError> {
    static P: OnceLock<Result<Patterns, DocxError>> = OnceLock::new();
    P.get_or_init(build).as_ref().map_err(|e| e.clone())
}

fn build() -> Result<Patterns, DocxError> {
    let c = pyre::compile;
    let mut ytags = Vec::new();
    for y in ["tr", "tc", "p", "r"] {
        ytags.push(c(
            &format!(
                r"<w:{y}[ >](?:(?!<w:{y}[ >]).)*(\{{%|\{{\{{){y} ([^}}%]*(?:%\}}|\}}\}})).*?</w:{y}>"
            ),
            true,
        )?);
    }
    let mut ycomments = Vec::new();
    for y in ["tr", "tc", "p"] {
        ycomments.push(c(
            &format!(r"<w:{y}[ >](?:(?!<w:{y}[ >]).)*(\{{#){y} ([^}}#]*(?:#\}})).*?</w:{y}>"),
            true,
        )?);
    }
    Ok(Patterns {
        braces: c(
            r"(?<=\{)(<[^>]*>)+(?=[\{%\#])|(?<=[%\}\#])(<[^>]*>)+(?=\})",
            true,
        )?,
        tags: c(
            r"\{%(?:(?!%\}).)*|\{#(?:(?!#\}).)*|\{\{(?:(?!\}\}).)*",
            true,
        )?,
        striptags: c(r"</w:t>.*?(<w:t>|<w:t [^>]*>)", true)?,
        colspan: c(
            r"(<w:tc[ >](?:(?!<w:tc[ >]).)*)\{%\s*colspan\s+([^%]*)\s*%\}(.*?</w:tc>)",
            true,
        )?,
        cellbg: c(
            r"(<w:tc[ >](?:(?!<w:tc[ >]).)*)\{%\s*cellbg\s+([^%]*)\s*%\}(.*?</w:tc>)",
            true,
        )?,
        empty_run: c(r"<w:r[ >](?:(?!<w:r[ >]).)*<w:t></w:t>.*?</w:r>", true)?,
        gridspan: c(r"<w:gridSpan[^/]*/>", false)?,
        shd: c(r"<w:shd[^/]*/>", false)?,
        tcpr: c(r"(<w:tcPr[^>]*>)", false)?,
        preserve: c(r"<w:t>((?:(?!<w:t>).)*)(\{\{.*?\}\}|\{%.*?%\})", true)?,
        r_tag: c(r"(\{\{r\s.*?\}\}|\{%r\s.*?%\})", true)?,
        merge_prev: c(r"</w:t>(?:(?!</w:t>).)*?\{%-", true)?,
        merge_next: c(r"-%\}(?:(?!<w:t[ >]|\{%|\{\{).)*?<w:t[^>]*?>", true)?,
        ytags,
        ycomments,
        vm_tc: c(
            r"<w:tc[ >](?:(?!<w:tc[ >]).)*?\{%\s*vm\s*%\}.*?</w:tc[ >]",
            true,
        )?,
        vm_inner: c(
            r"(</w:tcPr[ >].*?<w:t(?:.*?)>)(.*?)(?:\{%\s*vm\s*%\})(.*?)(</w:t>)",
            true,
        )?,
        hm_tc: c(
            r"<w:tc[ >](?:(?!<w:tc[ >]).)*?\{%\s*hm\s*%\}.*?</w:tc[ >]",
            true,
        )?,
        gridspan_val: c(r#"(w:gridSpan w:val=")(\d+)(")"#, true)?,
        hm: c(r"\{%\s*hm\s*%\}", true)?,
        hm_inner: c(
            r"(</w:tcPr[ >].*?<w:t(?:.*?)>)(.*?)(?:\{%\s*hm\s*%\})(.*?)(</w:t>)",
            true,
        )?,
        has_gridspan: c(r"w:gridSpan", false)?,
        clean: c(r"(?<=\{[\{%])(.*?)(?=[\}%]\})", false)?,
        p_open: c(r"<w:p([ >])", false)?,
        p_close: c(r"\n<w:p([ >])", false)?,
        lst_p: c(r"<w:p(?: [^>]*)?>.*?</w:p>", true)?,
        lst_ppr: c(r"<w:pPr>.*?</w:pPr>", false)?,
        lst_r: c(r"<w:r(?: [^>]*)?>.*?</w:r>", true)?,
        lst_rpr: c(r"<w:rPr>.*?</w:rPr>", false)?,
        lst_t: c(r"<w:t(?: [^>]*)?>.*?</w:t>", true)?,
    })
}

/// `DocxTemplate.patch_xml`.
pub fn patch_xml(src: &str) -> Result<String, DocxError> {
    let p = patterns()?;
    let mut x = pyre::sub(&p.braces, "", src)?;
    x = pyre::sub_fn(&p.tags, &x, |m| {
        pyre::sub(&p.striptags, "", group(m, 0).unwrap_or(""))
    })?;
    let cell = |m: &fancy_regex::Captures<'_, str>, strip: &Regex, insert: &str| {
        let cell_xml = format!("{}{}", group(m, 1).unwrap_or(""), group(m, 3).unwrap_or(""));
        let cell_xml = pyre::sub(&p.empty_run, "", &cell_xml)?;
        let cell_xml = pyre::sub_once(strip, "", &cell_xml)?;
        let template = insert.replace("%s", group(m, 2).unwrap_or(""));
        pyre::sub(&p.tcpr, &template, &cell_xml)
    };
    x = pyre::sub_fn(&p.colspan, &x, |m| {
        cell(m, &p.gridspan, r#"\1<w:gridSpan w:val="{{%s}}"/>"#)
    })?;
    x = pyre::sub_fn(&p.cellbg, &x, |m| {
        cell(
            m,
            &p.shd,
            r#"\1<w:shd w:val="clear" w:color="auto" w:fill="{{%s}}"/>"#,
        )
    })?;
    x = pyre::sub(&p.preserve, r#"<w:t xml:space="preserve">\1\2"#, &x)?;
    x = pyre::sub(
        &p.r_tag,
        r#"</w:t></w:r><w:r><w:t xml:space="preserve">\1</w:t></w:r><w:r><w:t xml:space="preserve">"#,
        &x,
    )?;
    x = pyre::sub(&p.merge_prev, "{%", &x)?;
    x = pyre::sub(&p.merge_next, "%}", &x)?;
    for re in &p.ytags {
        x = pyre::sub(re, r"\1 \2", &x)?;
    }
    for re in &p.ycomments {
        x = pyre::sub(re, r"\1 \2", &x)?;
    }
    x = pyre::sub_fn(&p.vm_tc, &x, |m| {
        pyre::sub_fn(&p.vm_inner, group(m, 0).unwrap_or(""), |m1| {
            Ok(format!(
                "<w:vMerge w:val=\"{{% if loop.first %}}restart{{% else %}}continue{{% endif %}}\"/>{}{{% if loop.first %}}{}{}{{% endif %}}{}",
                group(m1, 1).unwrap_or(""),
                group(m1, 2).unwrap_or(""),
                group(m1, 3).unwrap_or(""),
                group(m1, 4).unwrap_or("")
            ))
        })
    })?;
    x = pyre::sub_fn(&p.hm_tc, &x, |m| {
        let to_patch = group(m, 0).unwrap_or("");
        let patched = if pyre::search(&p.has_gridspan, to_patch)?.is_some() {
            let y = pyre::sub_fn(&p.gridspan_val, to_patch, |m1| {
                Ok(format!(
                    "{}{{{{ {} * loop.length }}}}{}",
                    group(m1, 1).unwrap_or(""),
                    group(m1, 2).unwrap_or(""),
                    group(m1, 3).unwrap_or("")
                ))
            })?;
            pyre::sub(&p.hm, "", &y)?
        } else {
            pyre::sub_fn(&p.hm_inner, to_patch, |m2| {
                Ok(format!(
                    "<w:gridSpan w:val=\"{{{{ loop.length }}}}\"/>{}{}{}{}",
                    group(m2, 1).unwrap_or(""),
                    group(m2, 2).unwrap_or(""),
                    group(m2, 3).unwrap_or(""),
                    group(m2, 4).unwrap_or("")
                ))
            })?
        };
        Ok(format!("{{% if loop.first %}}{patched}{{% endif %}}"))
    })?;
    x = pyre::sub_fn(&p.clean, &x, |m| {
        Ok(group(m, 0)
            .unwrap_or("")
            .replace("&#8216;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace(['\u{201c}', '\u{201d}'], "\"")
            .replace(['\u{2018}', '\u{2019}'], "'"))
    })?;
    Ok(x)
}

/// A Jinja failure: a `ValueError` (or a subclass) is the 400, the rest a
/// bare 500.
pub fn jinja_error(e: copilot_jinja::Error) -> DocxError {
    match e.kind {
        "ValueError" | "UnicodeDecodeError" | "UnicodeEncodeError" | "UnicodeError" => {
            DocxError::Value(e.message)
        }
        _ => DocxError::Internal(format!("{}: {}", e.kind, e.message)),
    }
}

/// `DocxTemplate.render_xml_part`.
pub fn render_xml_part(
    src: &str,
    env: &Environment,
    vars: &[(String, Data)],
) -> Result<String, DocxError> {
    let p = patterns()?;
    let src = pyre::sub(&p.p_open, r"\n<w:p\1", src)?;
    let dst = env.render_string(&src, vars).map_err(jinja_error)?;
    let dst = pyre::sub(&p.p_close, r"<w:p\1", &dst)?;
    let dst = dst
        .replace("{_{", "{{")
        .replace("}_}", "}}")
        .replace("{_%", "{%")
        .replace("%_}", "%}");
    resolve_listing(&dst)
}

/// `DocxTemplate.resolve_listing`.
pub fn resolve_listing(x: &str) -> Result<String, DocxError> {
    let p = patterns()?;
    pyre::sub_fn(&p.lst_p, x, |pm| {
        let para = group(pm, 0).unwrap_or("");
        let ppr = pyre::search(&p.lst_ppr, para)?.unwrap_or("").to_string();
        pyre::sub_fn(&p.lst_r, para, |rm| {
            let run = group(rm, 0).unwrap_or("");
            let rpr = pyre::search(&p.lst_rpr, run)?.unwrap_or("").to_string();
            pyre::sub_fn(&p.lst_t, run, |tm| {
                let t = group(tm, 0).unwrap_or("");
                let t = t.replace(
                    '\t',
                    &format!(
                        "</w:t></w:r><w:r>{rpr}<w:tab/></w:r><w:r>{rpr}<w:t xml:space=\"preserve\">"
                    ),
                );
                let t = t.replace(
                    '\u{7}',
                    &format!("</w:t></w:r></w:p><w:p>{ppr}<w:r>{rpr}<w:t xml:space=\"preserve\">"),
                );
                let t = t.replace('\n', "</w:t><w:br/><w:t xml:space=\"preserve\">");
                let t = t.replace(
                    '\u{c}',
                    &format!(
                        "</w:t></w:r></w:p><w:p><w:r><w:br w:type=\"page\"/></w:r></w:p><w:p>{ppr}<w:r>{rpr}<w:t xml:space=\"preserve\">"
                    ),
                );
                Ok(t)
            })
        })
    })
}

/// lxml's `float()` of an attribute's text and `str(int(x))`.
fn py_float(s: Option<&str>) -> Result<f64, DocxError> {
    let Some(s) = s else {
        return Err(DocxError::Internal(
            "TypeError: float() argument must be a string or a real number, not 'NoneType'".into(),
        ));
    };
    let t = s.trim();
    let cleaned = t.replace('_', "");
    let ok = !t.is_empty()
        && !t.starts_with('_')
        && !t.ends_with('_')
        && !t.contains("__")
        && cleaned.parse::<f64>().is_ok();
    let lower = cleaned.to_ascii_lowercase();
    let special = matches!(
        lower.trim_start_matches(['+', '-']),
        "inf" | "infinity" | "nan"
    );
    if ok || special {
        if special {
            let neg = lower.starts_with('-');
            let v = if lower.contains("nan") {
                f64::NAN
            } else {
                f64::INFINITY
            };
            return Ok(if neg { -v } else { v });
        }
        return cleaned
            .parse::<f64>()
            .map_err(|_| DocxError::Value(format!("could not convert string to float: '{s}'")));
    }
    Err(DocxError::Value(format!(
        "could not convert string to float: '{s}'"
    )))
}

fn py_int_of_float(v: f64) -> Result<String, DocxError> {
    if v.is_nan() {
        return Err(DocxError::Value(
            "cannot convert float NaN to integer".into(),
        ));
    }
    if v.is_infinite() {
        return Err(DocxError::Internal(
            "OverflowError: cannot convert float infinity to integer".into(),
        ));
    }
    let t = v.trunc();
    if t.abs() < 1e18 {
        Ok(format!("{}", t as i64))
    } else {
        Ok(format!("{t:.0}"))
    }
}

fn py_int(s: Option<&str>) -> Result<i64, DocxError> {
    let Some(s) = s else {
        return Err(DocxError::Internal(
            "TypeError: int() argument must be a string, a bytes-like object or a real number, not 'NoneType'".into(),
        ));
    };
    let t = s.trim();
    let cleaned = t.replace('_', "");
    let valid = !t.is_empty()
        && !t.starts_with('_')
        && !t.ends_with('_')
        && !t.contains("__")
        && cleaned
            .trim_start_matches(['+', '-'])
            .chars()
            .all(|c| c.is_ascii_digit())
        && !cleaned.trim_start_matches(['+', '-']).is_empty()
        && cleaned.matches(['+', '-']).count() <= 1
        && !cleaned[1..].contains(['+', '-']);
    if valid {
        if let Ok(v) = cleaned.parse::<i64>() {
            return Ok(v);
        }
    }
    Err(DocxError::Value(format!(
        "invalid literal for int() with base 10: '{s}'"
    )))
}

/// The prefix lxml finds for a namespace from an element (outermost scope
/// first in `scopes`), skipping the default namespace for an attribute.
fn prefix_for(
    scopes: &[&[(Option<String>, String)]],
    uri: &str,
    attribute: bool,
) -> Option<String> {
    for (depth, defs) in scopes.iter().enumerate().rev() {
        for (p, u) in defs.iter() {
            if u != uri || (attribute && p.is_none()) {
                continue;
            }
            // Not shadowed by an inner declaration of the same prefix.
            let shadowed = scopes[depth + 1..]
                .iter()
                .any(|inner| inner.iter().any(|(q, v)| q == p && v != uri));
            if !shadowed {
                return p.clone();
            }
        }
    }
    None
}

fn scopes_along<'a>(root: &'a Element, path: &[usize]) -> Vec<&'a [(Option<String>, String)]> {
    let mut out = vec![root.ns_defs.as_slice()];
    let mut cur = root;
    for &i in path {
        if let Some(Node::Element(e)) = cur.children.get(i) {
            out.push(e.ns_defs.as_slice());
            cur = e;
        }
    }
    out
}

/// `DocxTemplate.fix_tables` on the rendered body, which
/// `etree.fromstring(xml, XMLParser(recover=True))` repairs as libxml2 does
/// ([`crate::recover`]).
pub fn fix_tables(xml_src: &str) -> Result<Element, DocxError> {
    let mut tree = match recover::parse(xml_src) {
        Ok(Recovered::Root(root)) => root,
        // `tree.nsmap` of the `None` a document without a root gives.
        Ok(Recovered::NoRoot) => {
            return Err(DocxError::Internal(
                "AttributeError: 'NoneType' object has no attribute 'nsmap'".into(),
            ));
        }
        Err(RecoverError::Syntax(m)) => {
            return Err(DocxError::Internal(format!("XMLSyntaxError: {m}")));
        }
        Err(RecoverError::Unsupported(m)) => return Err(DocxError::Internal(m)),
    };
    // `tree.nsmap["w"]`
    let Some(ns) = tree
        .ns_defs
        .iter()
        .find(|(p, _)| p.as_deref() == Some("w"))
        .map(|(_, u)| u.clone())
    else {
        return Err(DocxError::Internal("KeyError: 'w'".into()));
    };
    for tpath in tree.iter_paths(&ns, "tbl") {
        let Some(t) = tree.at(&tpath) else { continue };
        let Some(grid_index) = t
            .children
            .iter()
            .position(|n| matches!(n, Node::Element(e) if e.is(&ns, "tblGrid")))
        else {
            return Err(DocxError::Internal(
                "AttributeError: 'NoneType' object has no attribute 'findall'".into(),
            ));
        };
        let mut gpath = tpath.clone();
        gpath.push(grid_index);
        let column_count = t
            .at(&[grid_index])
            .map_or(0, |g| g.findall(&ns, "gridCol").len());
        // Rows of this table and of any table inside it (`t.iter(tr)`).
        let row_paths = t.iter_paths(&ns, "tr");
        let mut to_add = 0usize;
        for rp in &row_paths {
            let cells = t.at(rp).map_or(0, |r| r.findall(&ns, "tc").len());
            if column_count + to_add < cells {
                to_add = cells - column_count;
            }
        }
        let w_prefix = {
            let scopes = scopes_along(&tree, &gpath);
            prefix_for(&scopes, &ns, true)
        };
        let el_prefix = {
            let scopes = scopes_along(&tree, &gpath);
            prefix_for(&scopes, &ns, false)
        };
        if to_add > 0 {
            let Some(grid) = tree.at_mut(&gpath) else {
                continue;
            };
            let mut width = 0.0;
            for c in grid.findall(&ns, "gridCol") {
                if let Some(v) = c.get(Some(&ns), "w") {
                    width += py_float(Some(v))?;
                }
            }
            if width > 0.0 {
                let old_average = width / column_count as f64;
                let new_average = width / (column_count + to_add) as f64;
                let mut updates = Vec::new();
                for c in grid.findall(&ns, "gridCol") {
                    let w = py_float(c.get(Some(&ns), "w"))?;
                    updates.push(py_int_of_float(w * new_average / old_average)?);
                }
                let mut k = 0;
                for n in grid.children.iter_mut() {
                    if let Node::Element(c) = n {
                        if c.is(&ns, "gridCol") {
                            if let Some(v) = updates.get(k) {
                                c.set(Some(&ns), w_prefix.as_deref(), "w", v);
                            }
                            k += 1;
                        }
                    }
                }
                for _ in 0..to_add {
                    let mut col = Element::new(el_prefix.as_deref(), "gridCol", Some(&ns));
                    col.set(
                        Some(&ns),
                        w_prefix.as_deref(),
                        "w",
                        &py_int_of_float(new_average)?,
                    );
                    grid.children.push(Node::Element(col));
                }
            }
        }
        // Refetch columns after columns addition.
        let Some(t) = tree.at(&tpath) else { continue };
        let columns_len = t
            .at(&[grid_index])
            .map_or(0, |g| g.findall(&ns, "gridCol").len());
        let mut cells_len_max = 0i64;
        for rp in t.iter_paths(&ns, "tr") {
            let Some(r) = t.at(&rp) else { continue };
            let mut total = 0i64;
            for cell in r.findall(&ns, "tc") {
                let span = cell
                    .find(&ns, "tcPr")
                    .and_then(|pr| pr.find(&ns, "gridSpan"));
                match span {
                    Some(g) => total += py_int(g.get(Some(&ns), "val"))?,
                    None => total += 1,
                }
            }
            cells_len_max = cells_len_max.max(total);
        }
        let to_remove = columns_len as i64 - cells_len_max;
        if to_remove > 0 {
            let Some(grid) = tree.at_mut(&gpath) else {
                continue;
            };
            let col_indices: Vec<usize> = grid
                .children
                .iter()
                .enumerate()
                .filter(|(_, n)| matches!(n, Node::Element(e) if e.is(&ns, "gridCol")))
                .map(|(i, _)| i)
                .collect();
            let remove_from = col_indices.len() - to_remove as usize;
            let mut removed_width = 0.0;
            for &i in col_indices[remove_from..].iter().rev() {
                if let Some(Node::Element(c)) = grid.children.get(i) {
                    removed_width += py_float(c.get(Some(&ns), "w"))?;
                }
            }
            // Removal in document order (each takes its tail along).
            for &i in col_indices[remove_from..].iter().rev() {
                grid.remove_child(i);
            }
            let left: Vec<usize> = grid
                .children
                .iter()
                .enumerate()
                .filter(|(_, n)| matches!(n, Node::Element(e) if e.is(&ns, "gridCol")))
                .map(|(i, _)| i)
                .collect();
            let mut extra_space = 0i64;
            if !left.is_empty() {
                extra_space = (removed_width / left.len() as f64).trunc() as i64;
            }
            for i in left {
                if let Some(Node::Element(c)) = grid.children.get_mut(i) {
                    let w = py_float(c.get(Some(&ns), "w"))?;
                    let v = py_int_of_float(w + extra_space as f64)?;
                    c.set(Some(&ns), w_prefix.as_deref(), "w", &v);
                }
            }
        }
    }
    Ok(tree)
}

/// `DocxTemplate.fix_docpr_ids`.
pub fn fix_docpr_ids(tree: &mut Element, index: &mut u64) {
    for path in tree.iter_paths(WP_NS, "docPr") {
        if let Some(e) = tree.at_mut(&path) {
            *index += 1;
            e.set(None, None, "id", &index.to_string());
        }
    }
}

/// The rendering, as `render(context, jinja_env)` then `save()` run it.
pub struct Template {
    /// The package.
    pub package: Package,
    document: usize,
}

impl Template {
    /// `DocxTemplate(path)` then `Document(path)`: `path` names the file in
    /// the `ValueError`s python-docx raises.
    pub fn open(data: &[u8], path: &str) -> Result<Self, DocxError> {
        let package = Package::open(data, path)?;
        let document = match Package::part_with_reltype(&package.rels, opc::RT_OFFICE_DOCUMENT)? {
            Some(i) => i,
            None => {
                return Err(DocxError::Internal(format!(
                    "KeyError: \"no relationship of type '{}' in collection\"",
                    opc::RT_OFFICE_DOCUMENT
                )));
            }
        };
        let ct = &package.parts[document].content_type;
        if ct != opc::CT_DOCUMENT_MAIN {
            return Err(DocxError::Value(format!(
                "file '{path}' is not a Word file, content type is '{ct}'"
            )));
        }
        Ok(Self { package, document })
    }

    fn document_root(&self) -> Result<&Element, DocxError> {
        match &self.package.parts[self.document].content {
            Content::Xml(e) if e.is(W_NS, "document") => Ok(e),
            _ => Err(DocxError::Internal(
                "AttributeError: object has no attribute 'body'".into(),
            )),
        }
    }

    /// `DocxTemplate.render(context, jinja_env)`.
    pub fn render(
        &mut self,
        env: &Environment,
        vars: &[(String, Data)],
        now_utc: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), DocxError> {
        // Body.
        let root = self.document_root()?;
        let Some(body_index) = root
            .children
            .iter()
            .position(|n| matches!(n, Node::Element(e) if e.is(W_NS, "body")))
        else {
            return Err(DocxError::Internal(
                "TypeError: Type 'NoneType' cannot be serialized.".into(),
            ));
        };
        let Some(Node::Element(body)) = root.children.get(body_index) else {
            return Err(DocxError::Internal("body".into()));
        };
        let mut xml_src = xml::to_string_in(body, &[root.ns_defs.as_slice()]);
        // `tostring` writes the body's tail too.
        let mut k = body_index + 1;
        while let Some(Node::Text(t)) = root.children.get(k) {
            xml::escape_text(t, &mut xml_src);
            k += 1;
        }
        let patched = patch_xml(&xml_src)?;
        let rendered = render_xml_part(&patched, env, vars)?;
        let mut tree = fix_tables(&rendered)?;
        let mut ids = 1000u64;
        fix_docpr_ids(&mut tree, &mut ids);
        self.map_tree(tree, body_index)?;

        // Headers, then footers.
        for uri in [opc::RT_HEADER, opc::RT_FOOTER] {
            let targets: Vec<usize> = self.package.parts[self.document]
                .rels
                .iter()
                .filter(|r| r.reltype == uri)
                .filter_map(|r| match r.target {
                    Target::Part(i) => Some(i),
                    Target::External(_) => None,
                })
                .collect();
            for i in targets {
                let blob = self.package.parts[i].blob();
                if blob.is_empty() {
                    continue;
                }
                let parsed = parse_strict(&blob)?;
                let src = xml::to_string(&parsed);
                let patched = patch_xml(&src)?;
                let rendered = render_xml_part(&patched, env, vars)?;
                let new = parse_strict(rendered.as_bytes())?;
                self.package.parts[i].content = Content::Xml(new);
            }
        }
        self.render_properties(env, vars, now_utc)?;
        self.render_footnotes(env, vars)?;
        Ok(())
    }

    /// `map_tree`: `root.replace(body, tree)`, the declarations the document
    /// already makes stripped from the new body.
    fn map_tree(&mut self, mut tree: Element, body_index: usize) -> Result<(), DocxError> {
        let Content::Xml(root) = &mut self.package.parts[self.document].content else {
            return Err(DocxError::Internal("document".into()));
        };
        let in_scope: Vec<(Option<String>, String)> = root.ns_defs.clone();
        tree.ns_defs
            .retain(|(p, u)| !in_scope.iter().any(|(q, v)| q == p && v == u));
        // The old body's tail goes with it.
        let mut end = body_index + 1;
        while matches!(root.children.get(end), Some(Node::Text(_))) {
            end += 1;
        }
        root.children.splice(body_index..end, [Node::Element(tree)]);
        Ok(())
    }

    fn core_properties_part(
        &mut self,
        now_utc: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize, DocxError> {
        if let Some(i) = Package::part_with_reltype(&self.package.rels, opc::RT_CORE_PROPERTIES)? {
            return Ok(i);
        }
        // `CorePropertiesPart.default(package)`.
        let mut root = Element::new(Some("cp"), "coreProperties", Some(CP_NS));
        root.ns_defs = vec![
            (Some("cp".into()), CP_NS.into()),
            (Some("dc".into()), DC_NS.into()),
            (Some("dcterms".into()), DCTERMS_NS.into()),
        ];
        let mut title = Element::new(Some("dc"), "title", Some(DC_NS));
        title.set_text("Word Document");
        let mut by = Element::new(Some("cp"), "lastModifiedBy", Some(CP_NS));
        by.set_text("python-docx");
        let mut rev = Element::new(Some("cp"), "revision", Some(CP_NS));
        rev.set_text("1");
        let mut modified = Element::new(Some("dcterms"), "modified", Some(DCTERMS_NS));
        modified.set_text(&now_utc.format("%Y-%m-%dT%H:%M:%SZ").to_string());
        root.ns_defs.push((Some("xsi".into()), XSI_NS.into()));
        modified.set(Some(XSI_NS), Some("xsi"), "type", "dcterms:W3CDTF");
        for e in [title, by, rev, modified] {
            root.children.push(Node::Element(e));
        }
        self.package.parts.push(opc::Part {
            partname: "/docProps/core.xml".into(),
            content_type: opc::CT_CORE_PROPERTIES.into(),
            content: Content::Xml(root),
            rels: Vec::new(),
        });
        let i = self.package.parts.len() - 1;
        self.package.relate(opc::RT_CORE_PROPERTIES, i);
        Ok(i)
    }

    /// `render_properties`: author, comments, identifier, language, subject
    /// and title rendered as templates.
    fn render_properties(
        &mut self,
        env: &Environment,
        vars: &[(String, Data)],
        now_utc: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), DocxError> {
        let i = self.core_properties_part(now_utc)?;
        for (local, _prop) in [
            ("creator", "author"),
            ("description", "comments"),
            ("identifier", "identifier"),
            ("language", "language"),
            ("subject", "subject"),
            ("title", "title"),
        ] {
            let Content::Xml(root) = &mut self.package.parts[i].content else {
                return Err(DocxError::Internal(
                    "AttributeError: 'Part' object has no attribute 'core_properties'".into(),
                ));
            };
            if !root.is(CP_NS, "coreProperties") {
                return Err(DocxError::Internal(
                    "AttributeError: no attribute 'author_text'".into(),
                ));
            }
            let initial = root
                .find(DC_NS, local)
                .and_then(|e| e.text())
                .unwrap_or("")
                .to_string();
            let rendered = env.render_string(&initial, vars).map_err(jinja_error)?;
            if rendered.chars().count() > 255 {
                return Err(DocxError::Value(format!(
                    "exceeded 255 char limit for property, got:\n\n'{rendered}'"
                )));
            }
            if !rendered.chars().all(|c| xml::is_xml_char(c) && c != '\0') {
                return Err(DocxError::Value(
                    "All strings must be XML compatible: Unicode or ASCII, no NULL bytes or control characters"
                        .into(),
                ));
            }
            let el = match root.find_mut(DC_NS, local) {
                Some(e) => e,
                None => {
                    root.children
                        .push(Node::Element(Element::new(Some("dc"), local, Some(DC_NS))));
                    match root.children.last_mut() {
                        Some(Node::Element(e)) => e,
                        _ => return Err(DocxError::Internal("core properties".into())),
                    }
                }
            };
            el.set_text(&rendered);
        }
        Ok(())
    }

    /// `render_footnotes`: every footnotes part rendered once per section.
    fn render_footnotes(
        &mut self,
        env: &Environment,
        vars: &[(String, Data)],
    ) -> Result<(), DocxError> {
        let sections = {
            let root = self.document_root()?;
            let mut n = 0;
            if let Some(body) = root.find(W_NS, "body") {
                for c in body.elements() {
                    if c.is(W_NS, "p") {
                        for ppr in c.findall(W_NS, "pPr") {
                            n += ppr.findall(W_NS, "sectPr").len();
                        }
                    } else if c.is(W_NS, "sectPr") {
                        n += 1;
                    }
                }
            }
            n
        };
        for _ in 0..sections {
            for i in self.package.iter_parts() {
                if self.package.parts[i].content_type != opc::CT_FOOTNOTES {
                    continue;
                }
                let blob = self.package.parts[i].blob();
                let text = opc::decode_utf8(&blob)?;
                let patched = patch_xml(&text)?;
                let rendered = render_xml_part(&patched, env, vars)?;
                self.package.parts[i].content = Content::Raw(rendered.into_bytes());
            }
        }
        Ok(())
    }
}

fn parse_strict(blob: &[u8]) -> Result<Element, DocxError> {
    xml::parse_bytes(
        blob,
        ParseOptions {
            remove_blank_text: true,
        },
    )
    .map_err(|e| DocxError::Internal(format!("XMLSyntaxError: {}", e.0)))
}
