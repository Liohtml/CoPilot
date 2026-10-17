//! The Office 365 edits of the Wazuh manager's `ossec.conf`
//! (`app/integrations/office365/services/provision.py`): the first tenant's
//! `<office365>` block appended to the root (`office365_template_with_api_type`)
//! or a further tenant's `<api_auth>` block inserted before the block's
//! `<subscriptions>` (`add_api_auth_to_office365_block`), both through
//! `xml.dom.minidom`'s pretty printer, and what `update_wazuh_configuration`
//! then reads back and PUTs.
//!
//! Python hands the configuration from step to step through a file next to
//! its module (`wazuh_config.xml`); the Rust service keeps it in memory, with
//! what the round trip did to it: the text is read back with universal
//! newlines (`\r\n` and `\r` become `\n`). It writes no file (§4).

use copilot_integrations::etree::{self, Element, ParseError};
use copilot_upstream::py::PyExc;

/// The four auth keys (`ProvisionOffice365AuthKeys`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keys {
    /// `TENANT_ID`.
    pub tenant_id: String,
    /// `CLIENT_ID`.
    pub client_id: String,
    /// `CLIENT_SECRET`.
    pub client_secret: String,
    /// `API_TYPE`.
    pub api_type: String,
}

/// The fixed answer of `add_api_auth_to_office365_block`'s `except`.
pub const MULTIPLE_BLOCKS: &str = "Error found in ossec.conf. Multiple <ossec_config> blocks \
     found. Remove all additional <ossec_config> blocks and try again.";

const SUBSCRIPTIONS: [&str; 5] = [
    "Audit.SharePoint",
    "Audit.Exchange",
    "DLP.ALL",
    "Audit.General",
    "Audit.AzureActiveDirectory",
];

fn api_auth(keys: &Keys) -> Element {
    let mut e = Element::new("api_auth", Vec::new());
    e.sub("tenant_id", Some(&keys.tenant_id));
    e.sub("client_id", Some(&keys.client_id));
    e.sub("client_secret", Some(&keys.client_secret));
    e.sub("api_type", Some(&keys.api_type));
    e
}

/// `xml.dom.minidom._write_data`.
fn write_data(out: &mut String, data: &str) {
    for c in data.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '>' => out.push_str("&gt;"),
            other => out.push(other),
        }
    }
}

/// One DOM child: an element or a text node.
enum Node<'a> {
    Element(&'a Element),
    Text(&'a str),
}

/// The DOM children minidom builds for an ElementTree element: its text,
/// then each child followed by its tail (adjacent character data is one text
/// node, as the expat builder buffers it).
fn dom_children(e: &Element) -> Vec<Node<'_>> {
    let mut out = Vec::new();
    if let Some(t) = e.text.as_deref().filter(|t| !t.is_empty()) {
        out.push(Node::Text(t));
    }
    for c in &e.children {
        out.push(Node::Element(c));
        if let Some(t) = c.tail.as_deref().filter(|t| !t.is_empty()) {
            out.push(Node::Text(t));
        }
    }
    out
}

/// `Element.writexml(writer, indent, addindent, newl)` (comments do not
/// occur in what is pretty-printed here).
fn writexml(out: &mut String, e: &Element, indent: &str, addindent: &str, newl: &str) {
    out.push_str(indent);
    out.push('<');
    out.push_str(&e.tag);
    for (k, v) in &e.attrib {
        out.push(' ');
        out.push_str(k);
        out.push_str("=\"");
        write_data(out, v);
        out.push('"');
    }
    let children = dom_children(e);
    if children.is_empty() {
        out.push_str("/>");
        out.push_str(newl);
        return;
    }
    out.push('>');
    if let [Node::Text(t)] = children.as_slice() {
        write_data(out, t);
    } else {
        out.push_str(newl);
        let inner = format!("{indent}{addindent}");
        for node in &children {
            match node {
                Node::Element(c) => writexml(out, c, &inner, addindent, newl),
                Node::Text(t) => write_data(out, &format!("{inner}{t}{newl}")),
            }
        }
        out.push_str(indent);
    }
    out.push_str("</");
    out.push_str(&e.tag);
    out.push('>');
    out.push_str(newl);
}

/// `minidom.parseString(text).toprettyxml(indent=indent)`: `Err` is the
/// `ExpatError` (expat's message and position).
pub fn toprettyxml(text: &str, indent: &str) -> Result<String, ParseError> {
    let root = etree::fromstring(text)?;
    let mut out = String::from("<?xml version=\"1.0\" ?>\n");
    writexml(&mut out, &root, "", indent, "\n");
    Ok(out)
}

/// Universal newlines, as `open(path, "r")` reads the file back.
pub fn universal_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// `office365_template_with_api_type`: the configuration with the first
/// tenant's `<office365>` block appended; a parse failure is the exception
/// itself (`ParseError` / `ExpatError`, `str(e)` its text).
pub fn office365_template(raw: &str, keys: &Keys) -> Result<String, PyExc> {
    let parse_error = |e: ParseError| PyExc::Other("ParseError", e.to_string());
    let mut root = etree::fromstring(raw).map_err(parse_error)?;
    let mut office365 = Element::new("office365", Vec::new());
    office365.sub("enabled", Some("yes"));
    office365.sub("interval", Some("1m"));
    office365.sub("curl_max_size", Some("5M"));
    office365.sub("only_future_events", Some("yes"));
    office365.children.push(api_auth(keys));
    let mut subscriptions = Element::new("subscriptions", Vec::new());
    for s in SUBSCRIPTIONS {
        subscriptions.sub("subscription", Some(s));
    }
    office365.children.push(subscriptions);
    let office365_str = etree::tostring_ascii(&office365);
    let pretty = toprettyxml(&office365_str, "  ")
        .map_err(|e| PyExc::Other("ExpatError", e.to_string()))?
        .replace("<?xml version=\"1.0\" ?>", "");
    let pretty = etree::py_strip(&pretty).to_string();
    root.children.push(office365);
    root.tail = None;
    let xml_str = etree::tostring_ascii(&root);
    Ok(xml_str.replace(&office365_str, &pretty))
}

/// `add_api_auth_to_office365_block`: the configuration with this tenant's
/// `<api_auth>` block inserted, `None` when the root holds no `<office365>`
/// block (the file keeps the manager's text); any failure inside is the
/// fixed 500.
pub fn add_api_auth(raw: &str, keys: &Keys) -> Result<Option<String>, PyExc> {
    let fixed = || PyExc::http(500, MULTIPLE_BLOCKS);
    let mut root = etree::fromstring(raw).map_err(|_| fixed())?;
    let Some(block_at) = root.children.iter().position(|c| c.tag == "office365") else {
        return Ok(None);
    };
    let block = &mut root.children[block_at];
    let Some(index) = block.children.iter().position(|c| c.tag == "subscriptions") else {
        // `list(block).index(None)`: a ValueError.
        return Err(fixed());
    };
    let pretty =
        toprettyxml(&etree::tostring_ascii(&api_auth(keys)), "   ").map_err(|_| fixed())?;
    let element = etree::fromstring(&pretty).map_err(|_| fixed())?;
    block.children.insert(index, element);
    Ok(Some(etree::tostring(&root)))
}

/// What `update_wazuh_configuration` reads from `wazuh_config.xml` after the
/// edit: `raw` the manager's configuration.
pub fn configuration_to_push(raw: &str, keys: &Keys) -> Result<String, PyExc> {
    let file = if raw.contains("office365") {
        add_api_auth(raw, keys)?.unwrap_or_else(|| raw.to_string())
    } else {
        office365_template(raw, keys)?
    };
    Ok(universal_newlines(&file))
}

/// The configuration of the second attempt: the `<api_type>` tag removed
/// (as its plain text, `str.replace`).
pub fn without_api_type(config: &str, keys: &Keys) -> String {
    config.replace(&format!("<api_type>{}</api_type>", keys.api_type), "")
}
