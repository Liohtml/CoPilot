//! `app/integrations/aws/services/wazuh_config.py`: one instance's
//! `<bucket>` entries in the manager's `aws-s3` wodle, reconciled as a pure
//! string-in, string-out edit.
//!
//! The raw file is parsed under a synthetic `<copilot_ossec_wrapper>` root,
//! comments kept (several `<ossec_config>` blocks are fine), and written back
//! block by block. An instance's buckets are recognised by bucket name +
//! account; every change is checked by [`verify_only_instance_changed`]
//! before anything is pushed.

use crate::etree::{self, Element, ParseError, py_strip};

use super::services::ServiceConfig;

/// `WODLE_NAME`.
pub const WODLE_NAME: &str = "aws-s3";

/// `WODLE_DEFAULTS`: applied only when CoPilot creates the wodle.
pub const WODLE_DEFAULTS: &[(&str, &str)] = &[
    ("disabled", "no"),
    ("interval", "10m"),
    ("run_on_start", "yes"),
    ("skip_on_error", "yes"),
];

const WRAPPER_TAG: &str = "copilot_ossec_wrapper";

/// `WAZUH_MASK`.
pub const WAZUH_MASK: &str = "*****";

/// Why an edit was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// `AwsWazuhConfigError(message)` (a `ValueError`).
    Refused(String),
    /// An `ET.ParseError` raised outside `parse_ossec_config` (re-reading a
    /// serialisation in `ET.canonicalize`): its text.
    Parse(String),
}

impl From<ParseError> for ConfigError {
    fn from(e: ParseError) -> Self {
        ConfigError::Parse(e.to_string())
    }
}

/// The identifying auth keys and the bucket contents of one instance (what
/// `build_bucket` reads of `ProvisionAwsAuthKeys`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketKeys {
    /// `BUCKET_NAME`.
    pub bucket_name: String,
    /// `ACCESS_KEY_ID`.
    pub access_key_id: String,
    /// `SECRET_ACCESS_KEY`.
    pub secret_access_key: String,
    /// `AWS_ACCOUNT_ID`.
    pub account_id: String,
    /// `AWS_ACCOUNT_ALIAS`.
    pub account_alias: Option<String>,
    /// `AWS_ORGANIZATION_ID`.
    pub organization_id: Option<String>,
}

/// `ReconcileResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileResult {
    /// `config`: the new configuration (the raw one when unchanged).
    pub config: String,
    /// `changed`.
    pub changed: bool,
    /// `added`: the services whose bucket was added.
    pub added: Vec<String>,
    /// `updated`.
    pub updated: Vec<String>,
    /// `removed`.
    pub removed: Vec<String>,
    /// `wodle_created`.
    pub wodle_created: bool,
    /// `wodle_removed`.
    pub wodle_removed: bool,
    /// `wodle_disabled`.
    pub wodle_disabled: bool,
    /// `previous`: the instance's buckets as they were (a rollback's state).
    pub previous: Vec<Element>,
}

/// `str.isspace()`-based `\s` of Python's `re` for `str` patterns.
fn re_space(c: char) -> bool {
    etree::py_is_space(c)
}

/// `_XML_DECLARATION.sub("", raw, count=1)`: `^\s*<\?xml[^>]*\?>` removed.
fn strip_declaration(raw: &str) -> &str {
    let rest = raw.trim_start_matches(re_space);
    let Some(after) = rest.strip_prefix("<?xml") else {
        return raw;
    };
    // `[^>]*\?>`: the first `>` must close it, preceded by `?`.
    match after.find('>') {
        Some(i) if i >= 1 && after.as_bytes()[i - 1] == b'?' => &after[i + 1..],
        _ => raw,
    }
}

/// `_DTD.search(raw)` (`<!(DOCTYPE|ENTITY)`, `re.IGNORECASE`: `sre` also
/// takes `İ`/`ı` for `i` and `K` for `k`, the only non-ASCII case partners of
/// these letters).
fn has_dtd(raw: &str) -> bool {
    let folded: String = raw
        .chars()
        .map(|c| match c {
            '\u{130}' | '\u{131}' => 'i',
            '\u{212a}' => 'k',
            other => other.to_ascii_lowercase(),
        })
        .collect();
    folded.contains("<!doctype") || folded.contains("<!entity")
}

/// `parse_ossec_config(raw)`: the wrapper root, comments kept.
pub fn parse_ossec_config(raw: &str) -> Result<Element, ConfigError> {
    if raw.is_empty() || py_strip(raw).is_empty() {
        return Err(ConfigError::Refused(
            "The Wazuh manager returned an empty ossec.conf; refusing to edit it.".into(),
        ));
    }
    if has_dtd(raw) {
        return Err(ConfigError::Refused(
            "The Wazuh manager's ossec.conf contains a DOCTYPE or ENTITY declaration; refusing \
             to edit it."
                .into(),
        ));
    }
    let body = strip_declaration(raw);
    let wrapped = format!("<{WRAPPER_TAG}>{body}</{WRAPPER_TAG}>");
    let wrapper = etree::fromstring_with_comments(&wrapped).map_err(|e| {
        ConfigError::Refused(format!(
            "Could not parse the Wazuh manager's ossec.conf: {e}"
        ))
    })?;
    if wrapper.find("ossec_config").is_none() {
        return Err(ConfigError::Refused(
            "The Wazuh manager's configuration has no <ossec_config> block.".into(),
        ));
    }
    Ok(wrapper)
}

/// `_refuse_masked(wrapper)`.
fn refuse_masked(wrapper: &Element) -> Result<(), ConfigError> {
    for element in wrapper.iter() {
        if element.is_comment() {
            continue;
        }
        if py_strip(element.text.as_deref().unwrap_or_default()) == WAZUH_MASK {
            let tag = &element.tag;
            return Err(ConfigError::Refused(format!(
                "The Wazuh manager returned ossec.conf with a masked value \
                 (<{tag}>{WAZUH_MASK}</{tag}>). Writing it back would destroy that value, so \
                 nothing was changed. Check the Wazuh API user's manager:update_config \
                 permission."
            )));
        }
    }
    Ok(())
}

/// `serialize_ossec_config(wrapper)`: every top-level node back to back.
pub fn serialize_ossec_config(wrapper: &Element) -> String {
    let mut out = wrapper.text.clone().unwrap_or_default();
    for child in &wrapper.children {
        out.push_str(&etree::tostring_unicode(child));
    }
    out
}

/// `_canonical(element)`: C14N 2.0 with `strip_text=True`, no comments.
fn canonical(e: &Element) -> Result<String, ConfigError> {
    Ok(etree::canonical(e, false)?)
}

/// `build_bucket(config, keys, only_logs_after)`.
pub fn build_bucket(config: &ServiceConfig, keys: &BucketKeys, only_logs_after: &str) -> Element {
    let definition = config.definition;
    let mut bucket = Element::new(
        "bucket",
        vec![("type".to_string(), definition.wazuh_type.to_string())],
    );
    bucket.sub("name", Some(&keys.bucket_name));
    if let Some(p) = config.prefix.as_deref().filter(|p| !p.is_empty()) {
        bucket.sub("path", Some(p));
    }
    bucket.sub("access_key", Some(&keys.access_key_id));
    bucket.sub("secret_key", Some(&keys.secret_access_key));
    bucket.sub("aws_account_id", Some(&keys.account_id));
    if let Some(alias) = keys.account_alias.as_deref().filter(|a| !a.is_empty()) {
        bucket.sub("aws_account_alias", Some(alias));
    }
    if let Some(org) = keys.organization_id.as_deref().filter(|o| !o.is_empty()) {
        if definition.supports_organization_id {
            bucket.sub("aws_organization_id", Some(org));
        }
    }
    bucket.sub("only_logs_after", Some(only_logs_after));
    bucket
}

/// `desired_buckets(keys)` for the parsed services and the resolved start
/// date (`keys.only_logs_after()`).
pub fn desired_buckets(
    services: &[ServiceConfig],
    keys: &BucketKeys,
    only_logs_after: &str,
) -> Vec<Element> {
    services
        .iter()
        .map(|config| build_bucket(config, keys, only_logs_after))
        .collect()
}

/// `_text(element, tag)`.
fn text_of(element: &Element, tag: &str) -> String {
    py_strip(element.findtext(tag).unwrap_or_default()).to_string()
}

/// `_bucket_type(bucket)`.
fn bucket_type(bucket: &Element) -> String {
    py_strip(bucket.get("type").unwrap_or_default()).to_lowercase()
}

/// `_bucket_path(bucket)`.
fn bucket_path(bucket: &Element) -> String {
    text_of(bucket, "path").trim_matches('/').to_string()
}

/// `_bucket_accounts(bucket)`, sorted (a set).
fn bucket_accounts(bucket: &Element) -> Vec<String> {
    let mut out: Vec<String> = text_of(bucket, "aws_account_id")
        .split(',')
        .map(|a| py_strip(a).to_string())
        .filter(|a| !a.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// `_describe(bucket)`.
fn describe(bucket: &Element) -> String {
    let path = bucket_path(bucket);
    let accounts = bucket_accounts(bucket).join(",");
    let accounts = if accounts.is_empty() {
        "any account".to_string()
    } else {
        accounts
    };
    let kind = bucket_type(bucket);
    format!(
        "{} bucket {}{} ({accounts})",
        if kind.is_empty() { "untyped" } else { &kind },
        text_of(bucket, "name"),
        if path.is_empty() {
            String::new()
        } else {
            format!("/{path}")
        }
    )
}

/// `is_owned_bucket(bucket, bucket_name, account_id)`.
pub fn is_owned_bucket(bucket: &Element, bucket_name: &str, account_id: &str) -> bool {
    text_of(bucket, "name") == bucket_name && bucket_accounts(bucket) == [account_id.to_string()]
}

/// `_overlaps(existing, desired, account_id)`.
fn overlaps(existing: &Element, desired: &Element, account_id: &str) -> bool {
    if bucket_type(existing) != bucket_type(desired) {
        return false;
    }
    if text_of(existing, "name") != text_of(desired, "name")
        || bucket_path(existing) != bucket_path(desired)
    {
        return false;
    }
    let accounts = bucket_accounts(existing);
    accounts.is_empty() || accounts.iter().any(|a| a == account_id)
}

/// `_aws_wodles(wrapper)`: `(block index, wodle index)` pairs in document
/// order.
fn aws_wodles(wrapper: &Element) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for b in wrapper.findall("ossec_config") {
        for w in wrapper.children[b].findall("wodle") {
            if py_strip(
                wrapper.children[b].children[w]
                    .get("name")
                    .unwrap_or_default(),
            ) == WODLE_NAME
            {
                out.push((b, w));
            }
        }
    }
    out
}

/// `_new_wodle(block)`: appended to `block`; its index there.
fn new_wodle(block: &mut Element) -> usize {
    let mut wodle = Element::new("wodle", vec![("name".to_string(), WODLE_NAME.to_string())]);
    for (tag, value) in WODLE_DEFAULTS {
        wodle.sub(tag, Some(value));
    }
    block.children.push(wodle);
    let len = block.children.len();
    if len > 1 {
        let previous = &mut block.children[len - 2];
        if py_strip(previous.tail.as_deref().unwrap_or_default()).is_empty() {
            previous.tail = Some("\n\n  ".into());
        }
    }
    block.children[len - 1].tail = Some("\n".into());
    len - 1
}

/// `_is_empty_wodle(wodle)`.
fn is_empty_wodle(wodle: &Element) -> bool {
    !wodle
        .children
        .iter()
        .any(|c| matches!(c.tag.as_str(), "bucket" | "service" | "subscriber"))
}

/// `_remove_keeping_layout(parent, child)` for the child at `index`.
fn remove_keeping_layout(parent: &mut Element, index: usize) {
    let tail = parent.children[index].tail.clone();
    if index > 0 {
        parent.children[index - 1].tail = tail;
    } else {
        parent.text = tail;
    }
    parent.children.remove(index);
}

/// What happens to one wodle's buckets: by original index, replaced or
/// removed; and the buckets appended at its end.
#[derive(Default)]
struct WodleEdit {
    replace: Vec<(usize, Element)>,
    remove: Vec<usize>,
    append: Vec<Element>,
}

/// A bucket's place: `((block, wodle), index in the wodle)`.
type BucketAt = ((usize, usize), usize);

/// `reconcile_aws_buckets(raw_config, desired, bucket_name, account_id,
/// adopt_existing, keep_only_logs_after)`.
pub fn reconcile_aws_buckets(
    raw_config: &str,
    desired: &[Element],
    bucket_name: &str,
    account_id: &str,
    adopt_existing: bool,
    keep_only_logs_after: bool,
) -> Result<ReconcileResult, ConfigError> {
    let mut wrapper = parse_ossec_config(raw_config)?;
    refuse_masked(&wrapper)?;
    let before = canonical(&wrapper)?;
    let mut result = ReconcileResult {
        config: raw_config.to_string(),
        changed: false,
        added: Vec::new(),
        updated: Vec::new(),
        removed: Vec::new(),
        wodle_created: false,
        wodle_removed: false,
        wodle_disabled: false,
        previous: Vec::new(),
    };

    let wodles = aws_wodles(&wrapper);
    // (wodle, bucket index within it), in document order.
    let mut existing: Vec<BucketAt> = Vec::new();
    for &(b, w) in &wodles {
        for i in wrapper.children[b].children[w].findall("bucket") {
            existing.push(((b, w), i));
        }
    }
    let bucket_at = |wrapper: &Element, ((b, w), i): BucketAt| -> Element {
        wrapper.children[b].children[w].children[i].clone()
    };
    let owned: Vec<BucketAt> = existing
        .iter()
        .copied()
        .filter(|&loc| {
            adopt_existing && is_owned_bucket(&bucket_at(&wrapper, loc), bucket_name, account_id)
        })
        .collect();
    result.previous = owned.iter().map(|&loc| bucket_at(&wrapper, loc)).collect();
    let mut conflicts: Vec<String> = existing
        .iter()
        .filter(|loc| !owned.contains(loc))
        .map(|&loc| bucket_at(&wrapper, loc))
        .filter(|bucket| {
            desired
                .iter()
                .any(|want| overlaps(bucket, want, account_id))
        })
        .map(|bucket| describe(&bucket))
        .collect();
    conflicts.sort();
    conflicts.dedup();
    if !conflicts.is_empty() {
        return Err(ConfigError::Refused(format!(
            "The Wazuh manager already collects these logs: {}. Remove the existing <bucket> \
             entries from the aws-s3 wodle in ossec.conf (or delete the CoPilot integration that \
             owns them) and deploy again.",
            conflicts.join("; ")
        )));
    }

    // `owned_by_type`, in the order a type is first seen.
    let mut owned_by_type: Vec<(String, Vec<BucketAt>)> = Vec::new();
    for &loc in &owned {
        let kind = bucket_type(&bucket_at(&wrapper, loc));
        match owned_by_type.iter_mut().find(|(k, _)| *k == kind) {
            Some((_, v)) => v.push(loc),
            None => owned_by_type.push((kind, vec![loc])),
        }
    }

    let target: Option<(usize, usize)> = if !desired.is_empty() && wodles.is_empty() {
        let b = wrapper.findall("ossec_config")[0];
        let w = new_wodle(&mut wrapper.children[b]);
        result.wodle_created = true;
        Some((b, w))
    } else {
        wodles.first().copied()
    };

    let mut edits: Vec<((usize, usize), WodleEdit)> = Vec::new();
    fn edit_of(
        edits: &mut Vec<((usize, usize), WodleEdit)>,
        wodle: (usize, usize),
    ) -> &mut WodleEdit {
        if let Some(i) = edits.iter().position(|(w, _)| *w == wodle) {
            return &mut edits[i].1;
        }
        edits.push((wodle, WodleEdit::default()));
        let last = edits.len() - 1;
        &mut edits[last].1
    }
    let mut leftovers: Vec<BucketAt> = Vec::new();
    for want in desired {
        let service = bucket_type(want);
        let matches = match owned_by_type.iter().position(|(k, _)| *k == service) {
            Some(i) => owned_by_type.remove(i).1,
            None => Vec::new(),
        };
        let Some(&(wodle, index)) = matches.first() else {
            if let Some(t) = target {
                edit_of(&mut edits, t).append.push(want.clone());
            }
            result.added.push(service);
            continue;
        };
        leftovers.extend(matches[1..].iter().copied());
        let current = bucket_at(&wrapper, (wodle, index));
        let mut replacement = want.clone();
        let current_start = text_of(&current, "only_logs_after");
        if keep_only_logs_after && !current_start.is_empty() {
            if let Some(c) = replacement
                .children
                .iter_mut()
                .find(|c| c.tag == "only_logs_after")
            {
                c.text = Some(current_start);
            }
        }
        if canonical(&current)? != canonical(&replacement)? {
            edit_of(&mut edits, wodle)
                .replace
                .push((index, replacement));
            result.updated.push(service);
        }
    }
    for (_, matches) in owned_by_type {
        leftovers.extend(matches);
    }
    for &(wodle, index) in &leftovers {
        let kind = bucket_type(&bucket_at(&wrapper, (wodle, index)));
        edit_of(&mut edits, wodle).remove.push(index);
        result.removed.push(kind);
    }

    // Apply each wodle's edit: replacements in place, removals dropped,
    // additions at the end.
    let touched: Vec<(usize, usize)> = edits.iter().map(|(w, _)| *w).collect();
    for ((b, w), edit) in edits {
        let wodle = &mut wrapper.children[b].children[w];
        let old = std::mem::take(&mut wodle.children);
        for (i, child) in old.into_iter().enumerate() {
            if edit.remove.contains(&i) {
                continue;
            }
            match edit.replace.iter().find(|(r, _)| *r == i) {
                Some((_, replacement)) => wodle.children.push(replacement.clone()),
                None => wodle.children.push(child),
            }
        }
        wodle.children.extend(edit.append);
    }

    if let Some((b, w)) = target {
        result.wodle_disabled =
            text_of(&wrapper.children[b].children[w], "disabled").to_lowercase() == "yes";
    }
    // The touched wodles, emptied ones removed (from the end, so the indices
    // before them stay valid), the others indented.
    for (b, w) in aws_wodles(&wrapper).into_iter().rev() {
        if !touched.contains(&(b, w)) {
            continue;
        }
        if is_empty_wodle(&wrapper.children[b].children[w]) {
            remove_keeping_layout(&mut wrapper.children[b], w);
            result.wodle_removed = true;
        } else {
            etree::indent(&mut wrapper.children[b].children[w], "  ", 1);
        }
    }

    if canonical(&wrapper)? != before {
        result.config = serialize_ossec_config(&wrapper);
        result.changed = true;
        verify_only_instance_changed(raw_config, &result.config, bucket_name, account_id)?;
    }
    Ok(result)
}

/// `_without_instance(raw, bucket_name, account_id)`: canonical, comments
/// kept.
fn without_instance(raw: &str, bucket_name: &str, account_id: &str) -> Result<String, ConfigError> {
    let mut wrapper = parse_ossec_config(raw)?;
    for (b, w) in aws_wodles(&wrapper).into_iter().rev() {
        let wodle = &mut wrapper.children[b].children[w];
        wodle
            .children
            .retain(|c| !(c.tag == "bucket" && is_owned_bucket(c, bucket_name, account_id)));
        if is_empty_wodle(wodle) {
            wrapper.children[b].children.remove(w);
        }
    }
    Ok(etree::canonical(&wrapper, true)?)
}

/// `verify_only_instance_changed(before, after, bucket_name, account_id)`.
pub fn verify_only_instance_changed(
    before: &str,
    after: &str,
    bucket_name: &str,
    account_id: &str,
) -> Result<(), ConfigError> {
    if without_instance(before, bucket_name, account_id)?
        != without_instance(after, bucket_name, account_id)?
    {
        return Err(ConfigError::Refused(
            "Refusing to update ossec.conf: the new configuration would change more than this \
             AWS instance's <bucket> entries. Nothing was written to the Wazuh manager."
                .into(),
        ));
    }
    Ok(())
}
