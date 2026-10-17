//! `RulesCache`'s data and the pure functions of `services/copilot_searches.py`
//! over it: the detections folders (`category_*`), `_detect_platform`, the
//! filters, the statistics, `rule_to_summary` / `rule_to_detail`.
//!
//! A rule is the `dict` `yaml.safe_load` returned, with the fetch's own keys
//! set on it (`_file_path`, `_raw_yaml`, `_category`, `_platform`,
//! `_has_graylog`, `_provenance`, `_owner_customer_code`).

use std::collections::HashMap;
use std::sync::Arc;

use chrono::NaiveDateTime;
use copilot_jinja::unicode;
use copilot_upstream::py::{PyExc, PyResult};
use copilot_yaml::Value;

use crate::py::{self, get, hash_key, lower, s};
use crate::pyd;
use crate::schema;

/// The canonical repository.
pub const GITHUB_REPO: &str = "socfortress/CoPilot-Search-Queries";
/// Its branch.
pub const GITHUB_BRANCH: &str = "main";
/// `CACHE_TTL_MINUTES`.
pub const CACHE_TTL_MINUTES: i64 = 30;
/// `DETECTIONS_ROOT`.
pub const DETECTIONS_ROOT: &str = "detections";
/// `UNCATEGORIZED`.
pub const UNCATEGORIZED: &str = "uncategorized";

const LABEL_OVERRIDES: &[(&str, &str)] = &[
    ("entra_id", "Entra ID"),
    ("sharepoint_onedrive", "SharePoint / OneDrive"),
    (
        "eid_12_13_14_registry_events",
        "EID 12/13/14 Registry Events",
    ),
    ("eid_17_18_pipe_events", "EID 17/18 Pipe Events"),
    ("eid_19_20_21_wmi_events", "EID 19/20/21 WMI Events"),
    ("eid_23_26_file_delete", "EID 23/26 File Delete"),
    ("eid_27_28_29_file_block", "EID 27/28/29 File Block"),
    ("eid_22_dns_query", "EID 22 DNS Query"),
    (
        "eid_15_file_create_stream_hash",
        "EID 15 File Create Stream Hash",
    ),
    (
        "eid_16_sysmon_config_changed",
        "EID 16 Sysmon Config Changed",
    ),
    ("web", "Web"),
];

/// `CATEGORY_GROUP_ORDER`.
pub const GROUP_ORDER: &[&str] = &[
    "Sysmon",
    "Windows Event Logs",
    "PowerShell",
    "Linux",
    "Microsoft 365",
    "Other",
];

/// `_humanize_category(folder)`.
pub fn humanize_category(folder: &str) -> String {
    let replaced = folder.replace('-', "_");
    let words: Vec<String> = replaced
        .split('_')
        .filter(|w| !w.is_empty())
        .map(|w| {
            if unicode::lower(w) == "eid" {
                "EID".to_string()
            } else if unicode::str_islower(w) || unicode::str_isupper(w) {
                unicode::capitalize(w)
            } else {
                w.to_string()
            }
        })
        .collect();
    words.join(" ")
}

/// `category_label(folder)`.
pub fn category_label(folder: &str) -> String {
    let key = unicode::lower(folder);
    LABEL_OVERRIDES
        .iter()
        .find(|(k, _)| *k == key)
        .map_or_else(|| humanize_category(folder), |(_, v)| (*v).to_string())
}

/// `category_group(folder)`.
pub fn category_group(folder: &str) -> &'static str {
    let key = unicode::lower(folder);
    let key = key.as_str();
    if matches!(
        key,
        "eid_4103_module_logging" | "eid_4104_script_block_logging"
    ) {
        "PowerShell"
    } else if key.starts_with("eid_") {
        "Sysmon"
    } else if matches!(
        key,
        "application_eventlog"
            | "security_eventlog"
            | "system_eventlog"
            | "defender_operational"
            | "task_scheduler_operational"
    ) {
        "Windows Event Logs"
    } else if matches!(key, "auditd" | "syslog" | "tetragon") {
        "Linux"
    } else if matches!(key, "entra_id" | "exchange" | "sharepoint_onedrive") {
        "Microsoft 365"
    } else {
        "Other"
    }
}

/// `category_from_path(file_path)`.
pub fn category_from_path(file_path: &str) -> String {
    let parts: Vec<&str> = file_path.trim_matches('/').split('/').collect();
    if parts.len() >= 3 && parts[0] == DETECTIONS_ROOT {
        parts[1].to_string()
    } else {
        UNCATEGORIZED.to_string()
    }
}

/// `RulesCache._detect_platform(file_path, rule_data)`.
pub fn detect_platform(file_path: &str, rule: &Value) -> PyResult<&'static str> {
    let p = format!("/{}/", unicode::lower(file_path).trim_matches('/'));
    let has = |f: &str| p.contains(&format!("/{f}/"));
    if p.contains("eid_4103") || p.contains("eid_4104") || p.contains("/powershell/") {
        return Ok("powershell");
    }
    if p.contains("/microsoft_365/")
        || p.contains("/office365/")
        || p.contains("/office 365/")
        || [
            "entra_id",
            "exchange",
            "sharepoint_onedrive",
            "threat_intelligence",
        ]
        .iter()
        .any(|f| has(f))
    {
        return Ok("office365");
    }
    if p.contains("/linux/") || ["auditd", "syslog", "tetragon"].iter().any(|f| has(f)) {
        return Ok("linux");
    }
    if p.contains("/web/") {
        return Ok("web");
    }
    let win = [
        "application_eventlog",
        "defender_operational",
        "security_eventlog",
        "system_eventlog",
        "task_scheduler_operational",
        "multi_event",
    ];
    if p.contains("/windows/")
        || p.contains("/sysmon/")
        || p.contains("/eid_")
        || win.iter().any(|f| has(f))
    {
        return Ok("windows");
    }
    let tags = get(rule, "tags", py::dict(vec![]))?;
    let asset_type = lower(&get(&tags, "asset_type", s(""))?)?;
    if asset_type.contains("linux") {
        return Ok("linux");
    }
    if asset_type.contains("windows") {
        return Ok("windows");
    }
    let name_lower = lower(&get(rule, "name", s(""))?)?;
    if name_lower.contains("powershell") {
        return Ok("powershell");
    }
    if name_lower.contains("cve") {
        return Ok("cve");
    }
    if name_lower.contains("linux") {
        return Ok("linux");
    }
    if name_lower.contains("windows") {
        return Ok("windows");
    }
    let products = get(&tags, "product", py::list(vec![]))?;
    let product_text = if products.is_list() {
        unicode::lower(&py::join(" ", &py::iterate(&products)?)?)
    } else {
        unicode::lower(&products.py_str())
    };
    let security_domain = unicode::lower(&get(&tags, "security_domain", s(""))?.py_str());
    if ["office 365", "office365", "o365", "m365"]
        .iter()
        .any(|k| product_text.contains(k))
    {
        return Ok("office365");
    }
    if asset_type.contains("cloud") || security_domain == "cloud" {
        return Ok("cloud");
    }
    Ok("unknown")
}

/// `RulesCache._normalize_name(name)`.
pub fn normalize_name(name: &Value) -> PyResult<String> {
    let lowered = lower(name)?;
    Ok(py::py_strip(&lowered).replace([' ', '-'], "_"))
}

/// A rule's metadata value (`rule.get(key, default)`; a rule is a dict).
pub fn meta<'a>(rule: &'a Value, key: &str) -> Option<&'a Value> {
    rule.get(key)
}

fn meta_str(rule: &Value, key: &str, default: &str) -> Value {
    rule.get(key).cloned().unwrap_or_else(|| s(default))
}

/// One source's outcome in the last refresh (`_source_status`).
#[derive(Debug, Clone)]
pub struct SourceStatus {
    /// `repo`.
    pub repo: String,
    /// `provenance`.
    pub provenance: &'static str,
    /// `owner`.
    pub owner: Option<String>,
    /// `fetched_at` (`isoformat() + "Z"`).
    pub fetched_at: String,
    /// `ok`.
    pub ok: bool,
    /// `rules_loaded`.
    pub rules_loaded: usize,
    /// `error`.
    pub error: Option<String>,
}

/// The cached rules: `_rules` (by id, in insertion order) and
/// `_rules_by_name`.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Value>,
    index: HashMap<String, usize>,
    by_name: Vec<(String, Value)>,
    name_index: HashMap<String, usize>,
    /// `_last_refresh` (naive UTC).
    pub last_refresh: Option<NaiveDateTime>,
    /// `_source_status`.
    pub source_status: Vec<SourceStatus>,
}

impl RuleSet {
    /// `len(_rules)`.
    pub fn rules_count(&self) -> usize {
        self.rules.len()
    }

    /// `_rules.values()`.
    pub fn all(&self) -> &[Value] {
        &self.rules
    }

    /// `get_rule_by_id(rule_id)` for a `str` id.
    pub fn by_id(&self, rule_id: &str) -> Option<&Value> {
        self.index
            .get(&format!("s{rule_id}"))
            .map(|i| &self.rules[*i])
    }

    fn by_key(&self, key: &Value) -> Option<&Value> {
        let k = hash_key(key).ok()?;
        self.index.get(&k).map(|i| &self.rules[*i])
    }

    /// `get_rule_by_name(name)`: the exact normalised name, else the first
    /// stored name that contains it or that it contains.
    pub fn by_name(&self, name: &str) -> PyResult<Option<&Value>> {
        let normalized = normalize_name(&s(name))?;
        if let Some(i) = self.name_index.get(&normalized) {
            return Ok(self.by_key(&self.by_name[*i].1));
        }
        for (stored, id) in &self.by_name {
            if stored.contains(&normalized) || normalized.contains(stored.as_str()) {
                return Ok(self.by_key(id));
            }
        }
        Ok(None)
    }

    /// The body of `refresh()` after the fetch: the cache is emptied, then
    /// filled rule by rule. An exception leaves it as far as it got (the rule
    /// that failed included when the name broke), as Python's does; the
    /// caller keeps `last_refresh` then.
    pub fn fill(&mut self, rules: Vec<Value>) -> PyResult<()> {
        self.rules.clear();
        self.index.clear();
        self.by_name.clear();
        self.name_index.clear();
        for rule in rules {
            let rule_id = get(&rule, "id", s(""))?;
            let rule_name = get(&rule, "name", s(""))?;
            if rule_id.truthy() {
                let key = hash_key(&rule_id)?;
                if self.index.contains_key(&key) {
                    tracing::warn!(
                        "Duplicate rule id {} from {} repo (owner={}) — keeping the first, \
                         skipping this one.",
                        rule_id.py_str(),
                        meta_str(&rule, "_provenance", "None").py_str(),
                        meta_str(&rule, "_owner_customer_code", "None").py_str()
                    );
                    continue;
                }
            }
            let key = hash_key(&rule_id)?;
            match self.index.get(&key) {
                Some(i) => self.rules[*i] = rule.clone(),
                None => {
                    self.index.insert(key, self.rules.len());
                    self.rules.push(rule.clone());
                }
            }
            let normalized = normalize_name(&rule_name)?;
            match self.name_index.get(&normalized) {
                Some(i) => self.by_name[*i].1 = rule_id,
                None => {
                    self.name_index
                        .insert(normalized.clone(), self.by_name.len());
                    self.by_name.push((normalized, rule_id));
                }
            }
        }
        Ok(())
    }

    /// `get_categories()`.
    pub fn categories(&self) -> Vec<Category> {
        let mut counts: Vec<(String, i64)> = Vec::new();
        for rule in &self.rules {
            let folder = folder_of(rule);
            match counts.iter_mut().find(|(f, _)| *f == folder) {
                Some(c) => c.1 += 1,
                None => counts.push((folder, 1)),
            }
        }
        let mut out: Vec<Category> = counts
            .into_iter()
            .map(|(folder, count)| Category {
                label: category_label(&folder),
                group: category_group(&folder),
                value: folder,
                count,
            })
            .collect();
        out.sort_by(|a, b| {
            let ga = GROUP_ORDER.iter().position(|g| *g == a.group).unwrap_or(0);
            let gb = GROUP_ORDER.iter().position(|g| *g == b.group).unwrap_or(0);
            ga.cmp(&gb)
                .then(b.count.cmp(&a.count))
                .then_with(|| unicode::lower(&a.label).cmp(&unicode::lower(&b.label)))
        });
        out
    }
}

/// `rule.get("_category") or UNCATEGORIZED`.
pub fn folder_of(rule: &Value) -> String {
    match rule.get("_category") {
        Some(v) if v.truthy() => v.py_str(),
        _ => UNCATEGORIZED.to_string(),
    }
}

/// One `get_categories()` entry.
#[derive(Debug, Clone)]
pub struct Category {
    /// `value`.
    pub value: String,
    /// `label`.
    pub label: String,
    /// `group`.
    pub group: &'static str,
    /// `count`.
    pub count: i64,
}

impl Category {
    /// As `RuleCategory`.
    pub fn to_value(&self) -> Value {
        py::dict(vec![
            ("value", s(self.value.clone())),
            ("label", s(self.label.clone())),
            ("group", s(self.group)),
            ("count", py::int(self.count)),
        ])
    }
}

/// The filters of `filter_rules`.
#[derive(Debug, Clone, Default)]
pub struct Filters {
    /// `platform` (`None` for `all`).
    pub platform: Option<String>,
    /// `category`.
    pub category: Option<String>,
    /// `status`.
    pub status: Option<String>,
    /// `severity`.
    pub severity: Option<String>,
    /// `mitre_id`.
    pub mitre_id: Option<String>,
    /// `search`.
    pub search: Option<String>,
    /// `has_graylog`.
    pub has_graylog: Option<bool>,
    /// `provenance`.
    pub provenance: Option<String>,
}

fn has_graylog(rule: &Value) -> bool {
    matches!(rule.get("_has_graylog"), Some(Value::Bool(true)))
}

/// `filter_rules(...)`.
pub fn filter_rules(rules: &[Value], f: &Filters) -> PyResult<Vec<Value>> {
    let category_key = f.category.as_deref().map(unicode::lower);
    let mut out = Vec::new();
    for rule in rules {
        if let Some(platform) = &f.platform {
            let rule_platform = meta_str(rule, "_platform", "unknown");
            if rule_platform.as_str() != Some(platform.as_str()) {
                continue;
            }
        }
        if let Some(key) = &category_key {
            if unicode::lower(&folder_of(rule)) != *key {
                continue;
            }
        }
        if let Some(status) = &f.status {
            if lower(&get(rule, "status", s(""))?)? != *status {
                continue;
            }
        }
        if let Some(severity) = &f.severity {
            let response = get(rule, "response", py::dict(vec![]))?;
            if lower(&get(&response, "severity", s(""))?)? != *severity {
                continue;
            }
        }
        if let Some(mitre_id) = &f.mitre_id {
            let tags = get(rule, "tags", py::dict(vec![]))?;
            let ids = get(&tags, "mitre_attack_id", py::list(vec![]))?;
            let needle = unicode::upper(mitre_id);
            let mut hit = false;
            for m in py::iterate(&ids)? {
                if py::upper(&m)?.contains(&needle) {
                    hit = true;
                    break;
                }
            }
            if !hit {
                continue;
            }
        }
        if let Some(search) = &f.search {
            let needle = unicode::lower(search);
            let name = lower(&get(rule, "name", s(""))?)?;
            let description = lower(&get(rule, "description", s(""))?)?;
            if !name.contains(&needle) && !description.contains(&needle) {
                continue;
            }
        }
        if let Some(want) = f.has_graylog {
            if has_graylog(rule) != want {
                continue;
            }
        }
        if let Some(provenance) = &f.provenance {
            let p = match rule.get("_provenance") {
                Some(v) if v.truthy() => v.clone(),
                _ => s("catalog"),
            };
            if p.as_str() != Some(provenance.as_str()) {
                continue;
            }
        }
        out.push(rule.clone());
    }
    Ok(out)
}

/// `filtered.sort(key=lambda r: r.get("name", "").lower())`.
pub fn sort_by_name(rules: &mut Vec<Value>) -> PyResult<()> {
    let mut keyed: Vec<(String, Value)> = Vec::with_capacity(rules.len());
    for rule in rules.drain(..) {
        let k = lower(&get(&rule, "name", s(""))?)?;
        keyed.push((k, rule));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    rules.extend(keyed.into_iter().map(|(_, r)| r));
    Ok(())
}

/// A counter keyed by Python values (`dict[key] = dict.get(key, 0) + 1`).
#[derive(Debug, Default)]
struct Counter {
    items: Vec<(Value, i64)>,
    index: HashMap<String, usize>,
}

impl Counter {
    fn add(&mut self, key: Value) -> PyResult<()> {
        let k = hash_key(&key)?;
        match self.index.get(&k) {
            Some(i) => self.items[*i].1 += 1,
            None => {
                self.index.insert(k, self.items.len());
                self.items.push((key, 1));
            }
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        Value::Dict(Arc::new(
            self.items
                .iter()
                .map(|(k, n)| (k.clone(), py::int(*n)))
                .collect(),
        ))
    }
}

/// `get_stats()` → `get_rules_stats()`'s dict, validated as
/// `RuleStatsResponse`.
pub fn stats(set: &RuleSet) -> PyResult<Value> {
    let mut platform = Counter::default();
    let mut category = Counter::default();
    let mut status = Counter::default();
    let mut severity = Counter::default();
    let mut tactic = Counter::default();
    let mut with_graylog = 0i64;
    for rule in &set.rules {
        platform.add(meta_str(rule, "_platform", "unknown"))?;
        category.add(s(folder_of(rule)))?;
        status.add(get(rule, "status", s("unknown"))?)?;
        let response = get(rule, "response", py::dict(vec![]))?;
        severity.add(get(&response, "severity", s("unknown"))?)?;
        let tags = get(rule, "tags", py::dict(vec![]))?;
        let ids = get(&tags, "mitre_attack_id", py::list(vec![]))?;
        for mitre_id in py::iterate(&ids)? {
            let base = if py::contains_key(&mitre_id, ".")? {
                match &mitre_id {
                    Value::Str(t) => s(t.split('.').next().unwrap_or_default()),
                    other => return Err(py::no_attr(other, "split")),
                }
            } else {
                mitre_id.clone()
            };
            tactic.add(base)?;
        }
        if has_graylog(rule) {
            with_graylog += 1;
        }
    }
    let dict = py::dict(vec![
        ("total_rules", py::int(set.rules.len() as i64)),
        ("by_platform", platform.to_value()),
        ("by_category", category.to_value()),
        ("by_status", status.to_value()),
        ("by_severity", severity.to_value()),
        ("by_mitre_tactic", tactic.to_value()),
        ("rules_with_graylog", py::int(with_graylog)),
        (
            "last_refreshed",
            set.last_refresh.map_or(Value::None, naive_datetime),
        ),
        ("cache_ttl_minutes", py::int(CACHE_TTL_MINUTES)),
    ]);
    pyd::build(&schema::RULE_STATS_RESPONSE, &dict)
}

/// A naive `datetime` value.
pub fn naive_datetime(t: NaiveDateTime) -> Value {
    use chrono::{Datelike, Timelike};
    Value::DateTime(copilot_yaml::DateTime {
        date: copilot_yaml::Date {
            year: t.year(),
            month: t.month() as u8,
            day: t.day() as u8,
        },
        hour: t.hour() as u8,
        minute: t.minute() as u8,
        second: t.second() as u8,
        microsecond: t.nanosecond() / 1000 % 1_000_000,
        offset: None,
    })
}

/// `rule_to_summary(rule)`.
pub fn to_summary(rule: &Value) -> PyResult<Value> {
    let tags = get(rule, "tags", py::dict(vec![]))?;
    let response = get(rule, "response", py::dict(vec![]))?;
    let aggregation = get(rule, "aggregation", Value::None)?;
    let has_aggregation =
        aggregation.is_dict() && get(&aggregation, "enabled", Value::None)?.truthy();
    let folder = folder_of(rule);
    let input = py::dict(vec![
        ("id", get(rule, "id", s(""))?),
        ("name", get(rule, "name", s(""))?),
        ("version", get(rule, "version", py::int(1))?),
        ("status", get(rule, "status", s("unknown"))?),
        ("type", get(rule, "type", s("unknown"))?),
        ("description", get(rule, "description", s(""))?),
        ("author", get(rule, "author", s(""))?),
        ("date", get(rule, "date", s(""))?),
        ("severity", get(&response, "severity", s("medium"))?),
        ("risk_score", get(&response, "risk_score", py::int(0))?),
        ("platform", meta_str(rule, "_platform", "unknown")),
        ("category", s(folder.clone())),
        ("category_label", s(category_label(&folder))),
        (
            "mitre_attack_id",
            get(&tags, "mitre_attack_id", py::list(vec![]))?,
        ),
        (
            "analytic_story",
            get(&tags, "analytic_story", py::list(vec![]))?,
        ),
        ("cve", get(&tags, "cve", py::list(vec![]))?),
        ("file_path", meta_str(rule, "_file_path", "")),
        (
            "has_graylog_query",
            rule.get("_has_graylog")
                .cloned()
                .unwrap_or(Value::Bool(false)),
        ),
        ("has_aggregation", Value::Bool(has_aggregation)),
        ("provenance", meta_str(rule, "_provenance", "catalog")),
        (
            "owner_customer_code",
            rule.get("_owner_customer_code")
                .cloned()
                .unwrap_or(Value::None),
        ),
    ]);
    pyd::build(&schema::RULE_SUMMARY, &input)
}

/// `rule_to_detail(rule)`.
pub fn to_detail(rule: &Value) -> PyResult<Value> {
    let mut params = Vec::new();
    for (name, data) in py::items(&get(rule, "parameters", py::dict(vec![]))?)? {
        let input = py::dict(vec![
            ("name", name),
            ("description", get(&data, "description", s(""))?),
            ("type", get(&data, "type", s("string"))?),
            ("required", get(&data, "required", Value::Bool(false))?),
            ("default", get(&data, "default", Value::None)?),
            ("example", get(&data, "example", Value::None)?),
        ]);
        params.push(pyd::build(&schema::PARAMETER_SCHEMA, &input)?);
    }
    let mut graylog = Value::None;
    let graylog_data = get(rule, "graylog", Value::None)?;
    if graylog_data.truthy()
        && graylog_data.is_dict()
        && get(&graylog_data, "query", Value::None)?.truthy()
    {
        let input = py::dict(vec![("query", get(&graylog_data, "query", s(""))?)]);
        graylog = pyd::build(&schema::GRAYLOG_QUERY, &input)?;
    }
    let mut aggregation = Value::None;
    let aggregation_data = get(rule, "aggregation", Value::None)?;
    if aggregation_data.is_dict() {
        kwargs_check(&aggregation_data)?;
        if let Ok(dump) = schema::aggregation(&aggregation_data) {
            aggregation = dump;
        }
    }
    let input = py::dict(vec![
        ("id", get(rule, "id", s(""))?),
        ("name", get(rule, "name", s(""))?),
        ("version", get(rule, "version", py::int(1))?),
        ("schema_version", get(rule, "schema_version", s("1.0"))?),
        ("status", get(rule, "status", s("unknown"))?),
        ("type", get(rule, "type", s("unknown"))?),
        ("description", get(rule, "description", s(""))?),
        ("author", get(rule, "author", s(""))?),
        ("date", get(rule, "date", s(""))?),
        ("data_source", get(rule, "data_source", py::list(vec![]))?),
        ("search", get(rule, "search", py::dict(vec![]))?),
        ("parameters", py::list(params)),
        ("how_to_implement", get(rule, "how_to_implement", s(""))?),
        (
            "known_false_positives",
            get(rule, "known_false_positives", s(""))?,
        ),
        ("references", get(rule, "references", py::list(vec![]))?),
        ("response", get(rule, "response", py::dict(vec![]))?),
        ("tags", get(rule, "tags", py::dict(vec![]))?),
        ("file_path", meta_str(rule, "_file_path", "")),
        ("raw_yaml", meta_str(rule, "_raw_yaml", "")),
        ("graylog", graylog),
        ("aggregation", aggregation),
        ("provenance", meta_str(rule, "_provenance", "catalog")),
        (
            "owner_customer_code",
            rule.get("_owner_customer_code")
                .cloned()
                .unwrap_or(Value::None),
        ),
    ]);
    pyd::build(&schema::RULE_DETAIL, &input)
}

/// `Model(**d)` needs `str` keys: `TypeError: keywords must be strings`.
pub fn kwargs_check(d: &Value) -> PyResult<()> {
    match d {
        Value::Dict(items) if items.iter().any(|(k, _)| k.as_str().is_none()) => {
            Err(PyExc::TypeError("keywords must be strings".into()))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn labels_and_groups() {
        assert_eq!(
            category_label("eid_01_process_creation"),
            "EID 01 Process Creation"
        );
        assert_eq!(category_label("Entra_id"), "Entra ID");
        assert_eq!(category_label("multi-event"), "Multi Event");
        assert_eq!(category_label("auditD"), "auditD");
        assert_eq!(
            category_group("eid_4104_script_block_logging"),
            "PowerShell"
        );
        assert_eq!(category_group("Exchange"), "Microsoft 365");
        assert_eq!(category_from_path("detections/auditd/x.yaml"), "auditd");
        assert_eq!(category_from_path("other/x.yaml"), UNCATEGORIZED);
    }
}
