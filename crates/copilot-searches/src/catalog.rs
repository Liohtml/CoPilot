//! `services/detection_catalog.py`: the catalog's views over the cached
//! rules, the MITRE matrix, the Wazuh ruleset and its firing counts —
//! aggregated afresh on every request, as in Python.

use std::collections::HashMap;

use chrono::NaiveDateTime;
use copilot_jinja::unicode;
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_yaml::Value;
use num_bigint_dig::BigInt;

use crate::mitre::{Matrix, TacticNames, sorted_values};
use crate::py::{self, get, hash_key, s};
use crate::rules;

/// One rule's firing counts (`{"hits_30d", "hits_7d", "last_seen"}`).
#[derive(Debug, Clone)]
pub struct Firing {
    /// `hits_30d`.
    pub hits_30d: BigInt,
    /// `hits_7d`.
    pub hits_7d: BigInt,
    /// `last_seen`.
    pub last_seen: Value,
}

impl Firing {
    /// The zero entry `get()` falls back to.
    pub fn zero() -> Self {
        Self {
            hits_30d: BigInt::from(0),
            hits_7d: BigInt::from(0),
            last_seen: Value::None,
        }
    }
}

/// The firing counts by rule id.
pub type FiringStats = HashMap<BigInt, Firing>;

/// What the caches hold at the time of a request.
#[derive(Debug, Clone, Copy)]
pub struct Snapshot<'a> {
    /// `rules_cache.get_all_rules()`.
    pub rules: &'a [Value],
    /// `rules_cache.last_refresh`.
    pub rules_last_refresh: Option<NaiveDateTime>,
    /// `mitre_matrix`.
    pub matrix: &'a Matrix,
    /// `wazuh_rules_cache.get_all_rules()`.
    pub wazuh: &'a [Value],
    /// `wazuh_rules_cache`'s state.
    pub wazuh_last_refresh: Option<NaiveDateTime>,
    /// `wazuh_rules_cache.unavailable_reason`.
    pub wazuh_unavailable: Option<&'a str>,
    /// `wazuh_firing_stats_cache._stats`.
    pub firing: &'a FiringStats,
    /// `wazuh_firing_stats_cache.last_refresh`.
    pub firing_last_refresh: Option<NaiveDateTime>,
    /// `wazuh_firing_stats_cache.unavailable_reason`.
    pub firing_unavailable: Option<&'a str>,
}

fn dt(t: Option<NaiveDateTime>) -> Value {
    t.map_or(Value::None, rules::naive_datetime)
}

fn opt_text(t: Option<&str>) -> Value {
    t.map_or(Value::None, s)
}

/// `_ensure_list_of_str(value)`.
pub fn ensure_list_of_str(v: &Value) -> Vec<String> {
    match v {
        Value::Str(t) => vec![t.clone()],
        Value::List(items) => items
            .iter()
            .filter_map(|i| i.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

fn tags_get(rule: &Value, key: &str) -> PyResult<Value> {
    get(&get(rule, "tags", py::dict(vec![]))?, key, Value::None)
}

fn rule_mitre_ids(rule: &Value) -> PyResult<Vec<String>> {
    Ok(ensure_list_of_str(&tags_get(rule, "mitre_attack_id")?))
}

fn rule_stories(rule: &Value) -> PyResult<Vec<String>> {
    Ok(ensure_list_of_str(&tags_get(rule, "analytic_story")?))
}

fn rule_products(rule: &Value) -> PyResult<Vec<String>> {
    Ok(ensure_list_of_str(&tags_get(rule, "product")?))
}

fn rule_data_sources(rule: &Value) -> Vec<String> {
    ensure_list_of_str(rule.get("data_source").unwrap_or(&Value::None))
}

fn rule_max_date(rule: &Value) -> Option<String> {
    rule.get("date").and_then(Value::as_str).map(str::to_string)
}

fn newest(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (None, b) => b,
        (a, None) => a,
        (Some(a), Some(b)) => Some(if a >= b { a } else { b }),
    }
}

/// `_resolve_tactics_for_mitre_ids(ids)`.
pub fn resolve_tactics(matrix: &Matrix, ids: &[Value]) -> PyResult<Vec<Value>> {
    let names: TacticNames = matrix.tactics_by_short()?;
    let mut out: Vec<Value> = Vec::new();
    let mut seen: HashMap<String, ()> = HashMap::new();
    for raw in ids {
        let Value::Str(raw) = raw else {
            continue;
        };
        let base = py::py_upper(py::py_strip(raw.split('.').next().unwrap_or_default()));
        let Some(meta) = matrix.technique(&base) else {
            continue;
        };
        for short in py::iterate(&get(meta, "tactic_short_names", py::list(vec![]))?)? {
            if let Some(display) = names.get(&short)? {
                if display.truthy() {
                    let key = hash_key(display)?;
                    if seen.insert(key, ()).is_none() {
                        out.push(display.clone());
                    }
                }
            }
        }
    }
    Ok(out)
}

fn str_values(items: &[String]) -> Vec<Value> {
    items.iter().map(|t| s(t.clone())).collect()
}

fn sorted_set(items: Vec<String>) -> Vec<String> {
    let mut v = items;
    v.sort();
    v.dedup();
    v
}

/// `list_stories()`.
pub fn list_stories(snap: &Snapshot<'_>) -> PyResult<Vec<Value>> {
    struct Row {
        data_sources: Vec<String>,
        products: Vec<String>,
        tactics: Vec<Value>,
        count: i64,
        date: Option<String>,
    }
    let mut agg: Vec<(String, Row)> = Vec::new();
    for rule in snap.rules {
        let stories = rule_stories(rule)?;
        if stories.is_empty() {
            continue;
        }
        let tactics = resolve_tactics(snap.matrix, &str_values(&rule_mitre_ids(rule)?))?;
        let date = rule_max_date(rule);
        for story in stories {
            let idx = match agg.iter().position(|(n, _)| *n == story) {
                Some(i) => i,
                None => {
                    agg.push((
                        story.clone(),
                        Row {
                            data_sources: Vec::new(),
                            products: Vec::new(),
                            tactics: Vec::new(),
                            count: 0,
                            date: None,
                        },
                    ));
                    agg.len() - 1
                }
            };
            let sources = rule_data_sources(rule);
            let products = rule_products(rule)?;
            let row = &mut agg[idx].1;
            row.data_sources.extend(sources);
            row.products.extend(products);
            for t in &tactics {
                if !row.tactics.iter().any(|x| x.py_eq(t)) {
                    row.tactics.push(t.clone());
                }
            }
            row.count += 1;
            row.date = newest(row.date.take(), date.clone());
        }
    }
    let mut keyed: Vec<(String, (String, Row))> = agg
        .into_iter()
        .map(|(n, r)| (unicode::lower(&n), (n, r)))
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(keyed
        .into_iter()
        .map(|(_, (name, row))| {
            py::dict(vec![
                ("name", s(name)),
                ("data_sources", py::str_list(sorted_set(row.data_sources))),
                ("tactics", py::list(row.tactics)),
                ("products", py::str_list(sorted_set(row.products))),
                ("date", py::opt_str(row.date)),
                ("detection_count", py::int(row.count)),
            ])
        })
        .collect())
}

/// `_story_slug(name)`.
pub fn story_slug(name: &str) -> String {
    let lowered = unicode::lower(py::py_strip(name));
    let mut safe: String = lowered
        .chars()
        .map(|c| {
            if unicode::is_alnum(c) || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    while safe.contains("__") {
        safe = safe.replace("__", "_");
    }
    let trimmed = safe.trim_matches('_');
    if trimmed.is_empty() {
        "story".into()
    } else {
        trimmed.to_string()
    }
}

/// `get_story_detail(story_name)`: the dict, or `None`.
pub fn story_detail(snap: &Snapshot<'_>, story_name: &str) -> PyResult<Option<Value>> {
    let target = py::py_strip(story_name).to_string();
    let mut members = Vec::new();
    for rule in snap.rules {
        if rule_stories(rule)?.contains(&target) {
            members.push(rule);
        }
    }
    if members.is_empty() {
        return Ok(None);
    }
    let mut detections: Vec<Value> = Vec::new();
    let mut data_sources: Vec<String> = Vec::new();
    let mut references: Vec<String> = Vec::new();
    let mut products: Vec<String> = Vec::new();
    let mut authors: Vec<String> = Vec::new();
    let mut tactic_names: Vec<Value> = Vec::new();
    let mut type_counts: Vec<(Value, i64)> = Vec::new();
    let mut type_keys: HashMap<String, usize> = HashMap::new();
    let mut latest_date: Option<String> = None;
    let mut latest_version: Option<Value> = None;
    for rule in members {
        let mitre_ids = rule_mitre_ids(rule)?;
        let rule_tactics = resolve_tactics(snap.matrix, &str_values(&mitre_ids))?;
        for t in &rule_tactics {
            if !tactic_names.iter().any(|x| x.py_eq(t)) {
                tactic_names.push(t.clone());
            }
        }
        let rule_type = match rule.get("type") {
            Some(t) if t.truthy() => t.clone(),
            _ => s("Unknown"),
        };
        let key = hash_key(&rule_type)?;
        match type_keys.get(&key) {
            Some(i) => type_counts[*i].1 += 1,
            None => {
                type_keys.insert(key, type_counts.len());
                type_counts.push((rule_type.clone(), 1));
            }
        }
        let id_default = rule.get("id").cloned().unwrap_or_else(|| s("(unnamed)"));
        let response = get(rule, "response", py::dict(vec![]))?;
        detections.push(py::dict(vec![
            ("id", rule.get("id").cloned().unwrap_or(Value::None)),
            ("name", rule.get("name").cloned().unwrap_or(id_default)),
            ("type", rule_type),
            ("severity", get(&response, "severity", Value::None)?),
            ("mitre_attack_id", py::str_list(mitre_ids)),
            ("tactics", py::list(rule_tactics)),
            (
                "description",
                rule.get("description").cloned().unwrap_or(Value::None),
            ),
        ]));
        data_sources.extend(rule_data_sources(rule));
        products.extend(rule_products(rule)?);
        if let Some(Value::Str(author)) = rule.get("author") {
            let a = py::py_strip(author);
            if !a.is_empty() {
                authors.push(a.to_string());
            }
        }
        for r in ensure_list_of_str(rule.get("references").unwrap_or(&Value::None)) {
            if !references.contains(&r) {
                references.push(r);
            }
        }
        latest_date = newest(latest_date, rule_max_date(rule));
        if let Some(v @ (Value::Int(_) | Value::Bool(_))) = rule.get("version") {
            let replace = match &latest_version {
                None => true,
                Some(cur) => py::lt(cur, v)?,
            };
            if replace {
                latest_version = Some(v.clone());
            }
        }
    }
    let mut keyed = Vec::with_capacity(detections.len());
    for d in detections {
        let name = d.get("name").cloned().unwrap_or(Value::None);
        let k = if name.truthy() {
            py::lower(&name)?
        } else {
            String::new()
        };
        keyed.push((k, d));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    let detections: Vec<Value> = keyed.into_iter().map(|(_, d)| d).collect();
    let sorted_types = {
        let kinds = sorted_values(type_counts.iter().map(|(k, _)| k.clone()).collect())?;
        let mut out = Vec::new();
        for k in kinds {
            if let Some((_, n)) = type_counts.iter().find(|(t, _)| t.py_eq(&k)) {
                out.push(format!("{n} {}", k.py_str()));
            }
        }
        out.join(", ")
    };
    let tactic_text: Vec<String> = tactic_names.iter().map(Value::py_str).collect();
    let mut why = format!(
        "This story contains {} detection(s) covering {} MITRE ATT&CK tactic(s)",
        detections.len(),
        tactic_names.len()
    );
    if !tactic_names.is_empty() {
        why.push_str(&format!(" ({})", py::join(", ", &tactic_names)?));
    }
    why.push_str(". ");
    if !sorted_types.is_empty() {
        why.push_str(&format!("Detection types: {sorted_types}. "));
    }
    why.push_str(
        "Story metadata is auto-generated from member detections; curated narratives can be \
         added later via a story-metadata file in the rule repo.",
    );
    let _ = tactic_text;
    let description = format!(
        "{} detection(s) tagged with the analytic story '{target}'. Member detections span {} \
         MITRE tactic(s).",
        detections.len(),
        tactic_names.len()
    );
    let count = detections.len() as i64;
    Ok(Some(py::dict(vec![
        ("name", s(target.clone())),
        ("id", s(story_slug(&target))),
        ("description", s(description)),
        ("why_it_matters", s(why)),
        ("detections", py::list(detections)),
        ("data_sources", py::str_list(sorted_set(data_sources))),
        ("tactics", py::list(tactic_names)),
        ("products", py::str_list(sorted_set(products))),
        ("authors", py::str_list(sorted_set(authors))),
        ("references", py::str_list(references)),
        ("date", py::opt_str(latest_date)),
        ("version", latest_version.unwrap_or(Value::None)),
        ("detection_count", py::int(count)),
    ])))
}

/// `get_catalog_stats()`.
pub fn catalog_stats(snap: &Snapshot<'_>) -> PyResult<Value> {
    let mut stories = Vec::new();
    let mut products = Vec::new();
    let mut sources = Vec::new();
    let mut tactics: HashMap<String, ()> = HashMap::new();
    let mut count = 0i64;
    for rule in snap.rules {
        count += 1;
        stories.extend(rule_stories(rule)?);
        products.extend(rule_products(rule)?);
        sources.extend(rule_data_sources(rule));
        for t in resolve_tactics(snap.matrix, &str_values(&rule_mitre_ids(rule)?))? {
            tactics.insert(hash_key(&t)?, ());
        }
    }
    Ok(py::dict(vec![
        ("detection_count", py::int(count)),
        ("story_count", py::int(sorted_set(stories).len() as i64)),
        ("product_count", py::int(sorted_set(products).len() as i64)),
        (
            "data_source_count",
            py::int(sorted_set(sources).len() as i64),
        ),
        ("tactic_count", py::int(tactics.len() as i64)),
        ("last_refresh", dt(snap.rules_last_refresh)),
        ("wazuh_rule_count", py::int(snap.wazuh.len() as i64)),
        ("wazuh_last_refresh", dt(snap.wazuh_last_refresh)),
        (
            "wazuh_available",
            Value::Bool(snap.wazuh_unavailable.is_none()),
        ),
        ("wazuh_unavailable_reason", opt_text(snap.wazuh_unavailable)),
    ]))
}

/// `COMPLIANCE_FRAMEWORKS`: key, label (the field is the key).
pub const FRAMEWORKS: &[(&str, &str)] = &[
    ("pci_dss", "PCI DSS"),
    ("gdpr", "GDPR"),
    ("hipaa", "HIPAA"),
    ("nist_800_53", "NIST 800-53"),
    ("tsc", "TSC"),
    ("gpg13", "GPG13"),
];

/// The `ValueError` of an unknown framework.
fn unknown_framework(framework: &str) -> PyExc {
    let keys: Vec<String> = FRAMEWORKS.iter().map(|(k, _)| format!("'{k}'")).collect();
    PyExc::ValueError(format!(
        "Unknown compliance framework {}. Valid: [{}]",
        copilot_yaml::str_repr(framework),
        keys.join(", ")
    ))
}

fn compliance_values(rule: &Value, field: &str) -> Vec<String> {
    match rule.get(field) {
        Some(Value::List(items)) => items
            .iter()
            .filter_map(|v| match v {
                Value::Str(t) if !py::py_strip(t).is_empty() => Some(t.clone()),
                _ => None,
            })
            .collect(),
        Some(Value::Str(t)) => t
            .split(',')
            .map(|p| py::py_strip(p).to_string())
            .filter(|p| !p.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

fn rule_int_id(rule: &Value) -> Option<BigInt> {
    match rule.get("id") {
        Some(Value::Int(i)) => Some(i.clone()),
        Some(Value::Bool(b)) => Some(BigInt::from(u8::from(*b))),
        _ => None,
    }
}

fn firing_of(snap: &Snapshot<'_>, id: Option<&BigInt>) -> Firing {
    id.and_then(|i| snap.firing.get(i))
        .cloned()
        .unwrap_or_else(Firing::zero)
}

/// `list_compliance_pivot(framework)`.
pub fn compliance_pivot(snap: &Snapshot<'_>, framework: &str) -> PyResult<Value> {
    let Some((_, label)) = FRAMEWORKS.iter().find(|(k, _)| *k == framework) else {
        return Err(unknown_framework(framework));
    };
    struct Bucket {
        ids: Vec<BigInt>,
        h30: BigInt,
        h7: BigInt,
    }
    let mut grouped: Vec<(String, Bucket)> = Vec::new();
    let mut with = 0i64;
    for rule in snap.wazuh {
        let controls = compliance_values(rule, framework);
        if controls.is_empty() {
            continue;
        }
        with += 1;
        let rid = rule_int_id(rule);
        let stats = firing_of(snap, rid.as_ref());
        for control in controls {
            let idx = match grouped.iter().position(|(c, _)| *c == control) {
                Some(i) => i,
                None => {
                    grouped.push((
                        control.clone(),
                        Bucket {
                            ids: Vec::new(),
                            h30: BigInt::from(0),
                            h7: BigInt::from(0),
                        },
                    ));
                    grouped.len() - 1
                }
            };
            let b = &mut grouped[idx].1;
            if let Some(r) = &rid {
                b.ids.push(r.clone());
            }
            b.h30 += &stats.hits_30d;
            b.h7 += &stats.hits_7d;
        }
    }
    let mut groups: Vec<(String, Bucket)> = grouped;
    groups.sort_by(|a, b| b.1.h30.cmp(&a.1.h30).then_with(|| a.0.cmp(&b.0)));
    let n = groups.len() as i64;
    let rows: Vec<Value> = groups
        .into_iter()
        .map(|(control, mut b)| {
            b.ids.sort();
            group_row(&control, &b.ids, &b.h30, &b.h7)
        })
        .collect();
    Ok(py::dict(vec![
        ("framework", s(framework)),
        ("framework_label", s(*label)),
        ("groups", py::list(rows)),
        ("control_count", py::int(n)),
        ("rules_with_compliance", py::int(with)),
        ("total_rules", py::int(snap.wazuh.len() as i64)),
        (
            "firing_stats_available",
            Value::Bool(snap.firing_unavailable.is_none()),
        ),
    ]))
}

fn group_row(control: &str, ids: &[BigInt], h30: &BigInt, h7: &BigInt) -> Value {
    py::dict(vec![
        ("control", s(control)),
        ("rule_count", py::int(ids.len() as i64)),
        (
            "rule_ids",
            py::list(ids.iter().map(|i| Value::Int(i.clone())).collect()),
        ),
        ("total_hits_30d", Value::Int(h30.clone())),
        ("total_hits_7d", Value::Int(h7.clone())),
    ])
}

/// `get_compliance_group(framework, control)`.
pub fn compliance_group(
    snap: &Snapshot<'_>,
    framework: &str,
    control: &str,
) -> PyResult<Option<Value>> {
    let Some((_, label)) = FRAMEWORKS.iter().find(|(k, _)| *k == framework) else {
        return Err(unknown_framework(framework));
    };
    let key = py::py_strip(control).to_string();
    let mut ids = Vec::new();
    let mut h30 = BigInt::from(0);
    let mut h7 = BigInt::from(0);
    let mut matched = false;
    for rule in snap.wazuh {
        if !compliance_values(rule, framework).contains(&key) {
            continue;
        }
        matched = true;
        let rid = rule_int_id(rule);
        let stats = firing_of(snap, rid.as_ref());
        if let Some(r) = rid {
            ids.push(r);
        }
        h30 += &stats.hits_30d;
        h7 += &stats.hits_7d;
    }
    if !matched {
        return Ok(None);
    }
    ids.sort();
    Ok(Some(py::dict(vec![
        ("framework", s(framework)),
        ("framework_label", s(*label)),
        (
            "firing_stats_available",
            Value::Bool(snap.firing_unavailable.is_none()),
        ),
        ("group", group_row(&key, &ids, &h30, &h7)),
    ])))
}

/// `list_compliance_frameworks()`.
pub fn frameworks() -> Vec<Value> {
    FRAMEWORKS
        .iter()
        .map(|(k, l)| py::dict(vec![("key", s(*k)), ("label", s(*l))]))
        .collect()
}

fn gap_entry(tid: &Value, meta: &Value, names: &TacticNames) -> PyResult<Value> {
    let mut tactics: Vec<Value> = Vec::new();
    for short in py::iterate(&get(meta, "tactic_short_names", py::list(vec![]))?)? {
        if let Some(display) = names.get(&short)? {
            if display.truthy() && !tactics.iter().any(|t| t.py_eq(display)) {
                tactics.push(display.clone());
            }
        }
    }
    Ok(py::dict(vec![
        ("technique_id", tid.clone()),
        ("technique_name", get(meta, "name", tid.clone())?),
        ("tactics", py::list(tactics)),
        ("url", get(meta, "url", Value::None)?),
    ]))
}

fn base_tid(tid: &str) -> String {
    py::py_upper(py::py_strip(tid.split('.').next().unwrap_or_default()))
}

/// `list_coverage_gaps()`.
pub fn coverage_gaps(snap: &Snapshot<'_>) -> PyResult<Value> {
    let mut covered: HashMap<String, ()> = HashMap::new();
    for rule in snap.rules {
        for tid in rule_mitre_ids(rule)? {
            let base = base_tid(&tid);
            if !base.is_empty() {
                covered.insert(base, ());
            }
        }
    }
    for rule in snap.wazuh {
        for tid in wazuh_mitre_ids(rule) {
            let base = base_tid(&tid);
            if !base.is_empty() {
                covered.insert(base, ());
            }
        }
    }
    let names = snap.matrix.tactics_by_short()?;
    let mut gaps: Vec<(String, Value)> = Vec::new();
    let mut base_count = 0i64;
    for (tid, meta) in &snap.matrix.techniques {
        if get(meta, "is_subtechnique", Value::None)?.truthy() {
            continue;
        }
        base_count += 1;
        if let Value::Str(t) = tid {
            if covered.contains_key(t) {
                continue;
            }
        }
        gaps.push((tid.py_str(), gap_entry(tid, meta, &names)?));
    }
    gaps.sort_by(|a, b| a.0.cmp(&b.0));
    let gap_count = gaps.len() as i64;
    let covered_count = base_count - gap_count;
    let pct = if base_count > 0 {
        covered_count as f64 / base_count as f64 * 100.0
    } else {
        0.0
    };
    Ok(py::dict(vec![
        ("gaps", py::list(gaps.into_iter().map(|(_, g)| g).collect())),
        ("gap_count", py::int(gap_count)),
        ("covered_count", py::int(covered_count)),
        ("total_techniques", py::int(base_count)),
        ("coverage_pct", Value::Float(py::py_round(pct, 1))),
    ]))
}

/// `get_coverage_gap(technique_id)`.
pub fn coverage_gap(snap: &Snapshot<'_>, technique_id: &str) -> PyResult<Option<Value>> {
    let tid = py::py_upper(py::py_strip(technique_id));
    let Some(meta) = snap.matrix.technique(&tid) else {
        return Ok(None);
    };
    if !meta.truthy() || get(meta, "is_subtechnique", Value::None)?.truthy() {
        return Ok(None);
    }
    for rule in snap.rules {
        for t in rule_mitre_ids(rule)? {
            if base_tid(&t) == tid {
                return Ok(None);
            }
        }
    }
    for rule in snap.wazuh {
        for t in wazuh_mitre_ids(rule) {
            if base_tid(&t) == tid {
                return Ok(None);
            }
        }
    }
    let names = snap.matrix.tactics_by_short()?;
    Ok(Some(gap_entry(&s(tid), meta, &names)?))
}

fn split_list(rule: &Value, key: &str) -> Vec<String> {
    match rule.get(key) {
        Some(Value::List(items)) => items
            .iter()
            .filter_map(|v| match v {
                Value::Str(t) if !py::py_strip(t).is_empty() => Some(t.clone()),
                _ => None,
            })
            .collect(),
        Some(Value::Str(t)) => t
            .split(',')
            .map(|p| py::py_strip(p).to_string())
            .filter(|p| !p.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// `_wazuh_groups(rule)`.
pub fn wazuh_groups(rule: &Value) -> Vec<String> {
    split_list(rule, "groups")
}

/// `_wazuh_mitre_ids(rule)`.
pub fn wazuh_mitre_ids(rule: &Value) -> Vec<String> {
    split_list(rule, "mitre")
}

fn wazuh_compliance(rule: &Value) -> Value {
    let field = |k: &str| py::str_list(ensure_list_of_str(rule.get(k).unwrap_or(&Value::None)));
    py::dict(vec![
        ("pci_dss", field("pci_dss")),
        ("gdpr", field("gdpr")),
        ("hipaa", field("hipaa")),
        ("nist_800_53", field("nist_800_53")),
        ("tsc", field("tsc")),
        ("gpg13", field("gpg13")),
    ])
}

fn or_empty(rule: &Value, key: &str) -> Value {
    match rule.get(key) {
        Some(v) if v.truthy() => v.clone(),
        _ => s(""),
    }
}

/// `_wazuh_row(rule)`.
fn wazuh_row(snap: &Snapshot<'_>, rule: &Value) -> Vec<(Value, Value)> {
    let rid = rule_int_id(rule);
    let stats = firing_of(snap, rid.as_ref());
    vec![
        (s("id"), rule.get("id").cloned().unwrap_or(Value::None)),
        (
            s("level"),
            rule.get("level").cloned().unwrap_or(Value::None),
        ),
        (
            s("status"),
            rule.get("status").cloned().unwrap_or(Value::None),
        ),
        (s("description"), or_empty(rule, "description")),
        (s("filename"), or_empty(rule, "filename")),
        (s("relative_dirname"), or_empty(rule, "relative_dirname")),
        (s("groups"), py::str_list(wazuh_groups(rule))),
        (s("mitre"), py::str_list(wazuh_mitre_ids(rule))),
        (s("hits_7d"), Value::Int(stats.hits_7d)),
        (s("hits_30d"), Value::Int(stats.hits_30d)),
        (s("last_seen"), stats.last_seen),
    ]
}

/// `list_wazuh_rules(customer_code)` once the per-customer counts (if any)
/// are known: the rows, sorted by id.
pub fn wazuh_rows(snap: &Snapshot<'_>, customer: Option<&FiringStats>) -> Vec<Value> {
    let mut rows: Vec<(BigInt, Value)> = Vec::with_capacity(snap.wazuh.len());
    for rule in snap.wazuh {
        let mut row = wazuh_row(snap, rule);
        if let Some(cstats) = customer {
            let rid = rule_int_id(rule);
            let c = rid.as_ref().and_then(|r| cstats.get(r));
            let (h7, h30, seen) = match c {
                Some(c) => (
                    Value::Int(c.hits_7d.clone()),
                    Value::Int(c.hits_30d.clone()),
                    c.last_seen.clone(),
                ),
                None => (py::int(0), py::int(0), Value::None),
            };
            for (k, v) in row.iter_mut() {
                match k.as_str() {
                    Some("hits_7d") => *v = h7.clone(),
                    Some("hits_30d") => *v = h30.clone(),
                    Some("last_seen") => *v = seen.clone(),
                    _ => {}
                }
            }
        }
        let sort_key = rule_int_id(rule).unwrap_or_else(|| BigInt::from(0));
        rows.push((sort_key, Value::Dict(std::sync::Arc::new(row))));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows.into_iter().map(|(_, r)| r).collect()
}

/// The rest of `list_wazuh_rules`' payload.
pub fn wazuh_envelope(
    snap: &Snapshot<'_>,
    customer_code: Option<&str>,
) -> Vec<(&'static str, Value)> {
    vec![
        ("available", Value::Bool(snap.wazuh_unavailable.is_none())),
        ("unavailable_reason", opt_text(snap.wazuh_unavailable)),
        ("last_refresh", dt(snap.wazuh_last_refresh)),
        (
            "firing_stats_available",
            Value::Bool(snap.firing_unavailable.is_none()),
        ),
        (
            "firing_stats_unavailable_reason",
            opt_text(snap.firing_unavailable),
        ),
        ("firing_stats_last_refresh", dt(snap.firing_last_refresh)),
        ("customer_code", s(customer_code.unwrap_or_default())),
    ]
}

/// `get_wazuh_rule_detail(rule_id)`.
pub fn wazuh_rule_detail(snap: &Snapshot<'_>, rule_id: &BigInt) -> PyResult<Option<Value>> {
    let Some(rule) = snap
        .wazuh
        .iter()
        .find(|r| rule_int_id(r).as_ref() == Some(rule_id))
    else {
        return Ok(None);
    };
    let mitre = wazuh_mitre_ids(rule);
    let tactics = resolve_tactics(snap.matrix, &str_values(&mitre))?;
    let stats = snap
        .firing
        .get(rule_id)
        .cloned()
        .unwrap_or_else(Firing::zero);
    let details = match rule.get("details") {
        Some(d) if d.truthy() => d.clone(),
        _ => py::dict(vec![]),
    };
    Ok(Some(py::dict(vec![
        ("id", rule.get("id").cloned().unwrap_or(Value::None)),
        ("level", rule.get("level").cloned().unwrap_or(Value::None)),
        ("status", rule.get("status").cloned().unwrap_or(Value::None)),
        ("description", or_empty(rule, "description")),
        ("filename", or_empty(rule, "filename")),
        ("relative_dirname", or_empty(rule, "relative_dirname")),
        ("groups", py::str_list(wazuh_groups(rule))),
        ("mitre", py::str_list(mitre)),
        ("tactics", py::list(tactics)),
        ("compliance", wazuh_compliance(rule)),
        ("details", details),
        ("source_xml", s(synthesize_rule_xml(rule)?)),
        ("hits_7d", Value::Int(stats.hits_7d)),
        ("hits_30d", Value::Int(stats.hits_30d)),
        ("last_seen", stats.last_seen),
        (
            "firing_stats_available",
            Value::Bool(snap.firing_unavailable.is_none()),
        ),
        (
            "firing_stats_unavailable_reason",
            opt_text(snap.firing_unavailable),
        ),
    ])))
}

/// `_xml_escape(text)`.
pub fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// `_stringify_detail_value(value)`.
pub fn stringify_detail(v: &Value) -> String {
    match v {
        Value::None => String::new(),
        Value::Str(t) => t.clone(),
        Value::Int(_) | Value::Float(_) | Value::Bool(_) => v.py_str(),
        other => match crate::py::to_py(other) {
            Some(p) => py_dumps(
                &p,
                Dumps {
                    ensure_ascii: true,
                    compact: true,
                },
            )
            .unwrap_or_else(|_| other.py_str()),
            None => other.py_str(),
        },
    }
}

fn render_detail(key: &str, value: &Value) -> String {
    match value {
        Value::List(items) => items
            .iter()
            .map(|i| render_detail(key, i))
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Dict(items) => {
            if items.len() == 1 && items[0].0.as_str() == Some("pattern") {
                return format!(
                    "  <{key}>{}</{key}>",
                    xml_escape(&stringify_detail(&items[0].1))
                );
            }
            let mut attrs: Vec<(String, String)> = Vec::new();
            let mut body: Option<String> = None;
            for (k, v) in items.iter() {
                let ks = k.py_str();
                let is_text = matches!(ks.as_str(), "pattern" | "value" | "text" | "#text")
                    && k.as_str().is_some();
                if is_text && body.is_none() {
                    body = Some(stringify_detail(v));
                } else {
                    match attrs.iter_mut().find(|(a, _)| *a == ks) {
                        Some(slot) => slot.1 = v.py_str(),
                        None => attrs.push((ks, v.py_str())),
                    }
                }
            }
            let attr_str: String = attrs
                .iter()
                .map(|(k, v)| format!(" {k}=\"{}\"", xml_escape(v)))
                .collect();
            match body {
                Some(b) => format!("  <{key}{attr_str}>{}</{key}>", xml_escape(&b)),
                None => format!("  <{key}{attr_str} />"),
            }
        }
        other => {
            let text = stringify_detail(other);
            if text.is_empty() {
                format!("  <{key} />")
            } else {
                format!("  <{key}>{}</{key}>", xml_escape(&text))
            }
        }
    }
}

/// `_synthesize_rule_xml(rule)`.
pub fn synthesize_rule_xml(rule: &Value) -> PyResult<String> {
    let mut header = Vec::new();
    if let Some(rid) = rule.get("id").filter(|v| !matches!(v, Value::None)) {
        header.push(format!("id=\"{}\"", rid.py_str()));
    }
    if let Some(level) = rule.get("level").filter(|v| !matches!(v, Value::None)) {
        header.push(format!("level=\"{}\"", level.py_str()));
    }
    let header = header.join(" ");
    let mut lines = vec![if header.is_empty() {
        "<rule>".to_string()
    } else {
        format!("<rule {header}>")
    }];
    let details = match rule.get("details") {
        Some(d) if d.truthy() => d.clone(),
        _ => py::dict(vec![]),
    };
    if let Some(decoded) = details.get("decoded_as") {
        lines.push(format!(
            "  <decoded_as>{}</decoded_as>",
            xml_escape(&stringify_detail(decoded))
        ));
    }
    if let Some(Value::Str(desc)) = rule.get("description") {
        if !desc.is_empty() {
            lines.push(format!("  <description>{}</description>", xml_escape(desc)));
        }
    }
    let groups = wazuh_groups(rule);
    if !groups.is_empty() {
        lines.push(format!(
            "  <group>{}</group>",
            xml_escape(&(groups.join(",") + ","))
        ));
    }
    for (k, v) in py::items(&details)? {
        if k.as_str() == Some("decoded_as") {
            continue;
        }
        lines.push(render_detail(&k.py_str(), &v));
    }
    let mitre = wazuh_mitre_ids(rule);
    if !mitre.is_empty() {
        lines.push("  <mitre>".into());
        for m in &mitre {
            lines.push(format!("    <id>{}</id>", xml_escape(m)));
        }
        lines.push("  </mitre>".into());
    }
    for key in ["pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "gpg13"] {
        let tag = if key == "nist_800_53" {
            "nist-800-53"
        } else {
            key
        };
        for v in ensure_list_of_str(rule.get(key).unwrap_or(&Value::None)) {
            lines.push(format!("  <{tag}>{}</{tag}>", xml_escape(&v)));
        }
    }
    lines.push("</rule>".into());
    Ok(lines.join("\n"))
}

/// The dict `run_log_test` returns, given `run_logtest`'s outcome.
pub fn log_test_result(
    snap: &Snapshot<'_>,
    outcome: Result<(bool, Value, Value), String>,
) -> PyResult<Value> {
    let (matched, rule, alert) = match outcome {
        Ok(t) => t,
        Err(reason) => {
            return Ok(py::dict(vec![
                ("matched", Value::Bool(false)),
                ("rule", Value::None),
                ("alert", Value::None),
                ("tactics", py::list(vec![])),
                ("unavailable_reason", s(reason)),
            ]));
        }
    };
    let mut tactics = Vec::new();
    if rule.truthy() {
        let ids = match get(&rule, "mitre", Value::None)? {
            v if v.truthy() => v,
            _ => py::list(vec![]),
        };
        tactics = resolve_tactics(snap.matrix, &py::iterate(&ids)?)?;
    }
    Ok(py::dict(vec![
        ("matched", Value::Bool(matched)),
        ("rule", rule),
        ("alert", alert),
        ("tactics", py::list(tactics)),
        ("unavailable_reason", Value::None),
    ]))
}
