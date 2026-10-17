//! `services/mitre_coverage.py`: the ATT&CK Enterprise matrix parsed from
//! the STIX bundle (`_parse_bundle`), and the coverage map over the rules
//! (`get_coverage`).

use std::collections::HashMap;

use chrono::NaiveDateTime;
use copilot_jinja::unicode;
use copilot_upstream::py::PyResult;
use copilot_yaml::Value;

use crate::py::{self, get, hash_key, s};
use crate::rules::{self, Filters};

/// `MITRE_STIX_URL`.
pub const MITRE_STIX_URL: &str =
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";
/// `MITRE_CACHE_TTL_HOURS`.
pub const MITRE_CACHE_TTL_HOURS: i64 = 24;

const CANONICAL_ORDER: &[&str] = &[
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
];

/// The matrix (`_tactics`, `_techniques`, `_last_refresh`).
#[derive(Debug, Clone, Default)]
pub struct Matrix {
    /// `_tactics`: dicts in kill-chain order.
    pub tactics: Vec<Value>,
    /// `_techniques`: `external_id → dict`, in insertion order.
    pub techniques: Vec<(Value, Value)>,
    index: HashMap<String, usize>,
    /// `_last_refresh`.
    pub last_refresh: Option<NaiveDateTime>,
}

fn external(obj: &Value, field: &str) -> PyResult<Value> {
    for r in py::iterate(&get(obj, "external_references", py::list(vec![]))?)? {
        if get(&r, "source_name", Value::None)?.as_str() == Some("mitre-attack") {
            return get(&r, field, s(""));
        }
    }
    Ok(s(""))
}

/// An ordered `dict` keyed by Python values.
#[derive(Debug, Default)]
struct PyMap {
    items: Vec<(Value, Value)>,
    index: HashMap<String, usize>,
}

impl PyMap {
    fn set(&mut self, key: Value, value: Value) -> PyResult<()> {
        let k = hash_key(&key)?;
        match self.index.get(&k) {
            Some(i) => self.items[*i].1 = value,
            None => {
                self.index.insert(k, self.items.len());
                self.items.push((key, value));
            }
        }
        Ok(())
    }

    fn get(&self, key: &Value) -> PyResult<Option<&Value>> {
        let k = hash_key(key)?;
        Ok(self.index.get(&k).map(|i| &self.items[*i].1))
    }
}

impl Matrix {
    /// `_parse_bundle(bundle)`.
    pub fn parse(bundle: &Value) -> PyResult<Self> {
        let mut tactics = PyMap::default();
        let mut techniques = PyMap::default();
        for obj in py::iterate(&get(bundle, "objects", py::list(vec![]))?)? {
            let obj_type = get(&obj, "type", Value::None)?;
            if get(&obj, "revoked", Value::None)?.truthy()
                || get(&obj, "x_mitre_deprecated", Value::None)?.truthy()
            {
                continue;
            }
            if obj_type.as_str() == Some("x-mitre-tactic") {
                let external_id = external(&obj, "external_id")?;
                let short_name = get(&obj, "x_mitre_shortname", s(""))?;
                if !external_id.truthy() || !short_name.truthy() {
                    continue;
                }
                let entry = py::dict(vec![
                    ("id", external_id),
                    ("name", get(&obj, "name", s(""))?),
                    ("short_name", short_name.clone()),
                    ("url", external(&obj, "url")?),
                    ("description", get(&obj, "description", s(""))?),
                ]);
                tactics.set(short_name, entry)?;
            } else if obj_type.as_str() == Some("attack-pattern") {
                let external_id = external(&obj, "external_id")?;
                if !external_id.truthy() {
                    continue;
                }
                let mut short_names = Vec::new();
                for phase in py::iterate(&get(&obj, "kill_chain_phases", py::list(vec![]))?)? {
                    if get(&phase, "kill_chain_name", Value::None)?.as_str() == Some("mitre-attack")
                    {
                        short_names.push(get(&phase, "phase_name", s(""))?);
                    }
                }
                let entry = py::dict(vec![
                    ("id", external_id.clone()),
                    ("name", get(&obj, "name", s(""))?),
                    ("url", external(&obj, "url")?),
                    (
                        "is_subtechnique",
                        Value::Bool(get(&obj, "x_mitre_is_subtechnique", Value::None)?.truthy()),
                    ),
                    ("tactic_short_names", py::list(short_names)),
                ]);
                techniques.set(external_id, entry)?;
            }
        }
        let mut ordered = Vec::new();
        for short in CANONICAL_ORDER {
            if let Some(t) = tactics.get(&s(*short))? {
                ordered.push(t.clone());
            }
        }
        for (short, t) in &tactics.items {
            if !CANONICAL_ORDER.iter().any(|c| short.as_str() == Some(*c)) {
                ordered.push(t.clone());
            }
        }
        Ok(Self {
            tactics: ordered,
            index: techniques.index,
            techniques: techniques.items,
            last_refresh: None,
        })
    }

    /// `techniques.get(tid)` for a `str` id.
    pub fn technique(&self, tid: &str) -> Option<&Value> {
        self.index
            .get(&format!("s{tid}"))
            .map(|i| &self.techniques[*i].1)
    }

    /// `{t["short_name"]: t["name"] for t in tactics}`.
    pub fn tactics_by_short(&self) -> PyResult<TacticNames> {
        let mut map = PyMap::default();
        for t in &self.tactics {
            map.set(py::getitem(t, "short_name")?, py::getitem(t, "name")?)?;
        }
        Ok(TacticNames(map))
    }
}

/// `tactics_by_short`.
#[derive(Debug)]
pub struct TacticNames(PyMap);

impl TacticNames {
    /// `tactics_by_short.get(short_name)`.
    pub fn get(&self, short: &Value) -> PyResult<Option<&Value>> {
        self.0.get(short)
    }
}

fn rule_matches(rule: &Value, f: &Filters) -> PyResult<bool> {
    if let Some(platform) = &f.platform {
        if rule.get("_platform").and_then(Value::as_str) != Some(platform.as_str()) {
            return Ok(false);
        }
    }
    if let Some(category) = f.category.as_deref().filter(|c| !c.is_empty()) {
        let folder = match rule.get("_category") {
            Some(v) if v.truthy() => v.py_str(),
            _ => String::new(),
        };
        if unicode::lower(&folder) != unicode::lower(category) {
            return Ok(false);
        }
    }
    if let Some(severity) = &f.severity {
        let response = get(rule, "response", py::dict(vec![]))?;
        if py::lower(&get(&response, "severity", s(""))?)? != *severity {
            return Ok(false);
        }
    }
    if let Some(status) = &f.status {
        if py::lower(&get(rule, "status", s(""))?)? != *status {
            return Ok(false);
        }
    }
    if let Some(want) = f.has_graylog {
        let has = matches!(rule.get("_has_graylog"), Some(Value::Bool(true)));
        if has != want {
            return Ok(false);
        }
    }
    if let Some(search) = f.search.as_deref().filter(|t| !t.is_empty()) {
        let needle = unicode::lower(search);
        let name = py::lower(&get(rule, "name", s(""))?)?;
        let desc = py::lower(&get(rule, "description", s(""))?)?;
        if !name.contains(&needle) && !desc.contains(&needle) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// A set of rule ids in insertion order (`set()` + `sorted`).
#[derive(Debug, Default, Clone)]
struct IdSet {
    items: Vec<Value>,
    keys: HashMap<String, ()>,
}

impl IdSet {
    fn add(&mut self, v: &Value) -> PyResult<()> {
        let k = hash_key(v)?;
        if self.keys.insert(k, ()).is_none() {
            self.items.push(v.clone());
        }
        Ok(())
    }

    fn extend(&mut self, other: &[Value]) -> PyResult<()> {
        for v in other {
            self.add(v)?;
        }
        Ok(())
    }

    /// `sorted(the set)`.
    fn sorted(&self) -> PyResult<Vec<Value>> {
        sorted_values(self.items.clone())
    }
}

/// `sorted(values)`: `str`s (or numbers) ordered as Python orders them; a
/// mix Python cannot order is its `TypeError`.
pub fn sorted_values(mut values: Vec<Value>) -> PyResult<Vec<Value>> {
    for w in values.windows(2) {
        py::lt(&w[1], &w[0])?;
    }
    let mut err = None;
    values.sort_by(|a, b| match py::lt(a, b) {
        Ok(true) => std::cmp::Ordering::Less,
        Ok(false) => match py::lt(b, a) {
            Ok(true) => std::cmp::Ordering::Greater,
            Ok(false) => std::cmp::Ordering::Equal,
            Err(e) => {
                err.get_or_insert(e);
                std::cmp::Ordering::Equal
            }
        },
        Err(e) => {
            err.get_or_insert(e);
            std::cmp::Ordering::Equal
        }
    });
    match err {
        Some(e) => Err(e),
        None => Ok(values),
    }
}

#[derive(Debug, Default, Clone)]
struct Cover {
    rule_ids: IdSet,
    subs: Vec<(String, IdSet)>,
}

/// `get_coverage(...)` (the caches already loaded): the dict the route
/// validates as `MitreCoverageResponse`.
pub fn coverage(
    matrix: &Matrix,
    rule_list: &[Value],
    rules_last_refresh: Option<NaiveDateTime>,
    f: &Filters,
) -> PyResult<Value> {
    let mut coverage: Vec<(String, Cover)> = Vec::new();
    let mut rules_index: Vec<(Value, Value)> = Vec::new();
    let mut rules_index_keys: HashMap<String, usize> = HashMap::new();
    for rule in rule_list {
        let rule_id = get(rule, "id", s(""))?;
        if !rule_id.truthy() {
            continue;
        }
        if !rule_matches(rule, f)? {
            continue;
        }
        let ds = get(rule, "data_source", py::list(vec![]))?;
        let ds = if ds.truthy() { ds } else { py::list(vec![]) };
        let sources: Vec<Value> = py::iterate(&ds)?
            .into_iter()
            .filter(|v| v.as_str().is_some())
            .take(3)
            .collect();
        let response = get(rule, "response", py::dict(vec![]))?;
        let entry = py::dict(vec![
            ("id", rule_id.clone()),
            ("name", get(rule, "name", s(""))?),
            ("severity", get(&response, "severity", s("medium"))?),
            (
                "platform",
                rule.get("_platform")
                    .cloned()
                    .unwrap_or_else(|| s("unknown")),
            ),
            (
                "has_graylog",
                rule.get("_has_graylog")
                    .cloned()
                    .unwrap_or(Value::Bool(false)),
            ),
            ("data_sources", py::list(sources)),
        ]);
        let key = hash_key(&rule_id)?;
        match rules_index_keys.get(&key) {
            Some(i) => rules_index[*i].1 = entry,
            None => {
                rules_index_keys.insert(key, rules_index.len());
                rules_index.push((rule_id.clone(), entry));
            }
        }
        let tags = get(rule, "tags", py::dict(vec![]))?;
        let tids = get(&tags, "mitre_attack_id", py::list(vec![]))?;
        let tids = if tids.truthy() {
            tids
        } else {
            py::list(vec![])
        };
        for raw in py::iterate(&tids)? {
            let tid = py::py_upper(&py::strip(&raw)?);
            if !tid.starts_with('T') {
                continue;
            }
            let base = tid.split('.').next().unwrap_or_default().to_string();
            let idx = match coverage.iter().position(|(b, _)| *b == base) {
                Some(i) => i,
                None => {
                    coverage.push((base.clone(), Cover::default()));
                    coverage.len() - 1
                }
            };
            let entry = &mut coverage[idx].1;
            if tid.contains('.') {
                let sub = match entry.subs.iter().position(|(t, _)| *t == tid) {
                    Some(i) => i,
                    None => {
                        entry.subs.push((tid.clone(), IdSet::default()));
                        entry.subs.len() - 1
                    }
                };
                entry.subs[sub].1.add(&rule_id)?;
            } else {
                entry.rule_ids.add(&rule_id)?;
            }
        }
    }
    let mut tactics_out = Vec::new();
    let mut total_techniques = 0i64;
    let mut covered = 0i64;
    for tactic in &matrix.tactics {
        let short = py::getitem(tactic, "short_name")?;
        let mut techniques_in: Vec<(String, Value)> = Vec::new();
        for (tid, meta) in &matrix.techniques {
            if py::getitem(meta, "is_subtechnique")?.truthy() {
                continue;
            }
            let names = py::getitem(meta, "tactic_short_names")?;
            if !py::iterate(&names)?.iter().any(|n| n.py_eq(&short)) {
                continue;
            }
            let tid_s = tid.py_str();
            let cov = coverage
                .iter()
                .find(|(b, _)| tid.as_str() == Some(b.as_str()))
                .map(|(_, c)| c.clone())
                .unwrap_or_default();
            let base_ids = cov.rule_ids.sorted()?;
            let mut total = cov.rule_ids.clone();
            let mut subs: Vec<(String, Value)> = Vec::new();
            for (sub_tid, sub_meta) in &matrix.techniques {
                if !py::getitem(sub_meta, "is_subtechnique")?.truthy() {
                    continue;
                }
                let Value::Str(sub_text) = sub_tid else {
                    return Err(py::no_attr(sub_tid, "startswith"));
                };
                if !sub_text.starts_with(&format!("{tid_s}.")) {
                    continue;
                }
                let sub_ids = cov
                    .subs
                    .iter()
                    .find(|(t, _)| t == sub_text)
                    .map(|(_, ids)| ids.sorted())
                    .transpose()?
                    .unwrap_or_default();
                total.extend(&sub_ids)?;
                subs.push((
                    sub_text.clone(),
                    py::dict(vec![
                        ("id", sub_tid.clone()),
                        ("name", py::getitem(sub_meta, "name")?),
                        ("url", py::getitem(sub_meta, "url")?),
                        ("rule_count", py::int(sub_ids.len() as i64)),
                        ("rule_ids", py::list(sub_ids)),
                    ]),
                ));
            }
            subs.sort_by(|a, b| a.0.cmp(&b.0));
            let total_count = total.items.len() as i64;
            techniques_in.push((
                tid_s,
                py::dict(vec![
                    ("id", tid.clone()),
                    ("name", py::getitem(meta, "name")?),
                    ("url", py::getitem(meta, "url")?),
                    ("rule_count", py::int(base_ids.len() as i64)),
                    ("rule_ids", py::list(base_ids)),
                    ("total_rule_count", py::int(total_count)),
                    (
                        "subtechniques",
                        py::list(subs.into_iter().map(|(_, v)| v).collect()),
                    ),
                ]),
            ));
        }
        techniques_in.sort_by(|a, b| a.0.cmp(&b.0));
        total_techniques += techniques_in.len() as i64;
        covered += techniques_in
            .iter()
            .filter(|(_, t)| {
                t.get("total_rule_count")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    > 0
            })
            .count() as i64;
        tactics_out.push(py::dict(vec![
            ("id", py::getitem(tactic, "id")?),
            ("name", py::getitem(tactic, "name")?),
            ("short_name", short),
            ("url", py::getitem(tactic, "url")?),
            (
                "techniques",
                py::list(techniques_in.into_iter().map(|(_, v)| v).collect()),
            ),
        ]));
    }
    let n_tactics = tactics_out.len() as i64;
    let n_rules = rules_index.len() as i64;
    Ok(py::dict(vec![
        ("success", Value::Bool(true)),
        ("message", s("MITRE coverage built successfully")),
        ("tactics", py::list(tactics_out)),
        ("rules_index", Value::Dict(std::sync::Arc::new(rules_index))),
        (
            "stats",
            py::dict(vec![
                ("total_tactics", py::int(n_tactics)),
                ("total_techniques", py::int(total_techniques)),
                ("covered_techniques", py::int(covered)),
                ("total_rules", py::int(n_rules)),
                (
                    "matrix_last_refreshed",
                    matrix
                        .last_refresh
                        .map_or(Value::None, rules::naive_datetime),
                ),
                (
                    "rules_last_refreshed",
                    rules_last_refresh.map_or(Value::None, rules::naive_datetime),
                ),
            ]),
        ),
    ]))
}
