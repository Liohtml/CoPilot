//! `schema/microsoft_patch_tuesday.py`: the response models, written as their
//! JSON-mode dumps in declaration order. Every value is built by the service
//! with the right type, as Python passes them; the one field Python hands
//! over unchecked — EPSS's `date`, as FIRST sent it — goes through
//! `EPSSInfo`'s validation ([`EPSS_INFO`]).

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

use crate::cvrf::{Kev, Priority};

/// `EPSSInfo`.
pub static EPSS_INFO: Model = Model::new(
    "EPSSInfo",
    &[
        Field::opt("score", Ty::Nullable(&Ty::Float)),
        Field::opt("percentile", Ty::Nullable(&Ty::Float)),
        Field::opt("date", Ty::Nullable(&Ty::Str)),
    ],
);

fn s(v: impl Into<String>) -> PyValue {
    PyValue::Str(v.into())
}

fn opt_s(v: Option<&str>) -> PyValue {
    v.map_or(PyValue::None, s)
}

fn opt_f(v: Option<f64>) -> PyValue {
    v.map_or(PyValue::None, PyValue::Float)
}

fn int(n: usize) -> PyValue {
    PyValue::Int(n.to_string())
}

fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// One `PatchTuesdayItem`.
#[derive(Debug, Clone)]
pub struct Item {
    /// `cycle` (and `source.msrc_cvrf_id`).
    pub cycle: String,
    /// `cve`.
    pub cve: String,
    /// `title` (and `affected.component_hint`).
    pub title: Option<String>,
    /// `severity`.
    pub severity: Option<String>,
    /// `cvss.base`.
    pub cvss_base: Option<f64>,
    /// `cvss.vector`.
    pub cvss_vector: Option<String>,
    /// `EPSSInfo`'s dump.
    pub epss: PyValue,
    /// `epss.score` (the sort key).
    pub epss_score: Option<f64>,
    /// `kev.in_kev`.
    pub in_kev: bool,
    /// The KEV entry (empty when not in the catalog).
    pub kev: Kev,
    /// `affected.product`.
    pub product: String,
    /// `affected.family`.
    pub family: &'static str,
    /// `remediation.kbs`.
    pub kbs: Vec<String>,
    /// `prioritization`.
    pub priority: Priority,
    /// `source.msrc_cvrf_url`.
    pub cvrf_url: String,
    /// `source.cisa_kev_url`.
    pub kev_url: String,
    /// `timestamp_utc`.
    pub timestamp: String,
}

impl Item {
    /// The model's dump.
    pub fn dump(&self) -> PyValue {
        let k = &self.kev;
        dict(vec![
            ("cycle", s(&self.cycle)),
            ("release_type", s("patch_tuesday")),
            ("cve", s(&self.cve)),
            ("title", opt_s(self.title.as_deref())),
            ("severity", opt_s(self.severity.as_deref())),
            (
                "cvss",
                dict(vec![
                    ("base", opt_f(self.cvss_base)),
                    ("vector", opt_s(self.cvss_vector.as_deref())),
                ]),
            ),
            ("epss", self.epss.clone()),
            (
                "kev",
                dict(vec![
                    ("in_kev", PyValue::Bool(self.in_kev)),
                    ("date_added", opt_s(k.date_added.as_deref())),
                    ("due_date", opt_s(k.due_date.as_deref())),
                    ("required_action", opt_s(k.required_action.as_deref())),
                    (
                        "known_ransomware_campaign_use",
                        opt_s(k.known_ransomware_campaign_use.as_deref()),
                    ),
                    ("vendor_project", opt_s(k.vendor_project.as_deref())),
                    ("product", opt_s(k.product.as_deref())),
                    ("vulnerability_name", opt_s(k.vulnerability_name.as_deref())),
                    ("short_description", opt_s(k.short_description.as_deref())),
                    ("notes", opt_s(k.notes.as_deref())),
                ]),
            ),
            (
                "affected",
                dict(vec![
                    ("product", s(&self.product)),
                    ("family", s(self.family)),
                    ("component_hint", opt_s(self.title.as_deref())),
                ]),
            ),
            (
                "remediation",
                dict(vec![(
                    "kbs",
                    PyValue::List(self.kbs.iter().map(s).collect()),
                )]),
            ),
            (
                "prioritization",
                dict(vec![
                    ("priority", s(self.priority.level)),
                    (
                        "reason",
                        PyValue::List(self.priority.reasons.iter().map(s).collect()),
                    ),
                    ("suggested_sla", s(self.priority.sla)),
                ]),
            ),
            (
                "source",
                dict(vec![
                    ("msrc_cvrf_id", s(&self.cycle)),
                    ("msrc_cvrf_url", s(&self.cvrf_url)),
                    ("cisa_kev_url", s(&self.kev_url)),
                ]),
            ),
            ("timestamp_utc", s(&self.timestamp)),
        ])
    }
}

/// `PatchTuesdaySummary`.
#[derive(Debug, Clone)]
pub struct Summary {
    /// `cycle`.
    pub cycle: String,
    /// `patch_tuesday_date`.
    pub patch_tuesday_date: String,
    /// `generated_utc`.
    pub generated_utc: String,
    /// `unique_cves`.
    pub unique_cves: usize,
    /// `total_records`.
    pub total_records: usize,
    /// `by_priority` (P0 … P3).
    pub by_priority: [usize; 4],
    /// `by_family`, in its order.
    pub by_family: Vec<(String, usize)>,
    /// `by_severity`, in its order.
    pub by_severity: Vec<(String, usize)>,
}

impl Summary {
    /// The model's dump.
    pub fn dump(&self) -> PyValue {
        let counts = |pairs: &[(String, usize)]| {
            PyValue::Dict(pairs.iter().map(|(k, n)| (k.clone(), int(*n))).collect())
        };
        dict(vec![
            ("cycle", s(&self.cycle)),
            ("patch_tuesday_date", s(&self.patch_tuesday_date)),
            ("generated_utc", s(&self.generated_utc)),
            ("unique_cves", int(self.unique_cves)),
            ("total_records", int(self.total_records)),
            (
                "by_priority",
                dict(vec![
                    ("P0", int(self.by_priority[0])),
                    ("P1", int(self.by_priority[1])),
                    ("P2", int(self.by_priority[2])),
                    ("P3", int(self.by_priority[3])),
                ]),
            ),
            ("by_family", counts(&self.by_family)),
            ("by_severity", counts(&self.by_severity)),
        ])
    }
}

/// `PatchTuesdayResponse`.
pub fn response(
    success: bool,
    message: String,
    summary: Option<&Summary>,
    items: &[Item],
) -> PyValue {
    dict(vec![
        ("success", PyValue::Bool(success)),
        ("message", s(message)),
        ("summary", summary.map_or(PyValue::None, Summary::dump)),
        (
            "items",
            PyValue::List(items.iter().map(Item::dump).collect()),
        ),
    ])
}

/// `PatchTuesdaySummaryResponse`.
pub fn summary_response(
    success: bool,
    message: String,
    summary: Option<&Summary>,
    top_items: &[Item],
) -> PyValue {
    dict(vec![
        ("success", PyValue::Bool(success)),
        ("message", s(message)),
        ("summary", summary.map_or(PyValue::None, Summary::dump)),
        (
            "top_items",
            PyValue::List(top_items.iter().map(Item::dump).collect()),
        ),
    ])
}

/// `AvailableCyclesResponse`.
pub fn cycles_response(
    success: bool,
    message: String,
    cycles: &[String],
    current_cycle: &str,
    next_patch_tuesday: &str,
) -> PyValue {
    dict(vec![
        ("success", PyValue::Bool(success)),
        ("message", s(message)),
        ("cycles", PyValue::List(cycles.iter().map(s).collect())),
        ("current_cycle", s(current_cycle)),
        ("next_patch_tuesday", s(next_patch_tuesday)),
    ])
}

/// `sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))`.
pub fn sorted_counts(counts: Vec<(String, usize)>) -> Vec<(String, usize)> {
    let mut v = counts;
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

/// A counter in insertion order (`d[k] = d.get(k, 0) + 1`).
pub fn bump(counts: &mut Vec<(String, usize)>, key: &str) {
    match counts.iter_mut().find(|(k, _)| k == key) {
        Some((_, n)) => *n += 1,
        None => counts.push((key.to_string(), 1)),
    }
}
