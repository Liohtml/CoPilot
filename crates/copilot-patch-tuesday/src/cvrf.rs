//! The pure half of `services/microsoft_patch_tuesday.py`: reading MSRC's
//! CVRF document (products, CVSS, severity, KBs), FIRST's EPSS rows and
//! CISA's KEV catalog, the product families and the priority — each
//! operation on whatever JSON came back, as CPython runs it (an odd shape
//! fails with CPython's `AttributeError` / `TypeError` text).

use std::collections::{BTreeSet, HashMap};

use copilot_auth::pyvalue::PyValue;
use copilot_jinja::unicode;
use copilot_upstream::py::{PyResult, get};

use crate::py::{
    fixed, get_or, iterate, listed, lower, normalize_text, or, safe_float, title, upper,
};

/// `MONTH_ABBR`.
pub const MONTH_ABBR: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `product_family(name)`: a coarse family bucket.
pub fn product_family(name: &PyValue) -> &'static str {
    let n = lower(&normalize_text(name).unwrap_or_default());
    if n.contains("windows server") {
        "Windows Server"
    } else if n.contains("windows") {
        "Windows"
    } else if n.contains("office") || n.contains("microsoft 365") {
        "Office/M365"
    } else if n.contains("exchange") {
        "Exchange"
    } else if n.contains("sharepoint") {
        "SharePoint"
    } else if n.contains("sql server") {
        "SQL Server"
    } else if n.contains("visual studio") || n.contains(".net") {
        "Developer Platform"
    } else if n.contains("edge") {
        "Edge"
    } else if n.contains("azure") {
        "Azure"
    } else if n.contains("dynamics") {
        "Dynamics"
    } else {
        "Other"
    }
}

/// `chunk_by_max_chars(items, max_chars)`.
pub fn chunk_by_max_chars(items: &[String], max_chars: usize) -> Vec<Vec<String>> {
    let mut chunks = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut current_len = 0;
    for it in items {
        let len = it.chars().count();
        let add_len = len + usize::from(!current.is_empty());
        if !current.is_empty() && current_len + add_len > max_chars {
            chunks.push(std::mem::take(&mut current));
            current.push(it.clone());
            current_len = len;
        } else {
            current.push(it.clone());
            current_len += add_len;
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// `extract_cvss(vuln)`: the highest base score and its vector.
pub fn extract_cvss(vuln: &PyValue) -> PyResult<(Option<f64>, Option<String>)> {
    let sets = listed(or(
        get_or(vuln, &["CVSSScoreSets", "CvssScoreSets"])?,
        PyValue::List(Vec::new()),
    ));
    let mut best: (Option<f64>, Option<String>) = (None, None);
    for s in iterate(&sets)? {
        if !matches!(s, PyValue::Dict(_)) {
            continue;
        }
        let score = safe_float(&get_or(&s, &["BaseScore", "baseScore", "Score"])?);
        let vector = normalize_text(&get_or(&s, &["Vector", "vectorString", "VectorString"])?);
        let Some(score) = score else { continue };
        if best.0.is_none_or(|b| score > b) {
            best = (Some(score), vector);
        }
    }
    Ok(best)
}

/// `extract_severity(vuln)`.
pub fn extract_severity(vuln: &PyValue) -> PyResult<Option<String>> {
    let threats = listed(or(get_or(vuln, &["Threats"])?, PyValue::List(Vec::new())));
    for t in iterate(&threats)? {
        if !matches!(t, PyValue::Dict(_)) {
            continue;
        }
        let kind = or(get_or(&t, &["Type", "type"])?, PyValue::Str(String::new()));
        let ttype = normalize_text(&kind);
        let desc = normalize_text(&get_or(&t, &["Description", "description"])?);
        if let (Some(ttype), Some(desc)) = (ttype, desc) {
            if lower(&ttype).contains("severity") {
                return Ok(Some(title(&desc)));
            }
        }
    }
    let sev = normalize_text(&get_or(vuln, &["Severity", "severity"])?);
    Ok(sev.map(|s| title(&s)))
}

/// Python `re`'s `\bKB\d{6,8}\b` with `re.IGNORECASE` on a `str`: every
/// match, in order.
pub fn find_kbs(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let is_k = |c: char| matches!(c, 'K' | 'k' | '\u{212a}');
    let is_b = |c: char| matches!(c, 'B' | 'b');
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < n {
        let boundary = i == 0 || !unicode::is_word(chars[i - 1]);
        if boundary && is_k(chars[i]) && is_b(chars[i + 1]) {
            let mut j = i + 2;
            while j < n && unicode::is_decimal(chars[j]) {
                j += 1;
            }
            let digits = j - (i + 2);
            // Greedy digits, then `\b`: fewer digits would leave a digit
            // (a word character) after the match, so no backtracking helps.
            if (6..=8).contains(&digits) && (j == n || !unicode::is_word(chars[j])) {
                out.push(chars[i..j].iter().collect());
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// `extract_kbs(vuln)`: the KB numbers named in the remediations, sorted.
pub fn extract_kbs(vuln: &PyValue) -> PyResult<Vec<String>> {
    let rems = listed(or(
        get_or(vuln, &["Remediations"])?,
        PyValue::List(Vec::new()),
    ));
    let mut kbs = BTreeSet::new();
    for r in iterate(&rems)? {
        if !matches!(r, PyValue::Dict(_)) {
            continue;
        }
        for field in ["Description", "URL", "Url", "description", "url"] {
            let Some(val) = get(&r, field)? else { continue };
            if !val.truthy() {
                continue;
            }
            for kb in find_kbs(&val.py_str()) {
                kbs.insert(upper(&kb));
            }
        }
    }
    Ok(kbs.into_iter().collect())
}

/// `build_product_lookup(doc)`: ProductID → product name.
pub fn build_product_lookup(doc: &PyValue) -> PyResult<HashMap<String, String>> {
    let pt = or(get_or(doc, &["ProductTree"])?, PyValue::Dict(Vec::new()));
    let fp = listed(or(
        get_or(&pt, &["FullProductName"])?,
        PyValue::List(Vec::new()),
    ));
    let mut lookup = HashMap::new();
    for item in iterate(&fp)? {
        if !matches!(item, PyValue::Dict(_)) {
            continue;
        }
        let pid = get_or(&item, &["ProductID", "productId", "ProductId"])?;
        let val = normalize_text(&get_or(&item, &["Value", "value", "Name", "name"])?);
        if let Some(val) = val {
            if pid.truthy() {
                lookup.insert(pid.py_str(), val);
            }
        }
    }
    Ok(lookup)
}

/// `extract_affected_products(vuln, product_lookup)`: the product names, sorted.
pub fn extract_affected_products(
    vuln: &PyValue,
    lookup: &HashMap<String, String>,
) -> PyResult<Vec<String>> {
    let mut names = BTreeSet::new();
    let mut add = |pid: &PyValue| {
        if let Some(name) = lookup.get(&pid.py_str()) {
            names.insert(name.clone());
        }
    };
    let statuses = listed(or(
        get_or(vuln, &["ProductStatuses", "ProductStatus"])?,
        PyValue::List(Vec::new()),
    ));
    for st in iterate(&statuses)? {
        let PyValue::Dict(items) = &st else { continue };
        for (_, v) in items {
            match v {
                PyValue::List(pids) => pids.iter().for_each(&mut add),
                // `isinstance(v, (str, int))`: a bool is an int.
                PyValue::Str(_) | PyValue::Int(_) | PyValue::Bool(_) => add(v),
                _ => {}
            }
        }
    }
    if let Some(PyValue::List(pids)) = get(vuln, "Products")? {
        pids.iter().for_each(&mut add);
    }
    Ok(names.into_iter().collect())
}

/// The CVE id of one vulnerability (`(normalize_text(…) or "").upper()`).
pub fn cve_of(vuln: &PyValue) -> PyResult<String> {
    Ok(upper(
        &normalize_text(&get_or(vuln, &["CVE", "Cve", "cve"])?).unwrap_or_default(),
    ))
}

/// What `calculate_priority` returns.
#[derive(Debug, Clone, PartialEq)]
pub struct Priority {
    /// `P0` … `P3`.
    pub level: &'static str,
    /// The reasons, in order.
    pub reasons: Vec<String>,
    /// The suggested SLA.
    pub sla: &'static str,
}

const SLA_KEV: &str = "Emergency: known exploited. Patch/mitigate immediately; prioritize exposed and Tier-0 assets first.";
const SLA_P0: &str =
    "Emergency: validate mitigations immediately; deploy to highest-risk assets within 24h.";
const SLA_P1: &str = "High: deploy to pilot in 24–48h; broad rollout in 72h.";
const SLA_P2: &str =
    "Medium: deploy in the next standard patch window (7–14 days), sooner for exposed assets.";
const SLA_P3: &str =
    "Low: patch in routine maintenance (30 days) unless asset criticality dictates otherwise.";

/// `calculate_priority(severity, cvss, epss, family, in_kev)`.
pub fn calculate_priority(
    severity: Option<&str>,
    cvss: Option<f64>,
    epss: Option<f64>,
    family: &str,
    in_kev: bool,
) -> Priority {
    if in_kev {
        let mut reasons = vec!["CISA KEV (known exploited)".to_string()];
        if let Some(e) = epss {
            reasons.push(format!("EPSS={}", fixed(e, 3)));
        }
        if let Some(c) = cvss {
            reasons.push(format!("CVSS={}", fixed(c, 1)));
        }
        return Priority {
            level: "P0",
            reasons,
            sla: SLA_KEV,
        };
    }
    let sev = lower(severity.unwrap_or(""));
    let e = epss.unwrap_or(0.0);
    let s = cvss.unwrap_or(0.0);
    let core = matches!(
        family,
        "Windows" | "Windows Server" | "Office/M365" | "Exchange" | "Edge"
    );
    let critical = sev == "critical";
    if e >= 0.9 || (critical && e >= 0.7) {
        let reason = if e >= 0.9 {
            "Very high EPSS"
        } else {
            "Critical severity + high EPSS"
        };
        return Priority {
            level: "P0",
            reasons: vec![reason.to_string()],
            sla: SLA_P0,
        };
    }
    let mut reasons = Vec::new();
    if critical {
        reasons.push("Critical severity".to_string());
    }
    if s >= 8.0 {
        reasons.push("High CVSS (>= 8.0)".to_string());
    }
    if e >= 0.3 {
        reasons.push("Elevated EPSS (>= 0.3)".to_string());
    }
    if core {
        reasons.push(format!("High enterprise footprint ({family})"));
    }
    if critical || (s >= 8.0 && (e >= 0.3 || core)) {
        return Priority {
            level: "P1",
            reasons,
            sla: SLA_P1,
        };
    }
    let medium = sev == "important" || sev == "moderate";
    if medium {
        let label = match severity.filter(|s| !s.is_empty()) {
            Some(s) => title(s),
            None => "Unknown".to_string(),
        };
        reasons.push(format!("{label} severity"));
    }
    if s >= 6.0 {
        reasons.push("CVSS (>= 6.0)".to_string());
    }
    if e >= 0.1 {
        reasons.push("EPSS (>= 0.1)".to_string());
    }
    if medium || s >= 6.0 || e >= 0.1 {
        return Priority {
            level: "P2",
            reasons,
            sla: SLA_P2,
        };
    }
    Priority {
        level: "P3",
        reasons,
        sla: SLA_P3,
    }
}

/// One EPSS entry (`{"epss", "percentile", "date"}`).
#[derive(Debug, Clone, PartialEq)]
pub struct Epss {
    /// `safe_float(row["epss"])`.
    pub score: Option<f64>,
    /// `safe_float(row["percentile"])`.
    pub percentile: Option<f64>,
    /// `row.get("date")`, as it came.
    pub date: PyValue,
}

/// The rows of one EPSS answer into `out` (`for row in data.get("data", [])
/// or []`): rows read before a failure stay, as Python's loop leaves them.
pub fn read_epss_rows(data: &PyValue, out: &mut HashMap<String, Epss>) -> PyResult<()> {
    let rows = match get(data, "data")? {
        Some(v) => v.clone(),
        None => PyValue::List(Vec::new()),
    };
    let rows = or(rows, PyValue::List(Vec::new()));
    for row in iterate(&rows)? {
        let cve = or(get_or(&row, &["cve"])?, PyValue::Str(String::new()));
        let PyValue::Str(cve) = cve else {
            return Err(copilot_upstream::py::PyExc::AttributeError(format!(
                "'{}' object has no attribute 'upper'",
                copilot_upstream::py::type_name(&cve)
            )));
        };
        let cve = upper(&cve);
        if cve.is_empty() {
            continue;
        }
        let entry = Epss {
            score: safe_float(&get_or(&row, &["epss"])?),
            percentile: safe_float(&get_or(&row, &["percentile"])?),
            date: get_or(&row, &["date"])?,
        };
        out.insert(cve, entry);
    }
    Ok(())
}

/// One KEV entry (every field `normalize_text`ed).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Kev {
    /// `date_added`.
    pub date_added: Option<String>,
    /// `due_date`.
    pub due_date: Option<String>,
    /// `required_action`.
    pub required_action: Option<String>,
    /// `known_ransomware_campaign_use`.
    pub known_ransomware_campaign_use: Option<String>,
    /// `vendor_project`.
    pub vendor_project: Option<String>,
    /// `product`.
    pub product: Option<String>,
    /// `vulnerability_name`.
    pub vulnerability_name: Option<String>,
    /// `short_description`.
    pub short_description: Option<String>,
    /// `notes`.
    pub notes: Option<String>,
}

/// The KEV catalog by CVE (`fetch_kev_data` once the document is read).
pub fn read_kev(doc: &PyValue) -> PyResult<HashMap<String, Kev>> {
    let vulns = or(
        get_or(doc, &["vulnerabilities"])?,
        PyValue::List(Vec::new()),
    );
    let vulns = listed(vulns);
    let mut out = HashMap::new();
    for v in iterate(&vulns)? {
        if !matches!(v, PyValue::Dict(_)) {
            continue;
        }
        let cve =
            upper(&normalize_text(&get_or(&v, &["cveID", "cveId", "CVE"])?).unwrap_or_default());
        if !cve.starts_with("CVE-") {
            continue;
        }
        let field =
            |key: &str| -> PyResult<Option<String>> { Ok(normalize_text(&get_or(&v, &[key])?)) };
        let entry = Kev {
            date_added: field("dateAdded")?,
            due_date: field("dueDate")?,
            required_action: field("requiredAction")?,
            known_ransomware_campaign_use: field("knownRansomwareCampaignUse")?,
            vendor_project: field("vendorProject")?,
            product: field("product")?,
            vulnerability_name: field("vulnerabilityName")?,
            short_description: field("shortDescription")?,
            notes: field("notes")?,
        };
        out.insert(cve, entry);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kbs_match_like_python_re() {
        assert_eq!(
            find_kbs("q=KB5034441&x=kb1234567_ KB12345 KB123456789 xKB123456 \u{212a}b1111111"),
            vec!["KB5034441", "\u{212a}b1111111"]
        );
        assert_eq!(
            find_kbs("KB\u{661}\u{662}\u{663}\u{664}\u{665}\u{666}"),
            vec!["KB\u{661}\u{662}\u{663}\u{664}\u{665}\u{666}"]
        );
    }

    #[test]
    fn families() {
        assert_eq!(
            product_family(&PyValue::Str("Windows Server 2022".into())),
            "Windows Server"
        );
        assert_eq!(product_family(&PyValue::None), "Other");
    }
}
