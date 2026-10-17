//! `app/connectors/wazuh_manager/services/mitre.py:AtomicRedTeamService`:
//! the Atomic Red Team listings fetched from GitHub over aiohttp, and the
//! process's caches of them (24 hours, as Python's class attributes: each
//! process — Python's, this one — keeps its own).
//!
//! The listing reads the repository's markdown index (`| [name](link) | id |
//! count |` rows); when that is not a 200 it falls back to the GitHub API's
//! folder listing and each technique's YAML (then its markdown), five at a
//! time. A technique's markdown is fetched on demand. Failures keep Python's
//! texts and its double wrap (`Error listing atomic tests: 500: Error
//! listing atomic tests: …` from the fallback).
//!
//! `COPILOT_GITHUB_RAW_URL` / `COPILOT_GITHUB_API_URL` (tests only, as the
//! Detections Catalog's) replace `https://raw.githubusercontent.com` and
//! `https://api.github.com`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use num_bigint_dig::BigInt;
use regex::Regex;

use copilot_searches::py;
use copilot_upstream::py::PyExc;
use copilot_yaml::Value;

use crate::aiohttp::AioHttp;

/// The markdown index.
pub const INDEX_URL: &str = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/refs/heads/master/atomics/Indexes/Indexes-Markdown/atomic-red-team-index.md";
/// `GITHUB_RAW_URL`.
pub const GITHUB_RAW_URL: &str =
    "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/refs/heads/master/atomics";
/// The API's folder listing (the fallback).
pub const CONTENTS_URL: &str =
    "https://api.github.com/repos/redcanaryco/atomic-red-team/contents/atomics";
/// `CACHE_EXPIRY` (seconds).
pub const CACHE_EXPIRY: f64 = 86_400.0;

const RAW_HOST: &str = "https://raw.githubusercontent.com";
const API_HOST: &str = "https://api.github.com";

/// The index's rows (`technique_pattern`, Python's `\s` being `str.isspace`).
const INDEX_PATTERN: &str = r"\|[\s\x1c-\x1f]*\[([^\]]+)\]\([^)]+\)[\s\x1c-\x1f]*\|[\s\x1c-\x1f]*([T\d\.]+)[\s\x1c-\x1f]*\|[\s\x1c-\x1f]*(\d+)[\s\x1c-\x1f]*\|";

/// `time.time()`.
fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// `datetime.isoformat()` of a naive date-time with microseconds.
fn isoformat(dt: chrono::NaiveDateTime) -> String {
    let micros = dt.and_utc().timestamp_subsec_micros();
    let base = dt.format("%Y-%m-%dT%H:%M:%S").to_string();
    if micros == 0 {
        base
    } else {
        format!("{base}.{micros:06}")
    }
}

/// `datetime.utcnow().isoformat()`.
pub fn utcnow_iso() -> String {
    isoformat(chrono::Utc::now().naive_utc())
}

/// `datetime.fromtimestamp(ts).isoformat()`: local time, the fraction
/// rounded half-even to microseconds as CPython rounds it.
pub fn fromtimestamp_iso(ts: f64) -> String {
    let secs = ts.floor();
    let frac = ts - secs;
    let mut us = (frac * 1e6).round_ties_even();
    let mut secs = secs as i64;
    if us >= 1_000_000.0 {
        secs += 1;
        us -= 1_000_000.0;
    }
    let Some(utc) = chrono::DateTime::from_timestamp(secs, (us as u32) * 1000) else {
        return String::new();
    };
    isoformat(utc.with_timezone(&chrono::Local).naive_local())
}

/// What `list_all_atomic_tests()` returns.
#[derive(Debug, Clone)]
pub struct Listing {
    /// `tests`.
    pub tests: Vec<Value>,
    /// `total_tests` (absent from a cached answer: `None`).
    pub total_tests: Option<BigInt>,
    /// `last_updated`.
    pub last_updated: String,
}

/// The service and its caches.
#[derive(Debug)]
pub struct AtomicService {
    http: AioHttp,
    raw_base: Option<String>,
    api_base: Option<String>,
    tests: Mutex<Option<(Vec<Value>, f64)>>,
    markdown: Mutex<HashMap<String, (String, f64)>>,
    index: Regex,
}

/// `HTTPException(500, f"Error listing atomic tests: {e}")`.
fn listing_error(e: &PyExc) -> PyExc {
    PyExc::Http(500, format!("Error listing atomic tests: {}", e.display()))
}

impl AtomicService {
    /// The service, with the test-only URL overrides.
    pub fn new(raw_base: Option<String>, api_base: Option<String>) -> Result<Self, String> {
        Ok(Self {
            http: AioHttp::new().map_err(|e| e.to_string())?,
            raw_base: raw_base.map(|b| b.trim_end_matches('/').to_string()),
            api_base: api_base.map(|b| b.trim_end_matches('/').to_string()),
            tests: Mutex::new(None),
            markdown: Mutex::new(HashMap::new()),
            index: Regex::new(INDEX_PATTERN).map_err(|e| e.to_string())?,
        })
    }

    /// Where a request to one of Python's URLs goes.
    fn url(&self, url: &str) -> String {
        for (host, base) in [(RAW_HOST, &self.raw_base), (API_HOST, &self.api_base)] {
            if let (Some(rest), Some(base)) = (url.strip_prefix(host), base) {
                return format!("{base}{rest}");
            }
        }
        url.to_string()
    }

    /// `list_all_atomic_tests()` (no OS category: the route never passes
    /// one).
    pub async fn list_all(&self) -> Result<Listing, PyExc> {
        let cached = self.tests.lock().ok().and_then(|g| g.clone());
        if let Some((tests, ts)) = cached {
            if now() - ts < CACHE_EXPIRY {
                return Ok(Listing {
                    tests,
                    total_tests: None,
                    last_updated: fromtimestamp_iso(ts),
                });
            }
        }
        let outcome = async {
            let answer = self.http.get(&self.url(INDEX_URL), &[]).await?;
            if answer.status == 200 {
                let text = answer.text()?;
                return Ok(self.parse_index(&text));
            }
            tracing::warn!(
                "Could not fetch atomic-red-team-index.md: {}. Trying alternate method.",
                answer.status
            );
            self.folders_listing().await
        }
        .await;
        outcome.map_err(|e| {
            tracing::error!("Error listing atomic tests: {}", e.display());
            listing_error(&e)
        })
    }

    fn remember(&self, tests: &[Value]) {
        if let Ok(mut g) = self.tests.lock() {
            *g = Some((tests.to_vec(), now()));
        }
    }

    /// `_parse_atomic_index_markdown(content)`.
    fn parse_index(&self, content: &str) -> Listing {
        let mut tests = Vec::new();
        let mut total = BigInt::from(0);
        for caps in self.index.captures_iter(content) {
            let name = caps.get(1).map_or("", |m| m.as_str());
            let id = caps.get(2).map_or("", |m| m.as_str());
            let count_text = caps.get(3).map_or("", |m| m.as_str());
            let Ok(count) = copilot_yaml::pyint::parse_int(count_text, 10) else {
                continue;
            };
            total += count.clone();
            tests.push(py::dict(vec![
                ("technique_id", py::s(id)),
                ("technique_name", py::s(name)),
                ("test_count", Value::Int(count)),
                ("categories", py::list(Vec::new())),
                ("has_prerequisites", Value::Bool(false)),
            ]));
        }
        self.remember(&tests);
        Listing {
            tests,
            total_tests: Some(total),
            last_updated: utcnow_iso(),
        }
    }

    /// `_fetch_techniques_from_atomics_folder()`.
    async fn folders_listing(&self) -> Result<Listing, PyExc> {
        let outcome: Result<Listing, PyExc> = async {
            let answer = self
                .http
                .get(
                    &self.url(CONTENTS_URL),
                    &[("Accept", "application/vnd.github.v3+json")],
                )
                .await?;
            if answer.status != 200 {
                tracing::error!("GitHub API error: {}", answer.status);
                return Err(PyExc::Http(
                    answer.status,
                    "Could not access Atomic Red Team repository".into(),
                ));
            }
            let folders = py::from_py(&answer.json()?);
            let mut ids = Vec::new();
            for f in py::iterate(&folders)? {
                if !py::getitem(&f, "type")?.py_eq(&py::s("dir")) {
                    continue;
                }
                let name = py::getitem(&f, "name")?;
                let Value::Str(name) = name else {
                    return Err(py::no_attr(&name, "startswith"));
                };
                if name.starts_with('T') {
                    ids.push(name);
                }
            }
            let results: Vec<Result<(Option<Value>, BigInt), PyExc>> =
                futures::stream::iter(ids.into_iter().map(|id| self.technique(id)))
                    .buffered(5)
                    .collect()
                    .await;
            let mut tests = Vec::new();
            let mut total = BigInt::from(0);
            for r in results {
                let (data, counted) = r?;
                total += counted;
                if let Some(t) = data {
                    let positive =
                        matches!(t.get("test_count"), Some(Value::Int(n)) if *n > BigInt::from(0));
                    if positive {
                        tests.push(t);
                    }
                }
            }
            self.remember(&tests);
            Ok(Listing {
                tests,
                total_tests: Some(total),
                last_updated: utcnow_iso(),
            })
        }
        .await;
        outcome.map_err(|e| {
            tracing::error!("Error fetching atomic tests from GitHub: {}", e.display());
            listing_error(&e)
        })
    }

    /// `process_technique(folder)`: the technique's summary and what it adds
    /// to `total_tests`.
    async fn technique(&self, id: String) -> Result<(Option<Value>, BigInt), PyExc> {
        let yaml_url = self.url(&format!("{GITHUB_RAW_URL}/{id}/{id}.yaml"));
        let md_url = self.url(&format!("{GITHUB_RAW_URL}/{id}/{id}.md"));
        let yaml = self.http.get(&yaml_url, &[]).await?;
        if yaml.status == 200 {
            let text = yaml.text()?;
            match summary_of_yaml(&id, &text) {
                Ok((data, count)) => return Ok((Some(data), count)),
                Err(e) => tracing::warn!("Error parsing YAML for {id}: {}", e.display()),
            }
        }
        let md = self.http.get(&md_url, &[]).await?;
        if md.status == 200 {
            let text = md.text()?;
            let (data, count) = summary_of_markdown(&id, &text);
            return Ok((Some(data), count));
        }
        Ok((
            Some(py::dict(vec![
                ("technique_id", py::s(id.clone())),
                ("technique_name", py::s(id)),
                ("test_count", py::int(0)),
                ("categories", py::list(Vec::new())),
                ("has_prerequisites", Value::Bool(false)),
            ])),
            BigInt::from(0),
        ))
    }

    /// `get_technique_markdown(technique_id)`: `None` for anything but a
    /// 200 whose text decodes.
    pub async fn technique_markdown(&self, id: &str) -> Option<String> {
        let cached = self.markdown.lock().ok().and_then(|g| g.get(id).cloned());
        if let Some((content, ts)) = cached {
            if now() - ts < CACHE_EXPIRY {
                return Some(content);
            }
        }
        let url = self.url(&format!("{GITHUB_RAW_URL}/{id}/{id}.md"));
        tracing::info!("Fetching Atomic Red Team markdown from {url}");
        let answer = match self.http.get(&url, &[]).await {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("Error fetching markdown for {id}: {}", e.display());
                return None;
            }
        };
        match answer.status {
            200 => match answer.text() {
                Ok(content) => {
                    if let Ok(mut g) = self.markdown.lock() {
                        g.insert(id.to_string(), (content.clone(), now()));
                    }
                    Some(content)
                }
                Err(e) => {
                    tracing::error!(
                        "Unexpected error fetching markdown for {id}: {}",
                        e.display()
                    );
                    None
                }
            },
            404 => {
                tracing::warn!("Atomic Red Team markdown not found for technique {id}");
                None
            }
            status => {
                tracing::error!("Failed to fetch markdown for {id}: {status}");
                None
            }
        }
    }
}

/// `set.update(items)` on an insertion-ordered set (Python's iteration
/// order follows the hashes, randomised per process for `str`).
fn set_update(set: &mut Vec<(String, Value)>, items: &Value) -> Result<(), PyExc> {
    for item in py::iterate(items)? {
        let key = py::hash_key(&item)?;
        if !set.iter().any(|(k, _)| *k == key) {
            set.push((key, item));
        }
    }
    Ok(())
}

/// The YAML branch of `process_technique`: any exception falls back to the
/// markdown.
pub fn summary_of_yaml(id: &str, text: &str) -> Result<(Value, BigInt), PyExc> {
    let data =
        copilot_yaml::safe_load(text).map_err(|e| PyExc::Other("YAMLError", format!("{e:?}")))?;
    let tests = py::get(&data, "atomic_tests", py::list(Vec::new()))?;
    let test_count = py::len(&tests)?;
    let mut platforms: Vec<(String, Value)> = Vec::new();
    let mut has_prereqs = false;
    for test in py::iterate(&py::get(&data, "atomic_tests", py::list(Vec::new()))?)? {
        if py::get_none(&test, "supported_platforms")?.truthy() {
            set_update(
                &mut platforms,
                &py::get(&test, "supported_platforms", py::list(Vec::new()))?,
            )?;
        }
        if py::get_none(&test, "dependencies")?.truthy() {
            has_prereqs = true;
        }
    }
    let name = py::get(&data, "display_name", py::s(id))?;
    let count = BigInt::from(test_count);
    Ok((
        py::dict(vec![
            ("technique_id", py::s(id)),
            ("technique_name", name),
            ("test_count", Value::Int(count.clone())),
            (
                "categories",
                py::list(platforms.into_iter().map(|(_, v)| v).collect()),
            ),
            ("has_prerequisites", Value::Bool(has_prereqs)),
        ]),
        count,
    ))
}

/// The markdown branch of `process_technique`.
pub fn summary_of_markdown(id: &str, text: &str) -> (Value, BigInt) {
    let name = Regex::new(r"# ([^\n]+)")
        .ok()
        .and_then(|re| re.captures(text))
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
        .unwrap_or_else(|| id.to_string());
    let count = Regex::new(r"## Atomic Test #\d+")
        .map(|re| re.find_iter(text).count())
        .unwrap_or(0);
    let lower = copilot_jinja::unicode::lower(text);
    let mut platforms = Vec::new();
    if lower.contains("windows") {
        platforms.push(py::s("windows"));
    }
    if lower.contains("macos") || lower.contains("darwin") {
        platforms.push(py::s("macos"));
    }
    if lower.contains("linux") {
        platforms.push(py::s("linux"));
    }
    let technique_name = py::py_strip(&name.replace(&format!("- {id}"), "")).to_string();
    let count = BigInt::from(count);
    (
        py::dict(vec![
            ("technique_id", py::s(id)),
            ("technique_name", py::s(technique_name)),
            ("test_count", Value::Int(count.clone())),
            ("categories", py::list(platforms)),
            (
                "has_prerequisites",
                Value::Bool(lower.contains("dependency") || lower.contains("dependencies")),
            ),
        ]),
        count,
    )
}

/// One shared service per process.
pub type Shared = Arc<AtomicService>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_index_is_read_as_python_reads_it() {
        let svc = AtomicService::new(None, None).unwrap();
        let content = "| [OS Credential Dumping](./T1003/T1003.md) | T1003 | 12 |\n\
                       |[x](y)|T1.2|  3  |\n| [bad](z) | T9 | x |\n\
                       | [Unicode](u) | T7 | \u{0663} |";
        let l = svc.parse_index(content);
        let ids: Vec<String> = l
            .tests
            .iter()
            .map(|t| t.get("technique_id").unwrap().py_str())
            .collect();
        assert_eq!(ids, vec!["T1003", "T1.2", "T7"]);
        assert_eq!(l.total_tests, Some(BigInt::from(18)));
    }

    #[test]
    fn yaml_and_markdown_summaries() {
        let (v, n) = summary_of_yaml(
            "T1",
            "display_name: Dump\natomic_tests:\n- supported_platforms: [windows, linux, windows]\n  \
             dependencies: [x]\n- name: b\n",
        )
        .unwrap();
        assert_eq!(n, BigInt::from(2));
        assert_eq!(
            v.get("categories").unwrap().py_repr(),
            "['windows', 'linux']"
        );
        assert!(summary_of_yaml("T1", "- a").is_err());
        let (m, c) = summary_of_markdown(
            "T2",
            "# Thing - T2\n## Atomic Test #1\n## Atomic Test #2\nLinux and Darwin",
        );
        assert_eq!(c, BigInt::from(2));
        assert_eq!(m.get("technique_name").unwrap().py_str(), "Thing");
        assert_eq!(m.get("categories").unwrap().py_repr(), "['macos', 'linux']");
    }

    /// `_parse_atomic_index_markdown` against Python's
    /// (`scripts/gen-wazuh-rules-vectors.py`).
    #[test]
    fn index_vectors() {
        #[derive(serde::Deserialize)]
        struct Vectors {
            index: Vec<serde_json::Value>,
        }
        let v: Vectors =
            serde_json::from_str(include_str!("wazuh_rules_vectors.json")).expect("vectors");
        let svc = AtomicService::new(None, None).unwrap();
        for probe in v.index {
            let text = probe["text"].as_str().unwrap();
            let l = svc.parse_index(text);
            let parsed = &probe["parsed"];
            assert_eq!(
                serde_json::json!(l.tests.len()),
                parsed["total_techniques"],
                "{text:?}"
            );
            assert_eq!(
                l.total_tests.map(|t| t.to_string()),
                Some(parsed["total_tests"].to_string()),
                "{text:?}"
            );
            let tests = py::list(l.tests).to_pydantic_json().unwrap();
            let got: serde_json::Value = serde_json::from_str(&tests).unwrap();
            assert_eq!(got, parsed["tests"], "{text:?}");
        }
    }

    #[test]
    fn timestamps_follow_cpython() {
        let s = fromtimestamp_iso(0.0);
        assert!(!s.contains('.'), "{s}");
    }
}
