//! `app/threat_intel/services/epss.py:collect_epss_scores`: the EPSS score of
//! each CVE, asked of api.first.org 100 CVEs a request, best-effort — a
//! batch that fails is logged and left out, so the CSV keeps an empty
//! column instead of failing.
//!
//! The request is httpx's: `GET {EPSS_URL}?cve=A%2CB&limit=100` (the values
//! `quote_plus`-ed), 15 s, redirects not followed. `COPILOT_EPSS_URL`
//! replaces the URL for the parity harness, as `COPILOT_VERSION_CHECK_URL`
//! does for the release check (Python's `EPSS_URL` is a module constant the
//! harness patches).

use std::collections::BTreeSet;
use std::time::Duration;

use copilot_auth::pyvalue::{PyValue, loads};
use copilot_upstream::py::{PyExc, PyResult, type_name};

/// `EPSS_URL`.
pub const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
/// `EPSS_BATCH_SIZE`.
pub const BATCH: usize = 100;
const TIMEOUT: Duration = Duration::from_secs(15);

/// `urllib.parse.quote_plus(s, safe="")` (what httpx applies to a query value).
pub fn quote_plus(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The client (no redirects, the timeout of `httpx.AsyncClient(timeout=15)`).
#[derive(Debug, Clone)]
pub struct EpssClient {
    http: reqwest::Client,
    url: String,
}

impl EpssClient {
    /// With `COPILOT_EPSS_URL` or the public API.
    pub fn new() -> Result<Self, reqwest::Error> {
        let url = std::env::var("COPILOT_EPSS_URL")
            .ok()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| EPSS_URL.to_string());
        Self::with_url(url)
    }

    /// Against `url`.
    pub fn with_url(url: String) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .build()?;
        Ok(Self { http, url })
    }

    /// `collect_epss_scores(cves)`: CVE → score. An answer that is JSON but
    /// not a dict (or a row that is not one) is Python's `AttributeError`,
    /// which nothing catches.
    pub async fn scores(&self, cves: &[String]) -> PyResult<Vec<(String, PyValue)>> {
        let unique: BTreeSet<&str> = cves
            .iter()
            .map(String::as_str)
            .filter(|c| !c.is_empty())
            .collect();
        let unique: Vec<&str> = unique.into_iter().collect();
        let mut scores: Vec<(String, PyValue)> = Vec::new();
        for batch in unique.chunks(BATCH) {
            let url = format!(
                "{}?cve={}&limit={BATCH}",
                self.url,
                quote_plus(&batch.join(","))
            );
            let body = match self.fetch(&url).await {
                Ok(b) => b,
                Err(kind) => {
                    tracing::warn!(
                        "EPSS lookup failed for {} CVE(s), leaving their scores empty: {kind}",
                        batch.len()
                    );
                    continue;
                }
            };
            let Ok(doc) = loads(&body) else {
                tracing::warn!(
                    "EPSS lookup failed for {} CVE(s), leaving their scores empty: JSONDecodeError",
                    batch.len()
                );
                continue;
            };
            let PyValue::Dict(_) = doc else {
                return Err(PyExc::AttributeError(format!(
                    "'{}' object has no attribute 'get'",
                    type_name(&doc)
                )));
            };
            let rows = doc
                .get("data")
                .cloned()
                .unwrap_or(PyValue::List(Vec::new()));
            let rows = match rows {
                PyValue::List(items) => items,
                PyValue::Dict(items) => items.into_iter().map(|(k, _)| PyValue::Str(k)).collect(),
                PyValue::Str(s) => s.chars().map(|c| PyValue::Str(c.to_string())).collect(),
                other => {
                    return Err(PyExc::TypeError(format!(
                        "'{}' object is not iterable",
                        type_name(&other)
                    )));
                }
            };
            for row in rows {
                let PyValue::Dict(_) = row else {
                    return Err(PyExc::AttributeError(format!(
                        "'{}' object has no attribute 'get'",
                        type_name(&row)
                    )));
                };
                let cve = row.get("cve").cloned().unwrap_or(PyValue::None);
                let epss = row.get("epss").cloned().unwrap_or(PyValue::None);
                if cve.truthy() && !matches!(epss, PyValue::None) {
                    let key = cve.py_str();
                    match scores.iter_mut().find(|(k, _)| *k == key) {
                        Some(slot) => slot.1 = epss,
                        None => scores.push((key, epss)),
                    }
                }
            }
        }
        Ok(scores)
    }

    /// One GET with `raise_for_status()`; `Err` is the httpx exception's class.
    async fn fetch(&self, url: &str) -> Result<String, &'static str> {
        let resp = self.http.get(url).send().await.map_err(|e| {
            if e.is_timeout() {
                "ReadTimeout"
            } else {
                "ConnectError"
            }
        })?;
        if !resp.status().is_success() {
            return Err("HTTPStatusError");
        }
        resp.text().await.map_err(|_| "ReadError")
    }
}

/// httpx's own `User-Agent`.
const HTTPX_USER_AGENT: &str = "python-httpx/0.28.1";
/// `httpx.AsyncClient()`'s default timeout.
const HTTPX_DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

impl EpssClient {
    /// `get_epss_score_for_cve(cve)` of the vulnerability search and its CSV
    /// report: `collect_epss_score` over `invoke_epss_api`, one request per
    /// CVE — `GET {EPSS_URL}?cve=…` from a fresh `httpx.AsyncClient()` (5 s,
    /// httpx's headers and a `content-type: application/json`), no
    /// `raise_for_status()`. `(epss, percentile)` of the answer's first row
    /// when it is a dict with `status-code` 200 whose `data` rows all validate
    /// as `EpssData`; `(None, None)` for anything else, as every exception is
    /// swallowed there.
    pub async fn score_for_cve(&self, cve: &str) -> (Option<String>, Option<String>) {
        let url = format!("{}?cve={}", self.url, quote_plus(cve));
        tracing::info!(
            "Invoking EPSS with params: {{'cve': '{cve}'}} and headers: {{'content-type': \
             'application/json'}} and url: {}",
            self.url
        );
        let body = match self.fetch_any_status(&url).await {
            Ok(body) => body,
            Err(kind) => {
                tracing::warn!("Error fetching EPSS score for CVE {cve}: {kind}");
                return (None, None);
            }
        };
        let doc = match copilot_auth::pyvalue::loads_bytes(&body) {
            Ok(doc) => doc,
            Err(_) => {
                tracing::warn!("Error fetching EPSS score for CVE {cve}: JSONDecodeError");
                return (None, None);
            }
        };
        match first_epss_row(&doc) {
            Some(pair) => (Some(pair.0), Some(pair.1)),
            None => {
                tracing::debug!("No EPSS data found for CVE: {cve}");
                (None, None)
            }
        }
    }

    /// One GET as `httpx.AsyncClient().get(url, headers=…)` sends it; the
    /// body whatever the status (gzip and deflate decoded as httpx does).
    async fn fetch_any_status(&self, url: &str) -> Result<Vec<u8>, &'static str> {
        let resp = self
            .http
            .get(url)
            .timeout(HTTPX_DEFAULT_TIMEOUT)
            .header("accept", "*/*")
            .header("accept-encoding", "gzip, deflate")
            .header("connection", "keep-alive")
            .header("user-agent", HTTPX_USER_AGENT)
            .header("content-type", "application/json")
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    "ReadTimeout"
                } else {
                    "ConnectError"
                }
            })?;
        let encoding = resp
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let raw = resp.bytes().await.map_err(|_| "ReadError")?;
        decode_body(&encoding, &raw).ok_or("DecodingError")
    }
}

/// httpx's `gzip` / `deflate` decoders (`None` is its `DecodingError`).
fn decode_body(encoding: &str, raw: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let mut out = Vec::new();
    match encoding {
        "gzip" | "x-gzip" => {
            flate2::read::MultiGzDecoder::new(raw)
                .read_to_end(&mut out)
                .ok()?;
        }
        "deflate" => {
            if flate2::read::ZlibDecoder::new(raw)
                .read_to_end(&mut out)
                .is_err()
            {
                out.clear();
                flate2::read::DeflateDecoder::new(raw)
                    .read_to_end(&mut out)
                    .ok()?;
            }
        }
        _ => return Some(raw.to_vec()),
    }
    Some(out)
}

/// `collect_epss_score`'s checks on `response.json()`: a dict whose
/// `status-code` equals 200, `data` (default `[]`) a list of dicts that all
/// validate as `EpssData` (`cve`, `epss`, `percentile`, `date`: `str`), and
/// at least one of them. Anything else raised there and was swallowed.
fn first_epss_row(doc: &PyValue) -> Option<(String, String)> {
    let PyValue::Dict(_) = doc else {
        return None;
    };
    let ok = match doc.get("status-code") {
        Some(PyValue::Int(i)) => i == "200",
        Some(PyValue::Float(f)) => *f == 200.0,
        _ => false,
    };
    if !ok {
        return None;
    }
    let rows = match doc.get("data") {
        None => return None,
        Some(PyValue::List(items)) => items,
        Some(_) => return None,
    };
    let mut first = None;
    for row in rows {
        let PyValue::Dict(_) = row else {
            return None;
        };
        let text = |k: &str| match row.get(k) {
            Some(PyValue::Str(s)) => Some(s.clone()),
            _ => None,
        };
        let (Some(_), Some(epss), Some(percentile), Some(_)) =
            (text("cve"), text("epss"), text("percentile"), text("date"))
        else {
            return None;
        };
        first.get_or_insert((epss, percentile));
    }
    first
}

/// `epss_scores.get(cve or "", "")`.
pub fn score_of(scores: &[(String, PyValue)], cve: &str) -> String {
    scores
        .iter()
        .find(|(k, _)| k == cve)
        .map(|(_, v)| v.py_str())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_cve_answer_is_read_as_collect_epss_score_reads_it() {
        let row = |extra: &str| {
            copilot_auth::pyvalue::loads(&format!(
                r#"{{"status-code": 200, "data": [{{"cve": "CVE-1", "epss": "0.5", "percentile": "0.9", "date": "2026-01-01"}}{extra}]}}"#
            ))
            .unwrap()
        };
        assert_eq!(
            first_epss_row(&row("")),
            Some(("0.5".to_string(), "0.9".to_string()))
        );
        assert_eq!(first_epss_row(&row(", 5")), None);
        assert_eq!(first_epss_row(&row(r#", {"cve": "x"}"#)), None);
        let empty = copilot_auth::pyvalue::loads(r#"{"status-code": 200.0, "data": []}"#).unwrap();
        assert_eq!(first_epss_row(&empty), None);
        let refused = copilot_auth::pyvalue::loads(r#"{"status-code": 429}"#).unwrap();
        assert_eq!(first_epss_row(&refused), None);
    }

    #[test]
    fn query_values_are_quoted_as_httpx_does() {
        assert_eq!(
            quote_plus("CVE-2021-1,CVE-2021-2 x+y/é"),
            "CVE-2021-1%2CCVE-2021-2+x%2By%2F%C3%A9"
        );
    }
}
