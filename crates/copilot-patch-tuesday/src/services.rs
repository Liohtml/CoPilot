//! `services/microsoft_patch_tuesday.py`: the fetches (MSRC's CVRF document,
//! FIRST's EPSS scores in chunks, CISA's KEV catalog — httpx 0.28, a client
//! per call, 60 s) and what the routes make of them. Nothing is cached:
//! every request asks the three feeds again, as Python does.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::time::Duration;

use chrono::{Datelike, NaiveDate};
use copilot_auth::pyvalue::PyValue;
use copilot_threat_intel::httpx::{self, Request};
use copilot_upstream::model::{construct, kwargs};
use copilot_upstream::py::{PyExc, PyResult};
use http::Method;

use crate::cvrf::{
    Epss, Kev, MONTH_ABBR, build_product_lookup, calculate_priority, chunk_by_max_chars, cve_of,
    extract_affected_products, extract_cvss, extract_kbs, extract_severity, product_family,
    read_epss_rows, read_kev,
};
use crate::py::{
    get_or, iterate, listed, lower, lstrip, normalize_text, or, runtime_error, strip, title, upper,
};
use crate::schema::{EPSS_INFO, Item, Summary, bump, sorted_counts};
use crate::urls::Urls;

/// `fetch_json(url, params)`: one GET, its JSON, or a `RuntimeError`.
pub trait Fetch: Sync {
    /// Fetch `url` with `params=`.
    fn fetch_json(
        &self,
        url: &str,
        params: Option<Vec<(String, String)>>,
    ) -> impl Future<Output = PyResult<PyValue>> + Send;
}

/// The feeds over httpx, as `fetch_json` asks them.
#[derive(Debug, Clone, Copy, Default)]
pub struct Http;

/// What `json.loads(bytes)` raises: `JSONDecodeError`, or the
/// `UnicodeDecodeError` of bytes that are not UTF-8 (both `ValueError`s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadsError {
    /// `json.JSONDecodeError`'s `str()`.
    Json(String),
    /// `UnicodeDecodeError`'s `str()`.
    Unicode(String),
}

impl std::fmt::Display for LoadsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadsError::Json(t) | LoadsError::Unicode(t) => f.write_str(t),
        }
    }
}

/// `json.loads(content)` of `bytes` (`json.detect_encoding`, then the
/// parse): the value, or what it raises. The one Rust definition: the
/// ScoutSuite upload reads its file with it too.
pub fn json_loads_bytes(content: &[u8]) -> Result<PyValue, LoadsError> {
    let utf8 = content.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(content);
    let zero_led = |n: usize| content.len() == n || (n == 4 && content.len() > 4);
    let wide = content.starts_with(&[0xff, 0xfe])
        || content.starts_with(&[0xfe, 0xff])
        || ((zero_led(4) || zero_led(2)) && (content[0] == 0 || content[1] == 0));
    if wide {
        // UTF-16/32 (`json.detect_encoding`): parsed, but a document that
        // fails reads as the first character's error.
        return copilot_auth::pyvalue::loads_bytes(content)
            .map_err(|_| LoadsError::Json("Expecting value: line 1 column 1 (char 0)".into()));
    }
    let text = std::str::from_utf8(utf8)
        .map_err(|_| LoadsError::Unicode(copilot_yaml::pyint::utf8_decode_error(utf8)))?;
    copilot_upstream::json::py_loads(text).map_err(LoadsError::Json)
}

/// `text[:n]`.
fn head(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

impl Fetch for Http {
    async fn fetch_json(
        &self,
        url: &str,
        params: Option<Vec<(String, String)>>,
    ) -> PyResult<PyValue> {
        let mut req = Request::new(Method::GET, url)
            .header("Accept", Some("application/json"))
            .header("User-Agent", Some("CoPilot-PatchTuesday/1.0"))
            .timeout(Duration::from_secs(60));
        if let Some(params) = params {
            req = req.params(params);
        }
        let response = httpx::send(req)
            .await
            .map_err(|e| PyExc::Other(e.class, e.message))?;
        let text = response.text();
        if response.status != 200 {
            return Err(runtime_error(format!(
                "GET {url} failed: HTTP {} - {}",
                response.status,
                head(&text, 300)
            )));
        }
        let ctype = lower(
            &response
                .headers
                .get_all(http::header::CONTENT_TYPE)
                .iter()
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                .collect::<Vec<_>>()
                .join(", "),
        );
        if !ctype.contains("application/json") && lstrip(&text).starts_with('<') {
            return Err(runtime_error(format!(
                "Endpoint returned non-JSON (Content-Type: {ctype}). The MSRC API may have \
                 returned XML instead of JSON."
            )));
        }
        json_loads_bytes(&response.content).map_err(|e| {
            runtime_error(format!(
                "Response was not valid JSON: {e}. First 300 chars: {}",
                head(&text, 300)
            ))
        })
    }
}

/// The two clocks the module reads: `date.today()` (local) and the UTC
/// `now` stamped on the items.
pub trait Clock: Sync {
    /// `dt.date.today()`.
    fn today(&self) -> NaiveDate;
    /// `datetime.now(timezone.utc)` without microseconds, `Z`-suffixed.
    fn now_utc(&self) -> String;
}

/// The process's clocks.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn today(&self) -> NaiveDate {
        chrono::Local::now().date_naive()
    }

    fn now_utc(&self) -> String {
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }
}

/// `second_tuesday(year, month)` (`ValueError` outside `date`'s range).
pub fn second_tuesday(year: i64, month: u32) -> PyResult<NaiveDate> {
    let first = i32::try_from(year)
        .ok()
        .filter(|y| (1..=9999).contains(y))
        .and_then(|y| NaiveDate::from_ymd_opt(y, month, 1))
        .ok_or_else(|| PyExc::ValueError(format!("year {year} is out of range")))?;
    let weekday = i64::from(first.weekday().num_days_from_monday());
    let to_tuesday = (1 - weekday).rem_euclid(7);
    Ok(first + chrono::Duration::days(to_tuesday + 7))
}

/// `get_default_cycle(today)`.
pub fn default_cycle(today: NaiveDate) -> String {
    let month = today.month0() as usize;
    format!("{}-{}", today.year(), MONTH_ABBR[month])
}

/// `parse_cycle(cycle)`: `(year, month, normalized)`.
pub fn parse_cycle(cycle: &str) -> PyResult<(i64, u32, String)> {
    let invalid = || PyExc::ValueError("Cycle must be in format YYYY-Mmm (e.g., 2026-Jan)".into());
    let chars: Vec<char> = strip(cycle).chars().collect();
    if chars.len() != 8
        || chars[4] != '-'
        || !chars[..4]
            .iter()
            .all(|c| copilot_jinja::unicode::is_decimal(*c))
        || !chars[5..].iter().all(char::is_ascii_alphabetic)
    {
        return Err(invalid());
    }
    let mut year: i64 = 0;
    for c in &chars[..4] {
        year =
            year * 10 + i64::from(copilot_jinja::unicode::decimal_value(*c).ok_or_else(invalid)?);
    }
    let mon = title(&chars[5..].iter().collect::<String>());
    let Some(index) = MONTH_ABBR.iter().position(|m| *m == mon) else {
        return Err(PyExc::ValueError(format!(
            "Invalid month abbreviation '{mon}'. Use one of: {}",
            MONTH_ABBR.join(", ")
        )));
    };
    let month = u32::try_from(index + 1).unwrap_or(1);
    Ok((year, month, format!("{year}-{mon}")))
}

/// `fetch_epss_scores(cves)`: every chunk asked in turn, a failed chunk
/// skipped.
pub async fn fetch_epss_scores<F: Fetch>(
    fetch: &F,
    urls: &Urls,
    cves: &[String],
) -> HashMap<String, Epss> {
    let mut out = HashMap::new();
    let wanted: BTreeSet<String> = cves
        .iter()
        .filter(|c| !c.is_empty() && !strip(c).is_empty())
        .map(|c| upper(strip(c)))
        .collect();
    if wanted.is_empty() {
        return out;
    }
    let wanted: Vec<String> = wanted.into_iter().collect();
    tracing::info!("Fetching EPSS scores for {} CVEs", wanted.len());
    for chunk in chunk_by_max_chars(&wanted, 1900) {
        let params = vec![("cve".to_string(), chunk.join(","))];
        let result = match fetch.fetch_json(&urls.epss, Some(params)).await {
            Ok(data) => read_epss_rows(&data, &mut out),
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            tracing::warn!("Error fetching EPSS chunk: {}", e.display());
        }
    }
    tracing::info!("Retrieved EPSS scores for {} CVEs", out.len());
    out
}

/// `fetch_kev_data()`: the catalog by CVE (empty when the fetch fails; a
/// document of an odd shape fails as Python's loop does).
pub async fn fetch_kev_data<F: Fetch>(fetch: &F, urls: &Urls) -> PyResult<HashMap<String, Kev>> {
    tracing::info!("Fetching CISA KEV data");
    let doc = match fetch.fetch_json(&urls.kev, None).await {
        Ok(doc) => doc,
        Err(e) => {
            tracing::error!("Failed to fetch KEV data: {}", e.display());
            return Ok(HashMap::new());
        }
    };
    let out = read_kev(&doc)?;
    tracing::info!("Loaded {} CVEs from CISA KEV", out.len());
    Ok(out)
}

/// What `fetch_patch_tuesday_data` returns: the prioritised items and the
/// summary.
#[derive(Debug, Clone)]
pub struct Data {
    /// The items, sorted.
    pub items: Vec<Item>,
    /// The summary.
    pub summary: Summary,
}

fn sort_key_cmp(a: &Item, b: &Item) -> std::cmp::Ordering {
    let rank = |i: &Item| match i.priority.level {
        "P0" => 0,
        "P1" => 1,
        "P2" => 2,
        "P3" => 3,
        _ => 9,
    };
    // `-(score or 0.0)`; Python's tuple `<` compares what is not `==`.
    let neg = |v: Option<f64>| -v.filter(|f| *f != 0.0).unwrap_or(0.0);
    rank(a)
        .cmp(&rank(b))
        .then_with(|| {
            neg(a.epss_score)
                .partial_cmp(&neg(b.epss_score))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .then_with(|| {
            neg(a.cvss_base)
                .partial_cmp(&neg(b.cvss_base))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .then_with(|| a.cve.cmp(&b.cve))
        .then_with(|| a.product.cmp(&b.product))
}

/// `fetch_patch_tuesday_data(cycle, include_epss, include_kev)`.
pub async fn fetch_patch_tuesday_data<F: Fetch, C: Clock>(
    fetch: &F,
    clock: &C,
    urls: &Urls,
    cycle: Option<&str>,
    include_epss: bool,
    include_kev: bool,
) -> PyResult<Data> {
    let (year, month, cycle_norm) = match cycle.filter(|c| !c.is_empty()) {
        Some(c) => parse_cycle(c)?,
        None => parse_cycle(&default_cycle(clock.today()))?,
    };
    let pt_date = second_tuesday(year, month)?;
    let url = format!("{}/{cycle_norm}", urls.msrc);
    tracing::info!(
        "Fetching Patch Tuesday data for cycle {cycle_norm} (date: {})",
        pt_date.format("%Y-%m-%d")
    );
    let doc = fetch.fetch_json(&url, None).await?;
    let lookup = build_product_lookup(&doc)?;
    let vulns = listed(or(
        get_or(&doc, &["Vulnerability", "Vulnerabilities"])?,
        PyValue::List(Vec::new()),
    ));
    let vulns = iterate(&vulns)?;
    let mut cves_all = Vec::new();
    for v in &vulns {
        if matches!(v, PyValue::Dict(_)) {
            let cve = cve_of(v)?;
            if cve.starts_with("CVE-") {
                cves_all.push(cve);
            }
        }
    }
    let epss_map = if include_epss {
        fetch_epss_scores(fetch, urls, &cves_all).await
    } else {
        HashMap::new()
    };
    let kev_map = if include_kev {
        fetch_kev_data(fetch, urls).await?
    } else {
        HashMap::new()
    };
    let now = clock.now_utc();
    let mut items = Vec::new();
    let mut prio = [0usize; 4];
    let mut families: Vec<(String, usize)> = Vec::new();
    let mut severities: Vec<(String, usize)> = Vec::new();
    for v in &vulns {
        if !matches!(v, PyValue::Dict(_)) {
            continue;
        }
        let cve = cve_of(v)?;
        if !cve.starts_with("CVE-") {
            continue;
        }
        let title = normalize_text(&get_or(v, &["Title", "title"])?);
        let severity = extract_severity(v)?;
        let (cvss_base, cvss_vector) = extract_cvss(v)?;
        let kbs = extract_kbs(v)?;
        let mut products = extract_affected_products(v, &lookup)?;
        if products.is_empty() {
            products.push("(Unknown product mapping)".to_string());
        }
        let epss = epss_map.get(&cve);
        let (epss_score, epss_pct, epss_date) = match epss {
            Some(e) => (e.score, e.percentile, e.date.clone()),
            None => (None, None, PyValue::None),
        };
        let kev = kev_map.get(&cve);
        let in_kev = kev.is_some();
        if let Some(sev) = &severity {
            bump(&mut severities, sev);
        }
        for product in products {
            let product = normalize_text(&PyValue::Str(product.clone())).unwrap_or(product);
            let family = product_family(&PyValue::Str(product.clone()));
            bump(&mut families, family);
            let priority =
                calculate_priority(severity.as_deref(), cvss_base, epss_score, family, in_kev);
            let slot = match priority.level {
                "P0" => 0,
                "P1" => 1,
                "P2" => 2,
                _ => 3,
            };
            prio[slot] += 1;
            let epss_dump = construct(
                &EPSS_INFO,
                &kwargs(vec![
                    ("score", epss_score.map_or(PyValue::None, PyValue::Float)),
                    ("percentile", epss_pct.map_or(PyValue::None, PyValue::Float)),
                    ("date", epss_date.clone()),
                ]),
            )?;
            items.push(Item {
                cycle: cycle_norm.clone(),
                cve: cve.clone(),
                title: title.clone(),
                severity: severity.clone(),
                cvss_base,
                cvss_vector: cvss_vector.clone(),
                epss: epss_dump,
                epss_score,
                in_kev,
                kev: kev.cloned().unwrap_or_default(),
                product,
                family,
                kbs: kbs.clone(),
                priority,
                cvrf_url: url.clone(),
                kev_url: urls.kev.clone(),
                timestamp: now.clone(),
            });
        }
    }
    items.sort_by(sort_key_cmp);
    let unique: BTreeSet<&str> = items.iter().map(|i| i.cve.as_str()).collect();
    let summary = Summary {
        cycle: cycle_norm.clone(),
        patch_tuesday_date: pt_date.format("%Y-%m-%d").to_string(),
        generated_utc: now,
        unique_cves: unique.len(),
        total_records: items.len(),
        by_priority: prio,
        by_family: sorted_counts(families),
        by_severity: sorted_counts(severities),
    };
    tracing::info!(
        "Processed {} unique CVEs, {} total records for cycle {cycle_norm}",
        summary.unique_cves,
        summary.total_records
    );
    Ok(Data { items, summary })
}

/// `PatchTuesdayResponse` as the services build it.
#[derive(Debug, Clone)]
pub struct PtResponse {
    /// `success`.
    pub success: bool,
    /// `message`.
    pub message: String,
    /// `summary`.
    pub summary: Option<Summary>,
    /// `items`.
    pub items: Vec<Item>,
}

impl PtResponse {
    /// A failure: no summary, no items.
    pub fn failed(message: String) -> Self {
        Self {
            success: false,
            message,
            summary: None,
            items: Vec::new(),
        }
    }

    /// The model's dump.
    pub fn dump(&self) -> PyValue {
        crate::schema::response(
            self.success,
            self.message.clone(),
            self.summary.as_ref(),
            &self.items,
        )
    }
}

/// `get_patch_tuesday(request)`.
pub async fn get_patch_tuesday<F: Fetch, C: Clock>(
    fetch: &F,
    clock: &C,
    urls: &Urls,
    cycle: Option<&str>,
    include_epss: bool,
    include_kev: bool,
) -> PtResponse {
    match fetch_patch_tuesday_data(fetch, clock, urls, cycle, include_epss, include_kev).await {
        Ok(data) => PtResponse {
            success: true,
            message: format!(
                "Successfully retrieved {} CVEs for cycle {}",
                data.summary.unique_cves, data.summary.cycle
            ),
            summary: Some(data.summary),
            items: data.items,
        },
        Err(e) if e.is_value_error() => {
            tracing::error!("Invalid request: {}", e.text());
            PtResponse::failed(e.text())
        }
        Err(e) => {
            tracing::error!("Error fetching Patch Tuesday data: {}", e.display());
            PtResponse::failed(format!(
                "Failed to fetch Patch Tuesday data: {}",
                e.display()
            ))
        }
    }
}

/// `get_patch_tuesday_summary(request, top_n)`: the response model's dump.
pub async fn get_patch_tuesday_summary<F: Fetch, C: Clock>(
    fetch: &F,
    clock: &C,
    urls: &Urls,
    cycle: Option<&str>,
    include_epss: bool,
    include_kev: bool,
    top_n: usize,
) -> PyValue {
    match fetch_patch_tuesday_data(fetch, clock, urls, cycle, include_epss, include_kev).await {
        Ok(data) => crate::schema::summary_response(
            true,
            format!(
                "Successfully retrieved summary for cycle {}",
                data.summary.cycle
            ),
            Some(&data.summary),
            &data.items[..top_n.min(data.items.len())],
        ),
        Err(e) if e.is_value_error() => {
            tracing::error!("Invalid request: {}", e.text());
            crate::schema::summary_response(false, e.text(), None, &[])
        }
        Err(e) => {
            tracing::error!("Error fetching Patch Tuesday summary: {}", e.display());
            crate::schema::summary_response(
                false,
                format!("Failed to fetch Patch Tuesday summary: {}", e.display()),
                None,
                &[],
            )
        }
    }
}

/// `get_available_cycles()`: the response model's dump.
pub fn get_available_cycles<C: Clock>(clock: &C) -> PyValue {
    let today = clock.today();
    let current = default_cycle(today);
    let built = (|| -> Result<(Vec<String>, NaiveDate), String> {
        let mut cycles: Vec<String> = Vec::new();
        for i in 0..12 {
            let d = today
                .checked_sub_signed(chrono::Duration::days(i * 30))
                .filter(|d| d.year() >= 1)
                .ok_or_else(|| "date value out of range".to_string())?;
            let cycle = default_cycle(d);
            if !cycles.contains(&cycle) {
                cycles.push(cycle);
            }
        }
        let (year, month, _) = parse_cycle(&current).map_err(|e| e.text())?;
        let pt = second_tuesday(year, month).map_err(|e| e.text())?;
        let next = if today > pt {
            let (y, m) = if month == 12 {
                (year + 1, 1)
            } else {
                (year, month + 1)
            };
            second_tuesday(y, m).map_err(|e| e.text())?
        } else {
            pt
        };
        Ok((cycles, next))
    })();
    match built {
        Ok((cycles, next)) => crate::schema::cycles_response(
            true,
            "Successfully retrieved available cycles".into(),
            &cycles,
            &current,
            &next.format("%Y-%m-%d").to_string(),
        ),
        Err(e) => {
            tracing::error!("Error getting available cycles: {e}");
            crate::schema::cycles_response(
                false,
                format!("Failed to get available cycles: {e}"),
                &[],
                &current,
                "",
            )
        }
    }
}

/// `search_cves_in_patch_tuesday(cve_ids, cycle, product)`.
pub async fn search_cves<F: Fetch, C: Clock>(
    fetch: &F,
    clock: &C,
    urls: &Urls,
    cve_ids: &[String],
    cycle: Option<&str>,
    product: Option<&str>,
) -> PtResponse {
    let response = get_patch_tuesday(fetch, clock, urls, cycle, true, true).await;
    if !response.success {
        return response;
    }
    let wanted: BTreeSet<String> = cve_ids.iter().map(|c| upper(c)).collect();
    let mut matching: Vec<Item> = response
        .items
        .iter()
        .filter(|i| wanted.contains(&upper(&i.cve)))
        .cloned()
        .collect();
    if let Some(product) = product {
        matching.retain(|i| i.product == product);
    }
    let summary = match (&response.summary, matching.is_empty()) {
        (Some(full), false) => {
            let mut prio = [0usize; 4];
            let mut families = Vec::new();
            for item in &matching {
                let slot = match item.priority.level {
                    "P0" => 0,
                    "P1" => 1,
                    "P2" => 2,
                    _ => 3,
                };
                prio[slot] += 1;
                bump(&mut families, item.family);
            }
            let unique: BTreeSet<&str> = matching.iter().map(|i| i.cve.as_str()).collect();
            Some(Summary {
                cycle: full.cycle.clone(),
                patch_tuesday_date: full.patch_tuesday_date.clone(),
                generated_utc: full.generated_utc.clone(),
                unique_cves: unique.len(),
                total_records: matching.len(),
                by_priority: prio,
                by_family: sorted_counts(families),
                by_severity: full.by_severity.clone(),
            })
        }
        _ => None,
    };
    PtResponse {
        success: true,
        message: format!(
            "Found {} items matching {} CVE(s)",
            matching.len(),
            cve_ids.len()
        ),
        summary,
        items: matching,
    }
}
