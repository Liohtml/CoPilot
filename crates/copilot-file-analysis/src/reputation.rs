//! `services/reputation.py`: VirusTotal through the existing connector key
//! and `copilot-threat-intel`'s port of `app/threat_intel/services/
//! virustotal_file.py` (the file report, the analysis status), plus the
//! module's own raw GETs (`_vt_get`, the deep intel) and its upload
//! (`_submit`), all as httpx 0.28 sends them.
//!
//! A hash lookup never uploads: `virustotal_lookup_only` is the report, then
//! — for a hit, with `ENRICHMENT_VT_DEEP` — the full report and the VT
//! sandbox's `behaviour_summary` (`_extract_intel`, Python's operations on
//! VT's JSON; any failure there drops the intel, never the lookup). The
//! upload (`virustotal_submit_and_wait`) runs detached, only when the
//! analyst chose `reputation_mode=upload`.

use std::time::Duration;

use chrono::{DateTime, Utc};
use copilot_auth::pyvalue::PyValue;
use copilot_threat_intel::ThreatIntelState;
use copilot_threat_intel::httpx::{self, FileField, Request};
use copilot_threat_intel::services::virustotal;
use copilot_upstream::model::field;
use copilot_upstream::py::{PyExc, PyResult};
use http::Method;
use num_bigint_dig::BigInt;
use num_traits::ToPrimitive as _;

use crate::Settings;
use crate::py::{
    self, dict, empty_dict, empty_list, get, get_or, head, int_value, is_dict, or, str_of,
};

fn permalink(sha256: &str) -> PyValue {
    py::s(format!("https://www.virustotal.com/gui/file/{sha256}"))
}

/// `_vt_api_key()`: the `VirusTotal` connector's key, `None` when absent.
pub async fn api_key(st: &ThreatIntelState) -> Option<String> {
    match st.ctx.connectors.get("VirusTotal").await {
        Ok(row) => {
            let key = row
                .and_then(|r| r.connector_api_key)
                .filter(|k| !k.is_empty());
            match &key {
                Some(k) => tracing::info!(
                    "[reputation] VirusTotal API key found (len={})",
                    k.chars().count()
                ),
                None => tracing::warn!(
                    "[reputation] VirusTotal connector has NO api_key configured — skipping reputation"
                ),
            }
            key
        }
        Err(e) => {
            tracing::warn!("[reputation] failed to read VirusTotal connector key: {e}");
            None
        }
    }
}

fn not_found(sha256: &str) -> PyValue {
    dict(vec![
        ("source", py::s("virustotal")),
        ("found", PyValue::Bool(false)),
        ("sha256", py::s(sha256)),
        ("permalink", permalink(sha256)),
        ("submitted", PyValue::Bool(false)),
    ])
}

/// `isinstance(v, int)` (a `bool` is one).
fn as_int(v: &PyValue) -> Option<BigInt> {
    match v {
        PyValue::Int(i) => i.parse().ok(),
        PyValue::Bool(b) => Some(BigInt::from(u8::from(*b))),
        _ => None,
    }
}

/// `_parse_report(report, sha256)` on `FileReportResponse`'s dump.
pub(crate) fn parse_report(report: &PyValue, sha256: &str) -> PyResult<PyValue> {
    let attrs = field(field(report, "data"), "attributes");
    let stats = field(attrs, "last_analysis_stats");
    let (malicious, suspicious, total) = match stats {
        PyValue::None => (BigInt::from(0), BigInt::from(0), BigInt::from(0)),
        stats => {
            let m = int_value(&or(field(stats, "malicious").clone(), py::int(0)))?;
            let s = int_value(&or(field(stats, "suspicious").clone(), py::int(0)))?;
            let mut total = BigInt::from(0);
            if let PyValue::Dict(items) = stats {
                for (_, v) in items {
                    if let Some(n) = as_int(v) {
                        total += n;
                    }
                }
            }
            (m, s, total)
        }
    };
    let mut family = py::s("");
    let ptc = field(attrs, "popular_threat_classification");
    if is_dict(ptc) {
        family = or(get_or(ptc, "suggested_threat_label", py::s(""))?, py::s(""));
    }
    let meaningful_name = get_or(attrs, "meaningful_name", py::s(""))?;
    Ok(dict(vec![
        ("source", py::s("virustotal")),
        ("found", PyValue::Bool(true)),
        ("sha256", py::s(sha256)),
        ("malicious", PyValue::Int(malicious.to_string())),
        ("suspicious", PyValue::Int(suspicious.to_string())),
        ("total", PyValue::Int(total.to_string())),
        ("family", family),
        ("meaningful_name", meaningful_name),
        ("permalink", permalink(sha256)),
        ("submitted", PyValue::Bool(false)),
    ]))
}

/// `_lookup(api_key, sha256)`: the parsed report, `{found: false}` on a
/// 404, `None` on any other failure.
async fn lookup(st: &ThreatIntelState, key: &str, sha256: &str) -> Option<PyValue> {
    match virustotal::file_report(st, key, sha256).await {
        Ok(report) => match parse_report(&report, sha256) {
            Ok(rep) => Some(rep),
            Err(e) => {
                tracing::warn!("VirusTotal lookup error: {}", e.text());
                None
            }
        },
        Err(PyExc::Http(404, _)) => Some(not_found(sha256)),
        Err(PyExc::Http(status, detail)) => {
            tracing::warn!("VirusTotal lookup failed ({status}): {detail}");
            None
        }
        Err(e) => {
            tracing::warn!("VirusTotal lookup error: {}", e.text());
            None
        }
    }
}

fn uniq(items: Vec<PyValue>) -> Vec<PyValue> {
    let mut out: Vec<PyValue> = Vec::new();
    for x in items {
        if x.truthy() && !py::list_contains(&out, &x) {
            out.push(x);
        }
    }
    out
}

/// `_str_list(items, *keys)`.
fn str_list(items: &PyValue, keys: &[&str]) -> PyResult<Vec<PyValue>> {
    let mut out = Vec::new();
    for it in py::iter(&or(items.clone(), empty_list()))? {
        match &it {
            PyValue::Str(_) => out.push(it.clone()),
            PyValue::Dict(_) => {
                for k in keys {
                    let v = get(&it, k)?;
                    if v.truthy() {
                        out.push(match v {
                            PyValue::Str(_) => v,
                            other => py::s(str_of(&other)),
                        });
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(uniq(out))
}

fn take(items: Vec<PyValue>, n: usize) -> PyValue {
    PyValue::List(items.into_iter().take(n).collect())
}

/// `_iso(ts)`.
fn iso(ts: &PyValue) -> String {
    if !ts.truthy() {
        return String::new();
    }
    let Ok(n) = int_value(ts) else {
        return String::new();
    };
    let Some(secs) = n.to_i64() else {
        return String::new();
    };
    match DateTime::<Utc>::from_timestamp(secs, 0) {
        Some(dt) if (1..=9999).contains(&chrono::Datelike::year(&dt)) => {
            dt.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()
        }
        _ => String::new(),
    }
}

/// `_extract_intel(attrs, behaviour)`.
pub fn extract_intel(attrs: &PyValue, behaviour: &PyValue) -> PyResult<PyValue> {
    let attrs = or(attrs.clone(), empty_dict());
    let behaviour = or(behaviour.clone(), empty_dict());

    let ptc = or(get(&attrs, "popular_threat_classification")?, empty_dict());
    let mut threat_categories = Vec::new();
    for c in py::iter(&or(get(&ptc, "popular_threat_category")?, empty_list()))? {
        if is_dict(&c) && get(&c, "value")?.truthy() {
            threat_categories.push(get(&c, "value")?);
        }
    }
    let mut threat_names = Vec::new();
    for n in py::iter(&or(get(&ptc, "popular_threat_name")?, empty_list()))? {
        if is_dict(&n) && get(&n, "value")?.truthy() {
            threat_names.push(get(&n, "value")?);
        }
    }

    let results = or(get(&attrs, "last_analysis_results")?, empty_dict());
    let PyValue::Dict(engines) = &results else {
        return Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'items'",
            copilot_upstream::py::type_name(&results)
        )));
    };
    let mut detections: Vec<(bool, String, PyValue)> = Vec::new();
    for (engine, r) in engines {
        if !is_dict(r) {
            continue;
        }
        let category = get(r, "category")?;
        let wanted =
            category.as_str() == Some("malicious") || category.as_str() == Some("suspicious");
        if wanted && get(r, "result")?.truthy() {
            let name = or(get(r, "engine_name")?, py::s(engine.clone()));
            let entry = dict(vec![
                ("engine", name.clone()),
                ("result", get(r, "result")?),
                ("category", category.clone()),
            ]);
            detections.push((category.as_str() != Some("malicious"), String::new(), entry));
        }
    }
    for d in &mut detections {
        let engine = field(&d.2, "engine");
        d.1 = py::lower_of(engine)?;
    }
    detections.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    let detections: Vec<PyValue> = detections.into_iter().map(|d| d.2).collect();

    let mut yara = Vec::new();
    for y in py::iter(&or(get(&attrs, "crowdsourced_yara_results")?, empty_list()))? {
        if is_dict(&y) {
            yara.push(dict(vec![
                ("rule", get_or(&y, "rule_name", py::s(""))?),
                ("author", get_or(&y, "author", py::s(""))?),
                ("description", get_or(&y, "description", py::s(""))?),
                ("ruleset", get_or(&y, "ruleset_name", py::s(""))?),
            ]));
        }
    }
    let mut sigma = Vec::new();
    for s in py::iter(&or(get(&attrs, "sigma_analysis_results")?, empty_list()))? {
        if is_dict(&s) {
            sigma.push(dict(vec![
                ("title", get_or(&s, "rule_title", py::s(""))?),
                ("level", get_or(&s, "rule_level", py::s(""))?),
                ("source", get_or(&s, "rule_source", py::s(""))?),
            ]));
        }
    }
    let mut ids = Vec::new();
    for i in py::iter(&or(get(&attrs, "crowdsourced_ids_results")?, empty_list()))? {
        if is_dict(&i) {
            ids.push(dict(vec![
                ("msg", get_or(&i, "rule_msg", py::s(""))?),
                ("severity", get_or(&i, "alert_severity", py::s(""))?),
                ("category", get_or(&i, "rule_category", py::s(""))?),
                ("source", get_or(&i, "rule_source", py::s(""))?),
            ]));
        }
    }
    let votes = or(get(&attrs, "total_votes")?, empty_dict());
    let sig_info = or(get(&attrs, "signature_info")?, empty_dict());

    let mut mitre = Vec::new();
    for t in py::iter(&or(
        get(&behaviour, "mitre_attack_techniques")?,
        empty_list(),
    ))? {
        if is_dict(&t) && get(&t, "id")?.truthy() {
            let description = or(
                or(get(&t, "signature_description")?, get(&t, "description")?),
                py::s(""),
            );
            mitre.push(dict(vec![
                ("id", get(&t, "id")?),
                ("description", description),
                ("severity", get_or(&t, "severity", py::s(""))?),
            ]));
        }
    }
    let mut dropped = Vec::new();
    for f in py::iter(&or(get(&behaviour, "files_dropped")?, empty_list()))? {
        if is_dict(&f) {
            dropped.push(dict(vec![
                (
                    "name",
                    or(or(get(&f, "path")?, get(&f, "name")?), py::s("")),
                ),
                ("sha256", get_or(&f, "sha256", py::s(""))?),
                ("type", get_or(&f, "type", py::s(""))?),
            ]));
        }
    }
    let behaviour_out = vec![
        ("mitre", PyValue::List(mitre)),
        (
            "contacted_ips",
            take(
                str_list(&get(&behaviour, "ip_traffic")?, &["destination_ip", "ip"])?,
                60,
            ),
        ),
        (
            "contacted_domains",
            take(
                str_list(&get(&behaviour, "dns_lookups")?, &["hostname"])?,
                60,
            ),
        ),
        (
            "contacted_urls",
            take(
                str_list(&get(&behaviour, "http_conversations")?, &["url"])?,
                60,
            ),
        ),
        ("dropped_files", take(dropped, 40)),
        (
            "processes",
            take(
                str_list(&get(&behaviour, "processes_created")?, &["process"])?,
                40,
            ),
        ),
        (
            "registry_keys",
            take(
                str_list(&get(&behaviour, "registry_keys_set")?, &["key"])?,
                40,
            ),
        ),
        (
            "mutexes",
            take(str_list(&get(&behaviour, "mutexes_created")?, &[])?, 20),
        ),
        (
            "tags",
            take(
                uniq(py::iter(&or(get(&behaviour, "tags")?, empty_list()))?),
                20,
            ),
        ),
    ];
    let has_behaviour = behaviour_out
        .iter()
        .any(|(k, v)| *k != "tags" && v.truthy());

    let threat_label = or(
        get_or(&ptc, "suggested_threat_label", py::s(""))?,
        py::s(""),
    );
    let type_description = or(
        get_or(&attrs, "type_description", py::s(""))?,
        get_or(&attrs, "type_tag", py::s(""))?,
    );
    let harmless_votes = int_value(&or(get(&votes, "harmless")?, py::int(0)))?;
    let malicious_votes = int_value(&or(get(&votes, "malicious")?, py::int(0)))?;
    let verified = get(&sig_info, "verified")?;
    let signed = verified.as_str() == Some("Signed") || get(&sig_info, "product")?.truthy();
    let signer = or(
        or(get(&sig_info, "signers")?, get(&sig_info, "product")?),
        py::s(""),
    );
    let names = take(uniq(py::iter(&or(get(&attrs, "names")?, empty_list()))?), 8);
    let detection_count = detections.len();
    Ok(dict(vec![
        ("threat_label", threat_label),
        ("threat_categories", PyValue::List(uniq(threat_categories))),
        ("threat_names", PyValue::List(uniq(threat_names))),
        ("type_description", type_description),
        ("size", get(&attrs, "size")?),
        ("reputation", get(&attrs, "reputation")?),
        ("harmless_votes", PyValue::Int(harmless_votes.to_string())),
        ("malicious_votes", PyValue::Int(malicious_votes.to_string())),
        ("times_submitted", get(&attrs, "times_submitted")?),
        (
            "first_seen",
            py::s(iso(&get(&attrs, "first_submission_date")?)),
        ),
        (
            "last_analysis",
            py::s(iso(&get(&attrs, "last_analysis_date")?)),
        ),
        ("signed", PyValue::Bool(signed)),
        ("signer", signer),
        ("names", names),
        ("detections", take(detections, 40)),
        (
            "detection_count",
            py::int(i64::try_from(detection_count).unwrap_or(i64::MAX)),
        ),
        ("yara", take(yara, 20)),
        ("sigma", take(sigma, 20)),
        ("ids", take(ids, 20)),
        (
            "behaviour",
            if has_behaviour {
                dict(behaviour_out)
            } else {
                PyValue::None
            },
        ),
    ]))
}

/// `_vt_get(api_key, path)`: `None` on a 404, the JSON otherwise.
async fn vt_get(st: &ThreatIntelState, key: &str, path: &str) -> PyResult<Option<PyValue>> {
    let resp = httpx::send(
        Request::new(Method::GET, format!("{}{path}", st.urls.virustotal))
            .header("x-apikey", Some(key))
            .timeout(Duration::from_secs(30)),
    )
    .await
    .map_err(|e| e.into_py())?;
    if resp.status == 404 {
        return Ok(None);
    }
    resp.raise_for_status().map_err(|e| e.into_py())?;
    Ok(Some(resp.json()?))
}

/// `_fetch_vt_intel(api_key, sha256)`.
async fn fetch_intel(st: &ThreatIntelState, key: &str, sha256: &str) -> PyResult<PyValue> {
    let report = vt_get(st, key, &format!("/files/{sha256}")).await?;
    let report = or(report.unwrap_or(PyValue::None), empty_dict());
    let data = or(get(&report, "data")?, empty_dict());
    let attrs = or(get(&data, "attributes")?, empty_dict());
    let behaviour = match vt_get(st, key, &format!("/files/{sha256}/behaviour_summary")).await {
        Ok(b) => {
            let b = or(b.unwrap_or(PyValue::None), empty_dict());
            match get(&b, "data") {
                Ok(d) => or(d, empty_dict()),
                Err(e) => {
                    tracing::debug!(
                        "[reputation] VT behaviour_summary unavailable: {}",
                        e.text()
                    );
                    empty_dict()
                }
            }
        }
        Err(e) => {
            tracing::debug!(
                "[reputation] VT behaviour_summary unavailable: {}",
                e.text()
            );
            empty_dict()
        }
    };
    extract_intel(&attrs, &behaviour)
}

/// `_attach_intel(api_key, rep)`.
async fn attach_intel(
    settings: &Settings,
    st: &ThreatIntelState,
    key: &str,
    rep: PyValue,
) -> PyValue {
    let sha = field(&rep, "sha256").clone();
    if !(settings.vt_deep && rep.truthy() && field(&rep, "found").truthy() && sha.truthy()) {
        return rep;
    }
    match fetch_intel(st, key, &str_of(&sha)).await {
        Ok(intel) => {
            let PyValue::Dict(mut pairs) = rep else {
                return rep;
            };
            match pairs.iter_mut().find(|(k, _)| k == "intel") {
                Some(slot) => slot.1 = intel,
                None => pairs.push(("intel".into(), intel)),
            }
            PyValue::Dict(pairs)
        }
        Err(e) => {
            tracing::warn!("[reputation] VT deep intel failed: {}", e.text());
            rep
        }
    }
}

/// `virustotal_lookup_only(sha256)`.
pub async fn lookup_only(
    settings: &Settings,
    st: &ThreatIntelState,
    sha256: &str,
) -> Option<PyValue> {
    tracing::info!(
        "[reputation] VirusTotal hash lookup for {}",
        sha256.chars().take(16).collect::<String>()
    );
    let key = api_key(st).await?;
    let rep = lookup(st, &key, sha256).await?;
    if field(&rep, "found").truthy() {
        return Some(attach_intel(settings, st, &key, rep).await);
    }
    Some(rep)
}

/// `_submit(api_key, data, filename)`: the analysis id, or `None`.
async fn submit(st: &ThreatIntelState, key: &str, data: &[u8], filename: &str) -> Option<PyValue> {
    let filename = if filename.is_empty() {
        "sample"
    } else {
        filename
    };
    tracing::info!(
        "Submitting {filename} ({} bytes) to VirusTotal for analysis",
        data.len()
    );
    let sent = httpx::send(
        Request::new(Method::POST, format!("{}/files", st.urls.virustotal))
            .header("accept", Some("application/json"))
            .header("x-apikey", Some(key))
            .multipart(
                Vec::new(),
                vec![FileField {
                    name: "file".into(),
                    filename: Some(filename.to_string()),
                    content_type: "application/octet-stream".into(),
                    content: data.to_vec(),
                }],
            )
            .timeout(Duration::from_secs(300)),
    )
    .await;
    let outcome = (|| -> PyResult<PyValue> {
        let resp = sent.map_err(|e| e.into_py())?;
        resp.raise_for_status().map_err(|e| e.into_py())?;
        let body = resp.json()?;
        let data = copilot_upstream::py::getitem(&body, "data")?;
        Ok(copilot_upstream::py::getitem(data, "id")?.clone())
    })();
    match outcome {
        Ok(id) => Some(id),
        Err(e) => {
            tracing::warn!("VirusTotal submit failed: {}", e.text());
            None
        }
    }
}

/// `_wait_for_analysis(api_key, analysis_id)`.
async fn wait_for_analysis(
    settings: &Settings,
    st: &ThreatIntelState,
    key: &str,
    id: &str,
) -> bool {
    let mut waited = 0;
    while waited < settings.vt_max_wait {
        match virustotal::analysis_status(st, key, id).await {
            Ok(status) => {
                let state = field(field(field(&status, "data"), "attributes"), "status");
                if state.as_str() == Some("completed") {
                    return true;
                }
            }
            Err(e) => {
                tracing::warn!("VT analysis status check failed: {}", e.text());
                return false;
            }
        }
        tokio::time::sleep(Duration::from_secs(
            u64::try_from(settings.vt_poll).unwrap_or(0),
        ))
        .await;
        waited += settings.vt_poll;
    }
    tracing::warn!(
        "VT analysis {id} did not complete within {}s",
        settings.vt_max_wait
    );
    false
}

/// `virustotal_submit_and_wait(sha256, sample_bytes, filename)`.
pub async fn submit_and_wait(
    settings: &Settings,
    st: &ThreatIntelState,
    sha256: &str,
    sample: &[u8],
    filename: &str,
) -> Option<PyValue> {
    let key = api_key(st).await?;
    if sample.is_empty() {
        return None;
    }
    let cap = i128::from(settings.vt_max_upload_mb) * 1024 * 1024;
    if i128::try_from(sample.len()).unwrap_or(i128::MAX) > cap {
        return Some(dict(vec![
            ("source", py::s("virustotal")),
            ("found", PyValue::Bool(false)),
            ("sha256", py::s(sha256)),
            ("submitted", PyValue::Bool(false)),
            (
                "note",
                py::s(format!(
                    "exceeds {}MB VT upload cap; not submitted",
                    settings.vt_max_upload_mb
                )),
            ),
            ("permalink", permalink(sha256)),
        ]));
    }
    let Some(analysis_id) = submit(st, &key, sample, filename)
        .await
        .filter(PyValue::truthy)
    else {
        return Some(dict(vec![
            ("source", py::s("virustotal")),
            ("found", PyValue::Bool(false)),
            ("sha256", py::s(sha256)),
            ("submitted", PyValue::Bool(false)),
            ("note", py::s("VirusTotal submission failed")),
            ("permalink", permalink(sha256)),
        ]));
    };
    wait_for_analysis(settings, st, &key, &str_of(&analysis_id)).await;
    if let Some(final_rep) = lookup(st, &key, sha256).await {
        if field(&final_rep, "found").truthy() {
            let mut rep = final_rep;
            if let PyValue::Dict(pairs) = &mut rep {
                if let Some(slot) = pairs.iter_mut().find(|(k, _)| k == "submitted") {
                    slot.1 = PyValue::Bool(true);
                }
            }
            return Some(attach_intel(settings, st, &key, rep).await);
        }
    }
    Some(dict(vec![
        ("source", py::s("virustotal")),
        ("found", PyValue::Bool(false)),
        ("sha256", py::s(sha256)),
        ("submitted", PyValue::Bool(true)),
        (
            "note",
            py::s("uploaded to VirusTotal — still processing; open the permalink for live results"),
        ),
        ("permalink", permalink(sha256)),
    ]))
}

/// The orchestrator's "off" sentinel.
pub fn skipped() -> PyValue {
    dict(vec![
        ("source", py::s("virustotal")),
        ("skipped", PyValue::Bool(true)),
        (
            "note",
            py::s("VirusTotal was turned off for this analysis."),
        ),
    ])
}

/// The orchestrator's placeholder while the detached upload runs.
pub fn pending(sha256: &str) -> PyValue {
    dict(vec![
        ("source", py::s("virustotal")),
        ("found", PyValue::Bool(false)),
        ("sha256", py::s(sha256)),
        ("submitted", PyValue::Bool(true)),
        ("note", py::s("uploading to VirusTotal — scan in progress…")),
        ("permalink", permalink(sha256)),
    ])
}

/// `head` re-exported for the report builder.
pub fn cap(value: &PyValue, n: usize) -> PyResult<PyValue> {
    head(value, n)
}
