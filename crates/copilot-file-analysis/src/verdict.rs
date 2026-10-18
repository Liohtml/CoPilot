//! `app/file_analysis/services/verdict.py`: the cross-tier verdict, on the
//! values Python sees (a sandbox summary and a reputation result are
//! `json.loads` dicts here, as they are once stored).
//!
//! The job verdict is the most severe of the static hint, the sandbox's and
//! VirusTotal's. A sandbox run is *malicious* only with corroboration (a
//! decoded family, a C2 endpoint from its config, a meaningful signature at
//! severity ≥ [`HIGH_SEVERITY_SIGNATURE`]), *suspicious* with any meaningful
//! signature, *clean* otherwise — environmental noise and low-confidence
//! static-PE / .NET-JIT heuristics never count ([`NOISE`],
//! [`LOW_CONFIDENCE`]). `verdict_vectors` in `file_analysis_vectors.json`
//! pins every function against the Python module.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::py::{PyExc, PyResult};
use num_bigint_dig::BigInt;

use crate::py::{
    self, empty_list, float_of, format_g, get, get_or, in_str_set, int_value, is_dict, or, str_of,
    to_list,
};

/// `"clean"`.
pub const CLEAN: &str = "clean";
/// `"suspicious"`.
pub const SUSPICIOUS: &str = "suspicious";
/// `"malicious"`.
pub const MALICIOUS: &str = "malicious";

/// `HIGH_SEVERITY_SIGNATURE`.
pub const HIGH_SEVERITY_SIGNATURE: i64 = 4;

/// `ENVIRONMENTAL_NOISE_SIGNATURES`.
pub const NOISE: &[&str] = &[
    "creates_suspended_process",
    "resumethread_remote_process",
    "reads_memory_remote_process",
    "terminates_remote_process",
    "antivm_checks_available_memory",
    "antidebug_setunhandledexceptionfilter",
    "registers_vectored_exception_handler",
    "queries_locale_api",
    "queries_keyboard_layout",
    "language_check_registry",
    "stealth_network",
    "privilege_elevation_check",
    "per_file_acl_token_check",
    "mountpoint_manager_access",
    "mountpoints_volume_discovery",
    "discover_registry_mount_points",
    "enumerates_physical_drives",
    "hardware_id_profiling",
    "dllload_suspicious_directory",
    "uses_windows_utilities",
    "driver_filtermanager",
];

/// `LOW_CONFIDENCE_SIGNATURES`.
pub const LOW_CONFIDENCE: &[&str] = &[
    "pe_cert_self_signed",
    "pe_tls_callbacks",
    "antianalysis_tls_section",
    "packer_unknown_pe_section_name",
    "contains_pe_overlay",
    "pe_compile_timestomping",
    "static_pe_pdbpath",
    "packer_entropy",
    "packer_entropy_section",
    "unbacked_privilege_escalation",
    "unbacked_process_mitigation_alteration",
    "unbacked_api_resolution",
    "unbacked_library_load",
    "unbacked_memory_protection_alteration",
    "unbacked_process_creation",
    "unbacked_com_instantiation",
    "unbacked_file_dropping",
    "unbacked_process_enumeration",
    "unbacked_registry_modification",
    "unbacked_service_manipulation",
    "unbacked_token_manipulation",
    "unbacked_bind_shell",
    "injection_rwx",
    "network_bind",
    "antidebug_guardpages",
    "query_fips_reconnaissance",
];

fn severity(v: &str) -> u8 {
    match v {
        SUSPICIOUS => 1,
        MALICIOUS => 2,
        _ => 0,
    }
}

/// `is_noise_signature(name)`: `(name or "") in ENVIRONMENTAL_NOISE_SIGNATURES`.
pub fn is_noise(name: &PyValue) -> PyResult<bool> {
    in_str_set(&or(name.clone(), py::s("")), NOISE)
}

/// `is_low_confidence_signature(name)`.
pub fn is_low_confidence(name: &PyValue) -> PyResult<bool> {
    in_str_set(&or(name.clone(), py::s("")), LOW_CONFIDENCE)
}

fn signatures(sandbox: &PyValue) -> PyResult<Vec<PyValue>> {
    let list = or(get(sandbox, "signatures")?, empty_list());
    Ok(py::iter(&list)?.into_iter().filter(is_dict).collect())
}

fn sig_name(sig: &PyValue) -> PyResult<PyValue> {
    get_or(sig, "name", py::s(""))
}

/// `meaningful_signatures(sandbox)`.
pub fn meaningful_signatures(sandbox: &PyValue) -> PyResult<Vec<PyValue>> {
    let mut out = Vec::new();
    for sig in signatures(sandbox)? {
        if !is_noise(&sig_name(&sig)?)? && !is_low_confidence(&sig_name(&sig)?)? {
            out.push(sig);
        }
    }
    Ok(out)
}

/// `noise_stats(sandbox)`: `(total, noise, low_confidence, meaningful)`.
pub fn noise_stats(sandbox: &PyValue) -> PyResult<(usize, usize, usize, i64)> {
    let sigs = signatures(sandbox)?;
    let mut noise = 0;
    for s in &sigs {
        if is_noise(&sig_name(s)?)? {
            noise += 1;
        }
    }
    let mut low = 0;
    for s in &sigs {
        if !is_noise(&sig_name(s)?)? && is_low_confidence(&sig_name(s)?)? {
            low += 1;
        }
    }
    let total = sigs.len();
    let meaningful = i64::try_from(total).unwrap_or(i64::MAX)
        - i64::try_from(noise).unwrap_or(0)
        - i64::try_from(low).unwrap_or(0);
    Ok((total, noise, low, meaningful))
}

/// `merge_verdict(static_verdict, dynamic_verdict)` on verdict strings.
pub fn merge_verdict(static_verdict: &str, dynamic: Option<&str>) -> String {
    let best = if matches!(static_verdict, CLEAN | SUSPICIOUS | MALICIOUS) {
        static_verdict
    } else {
        CLEAN
    };
    match dynamic {
        Some(d) if !d.is_empty() && severity(d) > severity(best) => d.to_string(),
        _ => best.to_string(),
    }
}

/// `_malscore(sandbox)`.
fn malscore(sandbox: &PyValue) -> PyResult<f64> {
    let raw = or(get_or(sandbox, "malscore", py::int(0))?, py::int(0));
    match float_of(&raw) {
        Ok(f) => Ok(f),
        Err(PyExc::TypeError(_) | PyExc::ValueError(_)) => Ok(0.0),
        Err(e) => Err(e),
    }
}

/// `_max_meaningful_severity(sandbox)`: `int()` of each meaningful
/// signature's severity (a `TypeError`/`ValueError` skips it; an
/// `OverflowError` is raised).
fn max_meaningful_severity(sandbox: &PyValue) -> PyResult<BigInt> {
    let mut worst = BigInt::from(0);
    for sig in meaningful_signatures(sandbox)? {
        let raw = or(get_or(&sig, "severity", py::int(0))?, py::int(0));
        match int_value(&raw) {
            Ok(n) => {
                if n > worst {
                    worst = n;
                }
            }
            Err(PyExc::TypeError(_) | PyExc::ValueError(_)) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(worst)
}

/// `dynamic_evidence(sandbox)`.
pub fn dynamic_evidence(sandbox: &PyValue) -> PyResult<Vec<String>> {
    if !sandbox.truthy() {
        return Ok(Vec::new());
    }
    let mut reasons = Vec::new();
    let family = or(get(sandbox, "family")?, get(sandbox, "malfamily")?);
    if family.truthy() {
        reasons.push(format!("malware config extracted ({})", str_of(&family)));
    }
    let mut c2 = to_list(&or(get(sandbox, "c2_ips")?, empty_list()))?;
    c2.extend(to_list(&or(get(sandbox, "c2_domains")?, empty_list()))?);
    if let Some(first) = c2.first() {
        reasons.push(format!(
            "C2 endpoint in extracted config ({})",
            str_of(first)
        ));
    }
    let worst = max_meaningful_severity(sandbox)?;
    if worst >= BigInt::from(HIGH_SEVERITY_SIGNATURE) {
        reasons.push(format!("signature at severity {worst}"));
    }
    Ok(reasons)
}

/// `dynamic_verdict_from_report(sandbox)`.
pub fn dynamic_verdict_from_report(sandbox: &PyValue) -> PyResult<&'static str> {
    if !sandbox.truthy() {
        return Ok(CLEAN);
    }
    if !dynamic_evidence(sandbox)?.is_empty() {
        return Ok(MALICIOUS);
    }
    if !meaningful_signatures(sandbox)?.is_empty() {
        return Ok(SUSPICIOUS);
    }
    Ok(CLEAN)
}

/// `explain_verdict(static_verdict, sandbox, reputation, inspector)`.
pub fn explain_verdict(
    static_verdict: &str,
    sandbox: Option<&PyValue>,
    reputation: Option<&PyValue>,
    inspector: Option<&PyValue>,
) -> PyResult<String> {
    let mut parts: Vec<String> = Vec::new();
    let incomplete = match inspector {
        Some(i) if i.truthy() => get(i, "analysis_incomplete")?.truthy(),
        _ => false,
    };
    if incomplete {
        let inspector = inspector.cloned().unwrap_or(PyValue::None);
        let error = or(
            get(&inspector, "error")?,
            py::s("inspection did not complete"),
        );
        let PyValue::Str(text) = &error else {
            return Err(PyExc::AttributeError(format!(
                "'{}' object has no attribute 'strip'",
                copilot_upstream::py::type_name(&error)
            )));
        };
        let why = py::strip(text).trim_end_matches('.');
        parts.push(format!(
            "Tier-1 static inspection incomplete ({why}) — provisional fail-closed verdict, not a \
             content-based finding"
        ));
    } else if !static_verdict.is_empty() && static_verdict != CLEAN {
        parts.push(format!("static inspection: {static_verdict}"));
    }

    if let Some(sandbox) = sandbox.filter(|s| s.truthy()) {
        let evidence = dynamic_evidence(sandbox)?;
        let score = malscore(sandbox)?;
        let (total, noise, low, meaningful) = noise_stats(sandbox)?;
        if !evidence.is_empty() {
            parts.push(format!("sandbox: {}", evidence.join(", ")));
        } else if meaningful > 0 {
            parts.push(format!(
                "sandbox: malscore {} with {meaningful} sample-driven signature(s) (no malware \
                 config, no C2, nothing above severity {})",
                format_g(score),
                HIGH_SEVERITY_SIGNATURE - 1
            ));
        } else if low > 0 {
            parts.push(format!(
                "sandbox: malscore {} is static packer / .NET-JIT heuristics only ({low}/{total} \
                 signatures fire on benign software) — no sample-specific malicious behaviour",
                format_g(score)
            ));
        } else if score > 0.0 && total > 0 {
            parts.push(format!(
                "sandbox: malscore {} is entirely environmental noise ({noise}/{total} signatures \
                 are guest/monitor baseline) — no sample-specific behaviour",
                format_g(score)
            ));
        }
    }

    if let Some(rep) = reputation.filter(|r| r.truthy()) {
        if get(rep, "found")?.truthy() {
            let mal = or(get(rep, "malicious")?, py::int(0));
            let total = or(get(rep, "total")?, py::int(0));
            let mut line = format!("VirusTotal {}/{}", str_of(&mal), str_of(&total));
            if !mal.truthy() {
                line.push_str(" — no engine flagged it");
            }
            parts.push(line);
        } else if get(rep, "submitted")?.truthy() {
            parts.push("VirusTotal scan pending".into());
        }
    }
    Ok(parts.join("; "))
}

/// `verdict_from_reputation(rep)` with `ENRICHMENT_VT_MALICIOUS_THRESHOLD`.
pub fn verdict_from_reputation(rep: Option<&PyValue>, threshold: i64) -> PyResult<&'static str> {
    let Some(rep) = rep.filter(|r| r.truthy()) else {
        return Ok(CLEAN);
    };
    if !get(rep, "found")?.truthy() {
        return Ok(CLEAN);
    }
    let malicious = int_value(&get_or(rep, "malicious", py::int(0))?)?;
    if malicious >= BigInt::from(threshold) {
        return Ok(MALICIOUS);
    }
    if malicious >= BigInt::from(1) {
        return Ok(SUSPICIOUS);
    }
    let suspicious = int_value(&get_or(rep, "suspicious", py::int(0))?)?;
    if suspicious >= BigInt::from(1) {
        return Ok(SUSPICIOUS);
    }
    Ok(CLEAN)
}

/// The orchestrator's `_merge_verdict(static, sandbox, reputation)`.
pub fn merge_all(
    static_verdict: &str,
    sandbox: Option<&PyValue>,
    reputation: Option<&PyValue>,
    threshold: i64,
) -> PyResult<String> {
    let dynamic = match sandbox {
        Some(s) if s.truthy() => Some(dynamic_verdict_from_report(s)?),
        _ => None,
    };
    let merged = merge_verdict(static_verdict, dynamic);
    Ok(merge_verdict(
        &merged,
        Some(verdict_from_reputation(reputation, threshold)?),
    ))
}
