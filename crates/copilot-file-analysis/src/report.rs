//! `services/report_pdf.py`: the analyst PDF of a stored result.
//! `build_context` shapes the result with Python's operations on its values
//! (a `str` that is sliced, a list of non-strings joined, a severity that
//! cannot be negated fail as they fail in Python), `templates/report.html`
//! is rendered by `copilot-jinja` with autoescaping and Jinja2's default
//! `Undefined` (a copy compiled in, pinned to the backend's file by a test),
//! and wkhtmltopdf turns it into the PDF (`crate::pdf`).

use base64::Engine as _;
use chrono::Utc;
use copilot_auth::pyvalue::PyValue;
use copilot_jinja::Input;
use copilot_upstream::py::{PyExc, PyResult};

use crate::py::{self, dict, empty_dict, empty_list, get, get_or, head, iter, or, str_of};
use crate::verdict;

/// `templates/report.html`.
pub const TEMPLATE: &str = include_str!("../templates/report.html");

const MAX_SNIPPET: usize = 6000;
const MAX_LIST: usize = 200;
const MAX_STRINGS: usize = 120;

/// `_clip(text, limit)`.
fn clip(text: &PyValue, limit: usize) -> PyValue {
    let s = match text {
        PyValue::None => String::new(),
        other => str_of(other),
    };
    let len = s.chars().count();
    if len > limit {
        let head: String = s.chars().take(limit).collect();
        py::s(format!(
            "{head}\n… (+{} more chars, see raw report)",
            len - limit
        ))
    } else {
        py::s(s)
    }
}

/// `_fmt_verdict(v)`.
fn fmt_verdict(v: &PyValue) -> PyResult<PyValue> {
    let lowered = py::lower_of(&or(v.clone(), py::s("")))?;
    let row = |label: &str, color: &str, bg: &str, dark: &str, soft: &str| {
        dict(vec![
            ("label", py::s(label)),
            ("color", py::s(color)),
            ("bg", py::s(bg)),
            ("dark", py::s(dark)),
            ("soft", py::s(soft)),
        ])
    };
    Ok(match lowered.as_str() {
        "malicious" => row("MALICIOUS", "#dc2626", "#fef2f2", "#7f1d1d", "#fecaca"),
        "suspicious" => row("SUSPICIOUS", "#d97706", "#fffbeb", "#78350f", "#fde68a"),
        "clean" => row("CLEAN", "#16a34a", "#f0fdf4", "#14532d", "#bbf7d0"),
        other => {
            let shown = if other.is_empty() {
                "UNKNOWN".to_string()
            } else {
                py::upper(other)
            };
            row(&shown, "#64748b", "#f1f5f9", "#334155", "#cbd5e1")
        }
    })
}

/// `_dedup_connections(conns)`.
fn dedup_connections(conns: &PyValue) -> PyResult<PyValue> {
    type Row = (String, Vec<(String, PyValue)>, i64);
    let mut seen: Vec<Row> = Vec::new();
    for c in iter(&or(conns.clone(), empty_list()))? {
        let proto = py::lower_of(&or(get(&c, "proto")?, py::s("")))?;
        let dst = or(get(&c, "dst")?, py::s(""));
        let dport = get(&c, "dport")?;
        let key = format!("{proto}|{}|{}", str_of(&dst), str_of(&dport));
        match seen.iter_mut().find(|(k, _, _)| *k == key) {
            Some(row) => row.2 += 1,
            None => seen.push((
                key,
                vec![
                    ("proto".into(), py::s(proto)),
                    ("dst".into(), dst),
                    ("dport".into(), dport),
                ],
                1,
            )),
        }
    }
    seen.sort_by_key(|a| std::cmp::Reverse(a.2));
    Ok(PyValue::List(
        seen.into_iter()
            .take(MAX_LIST)
            .map(|(_, mut row, count)| {
                row.push(("count".into(), py::int(count)));
                PyValue::Dict(row)
            })
            .collect(),
    ))
}

/// `sorted(rows, key=lambda r: -(r.get("severity") or 0))`.
fn sort_by_severity(rows: Vec<PyValue>) -> PyResult<Vec<PyValue>> {
    let mut keyed = Vec::with_capacity(rows.len());
    for r in rows {
        let k = py::neg_key(&or(get(&r, "severity")?, py::int(0)))?;
        keyed.push((k, r));
    }
    keyed.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    Ok(keyed.into_iter().map(|(_, r)| r).collect())
}

/// `_split_signatures(sigs)`.
fn split_signatures(sigs: &PyValue) -> PyResult<PyValue> {
    let (mut meaningful, mut low, mut noise) = (Vec::new(), Vec::new(), Vec::new());
    for s in iter(&or(sigs.clone(), empty_list()))? {
        let name = get_or(&s, "name", py::s(""))?;
        let row = dict(vec![
            ("name", name.clone()),
            ("description", or(get(&s, "description")?, py::s(""))),
            ("severity", get(&s, "severity")?),
            (
                "mitre",
                py::s(py::join(", ", &or(get(&s, "mitre")?, empty_list()))?),
            ),
        ]);
        if get(&s, "noise")?.truthy() || verdict::is_noise(&name)? {
            noise.push(row);
        } else if get(&s, "low_confidence")?.truthy() || verdict::is_low_confidence(&name)? {
            low.push(row);
        } else {
            meaningful.push(row);
        }
    }
    Ok(dict(vec![
        ("meaningful", PyValue::List(sort_by_severity(meaningful)?)),
        ("low_confidence", PyValue::List(sort_by_severity(low)?)),
        ("noise", PyValue::List(sort_by_severity(noise)?)),
    ]))
}

fn capped(value: PyValue, n: usize) -> PyResult<PyValue> {
    head(&or(value, empty_list()), n)
}

/// `_static_section(inspector)`.
fn static_section(inspector: &PyValue) -> PyResult<PyValue> {
    let content = or(get(inspector, "content")?, empty_dict());
    let iocs = or(get(inspector, "iocs")?, empty_dict());
    let behaviors = or(get(&content, "behaviors")?, empty_list());
    let mut highlights = Vec::new();
    for (label, key) in [
        ("Deobfuscated script", "deobfuscated"),
        ("Extracted macros (VBA)", "macros"),
        ("Embedded JavaScript", "javascript"),
        ("DDE command", "dde"),
        ("LNK target", "target"),
        ("LNK arguments", "arguments"),
    ] {
        let val = get(&content, key)?;
        if val.truthy() {
            highlights.push(dict(vec![
                ("label", py::s(label)),
                ("text", clip(&val, MAX_SNIPPET)),
            ]));
        }
    }
    let mut behavior_rows = Vec::new();
    for b in iter(&behaviors)? {
        behavior_rows.push(dict(vec![
            ("attack_id", get(&b, "attack_id")?),
            ("technique", get(&b, "technique")?),
            ("severity", get(&b, "severity")?),
            ("evidence", clip(&get(&b, "evidence")?, 300)),
        ]));
    }
    let av = get(inspector, "av")?;
    Ok(dict(vec![
        ("filetype", get(inspector, "filetype")?),
        ("magic", get(inspector, "magic")?),
        ("entropy", get(inspector, "entropy")?),
        ("extension_mismatch", get(inspector, "extension_mismatch")?),
        (
            "analysis_incomplete",
            get(inspector, "analysis_incomplete")?,
        ),
        ("verdict_hint", get(inspector, "verdict_hint")?),
        ("flags", or(get(inspector, "flags")?, empty_list())),
        ("av", if av.truthy() { av } else { PyValue::None }),
        (
            "iocs",
            dict(vec![
                ("urls", capped(get(&iocs, "urls")?, MAX_LIST)?),
                ("ips", capped(get(&iocs, "ips")?, MAX_LIST)?),
                ("domains", capped(get(&iocs, "domains")?, MAX_LIST)?),
            ]),
        ),
        ("behaviors", PyValue::List(behavior_rows)),
        ("highlights", PyValue::List(highlights)),
        (
            "autoexec_keywords",
            capped(get(&content, "autoexec_keywords")?, MAX_LIST)?,
        ),
        (
            "suspicious_keywords",
            capped(get(&content, "suspicious_keywords")?, MAX_LIST)?,
        ),
        (
            "capabilities",
            capped(get(&content, "capabilities")?, MAX_LIST)?,
        ),
        ("imports", capped(get(&content, "imports")?, MAX_LIST)?),
        ("import_count", get(&content, "import_count")?),
        ("sections", or(get(&content, "sections")?, empty_list())),
        ("strings", capped(get(&content, "strings")?, MAX_STRINGS)?),
        (
            "pdf_metadata",
            or(get(&content, "pdf_metadata")?, empty_dict()),
        ),
    ]))
}

/// `_sandbox_section(sandbox)`.
fn sandbox_section(sandbox: &PyValue) -> PyResult<PyValue> {
    let behavior = or(get(sandbox, "behavior")?, empty_dict());
    let PyValue::Dict(categories) = &behavior else {
        return Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'items'",
            copilot_upstream::py::type_name(&behavior)
        )));
    };
    let mut behavior_view = Vec::new();
    for (k, v) in categories {
        if v.truthy() {
            behavior_view.push((k.clone(), head(&or(v.clone(), empty_list()), MAX_LIST)?));
        }
    }
    Ok(dict(vec![
        ("task_id", get(sandbox, "task_id")?),
        ("malscore", get(sandbox, "malscore")?),
        ("family", get(sandbox, "family")?),
        ("verdict", get(sandbox, "verdict")?),
        ("machine", get(sandbox, "machine")?),
        ("duration", get(sandbox, "duration")?),
        ("package", get(sandbox, "package")?),
        (
            "signatures",
            split_signatures(&or(get(sandbox, "signatures")?, empty_list()))?,
        ),
        ("c2_ips", or(get(sandbox, "c2_ips")?, empty_list())),
        ("c2_domains", or(get(sandbox, "c2_domains")?, empty_list())),
        ("hosts", capped(get(sandbox, "hosts")?, MAX_LIST)?),
        ("domains", capped(get(sandbox, "domains")?, MAX_LIST)?),
        ("dead_hosts", or(get(sandbox, "dead_hosts")?, empty_list())),
        ("dns", capped(get(sandbox, "dns")?, MAX_LIST)?),
        ("http", capped(get(sandbox, "http")?, MAX_LIST)?),
        (
            "connections",
            dedup_connections(&or(get(sandbox, "connections")?, empty_list()))?,
        ),
        ("processes", capped(get(sandbox, "processes")?, MAX_LIST)?),
        ("dropped", capped(get(sandbox, "dropped")?, MAX_LIST)?),
        ("ttps", capped(get(sandbox, "ttps")?, MAX_LIST)?),
        ("behavior", PyValue::Dict(behavior_view)),
        ("errors", or(get(sandbox, "errors")?, empty_list())),
    ]))
}

/// `_reputation_section(rep)`.
fn reputation_section(rep: &PyValue) -> PyResult<PyValue> {
    let intel = or(get(rep, "intel")?, empty_dict());
    Ok(dict(vec![
        ("skipped", get(rep, "skipped")?),
        ("found", get(rep, "found")?),
        ("malicious", get(rep, "malicious")?),
        ("suspicious", get(rep, "suspicious")?),
        ("total", get(rep, "total")?),
        ("family", get(rep, "family")?),
        ("meaningful_name", get(rep, "meaningful_name")?),
        ("permalink", get(rep, "permalink")?),
        ("submitted", get(rep, "submitted")?),
        ("note", get(rep, "note")?),
        ("threat_label", get(&intel, "threat_label")?),
        (
            "threat_names",
            capped(get(&intel, "threat_names")?, MAX_LIST)?,
        ),
        ("type_description", get(&intel, "type_description")?),
        ("reputation", get(&intel, "reputation")?),
        ("first_seen", get(&intel, "first_seen")?),
        ("last_analysis", get(&intel, "last_analysis")?),
        ("signed", get(&intel, "signed")?),
        ("signer", get(&intel, "signer")?),
        ("detection_count", get(&intel, "detection_count")?),
        ("detections", capped(get(&intel, "detections")?, MAX_LIST)?),
        ("yara", capped(get(&intel, "yara")?, MAX_LIST)?),
        ("sigma", capped(get(&intel, "sigma")?, MAX_LIST)?),
    ]))
}

/// `build_context(result, generated_at, screenshots)`.
pub fn build_context(
    result: &PyValue,
    generated_at: Option<&str>,
    screenshots: &[Vec<u8>],
) -> PyResult<PyValue> {
    let job = or(get(result, "job")?, empty_dict());
    let inspector = or(get(result, "inspector")?, empty_dict());
    let sandbox = get(result, "sandbox")?;
    let reputation = get(result, "reputation")?;
    let hashes = or(get(&inspector, "hashes")?, empty_dict());
    let shots: Vec<PyValue> = screenshots
        .iter()
        .take(MAX_LIST)
        .filter(|raw| !raw.is_empty())
        .map(|raw| {
            py::s(format!(
                "data:image/jpeg;base64,{}",
                base64::engine::general_purpose::STANDARD.encode(raw)
            ))
        })
        .collect();
    let generated_at = generated_at.map_or_else(
        || Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        str::to_string,
    );
    let verdict = fmt_verdict(&or(get(&job, "verdict")?, get(&inspector, "verdict_hint")?))?;
    let sha256 = or(get(&hashes, "sha256")?, get(&job, "sha256")?);
    Ok(dict(vec![
        ("generated_at", py::s(generated_at)),
        (
            "job",
            dict(vec![
                ("job_id", get(&job, "job_id")?),
                ("customer_code", get(&job, "customer_code")?),
                ("source", get(&job, "source")?),
                ("created_at", get(&job, "created_at")?),
                ("hardened", get(&job, "hardened")?),
                ("sandbox_enabled", get(&job, "sandbox_enabled")?),
            ]),
        ),
        ("verdict", verdict),
        ("verdict_reason", get(result, "verdict_reason")?),
        ("engine_version", get(result, "engine_version")?),
        (
            "file",
            dict(vec![
                (
                    "name",
                    or(get(&inspector, "filename")?, get(&job, "filename")?),
                ),
                (
                    "hashes",
                    dict(vec![
                        ("md5", get(&hashes, "md5")?),
                        ("sha1", get(&hashes, "sha1")?),
                        ("sha256", sha256),
                        ("imphash", get(&hashes, "imphash")?),
                    ]),
                ),
            ]),
        ),
        ("static", static_section(&inspector)?),
        (
            "reputation",
            if reputation.truthy() {
                reputation_section(&reputation)?
            } else {
                PyValue::None
            },
        ),
        (
            "sandbox",
            if sandbox.truthy() {
                sandbox_section(&sandbox)?
            } else {
                PyValue::None
            },
        ),
        ("screenshots", PyValue::List(shots)),
    ]))
}

/// A `json.loads` value as a template value.
fn input(value: &PyValue) -> Input {
    match value {
        PyValue::None => Input::None,
        PyValue::Bool(b) => Input::Bool(*b),
        PyValue::Int(i) => i.parse().map_or_else(|_| Input::Str(i.clone()), Input::Int),
        PyValue::Float(f) => Input::Float(*f),
        PyValue::Str(s) => Input::Str(s.clone()),
        PyValue::List(items) => Input::List(items.iter().map(input).collect()),
        PyValue::Dict(items) => {
            Input::Dict(items.iter().map(|(k, v)| (k.clone(), input(v))).collect())
        }
    }
}

/// `render_html_template(_TEMPLATE_PATH, context)`'s HTML.
pub fn render(context: &PyValue) -> Result<String, String> {
    let PyValue::Dict(pairs) = context else {
        return Err("the context is not a dict".into());
    };
    let vars: Vec<(String, Input)> = pairs.iter().map(|(k, v)| (k.clone(), input(v))).collect();
    copilot_jinja::render_page(TEMPLATE, &vars, true).map_err(|e| e.message)
}

/// `generate_report_pdf`'s options for `convert_html_to_pdf`.
pub const PDF_OPTIONS: &[(&str, &str)] = &[
    ("footer-right", "[page]/[topage]"),
    ("footer-font-size", "7"),
    ("footer-spacing", "4"),
    ("margin-top", "14mm"),
    ("margin-bottom", "16mm"),
    ("encoding", "UTF-8"),
];

/// The download's name: `file-analysis-{sha[:12]}.pdf`.
pub fn file_name(result: &PyValue) -> PyResult<String> {
    let inspector = or(get(result, "inspector")?, empty_dict());
    let job = or(get(result, "job")?, empty_dict());
    let sha = or(
        or(get(&inspector, "sha256")?, get(&job, "sha256")?),
        py::s("report"),
    );
    let head = head(&sha, 12)?;
    Ok(format!("file-analysis-{}.pdf", str_of(&head)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn the_template_is_the_backends() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../backend/app/file_analysis/templates/report.html");
        assert_eq!(std::fs::read_to_string(path).unwrap(), TEMPLATE);
    }

    #[test]
    fn context_matches_the_python_tests() {
        let result = loads(
            r#"{"job": {"job_id": "J1", "customer_code": "00001", "verdict": "malicious"},
            "inspector": {"filename": "evil.exe", "hashes": {"sha256": "aaaa"}, "content": {"deobfuscated": "XXXXXXXXXXXXXXXXXXXX"}},
            "sandbox": {"signatures": [{"name": "pe_tls_callbacks", "severity": 2, "low_confidence": true},
                                       {"name": "queries_user_name", "severity": 1, "noise": true},
                                       {"name": "real", "severity": 3}],
                        "connections": [{"proto": "TCP", "dst": "1.2.3.4", "dport": 443}, {"proto": "tcp", "dst": "1.2.3.4", "dport": 443}]},
            "reputation": null}"#,
        )
        .unwrap();
        let ctx = build_context(&result, Some("now"), &[b"x".to_vec(), Vec::new()]).unwrap();
        let sandbox = ctx.get("sandbox").unwrap();
        let sigs = sandbox.get("signatures").unwrap();
        assert!(sigs.get("meaningful").unwrap().py_repr().contains("'real'"));
        assert_eq!(
            sandbox.get("connections").unwrap().py_repr(),
            "[{'proto': 'tcp', 'dst': '1.2.3.4', 'dport': 443, 'count': 2}]"
        );
        assert_eq!(
            ctx.get("screenshots").unwrap().py_repr(),
            "['data:image/jpeg;base64,eA==']"
        );
        assert_eq!(file_name(&result).unwrap(), "file-analysis-report.pdf");
        let html = render(&ctx).unwrap();
        assert!(html.contains("MALICIOUS"));
        assert!(html.contains("evil.exe"));
    }
}
