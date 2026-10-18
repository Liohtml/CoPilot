//! `services/rule_linter.py`: the L1–L3 checks of a Graylog-only rule.
//!
//! The JSON Schema pass needs `jsonschema`, which the backend does not
//! install; Python then runs its fallback (one `SCHEMA` error per missing
//! required key), and so does this port. Python `re`'s patterns are matched
//! by hand with its `\w`, `\s` and `\d` (Unicode, `str.isalnum()`-based) and
//! its `$` (end, or before a final newline).

use copilot_jinja::unicode;
use copilot_upstream::py::{PyExc, PyResult};
use copilot_yaml::{LoadError, Value};

use crate::py::{self, get, s};

/// One finding.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// `error` | `warning`.
    pub level: &'static str,
    /// The code.
    pub code: &'static str,
    /// The message.
    pub message: String,
    /// The path.
    pub path: String,
    /// The 1-based line.
    pub line: Option<usize>,
}

impl Finding {
    fn new(level: &'static str, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            level,
            code,
            message: message.into(),
            path: String::new(),
            line: None,
        }
    }

    fn at(mut self, path: &str, line: Option<usize>) -> Self {
        self.path = path.into();
        self.line = line;
        self
    }

    /// `dataclasses.asdict(f)`.
    pub fn to_value(&self) -> Value {
        py::dict(vec![
            ("level", s(self.level)),
            ("code", s(self.code)),
            ("message", s(self.message.clone())),
            ("path", s(self.path.clone())),
            ("line", self.line.map_or(Value::None, |l| py::int(l as i64))),
        ])
    }
}

const CANONICAL_ORDER: &[&str] = &[
    "name",
    "id",
    "version",
    "schema_version",
    "date",
    "author",
    "description",
    "data_source",
    "how_to_implement",
    "known_false_positives",
    "response",
    "tags",
    "graylog",
    "aggregation",
];
const RESERVED_QUERY_TOKENS: &[&str] = &["AND", "OR", "NOT", "TO", "_exists_"];

fn is_word(c: char) -> bool {
    unicode::is_word(c)
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_field_char(c: char) -> bool {
    is_word(c) || c == '.'
}

/// `$` at `i`: the end, or a final `\n`.
fn at_end(chars: &[char], i: usize) -> bool {
    i == chars.len() || (i + 1 == chars.len() && chars[i] == '\n')
}

/// `[A-Za-z_][\w.]*` from `i`: the end of the run, if one starts there.
fn ident_end(chars: &[char], i: usize) -> Option<usize> {
    if i < chars.len() && is_ident_start(chars[i]) {
        let mut j = i + 1;
        while j < chars.len() && is_field_char(chars[j]) {
            j += 1;
        }
        Some(j)
    } else {
        None
    }
}

fn skip_space(chars: &[char], mut i: usize) -> usize {
    while i < chars.len() && unicode::is_space(chars[i]) {
        i += 1;
    }
    i
}

/// `findall(r"(?<![\w.])([A-Za-z_][\w.]*)\s*:")` — or without the
/// look-behind (`backtest._QUERY_FIELD_RE`).
pub fn query_fields(query: &str, lookbehind: bool) -> Vec<String> {
    let chars: Vec<char> = query.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let behind_ok = !lookbehind || i == 0 || !is_field_char(chars[i - 1]);
        if behind_ok {
            if let Some(end) = ident_end(&chars, i) {
                let after = skip_space(&chars, end);
                if after < chars.len() && chars[after] == ':' {
                    out.push(chars[i..end].iter().collect());
                    i = after + 1;
                    continue;
                }
                if !lookbehind {
                    // Without the look-behind a later start inside the run can
                    // still match (`a.b:` is found as `a.b`, but `1a:` as `a`).
                    i += 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// `findall(r"_exists_\s*:\s*([A-Za-z_][\w.]*)")`.
pub fn exists_fields(query: &str) -> Vec<String> {
    let chars: Vec<char> = query.chars().collect();
    let pat: Vec<char> = "_exists_".chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i + pat.len() <= chars.len() {
        if chars[i..i + pat.len()] == pat[..] {
            let mut j = skip_space(&chars, i + pat.len());
            if j < chars.len() && chars[j] == ':' {
                j = skip_space(&chars, j + 1);
                if let Some(end) = ident_end(&chars, j) {
                    out.push(chars[j..end].iter().collect());
                    i = end;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// `findall(r"\$([A-Za-z_][\w.]*)\$")`.
pub fn placeholders(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' {
            if let Some(end) = ident_end(&chars, i + 1) {
                if end < chars.len() && chars[end] == '$' {
                    out.push(chars[i + 1..end].iter().collect());
                    i = end + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

fn digits(chars: &[char], i: usize, n: usize) -> bool {
    i + n <= chars.len() && chars[i..i + n].iter().all(|c| unicode::is_decimal(*c))
}

/// `re.match(r"^T\d{4}(\.\d{3})?$", v)`.
pub fn is_mitre_id(v: &str) -> bool {
    let c: Vec<char> = v.chars().collect();
    if c.first() != Some(&'T') || !digits(&c, 1, 4) {
        return false;
    }
    if at_end(&c, 5) {
        return true;
    }
    c.get(5) == Some(&'.') && digits(&c, 6, 3) && at_end(&c, 9)
}

/// `re.match(r"^\d{4}-\d{2}-\d{2}$", v)`.
pub fn is_iso_date(v: &str) -> bool {
    let c: Vec<char> = v.chars().collect();
    digits(&c, 0, 4)
        && c.get(4) == Some(&'-')
        && digits(&c, 5, 2)
        && c.get(7) == Some(&'-')
        && digits(&c, 8, 2)
        && at_end(&c, 10)
}

/// `re.match(r"^\d+[smhd]$", v)`.
pub fn is_window(v: &str) -> bool {
    let c: Vec<char> = v.chars().collect();
    let mut i = 0;
    while i < c.len() && unicode::is_decimal(c[i]) {
        i += 1;
    }
    i > 0 && i < c.len() && matches!(c[i], 's' | 'm' | 'h' | 'd') && at_end(&c, i + 1)
}

/// The start (in chars) of `^{key}\s*:` (multi-line) and, with `folded`,
/// `^{key}\s*:\s*>`.
fn key_match(raw: &[char], key: &str, folded: bool) -> Option<usize> {
    let key: Vec<char> = key.chars().collect();
    let mut start = 0;
    loop {
        if start + key.len() <= raw.len() && raw[start..start + key.len()] == key[..] {
            let j = skip_space(raw, start + key.len());
            if j < raw.len() && raw[j] == ':' {
                if !folded {
                    return Some(start);
                }
                let k = skip_space(raw, j + 1);
                if k < raw.len() && raw[k] == '>' {
                    return Some(start);
                }
            }
        }
        let next = raw[start..].iter().position(|c| *c == '\n')?;
        start += next + 1;
    }
}

/// `_line_of_key(raw, key)`.
pub fn line_of_key(raw: &str, key: &str) -> Option<usize> {
    let chars: Vec<char> = raw.chars().collect();
    let start = key_match(&chars, key, false)?;
    Some(chars[..start].iter().filter(|c| **c == '\n').count() + 1)
}

fn has_folded(raw: &str, key: &str) -> bool {
    let chars: Vec<char> = raw.chars().collect();
    key_match(&chars, key, true).is_some()
}

/// `uuid.UUID(v)` succeeds.
pub fn is_uuid(v: &str) -> bool {
    let hex = v.replace("urn:", "").replace("uuid:", "");
    let hex = hex.trim_matches(|c| c == '{' || c == '}').replace('-', "");
    if hex.chars().count() != 32 {
        return false;
    }
    match copilot_yaml::pyint::parse_int(&hex, 16) {
        Ok(n) => {
            let zero = num_bigint_dig::BigInt::from(0);
            let limit = num_bigint_dig::BigInt::from(1) << 128;
            n >= zero && n < limit
        }
        Err(_) => false,
    }
}

/// `lint_graylog_query(query, line)` (L3).
pub fn lint_graylog_query(q: &str, line: Option<usize>) -> Vec<Finding> {
    let mut out = Vec::new();
    let at = |f: Finding| f.at("graylog.query", line);
    if py::py_strip(q).is_empty() {
        out.push(at(Finding::new(
            "error",
            "GRAYLOG_QUERY_EMPTY",
            "graylog.query is empty.",
        )));
        return out;
    }
    let (mut in_quote, mut escaped, mut went_negative) = (false, false, false);
    let (mut parens, mut slashes) = (0i64, 0i64);
    for ch in q.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quote = !in_quote;
            continue;
        }
        if in_quote {
            continue;
        }
        match ch {
            '(' => parens += 1,
            ')' => {
                parens -= 1;
                if parens < 0 {
                    went_negative = true;
                }
            }
            '/' => slashes += 1,
            _ => {}
        }
    }
    if in_quote {
        out.push(at(Finding::new(
            "error",
            "GRAYLOG_QUERY_QUOTES",
            "Unbalanced double-quote in graylog.query.",
        )));
    }
    if parens != 0 || went_negative {
        out.push(at(Finding::new(
            "error",
            "GRAYLOG_QUERY_PARENS",
            "Unbalanced parentheses in graylog.query.",
        )));
    }
    if slashes % 2 != 0 {
        out.push(at(Finding::new(
            "error",
            "GRAYLOG_QUERY_REGEX",
            "Unbalanced '/' — a regex literal (/.../) is not closed.",
        )));
    }
    let tokens = py::py_split_ws(q);
    if let Some(first) = tokens.first().filter(|t| matches!(**t, "AND" | "OR")) {
        out.push(at(Finding::new(
            "error",
            "GRAYLOG_QUERY_DANGLING_OP",
            format!("Query starts with '{first}'."),
        )));
    }
    if let Some(last) = tokens
        .last()
        .filter(|t| matches!(**t, "AND" | "OR" | "NOT"))
    {
        out.push(at(Finding::new(
            "error",
            "GRAYLOG_QUERY_DANGLING_OP",
            format!("Query ends with '{last}'."),
        )));
    }
    if q.contains("/.*") {
        out.push(at(Finding::new(
            "warning",
            "GRAYLOG_QUERY_LEADING_WILDCARD",
            "Leading '.*' in a regex scans everything — anchor it or use a literal where possible.",
        )));
    }
    out
}

/// `_rule_used_fields(data)`.
fn used_fields(data: &Value) -> PyResult<Vec<String>> {
    let graylog = match get(data, "graylog", Value::None)? {
        g @ Value::Dict(_) => g,
        _ => py::dict(vec![]),
    };
    let q = get(&graylog, "query", Value::None)?;
    let query = if q.truthy() {
        q.py_str()
    } else {
        String::new()
    };
    let mut fields: Vec<String> = Vec::new();
    let add = |f: String, fields: &mut Vec<String>| {
        if !fields.contains(&f) {
            fields.push(f);
        }
    };
    for m in query_fields(&query, true) {
        if !RESERVED_QUERY_TOKENS.contains(&m.as_str()) {
            add(m, &mut fields);
        }
    }
    for m in exists_fields(&query) {
        add(m, &mut fields);
    }
    let agg = get(data, "aggregation", Value::None)?;
    if agg.is_dict() {
        let group_by = get(&agg, "group_by", Value::None)?;
        let group_by = if group_by.truthy() {
            group_by
        } else {
            py::list(vec![])
        };
        for g in py::iterate(&group_by)? {
            if let Value::Str(t) = g {
                add(t, &mut fields);
            }
        }
        let field = get(&agg, "field", Value::None)?;
        if field.truthy() {
            add(py::getitem(&agg, "field")?.py_str(), &mut fields);
        }
    }
    Ok(fields)
}

fn data_key_present(data: &Value, key: &str) -> bool {
    data.get(key).is_some()
}

/// The keys of a mapping, sorted as `sorted(set(keys) - {"query"})`.
fn extra_graylog_keys(gl: &Value) -> PyResult<Vec<String>> {
    let keys: Vec<Value> = py::iterate(gl)?
        .into_iter()
        .filter(|k| k.as_str() != Some("query"))
        .collect();
    let mut strs = Vec::with_capacity(keys.len());
    for k in &keys {
        match k {
            Value::Str(t) => strs.push(t.clone()),
            _ => {
                // `sorted` of mixed types, or `", ".join` of a non-str: a
                // TypeError either way, which the routes do not catch.
                if keys.len() > 1 && keys.iter().any(|k| k.as_str().is_some()) {
                    return Err(PyExc::TypeError(format!(
                        "'<' not supported between instances of '{}' and 'str'",
                        k.type_name()
                    )));
                }
                return Err(PyExc::TypeError(format!(
                    "sequence item 0: expected str instance, {} found",
                    py::tp_name(k)
                )));
            }
        }
    }
    strs.sort();
    Ok(strs)
}

/// `lint_rule_yaml(raw)`: the findings, or the exception `yaml.safe_load`
/// (or a check) let escape.
pub fn lint_rule_yaml(raw: &str) -> PyResult<Vec<Finding>> {
    let data = match copilot_yaml::safe_load(raw) {
        Ok(d) => d,
        Err(LoadError::Yaml(e)) => {
            return Ok(vec![Finding {
                level: "error",
                code: "YAML_PARSE",
                message: format!("YAML is not parseable: {}", e.problem_text()),
                path: String::new(),
                line: e.problem_line(),
            }]);
        }
        Err(LoadError::Python(e)) => return Err(load_exc(e)),
    };
    if matches!(data, Value::None) {
        return Ok(vec![Finding::new("error", "EMPTY", "Rule is empty.")]);
    }
    if !data.is_dict() {
        return Ok(vec![Finding::new(
            "error",
            "NOT_A_MAPPING",
            "A rule must be a YAML mapping (key: value), not a list or scalar.",
        )]);
    }
    let mut findings = Vec::new();
    for block in ["search", "parameters"] {
        if data_key_present(&data, block) {
            findings.push(
                Finding::new(
                    "error",
                    "FORBIDDEN_BLOCK",
                    format!(
                        "'{block}' is out of scope for Graylog-only rules — remove it (this \
                         editor targets graylog.query only)."
                    ),
                )
                .at(block, line_of_key(raw, block)),
            );
        }
    }
    for req in [
        "name",
        "id",
        "version",
        "schema_version",
        "description",
        "graylog",
    ] {
        if !data_key_present(&data, req) {
            findings.push(
                Finding::new("error", "SCHEMA", format!("'{req}' is a required property"))
                    .at(req, None),
            );
        }
    }
    let gl = get(&data, "graylog", Value::None)?;
    if gl.is_dict() {
        let extra = extra_graylog_keys(&gl)?;
        if !extra.is_empty() {
            findings.push(
                Finding::new(
                    "error",
                    "GRAYLOG_EXTRA_KEYS",
                    format!(
                        "graylog must contain only 'query'; found extra key(s): {}.",
                        extra.join(", ")
                    ),
                )
                .at("graylog", line_of_key(raw, "graylog")),
            );
        }
        if let Value::Str(q) = get(&gl, "query", Value::None)? {
            findings.extend(lint_graylog_query(&q, line_of_key(raw, "graylog")));
        }
    }
    if let Some(v) = data.get("schema_version") {
        if v.as_str().is_none() {
            findings.push(
                Finding::new(
                    "error",
                    "SCHEMA_VERSION_UNQUOTED",
                    "schema_version must be a quoted string, e.g. \"1.0\" (unquoted 1.0 parses \
                     as a number).",
                )
                .at("schema_version", line_of_key(raw, "schema_version")),
            );
        }
    }
    if let Value::Str(rid) = get(&data, "id", Value::None)? {
        if !is_uuid(&rid) {
            findings.push(
                Finding::new(
                    "warning",
                    "ID_NOT_UUID",
                    "id should be a UUID (generate a fresh one per rule).",
                )
                .at("id", line_of_key(raw, "id")),
            );
        }
    }
    let keys: Vec<Value> = data
        .as_dict()
        .map(|items| items.iter().map(|(k, _)| k.clone()).collect())
        .unwrap_or_default();
    let present: Vec<&str> = keys
        .iter()
        .filter_map(Value::as_str)
        .filter(|k| CANONICAL_ORDER.contains(k))
        .collect();
    let mut expected = present.clone();
    expected.sort_by_key(|k| CANONICAL_ORDER.iter().position(|c| c == k));
    if present != expected {
        findings.push(Finding::new(
            "warning",
            "KEY_ORDER",
            format!(
                "Top-level keys are out of canonical order. Expected: {}.",
                expected.join(", ")
            ),
        ));
    }
    if data_key_present(&data, "aggregation") && data_key_present(&data, "graylog") {
        let pos = |name: &str| keys.iter().position(|k| k.as_str() == Some(name));
        if pos("aggregation") < pos("graylog") {
            findings.push(
                Finding::new(
                    "error",
                    "AGG_POSITION",
                    "aggregation must appear AFTER the graylog block.",
                )
                .at("aggregation", line_of_key(raw, "aggregation")),
            );
        }
    }
    let agg = get(&data, "aggregation", Value::None)?;
    if agg.is_dict() {
        let function = get(&agg, "function", Value::None)?;
        let field = get(&agg, "field", Value::None)?;
        let agg_line = line_of_key(raw, "aggregation");
        if function.as_str() == Some("count") && field.truthy() {
            findings.push(
                Finding::new(
                    "error",
                    "AGG_FIELD_FORBIDDEN",
                    "field must be null (or omitted) when function is 'count'.",
                )
                .at("aggregation.field", agg_line),
            );
        }
        if function.as_str() == Some("distinct_count") && !field.truthy() {
            findings.push(
                Finding::new(
                    "error",
                    "AGG_FIELD_REQUIRED",
                    "field is required when function is 'distinct_count'.",
                )
                .at("aggregation.field", agg_line),
            );
        }
        if let Value::Str(win) = get(&agg, "window", Value::None)? {
            if !is_window(&win) {
                findings.push(
                    Finding::new(
                        "warning",
                        "AGG_WINDOW_FORMAT",
                        "window should look like '10m' / '1h' / '30s' / '1d'.",
                    )
                    .at("aggregation.window", agg_line),
                );
            }
        }
    }
    for key in ["description", "how_to_implement", "known_false_positives"] {
        if data_key_present(&data, key)
            && matches!(data.get(key), Some(Value::Str(_)))
            && !has_folded(raw, key)
        {
            findings.push(
                Finding::new(
                    "warning",
                    "FOLDED_SCALAR",
                    format!("{key} should use a folded scalar (>) for readable multi-line text."),
                )
                .at(key, line_of_key(raw, key)),
            );
        }
    }
    if let Some(Value::List(ds)) = data.get("data_source") {
        for v in ds.iter() {
            if let Value::Str(v) = v {
                if v.contains(':')
                    && !raw.contains(&format!("\"{v}\""))
                    && !raw.contains(&format!("'{v}'"))
                {
                    findings.push(
                        Finding::new(
                            "warning",
                            "DATA_SOURCE_QUOTE",
                            format!(
                                "data_source entry '{v}' contains ':' — quote it so YAML doesn't \
                                 misparse it."
                            ),
                        )
                        .at("data_source", None),
                    );
                }
            }
        }
    }
    for key in ["author", "date", "data_source", "response", "tags"] {
        if !data_key_present(&data, key) {
            findings.push(
                Finding::new(
                    "warning",
                    "MISSING_RECOMMENDED",
                    format!("'{key}' is recommended for a complete rule."),
                )
                .at(key, None),
            );
        }
    }
    let used = used_fields(&data)?;
    let response = match get(&data, "response", Value::None)? {
        r @ Value::Dict(_) => r,
        _ => py::dict(vec![]),
    };
    let response_line = line_of_key(raw, "response");
    if let Value::Str(msg) = get(&response, "message", Value::None)? {
        let mut phs = placeholders(&msg);
        phs.sort();
        phs.dedup();
        for ph in phs {
            if !used.contains(&ph) {
                findings.push(
                    Finding::new(
                        "warning",
                        "REF_MESSAGE_FIELD",
                        format!(
                            "response.message references ${ph}$ but the query/aggregation never \
                             uses that field — it may render blank in alerts."
                        ),
                    )
                    .at("response.message", response_line),
                );
            }
        }
    }
    for (kind, code) in [
        ("risk_objects", "REF_RISK_OBJECT"),
        ("threat_objects", "REF_THREAT_OBJECT"),
    ] {
        if let Value::List(items) = get(&response, kind, Value::None)? {
            for obj in items.iter() {
                if !obj.is_dict() {
                    continue;
                }
                if let Value::Str(field) = get(obj, "field", Value::None)? {
                    if !used.contains(&field) {
                        findings.push(
                            Finding::new(
                                "warning",
                                code,
                                format!(
                                    "response.{kind} field '{field}' is not used by the \
                                     query/aggregation — the object may be empty on alerts."
                                ),
                            )
                            .at(&format!("response.{kind}"), response_line),
                        );
                    }
                }
            }
        }
    }
    let tags = match get(&data, "tags", Value::None)? {
        t @ Value::Dict(_) => t,
        _ => py::dict(vec![]),
    };
    if let Value::List(mitre) = get(&tags, "mitre_attack_id", Value::None)? {
        for mid in mitre.iter() {
            if let Value::Str(mid) = mid {
                if !is_mitre_id(mid) {
                    findings.push(
                        Finding::new(
                            "warning",
                            "MITRE_ID_FORMAT",
                            format!(
                                "'{mid}' does not look like a MITRE ATT&CK technique id (e.g. \
                                 T1059 or T1059.001)."
                            ),
                        )
                        .at("tags.mitre_attack_id", line_of_key(raw, "tags")),
                    );
                }
            }
        }
    }
    let sev_raw = get(&response, "severity", Value::None)?;
    let sev = if sev_raw.truthy() {
        unicode::lower(&sev_raw.py_str())
    } else {
        String::new()
    };
    let band = match sev.as_str() {
        "low" => Some((1, 40)),
        "medium" => Some((25, 75)),
        "high" => Some((55, 95)),
        "critical" => Some((75, 100)),
        _ => None,
    };
    if let (Some((lo, hi)), Value::Int(score)) = (band, get(&response, "risk_score", Value::None)?)
    {
        let lo_b = num_bigint_dig::BigInt::from(lo);
        let hi_b = num_bigint_dig::BigInt::from(hi);
        if !(lo_b <= score && score <= hi_b) {
            findings.push(
                Finding::new(
                    "warning",
                    "SEVERITY_SCORE_MISMATCH",
                    format!(
                        "risk_score {score} is unusual for severity '{sev}' (expected roughly \
                         {lo}–{hi})."
                    ),
                )
                .at("response.risk_score", response_line),
            );
        }
    }
    if let Value::Str(date) = get(&data, "date", Value::None)? {
        if !is_iso_date(&date) {
            findings.push(
                Finding::new(
                    "warning",
                    "DATE_FORMAT",
                    "date should be a quoted ISO date, e.g. \"2026-08-26\".",
                )
                .at("date", line_of_key(raw, "date")),
            );
        }
    }
    Ok(findings)
}

/// An exception `yaml.safe_load` let escape, as the route sees it.
pub fn load_exc(e: copilot_yaml::PyException) -> PyExc {
    if e.is_value_error() {
        PyExc::ValueError(e.message)
    } else {
        PyExc::Other(e.class, e.message)
    }
}

/// `lint_result(raw)`.
pub struct LintResult {
    /// The findings.
    pub findings: Vec<Finding>,
}

impl LintResult {
    /// `valid`.
    pub fn valid(&self) -> bool {
        self.error_count() == 0
    }

    /// `error_count`.
    pub fn error_count(&self) -> usize {
        self.findings.iter().filter(|f| f.level == "error").count()
    }

    /// The dict `lint_result` returns.
    pub fn to_value(&self) -> Value {
        let errors = self.error_count();
        py::dict(vec![
            ("valid", Value::Bool(errors == 0)),
            ("error_count", py::int(errors as i64)),
            (
                "warning_count",
                py::int((self.findings.len() - errors) as i64),
            ),
            (
                "findings",
                py::list(self.findings.iter().map(Finding::to_value).collect()),
            ),
        ])
    }
}

/// `lint_result(raw)`.
pub fn lint_result(raw: &str) -> PyResult<LintResult> {
    Ok(LintResult {
        findings: lint_rule_yaml(raw)?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn patterns_follow_python_re() {
        assert_eq!(
            query_fields("a.b:1 AND x:2 AND 1y:3 AND (z : 4)", true),
            vec!["a.b", "x", "z"]
        );
        assert_eq!(query_fields("1y:3", false), vec!["y"]);
        assert_eq!(
            exists_fields("_exists_ : host.name AND x"),
            vec!["host.name"]
        );
        assert_eq!(placeholders("$a$ $b.c$ $9$ $x"), vec!["a", "b.c"]);
        assert!(is_mitre_id("T1059.001"));
        assert!(is_mitre_id("T1059\n"));
        assert!(!is_mitre_id("T1059.01"));
        assert!(is_iso_date("2024-01-02"));
        assert!(is_window("10m"));
        assert!(!is_window("10"));
        assert_eq!(line_of_key("a: 1\nname : x\n", "name"), Some(2));
        assert!(is_uuid("6f3e1a2b-0000-4c1d-8e9f-0123456789ab"));
        assert!(!is_uuid("x"));
    }
}
