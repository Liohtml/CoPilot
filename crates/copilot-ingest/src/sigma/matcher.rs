//! `VeloSigmaExclusionService._matches_exclusion` and
//! `_normalize_windows_path` — the one matcher the ingest, and the dry-run
//! on a stored alert, decide suppression with.
//!
//! Patterns are Python `re` patterns. This uses the `regex` crate: a
//! pattern Python's `re` and `regex` read alike (the ones operators write:
//! literals, classes, `.*`, alternations, anchors) matches alike, `$`
//! included (translated to Python's "end, or before a final newline");
//! look-arounds, back-references and the other constructs `regex` does not
//! have do not compile, and a pattern that does not compile matches nothing
//! — what Python does with the patterns *it* cannot compile.

use copilot_auth::pyvalue::PyValue;
use regex::RegexBuilder;

use super::events::ParseError;

/// The parts of a rule the matcher reads.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Rule {
    /// `customer_code` (empty = every customer).
    pub customer_code: Option<String>,
    /// `channel` (exact).
    pub channel: Option<String>,
    /// `title` (exact).
    pub title: Option<String>,
    /// `field_matches` (a dict in every row the API writes).
    pub field_matches: Option<PyValue>,
}

fn set(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|s| !s.is_empty())
}

/// `_matches_exclusion(alert, event_data, exclusion, customer_code)`;
/// `Err` is the `AttributeError` of a `field_matches` that is no dict.
pub fn matches(
    rule: &Rule,
    alert_channel: &str,
    alert_title: &str,
    event_data: &[(String, String)],
    customer_code: Option<&str>,
) -> Result<bool, ParseError> {
    if let Some(code) = set(&rule.customer_code) {
        if Some(code) != customer_code {
            return Ok(false);
        }
    }
    if let Some(ch) = set(&rule.channel) {
        if ch != alert_channel {
            return Ok(false);
        }
    }
    if let Some(t) = set(&rule.title) {
        if t != alert_title {
            return Ok(false);
        }
    }
    let Some(field_matches) = rule.field_matches.as_ref().filter(|v| v.truthy()) else {
        return Ok(true);
    };
    let PyValue::Dict(items) = field_matches else {
        return Err(ParseError(format!(
            "'{}' object has no attribute 'items'",
            crate::py::type_name(field_matches)
        )));
    };
    let get = |name: &str| event_data.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    for (raw_name, field_value) in items {
        let mut field_name = raw_name.as_str();
        if field_name.to_lowercase() == "hostapplication" && get(field_name).is_none() {
            match ["Host Application", "HostApplication", "hostApplication"]
                .into_iter()
                .find(|alt| get(alt).is_some())
            {
                Some(alt) => field_name = alt,
                None => return Ok(false),
            }
        }
        let Some(event_value) = get(field_name) else {
            return Ok(false);
        };
        let lowered_name = field_name.to_lowercase();
        let pathish_name = lowered_name.contains("path") || lowered_name.contains("file");
        match field_value {
            PyValue::Str(value) => {
                if let Some(pattern) = value.strip_prefix("regex:") {
                    if pathish_name || pattern.contains('\\') || pattern.contains('/') {
                        // The path branch decides on its own: the rule's
                        // other fields are not looked at.
                        return Ok(path_regex_matches(pattern, event_value));
                    }
                    if !py_search(pattern, event_value) {
                        return Ok(false);
                    }
                } else if pathish_name || value.contains('\\') || value.contains('/') {
                    if normalize_windows_path(value) != normalize_windows_path(event_value) {
                        return Ok(false);
                    }
                } else if value.to_lowercase() != event_value.to_lowercase() {
                    return Ok(false);
                }
            }
            other => {
                if &other.py_str() != event_value {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

/// The path branch of a `regex:` value: both sides lowered with `\\`
/// collapsed, the pattern's `.*` kept and everything else literal, anchored
/// at both ends.
fn path_regex_matches(regex_pattern: &str, event_value: &str) -> bool {
    let mut pattern = regex_pattern.to_lowercase().replace("\\\\", "\\");
    let value = event_value.to_lowercase().replace("\\\\", "\\");
    if let Some(rest) = pattern.strip_prefix("regex:") {
        pattern = rest.to_string();
    }
    let pattern = pattern.replace("\\(", "(").replace("\\)", ")");
    let mut regex = String::from(r"\A");
    let mut rest = pattern.as_str();
    while let Some(i) = rest.find(".*") {
        regex.push_str(&regex::escape(&rest[..i]));
        regex.push_str(".*");
        rest = &rest[i + 2..];
    }
    regex.push_str(&regex::escape(rest));
    // Python's `$`: the end, or just before a final newline.
    regex.push_str(r"\n?\z");
    RegexBuilder::new(&regex)
        .case_insensitive(true)
        .build()
        .map(|re| re.is_match(&value))
        .unwrap_or(false)
}

/// `re.search(pattern, value, re.IGNORECASE)` for a pattern with no
/// backslash (those take the path branch); `false` when it does not
/// compile.
pub fn py_search(pattern: &str, value: &str) -> bool {
    RegexBuilder::new(&python_pattern(pattern))
        .case_insensitive(true)
        .build()
        .map(|re| re.is_match(value))
        .unwrap_or(false)
}

/// Python's `$` outside a character class (no `MULTILINE`) is "the end, or
/// before a final newline"; the `regex` crate's is the end only.
pub fn python_pattern(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() + 8);
    let mut in_class = false;
    let mut class_start = false;
    let mut escaped = false;
    for c in pattern.chars() {
        if escaped {
            out.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => {
                escaped = true;
                out.push(c);
            }
            '[' if !in_class => {
                in_class = true;
                class_start = true;
                out.push(c);
                continue;
            }
            ']' if in_class && !class_start => {
                in_class = false;
                out.push(c);
            }
            '^' if in_class && class_start => {
                out.push(c);
                continue;
            }
            '$' if !in_class => out.push_str(r"(?:\n?\z)"),
            _ => out.push(c),
        }
        class_start = false;
    }
    out
}

/// `_normalize_windows_path(path)`: lowered, every run of backslashes one
/// backslash, `\(`, `\)`, `\[`, `\]`, `\ ` unescaped, one trailing
/// backslash dropped.
pub fn normalize_windows_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let lowered = path.to_lowercase();
    let mut collapsed = String::with_capacity(lowered.len());
    let mut prev_backslash = false;
    for c in lowered.chars() {
        if c == '\\' {
            if !prev_backslash {
                collapsed.push(c);
            }
            prev_backslash = true;
        } else {
            collapsed.push(c);
            prev_backslash = false;
        }
    }
    let mut n = collapsed
        .replace("\\(", "(")
        .replace("\\)", ")")
        .replace("\\[", "[")
        .replace("\\]", "]")
        .replace("\\ ", " ");
    if n.ends_with('\\') {
        n.pop();
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn rule(fm: &str) -> Rule {
        Rule {
            field_matches: Some(copilot_auth::pyvalue::loads(fm).unwrap()),
            ..Rule::default()
        }
    }

    #[test]
    fn paths_compare_normalised() {
        let d = data(&[("TargetFilename", "C:\\Windows\\Temp\\chainsaw_batch.bat")]);
        let r = rule(r#"{"TargetFilename": "c:\\\\windows\\\\temp\\\\CHAINSAW_batch.bat"}"#);
        assert!(matches(&r, "c", "t", &d, None).unwrap());
    }

    #[test]
    fn the_path_regex_decides_alone() {
        let d = data(&[("Image", "C:\\Tools\\x.exe"), ("User", "bob")]);
        let r = rule(r#"{"Image": "regex:c:\\\\tools\\\\.*", "User": "alice"}"#);
        assert!(matches(&r, "c", "t", &d, None).unwrap());
    }

    #[test]
    fn dollars_follow_python() {
        assert!(py_search("exe$", "a.exe\n"));
        assert!(!py_search("exe$", "a.exe\nx"));
        assert!(py_search("[$]", "a$"));
        assert!(!py_search("(?<=a)b", "ab"));
    }

    #[test]
    fn rules_scoped_to_a_customer_need_the_customer() {
        let r = Rule {
            customer_code: Some("acme".into()),
            ..Rule::default()
        };
        assert!(!matches(&r, "c", "t", &[], None).unwrap());
        assert!(matches(&r, "c", "t", &[], Some("acme")).unwrap());
        let list = rule("[1]");
        assert_eq!(
            matches(&list, "c", "t", &[], None).unwrap_err().0,
            "'list' object has no attribute 'items'"
        );
    }

    #[test]
    fn windows_paths() {
        assert_eq!(normalize_windows_path("C:\\\\\\X\\(1\\)\\"), "c:\\x(1)");
    }
}
