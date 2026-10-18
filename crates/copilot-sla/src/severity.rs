//! Resolving a severity — port of `app/incidents/services/alert_severity.py`.
//!
//! `incident_management_alert.severity` is nullable, and NULL means "the
//! source did not tell us": it resolves at read time to the deployment
//! default (`DEFAULT_ALERT_SEVERITY`, itself `High` when unset).

/// `SEVERITY_LEVELS`: least to most severe.
pub const SEVERITY_LEVELS: [&str; 5] = ["Informational", "Low", "Medium", "High", "Critical"];

/// `FALLBACK_SEVERITY`.
pub const FALLBACK_SEVERITY: &str = "High";

/// Python's `str.strip()` (Unicode whitespace plus the ASCII separators
/// `str.isspace` counts).
fn py_strip(value: &str) -> &str {
    value.trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c))
}

/// `normalize_severity`: the canonical spelling of a level, compared
/// case-insensitively after stripping; `None` for empty or unknown values.
pub fn normalize_severity(value: Option<&str>) -> Option<&'static str> {
    let value = value.filter(|v| !v.is_empty())?;
    let wanted = py_strip(value).to_lowercase();
    SEVERITY_LEVELS
        .into_iter()
        .find(|level| level.to_lowercase() == wanted)
}

/// `default_severity()` for a configured `DEFAULT_ALERT_SEVERITY`: matched
/// case-insensitively after stripping, else `High`.
pub fn default_severity(configured: Option<&str>) -> &'static str {
    let configured = configured.map(py_strip).unwrap_or_default();
    if configured.is_empty() {
        return FALLBACK_SEVERITY;
    }
    SEVERITY_LEVELS
        .into_iter()
        .find(|level| level.to_lowercase() == configured.to_lowercase())
        .unwrap_or(FALLBACK_SEVERITY)
}

/// `severity_of(alert)`: the stored value, else the deployment default.
pub fn severity_of(stored: Option<&str>, default: &'static str) -> &'static str {
    normalize_severity(stored).unwrap_or(default)
}

/// `severity_rank`: position in [`SEVERITY_LEVELS`], `-1` when unknown.
pub fn severity_rank(severity: Option<&str>) -> i32 {
    normalize_severity(severity)
        .and_then(|s| SEVERITY_LEVELS.iter().position(|l| *l == s))
        .map_or(-1, |i| i as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_like_python() {
        assert_eq!(normalize_severity(Some(" high ")), Some("High"));
        assert_eq!(normalize_severity(Some("CRITICAL")), Some("Critical"));
        assert_eq!(normalize_severity(Some("")), None);
        assert_eq!(normalize_severity(Some("severe")), None);
        assert_eq!(normalize_severity(None), None);
        assert_eq!(severity_of(None, "High"), "High");
        assert_eq!(severity_of(Some("low"), "High"), "Low");
        assert_eq!(severity_rank(Some("Critical")), 4);
        assert_eq!(severity_rank(Some("nope")), -1);
        assert_eq!(default_severity(Some(" critical ")), "Critical");
        assert_eq!(default_severity(Some("typo")), "High");
        assert_eq!(default_severity(None), "High");
    }
}
