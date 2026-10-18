//! The settings `app/middleware/performance.py` and `app/db/query_metrics.py`
//! read at import (`_env_flag`, `_env_float`, `_env_int`).

use copilot_core::config::PerfEnv;

/// The instrumentation's settings, with Python's defaults.
#[derive(Debug, Clone, PartialEq)]
pub struct PerfConfig {
    /// `PERF_MONITOR_ENABLED`: the request timer and the lag watchdog.
    pub enabled: bool,
    /// `PERF_LAG_SAMPLE_INTERVAL` (seconds).
    pub lag_sample_interval: f64,
    /// `PERF_LAG_STALL_THRESHOLD_MS`.
    pub lag_stall_threshold_ms: f64,
    /// `PERF_SLOW_REQUEST_MS`.
    pub slow_request_ms: f64,
    /// `PERF_RECENT_REQUESTS`.
    pub recent_requests: usize,
    /// `PERF_RECENT_STALLS`.
    pub recent_stalls: usize,
    /// `PERF_LAG_SAMPLES`.
    pub lag_samples: usize,
    /// `PERF_DURATION_SAMPLES`.
    pub duration_samples: usize,
    /// `PERF_MAX_ENDPOINTS`.
    pub max_endpoints: usize,
    /// `DB_SLOW_QUERY_MS`.
    pub slow_query_ms: f64,
    /// `DB_QUERY_SAMPLES`.
    pub query_samples: usize,
    /// `DB_MAX_STATEMENTS`.
    pub max_statements: usize,
}

impl Default for PerfConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            lag_sample_interval: 0.25,
            lag_stall_threshold_ms: 100.0,
            slow_request_ms: 1000.0,
            recent_requests: 500,
            recent_stalls: 200,
            lag_samples: 2000,
            duration_samples: 200,
            max_endpoints: 500,
            slow_query_ms: 250.0,
            query_samples: 2000,
            max_statements: 300,
        }
    }
}

/// `_env_flag`: unset or blank is the default, else one of `1`, `true`,
/// `yes`, `on` (any case).
fn flag(raw: Option<&str>, default: bool) -> bool {
    match raw.map(str::trim) {
        None | Some("") => default,
        Some(v) => matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
    }
}

/// `float(raw)`: surrounding whitespace, a sign, single underscores between
/// digits, `inf`/`nan`.
fn py_float(raw: &str) -> Option<f64> {
    let text = raw.trim();
    let bytes = text.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'_' {
            let digit =
                |j: Option<usize>| j.and_then(|j| bytes.get(j)).is_some_and(u8::is_ascii_digit);
            if !digit(i.checked_sub(1)) || !digit(Some(i + 1)) {
                return None;
            }
        }
    }
    let cleaned = text.replace('_', "");
    let lower = cleaned.to_ascii_lowercase();
    let unsigned = lower.trim_start_matches(['+', '-']);
    if matches!(unsigned, "inf" | "infinity" | "nan")
        || unsigned.bytes().any(|b| b.is_ascii_digit())
    {
        cleaned.parse().ok()
    } else {
        None
    }
}

/// `_env_float`: unset, blank or unreadable is the default.
fn float(raw: Option<&str>, default: f64) -> f64 {
    match raw {
        None => default,
        Some(v) if v.trim().is_empty() => default,
        Some(v) => py_float(v).unwrap_or_else(|| {
            tracing::warn!("PERF: invalid float value {v:?}, using default {default}");
            default
        }),
    }
}

/// `_env_int`: `int(_env_float(...))`. Python cannot start with a value
/// `int()` or `deque(maxlen=…)` refuses (infinite, NaN, negative); here such
/// a value is the default.
fn int(raw: Option<&str>, default: usize) -> usize {
    let v = float(raw, default as f64).trunc();
    if v.is_finite() && v >= 0.0 && v <= usize::MAX as f64 {
        v as usize
    } else {
        default
    }
}

impl PerfConfig {
    /// Read the settings as Python reads them.
    pub fn from_env(env: &PerfEnv) -> Self {
        let d = Self::default();
        Self {
            enabled: flag(env.monitor_enabled.as_deref(), d.enabled),
            lag_sample_interval: float(env.lag_sample_interval.as_deref(), d.lag_sample_interval),
            lag_stall_threshold_ms: float(
                env.lag_stall_threshold_ms.as_deref(),
                d.lag_stall_threshold_ms,
            ),
            slow_request_ms: float(env.slow_request_ms.as_deref(), d.slow_request_ms),
            recent_requests: int(env.recent_requests.as_deref(), d.recent_requests),
            recent_stalls: int(env.recent_stalls.as_deref(), d.recent_stalls),
            lag_samples: int(env.lag_samples.as_deref(), d.lag_samples),
            duration_samples: int(env.duration_samples.as_deref(), d.duration_samples),
            max_endpoints: int(env.max_endpoints.as_deref(), d.max_endpoints),
            slow_query_ms: float(env.db_slow_query_ms.as_deref(), d.slow_query_ms),
            query_samples: int(env.db_query_samples.as_deref(), d.query_samples),
            max_statements: int(env.db_max_statements.as_deref(), d.max_statements),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_read_like_python() {
        assert!(flag(None, true));
        assert!(flag(Some("  "), true));
        assert!(!flag(Some("off"), true));
        assert!(flag(Some(" YES "), false));
        assert!(!flag(Some("2"), true));
        assert_eq!(float(Some(" 1_000.5 "), 0.0), 1000.5);
        assert_eq!(float(Some("1__0"), 7.0), 7.0);
        assert_eq!(float(Some("abc"), 7.0), 7.0);
        assert_eq!(float(Some("1e3"), 7.0), 1000.0);
        assert!(float(Some("-inf"), 7.0).is_infinite());
        assert_eq!(int(Some("12.9"), 3), 12);
        assert_eq!(int(Some("nan"), 3), 3);
        let env = PerfEnv {
            monitor_enabled: Some("false".into()),
            max_endpoints: Some("2".into()),
            ..PerfEnv::default()
        };
        let cfg = PerfConfig::from_env(&env);
        assert!(!cfg.enabled);
        assert_eq!(cfg.max_endpoints, 2);
        assert_eq!(cfg.slow_query_ms, 250.0);
    }
}
