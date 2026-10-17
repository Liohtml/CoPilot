//! `/api/performance` — port of `app/performance/` and of the
//! instrumentation it reads (`app/middleware/performance.py`,
//! `app/db/query_metrics.py`), reporting **this process**.
//!
//! With the Rust service in front it is the outermost process: every
//! request reaches it first, so its timer measures what the client waited
//! for — the time Python took on a proxied request included, which is what
//! `RequestTimingMiddleware` measured when Python was outermost (#1072). Its
//! lag watchdog measures the tokio runtime's scheduling delay, and its query
//! metrics this process's statements (sqlx's `sqlx::query` events). The
//! Python process keeps measuring itself into its session log files
//! (`backend/logs/performance/`), which no route reads any more. The numbers
//! of the two processes are not comparable: the parity suite compares the
//! shapes, units, ordering rules, guards and the reset (§4).
//!
//! Everything is in memory, bounded and per process, as in Python:
//!
//! - [`config`] — the `PERF_*` / `DB_*` settings
//! - [`registry`] — `PerformanceRegistry` (requests, endpoints, stalls)
//! - [`queries`] — `QueryRegistry`, its `summary()` and the tracing layer
//!   that feeds it
//! - [`middleware`] — `RequestTimingMiddleware`
//! - [`monitor`] — `EventLoopLagMonitor` and the pool sampler
//! - [`services`], [`schema`], [`routes`] — the six routes

pub mod config;
pub mod middleware;
pub mod monitor;
pub mod queries;
pub mod registry;
pub mod routes;
pub mod schema;
pub mod services;

use std::sync::{Mutex, MutexGuard, OnceLock};

pub use config::PerfConfig;
pub use queries::QueryMetricsLayer;
pub use routes::router;

/// This process's instrumentation (Python's module-level singletons).
#[derive(Debug)]
pub struct Perf {
    /// The settings read at start.
    pub config: PerfConfig,
    requests: Mutex<registry::Registry>,
    queries: Mutex<queries::QueryRegistry>,
    pool: Mutex<Option<sqlx::MySqlPool>>,
}

static PERF: OnceLock<Perf> = OnceLock::new();

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

impl Perf {
    fn new(config: PerfConfig) -> Self {
        Self {
            requests: Mutex::new(registry::Registry::new(&config)),
            queries: Mutex::new(queries::QueryRegistry::new(&config)),
            pool: Mutex::new(None),
            config,
        }
    }

    /// The request registry.
    pub fn requests(&self) -> MutexGuard<'_, registry::Registry> {
        lock(&self.requests)
    }

    /// The query registry.
    pub fn queries(&self) -> MutexGuard<'_, queries::QueryRegistry> {
        lock(&self.queries)
    }

    /// The pool whose occupancy is sampled (`query_registry._pool`).
    pub fn pool(&self) -> Option<sqlx::MySqlPool> {
        lock(&self.pool).clone()
    }

    /// `install(async_engine)`'s `query_registry._pool = async_engine.pool`.
    pub fn install_pool(&self, pool: sqlx::MySqlPool) {
        *lock(&self.pool) = Some(pool);
    }
}

/// Set this process's instrumentation up (the first call wins, as the
/// settings are read once at import in Python).
pub fn init(config: PerfConfig) -> &'static Perf {
    PERF.get_or_init(|| Perf::new(config))
}

/// The instrumentation, with the default settings when [`init`] has not
/// run yet.
pub fn perf() -> &'static Perf {
    PERF.get_or_init(|| Perf::new(PerfConfig::default()))
}

/// The instrumentation if it was set up (the query layer records nothing
/// before that).
pub fn installed() -> Option<&'static Perf> {
    PERF.get()
}

/// Python's `round(x, n)` for the figures these routes report.
pub fn py_round(x: f64, digits: usize) -> f64 {
    if !x.is_finite() {
        return x;
    }
    format!("{x:.digits$}").parse().unwrap_or(x)
}

/// `_percentile` / `percentile`: the nearest rank (`int(round(...))`,
/// half to even), rounded to 2 places; `0.0` for no samples.
pub fn percentile(samples: &[f64], pct: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut ordered = samples.to_vec();
    ordered.sort_by(f64::total_cmp);
    let position = (pct / 100.0) * (ordered.len() as f64 - 1.0);
    let index = position.round_ties_even();
    let last = ordered.len() - 1;
    let index = if index <= 0.0 {
        0
    } else {
        (index as usize).min(last)
    };
    py_round(ordered[index], 2)
}

/// `datetime.fromtimestamp(t, tz=timezone.utc).isoformat()`.
pub fn iso(epoch_seconds: f64) -> String {
    let micros = (epoch_seconds * 1_000_000.0).round_ties_even() as i64;
    match chrono::DateTime::<chrono::Utc>::from_timestamp_micros(micros) {
        Some(t) if micros % 1_000_000 == 0 => t.format("%Y-%m-%dT%H:%M:%S+00:00").to_string(),
        Some(t) => t.format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string(),
        None => String::new(),
    }
}

/// `time.time()`.
pub fn wall_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounding_and_ranks_follow_python() {
        assert_eq!(py_round(1.005, 2), 1.0);
        assert_eq!(py_round(2.675, 2), 2.67);
        assert_eq!(py_round(0.125, 2), 0.12);
        assert_eq!(percentile(&[], 50.0), 0.0);
        // round(0.5 * 3) = round(1.5) = 2; round(0.5 * 1) = round(0.5) = 0.
        assert_eq!(percentile(&[4.0, 1.0, 3.0, 2.0], 50.0), 3.0);
        assert_eq!(percentile(&[2.0, 1.0], 50.0), 1.0);
        assert_eq!(percentile(&[1.0, 2.0, 3.0], 99.0), 3.0);
        assert_eq!(iso(0.0), "1970-01-01T00:00:00+00:00");
        assert_eq!(iso(1.5), "1970-01-01T00:00:01.500000+00:00");
    }
}
