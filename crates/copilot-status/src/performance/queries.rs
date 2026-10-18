//! `app/db/query_metrics.py`: per-statement timings and connection-pool
//! occupancy, and `summary()` — the verdict that tells a slow statement, a
//! saturated pool and the per-round-trip cost apart.
//!
//! Python times statements with SQLAlchemy's cursor events; here sqlx's own
//! `sqlx::query` events carry each statement's text and elapsed time to
//! [`QueryMetricsLayer`]. The texts are sqlx's (`?` placeholders, the SQL
//! this process sends): never literal values.

use std::collections::{HashMap, VecDeque};
use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use super::config::PerfConfig;
use super::{percentile, py_round};

/// `StatementStats`.
#[derive(Debug, Clone)]
pub struct StatementStats {
    /// The digest.
    pub statement: String,
    /// Executions.
    pub count: u64,
    /// Summed durations.
    pub total_ms: f64,
    /// The longest.
    pub max_ms: f64,
    /// The last 200 durations.
    pub samples: VecDeque<f64>,
}

/// `QueryRegistry`.
#[derive(Debug)]
pub struct QueryRegistry {
    slow_query_ms: f64,
    query_samples: usize,
    max_statements: usize,
    statements: Vec<StatementStats>,
    index: HashMap<String, usize>,
    durations: VecDeque<f64>,
    /// Statements recorded.
    pub total_queries: u64,
    /// Their summed time.
    pub total_ms: f64,
    /// Those over `DB_SLOW_QUERY_MS`.
    pub slow_queries: u64,
    /// Statements not tracked past `DB_MAX_STATEMENTS`.
    pub dropped_statements: u64,
    /// Pool snapshots taken.
    pub pool_samples: u64,
    /// The most connections in use at a snapshot.
    pub pool_checked_out_peak: u64,
    /// Snapshots with every connection in use.
    pub pool_exhausted_samples: u64,
}

fn whitespace() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\s+").ok()).as_ref()
}

fn in_list() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)IN \(\s*(?:%s|\?)\s*(?:,\s*(?:%s|\?)\s*)+\)").ok())
        .as_ref()
}

/// `digest(statement)`: whitespace collapsed, `IN (?, ?, …)` folded, cut at
/// 220 characters.
pub fn digest(statement: &str) -> String {
    let collapsed = match whitespace() {
        Some(re) => re.replace_all(statement, " ").trim().to_string(),
        None => statement.trim().to_string(),
    };
    let folded = match in_list() {
        Some(re) => re.replace_all(&collapsed, "IN (...)").into_owned(),
        None => collapsed,
    };
    let limit = 220;
    if folded.chars().count() > limit {
        let cut: String = folded.chars().take(limit).collect();
        format!("{cut}\u{2026}")
    } else {
        folded
    }
}

impl QueryRegistry {
    /// A fresh registry.
    pub fn new(cfg: &PerfConfig) -> Self {
        Self {
            slow_query_ms: cfg.slow_query_ms,
            query_samples: cfg.query_samples,
            max_statements: cfg.max_statements,
            statements: Vec::new(),
            index: HashMap::new(),
            durations: VecDeque::new(),
            total_queries: 0,
            total_ms: 0.0,
            slow_queries: 0,
            dropped_statements: 0,
            pool_samples: 0,
            pool_checked_out_peak: 0,
            pool_exhausted_samples: 0,
        }
    }

    /// `reset()` (the pool stays attached).
    pub fn reset(&mut self) {
        let cfg = PerfConfig {
            slow_query_ms: self.slow_query_ms,
            query_samples: self.query_samples,
            max_statements: self.max_statements,
            ..PerfConfig::default()
        };
        *self = Self::new(&cfg);
    }

    /// `record(statement, duration_ms)`.
    pub fn record(&mut self, statement: &str, duration_ms: f64) {
        self.total_queries += 1;
        self.total_ms += duration_ms;
        if self.query_samples > 0 {
            self.durations.push_back(duration_ms);
            while self.durations.len() > self.query_samples {
                self.durations.pop_front();
            }
        }
        let key = digest(statement);
        let i = match self.index.get(&key) {
            Some(i) => *i,
            None => {
                if self.statements.len() >= self.max_statements {
                    self.dropped_statements += 1;
                    return;
                }
                self.statements.push(StatementStats {
                    statement: key.clone(),
                    count: 0,
                    total_ms: 0.0,
                    max_ms: 0.0,
                    samples: VecDeque::new(),
                });
                self.index.insert(key.clone(), self.statements.len() - 1);
                self.statements.len() - 1
            }
        };
        let stats = &mut self.statements[i];
        stats.count += 1;
        stats.total_ms += duration_ms;
        stats.samples.push_back(duration_ms);
        while stats.samples.len() > 200 {
            stats.samples.pop_front();
        }
        if duration_ms > stats.max_ms {
            stats.max_ms = duration_ms;
        }
        if duration_ms >= self.slow_query_ms {
            self.slow_queries += 1;
            tracing::info!(
                duration_ms = py_round(duration_ms, 1),
                statement = %key,
                "PERF: slow query"
            );
        }
    }

    /// `sample_pool()`: how much of the pool is in use now.
    pub fn sample_pool(&mut self, pool: Option<&sqlx::MySqlPool>) {
        let Some(pool) = pool else {
            return;
        };
        let (checked_out, capacity) = occupancy(pool);
        self.pool_samples += 1;
        if checked_out > self.pool_checked_out_peak {
            self.pool_checked_out_peak = checked_out;
        }
        if capacity != 0 && checked_out >= capacity {
            self.pool_exhausted_samples += 1;
        }
    }

    /// `pool_state()`.
    pub fn pool_state(&self, pool: Option<&sqlx::MySqlPool>) -> PoolState {
        let Some(pool) = pool else {
            return PoolState::default();
        };
        let (checked_out, capacity) = occupancy(pool);
        PoolState {
            size: Some(capacity),
            checked_out: Some(checked_out),
            overflow: Some(0),
            peak_checked_out: Some(self.pool_checked_out_peak),
            exhausted_samples: Some(self.pool_exhausted_samples),
            samples: Some(self.pool_samples),
        }
    }

    /// `summary()`.
    pub fn summary(&self, pool: Option<&sqlx::MySqlPool>, top: usize) -> DatabaseFigures {
        let durations: Vec<f64> = self.durations.iter().copied().collect();
        let mut statements: Vec<&StatementStats> =
            self.statements.iter().filter(|s| s.count != 0).collect();
        // `list.sort(key=…, reverse=True)`: stable, ties keep their order.
        statements.sort_by(|a, b| b.total_ms.total_cmp(&a.total_ms));
        let p50 = percentile(&durations, 50.0);
        let p99 = percentile(&durations, 99.0);
        let verdict = if durations.is_empty() {
            "No queries recorded yet.".to_string()
        } else if p50 >= 50.0 {
            format!(
                "Every statement pays ~{p50:.0}ms (p50), so the cost is per-round-trip, not \
                 per-query \u{2014} indexes will not move this. Look at where the database runs, not \
                 at the SQL."
            )
        } else if self.pool_exhausted_samples != 0 {
            format!(
                "The pool was fully checked out on {} of {} samples: requests are queueing for a \
                 connection, which looks like a slow query but is not one.",
                self.pool_exhausted_samples, self.pool_samples
            )
        } else if p99 >= 250.0 {
            format!(
                "Baseline is healthy (p50 {p50:.0}ms) but the tail is not (p99 {p99:.0}ms) \u{2014} a \
                 few statements are the problem."
            )
        } else {
            format!("Database is not a bottleneck: p50 {p50:.0}ms, p99 {p99:.0}ms.")
        };
        let max_ms = durations.iter().copied().fold(None, |m: Option<f64>, d| {
            Some(m.map_or(d, |m| if d > m { d } else { m }))
        });
        DatabaseFigures {
            queries: self.total_queries,
            total_ms: py_round(self.total_ms, 1),
            slow_queries: self.slow_queries,
            slow_query_threshold_ms: self.slow_query_ms,
            p50_ms: p50,
            p95_ms: percentile(&durations, 95.0),
            p99_ms: p99,
            max_ms: max_ms.map_or(0.0, |m| py_round(m, 2)),
            pool: self.pool_state(pool),
            dropped_statements: self.dropped_statements,
            verdict,
            top_statements: statements
                .into_iter()
                .take(top)
                .map(|s| {
                    let samples: Vec<f64> = s.samples.iter().copied().collect();
                    QueryStatement {
                        statement: s.statement.clone(),
                        count: s.count,
                        total_ms: py_round(s.total_ms, 1),
                        avg_ms: py_round(s.total_ms / s.count as f64, 2),
                        p95_ms: percentile(&samples, 95.0),
                        max_ms: py_round(s.max_ms, 2),
                    }
                })
                .collect(),
        }
    }
}

/// `(checked out, capacity)`: sqlx's pool has no overflow, so its capacity
/// is `max_connections`.
fn occupancy(pool: &sqlx::MySqlPool) -> (u64, u64) {
    let open = u64::from(pool.size());
    let idle = u64::try_from(pool.num_idle()).unwrap_or(u64::MAX);
    let capacity = u64::from(pool.options().get_max_connections());
    (open.saturating_sub(idle), capacity)
}

/// `PoolState` (every field `None` without a pool).
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct PoolState {
    /// The pool's capacity.
    pub size: Option<u64>,
    /// Connections in use now.
    pub checked_out: Option<u64>,
    /// Connections beyond the pool size (always 0 for sqlx).
    pub overflow: Option<u64>,
    /// The most in use at a snapshot.
    pub peak_checked_out: Option<u64>,
    /// Snapshots with every connection in use.
    pub exhausted_samples: Option<u64>,
    /// Snapshots taken.
    pub samples: Option<u64>,
}

/// `QueryStatement`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct QueryStatement {
    /// The digest.
    pub statement: String,
    /// Executions.
    pub count: u64,
    /// Summed time.
    pub total_ms: f64,
    /// Mean.
    pub avg_ms: f64,
    /// 95th percentile.
    pub p95_ms: f64,
    /// The longest.
    pub max_ms: f64,
}

/// `summary()`'s figures (the answer's fields after `success` and
/// `message`).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DatabaseFigures {
    /// Statements recorded.
    pub queries: u64,
    /// Their summed time.
    pub total_ms: f64,
    /// Slow ones.
    pub slow_queries: u64,
    /// `DB_SLOW_QUERY_MS`.
    pub slow_query_threshold_ms: f64,
    /// Median.
    pub p50_ms: f64,
    /// 95th percentile.
    pub p95_ms: f64,
    /// 99th percentile.
    pub p99_ms: f64,
    /// The longest.
    pub max_ms: f64,
    /// Pool occupancy.
    pub pool: PoolState,
    /// Statements not tracked.
    pub dropped_statements: u64,
    /// The reading.
    pub verdict: String,
    /// The costliest statements.
    pub top_statements: Vec<QueryStatement>,
}

/// Feeds the query registry from sqlx's `sqlx::query` events (their
/// `summary`, `db.statement` and `elapsed_secs` fields). Installed by the
/// binary with a filter of its own that enables that target at `DEBUG`;
/// records nothing until [`super::init`] has run.
#[derive(Debug, Clone, Copy, Default)]
pub struct QueryMetricsLayer;

/// The `sqlx::query` target.
pub const SQLX_QUERY_TARGET: &str = "sqlx::query";

#[derive(Default)]
struct QueryFields {
    summary: Option<String>,
    statement: Option<String>,
    elapsed_secs: Option<f64>,
}

impl Visit for QueryFields {
    fn record_f64(&mut self, field: &Field, value: f64) {
        if field.name() == "elapsed_secs" {
            self.elapsed_secs = Some(value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "summary" => self.summary = Some(value.to_string()),
            "db.statement" => self.statement = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "summary" if self.summary.is_none() => self.summary = Some(format!("{value:?}")),
            "db.statement" if self.statement.is_none() => {
                self.statement = Some(format!("{value:?}"));
            }
            _ => {}
        }
    }
}

impl<S: Subscriber> Layer<S> for QueryMetricsLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != SQLX_QUERY_TARGET {
            return;
        }
        let Some(perf) = super::installed() else {
            return;
        };
        let mut fields = QueryFields::default();
        event.record(&mut fields);
        let Some(elapsed) = fields.elapsed_secs else {
            return;
        };
        // sqlx writes the whole text only when its 4-word summary is not it.
        let statement = match fields.statement.as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => fields.summary.unwrap_or_default(),
        };
        perf.queries().record(&statement, elapsed * 1000.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_fold_like_python() {
        assert_eq!(
            digest("SELECT a\n  FROM t WHERE id IN (?, ?,?)  "),
            "SELECT a FROM t WHERE id IN (...)"
        );
        assert_eq!(
            digest("select 1 from t where x in (%s, %s)"),
            "select 1 from t where x IN (...)"
        );
        assert_eq!(digest("x IN (?)"), "x IN (?)");
        let long = "x".repeat(230);
        assert_eq!(digest(&long), format!("{}\u{2026}", "x".repeat(220)));
    }

    #[test]
    fn summaries_read_the_causes() {
        let cfg = PerfConfig {
            max_statements: 1,
            ..PerfConfig::default()
        };
        let mut q = QueryRegistry::new(&cfg);
        assert_eq!(q.summary(None, 12).verdict, "No queries recorded yet.");
        q.record("SELECT 1", 2.0);
        q.record("SELECT 1", 4.0);
        q.record("SELECT 2", 300.0);
        let s = q.summary(None, 12);
        assert_eq!(s.queries, 3);
        assert_eq!(s.dropped_statements, 1);
        // A statement past the cap is timed but not counted slow (Python
        // returns before the check).
        assert_eq!(s.slow_queries, 0);
        assert_eq!(s.top_statements.len(), 1);
        assert_eq!(s.top_statements[0].count, 2);
        assert_eq!(s.top_statements[0].avg_ms, 3.0);
        assert_eq!(s.pool, PoolState::default());
        assert_eq!(
            s.verdict,
            "Baseline is healthy (p50 4ms) but the tail is not (p99 300ms) \u{2014} a few \
             statements are the problem."
        );
        q.reset();
        assert_eq!(q.total_queries, 0);
    }
}
