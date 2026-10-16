//! `connectors` — credentials of the first-party tools, and the process-wide
//! cache in front of them (port of `app/connectors/utils.py:
//! get_connector_info_from_db` and `app/connectors/cache.py`).
//!
//! Connector rows are deployment-wide and change only on operator action.
//! Misses are never cached (a newly added row must be visible at once), and a
//! per-name lock keeps concurrent cold requests from stampeding MySQL.
//!
//! **Across processes.** The Python backend and this service each cache
//! rows, and neither can reach the other's memory. Each therefore *checks*:
//! before it serves a cached row, a process whose last look at the table is
//! older than the check interval (`CONNECTOR_CACHE_CHECK_SECONDS`, 5 s) reads
//! every row once and drops the cached rows that no longer match. A row is
//! served only if MySQL confirmed it — by its load or by a check — no earlier
//! than the last check began, so after any committed write (either backend,
//! the startup sync, or by hand) no process serves the old row for longer
//! than the interval plus one query; the writer itself forgets it at once
//! ([`ConnectorCache::invalidate`] after its commit). The same rule runs in
//! `backend/app/connectors/cache.py`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::NaiveDateTime;
use serde::Serialize;
use sqlx::FromRow;
use tokio::sync::Mutex as AsyncMutex;

use crate::{Db, DbError};

/// One `connectors` row.
#[derive(Clone, PartialEq, Eq, FromRow, Serialize)]
pub struct ConnectorRow {
    /// Primary key.
    pub id: i32,
    /// `Talon`, `Wazuh-Indexer`, … (no unique index; first match wins).
    pub connector_name: String,
    /// Connector kind.
    pub connector_type: String,
    /// Base URL (seeded as `""` when unset).
    pub connector_url: String,
    /// Last change.
    pub connector_last_updated: NaiveDateTime,
    /// User name, for username/password connectors.
    pub connector_username: Option<String>,
    /// Password (secret).
    pub connector_password: Option<String>,
    /// API key (secret) — for Velociraptor a *file path*.
    pub connector_api_key: Option<String>,
    /// Description.
    pub connector_description: Option<String>,
    /// Capability text.
    pub connector_supports: Option<String>,
    /// Operator filled the form in.
    pub connector_configured: bool,
    /// Last verification succeeded.
    pub connector_verified: bool,
    /// Accepts a host only.
    pub connector_accepts_host_only: bool,
    /// Accepts an API key.
    pub connector_accepts_api_key: bool,
    /// Accepts username/password.
    pub connector_accepts_username_password: bool,
    /// Accepts a file upload.
    pub connector_accepts_file: bool,
    /// Accepts extra data.
    pub connector_accepts_extra_data: bool,
    /// Extra data (`ORG,BUCKET` for InfluxDB, …).
    pub connector_extra_data: Option<String>,
    /// Enabled in the UI.
    pub connector_enabled: bool,
}

impl std::fmt::Debug for ConnectorRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectorRow")
            .field("id", &self.id)
            .field("connector_name", &self.connector_name)
            .field("connector_url", &self.connector_url)
            .field("connector_enabled", &self.connector_enabled)
            .finish_non_exhaustive()
    }
}

const SELECT: &str = "SELECT id, connector_name, connector_type, connector_url, \
     connector_last_updated, connector_username, connector_password, connector_api_key, \
     connector_description, connector_supports, connector_configured, connector_verified, \
     connector_accepts_host_only, connector_accepts_api_key, \
     connector_accepts_username_password, connector_accepts_file, \
     connector_accepts_extra_data, connector_extra_data, connector_enabled FROM connectors";

/// Uncached read of the first row with this name.
pub async fn find_by_name(db: &Db, name: &str) -> Result<Option<ConnectorRow>, DbError> {
    let row = sqlx::query_as::<_, ConnectorRow>(&format!(
        "{SELECT} WHERE connector_name = ? ORDER BY id LIMIT 1"
    ))
    .bind(name)
    .fetch_optional(db.pool())
    .await?;
    Ok(row)
}

/// Every row, as `select(Connectors)` reads them: no `ORDER BY`, so MySQL
/// returns them in the same order to either backend.
pub async fn list_unordered(db: &Db) -> Result<Vec<ConnectorRow>, DbError> {
    let rows = sqlx::query_as::<_, ConnectorRow>(SELECT)
        .fetch_all(db.pool())
        .await?;
    Ok(rows)
}

/// Uncached read of one row by primary key.
pub async fn find_by_id(db: &Db, id: i64) -> Result<Option<ConnectorRow>, DbError> {
    let row = sqlx::query_as::<_, ConnectorRow>(&format!("{SELECT} WHERE id = ?"))
        .bind(id)
        .fetch_optional(db.pool())
        .await?;
    Ok(row)
}

/// Every row in id order (the change check's snapshot; `select(Connectors)`'s
/// order).
pub async fn all_rows(db: &Db) -> Result<Vec<ConnectorRow>, DbError> {
    let rows = sqlx::query_as::<_, ConnectorRow>(&format!("{SELECT} ORDER BY id"))
        .fetch_all(db.pool())
        .await?;
    Ok(rows)
}

/// The default interval of the cross-process change check.
pub const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Cache counters (`cache.stats()`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CacheStats {
    /// Live entries.
    pub entries: usize,
    /// Served from cache.
    pub hits: u64,
    /// Loaded from MySQL.
    pub misses: u64,
    /// Explicit invalidations.
    pub invalidations: u64,
    /// Change checks run (one table read each).
    pub checks: u64,
    /// Entries a check found changed (or gone) and dropped.
    pub stale_dropped: u64,
}

#[derive(Debug)]
struct Entry {
    /// When the load that produced it began (the TTL counts from here).
    loaded_at: Instant,
    /// The latest moment MySQL confirmed this row: its load or a check.
    confirmed_at: Instant,
    row: ConnectorRow,
}

#[derive(Debug, Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    /// When the last successful change check began.
    checked_at: Option<Instant>,
    stats: CacheStats,
}

/// Read-through TTL cache over [`find_by_name`], kept honest across
/// processes by a periodic change check (see the module docs).
#[derive(Debug, Clone)]
pub struct ConnectorCache {
    db: Db,
    ttl: Duration,
    check_interval: Duration,
    inner: Arc<Mutex<Inner>>,
    locks: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
    check_lock: Arc<AsyncMutex<()>>,
}

impl ConnectorCache {
    /// `ttl == 0` disables caching (every call reads MySQL). The change
    /// check runs every [`DEFAULT_CHECK_INTERVAL`].
    pub fn new(db: Db, ttl: Duration) -> Self {
        Self {
            db,
            ttl,
            check_interval: DEFAULT_CHECK_INTERVAL,
            inner: Arc::default(),
            locks: Arc::default(),
            check_lock: Arc::default(),
        }
    }

    /// Set the change-check interval (`CONNECTOR_CACHE_CHECK_SECONDS`);
    /// zero turns the check off (rows then live for the TTL).
    pub fn with_check_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval;
        self
    }

    /// The configured TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The configured change-check interval.
    pub fn check_interval(&self) -> Duration {
        self.check_interval
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn check_due(&self) -> bool {
        if self.ttl.is_zero() || self.check_interval.is_zero() {
            return false;
        }
        let inner = self.lock_inner();
        inner
            .checked_at
            .is_none_or(|at| at.elapsed() >= self.check_interval)
    }

    /// The change check: read every row once and drop the cached rows that
    /// differ from (or no longer have) their row. A failed read drops every
    /// entry — a row that cannot be confirmed is not served.
    async fn revalidate(&self) {
        if !self.check_due() {
            return;
        }
        let _guard = self.check_lock.lock().await;
        if !self.check_due() {
            return;
        }
        let started = Instant::now();
        let rows = all_rows(&self.db).await;
        let mut inner = self.lock_inner();
        inner.stats.checks += 1;
        let rows = match rows {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(err = %e, "connector cache check failed; dropping cached rows");
                let n = inner.entries.len() as u64;
                inner.entries.clear();
                inner.stats.stale_dropped += n;
                return;
            }
        };
        // `select(Connectors).where(name == …).first()`: the lowest id wins.
        let mut current: HashMap<&str, &ConnectorRow> = HashMap::new();
        for row in &rows {
            current.entry(row.connector_name.as_str()).or_insert(row);
        }
        let before = inner.entries.len();
        inner
            .entries
            .retain(|name, entry| current.get(name.as_str()) == Some(&&entry.row));
        let dropped = (before - inner.entries.len()) as u64;
        inner.stats.stale_dropped += dropped;
        for entry in inner.entries.values_mut() {
            entry.confirmed_at = started;
        }
        inner.checked_at = Some(started);
    }

    fn peek(&self, name: &str) -> Option<ConnectorRow> {
        if self.ttl.is_zero() {
            return None;
        }
        let mut inner = self.lock_inner();
        let checked_at = inner.checked_at;
        let entry = inner.entries.get(name)?;
        let fresh = entry.loaded_at.elapsed() < self.ttl
            && (self.check_interval.is_zero()
                || checked_at.is_none_or(|at| entry.confirmed_at >= at));
        if !fresh {
            inner.entries.remove(name);
            return None;
        }
        let row = inner.entries.get(name).map(|e| e.row.clone());
        inner.stats.hits += 1;
        row
    }

    /// `get_connector_info_from_db(name)` through the cache.
    pub async fn get(&self, name: &str) -> Result<Option<ConnectorRow>, DbError> {
        self.revalidate().await;
        if let Some(row) = self.peek(name) {
            return Ok(Some(row));
        }
        let lock = {
            let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
            locks.entry(name.to_string()).or_default().clone()
        };
        let _guard = lock.lock().await;
        if let Some(row) = self.peek(name) {
            return Ok(Some(row));
        }
        let started = Instant::now();
        let loaded = find_by_name(&self.db, name).await?;
        let mut inner = self.lock_inner();
        inner.stats.misses += 1;
        if let (Some(row), false) = (&loaded, self.ttl.is_zero()) {
            inner.entries.insert(
                name.to_string(),
                Entry {
                    loaded_at: started,
                    confirmed_at: started,
                    row: row.clone(),
                },
            );
        }
        Ok(loaded)
    }

    /// Drop one entry (call after a committed write).
    pub fn invalidate(&self, name: &str) {
        let mut inner = self.lock_inner();
        inner.entries.remove(name);
        inner.stats.invalidations += 1;
    }

    /// Drop everything.
    pub fn invalidate_all(&self) {
        let mut inner = self.lock_inner();
        inner.entries.clear();
        inner.stats.invalidations += 1;
    }

    /// Counters.
    pub fn stats(&self) -> CacheStats {
        let inner = self.lock_inner();
        CacheStats {
            entries: inner.entries.len(),
            ..inner.stats
        }
    }
}
