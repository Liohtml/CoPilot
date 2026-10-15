//! `connectors` — credentials of the first-party tools, and the process-wide
//! cache in front of them (port of `app/connectors/utils.py:
//! get_connector_info_from_db` and `app/connectors/cache.py`).
//!
//! Connector rows are deployment-wide and change only on operator action.
//! Misses are never cached (a newly added row must be visible at once), and a
//! per-name lock keeps concurrent cold requests from stampeding MySQL.
//!
//! **Cross-process caveat.** The Python backend invalidates *its* cache after
//! each write, but it cannot reach this one. While both services run, the
//! binary caps the TTL (see `copilot::app`), so an operator's change in the
//! legacy UI reaches the Rust service within that bound.

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
}

#[derive(Debug, Default)]
struct Inner {
    entries: HashMap<String, (Instant, ConnectorRow)>,
    stats: CacheStats,
}

/// Read-through TTL cache over [`find_by_name`].
#[derive(Debug, Clone)]
pub struct ConnectorCache {
    db: Db,
    ttl: Duration,
    inner: Arc<Mutex<Inner>>,
    locks: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
}

impl ConnectorCache {
    /// `ttl == 0` disables caching (every call reads MySQL).
    pub fn new(db: Db, ttl: Duration) -> Self {
        Self {
            db,
            ttl,
            inner: Arc::default(),
            locks: Arc::default(),
        }
    }

    /// The configured TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    fn peek(&self, name: &str) -> Option<ConnectorRow> {
        if self.ttl.is_zero() {
            return None;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match inner.entries.get(name) {
            Some((at, row)) if at.elapsed() < self.ttl => {
                let row = row.clone();
                inner.stats.hits += 1;
                Some(row)
            }
            Some(_) => {
                inner.entries.remove(name);
                None
            }
            None => None,
        }
    }

    /// `get_connector_info_from_db(name)` through the cache.
    pub async fn get(&self, name: &str) -> Result<Option<ConnectorRow>, DbError> {
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
        let loaded = find_by_name(&self.db, name).await?;
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.stats.misses += 1;
        if let (Some(row), false) = (&loaded, self.ttl.is_zero()) {
            inner
                .entries
                .insert(name.to_string(), (Instant::now(), row.clone()));
        }
        Ok(loaded)
    }

    /// Drop one entry (call after a committed write).
    pub fn invalidate(&self, name: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.entries.remove(name);
        inner.stats.invalidations += 1;
    }

    /// Drop everything.
    pub fn invalidate_all(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.entries.clear();
        inner.stats.invalidations += 1;
    }

    /// Counters.
    pub fn stats(&self) -> CacheStats {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        CacheStats {
            entries: inner.entries.len(),
            ..inner.stats
        }
    }
}
