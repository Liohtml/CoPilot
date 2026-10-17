//! Port of `app/customer_portal/services/branding_cache.py`: resolved
//! branding per customer (`None` = the global defaults), in this process.
//!
//! Every write route forgets every entry right after its commit
//! ([`BrandingCache::invalidate_all`]); the TTL (`BRANDING_CACHE_TTL_SECONDS`,
//! 600 s, `0` disables the cache) is a backstop. With the Python backend
//! running beside this one, either can write the branding tables, and
//! neither can reach the other's cache, so each one **checks**, with the
//! same rule and the same statement ([`super::services::fingerprint`]):
//! before serving an entry, a process whose last check began more than
//! `BRANDING_CACHE_CHECK_SECONDS` (5 s) ago reads the tables' fingerprint
//! and drops every entry when it differs from the last one it read. A load
//! that began before entries were dropped (by a check or a write) is not
//! stored. So no process serves branding older than the last committed
//! write for longer than the interval plus one query.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use copilot_db::DbError;

use super::services::FingerprintRow;
use crate::branding::schema::EffectiveBranding;

/// One entry: when it was stored, and the resolution.
type Entry = (Instant, EffectiveBranding);

#[derive(Debug, Default)]
struct State {
    entries: HashMap<Option<String>, Entry>,
    /// Bumped whenever the entries are dropped.
    epoch: u64,
    /// When the last change check began, and the fingerprint it read.
    checked: Option<(Instant, Vec<FingerprintRow>)>,
}

/// The cache. Shared by the routes of one process.
#[derive(Debug)]
pub struct BrandingCache {
    ttl: Duration,
    check: Duration,
    state: Mutex<State>,
}

impl BrandingCache {
    /// A cache with these intervals.
    pub fn new(ttl: Duration, check: Duration) -> Self {
        Self {
            ttl,
            check,
            state: Mutex::new(State::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn drop_entries(state: &mut State) {
        state.entries.clear();
        state.epoch += 1;
    }

    /// `_check`: at most one fingerprint read per interval; drop every entry
    /// when it changed.
    async fn check<F, Fut>(&self, fingerprint: F) -> Result<(), DbError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<FingerprintRow>, DbError>>,
    {
        let began = Instant::now();
        let due = match &self.lock().checked {
            Some((at, _)) => began.saturating_duration_since(*at) >= self.check,
            None => true,
        };
        if !due {
            return Ok(());
        }
        let current = fingerprint().await?;
        let mut state = self.lock();
        if state.checked.as_ref().is_some_and(|(at, _)| *at > began) {
            return Ok(()); // a check that began later has already run
        }
        if state.checked.as_ref().map(|(_, fp)| fp) != Some(&current) {
            Self::drop_entries(&mut state);
        }
        state.checked = Some((began, current));
        Ok(())
    }

    /// `get_or_load`: the resolution for `customer_code`, loaded at most once
    /// per TTL; `fingerprint` reads the tables for the change check.
    pub async fn get_or_load<L, LFut, F, FFut>(
        &self,
        customer_code: Option<&str>,
        loader: L,
        fingerprint: F,
    ) -> Result<EffectiveBranding, DbError>
    where
        L: FnOnce() -> LFut,
        LFut: Future<Output = Result<EffectiveBranding, DbError>>,
        F: FnOnce() -> FFut,
        FFut: Future<Output = Result<Vec<FingerprintRow>, DbError>>,
    {
        let key = customer_code.map(str::to_string);
        if !self.ttl.is_zero() {
            if !self.check.is_zero() {
                self.check(fingerprint).await?;
            }
            let state = self.lock();
            if let Some((stored, value)) = state.entries.get(&key) {
                if stored.elapsed() < self.ttl {
                    return Ok(value.clone());
                }
            }
        }
        let epoch = self.lock().epoch;
        let value = loader().await?;
        if !self.ttl.is_zero() {
            let mut state = self.lock();
            if state.epoch == epoch {
                state.entries.insert(key, (Instant::now(), value.clone()));
            }
        }
        Ok(value)
    }

    /// `invalidate_all`: forget every entry. Call after committing any write
    /// to either branding table.
    pub fn invalidate_all(&self) {
        Self::drop_entries(&mut self.lock());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn branding(title: &str) -> EffectiveBranding {
        EffectiveBranding {
            title: title.into(),
            logo_base64: None,
            logo_mime_type: None,
            brand_color: None,
            source: "global".into(),
            customer_code: None,
        }
    }

    fn fp(tag: &str) -> Vec<FingerprintRow> {
        vec![FingerprintRow {
            title: Some(tag.into()),
            ..FingerprintRow::default()
        }]
    }

    async fn get(cache: &BrandingCache, title: &str, tag: &str, loads: &AtomicUsize) -> String {
        cache
            .get_or_load(
                Some("acme"),
                || async {
                    loads.fetch_add(1, Ordering::SeqCst);
                    Ok(branding(title))
                },
                || async { Ok(fp(tag)) },
            )
            .await
            .map(|b| b.title)
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn checks_at_most_once_per_interval_and_sees_a_change() {
        let cache = BrandingCache::new(Duration::from_secs(600), Duration::from_millis(80));
        let loads = AtomicUsize::new(0);
        assert_eq!(get(&cache, "Before", "v1", &loads).await, "Before");
        assert_eq!(get(&cache, "After", "v2", &loads).await, "Before");
        assert_eq!(loads.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(get(&cache, "After", "v2", &loads).await, "After");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(get(&cache, "Other", "v2", &loads).await, "After");
        assert_eq!(loads.load(Ordering::SeqCst), 2, "unchanged: entries kept");
    }

    #[tokio::test]
    async fn a_load_racing_an_invalidation_is_not_stored() {
        let cache = BrandingCache::new(Duration::from_secs(600), Duration::ZERO);
        let value = cache
            .get_or_load(
                Some("acme"),
                || async {
                    cache.invalidate_all();
                    Ok(branding("Stale"))
                },
                || async { Ok(Vec::new()) },
            )
            .await
            .unwrap();
        assert_eq!(value.title, "Stale");
        assert!(cache.lock().entries.is_empty());
    }

    #[tokio::test]
    async fn ttl_zero_disables_the_cache() {
        let cache = BrandingCache::new(Duration::ZERO, Duration::from_secs(5));
        let loads = AtomicUsize::new(0);
        get(&cache, "A", "v1", &loads).await;
        get(&cache, "A", "v1", &loads).await;
        assert_eq!(loads.load(Ordering::SeqCst), 2);
    }
}
