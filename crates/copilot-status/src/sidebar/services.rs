//! `build_sidebar_context` and the process state behind it: the shared
//! indicators (`refresh_shared_indicators`, served while younger than 600 s),
//! the InfluxDB health value (`refresh_influx_health_indicator`, the same
//! TTL) and the version fields (`_get_version_fields`, 30 minutes).
//!
//! A refresh runs at most once at a time (Python's `asyncio.Lock`, checked
//! with `locked()`: a second caller returns at once), and a request that
//! finds a value stale starts one background refresh and answers with what
//! it has — never waiting for it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration as StdDuration;

use chrono::{Duration, NaiveDateTime};
use copilot_auth::pyvalue::PyValue;
use copilot_platform::pep440::Version;
use copilot_platform::version::{CURRENT_VERSION, Release};
use copilot_threat_intel::httpx;
use copilot_upstream::model::{Field, Model, Ty, construct, kwargs};
use copilot_web::{ApiError, CurrentUser};
use futures::future::join_all;
use tokio::sync::{Mutex, Semaphore};

use super::SidebarState;
use super::indicators::{self, Built};
use super::schema::{Indicator, SidebarResponse};

/// `SHARED_INDICATORS_TTL_SECONDS`.
pub const SHARED_TTL: StdDuration = StdDuration::from_secs(600);
/// `_INFLUX_INDICATOR_TTL_SECONDS`.
pub const INFLUX_TTL: StdDuration = StdDuration::from_secs(600);
/// `_VERSION_CACHE_MINUTES`.
pub const VERSION_TTL: StdDuration = StdDuration::from_secs(30 * 60);
/// `INDICATOR_CONCURRENCY` (the request path's per-user builders).
const INDICATOR_CONCURRENCY: usize = 6;
/// `SHARED_REFRESH_CONCURRENCY`.
const SHARED_REFRESH_CONCURRENCY: usize = 3;

/// An audience tag (`analyst`, `customer`, `admin`).
pub type Audience = u8;
/// `analyst`: admins, analysts and responders.
pub const ANALYST: Audience = 1;
/// `customer`: portal users.
pub const CUSTOMER: Audience = 2;
/// `admin`.
pub const ADMIN: Audience = 4;

/// The fourteen deployment-wide builders, in the order the sidebar renders
/// them (`_SHARED_BUILDERS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shared {
    /// `build_tag_rbac_indicator`.
    TagRbac,
    /// `build_ai_analyst_jobs_indicator`.
    AiAnalystJobs,
    /// `build_mem_palace_indicator`.
    MemPalace,
    /// `build_notification_dispatch_indicator`.
    NotificationDispatch,
    /// `build_scheduler_indicator_excluding_agent_sync`.
    Scheduler,
    /// `build_agent_sync_indicator`.
    AgentSync,
    /// `build_talon_indicator`.
    Talon,
    /// `build_core_soc_tools_indicator`.
    CoreSocTools,
    /// `build_wazuh_indexer_indicator`.
    WazuhIndexer,
    /// `_build_wazuh_catalog_indicator`.
    WazuhCatalog,
    /// `build_influx_health_indicator`.
    InfluxHealth,
    /// `_build_connector_indicator`.
    Connectors,
    /// `build_license_indicator`.
    License,
    /// `build_platform_storage_indicator`.
    PlatformStorage,
}

/// `_SHARED_BUILDERS` with their audiences.
pub const SHARED_BUILDERS: &[(Shared, Audience)] = &[
    (Shared::TagRbac, ANALYST),
    (Shared::AiAnalystJobs, ANALYST),
    (Shared::MemPalace, ANALYST),
    (Shared::NotificationDispatch, ANALYST),
    (Shared::Scheduler, ANALYST),
    (Shared::AgentSync, ANALYST),
    (Shared::Talon, ANALYST),
    (Shared::CoreSocTools, ANALYST),
    (Shared::WazuhIndexer, ANALYST),
    (Shared::WazuhCatalog, ANALYST | CUSTOMER),
    (Shared::InfluxHealth, ANALYST),
    (Shared::Connectors, ADMIN),
    (Shared::License, ADMIN),
    (Shared::PlatformStorage, ADMIN),
];

/// The version fields of the answer (`_VERSION_CACHE`).
#[derive(Debug, Clone, PartialEq)]
pub struct VersionFields {
    /// `current_version`.
    pub current_version: String,
    /// `latest_version`.
    pub latest_version: Option<String>,
    /// `bool(is_outdated)`.
    pub is_outdated: bool,
    /// `release_url`: GitHub's `html_url` as it came (a non-string fails
    /// the answer's model).
    pub release_url: PyValue,
}

type Stamped<T> = Option<(T, NaiveDateTime)>;

/// This process's sidebar state.
#[derive(Debug, Default)]
pub struct SidebarCache {
    shared: RwLock<Stamped<Vec<(Indicator, Audience)>>>,
    shared_lock: Mutex<()>,
    shared_task: AtomicBool,
    influx: RwLock<Stamped<Indicator>>,
    influx_lock: Mutex<()>,
    influx_task: AtomicBool,
    version: RwLock<Stamped<VersionFields>>,
}

fn read<T: Clone>(lock: &RwLock<T>) -> T {
    match lock.read() {
        Ok(g) => g.clone(),
        Err(p) => p.into_inner().clone(),
    }
}

fn write<T>(lock: &RwLock<T>, value: T) {
    match lock.write() {
        Ok(mut g) => *g = value,
        Err(p) => *p.into_inner() = value,
    }
}

fn utcnow() -> NaiveDateTime {
    copilot_core::time::now_utc_micros()
}

fn younger_than(at: NaiveDateTime, ttl: StdDuration) -> bool {
    let ttl = Duration::from_std(ttl).unwrap_or(Duration::MAX);
    utcnow() - at < ttl
}

impl SidebarCache {
    /// Whether the shared set exists and is younger than its TTL
    /// (`_shared_indicators_are_fresh`).
    pub fn shared_is_fresh(&self) -> bool {
        read(&self.shared).is_some_and(|(_, at)| younger_than(at, SHARED_TTL))
    }

    /// Whether the shared set has been computed at least once.
    pub fn has_shared(&self) -> bool {
        read(&self.shared).is_some()
    }
}

// --- the shared set -------------------------------------------------------------------------

async fn build_shared(st: &SidebarState, which: Shared) -> Built {
    match which {
        Shared::TagRbac => indicators::tag_rbac(st).await,
        Shared::AiAnalystJobs => indicators::ai_analyst_jobs(st).await,
        Shared::MemPalace => indicators::mem_palace(st).await,
        Shared::NotificationDispatch => indicators::notification_dispatch(st).await,
        Shared::Scheduler => indicators::scheduler(st).await,
        Shared::AgentSync => indicators::agent_sync(st).await,
        Shared::Talon => indicators::talon(st).await,
        Shared::CoreSocTools => indicators::core_soc_tools(st).await,
        Shared::WazuhIndexer => indicators::wazuh_indexer(st).await,
        Shared::WazuhCatalog => indicators::wazuh_catalog(st).await,
        Shared::InfluxHealth => Ok(influx_health(st)),
        Shared::Connectors => indicators::connectors(st).await,
        Shared::License => indicators::license(st).await,
        Shared::PlatformStorage => indicators::platform_storage(st).await,
    }
}

/// `safe_build`: a builder's exception is logged and the indicator left
/// out.
fn safe(name: &str, built: Built) -> Option<Indicator> {
    match built {
        Ok(i) => Some(i),
        Err(e) => {
            tracing::warn!("Sidebar indicator {name} failed: {e}");
            None
        }
    }
}

/// `refresh_shared_indicators()`: every deployment-wide indicator, three at
/// a time; returns at once while another refresh runs.
pub async fn refresh_shared(st: &SidebarState) {
    let Ok(_guard) = st.cache.shared_lock.try_lock() else {
        return;
    };
    let limiter = Arc::new(Semaphore::new(SHARED_REFRESH_CONCURRENCY));
    let runs = SHARED_BUILDERS.iter().map(|(which, audience)| {
        let limiter = limiter.clone();
        async move {
            let _permit = limiter.acquire().await.ok();
            let built = build_shared(st, *which).await;
            safe(&format!("{which:?}"), built).map(|i| (i, *audience))
        }
    });
    let set: Vec<(Indicator, Audience)> = join_all(runs).await.into_iter().flatten().collect();
    write(&st.cache.shared, Some((set, utcnow())));
}

/// `_schedule_shared_refresh()`: one background refresh at a time.
pub fn schedule_shared_refresh(st: &SidebarState) {
    if st.cache.shared_task.swap(true, Ordering::SeqCst) {
        return;
    }
    let st = st.clone();
    tokio::spawn(async move {
        refresh_shared(&st).await;
        st.cache.shared_task.store(false, Ordering::SeqCst);
    });
}

/// `_visible_shared_indicators(audience_tags)`.
fn visible_shared(st: &SidebarState, tags: Audience) -> Vec<Indicator> {
    match read(&st.cache.shared) {
        None => Vec::new(),
        Some((set, _)) => set
            .into_iter()
            .filter(|(_, audience)| audience & tags != 0)
            .map(|(i, _)| i)
            .collect(),
    }
}

// --- InfluxDB -----------------------------------------------------------------------------------

/// `refresh_influx_health_indicator()`.
pub async fn refresh_influx(st: &SidebarState) {
    let Ok(_guard) = st.cache.influx_lock.try_lock() else {
        return;
    };
    let indicator = indicators::compute_influx_health(st).await;
    write(&st.cache.influx, Some((indicator, utcnow())));
}

/// `_schedule_influx_refresh()`.
pub fn schedule_influx_refresh(st: &SidebarState) {
    if st.cache.influx_task.swap(true, Ordering::SeqCst) {
        return;
    }
    let st = st.clone();
    tokio::spawn(async move {
        refresh_influx(&st).await;
        st.cache.influx_task.store(false, Ordering::SeqCst);
    });
}

/// `build_influx_health_indicator()`: the last value while younger than
/// its TTL, else "checking" and a background refresh.
fn influx_health(st: &SidebarState) -> Indicator {
    if let Some((indicator, at)) = read(&st.cache.influx) {
        // `datetime.utcnow() - at > timedelta(...)` is stale.
        let ttl = Duration::from_std(INFLUX_TTL).unwrap_or(Duration::MAX);
        if utcnow() - at <= ttl {
            return indicator;
        }
    }
    schedule_influx_refresh(st);
    Indicator::new(
        "influx_health",
        "ok",
        "Healthchecks",
        "Checking InfluxDB healthchecks\u{2026}",
        0,
        "infrastructure",
    )
}

// --- the version --------------------------------------------------------------------------------

/// `get_latest_version()`: GitHub's latest release as httpx fetches it, or
/// `None` on any failure.
async fn latest_release(st: &SidebarState) -> Option<Release> {
    let request = httpx::Request::new(http::Method::GET, st.env.version_check_url.clone())
        .timeout(httpx::DEFAULT_TIMEOUT);
    let response = match httpx::send(request).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Failed to fetch latest version: {}", e.message);
            return None;
        }
    };
    if response.status != 200 {
        return None;
    }
    let data: serde_json::Value = serde_json::from_slice(&response.content).ok()?;
    Release::from_json(&data)
}

fn py_of(v: &serde_json::Value) -> PyValue {
    copilot_upstream::respond::from_json(v)
}

/// `check_version_outdated()` read by `_get_version_fields`.
async fn fetch_version(st: &SidebarState) -> VersionFields {
    let Some(release) = latest_release(st).await else {
        return VersionFields {
            current_version: CURRENT_VERSION.into(),
            latest_version: None,
            is_outdated: false,
            release_url: PyValue::None,
        };
    };
    let latest = release.tag_name.clone();
    let is_outdated = match (Version::parse(CURRENT_VERSION), Version::parse(&latest)) {
        (Some(current), Some(newest)) => current < newest,
        _ => {
            tracing::error!("Error comparing versions ({latest})");
            false
        }
    };
    VersionFields {
        current_version: CURRENT_VERSION.into(),
        latest_version: Some(latest),
        is_outdated,
        release_url: py_of(&release.html_url),
    }
}

/// `_get_version_fields()`: cached for 30 minutes, failures included.
pub async fn version_fields(st: &SidebarState) -> VersionFields {
    if let Some((fields, at)) = read(&st.cache.version) {
        if younger_than(at, VERSION_TTL) {
            return fields;
        }
    }
    let fields = fetch_version(st).await;
    write(&st.cache.version, Some((fields.clone(), utcnow())));
    fields
}

// --- the request --------------------------------------------------------------------------------

/// `SidebarContextResponse`'s one field a remote value can fail.
static RELEASE_URL_FIELD: Model = Model::new(
    "SidebarContextResponse",
    &[Field::opt("release_url", Ty::Nullable(&Ty::Str))],
);

/// The audience tags of a role (`build_sidebar_context`).
pub fn audience_of(role_id: Option<i32>) -> Audience {
    let mut tags = 0;
    if matches!(role_id, Some(1 | 2 | 5)) {
        tags |= ANALYST;
    }
    if role_id == Some(4) {
        tags |= CUSTOMER;
    }
    if role_id == Some(1) {
        tags |= ADMIN;
    }
    tags
}

/// The per-user builders (`_gather_indicators`), in order, each on its own
/// connection, failures left out.
async fn personal(st: &SidebarState, user: &CurrentUser, tags: Audience) -> Vec<Indicator> {
    if tags & (ANALYST | CUSTOMER) == 0 {
        return Vec::new();
    }
    let limiter = Semaphore::new(INDICATOR_CONCURRENCY);
    let (alerts, cases) = tokio::join!(
        async {
            let _permit = limiter.acquire().await.ok();
            indicators::open_alerts(st, user).await
        },
        async {
            let _permit = limiter.acquire().await.ok();
            indicators::my_open_cases(st, user).await
        }
    );
    [
        safe("build_open_alerts_indicator", alerts),
        safe("build_my_open_cases_indicator", cases),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// `build_sidebar_context(session, user)`.
pub async fn build_sidebar_context(
    st: &SidebarState,
    user: &CurrentUser,
) -> Result<SidebarResponse, ApiError> {
    let tags = audience_of(user.role_id);
    if !st.cache.shared_is_fresh() {
        // Never waited for: a cold or stale set is filled in for the next
        // caller while this one gets what is known.
        schedule_shared_refresh(st);
    }
    let (version, mine) = tokio::join!(version_fields(st), personal(st, user, tags));
    let release_url = match &version.release_url {
        PyValue::None => None,
        PyValue::Str(s) => Some(s.clone()),
        other => {
            // Pydantic refuses it: its ValidationError is the 400.
            let e = construct(
                &RELEASE_URL_FIELD,
                &kwargs(vec![("release_url", other.clone())]),
            )
            .err()
            .map_or_else(|| "release_url".to_string(), |e| e.text());
            return Err(ApiError::bad_request(e));
        }
    };
    let mut indicators = mine;
    indicators.extend(visible_shared(st, tags));
    Ok(SidebarResponse {
        success: true,
        message: "Sidebar context loaded",
        current_version: version.current_version,
        latest_version: version.latest_version,
        is_outdated: version.is_outdated,
        release_url,
        environment: st.env.environment.clone(),
        indicators,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audiences_follow_the_roles() {
        assert_eq!(audience_of(Some(1)), ANALYST | ADMIN);
        assert_eq!(audience_of(Some(2)), ANALYST);
        assert_eq!(audience_of(Some(5)), ANALYST);
        assert_eq!(audience_of(Some(4)), CUSTOMER);
        assert_eq!(audience_of(Some(3)), 0);
        assert_eq!(audience_of(None), 0);
        assert_eq!(SHARED_BUILDERS.len(), 14);
        let customer: Vec<Shared> = SHARED_BUILDERS
            .iter()
            .filter(|(_, a)| a & CUSTOMER != 0)
            .map(|(s, _)| *s)
            .collect();
        assert_eq!(customer, [Shared::WazuhCatalog]);
    }

    #[test]
    fn a_non_string_release_url_reads_as_pydantic_says() {
        let e = construct(
            &RELEASE_URL_FIELD,
            &kwargs(vec![("release_url", PyValue::Int("5".into()))]),
        )
        .unwrap_err();
        assert_eq!(
            e.text(),
            "1 validation error for SidebarContextResponse\nrelease_url\n  Input should be a \
             valid string [type=string_type, input_value=5, input_type=int]\n    For further \
             information visit https://errors.pydantic.dev/2.13/v/string_type"
        );
    }
}
