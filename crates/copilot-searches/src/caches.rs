//! The four catalog caches as state of this process, with
//! `cache_support.py`'s contract: a request never waits on a background
//! refresh (`ensure_fresh_nonblocking`), at most one background refresh runs
//! per cache (`is_loading` while it does), a failure is kept as the cache's
//! `unavailable_reason` (the Wazuh caches) or leaves the previous snapshot
//! (the GitHub-backed ones). `refresh()` itself takes the cache's lock, so
//! two refreshes run one after the other — the second one too, as in Python.
//!
//! The data come from where Python's come from, the same way: GitHub's tree
//! listing and raw files over httpx (a client per repository, twelve files at
//! a time, the repository order kept), the STIX bundle over httpx, the Wazuh
//! manager's `GET /rules` through `copilot-wazuh`'s port of
//! `get_wazuh_rules`, and the firing counts through elasticsearch-py's
//! `AsyncElasticsearch` (`copilot_wazuh::es`, async flavour).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::NaiveDateTime;
use copilot_auth::pyvalue::PyValue;
use copilot_core::catalog_env::CatalogEnv;
use copilot_threat_intel::httpx::{self, Client, Request};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_wazuh::es::{Es, Flavor, flag, make_path};
use copilot_yaml::Value;
use futures::StreamExt;
use http::Method;
use num_bigint_dig::BigInt;

use crate::SearchesState;
use crate::catalog::{Firing, FiringStats};
use crate::custom_repos;
use crate::mitre::Matrix;
use crate::py::{self, dict_set, s};
use crate::rules::{self, RuleSet, SourceStatus};

/// The catalog's settings: the upstream URLs (the parity harness points
/// them at stand-ins; never in production), the shared `GITHUB_TOKEN` and
/// whether this process refreshes its caches itself.
#[derive(Clone)]
pub struct Settings {
    /// `GITHUB_API_BASE` (`COPILOT_GITHUB_API_URL`).
    pub github_api: String,
    /// `GITHUB_RAW_BASE` (`COPILOT_GITHUB_RAW_URL`).
    pub github_raw: String,
    /// `MITRE_STIX_URL` (`COPILOT_MITRE_STIX_URL`).
    pub mitre_stix: String,
    /// `os.getenv("GITHUB_TOKEN")`, when set and not empty.
    pub github_token: Option<String>,
    /// `COPILOT_CATALOG_REFRESH` (see [`crate::refresher`]).
    pub refresh: bool,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("github_api", &self.github_api)
            .field("github_raw", &self.github_raw)
            .field("mitre_stix", &self.mitre_stix)
            .field(
                "github_token",
                &self.github_token.as_ref().map(|_| "<redacted>"),
            )
            .field("refresh", &self.refresh)
            .finish()
    }
}

impl Settings {
    /// Python's constants, or the overrides.
    pub fn from_config(env: &CatalogEnv) -> Self {
        Self {
            github_api: env
                .github_api_url
                .clone()
                .unwrap_or_else(|| "https://api.github.com".into()),
            github_raw: env
                .github_raw_url
                .clone()
                .unwrap_or_else(|| "https://raw.githubusercontent.com".into()),
            mitre_stix: env
                .mitre_stix_url
                .clone()
                .unwrap_or_else(|| crate::mitre::MITRE_STIX_URL.to_string()),
            github_token: env
                .github_token
                .as_ref()
                .map(|t| t.expose().to_string())
                .filter(|t| !t.is_empty()),
            refresh: env.refresh_enabled(),
        }
    }
}

/// `datetime.utcnow()`.
pub fn utcnow() -> NaiveDateTime {
    chrono::Utc::now().naive_utc()
}

/// One cache: its snapshot, its refresh lock, its background flag.
#[derive(Debug, Default)]
pub struct Slot<T> {
    data: RwLock<Arc<T>>,
    lock: tokio::sync::Mutex<()>,
    loading: AtomicBool,
}

impl<T> Slot<T> {
    /// The current snapshot.
    pub fn get(&self) -> Arc<T> {
        match self.data.read() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    fn set(&self, value: T) {
        match self.data.write() {
            Ok(mut g) => *g = Arc::new(value),
            Err(p) => *p.into_inner() = Arc::new(value),
        }
    }

    /// `is_loading`: a background refresh is in flight.
    pub fn is_loading(&self) -> bool {
        self.loading.load(Ordering::SeqCst)
    }
}

/// `WazuhRulesCache`'s state.
#[derive(Debug, Clone, Default)]
pub struct WazuhRules {
    /// The rules (`model_dump()` of each `WazuhRule`), by id in insertion
    /// order.
    pub rules: Vec<Value>,
    /// `_last_refresh`.
    pub last_refresh: Option<NaiveDateTime>,
    /// `_unavailable_reason`.
    pub unavailable: Option<String>,
}

/// `WazuhFiringStatsCache`'s state.
#[derive(Debug, Clone, Default)]
pub struct FiringCache {
    /// `_stats`.
    pub stats: FiringStats,
    /// `_last_refresh`.
    pub last_refresh: Option<NaiveDateTime>,
    /// `_unavailable_reason`.
    pub unavailable: Option<String>,
    /// `_winning_field`.
    pub winning_field: Option<String>,
    /// `_resolved_indices`.
    pub resolved_indices: Vec<String>,
}

/// The four caches.
#[derive(Debug, Default)]
pub struct Caches {
    /// `rules_cache`.
    pub rules: Slot<RuleSet>,
    /// `mitre_matrix`.
    pub mitre: Slot<Matrix>,
    /// `wazuh_rules_cache`.
    pub wazuh: Slot<WazuhRules>,
    /// `wazuh_firing_stats_cache`.
    pub firing: Slot<FiringCache>,
}

fn older_than(t: Option<NaiveDateTime>, ttl: chrono::Duration) -> bool {
    match t {
        None => true,
        Some(t) => utcnow() - t > ttl,
    }
}

/// Which cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `rules_cache`.
    Rules,
    /// `mitre_matrix`.
    Mitre,
    /// `wazuh_rules_cache`.
    Wazuh,
    /// `wazuh_firing_stats_cache`.
    Firing,
}

impl Caches {
    /// `is_stale`.
    pub fn is_stale(&self, kind: Kind) -> bool {
        match kind {
            Kind::Rules => older_than(
                self.rules.get().last_refresh,
                chrono::Duration::minutes(rules::CACHE_TTL_MINUTES),
            ),
            Kind::Mitre => older_than(
                self.mitre.get().last_refresh,
                chrono::Duration::hours(crate::mitre::MITRE_CACHE_TTL_HOURS),
            ),
            Kind::Wazuh => older_than(self.wazuh.get().last_refresh, chrono::Duration::minutes(60)),
            Kind::Firing => older_than(
                self.firing.get().last_refresh,
                chrono::Duration::minutes(15),
            ),
        }
    }

    fn loading_flag(&self, kind: Kind) -> &AtomicBool {
        match kind {
            Kind::Rules => &self.rules.loading,
            Kind::Mitre => &self.mitre.loading,
            Kind::Wazuh => &self.wazuh.loading,
            Kind::Firing => &self.firing.loading,
        }
    }

    /// `catalog_is_loading()`.
    pub fn any_loading(&self) -> bool {
        [Kind::Rules, Kind::Mitre, Kind::Wazuh, Kind::Firing]
            .iter()
            .any(|k| self.loading_flag(*k).load(Ordering::SeqCst))
    }
}

/// `ensure_fresh_nonblocking()`: start one background refresh if stale.
pub fn ensure_fresh_nonblocking(st: &SearchesState, kind: Kind) {
    if !st.caches.is_stale(kind) {
        return;
    }
    let flag = st.caches.loading_flag(kind);
    if flag.swap(true, Ordering::SeqCst) {
        return;
    }
    let st = st.clone();
    tokio::spawn(async move {
        let outcome = refresh(&st, kind).await;
        if let Err(e) = outcome {
            tracing::warn!("Background refresh of {kind:?} failed: {}", e.text());
        }
        st.caches.loading_flag(kind).store(false, Ordering::SeqCst);
    });
}

/// `ensure_loaded()`: a blocking refresh when stale.
pub async fn ensure_loaded(st: &SearchesState, kind: Kind) -> PyResult<()> {
    if st.caches.is_stale(kind) {
        refresh(st, kind).await?;
    }
    Ok(())
}

/// `refresh()` of one cache (the Wazuh ones never fail).
pub async fn refresh(st: &SearchesState, kind: Kind) -> PyResult<usize> {
    match kind {
        Kind::Rules => refresh_rules(st).await,
        Kind::Mitre => refresh_mitre(st).await.map(|_| 0),
        Kind::Wazuh => Ok(refresh_wazuh(st).await),
        Kind::Firing => Ok(refresh_firing(st).await),
    }
}

// --- CoPilot Searches rules ---------------------------------------------------------------

/// One repository to pull.
#[derive(Debug, Clone)]
pub struct Source {
    /// `repo`.
    pub repo: String,
    /// `branch`.
    pub branch: String,
    /// The bearer token (`None`: no `Authorization`).
    pub token: Option<String>,
    /// `provenance`.
    pub provenance: &'static str,
    /// `owner`.
    pub owner: Option<String>,
}

/// The client headers of a source: `Accept: application/vnd.github+json` and
/// the bearer token.
pub fn github_request(method: Method, url: String, token: Option<&str>) -> Request {
    let req = Request::new(method, url).header("Accept", Some("application/vnd.github+json"));
    match token {
        Some(t) => req.header("Authorization", Some(&format!("Bearer {t}"))),
        None => req,
    }
}

async fn build_sources(st: &SearchesState) -> Vec<Source> {
    let mut sources = vec![Source {
        repo: rules::GITHUB_REPO.into(),
        branch: rules::GITHUB_BRANCH.into(),
        token: st.settings.github_token.clone(),
        provenance: "catalog",
        owner: None,
    }];
    match custom_repos::list(&st.store).await {
        Ok(configs) => {
            for cfg in configs {
                if cfg.enabled && !cfg.repo.is_empty() {
                    sources.push(Source {
                        token: cfg
                            .token_text()
                            .or_else(|| st.settings.github_token.clone()),
                        branch: if cfg.branch.is_empty() {
                            "main".into()
                        } else {
                            cfg.branch.clone()
                        },
                        repo: cfg.repo,
                        provenance: "custom",
                        owner: Some(cfg.customer_code),
                    });
                }
            }
        }
        Err(e) => tracing::warn!("Could not load custom repo configs: {}", e.text()),
    }
    sources
}

fn httpx_text(e: httpx::HttpxError) -> String {
    e.message
}

fn py_text(e: &PyExc) -> String {
    e.text()
}

/// `[item for item in tree if item["path"].startswith("detections/") and
/// item["path"].endswith((".yaml", ".yml")) and item["type"] == "blob"]`.
pub fn yaml_paths(tree_data: &PyValue) -> PyResult<Vec<String>> {
    use copilot_upstream::py::{get, getitem, iterate, type_name};
    let tree = get(tree_data, "tree")?
        .cloned()
        .unwrap_or(PyValue::List(Vec::new()));
    let mut out = Vec::new();
    for item in iterate(&tree)? {
        let path = getitem(&item, "path")?;
        let PyValue::Str(p) = path else {
            return Err(PyExc::AttributeError(format!(
                "'{}' object has no attribute 'startswith'",
                type_name(path)
            )));
        };
        if !p.starts_with("detections/") || !(p.ends_with(".yaml") || p.ends_with(".yml")) {
            continue;
        }
        if getitem(&item, "type")?.as_str() == Some("blob") {
            out.push(p.clone());
        }
    }
    Ok(out)
}

async fn fetch_repo_rules(st: &SearchesState, src: &Source) -> Result<Vec<Value>, String> {
    let client = Client::new(Duration::from_secs(30)).map_err(httpx_text)?;
    let tree_url = format!(
        "{}/repos/{}/git/trees/{}?recursive=1",
        st.settings.github_api, src.repo, src.branch
    );
    let resp = httpx::send_on(
        &client,
        github_request(Method::GET, tree_url, src.token.as_deref()),
    )
    .await
    .map_err(httpx_text)?;
    resp.raise_for_status().map_err(httpx_text)?;
    let tree = resp.json().map_err(|e| py_text(&e))?;
    let paths = yaml_paths(&tree).map_err(|e| py_text(&e))?;
    tracing::info!("Found {} YAML files in {}", paths.len(), src.repo);
    let results: Vec<Option<Value>> = futures::stream::iter(paths)
        .map(|path| {
            let client = client.clone();
            async move { fetch_yaml_file(st, &client, src, &path).await }
        })
        .buffered(12)
        .collect()
        .await;
    Ok(results.into_iter().flatten().collect())
}

/// `_fetch_yaml_file(...)`: the rule, or `None` (every failure is logged
/// and swallowed).
async fn fetch_yaml_file(
    st: &SearchesState,
    client: &Client,
    src: &Source,
    file_path: &str,
) -> Option<Value> {
    let raw_url = format!(
        "{}/{}/{}/{}",
        st.settings.github_raw, src.repo, src.branch, file_path
    );
    let outcome: Result<Option<Value>, String> = async {
        let resp = httpx::send_on(
            client,
            github_request(Method::GET, raw_url, src.token.as_deref()),
        )
        .await
        .map_err(httpx_text)?;
        resp.raise_for_status().map_err(httpx_text)?;
        let raw = resp.text();
        Ok(build_rule(
            &raw,
            file_path,
            src.provenance,
            src.owner.as_deref(),
        ))
    }
    .await;
    match outcome {
        Ok(rule) => rule,
        Err(e) => {
            tracing::warn!("Error fetching {file_path}: {e}");
            None
        }
    }
}

/// The rule `_fetch_yaml_file` builds from a file's text (`None` where it
/// returns or swallows).
pub fn build_rule(
    raw: &str,
    file_path: &str,
    provenance: &str,
    owner: Option<&str>,
) -> Option<Value> {
    let data = match copilot_yaml::safe_load(raw) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("Error fetching {file_path}: {e}");
            return None;
        }
    };
    let Value::Dict(items) = &data else {
        tracing::warn!("Invalid YAML structure in {file_path}");
        return None;
    };
    let mut items: Vec<(Value, Value)> = items.to_vec();
    dict_set(&mut items, "_file_path", s(file_path));
    dict_set(&mut items, "_raw_yaml", s(raw));
    dict_set(
        &mut items,
        "_category",
        s(rules::category_from_path(file_path)),
    );
    let partial = Value::Dict(Arc::new(items.clone()));
    let platform = match rules::detect_platform(file_path, &partial) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Error fetching {file_path}: {}", e.text());
            return None;
        }
    };
    dict_set(&mut items, "_platform", s(platform));
    let has_graylog = if partial.has_key("graylog") {
        let graylog = match py::get(&partial, "graylog", py::dict(vec![])) {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!("Error fetching {file_path}: {}", e.text());
                return None;
            }
        };
        match py::get(&graylog, "query", Value::None) {
            Ok(q) => q.truthy(),
            Err(e) => {
                tracing::warn!("Error fetching {file_path}: {}", e.text());
                return None;
            }
        }
    } else {
        false
    };
    dict_set(&mut items, "_has_graylog", Value::Bool(has_graylog));
    dict_set(&mut items, "_provenance", s(provenance));
    dict_set(
        &mut items,
        "_owner_customer_code",
        owner.map_or(Value::None, s),
    );
    Some(Value::Dict(Arc::new(items)))
}

async fn fetch_all_rules(st: &SearchesState) -> (Vec<Value>, Vec<SourceStatus>) {
    let mut rules_out = Vec::new();
    let mut statuses = Vec::new();
    for src in build_sources(st).await {
        let fetched_at = format!(
            "{}Z",
            crate::py::py_str(&rules::naive_datetime(utcnow())).replacen(' ', "T", 1)
        );
        let mut entry = SourceStatus {
            repo: src.repo.clone(),
            provenance: src.provenance,
            owner: src.owner.clone(),
            fetched_at,
            ok: false,
            rules_loaded: 0,
            error: None,
        };
        match fetch_repo_rules(st, &src).await {
            Ok(rs) => {
                entry.ok = true;
                entry.rules_loaded = rs.len();
                tracing::info!(
                    "Loaded {} {} rules from {}",
                    rs.len(),
                    src.provenance,
                    src.repo
                );
                rules_out.extend(rs);
            }
            Err(e) => {
                tracing::warn!("Failed to fetch rules from {}: {e}", src.repo);
                entry.error = Some(e);
            }
        }
        statuses.push(entry);
    }
    (rules_out, statuses)
}

/// `RulesCache.refresh()`: the number of rules loaded.
pub async fn refresh_rules(st: &SearchesState) -> PyResult<usize> {
    let _guard = st.caches.rules.lock.lock().await;
    tracing::info!("Refreshing rules cache from GitHub...");
    let (rules, statuses) = fetch_all_rules(st).await;
    let mut set = (*st.caches.rules.get()).clone();
    set.source_status = statuses;
    let outcome = set.fill(rules);
    if outcome.is_ok() {
        set.last_refresh = Some(utcnow());
        tracing::info!("Loaded {} rules from GitHub", set.rules_count());
    }
    let n = set.rules_count();
    st.caches.rules.set(set);
    outcome.map(|_| n)
}

// --- MITRE ATT&CK -------------------------------------------------------------------------

/// `MitreMatrix.refresh()`.
pub async fn refresh_mitre(st: &SearchesState) -> PyResult<()> {
    let _guard = st.caches.mitre.lock.lock().await;
    tracing::info!(
        "Fetching MITRE ATT&CK Enterprise STIX bundle from {}",
        crate::mitre::MITRE_STIX_URL
    );
    let mut req =
        Request::new(Method::GET, st.settings.mitre_stix.clone()).timeout(Duration::from_secs(120));
    if let Some(t) = &st.settings.github_token {
        req = req.header("Authorization", Some(&format!("Bearer {t}")));
    }
    let resp = httpx::send(req).await.map_err(|e| e.into_py())?;
    resp.raise_for_status().map_err(|e| e.into_py())?;
    let bundle = resp.json()?;
    let mut matrix = Matrix::parse(&py::from_py(&bundle))?;
    matrix.last_refresh = Some(utcnow());
    tracing::info!(
        "Loaded MITRE matrix: {} tactics, {} techniques",
        matrix.tactics.len(),
        matrix.techniques.len()
    );
    st.caches.mitre.set(matrix);
    Ok(())
}

// --- Wazuh ruleset ------------------------------------------------------------------------

/// `_short_reason(exc)` of either Wazuh cache.
pub fn short_reason(raw: &str, class: &str, service: &str) -> String {
    let stripped = crate::py::py_strip(raw);
    let raw = if stripped.is_empty() { class } else { stripped };
    let lower = copilot_jinja::unicode::lower(raw);
    if lower.contains("connection") || lower.contains("timed out") || lower.contains("timeout") {
        return format!("{service} is not reachable.");
    }
    if raw.contains("401") || raw.contains("403") || lower.contains("unauthor") {
        return format!("{service} rejected the credentials.");
    }
    if lower.contains("not configured") || lower.contains("not found") {
        return format!("{service} connector is not configured.");
    }
    let chars: Vec<char> = raw.chars().collect();
    let mut out: String = chars.iter().take(160).collect();
    if chars.len() > 160 {
        out.push('…');
    }
    out
}

/// A `WazuhRule` dump as `model_dump(by_alias=False)` keys it.
fn wazuh_rule(v: &serde_json::Value) -> Value {
    let mut out = py::from_json(v);
    if let Value::Dict(items) = &mut out {
        let items = Arc::make_mut(items);
        for (k, _) in items.iter_mut() {
            if k.as_str() == Some("nist-800-53") {
                *k = s("nist_800_53");
            }
        }
    }
    out
}

/// `WazuhRulesCache.refresh()`.
pub async fn refresh_wazuh(st: &SearchesState) -> usize {
    let _guard = st.caches.wazuh.lock.lock().await;
    tracing::info!("Refreshing Wazuh rules cache from Wazuh Manager…");
    let params = vec![
        (
            "limit".to_string(),
            copilot_wazuh::manager::client::Param::Int(100_000),
        ),
        (
            "offset".to_string(),
            copilot_wazuh::manager::client::Param::Int(0),
        ),
    ];
    let mut state = (*st.caches.wazuh.get()).clone();
    match copilot_wazuh::manager::services::get_rules(&st.wazuh, params).await {
        Err(e) => {
            state.unavailable = Some(short_reason(&e.py_str(), "HTTPException", "Wazuh Manager"));
            tracing::warn!(
                "Wazuh rules cache refresh failed: {}. Keeping previously cached snapshot (if any).",
                state.unavailable.as_deref().unwrap_or_default()
            );
            state.last_refresh = Some(utcnow());
        }
        Ok(dump) => {
            let mut rules: Vec<Value> = Vec::new();
            let mut index: HashMap<BigInt, usize> = HashMap::new();
            if let Some(serde_json::Value::Array(items)) = dump.get("results") {
                for item in items {
                    let rule = wazuh_rule(item);
                    if let Some(Value::Int(id)) = rule.get("id") {
                        match index.get(id) {
                            Some(i) => rules[*i] = rule.clone(),
                            None => {
                                index.insert(id.clone(), rules.len());
                                rules.push(rule.clone());
                            }
                        }
                    }
                }
            }
            state.rules = rules;
            state.unavailable = None;
            state.last_refresh = Some(utcnow());
            tracing::info!("Loaded {} Wazuh rules into cache", state.rules.len());
        }
    }
    let n = state.rules.len();
    st.caches.wazuh.set(state);
    n
}

// --- firing counts ------------------------------------------------------------------------

/// `ALERT_INDEX_PATTERN`.
pub const ALERT_INDEX_PATTERN: &str = "*,-.*,-_*,-wazuh-monitoring-*,-wazuh-statistics-*,-wazuh-states-*,-wazuh-vulnerabilities-*,-security-auditlog-*";
/// `RULE_ID_FIELD_OPTIONS`.
pub const RULE_ID_FIELDS: &[&str] = &["rule.id", "rule_id", "id"];

/// `_build_firing_stats_query(field)`, with the customer filter spliced in.
pub fn firing_query(field: &str, customer: Option<(&str, &str)>) -> PyValue {
    let d = |items: Vec<(&str, PyValue)>| {
        PyValue::Dict(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    };
    let st = |t: &str| PyValue::Str(t.to_string());
    let int = |n: i64| PyValue::Int(n.to_string());
    let mut filter = vec![
        d(vec![(
            "range",
            d(vec![("timestamp", d(vec![("gte", st("now-30d"))]))]),
        )]),
        d(vec![("exists", d(vec![("field", st(field))]))]),
    ];
    if let Some((customer_field, code)) = customer {
        filter.push(d(vec![("term", d(vec![(customer_field, st(code))]))]));
    }
    d(vec![
        ("size", int(0)),
        (
            "query",
            d(vec![("bool", d(vec![("filter", PyValue::List(filter))]))]),
        ),
        (
            "aggs",
            d(vec![(
                "by_rule",
                d(vec![
                    (
                        "terms",
                        d(vec![
                            ("field", st(field)),
                            ("size", int(50_000)),
                            ("order", d(vec![("_count", st("desc"))])),
                        ]),
                    ),
                    (
                        "aggs",
                        d(vec![
                            (
                                "last_7d",
                                d(vec![(
                                    "filter",
                                    d(vec![(
                                        "range",
                                        d(vec![("timestamp", d(vec![("gte", st("now-7d"))]))]),
                                    )]),
                                )]),
                            ),
                            (
                                "last_seen",
                                d(vec![("max", d(vec![("field", st("timestamp"))]))]),
                            ),
                        ]),
                    ),
                ]),
            )]),
        ),
    ])
}

async fn es_client(st: &SearchesState) -> Result<Es, String> {
    Es::connect(&st.wazuh.es, &st.ctx.connectors, Flavor::Async)
        .await
        .map_err(|e| e.py_str())
}

/// `client.search(index=ALERT_INDEX_PATTERN, body=…, ignore_unavailable=True,
/// allow_no_indices=True)`.
async fn search(es: &Es, body: &PyValue) -> Result<PyValue, copilot_wazuh::es::EsError> {
    let payload = copilot_upstream::json::py_dumps(body, copilot_upstream::json::Dumps::HTTPX)
        .unwrap_or_default()
        .into_bytes();
    es.perform_raw(
        Method::POST,
        &make_path(&[ALERT_INDEX_PATTERN, "_search"]),
        &[
            ("allow_no_indices", flag(true)),
            ("ignore_unavailable", flag(true)),
        ],
        Some(payload),
    )
    .await
    .map(|v| copilot_wazuh::pymodel::py(&v))
}

/// `_discover_alert_indices(client)`.
async fn discover_indices(es: &Es) -> Vec<String> {
    let resp = match es
        .perform(
            Method::GET,
            "/_cat/indices",
            &[("format", "json".to_string()), ("h", "index".to_string())],
            None,
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Firing-stats index discovery failed: {e}");
            return Vec::new();
        }
    };
    let serde_json::Value::Array(items) = resp else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|i| i.get("index").and_then(|n| n.as_str()))
        .filter(|n| !n.is_empty())
        .filter(|n| {
            !(n.starts_with('.')
                || n.starts_with('_')
                || n.starts_with("wazuh-monitoring")
                || n.starts_with("wazuh-statistics")
                || n.starts_with("wazuh-states")
                || n.starts_with("wazuh-vulnerabilities")
                || n.contains("security-auditlog"))
        })
        .map(str::to_string)
        .collect()
}

/// `_coerce_rule_id(key)`.
fn coerce_rule_id(key: &Value) -> Option<BigInt> {
    match key {
        Value::Int(i) => Some(i.clone()),
        Value::Bool(b) => Some(BigInt::from(u8::from(*b))),
        Value::Str(t) => copilot_yaml::pyint::parse_int(t, 10).ok(),
        _ => None,
    }
}

/// `int(x or 0)`.
fn int_or_zero(v: Value) -> PyResult<BigInt> {
    if v.truthy() {
        py::py_int(&v)
    } else {
        Ok(BigInt::from(0))
    }
}

/// One bucket's counts.
fn bucket_stats(bucket: &Value) -> PyResult<Option<(BigInt, Firing)>> {
    let Some(rule_id) = coerce_rule_id(&py::get(bucket, "key", Value::None)?) else {
        return Ok(None);
    };
    let hits_30d = int_or_zero(py::get(bucket, "doc_count", Value::None)?)?;
    let last_7d = py::get(bucket, "last_7d", py::dict(vec![]))?;
    let hits_7d = int_or_zero(py::get(&last_7d, "doc_count", Value::None)?)?;
    let seen = match py::get(bucket, "last_seen", Value::None)? {
        v if v.truthy() => v,
        _ => py::dict(vec![]),
    };
    let last_seen = py::get(&seen, "value_as_string", Value::None)?;
    Ok(Some((
        rule_id,
        Firing {
            hits_30d,
            hits_7d,
            last_seen,
        },
    )))
}

/// `response.get("aggregations", {}).get("by_rule", {}).get("buckets", [])`.
fn buckets(resp: &Value) -> PyResult<Value> {
    let aggs = py::get(resp, "aggregations", py::dict(vec![]))?;
    let by_rule = py::get(&aggs, "by_rule", py::dict(vec![]))?;
    py::get(&by_rule, "buckets", py::list(vec![]))
}

fn first_chars(t: &str, n: usize) -> String {
    t.chars().take(n).collect()
}

/// `WazuhFiringStatsCache.refresh()`.
pub async fn refresh_firing(st: &SearchesState) -> usize {
    let _guard = st.caches.firing.lock.lock().await;
    tracing::info!("Refreshing Wazuh firing-stats cache from the indexer…");
    let mut state = (*st.caches.firing.get()).clone();
    let es = match es_client(st).await {
        Ok(es) => es,
        Err(e) => {
            state.unavailable = Some(short_reason(&e, "HTTPException", "Wazuh indexer"));
            state.last_refresh = Some(utcnow());
            let n = state.stats.len();
            st.caches.firing.set(state);
            return n;
        }
    };
    state.resolved_indices = discover_indices(&es).await;
    let mut fields: Vec<String> = state.winning_field.iter().cloned().collect();
    for f in RULE_ID_FIELDS {
        if !fields.iter().any(|x| x == f) {
            fields.push((*f).to_string());
        }
    }
    let mut new_stats: FiringStats = HashMap::new();
    let mut winner: Option<String> = None;
    let mut last_error: Option<String> = None;
    for field in fields {
        let resp = match search(&es, &firing_query(&field, None)).await {
            Ok(r) => r,
            Err(e) => {
                let text = match e.info() {
                    Some(info) if e.is_request_error() => info.py_str(),
                    _ => e.to_string(),
                };
                last_error = Some(format!("{field}: {}", first_chars(&text, 120)));
                continue;
            }
        };
        let outcome: PyResult<bool> = (|| {
            let list = buckets(&py::from_py(&resp))?;
            if !list.truthy() {
                return Ok(false);
            }
            for bucket in py::iterate(&list)? {
                if let Some((id, stats)) = bucket_stats(&bucket)? {
                    new_stats.insert(id, stats);
                }
            }
            Ok(true)
        })();
        match outcome {
            Ok(true) => {
                winner = Some(field);
                break;
            }
            Ok(false) => {}
            Err(e) => {
                last_error = Some(format!("{field}: {}", first_chars(&e.text(), 120)));
            }
        }
    }
    match winner {
        None => {
            state.unavailable = Some(last_error.unwrap_or_else(|| {
                "No rule-ID field returned hits in the alerts index.".to_string()
            }));
            state.last_refresh = Some(utcnow());
            tracing::warn!(
                "Could not resolve a rule-ID field for firing stats. {}",
                state.unavailable.as_deref().unwrap_or_default()
            );
        }
        Some(field) => {
            state.stats = new_stats;
            state.winning_field = Some(field);
            state.unavailable = None;
            state.last_refresh = Some(utcnow());
        }
    }
    let n = state.stats.len();
    st.caches.firing.set(state);
    n
}

/// `fetch_firing_stats_for_customer(customer_code)`: never fails.
pub async fn firing_for_customer(st: &SearchesState, customer_code: &str) -> FiringStats {
    if crate::py::py_strip(customer_code).is_empty() {
        return HashMap::new();
    }
    let field = st
        .caches
        .firing
        .get()
        .winning_field
        .clone()
        .unwrap_or_else(|| RULE_ID_FIELDS[0].to_string());
    let es = match es_client(st).await {
        Ok(es) => es,
        Err(e) => {
            tracing::warn!(
                "Per-customer firing stats: indexer unavailable ({})",
                short_reason(&e, "HTTPException", "Wazuh indexer")
            );
            return HashMap::new();
        }
    };
    for customer_field in ["agent_labels_customer", "agent.labels.customer"] {
        let body = firing_query(&field, Some((customer_field, customer_code)));
        let resp = match search(&es, &body).await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(
                    "Per-customer firing stats: customer field {customer_field} failed: {e}"
                );
                continue;
            }
        };
        let outcome: PyResult<Option<FiringStats>> = (|| {
            let list = buckets(&py::from_py(&resp))?;
            if !list.truthy() {
                return Ok(None);
            }
            let mut out = HashMap::new();
            for bucket in py::iterate(&list)? {
                if let Some((id, stats)) = bucket_stats(&bucket)? {
                    out.insert(id, stats);
                }
            }
            Ok(Some(out))
        })();
        match outcome {
            Ok(Some(out)) => return out,
            Ok(None) => continue,
            Err(e) => {
                tracing::debug!(
                    "Per-customer firing stats: customer field {customer_field} failed: {}",
                    e.text()
                );
                continue;
            }
        }
    }
    HashMap::new()
}

/// The rules `scope` may see: the shared catalog's and the custom rules of
/// its customers. Python listed every tenant's custom rules to every caller
/// (RUST_MIGRATION.md §4); a custom repository belongs to the customer whose
/// pointer (`custom-repos/<customer_code>.json`) names it. Admins see all.
pub fn visible_rules(
    st: &SearchesState,
    scope: &copilot_auth::AccessScope,
) -> std::sync::Arc<rules::RuleSet> {
    let set = st.caches.rules.get();
    let keep = |owner: Option<&str>| owner.is_none_or(|code| scope.can_access(code));
    if set.all_owners(keep) {
        set
    } else {
        std::sync::Arc::new(set.retain_owners(keep))
    }
}
