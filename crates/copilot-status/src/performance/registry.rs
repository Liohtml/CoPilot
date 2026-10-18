//! `PerformanceRegistry`: in-flight requests, the completed ones (a ring
//! buffer), the per-endpoint aggregates, the runtime-lag samples and the
//! stalls with the requests that overlapped them — the same buffers, caps
//! and attribution rules as `app/middleware/performance.py`.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::Instant;

use super::config::PerfConfig;
use super::wall_now;

/// `_OVERFLOW_KEY`.
pub const OVERFLOW_KEY: &str = "OTHER";

/// `_InFlight`: a request being served.
#[derive(Debug, Clone)]
pub struct InFlight {
    /// Its id (`X-Request-Id`).
    pub request_id: u64,
    /// The method.
    pub method: String,
    /// The decoded path (`scope["path"]`).
    pub raw_path: String,
    /// `perf_counter()` at the start.
    pub started: Instant,
    /// `time.time()` at the start.
    pub started_wall: f64,
    /// Stall time attributed while in flight.
    pub blocked_ms: f64,
    /// Stalls attributed while in flight.
    pub stall_hits: u64,
}

/// `RequestRecord`: a completed request.
#[derive(Debug, Clone)]
pub struct RequestRecord {
    /// Its id.
    pub request_id: u64,
    /// The method.
    pub method: String,
    /// Its route template.
    pub path: String,
    /// The status (`0`: none was sent).
    pub status_code: u16,
    /// Milliseconds from the start to the end of the body.
    pub duration_ms: f64,
    /// `time.time()` at the start.
    pub started_wall: f64,
    /// `perf_counter()` at the start.
    pub started: Instant,
    /// `perf_counter()` at the end.
    pub ended: Instant,
    /// Requests in flight when it completed, itself included.
    pub concurrency: usize,
    /// Stall time attributed to it.
    pub blocked_ms: f64,
    /// Stalls attributed to it.
    pub stall_hits: u64,
    /// Whether the client went away before the end.
    pub client_disconnected: bool,
}

/// `StallRecord`.
#[derive(Debug, Clone)]
pub struct StallRecord {
    /// `time.time()` when detected.
    pub at_wall: f64,
    /// How late the watchdog woke.
    pub lag_ms: f64,
    /// The watchdog's window.
    pub window_ms: f64,
    /// Requests in flight then.
    pub concurrency: usize,
    /// The requests that overlapped the window.
    pub suspects: Vec<String>,
}

/// `EndpointStats`.
#[derive(Debug, Clone)]
pub struct EndpointStats {
    /// The method (`*` for the overflow row).
    pub method: String,
    /// The route template (`OTHER` for the overflow row).
    pub path: String,
    /// Requests.
    pub count: u64,
    /// Responses `>= 500`.
    pub error_count: u64,
    /// Requests over the slow threshold.
    pub slow_count: u64,
    /// Requests the client abandoned.
    pub disconnects: u64,
    /// Summed durations.
    pub total_ms: f64,
    /// The longest.
    pub max_ms: f64,
    /// Attributed stalls.
    pub stall_hits: u64,
    /// Attributed stall time.
    pub stalled_ms: f64,
    /// The last durations (`PERF_DURATION_SAMPLES`).
    pub samples: VecDeque<f64>,
}

impl EndpointStats {
    fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_string(),
            path: path.to_string(),
            count: 0,
            error_count: 0,
            slow_count: 0,
            disconnects: 0,
            total_ms: 0.0,
            max_ms: 0.0,
            stall_hits: 0,
            stalled_ms: 0.0,
            samples: VecDeque::new(),
        }
    }
}

/// `deque(maxlen=n).append(x)`.
fn push<T>(buf: &mut VecDeque<T>, cap: usize, value: T) {
    if cap == 0 {
        return;
    }
    buf.push_back(value);
    while buf.len() > cap {
        buf.pop_front();
    }
}

fn ms(later: Instant, earlier: Instant) -> f64 {
    // `perf_counter()` differences: negative when `later` is earlier.
    match later.checked_duration_since(earlier) {
        Some(d) => d.as_secs_f64() * 1000.0,
        None => -(earlier.duration_since(later).as_secs_f64() * 1000.0),
    }
}

/// `str.isdigit()` of one segment.
fn is_digits(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .chars()
            .all(|c| c.is_ascii_digit() || copilot_jinja::unicode::decimal_value(c).is_some())
}

/// `_normalise_path`: identifier-looking segments collapsed.
pub fn normalise_path(raw_path: &str) -> String {
    let parts: Vec<String> = raw_path
        .split('/')
        .map(|segment| {
            if segment.is_empty() {
                String::new()
            } else if is_digits(segment) {
                "{id}".into()
            } else if segment.chars().count() >= 16
                && segment.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
            {
                "{uuid}".into()
            } else {
                segment.to_string()
            }
        })
        .collect();
    let joined = parts.join("/");
    if joined.is_empty() {
        "/".into()
    } else {
        joined
    }
}

/// The route template of a request: the matched route's (`{*rest}` written
/// `{rest}`, as Python's substitution writes a `:path` parameter), else the
/// normalised path (`_route_template`).
pub fn route_template(matched: Option<&str>, raw_path: &str) -> String {
    match matched {
        Some(m) => m.replace("{*", "{"),
        None => normalise_path(raw_path),
    }
}

/// `PerformanceRegistry`.
#[derive(Debug)]
pub struct Registry {
    limits: PerfConfig,
    in_flight: BTreeMap<u64, InFlight>,
    next_id: u64,
    /// `time.time()` at the start or the last reset.
    pub started_wall: f64,
    /// `perf_counter()` at the start or the last reset.
    pub started: Instant,
    recent: VecDeque<RequestRecord>,
    stalls: VecDeque<StallRecord>,
    endpoints: Vec<EndpointStats>,
    endpoint_index: HashMap<String, usize>,
    lag_samples: VecDeque<f64>,
    /// Completed requests.
    pub total_requests: u64,
    /// Slow ones.
    pub total_slow: u64,
    /// `>= 500` ones.
    pub total_errors: u64,
    /// Abandoned ones.
    pub total_disconnects: u64,
    /// Stalls.
    pub total_stalls: u64,
    /// Stall time.
    pub total_stalled_ms: f64,
    /// The worst lag.
    pub max_lag_ms: f64,
    /// The most requests in flight at once.
    pub max_concurrency: usize,
    /// Routes not tracked past `PERF_MAX_ENDPOINTS`.
    pub dropped_endpoints: u64,
}

impl Registry {
    /// A fresh registry.
    pub fn new(limits: &PerfConfig) -> Self {
        let mut r = Self {
            limits: limits.clone(),
            in_flight: BTreeMap::new(),
            next_id: 0,
            started_wall: 0.0,
            started: Instant::now(),
            recent: VecDeque::new(),
            stalls: VecDeque::new(),
            endpoints: Vec::new(),
            endpoint_index: HashMap::new(),
            lag_samples: VecDeque::new(),
            total_requests: 0,
            total_slow: 0,
            total_errors: 0,
            total_disconnects: 0,
            total_stalls: 0,
            total_stalled_ms: 0.0,
            max_lag_ms: 0.0,
            max_concurrency: 0,
            dropped_endpoints: 0,
        };
        r.reset_counters();
        r
    }

    fn reset_counters(&mut self) {
        self.started_wall = wall_now();
        self.started = Instant::now();
        self.recent.clear();
        self.stalls.clear();
        self.endpoints.clear();
        self.endpoint_index.clear();
        self.lag_samples.clear();
        self.total_requests = 0;
        self.total_slow = 0;
        self.total_errors = 0;
        self.total_disconnects = 0;
        self.total_stalls = 0;
        self.total_stalled_ms = 0.0;
        self.max_lag_ms = 0.0;
        self.max_concurrency = self.in_flight.len();
        self.dropped_endpoints = 0;
    }

    /// `reset()`: every counter zeroed, the in-flight requests kept.
    pub fn reset(&mut self) {
        tracing::info!(
            discarded_uptime_seconds = super::py_round(self.uptime_seconds(), 2),
            discarded_total_requests = self.total_requests,
            discarded_total_stalls = self.total_stalls,
            discarded_max_lag_ms = super::py_round(self.max_lag_ms, 2),
            "PERF: counters reset"
        );
        self.reset_counters();
    }

    /// `start_request`.
    pub fn start_request(&mut self, method: &str, raw_path: &str) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.in_flight.insert(
            id,
            InFlight {
                request_id: id,
                method: method.to_string(),
                raw_path: raw_path.to_string(),
                started: Instant::now(),
                started_wall: wall_now(),
                blocked_ms: 0.0,
                stall_hits: 0,
            },
        );
        if self.in_flight.len() > self.max_concurrency {
            self.max_concurrency = self.in_flight.len();
        }
        id
    }

    /// When a request started (for `X-Process-Time-Ms`).
    pub fn started_at(&self, id: u64) -> Option<Instant> {
        self.in_flight.get(&id).map(|e| e.started)
    }

    /// `finish_request`.
    pub fn finish_request(&mut self, id: u64, status_code: u16, path: &str, disconnected: bool) {
        let Some(entry) = self.in_flight.remove(&id) else {
            return;
        };
        let ended = Instant::now();
        let duration_ms = ms(ended, entry.started);
        let record = RequestRecord {
            request_id: entry.request_id,
            method: entry.method.clone(),
            path: path.to_string(),
            status_code,
            duration_ms,
            started_wall: entry.started_wall,
            started: entry.started,
            ended,
            concurrency: self.in_flight.len() + 1,
            blocked_ms: entry.blocked_ms,
            stall_hits: entry.stall_hits,
            client_disconnected: disconnected,
        };
        let cap = self.limits.recent_requests;
        push(&mut self.recent, cap, record);
        self.total_requests += 1;
        let slow = duration_ms >= self.limits.slow_request_ms;
        let index = self.stats_for(&entry.method, path);
        let duration_cap = self.limits.duration_samples;
        let stats = &mut self.endpoints[index];
        stats.count += 1;
        stats.total_ms += duration_ms;
        push(&mut stats.samples, duration_cap, duration_ms);
        if duration_ms > stats.max_ms {
            stats.max_ms = duration_ms;
        }
        if status_code >= 500 {
            stats.error_count += 1;
        }
        if slow {
            stats.slow_count += 1;
        }
        if disconnected {
            stats.disconnects += 1;
        }
        if entry.stall_hits != 0 {
            stats.stall_hits += entry.stall_hits;
            stats.stalled_ms += entry.blocked_ms;
        }
        if status_code >= 500 {
            self.total_errors += 1;
        }
        if slow {
            self.total_slow += 1;
            tracing::info!(
                method = %entry.method,
                path,
                status_code,
                duration_ms = super::py_round(duration_ms, 2),
                "PERF: slow request"
            );
        }
        if disconnected {
            self.total_disconnects += 1;
        }
    }

    /// `_stats_for`: the endpoint's row, created while under the cap, else
    /// the overflow row.
    fn stats_for(&mut self, method: &str, path: &str) -> usize {
        let key = format!("{method} {path}");
        if let Some(i) = self.endpoint_index.get(&key) {
            return *i;
        }
        if self.endpoints.len() >= self.limits.max_endpoints {
            self.dropped_endpoints += 1;
            if let Some(i) = self.endpoint_index.get(OVERFLOW_KEY) {
                return *i;
            }
            self.endpoints.push(EndpointStats::new("*", OVERFLOW_KEY));
            let i = self.endpoints.len() - 1;
            self.endpoint_index.insert(OVERFLOW_KEY.to_string(), i);
            return i;
        }
        self.endpoints.push(EndpointStats::new(method, path));
        let i = self.endpoints.len() - 1;
        self.endpoint_index.insert(key, i);
        i
    }

    /// `record_lag`: one watchdog sample; a stall above the threshold is
    /// attributed to the requests that overlapped it.
    pub fn record_lag(&mut self, window_start: Instant, window_end: Instant, lag_ms: f64) {
        let cap = self.limits.lag_samples;
        push(&mut self.lag_samples, cap, lag_ms);
        if lag_ms > self.max_lag_ms {
            self.max_lag_ms = lag_ms;
        }
        if lag_ms < self.limits.lag_stall_threshold_ms {
            return;
        }
        self.total_stalls += 1;
        self.total_stalled_ms += lag_ms;
        let suspects = self.attribute_stall(window_start, window_end, lag_ms);
        let stall = StallRecord {
            at_wall: wall_now(),
            lag_ms,
            window_ms: ms(window_end, window_start),
            concurrency: self.in_flight.len(),
            suspects: suspects.clone(),
        };
        let cap = self.limits.recent_stalls;
        push(&mut self.stalls, cap, stall);
        tracing::warn!(
            "PERF: runtime blocked for {lag_ms:.0}ms - in flight during the stall: {}",
            if suspects.is_empty() {
                "<none observed>".to_string()
            } else {
                suspects.join(", ")
            }
        );
    }

    /// `_attribute_stall`: the running requests that started before the
    /// window ended, then the completed ones whose lifetime overlapped it.
    fn attribute_stall(&mut self, start: Instant, end: Instant, lag_ms: f64) -> Vec<String> {
        let mut suspects = Vec::new();
        for entry in self.in_flight.values_mut() {
            if entry.started > end {
                continue;
            }
            entry.stall_hits += 1;
            entry.blocked_ms += lag_ms;
            let age_ms = ms(end, entry.started);
            suspects.push(format!(
                "{} {} (running, {age_ms:.0}ms)",
                entry.method,
                normalise_path(&entry.raw_path)
            ));
        }
        let mut overlapped = Vec::new();
        for (i, record) in self.recent.iter_mut().enumerate().rev() {
            if record.ended < start {
                break;
            }
            if record.started > end {
                continue;
            }
            record.stall_hits += 1;
            record.blocked_ms += lag_ms;
            overlapped.push(i);
            suspects.push(format!(
                "{} {} (finished, {:.0}ms)",
                record.method, record.path, record.duration_ms
            ));
        }
        for i in overlapped {
            let (method, path) = (self.recent[i].method.clone(), self.recent[i].path.clone());
            let index = self.stats_for(&method, &path);
            self.endpoints[index].stall_hits += 1;
            self.endpoints[index].stalled_ms += lag_ms;
        }
        suspects
    }

    /// `in_flight`, in arrival order.
    pub fn in_flight(&self) -> Vec<InFlight> {
        self.in_flight.values().cloned().collect()
    }

    /// `recent_requests`, oldest first.
    pub fn recent_requests(&self) -> Vec<RequestRecord> {
        self.recent.iter().cloned().collect()
    }

    /// `stalls`, oldest first.
    pub fn stalls(&self) -> Vec<StallRecord> {
        self.stalls.iter().cloned().collect()
    }

    /// `endpoints`, in first-seen order.
    pub fn endpoints(&self) -> Vec<EndpointStats> {
        self.endpoints.clone()
    }

    /// `lag_samples`.
    pub fn lag_samples(&self) -> Vec<f64> {
        self.lag_samples.iter().copied().collect()
    }

    /// `uptime_seconds`.
    pub fn uptime_seconds(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> PerfConfig {
        PerfConfig {
            max_endpoints: 2,
            recent_requests: 3,
            ..PerfConfig::default()
        }
    }

    #[test]
    fn paths_collapse_like_python() {
        assert_eq!(
            normalise_path("/api/agents/123/vulns"),
            "/api/agents/{id}/vulns"
        );
        assert_eq!(
            normalise_path("/api/x/0123456789abcdef-12"),
            "/api/x/{uuid}"
        );
        assert_eq!(
            normalise_path("/api/x/0123456789abcdeg"),
            "/api/x/0123456789abcdeg"
        );
        assert_eq!(normalise_path(""), "/");
        assert_eq!(normalise_path("/"), "/");
        assert_eq!(normalise_path("/a//b/"), "/a//b/");
        assert_eq!(
            route_template(Some("/api/x/{*rest}"), "/api/x/a/b"),
            "/api/x/{rest}"
        );
        assert_eq!(route_template(None, "/api/x/42"), "/api/x/{id}");
    }

    #[test]
    fn endpoints_overflow_and_requests_ring() {
        let mut r = Registry::new(&limits());
        for path in ["/a", "/b", "/c", "/d", "/a"] {
            let id = r.start_request("GET", path);
            r.finish_request(id, 200, path, false);
        }
        let rows: Vec<(String, String, u64)> = r
            .endpoints()
            .into_iter()
            .map(|e| (e.method, e.path, e.count))
            .collect();
        assert_eq!(
            rows,
            [
                ("GET".into(), "/a".into(), 2),
                ("GET".into(), "/b".into(), 1),
                ("*".into(), "OTHER".into(), 2)
            ]
        );
        assert_eq!(r.dropped_endpoints, 2);
        assert_eq!(r.total_requests, 5);
        let ids: Vec<u64> = r.recent_requests().iter().map(|x| x.request_id).collect();
        assert_eq!(ids, [3, 4, 5]);
        // A reset keeps what is in flight.
        let open = r.start_request("POST", "/reset");
        r.reset();
        assert_eq!(r.total_requests, 0);
        assert_eq!(r.max_concurrency, 1);
        r.finish_request(open, 200, "/reset", false);
        assert_eq!(r.total_requests, 1);
    }

    #[test]
    fn stalls_name_the_overlapping_requests() {
        let mut r = Registry::new(&PerfConfig::default());
        let start = Instant::now();
        let done = r.start_request("GET", "/api/done/7");
        r.finish_request(done, 200, "/api/done/{id}", false);
        let running = r.start_request("GET", "/api/run/9");
        let end = Instant::now();
        r.record_lag(start, end, 50.0);
        assert_eq!(r.total_stalls, 0);
        r.record_lag(start, end, 150.0);
        assert_eq!(r.total_stalls, 1);
        let stall = &r.stalls()[0];
        assert_eq!(stall.concurrency, 1);
        assert!(stall.suspects[0].starts_with("GET /api/run/{id} (running, "));
        assert!(stall.suspects[1].starts_with("GET /api/done/{id} (finished, "));
        r.finish_request(running, 200, "/api/run/{id}", false);
        let row = r
            .endpoints()
            .into_iter()
            .find(|e| e.path == "/api/run/{id}")
            .unwrap();
        assert_eq!((row.stall_hits, row.stalled_ms), (1, 150.0));
        assert_eq!(r.max_lag_ms, 150.0);
    }
}
