//! `app/performance/schema/performance.py`: the answers, fields in the
//! models' order, floats as floats.

use serde::Serialize;

use super::queries::DatabaseFigures;

/// `LoopLagStats`.
#[derive(Debug, Clone, Serialize)]
pub struct LoopLagStats {
    /// Watchdog samples in the window.
    pub samples: usize,
    /// How often the watchdog wakes (seconds).
    pub sample_interval_seconds: f64,
    /// The stall threshold.
    pub stall_threshold_ms: f64,
    /// Median lag.
    pub p50_ms: f64,
    /// 95th percentile.
    pub p95_ms: f64,
    /// 99th percentile.
    pub p99_ms: f64,
    /// The worst lag since the last reset.
    pub max_ms: f64,
    /// Samples above the threshold.
    pub stalls: u64,
    /// Their summed lag.
    pub total_stalled_ms: f64,
    /// The share of the uptime spent blocked.
    pub stalled_ratio: f64,
}

/// `PerformanceSummaryResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct PerformanceSummaryResponse {
    /// Always `true`.
    pub success: bool,
    /// The message.
    pub message: &'static str,
    /// `PERF_MONITOR_ENABLED`.
    pub monitoring_enabled: bool,
    /// Seconds since the start or the last reset.
    pub uptime_seconds: f64,
    /// Completed requests.
    pub total_requests: u64,
    /// Slow ones.
    pub slow_requests: u64,
    /// `PERF_SLOW_REQUEST_MS`.
    pub slow_request_threshold_ms: f64,
    /// `>= 500` ones.
    pub error_requests: u64,
    /// Abandoned ones.
    pub client_disconnects: u64,
    /// In flight now.
    pub in_flight: usize,
    /// The most at once.
    pub max_concurrency: usize,
    /// The lag figures.
    pub loop_lag: LoopLagStats,
    /// Their reading.
    pub verdict: String,
}

/// `EndpointTiming`.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointTiming {
    /// The method.
    pub method: String,
    /// The route template.
    pub path: String,
    /// Requests.
    pub count: u64,
    /// Mean duration.
    pub avg_ms: f64,
    /// Median.
    pub p50_ms: f64,
    /// 95th percentile.
    pub p95_ms: f64,
    /// The longest.
    pub max_ms: f64,
    /// Slow requests.
    pub slow_count: u64,
    /// `>= 500` answers.
    pub error_count: u64,
    /// Abandoned requests.
    pub disconnects: u64,
    /// Attributed stalls.
    pub stall_hits: u64,
    /// Attributed stall time.
    pub stalled_ms: f64,
}

/// `PerformanceEndpointsResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct PerformanceEndpointsResponse {
    /// Always `true`.
    pub success: bool,
    /// The message (naming the sort).
    pub message: String,
    /// The rows.
    pub endpoints: Vec<EndpointTiming>,
    /// Routes not tracked.
    pub dropped_endpoints: u64,
}

/// `RequestTiming`.
#[derive(Debug, Clone, Serialize)]
pub struct RequestTiming {
    /// Its id.
    pub request_id: u64,
    /// The method.
    pub method: String,
    /// The route template.
    pub path: String,
    /// The status (`0`: none was sent).
    pub status_code: u16,
    /// Its duration.
    pub duration_ms: f64,
    /// When it started (ISO, UTC).
    pub started_at: String,
    /// Requests in flight when it completed.
    pub concurrency: usize,
    /// Stall time observed while in flight.
    pub blocked_ms: f64,
    /// Stalls observed while in flight.
    pub stall_hits: u64,
    /// Whether the client went away.
    pub client_disconnected: bool,
}

/// `InFlightRequest`.
#[derive(Debug, Clone, Serialize)]
pub struct InFlightRequest {
    /// Its id.
    pub request_id: u64,
    /// The method.
    pub method: String,
    /// The decoded path.
    pub path: String,
    /// How long it has run.
    pub age_ms: f64,
    /// When it started.
    pub started_at: String,
}

/// `PerformanceRequestsResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct PerformanceRequestsResponse {
    /// Always `true`.
    pub success: bool,
    /// The message.
    pub message: &'static str,
    /// Completed requests, newest first.
    pub requests: Vec<RequestTiming>,
    /// Requests in flight.
    pub in_flight: Vec<InFlightRequest>,
}

/// `LoopStall`.
#[derive(Debug, Clone, Serialize)]
pub struct LoopStall {
    /// When it was detected.
    pub at: String,
    /// How late the watchdog woke.
    pub lag_ms: f64,
    /// The watchdog's window.
    pub window_ms: f64,
    /// Requests in flight then.
    pub concurrency: usize,
    /// The requests that overlapped it.
    pub suspects: Vec<String>,
}

/// `PerformanceStallsResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct PerformanceStallsResponse {
    /// Always `true`.
    pub success: bool,
    /// The message.
    pub message: &'static str,
    /// Stalls, newest first.
    pub stalls: Vec<LoopStall>,
    /// Stalls since the last reset.
    pub total_stalls: u64,
    /// Their summed lag.
    pub total_stalled_ms: f64,
}

/// `PerformanceResetResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct PerformanceResetResponse {
    /// Always `true`.
    pub success: bool,
    /// The message.
    pub message: &'static str,
    /// The new window's start.
    pub reset_at: String,
    /// The discarded window's length.
    pub previous_uptime_seconds: f64,
    /// Its requests.
    pub previous_total_requests: u64,
    /// Its worst lag.
    pub previous_max_lag_ms: Option<f64>,
}

/// `DatabaseSummaryResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct DatabaseSummaryResponse {
    /// Always `true`.
    pub success: bool,
    /// The message.
    pub message: &'static str,
    /// The figures.
    #[serde(flatten)]
    pub figures: DatabaseFigures,
}
