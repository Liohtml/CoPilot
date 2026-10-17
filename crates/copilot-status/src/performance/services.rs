//! `app/performance/services/performance.py`: read-side projections of the
//! registries — no I/O. `client_disconnects` is a lower bound, as in
//! Python: a request whose client leaves after the last byte was handed to
//! the connection is not seen.

use super::schema::{
    DatabaseSummaryResponse, EndpointTiming, InFlightRequest, LoopLagStats, LoopStall,
    PerformanceEndpointsResponse, PerformanceRequestsResponse, PerformanceResetResponse,
    PerformanceStallsResponse, PerformanceSummaryResponse, RequestTiming,
};
use super::{Perf, iso, percentile, py_round};

/// `SORT_FIELDS`.
pub const SORT_FIELDS: [&str; 7] = [
    "stalled_ms",
    "stall_hits",
    "avg_ms",
    "p95_ms",
    "max_ms",
    "count",
    "slow_count",
];

fn lag_stats(perf: &Perf) -> LoopLagStats {
    let r = perf.requests();
    let samples = r.lag_samples();
    let uptime = r.uptime_seconds().max(1e-9);
    LoopLagStats {
        samples: samples.len(),
        sample_interval_seconds: perf.config.lag_sample_interval,
        stall_threshold_ms: perf.config.lag_stall_threshold_ms,
        p50_ms: percentile(&samples, 50.0),
        p95_ms: percentile(&samples, 95.0),
        p99_ms: percentile(&samples, 99.0),
        max_ms: py_round(r.max_lag_ms, 2),
        stalls: r.total_stalls,
        total_stalled_ms: py_round(r.total_stalled_ms, 2),
        stalled_ratio: py_round(r.total_stalled_ms / 1000.0 / uptime, 4),
    }
}

/// `_verdict(lag)`.
fn verdict(perf: &Perf, lag: &LoopLagStats) -> String {
    if !perf.config.enabled {
        return "Monitoring is disabled (PERF_MONITOR_ENABLED=false) - no measurements are being \
                taken."
            .into();
    }
    if lag.samples == 0 {
        return "No samples yet - the watchdog has not completed its first interval.".into();
    }
    if lag.p95_ms < 20.0 && lag.max_ms < perf.config.lag_stall_threshold_ms {
        return "Event loop is healthy: it is always able to schedule work promptly. Slow pages \
                are not caused by blocking on the backend."
            .into();
    }
    if lag.stalls == 0 {
        return "Minor scheduling delay, no stalls above the threshold. The loop is not being \
                blocked meaningfully."
            .into();
    }
    format!(
        "Event loop was blocked {} time(s) for {:.0}ms total ({:.1}% of uptime), peaking at \
         {:.0}ms. While blocked, every concurrent request waits regardless of what the client \
         does. Check /performance/stalls for the endpoints that overlapped each stall.",
        lag.stalls,
        lag.total_stalled_ms,
        lag.stalled_ratio * 100.0,
        lag.max_ms
    )
}

/// `get_performance_summary()`.
pub fn summary(perf: &Perf) -> PerformanceSummaryResponse {
    let lag = lag_stats(perf);
    let verdict = verdict(perf, &lag);
    let r = perf.requests();
    PerformanceSummaryResponse {
        success: true,
        message: "Performance summary retrieved successfully",
        monitoring_enabled: perf.config.enabled,
        uptime_seconds: py_round(r.uptime_seconds(), 2),
        total_requests: r.total_requests,
        slow_requests: r.total_slow,
        slow_request_threshold_ms: perf.config.slow_request_ms,
        error_requests: r.total_errors,
        client_disconnects: r.total_disconnects,
        in_flight: r.in_flight().len(),
        max_concurrency: r.max_concurrency,
        loop_lag: lag,
        verdict,
    }
}

fn sort_key(row: &EndpointTiming, field: &str) -> f64 {
    match field {
        "stall_hits" => row.stall_hits as f64,
        "avg_ms" => row.avg_ms,
        "p95_ms" => row.p95_ms,
        "max_ms" => row.max_ms,
        "count" => row.count as f64,
        "slow_count" => row.slow_count as f64,
        _ => row.stalled_ms,
    }
}

/// `get_endpoint_timings(limit, sort_by)`: an unknown sort is
/// `stalled_ms`.
pub fn endpoints(perf: &Perf, limit: usize, sort_by: &str) -> PerformanceEndpointsResponse {
    let sort_by = if SORT_FIELDS.contains(&sort_by) {
        sort_by
    } else {
        "stalled_ms"
    };
    let r = perf.requests();
    let mut rows: Vec<EndpointTiming> = r
        .endpoints()
        .into_iter()
        .filter(|s| s.count != 0)
        .map(|s| {
            let samples: Vec<f64> = s.samples.iter().copied().collect();
            EndpointTiming {
                method: s.method,
                path: s.path,
                count: s.count,
                avg_ms: py_round(s.total_ms / s.count as f64, 2),
                p50_ms: percentile(&samples, 50.0),
                p95_ms: percentile(&samples, 95.0),
                max_ms: py_round(s.max_ms, 2),
                slow_count: s.slow_count,
                error_count: s.error_count,
                disconnects: s.disconnects,
                stall_hits: s.stall_hits,
                stalled_ms: py_round(s.stalled_ms, 2),
            }
        })
        .collect();
    // `rows.sort(key=…, reverse=True)`: stable, equal rows keep their order.
    rows.sort_by(|a, b| sort_key(b, sort_by).total_cmp(&sort_key(a, sort_by)));
    rows.truncate(limit);
    PerformanceEndpointsResponse {
        success: true,
        message: format!("Endpoint timings retrieved successfully, sorted by {sort_by}"),
        endpoints: rows,
        dropped_endpoints: r.dropped_endpoints,
    }
}

/// `get_recent_requests(limit, min_duration_ms)`: completed requests at
/// least that slow, newest first, and every request in flight (this one
/// included).
pub fn requests(perf: &Perf, limit: usize, min_duration_ms: f64) -> PerformanceRequestsResponse {
    let r = perf.requests();
    let records: Vec<RequestTiming> = r
        .recent_requests()
        .into_iter()
        .filter(|x| x.duration_ms >= min_duration_ms)
        .rev()
        .take(limit)
        .map(|x| RequestTiming {
            request_id: x.request_id,
            method: x.method,
            path: x.path,
            status_code: x.status_code,
            duration_ms: py_round(x.duration_ms, 2),
            started_at: iso(x.started_wall),
            concurrency: x.concurrency,
            blocked_ms: py_round(x.blocked_ms, 2),
            stall_hits: x.stall_hits,
            client_disconnected: x.client_disconnected,
        })
        .collect();
    let in_flight = r
        .in_flight()
        .into_iter()
        .map(|e| InFlightRequest {
            request_id: e.request_id,
            method: e.method,
            path: e.raw_path,
            age_ms: py_round(e.started.elapsed().as_secs_f64() * 1000.0, 2),
            started_at: iso(e.started_wall),
        })
        .collect();
    PerformanceRequestsResponse {
        success: true,
        message: "Recent requests retrieved successfully",
        requests: records,
        in_flight,
    }
}

/// `get_loop_stalls(limit)`: newest first.
pub fn stalls(perf: &Perf, limit: usize) -> PerformanceStallsResponse {
    let r = perf.requests();
    PerformanceStallsResponse {
        success: true,
        message: "Event loop stalls retrieved successfully",
        stalls: r
            .stalls()
            .into_iter()
            .rev()
            .take(limit)
            .map(|s| LoopStall {
                at: iso(s.at_wall),
                lag_ms: py_round(s.lag_ms, 2),
                window_ms: py_round(s.window_ms, 2),
                concurrency: s.concurrency,
                suspects: s.suspects,
            })
            .collect(),
        total_stalls: r.total_stalls,
        total_stalled_ms: py_round(r.total_stalled_ms, 2),
    }
}

/// `reset_performance_counters()`: both registries zeroed, the requests in
/// flight kept.
pub fn reset(perf: &Perf) -> PerformanceResetResponse {
    let (uptime, total, max_lag, reset_at) = {
        let mut r = perf.requests();
        let previous = (
            py_round(r.uptime_seconds(), 2),
            r.total_requests,
            py_round(r.max_lag_ms, 2),
        );
        r.reset();
        (previous.0, previous.1, previous.2, iso(r.started_wall))
    };
    perf.queries().reset();
    PerformanceResetResponse {
        success: true,
        message: "Performance counters reset successfully",
        reset_at,
        previous_uptime_seconds: uptime,
        previous_total_requests: total,
        previous_max_lag_ms: Some(max_lag),
    }
}

/// `get_database_summary()`: the pool sampled first, so the answer reflects
/// the moment it was asked.
pub fn database(perf: &Perf) -> DatabaseSummaryResponse {
    let pool = perf.pool();
    let mut q = perf.queries();
    q.sample_pool(pool.as_ref());
    DatabaseSummaryResponse {
        success: true,
        message: "Database metrics retrieved successfully",
        figures: q.summary(pool.as_ref(), 12),
    }
}
