//! `EventLoopLagMonitor`: a task that sleeps `PERF_LAG_SAMPLE_INTERVAL` and
//! measures how late it wakes — on tokio, the time the runtime could not
//! schedule it (a worker blocked in synchronous code, or every worker
//! busy). A sample above `PERF_LAG_STALL_THRESHOLD_MS` is a stall,
//! attributed to the requests that overlapped it. Python's session-log
//! snapshot timer also samples the pool every minute; here the same task
//! does.

use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use super::perf;

/// How often the pool is sampled (`PERF_LOG_SNAPSHOT_INTERVAL`'s default).
pub const POOL_SAMPLE_INTERVAL: Duration = Duration::from_secs(60);

/// Start the watchdog (not when `PERF_MONITOR_ENABLED` is off) until
/// `cancel`.
pub fn spawn(cancel: CancellationToken) {
    let perf = perf();
    if !perf.config.enabled {
        tracing::info!(
            "PERF: monitoring disabled via PERF_MONITOR_ENABLED, lag monitor not started"
        );
        return;
    }
    // `asyncio.sleep(0)` would spin; a millisecond is the floor here.
    // An interval `Duration` cannot hold (infinite, NaN) is the default.
    let interval = Duration::try_from_secs_f64(perf.config.lag_sample_interval.max(0.001))
        .unwrap_or(Duration::from_millis(250));
    tracing::info!(
        "PERF: runtime lag monitor started (interval={}s, stall threshold={}ms)",
        perf.config.lag_sample_interval,
        perf.config.lag_stall_threshold_ms
    );
    tokio::spawn(async move {
        let mut last_pool_sample = Instant::now();
        loop {
            let start = Instant::now();
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(interval) => {}
            }
            let end = Instant::now();
            let lag_ms = ((end - start).as_secs_f64() - interval.as_secs_f64()).max(0.0) * 1000.0;
            perf.requests().record_lag(start, end, lag_ms);
            if last_pool_sample.elapsed() >= POOL_SAMPLE_INTERVAL {
                last_pool_sample = Instant::now();
                let pool = perf.pool();
                perf.queries().sample_pool(pool.as_ref());
            }
        }
    });
}
