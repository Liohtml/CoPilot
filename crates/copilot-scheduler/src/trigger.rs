//! APScheduler's interval trigger, as CoPilot configures it, in pure
//! functions.
//!
//! `scheduler.add_job(func, "interval", minutes=n, coalesce=True,
//! max_instances=1)` with the default `misfire_grace_time` of one second:
//!
//! - **a fixed grid**: the first run is one interval after the job was
//!   scheduled (`start_date = now + interval`), then every interval from
//!   there — not an interval after the previous run finished;
//! - **coalesce**: when several fire times have passed, one run, for the
//!   latest of them;
//! - **one instance**: a fire time reached while the job still runs is
//!   skipped (`maximum number of running instances reached`), so the next run
//!   is the first grid point after the run ended;
//! - **misfire grace**: a run more than a second late (a suspended host, a
//!   blocked loop) is not run at all (`EVENT_JOB_MISSED`).

use chrono::{DateTime, Duration, Utc};

/// `misfire_grace_time` (APScheduler's default).
pub const MISFIRE_GRACE: Duration = Duration::seconds(1);

/// A wake-up's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Due {
    /// The fire time being served (the latest one passed: coalesce).
    pub run_time: DateTime<Utc>,
    /// More than [`MISFIRE_GRACE`] late: do not run.
    pub missed: bool,
}

fn steps(span: Duration, interval: Duration) -> i64 {
    let span = span.num_microseconds().unwrap_or(i64::MAX);
    let step = interval.num_microseconds().unwrap_or(i64::MAX).max(1);
    span / step
}

/// What to do at `now` for a job whose next fire time is `next`; `None`
/// when it is not due yet.
pub fn due(next: DateTime<Utc>, interval: Duration, now: DateTime<Utc>) -> Option<Due> {
    if now < next {
        return None;
    }
    let k = steps(now - next, interval);
    let run_time = next + interval * i32::try_from(k).unwrap_or(i32::MAX);
    Some(Due {
        run_time,
        missed: now - run_time > MISFIRE_GRACE,
    })
}

/// The first fire time strictly after `after` on the grid through `anchor`.
pub fn next_after(
    anchor: DateTime<Utc>,
    interval: Duration,
    after: DateTime<Utc>,
) -> DateTime<Utc> {
    if after < anchor {
        return anchor;
    }
    let k = steps(after - anchor, interval) + 1;
    anchor + interval * i32::try_from(k).unwrap_or(i32::MAX)
}

/// How soon an overdue job runs after this service starts.
pub const OVERDUE_DELAY: Duration = Duration::minutes(1);

/// The first fire time of a job whose loop starts at `now`.
///
/// APScheduler starts a fresh grid one interval after it schedules a job,
/// and CoPilot reschedules every job at each start — so a job whose interval
/// is longer than the process's uptime (the daily `prune_audit_log` on a host
/// restarted daily) never runs. This runner continues from the job's last
/// success instead: one interval after it, or [`OVERDUE_DELAY`] from now when
/// that has passed; one interval from now when the job never ran.
pub fn first_fire(
    now: DateTime<Utc>,
    interval: Duration,
    last_success: Option<DateTime<Utc>>,
) -> DateTime<Utc> {
    match last_success {
        None => now + interval,
        Some(last) => {
            let due = last + interval;
            if due > now {
                due.min(now + interval)
            } else {
                now + OVERDUE_DELAY.min(interval)
            }
        }
    }
}

/// An interval of `minutes` (at least one, as the Python form enforces
/// nothing and a zero interval would spin).
pub fn interval_minutes(minutes: i64) -> Duration {
    Duration::minutes(minutes.clamp(1, 60 * 24 * 365))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000 + secs, 0)
            .single()
            .unwrap_or_default()
    }

    #[test]
    fn not_due_before_the_fire_time() {
        assert_eq!(due(t(60), Duration::seconds(60), t(59)), None);
    }

    #[test]
    fn on_time_runs_late_by_more_than_a_second_is_missed() {
        let i = Duration::seconds(60);
        assert_eq!(
            due(t(60), i, t(60)),
            Some(Due {
                run_time: t(60),
                missed: false
            })
        );
        assert!(!due(t(60), i, t(60) + Duration::milliseconds(900)).is_some_and(|d| d.missed));
        assert!(due(t(60), i, t(62)).is_some_and(|d| d.missed));
    }

    #[test]
    fn coalesces_to_the_latest_fire_time() {
        let d = due(t(60), Duration::seconds(60), t(60 * 5)).unwrap_or(Due {
            run_time: t(0),
            missed: true,
        });
        assert_eq!(d.run_time, t(300));
        assert!(!d.missed);
    }

    #[test]
    fn a_long_run_skips_the_fire_times_it_overlapped() {
        let i = Duration::seconds(60);
        // Ran at 60 until 185: 120 and 180 were skipped, next is 240.
        assert_eq!(next_after(t(60), i, t(185)), t(240));
        // A quick run: the next grid point.
        assert_eq!(next_after(t(60), i, t(60)), t(120));
        assert_eq!(next_after(t(60), i, t(10)), t(60));
    }

    #[test]
    fn the_first_run_continues_from_the_last_success() {
        let i = Duration::minutes(10);
        // Never ran: one interval from now, like APScheduler.
        assert_eq!(first_fire(t(0), i, None), t(600));
        // Ran 4 minutes ago: six minutes from now.
        assert_eq!(first_fire(t(0), i, Some(t(-240))), t(360));
        // Overdue: shortly.
        assert_eq!(first_fire(t(0), i, Some(t(-3600))), t(60));
        // A clock ahead of ours never pushes it beyond one interval.
        assert_eq!(first_fire(t(0), i, Some(t(3600))), t(600));
    }

    #[test]
    fn interval_is_at_least_a_minute() {
        assert_eq!(interval_minutes(0), Duration::minutes(1));
        assert_eq!(interval_minutes(1440), Duration::minutes(1440));
    }
}
