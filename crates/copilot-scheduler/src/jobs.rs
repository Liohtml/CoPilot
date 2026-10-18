//! Jobs whose work needs only the database: ported here, run when handed
//! over.
//!
//! | Job | Python | Interval |
//! |---|---|---|
//! | [`PRUNE_AUDIT_LOG`] | `app/audit/services/retention.py:prune_audit_log` | daily |
//!
//! The palace drainer and sweeper (Talon) live in `copilot-ai-analyst`
//! (`palace_jobs::job_specs`).

use chrono::{Datelike, Duration, NaiveDateTime};

use copilot_db::Db;
use copilot_db::scheduler as db;

use crate::job::{JobError, JobSpec};

/// `prune_audit_log`'s job id.
pub const PRUNE_AUDIT_LOG: &str = "prune_audit_log";

/// `DEFAULT_AUDIT_LOG_RETENTION_DAYS`.
pub const DEFAULT_RETENTION_DAYS: i64 = 90;

/// `get_retention_days()` and what `timedelta(days=…)` makes of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retention {
    /// Prune rows older than this many days.
    Days(i64),
    /// `<= 0`: keep everything.
    Disabled,
    /// A positive integer `timedelta` refuses (Python's job raises).
    TooLarge(String),
}

/// Python's `int()` shape: sign, digits, single underscores between digits.
fn int_shape(text: &str) -> Option<(bool, String)> {
    let t = text.trim();
    let (negative, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let b = digits.as_bytes();
    if b.is_empty()
        || b[0] == b'_'
        || b[b.len() - 1] == b'_'
        || digits.contains("__")
        || !b.iter().all(|c| c.is_ascii_digit() || *c == b'_')
    {
        return None;
    }
    Some((negative, digits.replace('_', "")))
}

/// `get_retention_days()` over `os.getenv("AUDIT_LOG_RETENTION_DAYS", "90")`:
/// unreadable → the default (with a warning), `<= 0` → disabled.
pub fn retention(raw: Option<&str>) -> Retention {
    let raw = raw.unwrap_or("90");
    let Some((negative, digits)) = int_shape(raw) else {
        tracing::warn!(
            value = raw,
            "Invalid AUDIT_LOG_RETENTION_DAYS; using default {DEFAULT_RETENTION_DAYS}"
        );
        return Retention::Days(DEFAULT_RETENTION_DAYS);
    };
    let zero = digits.bytes().all(|b| b == b'0');
    if negative || zero {
        return Retention::Disabled;
    }
    match digits.trim_start_matches('0').parse::<i64>() {
        // `timedelta(days=…)` takes a C int, at most 999999999.
        Ok(d) if d <= 999_999_999 => Retention::Days(d),
        Ok(d) if d <= i64::from(i32::MAX) => {
            Retention::TooLarge(format!("days={d}; must have magnitude <= 999999999"))
        }
        _ => Retention::TooLarge("Python int too large to convert to C int".into()),
    }
}

/// `datetime.utcnow() - timedelta(days=days)`, or Python's error.
pub fn cutoff(now: NaiveDateTime, days: i64) -> Result<NaiveDateTime, JobError> {
    let out_of_range = || JobError("date value out of range".into());
    let span = Duration::try_days(days).ok_or_else(out_of_range)?;
    let cutoff = now.checked_sub_signed(span).ok_or_else(out_of_range)?;
    if cutoff.year() < 1 {
        return Err(out_of_range());
    }
    Ok(cutoff)
}

/// One run of `prune_audit_log`; returns the rows deleted.
pub async fn prune_audit_log(db: &Db, raw_retention: Option<&str>) -> Result<u64, JobError> {
    let days = match retention(raw_retention) {
        Retention::Disabled => {
            tracing::info!(
                "Audit-log pruning disabled (AUDIT_LOG_RETENTION_DAYS <= 0); keeping all rows"
            );
            return Ok(0);
        }
        Retention::TooLarge(msg) => return Err(JobError(msg)),
        Retention::Days(d) => d,
    };
    let cutoff = cutoff(copilot_core::time::now_utc_micros(), days)?;
    let deleted = db::delete_audit_log_before(db, cutoff).await?;
    tracing::info!(
        deleted,
        days,
        cutoff = %cutoff.format("%Y-%m-%dT%H:%M:%S%.6fZ"),
        "Audit-log prune"
    );
    Ok(deleted)
}

/// The job, reading `AUDIT_LOG_RETENTION_DAYS` as configured.
pub fn prune_audit_log_spec(db: Db, raw_retention: Option<String>) -> JobSpec {
    JobSpec::new(PRUNE_AUDIT_LOG, 1440, move || {
        let db = db.clone();
        let raw = raw_retention.clone();
        async move { prune_audit_log(&db, raw.as_deref()).await.map(|_| ()) }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn retention_reads_like_get_retention_days() {
        assert_eq!(retention(None), Retention::Days(90));
        assert_eq!(retention(Some("30")), Retention::Days(30));
        assert_eq!(retention(Some(" +3_65 ")), Retention::Days(365));
        assert_eq!(retention(Some("0")), Retention::Disabled);
        assert_eq!(retention(Some("-5")), Retention::Disabled);
        assert_eq!(
            retention(Some("-99999999999999999999")),
            Retention::Disabled
        );
        assert_eq!(retention(Some("ninety")), Retention::Days(90));
        assert_eq!(retention(Some("")), Retention::Days(90));
        assert_eq!(retention(Some("9.5")), Retention::Days(90));
        assert_eq!(
            retention(Some("1000000000")),
            Retention::TooLarge("days=1000000000; must have magnitude <= 999999999".into())
        );
        assert_eq!(
            retention(Some("99999999999999999999999")),
            Retention::TooLarge("Python int too large to convert to C int".into())
        );
    }

    #[test]
    fn cutoff_matches_python_range() {
        let now =
            NaiveDateTime::parse_from_str("2026-10-15 18:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        assert_eq!(cutoff(now, 90).unwrap().to_string(), "2026-07-17 18:00:00");
        assert!(cutoff(now, 739_000).is_ok());
        assert_eq!(
            cutoff(now, 740_000).unwrap_err().0,
            "date value out of range"
        );
        assert_eq!(
            cutoff(now, 999_999_999).unwrap_err().0,
            "date value out of range"
        );
    }
}
