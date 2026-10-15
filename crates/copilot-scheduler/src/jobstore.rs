//! APScheduler's job store (`apscheduler_jobs`), read as the Python scheduler
//! reads it.
//!
//! Each row's `job_state` is a pickle of `Job.__getstate__()`
//! ([`crate::pickle`]). The Scheduler routes need three things from it: the
//! job's `id` and `name` (the callable's name — `get_function_by_name(job.name)`
//! is how a manual run finds the function) and `next_run_time`, rendered the
//! way Pydantic renders an aware `datetime` (`2026-10-15T18:00:00Z`,
//! `…+05:30`). The timezone comes from the pickled `tzinfo`: UTC under any
//! of its names, a fixed `datetime.timezone`, the fixed `Etc/GMT±N` zones and
//! pytz (whose pickle carries the offset) are converted here; a `zoneinfo`
//! zone with daylight saving time would need a tz database, so such a time is
//! [`NextRun::Unconvertible`] and the route lets Python answer.
//!
//! `apscheduler_vectors.json` (`scripts/gen-apscheduler-vectors.py`) pins
//! the reader against blobs written by APScheduler itself.

use crate::pickle::{self, PickleError, Value};

/// A job as the routes need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApsJob {
    /// `job.id`.
    pub id: String,
    /// `job.name` (by default the callable's name).
    pub name: String,
    /// `job.func_ref` (`module:function`).
    pub func: String,
    /// `job.next_run_time`.
    pub next_run: NextRun,
}

/// `job.next_run_time`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextRun {
    /// `None`: the job is paused.
    Paused,
    /// Rendered as Pydantic renders it.
    At(String),
    /// In a timezone this reader does not convert.
    Unconvertible,
}

impl NextRun {
    /// `job.next_run_time is not None`.
    pub fn is_scheduled(&self) -> bool {
        !matches!(self, NextRun::Paused)
    }
}

/// Decode one `job_state` blob.
pub fn decode_job(state: &[u8]) -> Result<ApsJob, PickleError> {
    let v = pickle::loads(state)?;
    let text = |key: &str| -> Result<String, PickleError> {
        v.get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| PickleError(format!("job state has no string {key:?}")))
    };
    match v.get("version") {
        Some(Value::Int(1)) => {}
        _ => return Err(PickleError("unknown job state version".into())),
    }
    let next_run = match v.get("next_run_time") {
        None | Some(Value::None) => NextRun::Paused,
        Some(dt) => match render_datetime(dt)? {
            Some(s) => NextRun::At(s),
            None => NextRun::Unconvertible,
        },
    };
    Ok(ApsJob {
        id: text("id")?,
        name: text("name")?,
        func: text("func")?,
        next_run,
    })
}

/// ZoneInfo keys that are UTC.
const UTC_KEYS: &[&str] = &[
    "UTC",
    "Etc/UTC",
    "Etc/UCT",
    "UCT",
    "Etc/Universal",
    "Universal",
    "Etc/Zulu",
    "Zulu",
    "Etc/GMT",
    "GMT",
    "Etc/GMT0",
    "GMT0",
    "Etc/GMT+0",
    "Etc/GMT-0",
    "GMT+0",
    "GMT-0",
    "Etc/Greenwich",
    "Greenwich",
];

/// What a pickled `tzinfo` says about the offset.
enum Tz {
    Naive,
    Offset(i64),
    Unconvertible,
}

fn int(v: &Value) -> Option<i128> {
    match v {
        Value::Int(i) => Some(*i),
        Value::Bool(b) => Some(i128::from(*b)),
        _ => None,
    }
}

/// `timedelta(days, seconds, microseconds)` → whole seconds (a UTC offset
/// is whole seconds in practice; microseconds are dropped like Pydantic's
/// rendering drops them).
fn timedelta_seconds(v: &Value) -> Option<i64> {
    let Value::Call { func, args, .. } = v else {
        return None;
    };
    if !func.is_global("datetime", "timedelta") {
        return None;
    }
    let a = args.items()?;
    let days = a.first().and_then(int).unwrap_or(0);
    let secs = a.get(1).and_then(int).unwrap_or(0);
    i64::try_from(days * 86_400 + secs).ok()
}

fn tz_of(v: Option<&Value>) -> Tz {
    let Some(v) = v else { return Tz::Naive };
    if matches!(v, Value::None) {
        return Tz::Naive;
    }
    let Value::Call { func, args, .. } = v else {
        return Tz::Unconvertible;
    };
    let args = args.items().unwrap_or(&[]);
    // zoneinfo: getattr(ZoneInfo, "_unpickle")(key, from_cache)
    if let Value::Call {
        func: inner,
        args: inner_args,
        ..
    } = func.as_ref()
    {
        let is_unpickle = inner.is_global("builtins", "getattr")
            && inner_args.items().is_some_and(|a| {
                a.first()
                    .is_some_and(|c| c.is_global("zoneinfo", "ZoneInfo"))
                    && a.get(1).and_then(Value::as_str) == Some("_unpickle")
            });
        if is_unpickle {
            return match args.first().and_then(Value::as_str) {
                Some(key) => zoneinfo_offset(key).map_or(Tz::Unconvertible, Tz::Offset),
                None => Tz::Unconvertible,
            };
        }
        return Tz::Unconvertible;
    }
    // datetime.timezone(offset[, name])
    if func.is_global("datetime", "timezone") {
        return args
            .first()
            .and_then(timedelta_seconds)
            .map_or(Tz::Unconvertible, Tz::Offset);
    }
    // pytz.utc
    if func.is_global("pytz", "_UTC") {
        return Tz::Offset(0);
    }
    // pytz DstTzInfo: _p(zone, utcoffset_seconds, dst_seconds, tzname)
    if func.is_global("pytz", "_p") && args.len() >= 2 {
        return args
            .get(1)
            .and_then(int)
            .and_then(|o| i64::try_from(o).ok())
            .map_or(Tz::Unconvertible, Tz::Offset);
    }
    Tz::Unconvertible
}

/// The fixed offset of a ZoneInfo key, if it has one this reader knows.
fn zoneinfo_offset(key: &str) -> Option<i64> {
    if UTC_KEYS.contains(&key) {
        return Some(0);
    }
    // POSIX-style: Etc/GMT+5 is five hours *behind* UTC.
    let n = key.strip_prefix("Etc/GMT")?;
    let (sign, digits) = match n.as_bytes().first()? {
        b'+' => (-1, &n[1..]),
        b'-' => (1, &n[1..]),
        _ => return None,
    };
    let hours: i64 = digits.parse().ok()?;
    // Only the zones tzdata has: `Etc/GMT+5`, never `Etc/GMT+05`.
    ((1..=14).contains(&hours) && digits == hours.to_string()).then_some(sign * hours * 3600)
}

/// Render a pickled `datetime` as Pydantic's JSON does; `None` when its
/// timezone is not convertible here.
pub fn render_datetime(v: &Value) -> Result<Option<String>, PickleError> {
    let bad = || PickleError("next_run_time is not a datetime".into());
    let Value::Call { func, args, .. } = v else {
        return Err(bad());
    };
    if !func.is_global("datetime", "datetime") {
        return Err(bad());
    }
    let a = args.items().ok_or_else(bad)?;
    let Some(Value::Bytes(b)) = a.first() else {
        return Err(bad());
    };
    if b.len() != 10 {
        return Err(bad());
    }
    let year = u32::from(b[0]) * 256 + u32::from(b[1]);
    // `fold` rides on the month byte's high bit (protocol > 3).
    let month = b[2] & 0x7f;
    let (day, hour, minute, second) = (b[3], b[4], b[5], b[6]);
    let micro = (u32::from(b[7]) << 16) | (u32::from(b[8]) << 8) | u32::from(b[9]);
    let mut out = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}");
    if micro != 0 {
        out.push_str(&format!(".{micro:06}"));
    }
    match tz_of(a.get(1)) {
        Tz::Naive => {}
        Tz::Offset(0) => out.push('Z'),
        Tz::Offset(secs) => {
            let sign = if secs < 0 { '-' } else { '+' };
            let abs = secs.unsigned_abs();
            out.push_str(&format!("{sign}{:02}:{:02}", abs / 3600, (abs % 3600) / 60));
        }
        Tz::Unconvertible => return Ok(None),
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use serde_json::Value as Json;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn apscheduler_vectors() {
        let doc: Json = serde_json::from_str(include_str!("apscheduler_vectors.json")).unwrap();
        let vectors = doc["vectors"].as_array().unwrap();
        assert!(vectors.len() >= 20);
        for v in vectors {
            let label = v["label"].as_str().unwrap();
            let job = decode_job(&hex(v["job_state"].as_str().unwrap()))
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(job.id, v["id"], "{label}");
            assert_eq!(job.name, v["name"], "{label}");
            assert_eq!(job.func, v["func"], "{label}");
            let expected = match (&v["next_run_time"], v["tz_supported"].as_bool().unwrap()) {
                (Json::Null, _) => NextRun::Paused,
                (_, false) => NextRun::Unconvertible,
                (Json::String(s), true) => NextRun::At(s.clone()),
                other => panic!("{label}: {other:?}"),
            };
            assert_eq!(job.next_run, expected, "{label}");
        }
    }

    #[test]
    fn etc_gmt_zones() {
        assert_eq!(zoneinfo_offset("Etc/GMT+5"), Some(-5 * 3600));
        assert_eq!(zoneinfo_offset("Etc/GMT-14"), Some(14 * 3600));
        assert_eq!(zoneinfo_offset("Etc/GMT-15"), None);
        assert_eq!(zoneinfo_offset("Etc/GMT+05"), None);
        assert_eq!(zoneinfo_offset("Europe/Berlin"), None);
        assert_eq!(zoneinfo_offset("Etc/UTC"), Some(0));
    }

    #[test]
    fn garbage_is_an_error() {
        assert!(decode_job(b"not a pickle").is_err());
        // A dict without the APScheduler fields.
        assert!(decode_job(b"\x80\x05}\x94.").is_err());
    }
}
