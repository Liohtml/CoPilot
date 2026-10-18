//! APScheduler 3.11's `interval` trigger, as CoPilot configures it, in pure
//! functions over epoch microseconds.
//!
//! `scheduler.add_job(func, "interval", minutes=n, coalesce=True,
//! max_instances=1)` with the default `misfire_grace_time` of one second:
//!
//! - **the trigger** ([`IntervalTrigger`]): `interval = timedelta(minutes=n)`
//!   (a zero interval is one second), `start_date = now + interval` when the
//!   job is scheduled; `get_next_fire_time` works in **float seconds** —
//!   `previous.timestamp() + interval_length`, or, without a previous fire,
//!   the start date while it is ahead, else `start + interval_length *
//!   ceil((now - start) / interval_length)` — and turns the result back into
//!   a `datetime` with `fromtimestamp`'s round-half-even
//!   ([`fromtimestamp`]). A reschedule builds a new trigger from now; a
//!   resume asks the job's existing one (`get_next_fire_time(None, now)`), so
//!   it lands on the job's original grid;
//! - **coalesce**: of the run times due (`_get_run_times`: from the job's
//!   next run time, each the trigger's next fire after the previous, up to
//!   `now`), only the latest is run, and the next run time stored is the
//!   trigger's next fire after it ([`due`]);
//! - **one instance**: a due run time reached while the job still runs is not
//!   run (`maximum number of running instances reached`); the next run time
//!   moves on all the same;
//! - **misfire grace**: a run that starts more than a second after its run
//!   time is not run (`Run time of job … was missed`).
//!
//! Pinned by `scheduler_vectors.json` (`scripts/gen-scheduler-vectors.py`,
//! from APScheduler itself).

/// An aware UTC `datetime`, in microseconds since the epoch.
pub type Micros = i64;

/// `misfire_grace_time` (APScheduler's default), in microseconds.
pub const MISFIRE_GRACE_US: Micros = 1_000_000;

/// `datetime.max` / `datetime.min` (UTC), in microseconds since the epoch.
pub const MAX_DATETIME_US: Micros = 253_402_300_799_999_999;
/// See [`MAX_DATETIME_US`].
pub const MIN_DATETIME_US: Micros = -62_135_596_800_000_000;

/// `timedelta`'s day limit.
const MAX_DELTA_DAYS: i128 = 999_999_999;

/// Microseconds per minute.
const US_PER_MINUTE: i128 = 60_000_000;

/// Why a trigger could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntervalError {
    /// The `OverflowError` Python raises (`timedelta`, or the start date):
    /// uncaught by every route, a bare 500.
    Overflow(String),
    /// A negative interval: APScheduler accepts it and its scheduler then
    /// loops for ever over run times that never pass `now` (the event loop,
    /// the whole Python process, hangs). Refused here (§4).
    Negative,
}

impl std::fmt::Display for IntervalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntervalError::Overflow(text) => write!(f, "OverflowError: {text}"),
            IntervalError::Negative => f.write_str(NEGATIVE_INTERVAL),
        }
    }
}

/// The refusal of a negative interval (the 400's message).
pub const NEGATIVE_INTERVAL: &str = "time_interval must not be negative: APScheduler's interval trigger never gets past a \
     negative interval";

/// `datetime.timestamp()` of an aware datetime: the exact microseconds over
/// 10⁶, correctly rounded (exact operands below 2⁵³ µs, i.e. before 2255).
pub fn timestamp(t: Micros) -> f64 {
    // An i64 below 2^53 converts exactly; IEEE division is correctly rounded.
    #[allow(clippy::cast_precision_loss)]
    let us = t as f64;
    us / 1e6
}

/// C's `round()` (half away from zero), then CPython's half-even correction
/// (`_PyTime_RoundHalfEven`).
fn round_half_even(x: f64) -> f64 {
    let rounded = x.round();
    if (x - rounded).abs() == 0.5 {
        2.0 * (x / 2.0).round()
    } else {
        rounded
    }
}

/// `datetime.fromtimestamp(t, tz)` in microseconds: `modf`, the fraction
/// times 10⁶ rounded half to even (`_PyTime_DoubleToDenominator`), carried
/// into the seconds; `None` outside `datetime`'s range (Python raises).
pub fn fromtimestamp(t: f64) -> Option<Micros> {
    if !t.is_finite() {
        return None;
    }
    let mut intpart = t.trunc();
    let mut floatpart = round_half_even((t - intpart) * 1e6);
    if floatpart >= 1e6 {
        floatpart -= 1e6;
        intpart += 1.0;
    } else if floatpart < 0.0 {
        floatpart += 1e6;
        intpart -= 1.0;
    }
    // Whole seconds within datetime's range fit an i64 exactly.
    if !(-62_135_596_800.0..=253_402_300_799.0).contains(&intpart) {
        return None;
    }
    #[allow(clippy::cast_possible_truncation)]
    let us = (intpart as i64) * 1_000_000 + floatpart as i64;
    Some(us)
}

/// `IntervalTrigger(minutes=n, timezone=…)`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IntervalTrigger {
    /// `start_date`.
    pub start: Micros,
    /// `interval`, in microseconds (at least one second).
    pub interval: Micros,
    /// `interval_length` (`interval.total_seconds()`).
    pub length: f64,
}

impl IntervalTrigger {
    /// The trigger a job scheduled at `now` gets (`start_date = now +
    /// interval`), or what Python raises for `minutes`.
    pub fn new(minutes: i128, now: Micros) -> Result<Self, IntervalError> {
        if minutes < 0 {
            // Checked first: the refusal is this service's own, and every
            // negative interval Python can even build would hang it.
            return Err(IntervalError::Negative);
        }
        // `timedelta(minutes=n)`: the days must fit a C int, then 999999999.
        let interval_us = minutes.saturating_mul(US_PER_MINUTE);
        let days = interval_us.div_euclid(86_400_000_000);
        if i32::try_from(days).is_err() {
            return Err(IntervalError::Overflow(
                "Python int too large to convert to C int".into(),
            ));
        }
        if days.abs() > MAX_DELTA_DAYS {
            return Err(IntervalError::Overflow(format!(
                "days={days}; must have magnitude <= {MAX_DELTA_DAYS}"
            )));
        }
        // `interval_length == 0` → one second.
        let interval_us = if interval_us == 0 {
            1_000_000
        } else {
            interval_us
        };
        let start = i128::from(now) + interval_us;
        if start > i128::from(MAX_DATETIME_US) || start < i128::from(MIN_DATETIME_US) {
            return Err(IntervalError::Overflow("date value out of range".into()));
        }
        // A whole number of seconds: `total_seconds()` is exact up to 2^53.
        #[allow(clippy::cast_precision_loss)]
        let length = (interval_us / 1_000_000) as f64;
        Ok(Self {
            start: i64::try_from(start).unwrap_or(MAX_DATETIME_US),
            interval: i64::try_from(interval_us).unwrap_or(i64::MAX),
            length,
        })
    }

    /// `get_next_fire_time(previous_fire_time, now)`; `None` where Python's
    /// `fromtimestamp` would raise (the job is then finished).
    pub fn next_fire(&self, previous: Option<Micros>, now: Micros) -> Option<Micros> {
        let next = match previous {
            Some(prev) => timestamp(prev) + self.length,
            None if self.start > now => timestamp(self.start),
            None => {
                let diff = timestamp(now) - timestamp(self.start);
                let n = (diff / self.length).ceil();
                timestamp(self.start) + self.length * n
            }
        };
        fromtimestamp(next)
    }
}

/// How many run times [`run_times`] walks before giving up (a one-second job
/// after a very long suspension).
pub const MAX_RUN_TIMES: usize = 1_000_000;

/// `job._get_run_times(now)`: the run times from `next_run_time` up to `now`
/// (inclusive), each the trigger's next fire after the previous.
pub fn run_times(trigger: &IntervalTrigger, next_run_time: Micros, now: Micros) -> Vec<Micros> {
    let mut out = Vec::new();
    let mut next = Some(next_run_time);
    while let Some(t) = next {
        if t > now || out.len() >= MAX_RUN_TIMES {
            break;
        }
        out.push(t);
        next = trigger.next_fire(Some(t), now);
    }
    out
}

/// What `_process_jobs` does with a job whose next run time is due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Due {
    /// The run time coalescing keeps (the latest due).
    pub run_time: Micros,
    /// The next run time stored (`None`: the job is finished).
    pub next: Option<Micros>,
}

/// `_process_jobs` for one job at `now`: `None` while it is not due.
pub fn due(trigger: &IntervalTrigger, next_run_time: Micros, now: Micros) -> Option<Due> {
    let times = run_times(trigger, next_run_time, now);
    let run_time = *times.last()?;
    Some(Due {
        run_time,
        next: trigger.next_fire(Some(run_time), now),
    })
}

/// The executor's misfire check, at the moment the run starts.
pub fn missed(run_time: Micros, started: Micros) -> bool {
    started - run_time > MISFIRE_GRACE_US
}

/// The current time, as [`Micros`].
pub fn now_us() -> Micros {
    chrono::Utc::now().timestamp_micros()
}

/// A [`Micros`] as a chrono UTC time.
pub fn to_utc(t: Micros) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp_micros(t)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use serde_json::Value;

    fn doc() -> Value {
        serde_json::from_str(include_str!("scheduler_vectors.json")).unwrap()
    }

    fn opt(v: &Value) -> Option<Micros> {
        v.as_i64()
    }

    fn trigger(start: Micros, minutes: i64) -> IntervalTrigger {
        let interval = if minutes == 0 {
            1_000_000
        } else {
            minutes * 60_000_000
        };
        #[allow(clippy::cast_precision_loss)]
        IntervalTrigger {
            start,
            interval,
            length: (interval / 1_000_000) as f64,
        }
    }

    #[test]
    fn fromtimestamp_rounds_like_cpython() {
        let d = doc();
        for v in d["fromtimestamp"].as_array().unwrap() {
            let t: f64 = v["repr"].as_str().unwrap().parse().unwrap();
            assert_eq!(fromtimestamp(t), opt(&v["us"]), "{v}");
        }
    }

    #[test]
    fn next_fire_is_apscheduler_s() {
        let d = doc();
        let cases = d["next_fire"].as_array().unwrap();
        assert!(cases.len() > 200);
        for v in cases {
            let t = trigger(v["start"].as_i64().unwrap(), v["minutes"].as_i64().unwrap());
            let got = t.next_fire(opt(&v["prev"]), v["now"].as_i64().unwrap());
            assert_eq!(got, opt(&v["next"]), "{v}");
        }
    }

    #[test]
    fn run_times_and_coalescing_are_apscheduler_s() {
        let d = doc();
        for v in d["run_times"].as_array().unwrap() {
            let t = trigger(v["start"].as_i64().unwrap(), v["minutes"].as_i64().unwrap());
            let next = v["next_run_time"].as_i64().unwrap();
            let now = v["now"].as_i64().unwrap();
            let times: Vec<Value> = run_times(&t, next, now)
                .into_iter()
                .map(Value::from)
                .collect();
            assert_eq!(&Value::Array(times), &v["run_times"], "{v}");
            let d = due(&t, next, now);
            assert_eq!(
                d.map(|d| vec![Value::from(d.run_time)]).unwrap_or_default(),
                v["kept"].as_array().unwrap().clone(),
                "{v}"
            );
            assert_eq!(d.and_then(|d| d.next), opt(&v["next"]), "{v}");
        }
    }

    #[test]
    fn new_triggers_and_their_overflows_are_python_s() {
        let d = doc();
        for v in d["intervals"].as_array().unwrap() {
            let minutes: i128 = v["minutes"].as_str().unwrap().parse().unwrap();
            let now = v["now"].as_i64().unwrap();
            let got = IntervalTrigger::new(minutes, now);
            if minutes < 0 {
                assert_eq!(got, Err(IntervalError::Negative), "{v}");
                continue;
            }
            match v.get("error") {
                Some(Value::String(e)) => {
                    assert_eq!(got.unwrap_err().to_string(), *e, "{v}");
                }
                _ => {
                    let t = got.unwrap();
                    assert_eq!(t.start, v["start"].as_i64().unwrap(), "{v}");
                    assert_eq!(
                        t.interval.to_string(),
                        v["interval_us"].as_str().unwrap(),
                        "{v}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_resume_lands_on_the_original_grid() {
        let t = trigger(1_800_000_000_000_000, 5);
        // Resumed 12 minutes after the start: the 15-minute grid point.
        assert_eq!(
            t.next_fire(None, 1_800_000_000_000_000 + 12 * 60_000_000),
            Some(1_800_000_000_000_000 + 15 * 60_000_000)
        );
    }

    #[test]
    fn misfire_grace_is_one_second() {
        assert!(!missed(0, 1_000_000));
        assert!(missed(0, 1_000_001));
    }
}
