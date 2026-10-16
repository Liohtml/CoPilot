//! Evaluating one SLA clock, and summarising many into compliance — port of
//! `soc_management/domain/sla.py`.
//!
//! A clock is `(opened_at, due_at, achieved_at)` read against `now`:
//!
//! - no `due_at`                          → [`SlaState::NotTracked`]
//! - achieved on or before due            → [`SlaState::Met`]
//! - achieved after due                   → [`SlaState::Breached`]
//! - not achieved, waiting on the customer → [`SlaState::Paused`] (or
//!   breached, when it was already late when it stopped)
//! - not achieved, already past due       → [`SlaState::Breached`]
//! - not achieved, in the last quarter of its window (on the clock's own
//!   basis) → [`SlaState::AtRisk`]
//! - otherwise                            → [`SlaState::OnTrack`]
//!
//! **Compliance is met ÷ (met + breached)**: items still on track have no
//! outcome yet and stay out of both sides.

use chrono::NaiveDateTime;
use copilot_core::time::py_round;

use crate::calendar::{Clock, total_seconds};

/// `AT_RISK_FRACTION`: the share of a clock's window left at which an open
/// item turns at risk.
pub const AT_RISK_FRACTION: f64 = 0.25;

/// `SlaState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlaState {
    /// Achieved on time.
    Met,
    /// Late (achieved late, or past due and still running).
    Breached,
    /// In the last quarter of its window.
    AtRisk,
    /// Running, with time to spare.
    OnTrack,
    /// Stopped while waiting on the customer.
    Paused,
    /// No promise for this clock.
    NotTracked,
}

impl SlaState {
    /// Every value, in the Python enum's order.
    pub const ALL: [Self; 6] = [
        Self::Met,
        Self::Breached,
        Self::AtRisk,
        Self::OnTrack,
        Self::Paused,
        Self::NotTracked,
    ];

    /// Wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Met => "met",
            Self::Breached => "breached",
            Self::AtRisk => "at_risk",
            Self::OnTrack => "on_track",
            Self::Paused => "paused",
            Self::NotTracked => "not_tracked",
        }
    }

    /// The enum for a wire value (exact, like `SlaState(value)`).
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == value)
    }
}

/// `evaluate(opened_at, due_at, achieved_at, now, clock, paused_at)`.
pub fn evaluate(
    opened_at: NaiveDateTime,
    due_at: Option<NaiveDateTime>,
    achieved_at: Option<NaiveDateTime>,
    now: NaiveDateTime,
    clock: Clock<'_>,
    paused_at: Option<NaiveDateTime>,
) -> SlaState {
    let Some(due_at) = due_at else {
        return SlaState::NotTracked;
    };
    if let Some(achieved) = achieved_at {
        return if achieved <= due_at {
            SlaState::Met
        } else {
            SlaState::Breached
        };
    }
    if let Some(paused) = paused_at {
        // Stopped: judged as of the moment it stopped.
        return if paused > due_at {
            SlaState::Breached
        } else {
            SlaState::Paused
        };
    }
    if now > due_at {
        return SlaState::Breached;
    }
    let window = clock.elapsed(opened_at, due_at);
    let remaining = clock.elapsed(now, due_at);
    if window > 0.0 && remaining <= window * AT_RISK_FRACTION {
        return SlaState::AtRisk;
    }
    SlaState::OnTrack
}

/// `overdue_seconds(due_at, achieved_at, now)`: how far past due the clock is
/// (or was, when achieved late); `None` when not late.
pub fn overdue_seconds(
    due_at: Option<NaiveDateTime>,
    achieved_at: Option<NaiveDateTime>,
    now: NaiveDateTime,
) -> Option<f64> {
    let due_at = due_at?;
    let late = total_seconds(due_at, achieved_at.unwrap_or(now));
    (late > 0.0).then_some(late)
}

/// `Compliance`: counts per state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Compliance {
    /// Met.
    pub met: i64,
    /// Breached.
    pub breached: i64,
    /// At risk.
    pub at_risk: i64,
    /// On track.
    pub on_track: i64,
    /// Paused.
    pub paused: i64,
    /// Not tracked.
    pub not_tracked: i64,
}

impl Compliance {
    /// `decided`: met + breached.
    pub fn decided(&self) -> i64 {
        self.met + self.breached
    }

    /// `rate`: percentage met, one decimal; `None` when nothing is decided.
    pub fn rate(&self) -> Option<f64> {
        let decided = self.decided();
        if decided == 0 {
            return None;
        }
        Some(py_round(self.met as f64 * 100.0 / decided as f64, 1))
    }
}

/// `summarize(states)`.
pub fn summarize(states: impl IntoIterator<Item = SlaState>) -> Compliance {
    let mut c = Compliance::default();
    for state in states {
        match state {
            SlaState::Met => c.met += 1,
            SlaState::Breached => c.breached += 1,
            SlaState::AtRisk => c.at_risk += 1,
            SlaState::OnTrack => c.on_track += 1,
            SlaState::Paused => c.paused += 1,
            SlaState::NotTracked => c.not_tracked += 1,
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::BusinessCalendar;

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    #[test]
    fn states_follow_the_python_table() {
        let c = Clock::Continuous;
        let opened = at("2026-01-01 10:00:00");
        let due = Some(at("2026-01-01 11:00:00"));
        let e = |achieved, now, paused| evaluate(opened, due, achieved, at(now), c, paused);
        assert_eq!(
            evaluate(opened, None, None, opened, c, None),
            SlaState::NotTracked
        );
        assert_eq!(
            e(Some(at("2026-01-01 11:00:00")), "2026-01-02 00:00:00", None),
            SlaState::Met
        );
        assert_eq!(
            e(Some(at("2026-01-01 11:00:01")), "2026-01-01 10:00:00", None),
            SlaState::Breached
        );
        assert_eq!(
            e(None, "2026-01-01 12:00:00", Some(at("2026-01-01 10:30:00"))),
            SlaState::Paused
        );
        assert_eq!(
            e(None, "2026-01-01 12:00:00", Some(at("2026-01-01 11:30:00"))),
            SlaState::Breached
        );
        assert_eq!(e(None, "2026-01-01 11:00:01", None), SlaState::Breached);
        assert_eq!(e(None, "2026-01-01 10:45:00", None), SlaState::AtRisk);
        assert_eq!(e(None, "2026-01-01 10:44:59", None), SlaState::OnTrack);
    }

    #[test]
    fn business_hours_risk_is_measured_in_working_time() {
        let cal = BusinessCalendar::office_hours("UTC").unwrap();
        let clock = Clock::Business(&cal);
        // Opened Friday 16:00, 4 business hours → due Monday 12:00.
        let opened = at("2026-01-02 16:00:00");
        let due = Some(at("2026-01-05 12:00:00"));
        // All weekend there are 3 working hours left of 4: on track.
        assert_eq!(
            evaluate(opened, due, None, at("2026-01-03 12:00:00"), clock, None),
            SlaState::OnTrack
        );
        assert_eq!(
            evaluate(opened, due, None, at("2026-01-05 11:00:00"), clock, None),
            SlaState::AtRisk
        );
    }

    #[test]
    fn compliance_rate() {
        use SlaState::*;
        let c = summarize([Met, Met, Breached, OnTrack, AtRisk, Paused, NotTracked]);
        assert_eq!(c.decided(), 3);
        assert_eq!(c.rate(), Some(66.7));
        assert_eq!(summarize([OnTrack]).rate(), None);
        assert_eq!(summarize([Met]).rate(), Some(100.0));
        assert_eq!(
            overdue_seconds(
                Some(at("2026-01-01 10:00:00")),
                None,
                at("2026-01-01 10:01:00")
            ),
            Some(60.0)
        );
        assert_eq!(
            overdue_seconds(
                Some(at("2026-01-01 10:00:00")),
                None,
                at("2026-01-01 09:00:00")
            ),
            None
        );
    }
}
