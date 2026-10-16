//! SLA notices: which clocks have just turned at risk or breached, and must
//! say so once — port of `soc_management/domain/notices.py`.
//!
//! Four write-once stamps per tracking row (`{ack,resolve}_{at_risk,
//! breached}_notified_at`) remember what was told. A breach also settles the
//! at-risk notice; a breach older than [`STALE_AFTER`] when first noticed is
//! stamped without a message; a paused clock is owed nothing.

use chrono::{Duration, NaiveDateTime};
use copilot_sla::evaluate::SlaState;

use crate::domain::analytics::ItemFact;

/// `STALE_AFTER`: a breach older than this when first noticed is stamped
/// silently.
pub fn stale_after() -> Duration {
    Duration::hours(24)
}

/// `NoticeKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    /// Entered its last quarter.
    AtRisk,
    /// Ran out.
    Breached,
}

impl NoticeKind {
    /// Wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AtRisk => "at_risk",
            Self::Breached => "breached",
        }
    }
}

/// `SlaClock`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaClock {
    /// The acknowledge clock.
    Ack,
    /// The resolve clock.
    Resolve,
}

impl SlaClock {
    /// Wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ack => "ack",
            Self::Resolve => "resolve",
        }
    }

    /// `label`: the word used in messages.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ack => "acknowledge",
            Self::Resolve => "resolve",
        }
    }
}

/// `stamp_column(clock, kind)`.
pub const fn stamp_column(clock: SlaClock, kind: NoticeKind) -> &'static str {
    match (clock, kind) {
        (SlaClock::Ack, NoticeKind::AtRisk) => "ack_at_risk_notified_at",
        (SlaClock::Ack, NoticeKind::Breached) => "ack_breached_notified_at",
        (SlaClock::Resolve, NoticeKind::AtRisk) => "resolve_at_risk_notified_at",
        (SlaClock::Resolve, NoticeKind::Breached) => "resolve_breached_notified_at",
    }
}

/// `STAMP_COLUMNS`, in Python's order.
pub const STAMP_COLUMNS: [&str; 4] = [
    "ack_at_risk_notified_at",
    "ack_breached_notified_at",
    "resolve_at_risk_notified_at",
    "resolve_breached_notified_at",
];

/// The stamps of one tracking row, in [`STAMP_COLUMNS`] order.
pub type Stamps = [Option<NaiveDateTime>; 4];

fn stamp(stamps: &Stamps, column: &str) -> Option<NaiveDateTime> {
    STAMP_COLUMNS
        .iter()
        .position(|c| *c == column)
        .and_then(|i| stamps[i])
}

/// `Notice`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notice {
    /// Which clock.
    pub clock: SlaClock,
    /// At risk or breached.
    pub kind: NoticeKind,
    /// The clock's due time.
    pub due_at: NaiveDateTime,
    /// Stamp it but send nothing.
    pub silent: bool,
}

impl Notice {
    /// `column`: the stamp that claims it.
    pub const fn column(&self) -> &'static str {
        stamp_column(self.clock, self.kind)
    }

    /// `settles`: further stamps this notice makes moot.
    pub fn settles(&self) -> Option<&'static str> {
        (self.kind == NoticeKind::Breached).then(|| stamp_column(self.clock, NoticeKind::AtRisk))
    }
}

/// `notices_for(fact, stamps, now)`.
pub fn notices_for(fact: &ItemFact<'_>, stamps: &Stamps, now: NaiveDateTime) -> Vec<Notice> {
    if !fact.tracked || !fact.is_open() {
        return Vec::new();
    }
    let mut running: Vec<(SlaClock, Option<NaiveDateTime>, SlaState)> = Vec::new();
    if fact.ack_achieved_at().is_none() {
        running.push((SlaClock::Ack, fact.ack_due_at, fact.ack_state(now)));
    }
    if fact.resolved_at.is_none() {
        running.push((
            SlaClock::Resolve,
            fact.resolve_due_at,
            fact.resolve_state(now),
        ));
    }
    let mut owed = Vec::new();
    for (clock, due_at, state) in running {
        let Some(due_at) = due_at else {
            continue;
        };
        if state == SlaState::Breached
            && stamp(stamps, stamp_column(clock, NoticeKind::Breached)).is_none()
        {
            owed.push(Notice {
                clock,
                kind: NoticeKind::Breached,
                due_at,
                silent: now - due_at > stale_after(),
            });
        } else if state == SlaState::AtRisk
            && stamp(stamps, stamp_column(clock, NoticeKind::AtRisk)).is_none()
        {
            owed.push(Notice {
                clock,
                kind: NoticeKind::AtRisk,
                due_at,
                silent: false,
            });
        }
    }
    owed
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_sla::calendar::Clock;
    use copilot_sla::policy::SlaEntity;

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    fn fact() -> ItemFact<'static> {
        ItemFact {
            entity: SlaEntity::Alert,
            id: 1,
            title: "t".into(),
            customer_code: Some("acme".into()),
            severity: "High".into(),
            status: "OPEN".into(),
            assigned_to: None,
            opened_at: at("2026-01-01 10:00:00"),
            tracked: true,
            ack_due_at: Some(at("2026-01-01 11:00:00")),
            resolve_due_at: Some(at("2026-01-01 18:00:00")),
            first_ack_at: None,
            first_ack_by: None,
            resolved_at: None,
            resolved_by: None,
            reopen_count: 0,
            paused_at: None,
            paused_seconds: 0,
            clock: Clock::Continuous,
            source: None,
            verdict: None,
            in_case: false,
            escalated: false,
        }
    }

    #[test]
    fn once_per_clock_and_state() {
        let f = fact();
        let none: Stamps = [None; 4];
        let n = notices_for(&f, &none, at("2026-01-01 10:50:00"));
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].column(), "ack_at_risk_notified_at");
        let told: Stamps = [Some(at("2026-01-01 10:50:00")), None, None, None];
        assert!(notices_for(&f, &told, at("2026-01-01 10:55:00")).is_empty());
        let n = notices_for(&f, &told, at("2026-01-01 11:30:00"));
        assert_eq!(n[0].kind, NoticeKind::Breached);
        assert_eq!(n[0].settles(), Some("ack_at_risk_notified_at"));
        assert!(!n[0].silent);
        let n = notices_for(&f, &none, at("2026-01-02 11:00:01"));
        assert!(n[0].silent, "a day-old breach is stamped silently");
        assert_eq!(n[1].clock, SlaClock::Resolve);
        let mut closed = fact();
        closed.status = "CLOSED".into();
        assert!(notices_for(&closed, &none, at("2026-01-02 11:00:00")).is_empty());
        let mut paused = fact();
        paused.paused_at = Some(at("2026-01-01 10:30:00"));
        assert!(notices_for(&paused, &none, at("2026-01-01 10:50:00")).is_empty());
    }
}
