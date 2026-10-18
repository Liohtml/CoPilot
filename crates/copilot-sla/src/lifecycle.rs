//! Lifecycle milestones — port of `soc_management/domain/lifecycle.py`.
//!
//! Acknowledgement is the first SOC action; a customer or automation never
//! acknowledges. Every milestone is one guarded `UPDATE … WHERE <column> IS
//! [NOT] NULL`, so two analysts acting at once can never both be first.
//! `PENDING_CUSTOMER` pauses the clocks; any later status change resumes
//! them, pushing running targets back by the pause measured on their basis.

use chrono::NaiveDateTime;

use crate::SlaError;
use crate::calendar::{Clock, total_seconds};
use crate::policy::SlaTargets;

/// `CLOSED`.
pub const CLOSED: &str = "CLOSED";
/// `PENDING_CUSTOMER`.
pub const PENDING_CUSTOMER: &str = "PENDING_CUSTOMER";

/// `LifecycleAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleAction {
    /// The item was created (by a person, for the acknowledgement).
    Created,
    /// Assigned.
    Assigned,
    /// Status changed.
    StatusChanged,
    /// Commented.
    Commented,
    /// Verdict set or cleared.
    VerdictSet,
    /// Escalated.
    Escalated,
    /// Linked to a case.
    LinkedToCase,
    /// A case's severity changed.
    SeverityChanged,
}

impl LifecycleAction {
    /// Wire value (`first_ack_action`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Assigned => "assigned",
            Self::StatusChanged => "status_changed",
            Self::Commented => "commented",
            Self::VerdictSet => "verdict_set",
            Self::Escalated => "escalated",
            Self::LinkedToCase => "linked_to_case",
            Self::SeverityChanged => "severity_changed",
        }
    }
}

/// `SOC_ROLE_IDS`: admin and analyst. A responder's role id (5) is *not*
/// in it, exactly as in the Python recorder.
pub const SOC_ROLE_IDS: [i32; 2] = [1, 2];

/// `Actor`: who acted (`username` `None` is automation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    /// User name.
    pub username: Option<String>,
    /// The SOC (admin/analyst) acted.
    pub is_soc: bool,
}

impl Actor {
    /// `Actor.from_user(user)`.
    pub fn from_user(username: &str, role_id: i32) -> Self {
        Self {
            username: Some(username.to_string()),
            is_soc: SOC_ROLE_IDS.contains(&role_id),
        }
    }

    /// `Actor.system()`.
    pub fn system() -> Self {
        Self {
            username: None,
            is_soc: false,
        }
    }
}

/// `LifecycleEvent`.
#[derive(Debug, Clone)]
pub struct LifecycleEvent<'a> {
    /// What happened.
    pub action: LifecycleAction,
    /// Who did it.
    pub actor: &'a Actor,
    /// When (naive UTC, microseconds).
    pub at: NaiveDateTime,
    /// New status, for `StatusChanged`.
    pub to_status: Option<&'a str>,
    /// New assignee, for `Assigned`.
    pub assignee: Option<&'a str>,
}

/// A value one milestone writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Set {
    /// A timestamp column.
    Time(Option<NaiveDateTime>),
    /// A text column.
    Text(Option<String>),
    /// `column + 1` (the reopen counter).
    Increment,
}

/// `GuardedUpdate`: set `values` only where `guard_column` is (not) NULL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedUpdate {
    /// Columns and values.
    pub values: Vec<(&'static str, Set)>,
    /// The guard column.
    pub guard_column: &'static str,
    /// `IS NULL` (else `IS NOT NULL`).
    pub guard_is_null: bool,
}

/// `acknowledges(event)`: every action of the SOC.
pub fn acknowledges(event: &LifecycleEvent<'_>) -> bool {
    event.actor.is_soc
}

/// `resumes(event)`: a status change to anything but `PENDING_CUSTOMER`.
pub fn resumes(event: &LifecycleEvent<'_>) -> bool {
    event.action == LifecycleAction::StatusChanged
        && event
            .to_status
            .is_some_and(|s| !s.is_empty() && s != PENDING_CUSTOMER)
}

/// `plan_milestones(event)`: the guarded writes, in order.
pub fn plan_milestones(event: &LifecycleEvent<'_>) -> Vec<GuardedUpdate> {
    let mut plan = Vec::new();
    let at = Some(event.at);
    if acknowledges(event) {
        plan.push(GuardedUpdate {
            values: vec![
                ("first_ack_at", Set::Time(at)),
                ("first_ack_by", Set::Text(event.actor.username.clone())),
                (
                    "first_ack_action",
                    Set::Text(Some(event.action.as_str().to_string())),
                ),
            ],
            guard_column: "first_ack_at",
            guard_is_null: true,
        });
    }
    if event.action == LifecycleAction::Assigned && event.assignee.is_some_and(|a| !a.is_empty()) {
        plan.push(GuardedUpdate {
            values: vec![("first_assigned_at", Set::Time(at))],
            guard_column: "first_assigned_at",
            guard_is_null: true,
        });
    }
    if event.action == LifecycleAction::StatusChanged {
        if let Some(to) = event.to_status.filter(|s| !s.is_empty()) {
            if to == CLOSED {
                plan.push(GuardedUpdate {
                    values: vec![
                        ("resolved_at", Set::Time(at)),
                        ("resolved_by", Set::Text(event.actor.username.clone())),
                    ],
                    guard_column: "resolved_at",
                    guard_is_null: true,
                });
                plan.push(GuardedUpdate {
                    values: vec![("first_resolved_at", Set::Time(at))],
                    guard_column: "first_resolved_at",
                    guard_is_null: true,
                });
            } else {
                plan.push(GuardedUpdate {
                    values: vec![
                        ("resolved_at", Set::Time(None)),
                        ("resolved_by", Set::Text(None)),
                        ("reopen_count", Set::Increment),
                    ],
                    guard_column: "resolved_at",
                    guard_is_null: false,
                });
            }
            if to == PENDING_CUSTOMER {
                plan.push(GuardedUpdate {
                    values: vec![("paused_at", Set::Time(at))],
                    guard_column: "paused_at",
                    guard_is_null: true,
                });
            }
        }
    }
    plan
}

/// What ending a pause writes (`resume_values`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resume {
    /// `paused_seconds` after the pause.
    pub paused_seconds: i64,
    /// `pause_credit_seconds` after the pause.
    pub pause_credit_seconds: i64,
    /// New acknowledge due time, when that clock runs.
    pub ack_due_at: Option<NaiveDateTime>,
    /// New resolve due time, when that clock runs.
    pub resolve_due_at: Option<NaiveDateTime>,
}

/// The tracking state `resume_values` reads.
#[derive(Debug, Clone, Copy)]
pub struct PauseState {
    /// When the pause began.
    pub paused_at: NaiveDateTime,
    /// Current acknowledge due time.
    pub ack_due_at: Option<NaiveDateTime>,
    /// The acknowledge clock still runs.
    pub ack_running: bool,
    /// Current resolve due time.
    pub resolve_due_at: Option<NaiveDateTime>,
    /// The resolve clock still runs.
    pub resolve_running: bool,
    /// Banked wall-clock pause seconds.
    pub paused_seconds: i64,
    /// Banked basis pause seconds.
    pub pause_credit_seconds: i64,
}

/// `resume_values`.
pub fn resume_values(
    state: PauseState,
    resumed_at: NaiveDateTime,
    clock: Clock<'_>,
) -> Result<Resume, SlaError> {
    let credit = clock.elapsed(state.paused_at, resumed_at);
    let wall = total_seconds(state.paused_at, resumed_at).trunc() as i64;
    let mut out = Resume {
        paused_seconds: state.paused_seconds + wall.max(0),
        pause_credit_seconds: state.pause_credit_seconds + credit.trunc() as i64,
        ack_due_at: None,
        resolve_due_at: None,
    };
    if state.ack_running {
        if let Some(due) = state.ack_due_at {
            out.ack_due_at = Some(clock.add(due, credit)?);
        }
    }
    if state.resolve_running {
        if let Some(due) = state.resolve_due_at {
            out.resolve_due_at = Some(clock.add(due, credit)?);
        }
    }
    Ok(out)
}

/// `retarget_values`: new due times of the clocks still running (`None` in
/// the outer option = that clock is not rewritten).
#[allow(clippy::type_complexity)]
pub fn retarget_values(
    opened_at: NaiveDateTime,
    targets: &SlaTargets,
    ack_running: bool,
    resolve_running: bool,
    clock: Clock<'_>,
    credit_seconds: i64,
) -> Result<(Option<Option<NaiveDateTime>>, Option<Option<NaiveDateTime>>), SlaError> {
    let due = |base: Option<NaiveDateTime>| -> Result<Option<NaiveDateTime>, SlaError> {
        match base {
            Some(b) if credit_seconds != 0 => Ok(Some(clock.add(b, credit_seconds as f64)?)),
            other => Ok(other),
        }
    };
    let ack = if ack_running {
        Some(due(targets.ack_due(opened_at, clock)?)?)
    } else {
        None
    };
    let resolve = if resolve_running {
        Some(due(targets.resolve_due(opened_at, clock)?)?)
    } else {
        None
    };
    Ok((ack, resolve))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    #[test]
    fn soc_closing_acknowledges_and_resolves() {
        let actor = Actor::from_user("al", 2);
        let e = LifecycleEvent {
            action: LifecycleAction::StatusChanged,
            actor: &actor,
            at: at("2026-01-01 10:00:00"),
            to_status: Some(CLOSED),
            assignee: None,
        };
        let plan = plan_milestones(&e);
        let guards: Vec<_> = plan
            .iter()
            .map(|p| (p.guard_column, p.guard_is_null))
            .collect();
        assert_eq!(
            guards,
            vec![
                ("first_ack_at", true),
                ("resolved_at", true),
                ("first_resolved_at", true)
            ]
        );
        assert!(!resumes(&LifecycleEvent {
            to_status: Some(PENDING_CUSTOMER),
            ..e.clone()
        }));
        assert!(resumes(&e));
    }

    #[test]
    fn customers_and_responders_never_acknowledge() {
        for role in [4, 5] {
            let actor = Actor::from_user("x", role);
            let e = LifecycleEvent {
                action: LifecycleAction::StatusChanged,
                actor: &actor,
                at: at("2026-01-01 10:00:00"),
                to_status: Some(PENDING_CUSTOMER),
                assignee: None,
            };
            let guards: Vec<_> = plan_milestones(&e)
                .iter()
                .map(|p| (p.guard_column, p.guard_is_null))
                .collect();
            assert_eq!(guards, vec![("resolved_at", false), ("paused_at", true)]);
        }
    }

    #[test]
    fn resume_extends_running_clocks() {
        let state = PauseState {
            paused_at: at("2026-01-01 10:00:00"),
            ack_due_at: Some(at("2026-01-01 11:00:00")),
            ack_running: false,
            resolve_due_at: Some(at("2026-01-01 18:00:00")),
            resolve_running: true,
            paused_seconds: 5,
            pause_credit_seconds: 7,
        };
        let r = resume_values(state, at("2026-01-01 12:30:00"), Clock::Continuous).unwrap();
        assert_eq!(r.paused_seconds, 5 + 9000);
        assert_eq!(r.pause_credit_seconds, 7 + 9000);
        assert_eq!(r.ack_due_at, None);
        assert_eq!(r.resolve_due_at, Some(at("2026-01-01 20:30:00")));
    }
}
