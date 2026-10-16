//! Pure rules, no I/O — ports of `soc_management/domain/` (periods, duration
//! statistics, the analytics behind every figure). SLA
//! evaluation, policy resolution, calendars and lifecycle milestones live in
//! `copilot-sla`, shared with the incidents recorder.

pub mod analytics;
pub mod periods;
pub mod stats;
