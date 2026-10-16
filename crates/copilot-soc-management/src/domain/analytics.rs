//! From facts to metrics: every number on the SOC Management dashboard —
//! port of `soc_management/domain/analytics.py`.
//!
//! The services load two kinds of facts per entity and hand them over:
//! **window facts** (items opened *or* resolved in the period and its
//! predecessor) and **open facts** (the backlog). Cohort figures are by
//! `opened_at`; activity figures by when the action happened. Waiting on the
//! customer is not the SOC's time, and only tracked items carry timings.
//!
//! Where Python's result depends on an iteration order (a `Counter`'s tie,
//! a stable sort), the order of the facts as loaded is kept.

use std::collections::{BTreeSet, HashMap, HashSet};

use chrono::NaiveDateTime;
use copilot_core::time::py_round;
use copilot_sla::calendar::{Clock, total_seconds};
use copilot_sla::evaluate::{Compliance, SlaState, evaluate, summarize};
use copilot_sla::lifecycle::CLOSED;
use copilot_sla::policy::{SEVERITIES_DESC, SlaEntity};

use crate::domain::periods::{Bucket, OutOfRange, Period, bucket_starts, floor_to};
use crate::domain::stats::{DurationStats, describe};

/// `TRUE_POSITIVE`.
pub const TRUE_POSITIVE: &str = "TRUE_POSITIVE";
/// `FALSE_POSITIVE`.
pub const FALSE_POSITIVE: &str = "FALSE_POSITIVE";
/// `NOISY_MIN_REVIEWED`.
pub const NOISY_MIN_REVIEWED: usize = 5;
/// `NOISY_FP_RATE`.
pub const NOISY_FP_RATE: f64 = 50.0;

// ── facts ───────────────────────────────────────────────────────────────

/// `ItemFact`: one alert or case with its SLA tracking.
#[derive(Debug, Clone)]
pub struct ItemFact<'a> {
    /// Alert or case.
    pub entity: SlaEntity,
    /// Id.
    pub id: i64,
    /// Alert name / case name (`""` when empty).
    pub title: String,
    /// Tenant.
    pub customer_code: Option<String>,
    /// Severity the targets were computed for.
    pub severity: String,
    /// Status (`""` when empty).
    pub status: String,
    /// Assignee (`None` when empty).
    pub assigned_to: Option<String>,
    /// When the item reached CoPilot.
    pub opened_at: NaiveDateTime,
    /// Observed from its opening.
    pub tracked: bool,
    /// Acknowledge due time.
    pub ack_due_at: Option<NaiveDateTime>,
    /// Resolve due time.
    pub resolve_due_at: Option<NaiveDateTime>,
    /// First SOC response.
    pub first_ack_at: Option<NaiveDateTime>,
    /// Who responded first.
    pub first_ack_by: Option<String>,
    /// Current resolution.
    pub resolved_at: Option<NaiveDateTime>,
    /// Who resolved it.
    pub resolved_by: Option<String>,
    /// How often it was reopened.
    pub reopen_count: i64,
    /// Waiting on the customer since.
    pub paused_at: Option<NaiveDateTime>,
    /// Wall-clock seconds of the pauses that ended.
    pub paused_seconds: i64,
    /// The basis the targets run on.
    pub clock: Clock<'a>,
    /// Alert source.
    pub source: Option<String>,
    /// Alert verdict.
    pub verdict: Option<String>,
    /// The alert is linked to a case.
    pub in_case: bool,
    /// Escalated.
    pub escalated: bool,
}

impl ItemFact<'_> {
    /// `is_open`.
    pub fn is_open(&self) -> bool {
        self.status != CLOSED
    }

    /// `tta`: time to acknowledge.
    pub fn tta(&self) -> Option<f64> {
        if !self.tracked {
            return None;
        }
        self.first_ack_at
            .map(|ack| total_seconds(self.opened_at, ack))
    }

    /// `is_paused`.
    pub fn is_paused(&self) -> bool {
        self.paused_at.is_some()
    }

    /// `ttr`: time to resolve, less the time spent waiting on the customer.
    pub fn ttr(&self) -> Option<f64> {
        if !self.tracked {
            return None;
        }
        self.resolved_at
            .map(|r| total_seconds(self.opened_at, r) - self.paused_seconds as f64)
    }

    /// `ack_achieved_at`: the first response, else the resolution.
    pub fn ack_achieved_at(&self) -> Option<NaiveDateTime> {
        self.first_ack_at.or(self.resolved_at)
    }

    /// `ack_state(now)`.
    pub fn ack_state(&self, now: NaiveDateTime) -> SlaState {
        if !self.tracked {
            return SlaState::NotTracked;
        }
        evaluate(
            self.opened_at,
            self.ack_due_at,
            self.ack_achieved_at(),
            now,
            self.clock,
            self.paused_at,
        )
    }

    /// `resolve_state(now)`.
    pub fn resolve_state(&self, now: NaiveDateTime) -> SlaState {
        if !self.tracked {
            return SlaState::NotTracked;
        }
        evaluate(
            self.opened_at,
            self.resolve_due_at,
            self.resolved_at,
            now,
            self.clock,
            self.paused_at,
        )
    }

    /// `live_state(now)`: the state of the clocks still running.
    pub fn live_state(&self, now: NaiveDateTime) -> SlaState {
        let mut running = Vec::with_capacity(2);
        if self.ack_achieved_at().is_none() {
            running.push(self.ack_state(now));
        }
        if self.resolved_at.is_none() {
            running.push(self.resolve_state(now));
        }
        for state in [
            SlaState::Breached,
            SlaState::AtRisk,
            SlaState::Paused,
            SlaState::OnTrack,
        ] {
            if running.contains(&state) {
                return state;
            }
        }
        SlaState::NotTracked
    }
}

// ── results ─────────────────────────────────────────────────────────────

/// `SlaPair`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SlaPair {
    /// Acknowledge clocks.
    pub ack: Compliance,
    /// Resolve clocks.
    pub resolve: Compliance,
}

/// `EntityHeadline`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct EntityHeadline {
    /// Opened in the period.
    pub opened: i64,
    /// Resolved in the period.
    pub resolved: i64,
    /// Of those, closed by someone outside the SOC.
    pub resolved_by_customer: i64,
    /// Time to acknowledge.
    pub tta: DurationStats,
    /// Time to resolve.
    pub ttr: DurationStats,
    /// Compliance.
    pub sla: SlaPair,
    /// Reopened at least once.
    pub reopened: i64,
}

/// `Headline`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Headline {
    /// Alerts.
    pub alerts: EntityHeadline,
    /// Cases.
    pub cases: EntityHeadline,
    /// Share of reviewed alerts judged false positives.
    pub false_positive_rate: Option<f64>,
    /// Reviewed alerts.
    pub reviewed_alerts: i64,
    /// Share of alerts that ended up in a case.
    pub case_conversion_rate: Option<f64>,
    /// Escalated alerts.
    pub escalated_alerts: i64,
}

/// `SeverityRow`.
#[derive(Debug, Clone, PartialEq)]
pub struct SeverityRow {
    /// Entity.
    pub entity: SlaEntity,
    /// Severity.
    pub severity: &'static str,
    /// Opened in the period.
    pub opened: i64,
    /// Resolved in the period.
    pub resolved: i64,
    /// Open now.
    pub open_now: i64,
    /// Open and past SLA now.
    pub breached_now: i64,
    /// Time to acknowledge.
    pub tta: DurationStats,
    /// Time to resolve.
    pub ttr: DurationStats,
    /// Compliance.
    pub sla: SlaPair,
}

/// `TrendPoint`.
#[derive(Debug, Clone, PartialEq)]
pub struct TrendPoint {
    /// Bucket start.
    pub start: NaiveDateTime,
    /// Alerts opened.
    pub alerts_opened: i64,
    /// Alerts resolved.
    pub alerts_resolved: i64,
    /// Cases opened.
    pub cases_opened: i64,
    /// Cases resolved.
    pub cases_resolved: i64,
    /// Resolve compliance of the items opened in the bucket.
    pub sla_rate: Option<f64>,
    /// Median alert TTR of the bucket.
    pub alert_ttr_median: Option<f64>,
}

/// `AnalystRow`.
#[derive(Debug, Clone, PartialEq)]
pub struct AnalystRow {
    /// User.
    pub username: String,
    /// Alerts acknowledged.
    pub alerts_acknowledged: i64,
    /// Alerts resolved.
    pub alerts_resolved: i64,
    /// Cases acknowledged.
    pub cases_acknowledged: i64,
    /// Cases resolved.
    pub cases_resolved: i64,
    /// Time to acknowledge.
    pub tta: DurationStats,
    /// Time to resolve.
    pub ttr: DurationStats,
    /// Resolve compliance of what they resolved.
    pub sla: Compliance,
    /// Open alerts assigned.
    pub open_alerts: i64,
    /// Open cases assigned.
    pub open_cases: i64,
    /// Of those, at risk.
    pub at_risk: i64,
    /// Of those, breached.
    pub breached: i64,
}

/// `RuleRow`.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleRow {
    /// Alert title.
    pub alert_name: String,
    /// Sources, sorted.
    pub sources: Vec<String>,
    /// Alerts opened.
    pub alerts: i64,
    /// In a case.
    pub in_case: i64,
    /// Reviewed.
    pub reviewed: i64,
    /// True positives.
    pub true_positives: i64,
    /// False positives.
    pub false_positives: i64,
    /// False-positive rate.
    pub false_positive_rate: Option<f64>,
    /// A tuning candidate.
    pub noisy: bool,
    /// Still open.
    pub open_now: i64,
    /// Time to resolve.
    pub ttr: DurationStats,
    /// Resolve compliance.
    pub sla: Compliance,
    /// Alerts opened per trend bucket.
    pub series: Vec<i64>,
}

/// `CustomerRow`.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomerRow {
    /// Customer.
    pub customer_code: String,
    /// Alerts opened.
    pub alerts: i64,
    /// Cases opened.
    pub cases: i64,
    /// Resolved in the period.
    pub resolved: i64,
    /// Open now.
    pub open_now: i64,
    /// Open and past SLA now.
    pub breached_now: i64,
    /// Alert TTR.
    pub alert_ttr: DurationStats,
    /// Case TTR.
    pub case_ttr: DurationStats,
    /// Alert resolve compliance.
    pub alert_sla: Compliance,
    /// Case resolve compliance.
    pub case_sla: Compliance,
    /// Most frequent alert title.
    pub top_rule: Option<String>,
}

/// `SeverityLoad`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeverityLoad {
    /// Severity.
    pub severity: &'static str,
    /// Open alerts.
    pub alerts: i64,
    /// Open cases.
    pub cases: i64,
    /// Breached.
    pub breached: i64,
    /// At risk.
    pub at_risk: i64,
}

/// `AssigneeLoad`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssigneeLoad {
    /// User.
    pub username: String,
    /// Open alerts.
    pub alerts: i64,
    /// Open cases.
    pub cases: i64,
    /// Breached.
    pub breached: i64,
    /// At risk.
    pub at_risk: i64,
}

/// `Workload`.
#[derive(Debug, Clone, PartialEq)]
pub struct Workload {
    /// Open alerts.
    pub open_alerts: i64,
    /// Open cases.
    pub open_cases: i64,
    /// Unassigned open alerts.
    pub unassigned_alerts: i64,
    /// Unassigned open cases.
    pub unassigned_cases: i64,
    /// Open items waiting on the customer.
    pub waiting_on_customer: i64,
    /// Opening time of the oldest unassigned open item.
    pub oldest_unassigned_at: Option<NaiveDateTime>,
    /// Breached.
    pub breached: i64,
    /// At risk.
    pub at_risk: i64,
    /// Per severity.
    pub by_severity: Vec<SeverityLoad>,
    /// Per assignee.
    pub by_assignee: Vec<AssigneeLoad>,
}

/// `AttentionItem`.
#[derive(Debug, Clone, PartialEq)]
pub struct AttentionItem {
    /// Entity.
    pub entity: SlaEntity,
    /// Id.
    pub id: i64,
    /// Title.
    pub title: String,
    /// Tenant.
    pub customer_code: Option<String>,
    /// Severity.
    pub severity: String,
    /// Status.
    pub status: String,
    /// Assignee.
    pub assigned_to: Option<String>,
    /// Opening.
    pub opened_at: NaiveDateTime,
    /// Breached or at risk.
    pub state: SlaState,
    /// `ack` or `resolve`.
    pub clock: &'static str,
    /// Due time of that clock.
    pub due_at: Option<NaiveDateTime>,
    /// Positive when late; negative = seconds still left.
    pub overdue_seconds: f64,
}

// ── helpers ─────────────────────────────────────────────────────────────

fn rate(numerator: i64, denominator: i64) -> Option<f64> {
    (denominator != 0).then(|| py_round(numerator as f64 * 100.0 / denominator as f64, 1))
}

fn count<T>(items: impl IntoIterator<Item = T>, pred: impl Fn(&T) -> bool) -> i64 {
    items.into_iter().filter(|x| pred(x)).count() as i64
}

fn opened_in<'f, 'a>(facts: &'f [ItemFact<'a>], period: &Period) -> Vec<&'f ItemFact<'a>> {
    facts
        .iter()
        .filter(|f| period.contains(f.opened_at))
        .collect()
}

fn resolved_in<'f, 'a>(
    facts: impl IntoIterator<Item = &'f ItemFact<'a>>,
    period: &Period,
) -> Vec<&'f ItemFact<'a>>
where
    'a: 'f,
{
    facts
        .into_iter()
        .filter(|f| f.resolved_at.is_some_and(|r| period.contains(r)))
        .collect()
}

fn sla_pair(facts: &[&ItemFact<'_>], now: NaiveDateTime) -> SlaPair {
    SlaPair {
        ack: summarize(facts.iter().map(|f| f.ack_state(now))),
        resolve: summarize(facts.iter().map(|f| f.resolve_state(now))),
    }
}

/// `_is_breached`: open and overdue on a running clock.
pub fn is_breached(fact: &ItemFact<'_>, now: NaiveDateTime) -> bool {
    fact.is_open() && fact.live_state(now) == SlaState::Breached
}

/// `_is_at_risk`.
pub fn is_at_risk(fact: &ItemFact<'_>, now: NaiveDateTime) -> bool {
    fact.is_open() && fact.live_state(now) == SlaState::AtRisk
}

// ── sections ────────────────────────────────────────────────────────────

/// `entity_headline`.
pub fn entity_headline(
    facts: &[ItemFact<'_>],
    period: &Period,
    now: NaiveDateTime,
    soc_usernames: &HashSet<String>,
) -> EntityHeadline {
    let cohort = opened_in(facts, period);
    let resolved = resolved_in(facts, period);
    EntityHeadline {
        opened: cohort.len() as i64,
        resolved: resolved.len() as i64,
        resolved_by_customer: count(&resolved, |f| {
            f.resolved_by
                .as_deref()
                .is_some_and(|by| !by.is_empty() && !soc_usernames.contains(by))
        }),
        tta: describe(cohort.iter().map(|f| f.tta())),
        ttr: describe(cohort.iter().map(|f| f.ttr())),
        sla: sla_pair(&cohort, now),
        reopened: count(&cohort, |f| f.reopen_count > 0),
    }
}

fn reviewed(verdict: Option<&str>) -> bool {
    matches!(verdict, Some(TRUE_POSITIVE | FALSE_POSITIVE))
}

/// `headline`.
pub fn headline(
    alerts: &[ItemFact<'_>],
    cases: &[ItemFact<'_>],
    period: &Period,
    now: NaiveDateTime,
    soc_usernames: &HashSet<String>,
) -> Headline {
    let cohort = opened_in(alerts, period);
    let reviewed_alerts: Vec<_> = cohort
        .iter()
        .filter(|f| reviewed(f.verdict.as_deref()))
        .collect();
    let false_positives = count(&reviewed_alerts, |f| {
        f.verdict.as_deref() == Some(FALSE_POSITIVE)
    });
    Headline {
        alerts: entity_headline(alerts, period, now, soc_usernames),
        cases: entity_headline(cases, period, now, soc_usernames),
        false_positive_rate: rate(false_positives, reviewed_alerts.len() as i64),
        reviewed_alerts: reviewed_alerts.len() as i64,
        case_conversion_rate: rate(count(&cohort, |f| f.in_case), cohort.len() as i64),
        escalated_alerts: count(&cohort, |f| f.escalated),
    }
}

/// `severity_rows(entity, window, open_now, period, now)`.
pub fn severity_rows(
    entity: SlaEntity,
    window: &[ItemFact<'_>],
    open_now: &[ItemFact<'_>],
    period: &Period,
    now: NaiveDateTime,
) -> Vec<SeverityRow> {
    let cohort = opened_in(window, period);
    let resolved = resolved_in(window, period);
    SEVERITIES_DESC
        .iter()
        .map(|severity| {
            let of_cohort: Vec<&ItemFact<'_>> = cohort
                .iter()
                .copied()
                .filter(|f| f.severity == *severity)
                .collect();
            let of_open: Vec<&ItemFact<'_>> = open_now
                .iter()
                .filter(|f| f.severity == *severity)
                .collect();
            SeverityRow {
                entity,
                severity,
                opened: of_cohort.len() as i64,
                resolved: count(&resolved, |f| f.severity == *severity),
                open_now: of_open.len() as i64,
                breached_now: count(&of_open, |f| is_breached(f, now)),
                tta: describe(of_cohort.iter().map(|f| f.tta())),
                ttr: describe(of_cohort.iter().map(|f| f.ttr())),
                sla: sla_pair(&of_cohort, now),
            }
        })
        .collect()
}

/// `trends(alerts, cases, period, bucket, now)`.
pub fn trends(
    alerts: &[ItemFact<'_>],
    cases: &[ItemFact<'_>],
    period: &Period,
    bucket: Bucket,
    now: NaiveDateTime,
) -> Result<Vec<TrendPoint>, OutOfRange> {
    let starts = bucket_starts(period, bucket)?;
    let index: HashMap<NaiveDateTime, usize> =
        starts.iter().enumerate().map(|(i, s)| (*s, i)).collect();
    let slot = |moment: Option<NaiveDateTime>| -> Result<Option<usize>, OutOfRange> {
        match moment {
            Some(m) if period.contains(m) => Ok(index.get(&floor_to(m, bucket)?).copied()),
            _ => Ok(None),
        }
    };
    let n = starts.len();
    let mut opened = [vec![0i64; n], vec![0i64; n]];
    let mut resolved = [vec![0i64; n], vec![0i64; n]];
    let mut resolve_states: Vec<Vec<SlaState>> = vec![Vec::new(); n];
    let mut alert_ttrs: Vec<Vec<Option<f64>>> = vec![Vec::new(); n];
    for (k, facts) in [alerts, cases].into_iter().enumerate() {
        for fact in facts {
            if let Some(i) = slot(Some(fact.opened_at))? {
                opened[k][i] += 1;
                resolve_states[i].push(fact.resolve_state(now));
                if fact.entity == SlaEntity::Alert {
                    if let Some(ttr) = fact.ttr() {
                        alert_ttrs[i].push(Some(ttr));
                    }
                }
            }
            if let Some(i) = slot(fact.resolved_at)? {
                resolved[k][i] += 1;
            }
        }
    }
    Ok(starts
        .iter()
        .enumerate()
        .map(|(i, start)| TrendPoint {
            start: *start,
            alerts_opened: opened[0][i],
            alerts_resolved: resolved[0][i],
            cases_opened: opened[1][i],
            cases_resolved: resolved[1][i],
            sla_rate: summarize(resolve_states[i].iter().copied()).rate(),
            alert_ttr_median: describe(alert_ttrs[i].iter().copied()).median,
        })
        .collect())
}

/// `analysts(...)`: activity in the period, attributed to whoever performed
/// it (SOC users only), plus their open load.
pub fn analysts(
    alerts: &[ItemFact<'_>],
    cases: &[ItemFact<'_>],
    open_alerts: &[ItemFact<'_>],
    open_cases: &[ItemFact<'_>],
    period: &Period,
    now: NaiveDateTime,
    soc_usernames: &HashSet<String>,
) -> Vec<AnalystRow> {
    let mut acked: HashMap<&str, Vec<&ItemFact<'_>>> = HashMap::new();
    let mut resolved: HashMap<&str, Vec<&ItemFact<'_>>> = HashMap::new();
    for fact in alerts.iter().chain(cases) {
        if let (Some(by), Some(at)) = (fact.first_ack_by.as_deref(), fact.first_ack_at) {
            if soc_usernames.contains(by) && period.contains(at) {
                acked.entry(by).or_default().push(fact);
            }
        }
        if let (Some(by), Some(at)) = (fact.resolved_by.as_deref(), fact.resolved_at) {
            if soc_usernames.contains(by) && period.contains(at) {
                resolved.entry(by).or_default().push(fact);
            }
        }
    }
    let mut load: HashMap<&str, Vec<&ItemFact<'_>>> = HashMap::new();
    for fact in open_alerts.iter().chain(open_cases) {
        if let Some(who) = fact.assigned_to.as_deref() {
            if soc_usernames.contains(who) {
                load.entry(who).or_default().push(fact);
            }
        }
    }
    let users: BTreeSet<&str> = acked
        .keys()
        .chain(resolved.keys())
        .chain(load.keys())
        .copied()
        .collect();
    let empty = Vec::new();
    let mut rows: Vec<AnalystRow> = users
        .into_iter()
        .map(|username| {
            let mine_acked = acked.get(username).unwrap_or(&empty);
            let mine_resolved = resolved.get(username).unwrap_or(&empty);
            let mine_open = load.get(username).unwrap_or(&empty);
            let alerts_of = |v: &Vec<&ItemFact<'_>>| count(v, |f| f.entity == SlaEntity::Alert);
            let cases_of = |v: &Vec<&ItemFact<'_>>| count(v, |f| f.entity == SlaEntity::Case);
            AnalystRow {
                username: username.to_string(),
                alerts_acknowledged: alerts_of(mine_acked),
                alerts_resolved: alerts_of(mine_resolved),
                cases_acknowledged: cases_of(mine_acked),
                cases_resolved: cases_of(mine_resolved),
                tta: describe(mine_acked.iter().map(|f| f.tta())),
                ttr: describe(mine_resolved.iter().map(|f| f.ttr())),
                sla: summarize(mine_resolved.iter().map(|f| f.resolve_state(now))),
                open_alerts: alerts_of(mine_open),
                open_cases: cases_of(mine_open),
                at_risk: count(mine_open, |f| is_at_risk(f, now)),
                breached: count(mine_open, |f| is_breached(f, now)),
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        (b.alerts_resolved + b.cases_resolved)
            .cmp(&(a.alerts_resolved + a.cases_resolved))
            .then((b.open_alerts + b.open_cases).cmp(&(a.open_alerts + a.open_cases)))
            .then(a.username.cmp(&b.username))
    });
    rows
}

/// `rules(alerts, period, bucket, now, limit=25)`: detection rules (alert
/// titles) by volume.
pub fn rules(
    alerts: &[ItemFact<'_>],
    period: &Period,
    bucket: Bucket,
    now: NaiveDateTime,
    limit: usize,
) -> Result<Vec<RuleRow>, OutOfRange> {
    let cohort = opened_in(alerts, period);
    let mut order: Vec<&str> = Vec::new();
    let mut by_name: HashMap<&str, Vec<&ItemFact<'_>>> = HashMap::new();
    for fact in cohort {
        let entry = by_name.entry(fact.title.as_str()).or_insert_with(|| {
            order.push(fact.title.as_str());
            Vec::new()
        });
        entry.push(fact);
    }
    let starts = bucket_starts(period, bucket)?;
    let index: HashMap<NaiveDateTime, usize> =
        starts.iter().enumerate().map(|(i, s)| (*s, i)).collect();
    let mut ranked: Vec<(&str, &Vec<&ItemFact<'_>>)> = order
        .iter()
        .filter_map(|name| by_name.get(name).map(|v| (*name, v)))
        .collect();
    ranked.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
    ranked.truncate(limit);
    let mut rows = Vec::with_capacity(ranked.len());
    for (name, facts) in ranked {
        let reviewed_facts: Vec<_> = facts
            .iter()
            .filter(|f| reviewed(f.verdict.as_deref()))
            .collect();
        let false_positives = count(&reviewed_facts, |f| {
            f.verdict.as_deref() == Some(FALSE_POSITIVE)
        });
        let fp_rate = rate(false_positives, reviewed_facts.len() as i64);
        let mut series = vec![0i64; starts.len()];
        for fact in facts {
            if let Some(i) = index.get(&floor_to(fact.opened_at, bucket)?) {
                series[*i] += 1;
            }
        }
        let sources: BTreeSet<String> = facts
            .iter()
            .filter_map(|f| f.source.clone().filter(|s| !s.is_empty()))
            .collect();
        rows.push(RuleRow {
            alert_name: name.to_string(),
            sources: sources.into_iter().collect(),
            alerts: facts.len() as i64,
            in_case: count(facts, |f| f.in_case),
            reviewed: reviewed_facts.len() as i64,
            true_positives: reviewed_facts.len() as i64 - false_positives,
            false_positives,
            false_positive_rate: fp_rate,
            noisy: reviewed_facts.len() >= NOISY_MIN_REVIEWED
                && fp_rate.is_some_and(|r| r >= NOISY_FP_RATE),
            open_now: count(facts, |f| f.is_open()),
            ttr: describe(facts.iter().map(|f| f.ttr())),
            sla: summarize(facts.iter().map(|f| f.resolve_state(now))),
            series,
        });
    }
    Ok(rows)
}

/// Facts grouped by customer, dropping those without one (`group`).
fn group<'f, 'a>(
    facts: impl IntoIterator<Item = &'f ItemFact<'a>>,
) -> HashMap<&'f str, Vec<&'f ItemFact<'a>>>
where
    'a: 'f,
{
    let mut grouped: HashMap<&str, Vec<&ItemFact<'a>>> = HashMap::new();
    for fact in facts {
        if let Some(code) = fact.customer_code.as_deref().filter(|c| !c.is_empty()) {
            grouped.entry(code).or_default().push(fact);
        }
    }
    grouped
}

/// `Counter(titles).most_common(1)`: the most frequent, the first seen on a
/// tie.
fn most_common(titles: impl IntoIterator<Item = String>) -> Option<String> {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for title in titles {
        match counts.iter_mut().find(|(t, _)| *t == title) {
            Some((_, n)) => *n += 1,
            None => counts.push((title, 1)),
        }
    }
    let mut best: Option<(String, usize)> = None;
    for (title, n) in counts {
        if best.as_ref().is_none_or(|(_, b)| n > *b) {
            best = Some((title, n));
        }
    }
    best.map(|(t, _)| t)
}

/// `customers(...)`: per-tenant figures.
pub fn customers(
    alerts: &[ItemFact<'_>],
    cases: &[ItemFact<'_>],
    open_alerts: &[ItemFact<'_>],
    open_cases: &[ItemFact<'_>],
    period: &Period,
    now: NaiveDateTime,
) -> Vec<CustomerRow> {
    let alert_cohort = opened_in(alerts, period);
    let case_cohort = opened_in(cases, period);
    let resolved = resolved_in(alerts.iter().chain(cases), period);
    let alerts_by = group(alert_cohort);
    let cases_by = group(case_cohort);
    let resolved_by = group(resolved);
    let open_by = group(open_alerts.iter().chain(open_cases));
    let codes: BTreeSet<&str> = alerts_by
        .keys()
        .chain(cases_by.keys())
        .chain(resolved_by.keys())
        .chain(open_by.keys())
        .copied()
        .collect();
    let empty = Vec::new();
    let mut rows: Vec<CustomerRow> = codes
        .into_iter()
        .map(|code| {
            let its_alerts = alerts_by.get(code).unwrap_or(&empty);
            let its_cases = cases_by.get(code).unwrap_or(&empty);
            let its_open = open_by.get(code).unwrap_or(&empty);
            CustomerRow {
                customer_code: code.to_string(),
                alerts: its_alerts.len() as i64,
                cases: its_cases.len() as i64,
                resolved: resolved_by.get(code).map_or(0, |v| v.len() as i64),
                open_now: its_open.len() as i64,
                breached_now: count(its_open, |f| is_breached(f, now)),
                alert_ttr: describe(its_alerts.iter().map(|f| f.ttr())),
                case_ttr: describe(its_cases.iter().map(|f| f.ttr())),
                alert_sla: summarize(its_alerts.iter().map(|f| f.resolve_state(now))),
                case_sla: summarize(its_cases.iter().map(|f| f.resolve_state(now))),
                top_rule: most_common(its_alerts.iter().map(|f| f.title.clone())),
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        (b.alerts + b.cases)
            .cmp(&(a.alerts + a.cases))
            .then(a.customer_code.cmp(&b.customer_code))
    });
    rows
}

/// `workload(open_alerts, open_cases, now)`.
pub fn workload(
    open_alerts: &[ItemFact<'_>],
    open_cases: &[ItemFact<'_>],
    now: NaiveDateTime,
) -> Workload {
    let everything: Vec<&ItemFact<'_>> = open_alerts.iter().chain(open_cases).collect();
    let assigned = |f: &&ItemFact<'_>| f.assigned_to.as_deref().is_some_and(|a| !a.is_empty());
    let by_severity = SEVERITIES_DESC
        .iter()
        .map(|severity| {
            let of: Vec<&&ItemFact<'_>> = everything
                .iter()
                .filter(|f| f.severity == *severity)
                .collect();
            SeverityLoad {
                severity,
                alerts: count(&of, |f| f.entity == SlaEntity::Alert),
                cases: count(&of, |f| f.entity == SlaEntity::Case),
                breached: count(&of, |f| is_breached(f, now)),
                at_risk: count(&of, |f| is_at_risk(f, now)),
            }
        })
        .collect();
    let mut users: Vec<&str> = Vec::new();
    let mut by_user: HashMap<&str, Vec<&ItemFact<'_>>> = HashMap::new();
    for fact in &everything {
        if let Some(who) = fact.assigned_to.as_deref().filter(|a| !a.is_empty()) {
            by_user
                .entry(who)
                .or_insert_with(|| {
                    users.push(who);
                    Vec::new()
                })
                .push(fact);
        }
    }
    let mut by_assignee: Vec<AssigneeLoad> = users
        .iter()
        .map(|who| {
            let facts = &by_user[who];
            AssigneeLoad {
                username: (*who).to_string(),
                alerts: count(facts, |f| f.entity == SlaEntity::Alert),
                cases: count(facts, |f| f.entity == SlaEntity::Case),
                breached: count(facts, |f| is_breached(f, now)),
                at_risk: count(facts, |f| is_at_risk(f, now)),
            }
        })
        .collect();
    by_assignee.sort_by(|a, b| {
        (b.alerts + b.cases)
            .cmp(&(a.alerts + a.cases))
            .then(a.username.cmp(&b.username))
    });
    Workload {
        open_alerts: open_alerts.len() as i64,
        open_cases: open_cases.len() as i64,
        unassigned_alerts: count(open_alerts.iter(), |f| !assigned(f)),
        unassigned_cases: count(open_cases.iter(), |f| !assigned(f)),
        waiting_on_customer: count(&everything, |f| f.is_paused()),
        oldest_unassigned_at: everything
            .iter()
            .filter(|f| !assigned(f))
            .map(|f| f.opened_at)
            .min(),
        breached: count(&everything, |f| is_breached(f, now)),
        at_risk: count(&everything, |f| is_at_risk(f, now)),
        by_severity,
        by_assignee,
    }
}

fn severity_rank(severity: &str) -> usize {
    SEVERITIES_DESC
        .iter()
        .position(|s| *s == severity)
        .unwrap_or(SEVERITIES_DESC.len())
}

/// `_most_urgent`: the most overdue breached running clock, else the
/// at-risk one closest to its due time.
fn most_urgent(
    fact: &ItemFact<'_>,
    now: NaiveDateTime,
) -> Option<(&'static str, SlaState, NaiveDateTime)> {
    let mut running = Vec::with_capacity(2);
    if fact.ack_achieved_at().is_none() {
        if let Some(due) = fact.ack_due_at {
            running.push(("ack", fact.ack_state(now), due));
        }
    }
    if fact.resolved_at.is_none() {
        if let Some(due) = fact.resolve_due_at {
            running.push(("resolve", fact.resolve_state(now), due));
        }
    }
    for wanted in [SlaState::Breached, SlaState::AtRisk] {
        let mut best: Option<(&'static str, SlaState, NaiveDateTime)> = None;
        for clock in running.iter().filter(|c| c.1 == wanted) {
            if best.is_none_or(|b| clock.2 < b.2) {
                best = Some(*clock);
            }
        }
        if best.is_some() {
            return best;
        }
    }
    None
}

/// `attention_items(facts, now, limit)`: breached first (most overdue on
/// top), then at risk (closest to breaching on top).
pub fn attention_items<'f, 'a: 'f>(
    facts: impl IntoIterator<Item = &'f ItemFact<'a>>,
    now: NaiveDateTime,
    limit: usize,
) -> Vec<AttentionItem> {
    let mut items: Vec<AttentionItem> = Vec::new();
    for fact in facts {
        if !fact.is_open() {
            continue;
        }
        let Some((clock, state, due_at)) = most_urgent(fact, now) else {
            continue;
        };
        items.push(AttentionItem {
            entity: fact.entity,
            id: fact.id,
            title: fact.title.clone(),
            customer_code: fact.customer_code.clone(),
            severity: fact.severity.clone(),
            status: fact.status.clone(),
            assigned_to: fact.assigned_to.clone(),
            opened_at: fact.opened_at,
            state,
            clock,
            due_at: Some(due_at),
            overdue_seconds: total_seconds(due_at, now),
        });
    }
    items.sort_by(|a, b| {
        let breached = |i: &AttentionItem| i.state != SlaState::Breached;
        breached(a)
            .cmp(&breached(b))
            .then(
                b.overdue_seconds
                    .partial_cmp(&a.overdue_seconds)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then(severity_rank(&a.severity).cmp(&severity_rank(&b.severity)))
            .then(a.id.cmp(&b.id))
    });
    items.truncate(limit);
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    fn fact(id: i64, title: &str, opened: &str) -> ItemFact<'static> {
        ItemFact {
            entity: SlaEntity::Alert,
            id,
            title: title.into(),
            customer_code: Some("acme".into()),
            severity: "High".into(),
            status: "OPEN".into(),
            assigned_to: None,
            opened_at: at(opened),
            tracked: true,
            ack_due_at: None,
            resolve_due_at: None,
            first_ack_at: None,
            first_ack_by: None,
            resolved_at: None,
            resolved_by: None,
            reopen_count: 0,
            paused_at: None,
            paused_seconds: 0,
            clock: Clock::Continuous,
            source: Some("wazuh".into()),
            verdict: None,
            in_case: false,
            escalated: false,
        }
    }

    #[test]
    fn top_rule_takes_the_first_seen_on_a_tie() {
        assert_eq!(
            most_common(["b", "a", "a", "b", "c"].map(String::from)),
            Some("b".into())
        );
        assert_eq!(most_common(Vec::<String>::new()), None);
    }

    #[test]
    fn live_state_and_attention() {
        let now = at("2026-01-01 12:00:00");
        let mut late = fact(1, "x", "2026-01-01 10:00:00");
        late.ack_due_at = Some(at("2026-01-01 11:00:00"));
        late.resolve_due_at = Some(at("2026-01-01 18:00:00"));
        let mut risky = fact(2, "y", "2026-01-01 08:00:00");
        risky.first_ack_at = Some(at("2026-01-01 08:10:00"));
        risky.resolve_due_at = Some(at("2026-01-01 12:30:00"));
        let mut paused = fact(3, "z", "2026-01-01 08:00:00");
        paused.resolve_due_at = Some(at("2026-01-01 12:30:00"));
        paused.paused_at = Some(at("2026-01-01 09:00:00"));
        assert_eq!(late.live_state(now), SlaState::Breached);
        assert_eq!(risky.live_state(now), SlaState::AtRisk);
        assert_eq!(paused.live_state(now), SlaState::Paused);
        let items = attention_items([&risky, &late, &paused], now, 10);
        let ids: Vec<_> = items.iter().map(|i| (i.id, i.clock)).collect();
        assert_eq!(ids, vec![(1, "ack"), (2, "resolve")]);
        assert_eq!(items[0].overdue_seconds, 3600.0);
        assert_eq!(items[1].overdue_seconds, -1800.0);
    }

    #[test]
    fn rules_rank_by_volume_then_name() {
        let p = Period::new(at("2026-01-01 00:00:00"), at("2026-01-03 00:00:00")).unwrap();
        let mut facts = vec![
            fact(1, "b", "2026-01-01 01:00:00"),
            fact(2, "a", "2026-01-01 02:00:00"),
            fact(3, "b", "2026-01-02 03:00:00"),
            fact(4, "c", "2026-01-02 04:00:00"),
        ];
        facts[0].verdict = Some(FALSE_POSITIVE.into());
        let rows = rules(&facts, &p, Bucket::Day, at("2026-01-03 00:00:00"), 2).unwrap();
        let names: Vec<_> = rows.iter().map(|r| r.alert_name.as_str()).collect();
        assert_eq!(names, vec!["b", "a"]);
        assert_eq!(rows[0].series, vec![1, 1]);
        assert_eq!(rows[0].false_positive_rate, Some(100.0));
        assert!(!rows[0].noisy);
    }
}
