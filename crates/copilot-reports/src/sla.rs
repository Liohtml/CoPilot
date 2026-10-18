//! The SLA figures of the PDF reports: `soc_management/services/formatting.py`
//! (human-readable durations, rates, deltas) and the dictionaries
//! `soc_management/services/report.py` builds from a `Snapshot`
//! (`_compliance`, `severity_table`, `_entity_summary`,
//! `customer_sla_context`).

use chrono::NaiveDateTime;
use copilot_jinja::Data;
use copilot_sla::evaluate::Compliance;
use copilot_sla::policy::SlaEntity;
use copilot_soc_management::domain::analytics::EntityHeadline;
use copilot_soc_management::domain::periods::Period;
use copilot_soc_management::schema::metrics::Viewer;
use copilot_soc_management::services::datasets::Visibility;
use copilot_soc_management::services::metrics::{self, DashboardQuery, Snapshot};
use copilot_web::{ApiError, AppContext};

/// `RATE_GOOD`.
pub const RATE_GOOD: f64 = 95.0;
/// `RATE_WARN`.
pub const RATE_WARN: f64 = 85.0;
/// `EMPTY`.
pub const EMPTY: &str = "\u{2014}";

/// A dict of the template context.
pub fn dict(items: Vec<(&str, Data)>) -> Data {
    Data::Dict(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// A `str`.
pub fn s(v: impl Into<String>) -> Data {
    Data::Str(v.into())
}

/// An `int`.
pub fn int(v: i64) -> Data {
    Data::Int(i128::from(v))
}

/// An `Optional[str]`.
pub fn opt_s(v: Option<&str>) -> Data {
    v.map_or(Data::None, |v| Data::Str(v.to_string()))
}

/// `format(x, spec)` of a `float` (`.1f`, `.0f`, `.3g`).
pub fn pyfmt(x: f64, spec: &str) -> String {
    copilot_jinja::format_float(x, spec).unwrap_or_default()
}

/// `duration(seconds)`: `45s` · `12m` · `1h 20m` · `2d 4h`.
pub fn duration(seconds: Option<f64>) -> String {
    let Some(seconds) = seconds else {
        return EMPTY.into();
    };
    let total = seconds.round_ties_even() as i64;
    if total < 60 {
        return format!("{total}s");
    }
    let minutes = total.div_euclid(60);
    if minutes < 60 {
        return format!("{minutes}m");
    }
    let (hours, minutes) = (minutes.div_euclid(60), minutes.rem_euclid(60));
    if hours < 24 {
        return if minutes != 0 {
            format!("{hours}h {minutes:02}m")
        } else {
            format!("{hours}h")
        };
    }
    let (days, hours) = (hours.div_euclid(24), hours.rem_euclid(24));
    if hours != 0 {
        format!("{days}d {hours}h")
    } else {
        format!("{days}d")
    }
}

/// `target(minutes)`.
pub fn target(minutes: Option<i64>) -> String {
    match minutes {
        Some(m) => duration(Some((m * 60) as f64)),
        None => "no target".into(),
    }
}

/// `rate(value)`.
pub fn rate(value: Option<f64>) -> String {
    match value {
        Some(v) => format!("{}%", pyfmt(v, ".1f")),
        None => "n/a".into(),
    }
}

/// `rate_class(value)`.
pub fn rate_class(value: Option<f64>) -> &'static str {
    match value {
        None => "dim",
        Some(v) if v >= RATE_GOOD => "rate-good",
        Some(v) if v >= RATE_WARN => "rate-warn",
        Some(_) => "rate-bad",
    }
}

/// `delta(current, previous)`: `+12%`, `−4%`, `new`, `±0%`, or empty.
pub fn delta(current: f64, previous: f64) -> String {
    if previous == 0.0 {
        return if current != 0.0 {
            "new".into()
        } else {
            String::new()
        };
    }
    let change = (current - previous) * 100.0 / previous;
    if change.abs() < 0.5 {
        return "\u{b1}0%".into();
    }
    let sign = if change > 0.0 { "+" } else { "\u{2212}" };
    format!("{sign}{}%", pyfmt(change.abs(), ".0f"))
}

/// `_compliance(compliance)`.
pub fn compliance(c: &Compliance) -> Data {
    let r = c.rate();
    dict(vec![
        ("rate", s(rate(r))),
        ("cls", s(rate_class(r))),
        ("width", r.map_or(Data::Int(0), Data::Float)),
        ("met", int(c.met)),
        ("breached", int(c.breached)),
    ])
}

/// `severity_table(snapshot, entity)`.
pub fn severity_table(snapshot: &Snapshot, entity: SlaEntity) -> Data {
    let mut rows = Vec::new();
    for row in &snapshot.severities {
        if row.entity != entity {
            continue;
        }
        let cell = snapshot
            .policy
            .cells
            .iter()
            .rev()
            .find(|c| c.entity == entity.as_str() && c.severity == row.severity);
        let (ack_target, resolve_target) = match cell {
            Some(c) => (target(c.ack_minutes), target(c.resolve_minutes)),
            None => (EMPTY.to_string(), EMPTY.to_string()),
        };
        rows.push(dict(vec![
            ("severity", s(row.severity)),
            ("opened", int(row.opened)),
            ("resolved", int(row.resolved)),
            ("open_now", int(row.open_now)),
            ("breached_now", int(row.breached_now)),
            ("ack_target", s(ack_target)),
            ("resolve_target", s(resolve_target)),
            ("tta", s(duration(row.tta.median))),
            ("ttr", s(duration(row.ttr.median))),
            ("ack", compliance(&row.sla.ack)),
            ("resolve", compliance(&row.sla.resolve)),
            ("empty", Data::Bool(row.opened == 0 && row.open_now == 0)),
        ]));
    }
    Data::List(rows)
}

/// `_entity_summary(headline, previous)`.
pub fn entity_summary(h: &EntityHeadline, previous: &EntityHeadline) -> Data {
    dict(vec![
        ("opened", int(h.opened)),
        (
            "opened_delta",
            s(delta(h.opened as f64, previous.opened as f64)),
        ),
        ("resolved", int(h.resolved)),
        ("tta_median", s(duration(h.tta.median))),
        ("tta_mean", s(duration(h.tta.mean))),
        ("tta_p90", s(duration(h.tta.p90))),
        ("ttr_median", s(duration(h.ttr.median))),
        ("ttr_mean", s(duration(h.ttr.mean))),
        ("ttr_p90", s(duration(h.ttr.p90))),
        ("ack", compliance(&h.sla.ack)),
        ("resolve", compliance(&h.sla.resolve)),
        ("breaches", int(h.sla.ack.breached + h.sla.resolve.breached)),
        ("reopened", int(h.reopened)),
    ])
}

/// `tracking_since.strftime("%Y-%m-%d")` or `None`.
pub fn tracking_since(t: Option<NaiveDateTime>) -> Data {
    t.map_or(Data::None, |t| s(t.format("%Y-%m-%d").to_string()))
}

/// `customer_visibility(code)`: exactly that customer's alerts and cases.
pub fn customer_visibility(code: &str) -> Visibility {
    Visibility {
        alerts: Some(copilot_db::visibility::AlertVisibility {
            customers: Some(vec![code.to_string()]),
            tags: copilot_auth::tags::TagScope::All,
        }),
        alert_codes: None,
        case_codes: Some(vec![code.to_string()]),
    }
}

/// `customer_sla_context(session, customer_code, date_from, date_to)`.
pub async fn customer_sla_context(
    ctx: &AppContext,
    code: &str,
    date_from: NaiveDateTime,
    date_to: NaiveDateTime,
) -> Result<Data, ApiError> {
    let query = DashboardQuery {
        period: Period {
            start: date_from,
            end: date_to,
        },
        customer_codes: Some(vec![code.to_string()]),
        filters: Default::default(),
        bucket: None,
    };
    let viewer = Viewer {
        username: String::new(),
        is_admin: false,
        sees_all_analysts: false,
    };
    let snapshot =
        metrics::compute_snapshot(ctx, &query, viewer, &customer_visibility(code), 0).await?;
    let (head, prev) = (&snapshot.headline, &snapshot.previous_headline);
    Ok(dict(vec![
        ("tracking_since", tracking_since(snapshot.tracking_since)),
        ("alerts", entity_summary(&head.alerts, &prev.alerts)),
        ("cases", entity_summary(&head.cases, &prev.cases)),
        (
            "alert_severities",
            severity_table(&snapshot, SlaEntity::Alert),
        ),
        (
            "case_severities",
            severity_table(&snapshot, SlaEntity::Case),
        ),
        (
            "has_data",
            Data::Bool(head.alerts.opened != 0 || head.cases.opened != 0),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_like_python() {
        assert_eq!(duration(None), "\u{2014}");
        assert_eq!(duration(Some(44.5)), "44s");
        assert_eq!(duration(Some(59.5)), "1m");
        assert_eq!(duration(Some(3600.0)), "1h");
        assert_eq!(duration(Some(3900.0)), "1h 05m");
        assert_eq!(duration(Some(90000.0)), "1d 1h");
        assert_eq!(duration(Some(172800.0)), "2d");
        assert_eq!(rate(Some(97.25)), "97.2%");
        assert_eq!(rate(None), "n/a");
        assert_eq!(delta(3.0, 0.0), "new");
        assert_eq!(delta(0.0, 0.0), "");
        assert_eq!(delta(10.0, 8.0), "+25%");
        assert_eq!(delta(7.0, 8.0), "\u{2212}12%");
        assert_eq!(delta(1000.0, 1001.0), "\u{b1}0%");
        assert_eq!(target(Some(240)), "4h");
        assert_eq!(target(None), "no target");
    }
}
