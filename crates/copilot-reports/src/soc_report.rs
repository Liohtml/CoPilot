//! `GET /api/soc_management/report` (`soc_management/routes`' `get_report`
//! and `services/report.py`): the SOC operations report — the dashboard's
//! `Snapshot` for the caller (20 attention items), its context, the two line
//! charts and the rules chart, `soc_operations_report.html` over the shared
//! chrome, wkhtmltopdf — answered as Starlette's `Response`.
//!
//! The query is validated first (422), the period next (400 with the
//! `ValueError` text); whatever fails after that is the route's 500
//! `Failed to generate the SOC report`, as Python's `except Exception`.

use std::collections::HashMap;

use axum::Router;
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use copilot_jinja::Data;
use copilot_sla::policy::SlaEntity;
use copilot_soc_management::domain::periods::{Bucket, Period};
use copilot_soc_management::routes::soc_management::{fact_filters, period, req_datetime};
use copilot_soc_management::services::metrics::{self, DashboardQuery, Snapshot};
use copilot_web::validate::Validator;
use copilot_web::{AdminOrAnalyst, ApiError, AppContext, Authorized, QueryPairs};

use crate::sla::{
    EMPTY, RATE_GOOD, compliance, dict, duration, entity_summary, int, rate, s, severity_table,
    tracking_since,
};
use crate::{charts, customer_report, pdfkit, starlette, templates};

type Soc = Authorized<AdminOrAnalyst>;

/// `TLP`.
pub const TLP: &str = "TLP:AMBER";
const REPORT_ATTENTION_LIMIT: usize = 20;
const REPORT_RULES_LIMIT: usize = 15;

/// The route, at its full path.
pub fn router(ctx: AppContext) -> Router {
    Router::new()
        .route("/api/soc_management/report", get(get_report))
        .with_state(ctx)
}

fn bucket_format(b: Bucket) -> &'static str {
    match b {
        Bucket::Hour => "%H:%M",
        Bucket::Day | Bucket::Week => "%d %b",
        Bucket::Month => "%b %Y",
    }
}

fn period_label(p: &Period) -> Data {
    dict(vec![
        ("from", s(p.start.format("%Y-%m-%d %H:%M").to_string())),
        ("to", s(p.end.format("%Y-%m-%d %H:%M").to_string())),
    ])
}

/// `_scope_label(codes, names)`.
fn scope_label(codes: Option<&[String]>, names: &HashMap<String, String>) -> String {
    let name = |c: &String| {
        names
            .get(c)
            .filter(|n| !n.is_empty())
            .cloned()
            .unwrap_or_else(|| c.clone())
    };
    match codes {
        None => "All customers".into(),
        Some([]) => "No customer".into(),
        Some([one]) => name(one),
        Some(many) if many.len() <= 4 => many.iter().map(name).collect::<Vec<_>>().join(", "),
        Some(many) => format!("{} customers", many.len()),
    }
}

fn get_str(d: &Data, key: &str) -> Option<String> {
    match d {
        Data::Dict(items) => items
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| match v {
                Data::Str(s) if !s.is_empty() => Some(s.clone()),
                _ => None,
            }),
        _ => None,
    }
}

fn item(d: &Data, key: &str) -> Data {
    match d {
        Data::Dict(items) => items
            .iter()
            .find(|(k, _)| k == key)
            .map_or(Data::None, |(_, v)| v.clone()),
        _ => Data::None,
    }
}

/// `build_report_context(session, snapshot)`.
async fn build_context(ctx: &AppContext, snap: &Snapshot) -> Result<Data, ApiError> {
    let single = snap
        .customer_codes
        .as_deref()
        .filter(|c| c.len() == 1)
        .map(|c| c[0].as_str());
    let theme = customer_report::resolve_theme(&ctx.db, "customer", single).await?;
    let (head, prev) = (&snap.headline, &snap.previous_headline);
    let labels: Vec<String> = snap
        .trends
        .iter()
        .map(|p| p.start.format(bucket_format(snap.bucket)).to_string())
        .collect();
    let accent = get_str(&theme, "accent_strong")
        .or_else(|| get_str(&theme, "chart_bar"))
        .unwrap_or_else(|| "#2563eb".into());
    let volume = charts::line_png(
        &labels,
        &[
            (
                "Alerts opened".into(),
                snap.trends
                    .iter()
                    .map(|p| Some(p.alerts_opened as f64))
                    .collect(),
                accent.clone(),
            ),
            (
                "Alerts resolved".into(),
                snap.trends
                    .iter()
                    .map(|p| Some(p.alerts_resolved as f64))
                    .collect(),
                "#94a3b8".into(),
            ),
        ],
        false,
        None,
    );
    let sla_chart = charts::line_png(
        &labels,
        &[(
            "Resolve SLA met".into(),
            snap.trends.iter().map(|p| p.sla_rate).collect(),
            accent,
        )],
        true,
        Some(RATE_GOOD),
    );
    let rules_chart = if snap.rules.is_empty() {
        Data::None
    } else {
        let data: Vec<(String, i64)> = snap
            .rules
            .iter()
            .take(10)
            .map(|r| (r.alert_name.clone(), r.alerts))
            .collect();
        s(charts::hbar_png(
            &data,
            get_str(&theme, "chart_bar").as_deref(),
        ))
    };
    let label = scope_label(snap.customer_codes.as_deref(), &snap.customer_names);
    let w = &snap.workload;
    let attention: Vec<Data> = snap
        .attention
        .iter()
        .map(|i| {
            let kind = if i.entity == SlaEntity::Alert {
                "ALERT"
            } else {
                "CASE"
            };
            dict(vec![
                ("ref", s(format!("{kind}-{}", i.id))),
                ("title", s(i.title.clone())),
                (
                    "customer",
                    s(i.customer_code
                        .clone()
                        .filter(|c| !c.is_empty())
                        .unwrap_or_else(|| EMPTY.into())),
                ),
                ("severity", s(i.severity.clone())),
                (
                    "assigned_to",
                    s(i.assigned_to
                        .clone()
                        .filter(|a| !a.is_empty())
                        .unwrap_or_else(|| "unassigned".into())),
                ),
                ("state", s(i.state.as_str())),
                (
                    "clock",
                    s(if i.clock == "ack" {
                        "response"
                    } else {
                        "resolution"
                    }),
                ),
                ("overdue", s(duration(Some(i.overdue_seconds.abs())))),
                ("late", Data::Bool(i.overdue_seconds > 0.0)),
            ])
        })
        .collect();
    Ok(dict(vec![
        (
            "generated_at",
            s(snap.now.format("%Y-%m-%d %H:%M").to_string()),
        ),
        ("period", period_label(&snap.period)),
        ("previous_period", period_label(&snap.previous)),
        ("scope", s(label.clone())),
        ("customer", dict(vec![("name", s(label)), ("code", s(""))])),
        ("brand", item(&theme, "footer_brand")),
        ("logo", item(&theme, "logo")),
        ("theme", theme.clone()),
        ("tlp", s(TLP)),
        ("sla_objective", Data::Float(RATE_GOOD)),
        (
            "viewer",
            dict(vec![
                ("username", s(snap.viewer.username.clone())),
                ("is_admin", Data::Bool(snap.viewer.is_admin)),
                (
                    "sees_all_analysts",
                    Data::Bool(snap.viewer.sees_all_analysts),
                ),
            ]),
        ),
        ("tracking_since", tracking_since(snap.tracking_since)),
        ("alerts", entity_summary(&head.alerts, &prev.alerts)),
        ("cases", entity_summary(&head.cases, &prev.cases)),
        ("false_positive_rate", s(rate(head.false_positive_rate))),
        ("reviewed_alerts", int(head.reviewed_alerts)),
        ("case_conversion_rate", s(rate(head.case_conversion_rate))),
        ("escalated_alerts", int(head.escalated_alerts)),
        (
            "workload",
            dict(vec![
                ("open_alerts", int(w.open_alerts)),
                ("open_cases", int(w.open_cases)),
                ("unassigned_alerts", int(w.unassigned_alerts)),
                ("unassigned_cases", int(w.unassigned_cases)),
                ("breached", int(w.breached)),
                ("at_risk", int(w.at_risk)),
                ("waiting_on_customer", int(w.waiting_on_customer)),
                (
                    "by_severity",
                    Data::List(
                        w.by_severity
                            .iter()
                            .map(|l| {
                                dict(vec![
                                    ("severity", s(l.severity)),
                                    ("alerts", int(l.alerts)),
                                    ("cases", int(l.cases)),
                                    ("breached", int(l.breached)),
                                    ("at_risk", int(l.at_risk)),
                                ])
                            })
                            .collect(),
                    ),
                ),
                (
                    "by_assignee",
                    Data::List(
                        w.by_assignee
                            .iter()
                            .map(|l| {
                                dict(vec![
                                    ("username", s(l.username.clone())),
                                    ("alerts", int(l.alerts)),
                                    ("cases", int(l.cases)),
                                    ("breached", int(l.breached)),
                                    ("at_risk", int(l.at_risk)),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ]),
        ),
        ("alert_severities", severity_table(snap, SlaEntity::Alert)),
        ("case_severities", severity_table(snap, SlaEntity::Case)),
        (
            "charts",
            dict(vec![
                ("volume", s(volume)),
                ("sla", s(sla_chart)),
                ("rules", rules_chart),
            ]),
        ),
        (
            "analysts",
            Data::List(
                snap.analysts
                    .iter()
                    .map(|r| {
                        dict(vec![
                            ("username", s(r.username.clone())),
                            ("alerts_resolved", int(r.alerts_resolved)),
                            ("cases_resolved", int(r.cases_resolved)),
                            (
                                "acknowledged",
                                int(r.alerts_acknowledged + r.cases_acknowledged),
                            ),
                            ("tta", s(duration(r.tta.median))),
                            ("ttr", s(duration(r.ttr.median))),
                            ("sla", compliance(&r.sla)),
                            ("open", int(r.open_alerts + r.open_cases)),
                            ("breached", int(r.breached)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "rules",
            Data::List(
                snap.rules
                    .iter()
                    .take(REPORT_RULES_LIMIT)
                    .map(|r| {
                        let sources = r.sources.join(", ");
                        dict(vec![
                            ("name", s(r.alert_name.clone())),
                            (
                                "sources",
                                s(if sources.is_empty() {
                                    EMPTY.to_string()
                                } else {
                                    sources
                                }),
                            ),
                            ("alerts", int(r.alerts)),
                            ("in_case", int(r.in_case)),
                            ("fp_rate", s(rate(r.false_positive_rate))),
                            ("reviewed", int(r.reviewed)),
                            ("noisy", Data::Bool(r.noisy)),
                            ("ttr", s(duration(r.ttr.median))),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "customers",
            Data::List(
                snap.customers
                    .iter()
                    .map(|row| {
                        let name = snap
                            .customer_names
                            .get(&row.customer_code)
                            .filter(|n| !n.is_empty())
                            .cloned()
                            .unwrap_or_else(|| row.customer_code.clone());
                        dict(vec![
                            ("code", s(row.customer_code.clone())),
                            ("name", s(name)),
                            ("alerts", int(row.alerts)),
                            ("cases", int(row.cases)),
                            ("open", int(row.open_now)),
                            ("breached", int(row.breached_now)),
                            ("alert_sla", compliance(&row.alert_sla)),
                            ("case_sla", compliance(&row.case_sla)),
                            ("ttr", s(duration(row.alert_ttr.median))),
                            (
                                "top_rule",
                                s(row
                                    .top_rule
                                    .clone()
                                    .filter(|t| !t.is_empty())
                                    .unwrap_or_else(|| EMPTY.into())),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("attention", Data::List(attention)),
    ]))
}

/// `render_report(session, user, query)`: the PDF and its file name.
async fn render_report(
    ctx: &AppContext,
    auth: &Soc,
    query: &DashboardQuery,
) -> Result<(Vec<u8>, String), String> {
    let snap = metrics::snapshot_for_user(ctx, auth, query, REPORT_ATTENTION_LIMIT)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let context = build_context(ctx, &snap)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let brand = get_str(&context, "brand").unwrap_or_else(|| "CoPilot".into());
    let Data::Dict(vars) = context else {
        return Err("context".into());
    };
    let html = tokio::task::spawn_blocking(move || {
        templates::soc_env().render("soc_operations_report.html", &vars)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.message)?;
    let pdf = pdfkit::html_to_pdf_bytes(&html, &brand, TLP).await?;
    let name = format!(
        "soc_report_{}_{}.pdf",
        snap.period.start.format("%Y%m%d"),
        snap.period.end.format("%Y%m%d")
    );
    Ok((pdf, name))
}

/// `GET /report`.
async fn get_report(
    auth: Soc,
    State(ctx): State<AppContext>,
    headers: http::HeaderMap,
    q: QueryPairs,
) -> Result<Response, ApiError> {
    let mut v = Validator::new();
    let from = req_datetime(&mut v, &q, "date_from");
    let to = req_datetime(&mut v, &q, "date_to");
    v.finish()?;
    let (Some(from), Some(to)) = (from, to) else {
        return Err(ApiError::internal("report: dates without errors"));
    };
    let query = DashboardQuery {
        period: period(from, to)?,
        customer_codes: q.customer_codes(),
        filters: fact_filters(&q),
        bucket: None,
    };
    let (pdf, name) = match render_report(&ctx, &auth, &query).await {
        Ok(done) => done,
        Err(e) => {
            tracing::error!("SOC report generation failed: {e}");
            return Err(ApiError::server_error("Failed to generate the SOC report"));
        }
    };
    starlette::response(
        http::StatusCode::OK,
        pdf,
        Some("application/pdf"),
        &[
            (
                "Content-Disposition",
                format!("attachment; filename=\"{name}\""),
            ),
            ("Cache-Control", "no-store".to_string()),
        ],
        &headers,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_labels() {
        let mut names = HashMap::new();
        names.insert("a".to_string(), "Acme".to_string());
        assert_eq!(scope_label(None, &names), "All customers");
        assert_eq!(scope_label(Some(&[]), &names), "No customer");
        assert_eq!(scope_label(Some(&["a".into()]), &names), "Acme");
        assert_eq!(
            scope_label(Some(&["a".into(), "b".into()]), &names),
            "Acme, b"
        );
        let five: Vec<String> = (0..5).map(|i| i.to_string()).collect();
        assert_eq!(scope_label(Some(&five), &names), "5 customers");
    }
}
