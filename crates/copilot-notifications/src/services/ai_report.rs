//! `context.ai_report` for templates (`services/ai_report_context.py`) and
//! the webhook's full-report fields (`channels/webhook.build_full_report`):
//! projections of the alert's newest AI report, never stored.

use copilot_auth::pyvalue::PyValue;
use copilot_db::Db;
use copilot_db::ai_analyst;
use copilot_jinja::Input;

use crate::db;

/// `MAX_IOCS`: indicators handed to a template.
pub const MAX_IOCS: usize = 50;

/// `str(datetime)` of a stored timestamp.
fn py_datetime_str(t: chrono::NaiveDateTime) -> String {
    t.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// `load_ai_report_context(alert_id)`; a failure is logged and reads as no
/// report (`safe_load_ai_report_context`).
pub async fn safe_load(db: &Db, alert_id: i64) -> Input {
    match load(db, alert_id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                alert_id,
                "Could not load AI report for alert {alert_id}: {e}"
            );
            Input::None
        }
    }
}

async fn load(db: &Db, alert_id: i64) -> Result<Input, String> {
    let Some(report) = db::latest_report(db, alert_id)
        .await
        .map_err(|e| format!("OperationalError: {e}"))?
    else {
        return Ok(Input::None);
    };
    let iocs = ai_analyst::iocs_by_report_unordered(db, i64::from(report.id))
        .await
        .map_err(|e| format!("OperationalError: {e}"))?;
    let markdown = report.report_markdown.clone().unwrap_or_default();
    let html = copilot_markdown::markdown_to_html(&markdown)
        .map_err(|e| format!("{}: {e}", copilot_markdown::Error::TYPE_NAME))?;
    let count = iocs.len();
    let listed: Vec<Input> = iocs
        .iter()
        .take(MAX_IOCS)
        .map(|i| {
            Input::Dict(vec![
                ("value".into(), Input::Str(i.ioc_value.clone())),
                ("type".into(), Input::Str(i.ioc_type.clone())),
                ("vt_verdict".into(), Input::Str(i.vt_verdict.clone())),
                (
                    "vt_score".into(),
                    Input::Str(i.vt_score.clone().unwrap_or_default()),
                ),
                (
                    "details".into(),
                    Input::Str(i.details.clone().unwrap_or_default()),
                ),
            ])
        })
        .collect();
    Ok(Input::Dict(vec![
        ("markdown".into(), Input::Str(markdown)),
        ("html".into(), Input::Markup(html)),
        (
            "summary".into(),
            Input::Str(report.summary.unwrap_or_default()),
        ),
        (
            "recommended_actions".into(),
            Input::Str(report.recommended_actions.unwrap_or_default()),
        ),
        (
            "severity".into(),
            Input::Str(report.severity_assessment.unwrap_or_default()),
        ),
        // A datetime in Python; templates print it as `str(datetime)`.
        (
            "created_at".into(),
            Input::Str(py_datetime_str(report.created_at)),
        ),
        ("report_id".into(), Input::Int(i128::from(report.id))),
        ("iocs".into(), Input::List(listed)),
        ("ioc_count".into(), Input::Int(count as i128)),
        ("iocs_truncated".into(), Input::Bool(count > MAX_IOCS)),
    ]))
}

fn opt(v: Option<String>) -> PyValue {
    v.map_or(PyValue::None, PyValue::Str)
}

/// `build_full_report(alert_id)`: the report's fields the webhook payload
/// does not already carry, or `None` without a report.
pub async fn full_report(db: &Db, alert_id: i64) -> Result<Option<PyValue>, copilot_db::DbError> {
    let Some(report) = db::latest_report(db, alert_id).await? else {
        return Ok(None);
    };
    let iocs = ai_analyst::iocs_by_alert(db, alert_id).await?;
    Ok(Some(PyValue::Dict(vec![
        ("report_id".into(), PyValue::Int(report.id.to_string())),
        (
            "recommended_actions".into(),
            opt(report.recommended_actions),
        ),
        ("report_markdown".into(), opt(report.report_markdown)),
        (
            "report_created_at".into(),
            PyValue::Str(copilot_core::time::to_pydantic_iso(report.created_at)),
        ),
        (
            "iocs".into(),
            PyValue::List(
                iocs.into_iter()
                    .map(|i| {
                        PyValue::Dict(vec![
                            ("ioc_value".into(), PyValue::Str(i.ioc_value)),
                            ("ioc_type".into(), PyValue::Str(i.ioc_type)),
                            ("vt_verdict".into(), PyValue::Str(i.vt_verdict)),
                            ("vt_score".into(), opt(i.vt_score)),
                            ("details".into(), opt(i.details)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])))
}
