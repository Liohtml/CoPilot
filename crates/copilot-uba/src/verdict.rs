//! A verdict given on the UBA page, written back to the CoPilot incident
//! alert (#1239) — port of `services/incident_verdict.py` and the route's
//! `_record_on_incident`.
//!
//! UBA holds the verdict once it has accepted it; the incident alert is a
//! second, best-effort write, and every outcome but `recorded` leaves it
//! alone and says why:
//!
//! - `not_linked`: the UBA alert names no incident alert, or it is gone;
//! - `skipped`: a FALSE_POSITIVE without suppression while another of the
//!   incident's UBA alerts is still open (UBA's poller would suppress their
//!   rules), an incident alert the caller's tags do not reach, or another
//!   customer's;
//! - `already_set`: the incident alert has a verdict (never overwritten);
//! - `failed`: anything raised on the way (UBA's error `reason`, else
//!   `error`).
//!
//! The incident alert is the one `get_alert_by_id(incident_id, user=…)`
//! finds — `incident_id` bound as UBA sent it, so MySQL compares a string id
//! numerically as it does for Python — then `copilot-incidents`' verdict
//! update; the audit event and the SLA action are recorded exactly where the
//! route records them.

use copilot_auth::pyvalue::PyValue;
use copilot_core::audit::AuditRecord;
use copilot_incidents::access;
use copilot_incidents::routes::common::{actor, sla};
use copilot_incidents::writes;
use copilot_sla::LifecycleAction;
use copilot_upstream::model::{construct, kwargs};
use copilot_upstream::py::{self, PyExc, py_eq};
use copilot_web::{ApiError, AppContext, CurrentUser};
use serde_json::json;

use crate::client::{UbaClient, UbaError, UbaResult};
use crate::schema::{Feedback, INCIDENT_VERDICT};
use crate::services::{int, model_extra, p, s};

/// `FalsePositiveReason`'s values.
pub const FALSE_POSITIVE_REASONS: &[&str] = &[
    "EXPECTED_ACTIVITY",
    "KNOWN_APPLICATION",
    "AUTHORIZED_USER",
    "RULE_TOO_SENSITIVE",
    "OTHER",
];

/// `incident_reason(verdict, reason)`: CoPilot's closed vocabulary on a
/// FALSE_POSITIVE (anything else is `OTHER`), nothing on a TRUE_POSITIVE.
pub fn incident_reason(verdict: &str, reason: Option<&str>) -> Option<String> {
    if verdict != "FALSE_POSITIVE" {
        return None;
    }
    Some(
        reason
            .filter(|r| FALSE_POSITIVE_REASONS.contains(r))
            .unwrap_or("OTHER")
            .to_string(),
    )
}

/// What a step raised: a UBA error (its `reason`), anything else (`error`).
#[derive(Debug)]
enum Failure {
    Uba(&'static str),
    Other,
}

impl From<UbaError> for Failure {
    fn from(e: UbaError) -> Self {
        match e {
            UbaError::Request { reason, .. } => Self::Uba(reason),
            UbaError::Py(_) => Self::Other,
        }
    }
}

impl From<PyExc> for Failure {
    fn from(_: PyExc) -> Self {
        Self::Other
    }
}

impl From<ApiError> for Failure {
    fn from(_: ApiError) -> Self {
        Self::Other
    }
}

/// `UbaIncidentVerdict(...)`: its dump, or the `ValidationError` of an
/// `incident_alert_id` Pydantic cannot read as an int.
fn verdict_model(
    status: &str,
    incident_id: Option<&PyValue>,
    verdict: Option<&str>,
    message: String,
) -> Result<PyValue, Failure> {
    let mut fields = vec![("status", s(status))];
    if let Some(id) = incident_id {
        fields.push(("incident_alert_id", id.clone()));
    }
    if let Some(v) = verdict {
        fields.push(("verdict", s(v)));
    }
    fields.push(("message", PyValue::Str(message)));
    Ok(construct(&INCIDENT_VERDICT, &kwargs(fields))?)
}

/// An updated alert: what the route audits and puts on the SLA clock.
struct Recorded {
    id: i32,
    customer_code: String,
    verdict: Option<String>,
    reason: Option<String>,
    note: Option<String>,
    previous: serde_json::Value,
}

/// The row `Alert.id == incident_id` selects, `incident_id` bound as UBA
/// sent it (a string is compared numerically by MySQL, as for Python).
async fn matching_alert(ctx: &AppContext, raw: &PyValue) -> Result<Option<i64>, Failure> {
    // pymysql renders a list as `(item, …)`: `id = (7)` is MySQL's 7, two
    // items are its "Operand should contain 1 column(s)".
    let mut raw = raw;
    while let PyValue::List(items) = raw {
        match items.as_slice() {
            [one] => raw = one,
            _ => return Err(Failure::Other),
        }
    }
    if matches!(raw, PyValue::None) {
        return Ok(None);
    }
    let query = "SELECT id FROM incident_management_alert WHERE id = ?";
    let row: Option<(i32,)> = match raw {
        PyValue::Int(text) => match text.parse::<i64>() {
            Ok(n) => {
                sqlx::query_as(query)
                    .bind(n)
                    .fetch_optional(ctx.db.pool())
                    .await
            }
            // An int no id can equal (MySQL compares it as a decimal).
            Err(_) => return Ok(None),
        },
        PyValue::Bool(b) => {
            sqlx::query_as(query)
                .bind(i64::from(*b))
                .fetch_optional(ctx.db.pool())
                .await
        }
        PyValue::Float(f) if f.is_finite() => {
            sqlx::query_as(query)
                .bind(*f)
                .persistent(false)
                .fetch_optional(ctx.db.pool())
                .await
        }
        PyValue::Str(text) => {
            sqlx::query_as(query)
                .bind(text)
                .persistent(false)
                .fetch_optional(ctx.db.pool())
                .await
        }
        // NaN or a dict: pymysql renders what MySQL refuses (or refuses it).
        _ => return Err(Failure::Other),
    }
    .map_err(|_| Failure::Other)?;
    Ok(row.map(|(id,)| i64::from(id)))
}

/// `_open_siblings`: the incident's other UBA alerts without a verdict.
async fn open_siblings(
    client: &UbaClient,
    customer_code: &str,
    entity_key: PyValue,
    uba_alert_id: &str,
    incident_id: &PyValue,
) -> Result<usize, Failure> {
    let page = client
        .list_alerts(
            customer_code,
            vec![
                p("entity_key", entity_key),
                p("status", s("open")),
                p("page_size", int("500")),
            ],
        )
        .await?;
    let extra = PyValue::Dict(model_extra(&page));
    let alerts = match extra.get("alerts") {
        Some(a) if a.truthy() => a.clone(),
        _ => PyValue::List(Vec::new()),
    };
    let mut n = 0;
    for a in py::iterate(&alerts)? {
        let linked = py::get(&a, "copilot_alert_id")?
            .cloned()
            .unwrap_or(PyValue::None);
        if !py_eq(&linked, incident_id) {
            continue;
        }
        let id = py::get(&a, "id")?.cloned().unwrap_or(PyValue::None);
        if !py_eq(&id, &s(uba_alert_id)) {
            n += 1;
        }
    }
    Ok(n)
}

/// `record_on_incident`: the outcome and, when it was recorded, what the
/// route audits.
async fn record_on_incident(
    ctx: &AppContext,
    client: &UbaClient,
    customer_code: &str,
    uba_alert_id: &str,
    body: &Feedback,
    user: &CurrentUser,
) -> Result<(PyValue, Option<Recorded>), Failure> {
    let dump = client.get_alert(customer_code, uba_alert_id).await?;
    let extra = PyValue::Dict(model_extra(&dump));
    let uba_alert = match extra.get("alert") {
        Some(a) if a.truthy() => a.clone(),
        _ => PyValue::Dict(Vec::new()),
    };
    let incident_id = py::get(&uba_alert, "copilot_alert_id")?
        .cloned()
        .unwrap_or(PyValue::None);
    if !incident_id.truthy() {
        return Ok((
            verdict_model(
                "not_linked",
                None,
                None,
                "This UBA alert has no incident alert in CoPilot.".into(),
            )?,
            None,
        ));
    }
    let id_text = incident_id.py_str();
    let outcome = |status: &str, message: String, verdict: Option<&str>| {
        verdict_model(status, Some(&incident_id), verdict, message)
    };

    if body.verdict == "FALSE_POSITIVE" && !body.suppress {
        let entity_key = match py::get(&uba_alert, "entity_key")? {
            Some(k) if k.truthy() => k.clone(),
            _ => s(""),
        };
        let siblings = open_siblings(
            client,
            customer_code,
            entity_key,
            uba_alert_id,
            &incident_id,
        )
        .await?;
        if siblings > 0 {
            return Ok((
                outcome(
                    "skipped",
                    format!(
                        "Incident alert #{id_text} also holds {siblings} other open UBA alert(s) \
                         for this entity; a false positive there would suppress their rules, so \
                         it was left untriaged."
                    ),
                    None,
                )?,
                None,
            ));
        }
    }

    // `get_alert_by_id(incident_id, db, user=user)`.
    let Some(alert_id) = matching_alert(ctx, &incident_id).await? else {
        return Ok((
            outcome(
                "not_linked",
                format!("Incident alert #{id_text} no longer exists."),
                None,
            )?,
            None,
        ));
    };
    let loaded = match access::alert_for(ctx, user, alert_id).await {
        Ok(a) => a,
        Err(e) if e.status() == http::StatusCode::NOT_FOUND => {
            return Ok((
                outcome(
                    "not_linked",
                    format!("Incident alert #{id_text} no longer exists."),
                    None,
                )?,
                None,
            ));
        }
        Err(ApiError::Http { .. }) => {
            return Ok((
                outcome(
                    "skipped",
                    format!("You cannot see incident alert #{id_text}."),
                    None,
                )?,
                None,
            ));
        }
        Err(e) => return Err(e.into()),
    };
    loaded.build()?;
    if loaded.row.customer_code != customer_code {
        return Ok((
            outcome(
                "skipped",
                format!("Incident alert #{id_text} belongs to another customer."),
                None,
            )?,
            None,
        ));
    }
    if let Some(existing) = loaded.row.verdict.as_deref().filter(|v| !v.is_empty()) {
        return Ok((
            outcome(
                "already_set",
                format!("Incident alert #{id_text} already has a verdict."),
                Some(existing),
            )?,
            None,
        ));
    }
    let reason = incident_reason(&body.verdict, body.reason.as_deref());
    let (row, previous) = writes::update_alert_verdict(
        &ctx.db,
        alert_id,
        Some(&body.verdict),
        reason.as_deref(),
        body.note.as_deref(),
        &user.username,
    )
    .await?;
    let model = outcome(
        "recorded",
        format!("Also recorded on incident alert #{id_text}."),
        row.verdict.as_deref(),
    )?;
    Ok((
        model,
        Some(Recorded {
            id: row.id,
            customer_code: row.customer_code,
            verdict: row.verdict,
            reason: row.verdict_reason,
            note: row.verdict_note,
            previous,
        }),
    ))
}

/// `_record_on_incident`: never fails the request — UBA has already
/// accepted the verdict.
pub async fn record(
    ctx: &AppContext,
    client: &UbaClient,
    customer_code: &str,
    uba_alert_id: &str,
    body: &Feedback,
    user: &CurrentUser,
) -> UbaResult<PyValue> {
    let (outcome, recorded) =
        match record_on_incident(ctx, client, customer_code, uba_alert_id, body, user).await {
            Ok(r) => r,
            Err(failure) => {
                let reason = match failure {
                    Failure::Uba(reason) => reason,
                    Failure::Other => "error",
                };
                tracing::error!(
                    "UBA alert {uba_alert_id}: recording the verdict on its incident alert failed"
                );
                let message = format!(
                    "The verdict was saved in UBA but not on the incident alert ({reason})."
                );
                return verdict_model("failed", None, None, message).map_err(|_| {
                    UbaError::Py(PyExc::Other("ValidationError", "failed outcome".into()))
                });
            }
        };
    let Some(updated) = recorded else {
        return Ok(outcome);
    };
    let record = AuditRecord::new("alert.verdict_set")
        .actor(Some(user.id), Some(&user.username))
        .customer(Some(&updated.customer_code))
        .entity("alert", updated.id)
        .values(
            Some(updated.previous.clone()),
            Some(json!({
                "verdict": updated.verdict,
                "verdict_reason": updated.reason,
                "verdict_note": updated.note,
                "via": "uba",
                "uba_alert_id": uba_alert_id,
            })),
        )
        .source_ip(user.source_ip.clone());
    // Python awaits the write before it answers.
    if let Err(e) = copilot_db::audit::insert_audit_record(&ctx.db, record).await {
        tracing::error!("Failed to record audit event 'alert.verdict_set': {e}");
    }
    sla(ctx)
        .alert_action(
            i64::from(updated.id),
            LifecycleAction::VerdictSet,
            &actor(user),
            None,
            None,
        )
        .await;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_follow_the_closed_vocabulary() {
        assert_eq!(incident_reason("TRUE_POSITIVE", Some("OTHER")), None);
        assert_eq!(
            incident_reason("FALSE_POSITIVE", Some("AUTHORIZED_USER")).as_deref(),
            Some("AUTHORIZED_USER")
        );
        assert_eq!(
            incident_reason("FALSE_POSITIVE", Some("authorized_user")).as_deref(),
            Some("OTHER")
        );
        assert_eq!(
            incident_reason("FALSE_POSITIVE", None).as_deref(),
            Some("OTHER")
        );
    }

    #[test]
    fn an_id_pydantic_refuses_fails_the_outcome() {
        assert!(matches!(
            verdict_model("recorded", Some(&s("12abc")), None, "m".into()),
            Err(Failure::Other)
        ));
        let ok = verdict_model(
            "recorded",
            Some(&s(" 12 ")),
            Some("TRUE_POSITIVE"),
            "m".into(),
        )
        .unwrap();
        assert_eq!(
            ok.py_repr(),
            "{'status': 'recorded', 'incident_alert_id': 12, 'verdict': 'TRUE_POSITIVE', \
             'message': 'm'}"
        );
    }
}
