//! Case templates applied to cases — port of the selection and application
//! half of `app/incidents/services/case_tasks.py` (`pick_template_for_case`,
//! `pick_templates_for_alert`, `apply_template_to_case`,
//! `auto_apply_template_for_new_case`).
//!
//! Tasks are *snapshots* of the template's tasks; editing the template later
//! changes nothing on a case. Field-match templates (`match_field` /
//! `match_value`) compare against the raw Wazuh document of the alert's first
//! asset, fetched from the Wazuh indexer ([`fetch_raw_event`]); when that
//! fails, selection falls back to the tier picker, as in Python.

use std::time::Duration;

use chrono::NaiveDateTime;
use copilot_core::time::{mysql_datetime, now_utc_micros};
use serde_json::{Map, Value, json};
use sqlx::{FromRow, MySqlConnection};

use copilot_db::Db;
use copilot_web::AppContext;

use crate::events::{self, CaseEvent};

/// One `incident_management_case_template` row (what selection needs).
#[derive(Debug, Clone, FromRow)]
pub struct TemplateRow {
    /// Id.
    pub id: i32,
    /// Name.
    pub name: String,
    /// Default of its scope.
    pub is_default: bool,
    /// Field-match field.
    pub match_field: Option<String>,
    /// Field-match value.
    pub match_value: Option<String>,
}

/// One `incident_management_case_template_task` row.
#[derive(Debug, Clone, FromRow)]
pub struct TemplateTaskRow {
    /// Id.
    pub id: i32,
    /// Title.
    pub title: String,
    /// Description.
    pub description: Option<String>,
    /// Guidelines.
    pub guidelines: Option<String>,
    /// Mandatory.
    pub mandatory: bool,
    /// Order.
    pub order_index: i32,
}

/// `select(CaseTemplate)`'s column list (the sort below must be the same
/// query: ties are left to MySQL).
const TEMPLATE_COLS: &str = crate::routes::case_templates::TEMPLATE_COLS;

async fn first_template(
    db: &Db,
    customer: Option<&str>,
    source: Option<&str>,
) -> Result<Option<TemplateRow>, sqlx::Error> {
    let mut sql = format!(
        "SELECT {TEMPLATE_COLS} FROM incident_management_case_template WHERE match_field IS NULL"
    );
    sql.push_str(if customer.is_some() {
        " AND customer_code = ?"
    } else {
        " AND customer_code IS NULL"
    });
    sql.push_str(if source.is_some() {
        " AND source = ?"
    } else {
        " AND source IS NULL"
    });
    sql.push_str(
        " ORDER BY incident_management_case_template.is_default DESC, \
         incident_management_case_template.created_at DESC",
    );
    let mut q = sqlx::query_as::<_, TemplateRow>(&sql);
    if let Some(c) = customer {
        q = q.bind(c);
    }
    if let Some(s) = source {
        q = q.bind(s);
    }
    q.fetch_optional(db.pool()).await
}

/// `pick_template_for_case`: customer+source > customer > source > the
/// global default; conditional templates never take part.
pub async fn pick_template_for_case(
    db: &Db,
    customer_code: Option<&str>,
    source: Option<&str>,
) -> Result<Option<TemplateRow>, sqlx::Error> {
    if let (Some(c), Some(s)) = (customer_code, source) {
        if let Some(t) = first_template(db, Some(c), Some(s)).await? {
            return Ok(Some(t));
        }
    }
    if let Some(c) = customer_code {
        if let Some(t) = first_template(db, Some(c), None).await? {
            return Ok(Some(t));
        }
    }
    if let Some(s) = source {
        if let Some(t) = first_template(db, None, Some(s)).await? {
            return Ok(Some(t));
        }
    }
    Ok(first_template(db, None, None)
        .await?
        .filter(|t| t.is_default))
}

/// Python's `str()` of a JSON value (the field-match comparison).
pub fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => py_repr(other),
    }
}

fn py_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(b) => if *b { "True" } else { "False" }.into(),
        Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
            (Some(i), _, _) => i.to_string(),
            (None, Some(u), _) => u.to_string(),
            (None, None, Some(f)) if f.fract() == 0.0 && f.abs() < 1e16 => format!("{f:.1}"),
            (None, None, Some(f)) => f.to_string(),
            _ => n.to_string(),
        },
        Value::String(s) => crate::views::py_str_repr(s),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(py_repr).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(k, v)| format!("{}: {}", crate::views::py_str_repr(k), py_repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// `_fetch_raw_event_for_alert`: the raw document of the alert's lowest-id
/// asset, or `None` (no asset, no or placeholder connector, any failure).
pub async fn fetch_raw_event(ctx: &AppContext, alert_id: i64) -> Option<Map<String, Value>> {
    let asset: Option<(String, String)> = sqlx::query_as(
        "SELECT index_name, index_id FROM incident_management_asset WHERE alert_linked = ? \
         ORDER BY id ASC LIMIT 1",
    )
    .bind(alert_id)
    .fetch_optional(ctx.db.pool())
    .await
    .ok()
    .flatten();
    let (index, id) = asset?;
    let connector = match ctx.connectors.get("Wazuh-Indexer").await {
        Ok(Some(c)) => c,
        _ => return None,
    };
    if connector.connector_url == "https://127.1.1.1:9200" {
        return None;
    }
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(15))
        .build()
        .ok()?;
    let url = format!(
        "{}/{}/_doc/{}",
        connector.connector_url.trim_end_matches('/'),
        es_quote(&index),
        es_quote(&id)
    );
    let response = client
        .get(url)
        .basic_auth(
            connector
                .connector_username
                .clone()
                .unwrap_or_else(|| "None".into()),
            Some(
                connector
                    .connector_password
                    .clone()
                    .unwrap_or_else(|| "None".into()),
            ),
        )
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        tracing::warn!(
            target: "copilot::incidents",
            alert_id, index, id, status = %response.status(),
            "raw-event fetch failed; falling back to non-field-match templates"
        );
        return None;
    }
    let doc: Value = response.json().await.ok()?;
    Some(
        doc.get("_source")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default(),
    )
}

/// `urllib.parse.quote(s, safe=",*")` (elasticsearch-py's `_make_path`).
fn es_quote(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"_.-~,*".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `pick_templates_for_alert(case, alert)`: every field-match template whose
/// condition holds on the raw event, else the tier picker's one.
pub async fn pick_templates_for_alert(
    ctx: &AppContext,
    case_customer: Option<&str>,
    alert_id: i64,
    alert_source: &str,
) -> Result<Vec<TemplateRow>, sqlx::Error> {
    let mut sql = format!(
        "SELECT {TEMPLATE_COLS} FROM incident_management_case_template \
         WHERE match_field IS NOT NULL AND match_value IS NOT NULL"
    );
    sql.push_str(if case_customer.is_some() {
        " AND (customer_code = ? OR customer_code IS NULL)"
    } else {
        " AND customer_code IS NULL"
    });
    sql.push_str(" AND (source = ? OR source IS NULL)");
    let mut q = sqlx::query_as::<_, TemplateRow>(&sql);
    if let Some(c) = case_customer {
        q = q.bind(c);
    }
    let candidates = q.bind(alert_source).fetch_all(ctx.db.pool()).await?;
    let mut matched = Vec::new();
    if !candidates.is_empty() {
        if let Some(raw) = fetch_raw_event(ctx, alert_id).await {
            for t in candidates {
                let field = t.match_field.clone().unwrap_or_default();
                let Some(value) = raw.get(&field).filter(|v| !v.is_null()) else {
                    continue;
                };
                if t.match_value.as_deref() == Some(py_str(value).as_str()) {
                    matched.push(t);
                }
            }
        }
    }
    if !matched.is_empty() {
        return Ok(matched);
    }
    Ok(
        pick_template_for_case(&ctx.db, case_customer, Some(alert_source))
            .await?
            .into_iter()
            .collect(),
    )
}

/// `apply_template_to_case(..., commit=False)` inside the caller's
/// transaction: snapshot the tasks, then `template_applied` and one
/// `task_added` per task. Returns how many tasks were added (`None` when the
/// template or the case does not exist: nothing is written).
pub async fn apply_template(
    conn: &mut MySqlConnection,
    case_id: i64,
    template_id: i64,
    actor: &str,
    alert_id: Option<i64>,
) -> Result<Option<usize>, sqlx::Error> {
    let template: Option<(i32, String)> =
        sqlx::query_as("SELECT id, name FROM incident_management_case_template WHERE id = ?")
            .bind(template_id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((template_id, template_name)) = template else {
        tracing::warn!(target: "copilot::incidents", "apply_template_to_case: template id={template_id} not found");
        return Ok(None);
    };
    let case: Option<(i32,)> =
        sqlx::query_as("SELECT id FROM incident_management_case WHERE id = ?")
            .bind(case_id)
            .fetch_optional(&mut *conn)
            .await?;
    if case.is_none() {
        tracing::warn!(target: "copilot::incidents", "apply_template_to_case: case id={case_id} not found");
        return Ok(None);
    }
    let mut tasks: Vec<TemplateTaskRow> = sqlx::query_as(
        "SELECT id, title, description, guidelines, mandatory, order_index \
         FROM incident_management_case_template_task WHERE template_id = ?",
    )
    .bind(template_id)
    .fetch_all(&mut *conn)
    .await?;
    tasks.sort_by_key(|t| (t.order_index, t.id));

    let mut created = Vec::with_capacity(tasks.len());
    for t in &tasks {
        let now: NaiveDateTime = mysql_datetime(now_utc_micros());
        let result = sqlx::query(
            "INSERT INTO incident_management_case_task (case_id, alert_id, template_task_id, \
             title, description, guidelines, mandatory, order_index, status, evidence_comment, \
             completed_by, completed_at, assigned_to, created_by, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'TODO', NULL, NULL, NULL, NULL, ?, ?, ?)",
        )
        .bind(case_id)
        .bind(alert_id)
        .bind(t.id)
        .bind(&t.title)
        .bind(&t.description)
        .bind(&t.guidelines)
        .bind(t.mandatory)
        .bind(t.order_index)
        .bind(actor)
        .bind(now)
        .bind(now)
        .execute(&mut *conn)
        .await?;
        created.push((result.last_insert_id() as i64, t));
    }

    let mut applied = events::template_applied(i64::from(template_id), &template_name, tasks.len());
    if let (Some(a), Some(obj)) = (alert_id, applied.as_object_mut()) {
        obj.insert("alert_id".into(), json!(a));
    }
    events::insert(
        conn,
        &CaseEvent::new(case_id, events::TEMPLATE_APPLIED, actor, applied),
    )
    .await?;
    for (task_id, t) in created {
        let payload = events::task(
            task_id,
            &t.title,
            t.mandatory,
            &[
                ("source", json!("template")),
                ("template_id", json!(template_id)),
                ("alert_id", json!(alert_id)),
            ],
        );
        events::insert(
            conn,
            &CaseEvent::new(case_id, events::TASK_ADDED, actor, payload),
        )
        .await?;
    }
    Ok(Some(tasks.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_str_of_json_values() {
        assert_eq!(py_str(&json!("1")), "1");
        assert_eq!(py_str(&json!(1)), "1");
        assert_eq!(py_str(&json!(1.5)), "1.5");
        assert_eq!(py_str(&json!(2.0)), "2.0");
        assert_eq!(py_str(&json!(true)), "True");
        assert_eq!(py_str(&json!(["a", 1])), "['a', 1]");
        assert_eq!(
            es_quote("wazuh-alerts-4.x-2026.01.01"),
            "wazuh-alerts-4.x-2026.01.01"
        );
        assert_eq!(es_quote("a/b c"), "a%2Fb%20c");
    }
}
