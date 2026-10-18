//! `app/connectors/sublime/services/alerts.py`.
//!
//! **The store** (`store_sublime_alert`) is the ORM's work, statement for
//! statement: the alert's `INSERT` at the `flush()`, then — the transaction
//! still open — the sender and the recipient, each read with its own
//! `GET /v0/messages/{message_id}` (`data.sender.email`,
//! `data.recipients[0].email`), then at the `commit()` the child rows in the
//! unit of work's order (the tables sorted by name: `flaggedrule`,
//! `mailbox`, `recipient`, `sender`, `triggeredaction`; rows of one table in
//! the order they were added). Whatever fails — a column MySQL refuses, a
//! Sublime that cannot be reached or answers something else, a missing
//! connector row (`'NoneType' object is not subscriptable`) — is rolled back
//! and is the 500 `Failed to store alert {id} in the database: {e}` (an
//! `HTTPException` from the message lookup reads `500: …` there, as its
//! `str()` does).
//!
//! The alert's `timestamp` is the time it arrived (`datetime.now()`, local
//! time). Python's model declares `timestamp = datetime.datetime.now()` as
//! a class default, evaluated once when the module is imported, so every
//! alert a Python process stores carries that process's start time — a §4
//! row.
//!
//! **The listing** (`collect_alerts`) reads every alert, then each
//! relationship with `selectinload`'s statement (`… WHERE
//! <child>.sublime_alert_id IN (…)`, 500 keys at a time, no `ORDER BY`), and
//! validates each alert against `SublimeAlertsSchema`: the first that fails
//! (a `NULL` sender or recipient name — the column is nullable, the schema's
//! `str` is not) is the 500 `Failed to get all Sublime Alerts with error:
//! {ValidationError}`.

use std::collections::HashMap;

use chrono::{NaiveDateTime, Timelike};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::json::{Dumps, py_dumps_allow_nan};
use copilot_upstream::model::{self, Invalid, format_validation_error};
use copilot_upstream::py::{PyExc, getitem, type_name};
use sqlx::Row;

use crate::SublimeState;
use crate::schema::{SUBLIME_ALERTS_SCHEMA, alert_response, alerts_response, dict};
use crate::sql::{Insert, Param, operational};

const ALERT_COLUMNS: &[&str] = &[
    "api_version",
    "created_at",
    "event_id",
    "type",
    "message_id",
    "canonical_id",
    "external_id",
    "message_source_id",
    "timestamp",
];
const FLAGGED_RULE_COLUMNS: &[&str] = &["rule_id", "name", "severity", "tags", "sublime_alert_id"];
const MAILBOX_COLUMNS: &[&str] = &["external_id", "mailbox_id", "sublime_alert_id"];
const PERSON_COLUMNS: &[&str] = &["email", "name", "sublime_alert_id"];
const ACTION_COLUMNS: &[&str] = &["action_id", "name", "type", "sublime_alert_id"];

/// `selectinload`'s chunk size.
const CHUNK: usize = 500;

/// A validated string field of the body's dump.
fn text(v: &PyValue, key: &str) -> String {
    match getitem(v, key) {
        Ok(PyValue::Str(s)) => s.clone(),
        _ => String::new(),
    }
}

/// An `Optional[str]` field of the body's dump.
fn opt_text(v: &PyValue, key: &str) -> Option<String> {
    match getitem(v, key) {
        Ok(PyValue::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

fn items(v: &PyValue, key: &str) -> Vec<PyValue> {
    match getitem(v, key) {
        Ok(PyValue::List(items)) => items.clone(),
        _ => Vec::new(),
    }
}

/// `datetime.datetime.now()` (local time, microseconds).
fn now() -> NaiveDateTime {
    let t = chrono::Local::now().naive_local();
    t.with_nanosecond(t.nanosecond() / 1000 * 1000).unwrap_or(t)
}

/// `value[0]`, as CPython indexes a `json.loads` value.
fn first(value: &PyValue) -> Result<PyValue, PyExc> {
    match value {
        PyValue::List(items) => items
            .first()
            .cloned()
            .ok_or_else(|| PyExc::IndexError("list index out of range".into())),
        // A JSON object's keys are strings: `0` is never one.
        PyValue::Dict(_) => Err(PyExc::KeyError("0".into())),
        PyValue::Str(s) => s
            .chars()
            .next()
            .map(|c| PyValue::Str(c.to_string()))
            .ok_or_else(|| PyExc::IndexError("string index out of range".into())),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not subscriptable",
            type_name(other)
        ))),
    }
}

/// `collect_sender` / `collect_recipient`: the message's details, its
/// `success` checked, then the email.
async fn collect(st: &SublimeState, message_id: &str, recipient: bool) -> Result<PyValue, PyExc> {
    tracing::info!("Getting Sublime Alert with message_id {message_id}");
    let details = st
        .client
        .get(&format!("/v0/messages/{message_id}"))
        .await?
        .unwrap_or(PyValue::None);
    let success = getitem(&details, "success")?;
    if matches!(success, PyValue::Bool(false)) {
        let message = getitem(&details, "message")?.py_str();
        let text = format!("Failed to get Sublime Alert with message_id {message_id}: {message}");
        tracing::error!("{text}");
        return Err(PyExc::http(500, text));
    }
    tracing::info!("Successfully retrieved Sublime Alert with message_id {message_id}");
    email_of(getitem(&details, "data")?, recipient)
}

/// `data["sender"]["email"]` or `data["recipients"][0]["email"]`, as CPython
/// indexes Sublime's answer.
pub fn email_of(data: &PyValue, recipient: bool) -> Result<PyValue, PyExc> {
    Ok(if recipient {
        getitem(&first(getitem(data, "recipients")?)?, "email")?.clone()
    } else {
        getitem(getitem(data, "sender")?, "email")?.clone()
    })
}

/// The child rows `store_sublime_alert` adds, in the unit of work's order.
fn children(body: &PyValue, alert_id: u64, sender: PyValue, recipient: PyValue) -> Vec<Insert> {
    let data = getitem(body, "data").cloned().unwrap_or(PyValue::None);
    let message = getitem(&data, "message").cloned().unwrap_or(PyValue::None);
    let mailbox = getitem(&message, "mailbox")
        .cloned()
        .unwrap_or(PyValue::None);
    let mut out = Vec::new();
    for rule in items(&data, "flagged_rules") {
        let tags = getitem(&rule, "tags")
            .cloned()
            .unwrap_or(PyValue::List(Vec::new()));
        out.push(Insert {
            table: "flaggedrule",
            columns: FLAGGED_RULE_COLUMNS,
            params: vec![
                Param::Text(Some(text(&rule, "id"))),
                Param::Text(Some(text(&rule, "name"))),
                Param::Text(opt_text(&rule, "severity")),
                Param::Text(Some(py_dumps_allow_nan(&tags, Dumps::DEFAULT))),
                Param::Id(alert_id),
            ],
        });
    }
    out.push(Insert {
        table: "mailbox",
        columns: MAILBOX_COLUMNS,
        params: vec![
            Param::Text(opt_text(&mailbox, "external_id")),
            Param::Text(Some(text(&mailbox, "id"))),
            Param::Id(alert_id),
        ],
    });
    for (table, email) in [("recipient", recipient), ("sender", sender)] {
        out.push(Insert {
            table,
            columns: PERSON_COLUMNS,
            params: vec![Param::Json(email), Param::Const("n/a"), Param::Id(alert_id)],
        });
    }
    for action in items(&data, "triggered_actions") {
        out.push(Insert {
            table: "triggeredaction",
            columns: ACTION_COLUMNS,
            params: vec![
                Param::Text(Some(text(&action, "id"))),
                Param::Text(Some(text(&action, "name"))),
                Param::Text(Some(text(&action, "type"))),
                Param::Id(alert_id),
            ],
        });
    }
    out
}

async fn store(st: &SublimeState, body: &PyValue) -> Result<(), PyExc> {
    let data = getitem(body, "data").cloned().unwrap_or(PyValue::None);
    let message = getitem(&data, "message").cloned().unwrap_or(PyValue::None);
    let message_id = text(&message, "id");
    let alert = Insert {
        table: "sublimealerts",
        columns: ALERT_COLUMNS,
        params: vec![
            Param::Text(Some(text(body, "api_version"))),
            Param::Text(Some(text(body, "created_at"))),
            Param::Text(Some(text(body, "id"))),
            Param::Text(Some(text(body, "type"))),
            Param::Text(Some(message_id.clone())),
            Param::Text(Some(text(&message, "canonical_id"))),
            Param::Text(opt_text(&message, "external_id")),
            Param::Text(Some(text(&message, "message_source_id"))),
            Param::Time(now()),
        ],
    };
    let mut tx = st
        .ctx
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| operational(&e))?;
    let outcome = async {
        let alert_id = alert.run(&mut tx).await?;
        let sender = collect(st, &message_id, false).await?;
        let recipient = collect(st, &message_id, true).await?;
        tracing::info!(
            "Preparing to store: id={alert_id} event_id={}",
            text(body, "id")
        );
        for row in children(body, alert_id, sender, recipient) {
            row.run(&mut tx).await?;
        }
        Ok::<(), PyExc>(())
    }
    .await;
    match outcome {
        Ok(()) => tx.commit().await.map_err(|e| operational(&e)),
        Err(e) => {
            let _ = tx.rollback().await;
            Err(e)
        }
    }
}

/// `store_sublime_alert(session, alert_request_body)`: the answer, or the
/// 500 `HTTPException`.
pub async fn store_sublime_alert(st: &SublimeState, body: &PyValue) -> Result<PyValue, PyExc> {
    let id = text(body, "id");
    match store(st, body).await {
        Ok(()) => {
            tracing::info!("Alert {id} stored in the database");
            Ok(alert_response(
                true,
                format!("Alert {id} stored in the database"),
            ))
        }
        Err(e) => {
            let text = format!(
                "Failed to store alert {id} in the database: {}",
                e.display()
            );
            tracing::error!("{text}");
            Err(PyExc::http(500, text))
        }
    }
}

fn s(v: String) -> PyValue {
    PyValue::Str(v)
}

fn opt(v: Option<String>) -> PyValue {
    v.map_or(PyValue::None, PyValue::Str)
}

/// One relationship: `selectinload`'s statement for each chunk of keys,
/// the rows grouped by parent in the order MySQL returns them.
async fn related(
    st: &SublimeState,
    table: &str,
    columns: &[&str],
    keys: &[i64],
) -> Result<HashMap<i64, Vec<Vec<Option<String>>>>, PyExc> {
    let mut out: HashMap<i64, Vec<Vec<Option<String>>>> = HashMap::new();
    for chunk in keys.chunks(CHUNK) {
        let select: Vec<String> = std::iter::once(format!(
            "{table}.sublime_alert_id AS {table}_sublime_alert_id"
        ))
        .chain(std::iter::once(format!("{table}.id AS {table}_id")))
        .chain(
            columns
                .iter()
                .map(|c| format!("{table}.{c} AS {table}_{c}")),
        )
        .collect();
        let sql = format!(
            "SELECT {} \nFROM {table} \nWHERE {table}.sublime_alert_id IN ({})",
            select.join(", "),
            vec!["?"; chunk.len()].join(", ")
        );
        let mut q = sqlx::query(&sql).persistent(false);
        for k in chunk {
            q = q.bind(*k);
        }
        let rows = q
            .fetch_all(st.ctx.db.pool())
            .await
            .map_err(|e| operational(&e))?;
        for row in rows {
            let parent: i64 = row.try_get(0).map_err(|e| operational(&e))?;
            let mut values = Vec::with_capacity(columns.len());
            for i in 0..columns.len() {
                values.push(
                    row.try_get::<Option<String>, _>(i + 2)
                        .map_err(|e| operational(&e))?,
                );
            }
            out.entry(parent).or_default().push(values);
        }
    }
    Ok(out)
}

async fn load(st: &SublimeState) -> Result<Vec<PyValue>, PyExc> {
    let rows = sqlx::query(
        "SELECT sublimealerts.id, sublimealerts.api_version, sublimealerts.created_at, \
         sublimealerts.event_id, sublimealerts.type, sublimealerts.message_id, \
         sublimealerts.canonical_id, sublimealerts.external_id, sublimealerts.message_source_id, \
         sublimealerts.timestamp \nFROM sublimealerts",
    )
    .fetch_all(st.ctx.db.pool())
    .await
    .map_err(|e| operational(&e))?;
    let mut alerts = Vec::with_capacity(rows.len());
    for row in &rows {
        let id: i64 = row.try_get(0).map_err(|e| operational(&e))?;
        let mut fields = Vec::with_capacity(9);
        for i in 1..9 {
            fields.push(
                row.try_get::<Option<String>, _>(i)
                    .map_err(|e| operational(&e))?,
            );
        }
        let ts: Option<NaiveDateTime> = row.try_get(9).map_err(|e| operational(&e))?;
        alerts.push((id, fields, ts));
    }
    let mut keys: Vec<i64> = alerts.iter().map(|(id, ..)| *id).collect();
    keys.sort_unstable();
    keys.dedup();
    let empty = HashMap::new();
    let (rules, mailboxes, actions, senders, recipients) = if keys.is_empty() {
        (
            empty.clone(),
            empty.clone(),
            empty.clone(),
            empty.clone(),
            empty,
        )
    } else {
        (
            related(
                st,
                "flaggedrule",
                &["rule_id", "name", "severity", "tags"],
                &keys,
            )
            .await?,
            related(st, "mailbox", &["external_id", "mailbox_id"], &keys).await?,
            related(st, "triggeredaction", &["action_id", "name", "type"], &keys).await?,
            related(st, "sender", &["email", "name"], &keys).await?,
            related(st, "recipient", &["email", "name"], &keys).await?,
        )
    };
    let list = |map: &HashMap<i64, Vec<Vec<Option<String>>>>, id: i64, names: &[&str]| {
        PyValue::List(
            map.get(&id)
                .map(|rows| {
                    rows.iter()
                        .map(|values| {
                            dict(
                                names
                                    .iter()
                                    .zip(values)
                                    .map(|(n, v)| (*n, opt(v.clone())))
                                    .collect(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default(),
        )
    };
    let mut out = Vec::with_capacity(alerts.len());
    for (id, fields, ts) in alerts {
        let mut pairs: Vec<(&str, PyValue)> = ALERT_COLUMNS[..8]
            .iter()
            .zip(fields)
            .map(|(n, v)| (*n, opt(v)))
            .collect();
        pairs.push((
            "timestamp",
            ts.map_or(PyValue::None, |t| {
                s(t.format("%Y-%m-%dT%H:%M:%S%.f").to_string())
            }),
        ));
        pairs.push((
            "flagged_rules",
            list(&rules, id, &["rule_id", "name", "severity", "tags"]),
        ));
        pairs.push((
            "mailbox",
            list(&mailboxes, id, &["external_id", "mailbox_id"]),
        ));
        pairs.push((
            "triggered_actions",
            list(&actions, id, &["action_id", "name", "type"]),
        ));
        pairs.push(("sender", list(&senders, id, &["email", "name"])));
        pairs.push(("recipients", list(&recipients, id, &["email", "name"])));
        let input = dict(pairs);
        match model::validate(&SUBLIME_ALERTS_SCHEMA, &input) {
            Ok(dump) => out.push(dump),
            Err(Invalid::Errors(errors)) => {
                return Err(PyExc::Validation(format_validation_error(
                    SUBLIME_ALERTS_SCHEMA.name,
                    &errors,
                )));
            }
            Err(Invalid::Abort(status, detail)) => return Err(PyExc::http(status, detail)),
        }
    }
    Ok(out)
}

/// `collect_alerts(session)`: the answer, or the 500 `HTTPException`.
pub async fn collect_alerts(st: &SublimeState) -> Result<PyValue, PyExc> {
    tracing::info!("Getting all Sublime Alerts");
    match load(st).await {
        Ok(alerts) => {
            tracing::info!("Successfully retrieved all Sublime Alerts");
            Ok(alerts_response(alerts))
        }
        Err(e) => {
            let text = format!(
                "Failed to get all Sublime Alerts with error: {}",
                e.display()
            );
            tracing::error!("{text}");
            Err(PyExc::http(500, text))
        }
    }
}
