//! Re-targeting open items after a policy or calendar save — port of
//! `soc_management/services/lifecycle.py:retarget_open` and `_retarget_row`.
//!
//! Runs in the caller's transaction (the save) and fails with it: unlike a
//! lifecycle action, this *is* the operation the caller asked for. Only
//! clocks still running move; a clock already met or breached keeps the due
//! time it was judged against, and time spent waiting on the customer stays
//! credited.

use chrono::NaiveDateTime;
use copilot_core::time::mysql_datetime;
use sqlx::MySqlConnection;

use crate::SlaError;
use crate::calendar::{CalendarBook, load_all_book};
use crate::lifecycle::retarget_values;
use crate::policy::{PolicyRow, SlaEntity, load_all_rows, resolve_targets};

/// One open tracked row, as `retarget_open` reads it.
#[derive(Debug, Clone, sqlx::FromRow)]
struct OpenRow {
    id: i64,
    customer_code: Option<String>,
    severity: String,
    opened_at: NaiveDateTime,
    ack_due_at: Option<NaiveDateTime>,
    resolve_due_at: Option<NaiveDateTime>,
    first_ack_at: Option<NaiveDateTime>,
    resolved_at: Option<NaiveDateTime>,
    business_hours: bool,
    pause_credit_seconds: i32,
}

/// What `_retarget_row` changes on one row (only what differs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Change {
    ack_due_at: Option<Option<NaiveDateTime>>,
    resolve_due_at: Option<Option<NaiveDateTime>>,
    business_hours: Option<bool>,
}

fn plan(
    row: &OpenRow,
    entity: SlaEntity,
    rows: &[PolicyRow],
    book: &CalendarBook,
) -> Result<Option<Change>, SlaError> {
    let code = row.customer_code.as_deref();
    let targets = resolve_targets(entity, &row.severity, code, rows);
    let ack_running = row.first_ack_at.is_none() && row.resolved_at.is_none();
    let resolve_running = row.resolved_at.is_none();
    if !(ack_running || resolve_running) {
        return Ok(None);
    }
    let (ack, resolve) = retarget_values(
        row.opened_at,
        &targets,
        ack_running,
        resolve_running,
        book.clock(code, targets.business_hours),
        i64::from(row.pause_credit_seconds),
    )?;
    let change = Change {
        ack_due_at: ack.filter(|a| *a != row.ack_due_at),
        resolve_due_at: resolve.filter(|r| *r != row.resolve_due_at),
        business_hours: (targets.business_hours != row.business_hours)
            .then_some(targets.business_hours),
    };
    Ok((change != Change::default()).then_some(change))
}

/// `retarget_open(session, customer_code)`: recompute the running clocks of
/// every open tracked item of a scope (`None`: every customer, each still
/// resolving its own overrides). Returns how many items' due times moved.
pub async fn retarget_open(
    conn: &mut MySqlConnection,
    customer_code: Option<&str>,
    now: NaiveDateTime,
) -> Result<i64, SlaError> {
    let rows = load_all_rows(conn).await?;
    let book = load_all_book(conn).await?;
    let mut moved = 0;
    for (entity, owner) in [
        (SlaEntity::Alert, "incident_management_alert"),
        (SlaEntity::Case, "incident_management_case"),
    ] {
        let table = entity.tracking_table();
        let key = entity.key();
        let mut sql = format!(
            "SELECT t.{key} AS id, o.customer_code, t.severity, t.opened_at, t.ack_due_at, \
             t.resolve_due_at, t.first_ack_at, t.resolved_at, t.business_hours, \
             t.pause_credit_seconds FROM {table} t JOIN {owner} o ON o.id = t.{key} \
             WHERE t.tracked IS TRUE AND t.resolved_at IS NULL"
        );
        if customer_code.is_some() {
            sql.push_str(" AND o.customer_code = ?");
        }
        sql.push_str(&format!(" ORDER BY t.{key}"));
        let mut query = sqlx::query_as::<_, OpenRow>(&sql);
        if let Some(code) = customer_code {
            query = query.bind(code);
        }
        let open = query.fetch_all(&mut *conn).await?;
        for row in &open {
            let Some(change) = plan(row, entity, &rows, &book)? else {
                continue;
            };
            let mut sets: Vec<&str> = Vec::new();
            if change.ack_due_at.is_some() {
                sets.push("ack_due_at = ?");
            }
            if change.resolve_due_at.is_some() {
                sets.push("resolve_due_at = ?");
            }
            if change.business_hours.is_some() {
                sets.push("business_hours = ?");
            }
            sets.push("updated_at = ?");
            let sql = format!("UPDATE {table} SET {} WHERE {key} = ?", sets.join(", "));
            let mut update = sqlx::query(&sql);
            if let Some(ack) = change.ack_due_at {
                update = update.bind(ack.map(mysql_datetime));
            }
            if let Some(resolve) = change.resolve_due_at {
                update = update.bind(resolve.map(mysql_datetime));
            }
            if let Some(bh) = change.business_hours {
                update = update.bind(bh);
            }
            update = update.bind(mysql_datetime(now)).bind(row.id);
            update.execute(&mut *conn).await?;
            moved += 1;
        }
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    fn open_row() -> OpenRow {
        OpenRow {
            id: 1,
            customer_code: Some("acme".into()),
            severity: "High".into(),
            opened_at: at("2026-01-01 10:00:00"),
            ack_due_at: Some(at("2026-01-01 11:00:00")),
            resolve_due_at: Some(at("2026-01-01 18:00:00")),
            first_ack_at: None,
            resolved_at: None,
            business_hours: false,
            pause_credit_seconds: 0,
        }
    }

    #[test]
    fn unchanged_targets_move_nothing() {
        let book = CalendarBook::default();
        assert_eq!(
            plan(&open_row(), SlaEntity::Alert, &[], &book).unwrap(),
            None
        );
    }

    #[test]
    fn only_running_clocks_move_and_credit_is_kept() {
        let book = CalendarBook::default();
        let rows = vec![PolicyRow {
            customer_code: Some("acme".into()),
            entity: SlaEntity::Alert,
            severity: "High".into(),
            ack_minutes: Some(30),
            resolve_minutes: Some(120),
            business_hours: false,
        }];
        let mut acked = open_row();
        acked.first_ack_at = Some(at("2026-01-01 10:05:00"));
        acked.pause_credit_seconds = 600;
        let change = plan(&acked, SlaEntity::Alert, &rows, &book)
            .unwrap()
            .unwrap();
        assert_eq!(
            change.ack_due_at, None,
            "an acknowledged clock keeps its due time"
        );
        assert_eq!(change.resolve_due_at, Some(Some(at("2026-01-01 12:10:00"))));
        assert_eq!(change.business_hours, None);
    }
}
