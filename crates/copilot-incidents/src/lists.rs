//! Alert listings and counts — `list_alerts_*`, `alerts_{total,open,…}_by_*`,
//! `list_alerts_multiple_filters`, `alerts_total_multiple_filters`,
//! `list_alerts_for_user` and `alert_status_counts_for_user`.
//!
//! Every Python count is `len(result.scalars().all())` over the same query
//! (so a join that matches an alert twice counts it twice) or a
//! `count(DISTINCT id)`; the SQL here has the same `FROM`/`JOIN`/`WHERE`.

use chrono::NaiveDateTime;
use sqlx::{MySql, QueryBuilder};

use copilot_db::visibility::AlertVisibility;
use copilot_db::{Db, DbError};

use crate::schema::VERDICT_UNTRIAGED;
use crate::store::{self, ALERT_COLS, AlertRow, push_list, push_page};

/// `StatusCounts`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatusCounts {
    /// Every status.
    pub total: i64,
    /// OPEN.
    pub open: i64,
    /// IN_PROGRESS.
    pub in_progress: i64,
    /// CLOSED.
    pub closed: i64,
    /// PENDING_CUSTOMER.
    pub pending_customer: i64,
}

impl StatusCounts {
    /// `_status_counts`.
    pub fn from_rows(rows: &[(String, i64)]) -> Self {
        let get = |s: &str| {
            rows.iter()
                .rev()
                .find(|(status, _)| status == s)
                .map(|(_, n)| *n)
                .unwrap_or(0)
        };
        Self {
            total: rows.iter().map(|(_, n)| n).sum(),
            open: get("OPEN"),
            in_progress: get("IN_PROGRESS"),
            closed: get("CLOSED"),
            pending_customer: get("PENDING_CUSTOMER"),
        }
    }
}

/// `alert_status_counts_for_user` (visibility already resolved; `None` sees
/// nothing).
pub async fn alert_status_counts(
    db: &Db,
    vis: Option<&AlertVisibility>,
) -> Result<StatusCounts, DbError> {
    let Some(vis) = vis else {
        return Ok(StatusCounts::default());
    };
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT a.status, count(a.id) FROM incident_management_alert a WHERE 1=1",
    );
    vis.push_and(&mut qb, "a");
    qb.push(" GROUP BY a.status");
    Ok(StatusCounts::from_rows(
        &store::status_rows(&mut qb, db).await?,
    ))
}

/// `list_alerts_for_user`.
pub async fn list_for_user(
    db: &Db,
    vis: &AlertVisibility,
    page: i64,
    page_size: i64,
    order: &str,
) -> Result<Vec<AlertRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(format!(
        "SELECT {ALERT_COLS} FROM incident_management_alert a WHERE 1=1"
    ));
    vis.push_and(&mut qb, "a");
    push_page(&mut qb, order, page, page_size);
    store::fetch_alerts(&mut qb, db).await
}

/// `_alert_criteria`'s inputs. Falsy values (`""`, `[]`) are no criterion,
/// as in Python.
#[derive(Debug, Clone, Default)]
pub struct Criteria {
    /// `assigned_to ==`.
    pub assigned_to: Option<String>,
    /// `alert_name LIKE %…%` (wildcards in the value stay wildcards).
    pub alert_title: Option<String>,
    /// `customer_code ==`.
    pub customer_code: Option<String>,
    /// `customer_code IN`.
    pub customer_codes: Option<Vec<String>>,
    /// `source ==`.
    pub source: Option<String>,
    /// `asset_name ==` (joined).
    pub asset_name: Option<String>,
    /// `status ==`.
    pub status: Option<String>,
    /// `tag IN` (joined).
    pub tags: Option<Vec<String>>,
    /// `ioc.value ==` (joined).
    pub ioc_value: Option<String>,
    /// `verdict ==`, or `IS NULL` for `UNTRIAGED`.
    pub verdict: Option<String>,
    /// `verdict_reason ==`.
    pub verdict_reason: Option<String>,
    /// `alert_creation_time >=`.
    pub date_from: Option<NaiveDateTime>,
    /// `alert_creation_time <=`.
    pub date_to: Option<NaiveDateTime>,
}

fn some(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|s| !s.is_empty())
}

fn push_criteria<'a>(qb: &mut QueryBuilder<'a, MySql>, c: &'a Criteria) {
    if let Some(v) = some(&c.assigned_to) {
        qb.push(" AND a.assigned_to = ").push_bind(v);
    }
    if let Some(v) = some(&c.alert_title) {
        qb.push(" AND a.alert_name LIKE ")
            .push_bind(format!("%{v}%"));
    }
    if let Some(v) = some(&c.customer_code) {
        qb.push(" AND a.customer_code = ").push_bind(v);
    }
    if let Some(codes) = c.customer_codes.as_ref().filter(|c| !c.is_empty()) {
        qb.push(" AND a.customer_code IN (");
        push_list(qb, codes.iter().map(String::as_str));
        qb.push(")");
    }
    if let Some(v) = some(&c.source) {
        qb.push(" AND a.source = ").push_bind(v);
    }
    if let Some(v) = some(&c.asset_name) {
        qb.push(" AND s.asset_name = ").push_bind(v);
    }
    if let Some(v) = some(&c.status) {
        qb.push(" AND a.status = ").push_bind(v);
    }
    if let Some(tags) = c.tags.as_ref().filter(|t| !t.is_empty()) {
        qb.push(" AND tg.tag IN (");
        push_list(qb, tags.iter().map(String::as_str));
        qb.push(")");
    }
    if let Some(v) = some(&c.ioc_value) {
        qb.push(" AND i.value = ").push_bind(v);
    }
    if let Some(v) = some(&c.verdict) {
        if v == VERDICT_UNTRIAGED {
            qb.push(" AND a.verdict IS NULL");
        } else {
            qb.push(" AND a.verdict = ").push_bind(v);
        }
    }
    if let Some(v) = some(&c.verdict_reason) {
        qb.push(" AND a.verdict_reason = ").push_bind(v);
    }
    if let Some(v) = c.date_from {
        qb.push(" AND a.alert_creation_time >= ").push_bind(v);
    }
    if let Some(v) = c.date_to {
        qb.push(" AND a.alert_creation_time <= ").push_bind(v);
    }
}

const MULTI_JOINS: &str = " FROM incident_management_alert a \
    LEFT OUTER JOIN incident_management_asset s ON s.alert_linked = a.id \
    LEFT OUTER JOIN incident_management_alert_to_tag att ON att.alert_id = a.id \
    LEFT OUTER JOIN incident_management_alerttag tg ON att.tag_id = tg.id \
    LEFT OUTER JOIN incident_management_alert_to_ioc ati ON ati.alert_id = a.id \
    LEFT OUTER JOIN incident_management_ioc i ON ati.ioc_id = i.id WHERE 1=1";

/// `list_alerts_multiple_filters` (`visibility` given, or none at all).
pub async fn list_multi(
    db: &Db,
    c: &Criteria,
    vis: Option<&AlertVisibility>,
    page: i64,
    page_size: i64,
    order: &str,
) -> Result<Vec<AlertRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(format!("SELECT DISTINCT {ALERT_COLS}{MULTI_JOINS}"));
    push_criteria(&mut qb, c);
    if let Some(vis) = vis {
        vis.push_and(&mut qb, "a");
    }
    push_page(&mut qb, order, page, page_size);
    store::fetch_alerts(&mut qb, db).await
}

/// `alerts_total_multiple_filters`.
pub async fn count_multi(
    db: &Db,
    c: &Criteria,
    vis: Option<&AlertVisibility>,
) -> Result<i64, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(format!("SELECT count(DISTINCT a.id){MULTI_JOINS}"));
    push_criteria(&mut qb, c);
    if let Some(vis) = vis {
        vis.push_and(&mut qb, "a");
    }
    store::count(&mut qb, db).await
}

/// The single-criterion listings of the admin branch of the per-key routes.
#[derive(Debug, Clone, Copy)]
pub enum Key<'a> {
    /// `/alerts/status/{status}` (counts are the deployment's).
    Status(&'a str),
    /// `/alerts/assigned-to/{assigned_to}`.
    AssignedTo(&'a str),
    /// `/alerts/asset/{asset_name}` (joined).
    Asset(&'a str),
    /// `/alerts/title/{title}` (`LIKE`).
    Title(&'a str),
    /// `/alerts/customer/{customer_code}`.
    Customer(&'a str),
    /// `/alerts/source/{source}`.
    Source(&'a str),
    /// `/alert/ioc/{ioc_value}` (joined).
    Ioc(&'a str),
    /// `/alert/tag/{tag}` (joined).
    Tag(&'a str),
}

fn push_key_from<'a>(qb: &mut QueryBuilder<'a, MySql>, key: Key<'a>) {
    match key {
        Key::Asset(name) => {
            qb.push(
                " FROM incident_management_alert a JOIN incident_management_asset s \
                 ON a.id = s.alert_linked WHERE s.asset_name = ",
            )
            .push_bind(name);
        }
        Key::Ioc(value) => {
            qb.push(
                " FROM incident_management_alert a JOIN incident_management_alert_to_ioc ati \
                 ON a.id = ati.alert_id JOIN incident_management_ioc i ON ati.ioc_id = i.id \
                 WHERE i.value = ",
            )
            .push_bind(value);
        }
        Key::Tag(tag) => {
            qb.push(
                " FROM incident_management_alert a JOIN incident_management_alert_to_tag att \
                 ON a.id = att.alert_id JOIN incident_management_alerttag tg \
                 ON att.tag_id = tg.id WHERE tg.tag = ",
            )
            .push_bind(tag);
        }
        Key::Status(status) => {
            qb.push(" FROM incident_management_alert a WHERE a.status = ")
                .push_bind(status);
        }
        Key::AssignedTo(v) => {
            qb.push(" FROM incident_management_alert a WHERE a.assigned_to = ")
                .push_bind(v);
        }
        Key::Title(v) => {
            qb.push(" FROM incident_management_alert a WHERE a.alert_name LIKE ")
                .push_bind(format!("%{v}%"));
        }
        Key::Customer(v) => {
            qb.push(" FROM incident_management_alert a WHERE a.customer_code = ")
                .push_bind(v);
        }
        Key::Source(v) => {
            qb.push(" FROM incident_management_alert a WHERE a.source = ")
                .push_bind(v);
        }
    }
}

/// `list_alert_by_status`, `list_alerts_by_*`.
pub async fn list_by_key(
    db: &Db,
    key: Key<'_>,
    page: i64,
    page_size: i64,
    order: &str,
) -> Result<Vec<AlertRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(format!("SELECT {ALERT_COLS}"));
    push_key_from(&mut qb, key);
    push_page(&mut qb, order, page, page_size);
    store::fetch_alerts(&mut qb, db).await
}

/// `alerts_{total,open,in_progress,closed}_by_<key>`; `/alerts/status`'s
/// admin counts are `alert_total` / `alerts_open` … over every alert.
pub async fn count_by_key(db: &Db, key: Key<'_>, status: Option<&str>) -> Result<i64, DbError> {
    let mut qb = QueryBuilder::<MySql>::new("SELECT count(*)");
    match key {
        Key::Status(_) => {
            qb.push(" FROM incident_management_alert a WHERE 1=1");
        }
        other => push_key_from(&mut qb, other),
    }
    if let Some(s) = status {
        qb.push(" AND a.status = ").push_bind(s);
    }
    store::count(&mut qb, db).await
}

/// The four counts of a per-key admin answer.
pub async fn key_counts(db: &Db, key: Key<'_>) -> Result<[i64; 4], DbError> {
    Ok([
        count_by_key(db, key, None).await?,
        count_by_key(db, key, Some("OPEN")).await?,
        count_by_key(db, key, Some("IN_PROGRESS")).await?,
        count_by_key(db, key, Some("CLOSED")).await?,
    ])
}

/// `alert_total_by_customer_codes` and friends, over a visibility (the
/// scoped branch of the per-key routes): total, open, in progress, closed.
pub async fn visible_counts(db: &Db, vis: Option<&AlertVisibility>) -> Result<[i64; 4], DbError> {
    let Some(vis) = vis else {
        return Ok([0; 4]);
    };
    let mut out = [0; 4];
    for (i, status) in [None, Some("OPEN"), Some("IN_PROGRESS"), Some("CLOSED")]
        .into_iter()
        .enumerate()
    {
        let mut qb = QueryBuilder::<MySql>::new(
            "SELECT count(*) FROM incident_management_alert a WHERE 1=1",
        );
        if let Some(s) = status {
            qb.push(" AND a.status = ").push_bind(s);
        }
        vis.push_and(&mut qb, "a");
        out[i] = store::count(&mut qb, db).await?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_counts_like_python() {
        let rows = vec![
            ("OPEN".to_string(), 3),
            ("CLOSED".to_string(), 2),
            ("weird".to_string(), 1),
        ];
        let c = StatusCounts::from_rows(&rows);
        assert_eq!(
            c,
            StatusCounts {
                total: 6,
                open: 3,
                in_progress: 0,
                closed: 2,
                pending_customer: 0
            }
        );
    }

    #[test]
    fn criteria_render_in_python_order() {
        let c = Criteria {
            alert_title: Some("mimi".into()),
            status: Some("OPEN".into()),
            tags: Some(vec!["a".into()]),
            verdict: Some("UNTRIAGED".into()),
            source: Some(String::new()),
            ..Default::default()
        };
        let mut qb = QueryBuilder::<MySql>::new("SELECT 1 WHERE 1=1");
        push_criteria(&mut qb, &c);
        assert_eq!(
            qb.sql(),
            "SELECT 1 WHERE 1=1 AND a.alert_name LIKE ? AND a.status = ? AND tg.tag IN (?) \
             AND a.verdict IS NULL"
        );
    }
}
