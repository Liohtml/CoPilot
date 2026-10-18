//! The `disabledrule` rows (`app/connectors/wazuh_manager/models/rules.py`):
//! the disabled rules and the level each had.

use copilot_db::{Db, DbError};
use sqlx::FromRow;

/// The table.
pub const TABLE: &str = "disabledrule";

/// The columns this crate reads and writes.
pub const COLUMNS: &[&str] = &[
    "id",
    "rule_id",
    "previous_level",
    "new_level",
    "reason_for_disabling",
    "length_of_time",
    "date_disabled",
    "disabled_by",
];

/// A stored row.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct DisabledRule {
    /// The primary key.
    pub id: i32,
    /// The rule's id.
    pub rule_id: String,
    /// The level it had.
    pub previous_level: String,
    /// The level it was given.
    pub new_level: String,
    /// Why.
    pub reason_for_disabling: String,
    /// For how long.
    pub length_of_time: String,
    /// Who.
    pub disabled_by: String,
}

const SELECT: &str = "SELECT id, rule_id, previous_level, new_level, reason_for_disabling, \
                      length_of_time, disabled_by FROM disabledrule";

/// `select(DisabledRule)`: every row, in the table's order.
pub async fn all(db: &Db) -> Result<Vec<DisabledRule>, DbError> {
    Ok(sqlx::query_as::<_, DisabledRule>(SELECT)
        .fetch_all(db.pool())
        .await?)
}

/// `select(DisabledRule).where(DisabledRule.rule_id == rule_id)…first()`.
pub async fn first_for(db: &Db, rule_id: &str) -> Result<Option<DisabledRule>, DbError> {
    Ok(
        sqlx::query_as::<_, DisabledRule>(&format!("{SELECT} WHERE rule_id = ?"))
            .bind(rule_id)
            .fetch_optional(db.pool())
            .await?,
    )
}

/// What `disable_wazuh_rule` adds.
#[derive(Debug, Clone)]
pub struct NewDisabledRule<'a> {
    /// The rule's id.
    pub rule_id: &'a str,
    /// Its level before (`None` is a `NULL`, which the column refuses).
    pub previous_level: Option<&'a str>,
    /// `NEW_LEVEL`.
    pub new_level: &'a str,
    /// Why.
    pub reason_for_disabling: &'a str,
    /// For how long.
    pub length_of_time: &'a str,
    /// Who (`username.username`).
    pub disabled_by: &'a str,
}

/// `session.add(DisabledRule(…)); await session.commit()`. `date_disabled`
/// is now (Python's default is the time its module was imported).
pub async fn insert(db: &Db, row: &NewDisabledRule<'_>) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO disabledrule (rule_id, previous_level, new_level, reason_for_disabling, \
         length_of_time, date_disabled, disabled_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(row.rule_id)
    .bind(row.previous_level)
    .bind(row.new_level)
    .bind(row.reason_for_disabling)
    .bind(row.length_of_time)
    .bind(chrono::Local::now().naive_local())
    .bind(row.disabled_by)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// `await session.delete(disabled_rule); await session.commit()`.
pub async fn delete(db: &Db, id: i32) -> Result<(), DbError> {
    sqlx::query("DELETE FROM disabledrule WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}
