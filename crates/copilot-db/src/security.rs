//! The reads and writes of the admin Security tab
//! (`app/auth/services/security_admin.py`, `temp_password_email.py`): the
//! users bound to a customer, their TOTP state, and the `notification_template`
//! rows scoped to the temporary-password email.

use std::collections::HashMap;

use chrono::NaiveDateTime;
use sqlx::{FromRow, MySql, QueryBuilder};

use crate::schema::TableRequirement;
use crate::users::UserRow;
use crate::{Db, DbError};

/// Columns this module needs.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "notification_template",
        columns: &[
            "id",
            "name",
            "description",
            "trigger",
            "format",
            "subject_template",
            "body_template",
            "customer_code",
            "is_default",
            "created_at",
            "updated_at",
        ],
    },
    TableRequirement {
        table: "user_totp",
        columns: &["user_id", "enabled"],
    },
];

/// `list_customer_users`: the users whose `user_customer_access` names
/// `customer_code` (compared in SQL, under the column's collation). The query
/// has Python's shape — a join, no `ORDER BY` — so MySQL returns the rows in
/// the same order; a user listed twice keeps its first place
/// (`.scalars().unique()`).
pub async fn customer_users(db: &Db, customer_code: &str) -> Result<Vec<UserRow>, DbError> {
    let rows = sqlx::query_as::<_, UserRow>(
        "SELECT `user`.id, `user`.username, `user`.email, `user`.role_id, \
         `user`.created_at, `user`.last_login_at \
         FROM `user` JOIN user_customer_access ON user_customer_access.user_id = `user`.id \
         WHERE user_customer_access.customer_code = ?",
    )
    .bind(customer_code)
    .fetch_all(db.pool())
    .await?;
    let mut seen = std::collections::HashSet::new();
    Ok(rows.into_iter().filter(|u| seen.insert(u.id)).collect())
}

/// `{user_id: bool(enabled)}` for the users that have a `user_totp` row.
pub async fn totp_enabled(db: &Db, user_ids: &[i32]) -> Result<HashMap<i32, bool>, DbError> {
    if user_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let mut q: QueryBuilder<'_, MySql> =
        QueryBuilder::new("SELECT user_id, enabled FROM user_totp WHERE user_id IN (");
    let mut list = q.separated(", ");
    for id in user_ids {
        list.push_bind(*id);
    }
    q.push(")");
    let rows: Vec<(i32, bool)> = q.build_query_as().fetch_all(db.pool()).await?;
    Ok(rows.into_iter().collect())
}

/// `force_reset_totp`: delete the user's TOTP enrolment; `true` when there
/// was one.
pub async fn delete_totp(db: &Db, user_id: i32) -> Result<bool, DbError> {
    let done = sqlx::query("DELETE FROM user_totp WHERE user_id = ?")
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(done.rows_affected() > 0)
}

/// A `notification_template` row.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct TemplateRow {
    /// Primary key.
    pub id: i32,
    /// Display name.
    pub name: String,
    /// Free text.
    pub description: Option<String>,
    /// The trigger it is scoped to; `NULL` = any.
    pub trigger: Option<String>,
    /// `text`, `markdown`, `html` or `json`.
    pub format: String,
    /// Subject template (email-like channels).
    pub subject_template: Option<String>,
    /// Body template.
    pub body_template: String,
    /// `NULL` = shared with every customer.
    pub customer_code: Option<String>,
    /// A seeded built-in.
    pub is_default: bool,
    /// Who created it.
    pub created_by: Option<String>,
    /// Creation time (naive UTC).
    pub created_at: NaiveDateTime,
    /// Last edit (naive UTC).
    pub updated_at: Option<NaiveDateTime>,
}

/// SQLAlchemy's column list for `select(NotificationTemplate)`: the same
/// selected columns give MySQL's filesort the same rows to order, so a
/// same-second tie comes out as it does for the Python query.
const TEMPLATE_COLUMNS: &str = "notification_template.id, notification_template.name, \
     notification_template.description, notification_template.`trigger`, \
     notification_template.format, notification_template.subject_template, \
     notification_template.body_template, notification_template.customer_code, \
     notification_template.is_default, notification_template.created_by, \
     notification_template.created_at, notification_template.updated_at";

/// The templates scoped to `trigger`, newest edit first: Python's query
/// verbatim (`ORDER BY updated_at DESC, created_at DESC`), ties left to
/// MySQL exactly as Python leaves them.
pub async fn templates_for_trigger(db: &Db, trigger: &str) -> Result<Vec<TemplateRow>, DbError> {
    let rows = sqlx::query_as::<_, TemplateRow>(&format!(
        "SELECT {TEMPLATE_COLUMNS} FROM notification_template \
         WHERE notification_template.`trigger` = ? \
         ORDER BY notification_template.updated_at DESC, notification_template.created_at DESC"
    ))
    .bind(trigger)
    .fetch_all(db.pool())
    .await?;
    Ok(rows)
}

/// A template by id.
pub async fn template(db: &Db, id: i64) -> Result<Option<TemplateRow>, DbError> {
    let row = sqlx::query_as::<_, TemplateRow>(&format!(
        "SELECT {TEMPLATE_COLUMNS} FROM notification_template WHERE notification_template.id = ?"
    ))
    .bind(id)
    .fetch_optional(db.pool())
    .await?;
    Ok(row)
}
