//! The Customer Portal branding rows the temporary-password email reads for
//! its `branding` variable: the global `customer_portal_settings` and a
//! customer's `customer_portal_branding` override. Resolution (field by field)
//! is `copilot_identity::services::branding`, as in
//! `app/customer_portal/services/branding.py`.

use sqlx::FromRow;

use crate::schema::TableRequirement;
use crate::{Db, DbError};

/// Columns this module needs.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "customer_portal_settings",
        columns: &["title", "logo_base64", "logo_mime_type", "brand_color"],
    },
    TableRequirement {
        table: "customer_portal_branding",
        columns: &[
            "customer_code",
            "enabled",
            "title",
            "logo_base64",
            "logo_mime_type",
            "brand_color",
        ],
    },
];

/// The branding fields of either table.
#[derive(Debug, Clone, Default, PartialEq, Eq, FromRow)]
pub struct BrandingRow {
    /// `enabled` (the global row has none: `false` there, and unused).
    #[sqlx(default)]
    pub enabled: bool,
    /// Portal title.
    pub title: Option<String>,
    /// Logo, base64 (or a data URI).
    pub logo_base64: Option<String>,
    /// The logo's MIME type.
    pub logo_mime_type: Option<String>,
    /// `#RRGGBB`.
    pub brand_color: Option<String>,
}

/// `get_global_settings`: the first `customer_portal_settings` row, as
/// Python's `select(...).limit(1)` reads it.
pub async fn global_settings(db: &Db) -> Result<Option<BrandingRow>, DbError> {
    let row = sqlx::query_as::<_, BrandingRow>(
        "SELECT title, logo_base64, logo_mime_type, brand_color \
         FROM customer_portal_settings LIMIT 1",
    )
    .fetch_optional(db.pool())
    .await?;
    Ok(row)
}

/// `get_branding_override`: a customer's override, enabled or not.
pub async fn customer_override(
    db: &Db,
    customer_code: &str,
) -> Result<Option<BrandingRow>, DbError> {
    let row = sqlx::query_as::<_, BrandingRow>(
        "SELECT enabled, title, logo_base64, logo_mime_type, brand_color \
         FROM customer_portal_branding WHERE customer_code = ? LIMIT 1",
    )
    .bind(customer_code)
    .fetch_optional(db.pool())
    .await?;
    Ok(row)
}
