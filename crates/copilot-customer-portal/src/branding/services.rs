//! Port of `app/customer_portal/services/settings.py` and
//! `services/branding.py`: the two branding tables, the one resolver, the
//! logos.
//!
//! Resolution field by field is `copilot_notifications::branding::resolve`
//! (`build_effective_branding`, the definition the notification templates
//! and the temporary-password email already use); this module reads the
//! rows and serves the result through the [`BrandingCache`].

use chrono::{Local, LocalResult, NaiveDateTime, TimeZone, Utc};
use sha2::{Digest, Sha256};
use sqlx::FromRow;

use copilot_auth::pybase64::b64decode_validate;
use copilot_core::time::mysql_datetime;
use copilot_db::schema::TableRequirement;
use copilot_db::{Db, DbError, branding};
use copilot_notifications::branding::resolve;
use copilot_web::form::py_strip;

use super::cache::BrandingCache;
use super::schema::{BrandingFields, EffectiveBranding, PatchPortalSettingsRequest};

/// Relative to the API root, like every path the portal's HTTP client calls.
pub const LOGO_PATH: &str = "/customer_portal/settings/logo";
/// The authenticated logo of the resolved branding.
pub const EFFECTIVE_LOGO_PATH: &str = "/customer_portal/settings/effective/logo";
/// `CustomerPortalSettings.get_default_values()["title"]`.
pub const DEFAULT_TITLE: &str = "CoPilot";

/// Columns this module reads and writes.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "customer_portal_settings",
        columns: &[
            "id",
            "title",
            "logo_base64",
            "logo_mime_type",
            "brand_color",
            "updated_at",
            "updated_by",
        ],
    },
    TableRequirement {
        table: "customer_portal_branding",
        columns: &[
            "id",
            "customer_code",
            "enabled",
            "title",
            "logo_base64",
            "logo_mime_type",
            "brand_color",
            "updated_at",
            "updated_by",
        ],
    },
];

const SETTINGS_COLS: &str =
    "id, title, logo_base64, logo_mime_type, brand_color, updated_at, updated_by";
const OVERRIDE_COLS: &str = "id, customer_code, enabled, title, logo_base64, logo_mime_type, \
                             brand_color, updated_at, updated_by";

/// A `customer_portal_settings` row.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct SettingsRow {
    /// Row id.
    pub id: i32,
    /// Title.
    pub title: String,
    /// Logo, base64.
    pub logo_base64: Option<String>,
    /// Its MIME type.
    pub logo_mime_type: Option<String>,
    /// Colour.
    pub brand_color: Option<String>,
    /// Last save (naive UTC).
    pub updated_at: NaiveDateTime,
    /// Who saved it.
    pub updated_by: Option<i32>,
}

/// A `customer_portal_branding` row.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct OverrideRow {
    /// Row id.
    pub id: i32,
    /// Customer.
    pub customer_code: String,
    /// The switch.
    pub enabled: bool,
    /// Title.
    pub title: Option<String>,
    /// Logo, base64.
    pub logo_base64: Option<String>,
    /// Its MIME type.
    pub logo_mime_type: Option<String>,
    /// Colour.
    pub brand_color: Option<String>,
    /// Last save (naive UTC).
    pub updated_at: NaiveDateTime,
    /// Who saved it.
    pub updated_by: Option<i32>,
}

/// `get_global_settings`: `select(CustomerPortalSettings).limit(1)`.
pub async fn global_settings(db: &Db) -> Result<Option<SettingsRow>, DbError> {
    Ok(sqlx::query_as::<_, SettingsRow>(&format!(
        "SELECT {SETTINGS_COLS} FROM customer_portal_settings LIMIT 1"
    ))
    .fetch_optional(db.pool())
    .await?)
}

/// What `get_public_portal_settings` reads: no logo, only its length.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct PublicRow {
    /// Row id.
    pub id: i32,
    /// Title.
    pub title: String,
    /// The logo's MIME type.
    pub logo_mime_type: Option<String>,
    /// Colour.
    pub brand_color: Option<String>,
    /// Last save.
    pub updated_at: NaiveDateTime,
    /// `coalesce(length(logo_base64), 0)`.
    pub logo_length: i64,
}

/// `get_public_portal_settings`'s statement.
pub async fn public_settings(db: &Db) -> Result<Option<PublicRow>, DbError> {
    Ok(sqlx::query_as::<_, PublicRow>(
        "SELECT id, title, logo_mime_type, brand_color, updated_at, \
         CAST(coalesce(length(logo_base64), 0) AS SIGNED) AS logo_length \
         FROM customer_portal_settings LIMIT 1",
    )
    .fetch_optional(db.pool())
    .await?)
}

/// The four fields of the global row as they will be written.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GlobalValues {
    title: String,
    logo_base64: Option<String>,
    logo_mime_type: Option<String>,
    brand_color: Option<String>,
}

impl GlobalValues {
    /// `create_default()`.
    fn defaults() -> Self {
        Self {
            title: DEFAULT_TITLE.into(),
            logo_base64: None,
            logo_mime_type: None,
            brand_color: None,
        }
    }

    fn of(row: &SettingsRow) -> Self {
        Self {
            title: row.title.clone(),
            logo_base64: row.logo_base64.clone(),
            logo_mime_type: row.logo_mime_type.clone(),
            brand_color: row.brand_color.clone(),
        }
    }
}

/// Write the global row (the first one, or a new one), `updated_by` and
/// `updated_at` stamped; one transaction, as the session's.
async fn write_global(
    db: &Db,
    edit: impl FnOnce(Option<&SettingsRow>) -> GlobalValues,
    user_id: i32,
    now: NaiveDateTime,
) -> Result<(), DbError> {
    let mut tx = db.pool().begin().await?;
    let row = sqlx::query_as::<_, SettingsRow>(&format!(
        "SELECT {SETTINGS_COLS} FROM customer_portal_settings LIMIT 1"
    ))
    .fetch_optional(&mut *tx)
    .await?;
    let values = edit(row.as_ref());
    let query = match &row {
        Some(row) => sqlx::query(
            "UPDATE customer_portal_settings SET title=?, logo_base64=?, logo_mime_type=?, \
             brand_color=?, updated_at=?, updated_by=? WHERE customer_portal_settings.id = ?",
        )
        .bind(values.title)
        .bind(values.logo_base64)
        .bind(values.logo_mime_type)
        .bind(values.brand_color)
        .bind(mysql_datetime(now))
        .bind(user_id)
        .bind(row.id),
        None => sqlx::query(
            "INSERT INTO customer_portal_settings (title, logo_base64, logo_mime_type, \
             brand_color, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(values.title)
        .bind(values.logo_base64)
        .bind(values.logo_mime_type)
        .bind(values.brand_color)
        .bind(mysql_datetime(now))
        .bind(user_id),
    };
    query.execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

/// `replace_global_settings`: every field written, a null one restoring its
/// default.
pub async fn replace_global(
    db: &Db,
    fields: &BrandingFields,
    user_id: i32,
    now: NaiveDateTime,
) -> Result<(), DbError> {
    let defaults = GlobalValues::defaults();
    let values = GlobalValues {
        title: fields.title.clone().unwrap_or(defaults.title),
        logo_base64: fields.logo_base64.clone(),
        logo_mime_type: fields.logo_mime_type.clone(),
        brand_color: fields.brand_color.clone(),
    };
    write_global(db, |_| values, user_id, now).await
}

/// `patch_global_settings`: the fields sent, then the resets.
pub async fn patch_global(
    db: &Db,
    req: &PatchPortalSettingsRequest,
    user_id: i32,
    now: NaiveDateTime,
) -> Result<(), DbError> {
    let edit = |row: Option<&SettingsRow>| {
        let mut values = row.map_or_else(GlobalValues::defaults, GlobalValues::of);
        let f = &req.fields;
        for field in &req.sent {
            match *field {
                "title" => values.title = f.title.clone().unwrap_or_default(),
                "logo_base64" => values.logo_base64 = f.logo_base64.clone(),
                "logo_mime_type" => values.logo_mime_type = f.logo_mime_type.clone(),
                _ => values.brand_color = f.brand_color.clone(),
            }
        }
        for target in &req.reset {
            match *target {
                "title" => values.title = DEFAULT_TITLE.into(),
                "logo" => {
                    values.logo_base64 = None;
                    values.logo_mime_type = None;
                }
                _ => values.brand_color = None,
            }
        }
        values
    };
    write_global(db, edit, user_id, now).await
}

/// `get_branding_override`: a customer's row, enabled or not.
pub async fn override_row(db: &Db, customer_code: &str) -> Result<Option<OverrideRow>, DbError> {
    Ok(sqlx::query_as::<_, OverrideRow>(&format!(
        "SELECT {OVERRIDE_COLS} FROM customer_portal_branding \
         WHERE customer_portal_branding.customer_code = ?"
    ))
    .bind(customer_code)
    .fetch_optional(db.pool())
    .await?)
}

/// `list_branding_overrides` (ordered by customer code), the logo read as
/// `bool(logo_base64)`.
pub async fn list_overrides(
    db: &Db,
    customers: Option<&[String]>,
) -> Result<
    Vec<(
        String,
        bool,
        Option<String>,
        bool,
        Option<String>,
        NaiveDateTime,
    )>,
    DbError,
> {
    let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new(
        "SELECT customer_code, enabled, title, \
         coalesce(length(logo_base64), 0) > 0 AS has_logo, brand_color, updated_at \
         FROM customer_portal_branding",
    );
    if let Some(codes) = customers {
        if codes.is_empty() {
            return Ok(Vec::new());
        }
        qb.push(" WHERE customer_portal_branding.customer_code IN (");
        let mut sep = qb.separated(", ");
        for c in codes {
            sep.push_bind(c.clone());
        }
        qb.push(")");
    }
    qb.push(" ORDER BY customer_portal_branding.customer_code");
    Ok(qb.build_query_as().fetch_all(db.pool()).await?)
}

/// `_normalize`: blank is unset.
fn normalize(value: Option<&str>) -> Option<String> {
    value
        .map(py_strip)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// `upsert_branding_override` then the commit and `session.refresh`: the row
/// as stored.
pub async fn upsert_override(
    db: &Db,
    customer_code: &str,
    enabled: bool,
    fields: &BrandingFields,
    user_id: i32,
    now: NaiveDateTime,
) -> Result<OverrideRow, DbError> {
    let title = normalize(fields.title.as_deref());
    let logo = normalize(fields.logo_base64.as_deref());
    let mime = if logo.is_some() {
        normalize(fields.logo_mime_type.as_deref())
    } else {
        None
    };
    let color = normalize(fields.brand_color.as_deref());
    let mut tx = db.pool().begin().await?;
    let existing = sqlx::query_scalar::<_, i32>(
        "SELECT id FROM customer_portal_branding \
         WHERE customer_portal_branding.customer_code = ?",
    )
    .bind(customer_code)
    .fetch_optional(&mut *tx)
    .await?;
    let id = match existing {
        Some(id) => {
            sqlx::query(
                "UPDATE customer_portal_branding SET enabled=?, title=?, logo_base64=?, \
                 logo_mime_type=?, brand_color=?, updated_at=?, updated_by=? \
                 WHERE customer_portal_branding.id = ?",
            )
            .bind(enabled)
            .bind(title)
            .bind(logo)
            .bind(mime)
            .bind(color)
            .bind(mysql_datetime(now))
            .bind(user_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
            id
        }
        None => {
            let res = sqlx::query(
                "INSERT INTO customer_portal_branding (customer_code, enabled, title, \
                 logo_base64, logo_mime_type, brand_color, updated_at, updated_by) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(customer_code)
            .bind(enabled)
            .bind(title)
            .bind(logo)
            .bind(mime)
            .bind(color)
            .bind(mysql_datetime(now))
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            i32::try_from(res.last_insert_id())
                .map_err(|_| DbError::Config("override id out of range".into()))?
        }
    };
    tx.commit().await?;
    sqlx::query_as::<_, OverrideRow>(&format!(
        "SELECT {OVERRIDE_COLS} FROM customer_portal_branding \
         WHERE customer_portal_branding.id = ?"
    ))
    .bind(id)
    .fetch_optional(db.pool())
    .await?
    .ok_or_else(|| DbError::Config(format!("override {id} vanished after its commit")))
}

/// `delete_branding_override` and the commit: whether there was one.
pub async fn delete_override(db: &Db, customer_code: &str) -> Result<bool, DbError> {
    let Some(row) = override_row(db, customer_code).await? else {
        return Ok(false);
    };
    sqlx::query("DELETE FROM customer_portal_branding WHERE customer_portal_branding.id = ?")
        .bind(row.id)
        .execute(db.pool())
        .await?;
    tracing::info!(customer_code, "deleted customer portal branding override");
    Ok(true)
}

/// One row of the branding tables' fingerprint.
#[derive(Debug, Clone, Default, PartialEq, Eq, FromRow)]
pub struct FingerprintRow {
    /// `s` (settings) or `b` (an override).
    pub kind: String,
    /// Row id.
    pub id: i32,
    /// Customer (overrides).
    pub customer_code: Option<String>,
    /// The switch (overrides).
    pub enabled: Option<i64>,
    /// Title.
    pub title: Option<String>,
    /// The logo's MIME type.
    pub logo_mime_type: Option<String>,
    /// Colour.
    pub brand_color: Option<String>,
    /// Last save.
    pub updated_at: Option<NaiveDateTime>,
    /// The logo's length in characters.
    pub logo_length: Option<i64>,
    /// The logo's CRC-32.
    pub logo_crc: Option<i64>,
}

/// The cache's change check (`services/branding.py:BRANDING_FINGERPRINT`,
/// the same statement): one row per branding row, the logo as its length and
/// CRC-32, so no logo leaves MySQL.
pub async fn fingerprint(db: &Db) -> Result<Vec<FingerprintRow>, DbError> {
    Ok(sqlx::query_as::<_, FingerprintRow>(
        "SELECT 's' AS kind, id, NULL AS customer_code, NULL AS enabled, title, logo_mime_type, \
         brand_color, updated_at, CAST(CHAR_LENGTH(logo_base64) AS SIGNED) AS logo_length, \
         CAST(CRC32(logo_base64) AS SIGNED) AS logo_crc FROM customer_portal_settings \
         UNION ALL \
         SELECT 'b', id, customer_code, CAST(enabled AS SIGNED), title, logo_mime_type, \
         brand_color, updated_at, CAST(CHAR_LENGTH(logo_base64) AS SIGNED), \
         CAST(CRC32(logo_base64) AS SIGNED) FROM customer_portal_branding \
         ORDER BY 1, 2",
    )
    .fetch_all(db.pool())
    .await?)
}

/// `resolve_effective_branding(customer_code)`, through the cache: the
/// global row, then (for a customer) its override.
pub async fn resolve_effective(
    db: &Db,
    cache: &BrandingCache,
    customer_code: Option<&str>,
) -> Result<EffectiveBranding, DbError> {
    cache
        .get_or_load(
            customer_code,
            || async {
                let global = branding::global_settings(db).await?;
                let custom = match customer_code {
                    Some(code) if !code.is_empty() => branding::customer_override(db, code).await?,
                    _ => None,
                };
                let r = resolve(global.as_ref(), custom.as_ref(), customer_code);
                Ok(EffectiveBranding {
                    title: r.branding.title,
                    logo_base64: r.branding.logo_base64,
                    logo_mime_type: r.branding.logo_mime_type,
                    brand_color: r.branding.brand_color,
                    source: r.source.to_string(),
                    customer_code: r.customer_code,
                })
            },
            || fingerprint(db),
        )
        .await
}

/// `resolve_branding_for_user`: a per-customer override only for a user
/// scoped to exactly one customer; several (or the wildcard) read the global
/// defaults.
pub fn branding_customer(accessible: &[String]) -> Option<&str> {
    match accessible {
        [one] if one != "*" => Some(one.as_str()),
        _ => None,
    }
}

/// A logo ready to serve (`PortalLogo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalLogo {
    /// The decoded bytes.
    pub content: Vec<u8>,
    /// Its media type.
    pub mime_type: String,
    /// `"<version>"`.
    pub etag: String,
}

/// `_logo_version`: milliseconds of `updated_at.timestamp()` — a naive value
/// read as the process's local time, as CPython's `datetime.timestamp()` does
/// (fold 0: the earlier of two instants, the offset before a gap). In a
/// container (UTC) that is the UTC epoch.
pub fn logo_version(updated_at: NaiveDateTime) -> String {
    let offset = |t: NaiveDateTime| match Local.offset_from_local_datetime(&t) {
        LocalResult::Single(o) | LocalResult::Ambiguous(o, _) => Some(o.local_minus_utc()),
        LocalResult::None => None,
    };
    let seconds = offset(updated_at)
        .or_else(|| offset(updated_at - chrono::Duration::hours(24)))
        .unwrap_or(0);
    (updated_at - chrono::Duration::seconds(i64::from(seconds)))
        .and_utc()
        .timestamp_millis()
        .to_string()
}

/// `logo_content_version`: the first 16 hex digits of the logo's SHA-256.
pub fn logo_content_version(logo_base64: &str) -> String {
    let digest = Sha256::digest(logo_base64.as_bytes());
    hex::encode(digest)[..16].to_string()
}

/// `decode_logo`: `None` without a logo or when it is not valid base64.
pub fn decode_logo(
    logo_base64: Option<&str>,
    mime_type: Option<&str>,
    version: &str,
) -> Option<PortalLogo> {
    let logo = logo_base64.filter(|l| !l.is_empty())?;
    match b64decode_validate(logo) {
        Ok(content) => Some(PortalLogo {
            content,
            mime_type: mime_type
                .filter(|m| !m.is_empty())
                .unwrap_or("image/png")
                .to_string(),
            etag: format!("\"{version}\""),
        }),
        Err(_) => {
            tracing::error!("Stored customer portal logo is not valid base64");
            None
        }
    }
}

/// `get_portal_logo`: the global logo, versioned by its row's `updated_at`.
pub async fn global_logo(db: &Db) -> Result<Option<PortalLogo>, DbError> {
    Ok(global_settings(db).await?.and_then(|row| {
        decode_logo(
            row.logo_base64.as_deref(),
            row.logo_mime_type.as_deref(),
            &logo_version(row.updated_at),
        )
    }))
}

/// `get_effective_logo_for_user`'s decode: the resolved logo, versioned by
/// its content.
pub fn effective_logo(effective: &EffectiveBranding) -> Option<PortalLogo> {
    let logo = effective.logo_base64.as_deref().filter(|l| !l.is_empty())?;
    decode_logo(
        Some(logo),
        effective.logo_mime_type.as_deref(),
        &logo_content_version(logo),
    )
}

/// `datetime.isoformat()` of a naive value (whole seconds from MySQL; the
/// fraction only when there is one).
pub fn isoformat(t: NaiveDateTime) -> String {
    copilot_core::time::to_pydantic_iso(t)
}

/// `now_utc().isoformat()`: an aware UTC value with its offset.
pub fn aware_now_isoformat() -> String {
    let now = Utc::now();
    let micros = now.timestamp_subsec_micros();
    if micros == 0 {
        now.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()
    } else {
        format!("{}.{micros:06}+00:00", now.format("%Y-%m-%dT%H:%M:%S"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logo_versions() {
        assert_eq!(logo_content_version("iVBORw0KGgo="), {
            let d = Sha256::digest(b"iVBORw0KGgo=");
            hex::encode(d)[..16].to_string()
        });
        let logo = decode_logo(Some("QQ=="), Some(""), "7").unwrap();
        assert_eq!(
            (logo.content, logo.mime_type, logo.etag),
            (b"A".to_vec(), "image/png".to_string(), "\"7\"".to_string())
        );
        assert!(decode_logo(Some("QQ=="), None, "7").is_some());
        assert!(decode_logo(Some(" QQ=="), None, "7").is_none());
        assert!(decode_logo(Some(""), None, "7").is_none());
        assert_eq!(branding_customer(&["a".into()]), Some("a"));
        assert_eq!(branding_customer(&["*".into()]), None);
        assert_eq!(branding_customer(&["a".into(), "a".into()]), None);
    }
}
