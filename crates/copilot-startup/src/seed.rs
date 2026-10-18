//! The startup's rows, step by step as `app/db/db_setup.py` and its callees
//! write them.
//!
//! Every step is Python's check-then-insert: a row is looked up by its key
//! (case-insensitively, as MySQL's collation compares) and inserted when
//! missing, existing rows left alone but for the two updates Python makes (a
//! connector that gained an extra-data field, an integration whose
//! instructions were the placeholder) and the job intervals it resets. None
//! of these tables has a unique key, so two processes seeding at once could
//! both insert: every CoPilot process — the Python backend too
//! (`app/db/startup_lock.py`) — seeds under the startup lock
//! ([`copilot_migrate::StartupLock`]), which makes the checks race-free.
//! Each step is one transaction, as Python's session is; a failure stops the
//! start where Python's does, and the two steps Python never lets fail (the
//! templates, the portal settings) only log.

use std::collections::HashSet;

use copilot_core::env::EnvFile;
use copilot_core::time::now_utc_naive;
use copilot_db::Db;
use sqlx::{MySql, Transaction};

use crate::catalog::{
    CONNECTORS, DELETED_CONNECTORS, INTEGRATION_AUTH_KEYS, INTEGRATIONS, KNOWN_JOBS,
    NETWORK_CONNECTOR_AUTH_KEYS, NETWORK_CONNECTORS, NO_INSTRUCTIONS, ROLES,
};
use crate::markdown;
use crate::templates::BUILTIN_TEMPLATES;

/// A step that failed, and why.
#[derive(Debug, thiserror::Error)]
#[error("{step}: {message}")]
pub struct SeedError {
    /// The Python function the step ports.
    pub step: &'static str,
    /// The failure.
    pub message: String,
}

fn fail(step: &'static str) -> impl Fn(sqlx::Error) -> SeedError {
    move |e| SeedError {
        step,
        message: e.to_string(),
    }
}

async fn first_id(
    tx: &mut Transaction<'_, MySql>,
    sql: &str,
    key: &str,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(sql)
        .bind(key)
        .fetch_optional(&mut **tx)
        .await
}

/// `add_connectors` (`add_connectors_if_not_exist`): each connector of the
/// catalog inserted when no row has its name, in the catalog's order; an
/// existing row whose connector gained an extra-data field is flagged as
/// accepting it (its value left alone). Returns the names inserted.
pub async fn add_connectors(db: &Db, env: &EnvFile) -> Result<Vec<&'static str>, SeedError> {
    const STEP: &str = "add_connectors";
    let mut tx = db.pool().begin().await.map_err(fail(STEP))?;
    let mut added = Vec::new();
    for spec in CONNECTORS {
        let existing: Option<(i64, bool)> = sqlx::query_as(
            "SELECT id, connector_accepts_extra_data FROM connectors WHERE connector_name = ? \
             LIMIT 1",
        )
        .bind(spec.name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(fail(STEP))?;
        match existing {
            None => {
                let row = spec.row(env);
                sqlx::query(
                    "INSERT INTO connectors (connector_name, connector_type, connector_url, \
                     connector_last_updated, connector_username, connector_password, \
                     connector_api_key, connector_description, connector_supports, \
                     connector_configured, connector_verified, connector_accepts_host_only, \
                     connector_accepts_api_key, connector_accepts_username_password, \
                     connector_accepts_file, connector_accepts_extra_data, connector_extra_data, \
                     connector_enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, 0)",
                )
                .bind(row.name)
                .bind(row.kind)
                .bind(&row.url)
                .bind(now_utc_naive())
                .bind(&row.username)
                .bind(&row.password)
                .bind(&row.api_key)
                .bind(row.description)
                .bind(&row.supports)
                .bind(row.verified)
                .bind(row.accepts_host_only)
                .bind(row.accepts_api_key)
                .bind(row.accepts_username_password)
                .bind(row.accepts_file)
                .bind(row.accepts_extra_data)
                .bind(&row.extra_data)
                .execute(&mut *tx)
                .await
                .map_err(fail(STEP))?;
                tracing::info!("Added new connector: {}", spec.name);
                added.push(spec.name);
            }
            Some((id, accepts)) if spec.extra_data_key.is_some() && !accepts => {
                sqlx::query("UPDATE connectors SET connector_accepts_extra_data = 1 WHERE id = ?")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(fail(STEP))?;
                tracing::info!("Connector {} now accepts extra data", spec.name);
            }
            Some(_) => {}
        }
    }
    tx.commit().await.map_err(fail(STEP))?;
    Ok(added)
}

/// `delete_connectors` (`delete_connectors_if_exist`): the first row of each
/// retired connector's name deleted. Returns the names deleted.
pub async fn delete_connectors(db: &Db) -> Result<Vec<&'static str>, SeedError> {
    const STEP: &str = "delete_connectors";
    let mut tx = db.pool().begin().await.map_err(fail(STEP))?;
    let mut deleted = Vec::new();
    for name in DELETED_CONNECTORS {
        let id = first_id(
            &mut tx,
            "SELECT id FROM connectors WHERE connector_name = ? LIMIT 1",
            name,
        )
        .await
        .map_err(fail(STEP))?;
        if let Some(id) = id {
            sqlx::query("DELETE FROM connectors WHERE id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(fail(STEP))?;
            tracing::info!("Deleted connector: {name}");
            deleted.push(*name);
        }
    }
    tx.commit().await.map_err(fail(STEP))?;
    Ok(deleted)
}

/// `create_roles` (`add_roles_if_not_exist`): each role inserted with its
/// fixed id when no role has its name (an id another role holds is the
/// insert's error, as in Python).
pub async fn create_roles(db: &Db) -> Result<Vec<&'static str>, SeedError> {
    const STEP: &str = "create_roles";
    let mut tx = db.pool().begin().await.map_err(fail(STEP))?;
    let mut added = Vec::new();
    for (id, name, description) in ROLES {
        let found = first_id(&mut tx, "SELECT id FROM role WHERE name = ? LIMIT 1", name)
            .await
            .map_err(fail(STEP))?;
        if found.is_none() {
            sqlx::query("INSERT INTO role (id, name, description) VALUES (?, ?, ?)")
                .bind(id)
                .bind(name)
                .bind(description)
                .execute(&mut *tx)
                .await
                .map_err(fail(STEP))?;
            tracing::info!("Added new role: {name}");
            added.push(*name);
        }
    }
    tx.commit().await.map_err(fail(STEP))?;
    Ok(added)
}

/// The table names of a catalog (integrations or network connectors).
struct CatalogTables {
    step: &'static str,
    table: &'static str,
    name_col: &'static str,
    details_col: &'static str,
    keys_table: &'static str,
    keys_fk: &'static str,
    keys_name_col: &'static str,
    items: &'static [(&'static str, &'static str)],
    keys: &'static [(&'static str, &'static str)],
    details: fn(&str) -> Option<&'static str>,
    /// Whether an existing row holding the placeholder gets the instructions
    /// (integrations only, as in Python).
    refresh_placeholder: bool,
}

const INTEGRATION_TABLES: CatalogTables = CatalogTables {
    step: "create_available_integrations",
    table: "available_integrations",
    name_col: "integration_name",
    details_col: "integration_details",
    keys_table: "available_integrations_auth_keys",
    keys_fk: "integration_id",
    keys_name_col: "integration_name",
    items: INTEGRATIONS,
    keys: INTEGRATION_AUTH_KEYS,
    details: markdown::integration_details,
    refresh_placeholder: true,
};

const NETWORK_TABLES: CatalogTables = CatalogTables {
    step: "create_available_network_connectors",
    table: "available_network_connectors",
    name_col: "network_connector_name",
    details_col: "network_connector_details",
    keys_table: "available_network_connectors_keys",
    keys_fk: "network_connector_id",
    keys_name_col: "network_connector_name",
    items: NETWORK_CONNECTORS,
    keys: NETWORK_CONNECTOR_AUTH_KEYS,
    details: markdown::network_connector_details,
    refresh_placeholder: false,
};

/// What a catalog step inserted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CatalogOutcome {
    /// Entries inserted.
    pub added: Vec<&'static str>,
    /// Entries whose placeholder was replaced by their instructions.
    pub refreshed: Vec<&'static str>,
    /// `(entry, key)` pairs inserted.
    pub keys_added: Vec<(&'static str, &'static str)>,
}

async fn seed_catalog(db: &Db, t: &CatalogTables) -> Result<CatalogOutcome, SeedError> {
    let step = t.step;
    let mut out = CatalogOutcome::default();
    // `add_available_*_if_not_exist`: its own commit.
    let mut tx = db.pool().begin().await.map_err(fail(step))?;
    let lookup = format!(
        "SELECT id, {} FROM {} WHERE {} = ? LIMIT 1",
        t.details_col, t.table, t.name_col
    );
    for (name, description) in t.items {
        let existing: Option<(i64, String)> = sqlx::query_as(&lookup)
            .bind(name)
            .fetch_optional(&mut *tx)
            .await
            .map_err(fail(step))?;
        match existing {
            None => {
                let details = (t.details)(name).unwrap_or(NO_INSTRUCTIONS);
                sqlx::query(&format!(
                    "INSERT INTO {} ({}, description, {}) VALUES (?, ?, ?)",
                    t.table, t.name_col, t.details_col
                ))
                .bind(name)
                .bind(description)
                .bind(details)
                .execute(&mut *tx)
                .await
                .map_err(fail(step))?;
                tracing::info!("Added new available entry: {name}");
                out.added.push(*name);
            }
            Some((id, details)) if t.refresh_placeholder && details == NO_INSTRUCTIONS => {
                if let Some(found) = (t.details)(name) {
                    sqlx::query(&format!(
                        "UPDATE {} SET {} = ? WHERE id = ?",
                        t.table, t.details_col
                    ))
                    .bind(found)
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(fail(step))?;
                    tracing::info!("Updated integration details for {name}");
                    out.refreshed.push(*name);
                }
            }
            Some(_) => {}
        }
    }
    tx.commit().await.map_err(fail(step))?;

    // `add_available_*_auth_keys_if_not_exist`: the pairs whose entry exists
    // (`get_available_*_auth_keys_list`), each inserted when its entry has no
    // key of that name; one commit.
    let mut tx = db.pool().begin().await.map_err(fail(step))?;
    let id_of = format!(
        "SELECT id FROM {} WHERE {} = ? LIMIT 1",
        t.table, t.name_col
    );
    let mut pairs = Vec::new();
    for (name, key) in t.keys {
        if let Some(id) = first_id(&mut tx, &id_of, name).await.map_err(fail(step))? {
            if id != 0 {
                pairs.push((*name, *key));
            }
        }
    }
    let key_lookup = format!(
        "SELECT id FROM {} WHERE {} = ? AND auth_key_name = ? LIMIT 1",
        t.keys_table, t.keys_fk
    );
    let insert_key = format!(
        "INSERT INTO {} ({}, {}, auth_key_name) VALUES (?, ?, ?)",
        t.keys_table, t.keys_fk, t.keys_name_col
    );
    for (name, key) in pairs {
        let Some(entry) = first_id(&mut tx, &id_of, name).await.map_err(fail(step))? else {
            continue;
        };
        let existing: Option<i64> = sqlx::query_scalar(&key_lookup)
            .bind(entry)
            .bind(key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(fail(step))?;
        if existing.is_none() {
            sqlx::query(&insert_key)
                .bind(entry)
                .bind(name)
                .bind(key)
                .execute(&mut *tx)
                .await
                .map_err(fail(step))?;
            tracing::info!("Added new available auth key: {key} for {name}");
            out.keys_added.push((name, key));
        }
    }
    tx.commit().await.map_err(fail(step))?;
    Ok(out)
}

/// `create_available_integrations`.
pub async fn create_available_integrations(db: &Db) -> Result<CatalogOutcome, SeedError> {
    seed_catalog(db, &INTEGRATION_TABLES).await
}

/// `create_available_network_connectors`.
pub async fn create_available_network_connectors(db: &Db) -> Result<CatalogOutcome, SeedError> {
    seed_catalog(db, &NETWORK_TABLES).await
}

/// `seed_builtin_templates`: every built-in whose name no built-in row has,
/// in one commit. Never fails the start: a failure is a warning and `0`.
pub async fn seed_builtin_templates(db: &Db) -> usize {
    match try_seed_templates(db).await {
        Ok(added) => {
            if added > 0 {
                tracing::info!("Seeded {added} built-in notification template(s).");
            }
            added
        }
        Err(e) => {
            tracing::warn!("Could not seed built-in notification templates: {e}");
            0
        }
    }
}

async fn try_seed_templates(db: &Db) -> Result<usize, sqlx::Error> {
    let mut tx = db.pool().begin().await?;
    let existing: HashSet<String> =
        sqlx::query_scalar("SELECT name FROM notification_template WHERE is_default IS true")
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .collect();
    let mut added = 0;
    for t in BUILTIN_TEMPLATES {
        if existing.contains(t.name) {
            continue;
        }
        sqlx::query(
            "INSERT INTO notification_template (name, description, `trigger`, format, \
             subject_template, body_template, customer_code, is_default, created_by, created_at, \
             updated_at) VALUES (?, ?, ?, ?, ?, ?, NULL, 1, 'system', ?, NULL)",
        )
        .bind(t.name)
        .bind(t.description)
        .bind(t.trigger)
        .bind(t.format)
        .bind(t.subject_template)
        .bind(t.body_template)
        .bind(now_utc_naive())
        .execute(&mut *tx)
        .await?;
        added += 1;
    }
    if added > 0 {
        tx.commit().await?;
    }
    Ok(added)
}

/// `ensure_default_portal_settings`: the global row with its defaults when
/// the table has none. Never fails the start.
pub async fn ensure_default_portal_settings(db: &Db) -> bool {
    let run = async {
        let mut tx = db.pool().begin().await?;
        let any: Option<i64> =
            sqlx::query_scalar("SELECT id FROM customer_portal_settings LIMIT 1")
                .fetch_optional(&mut *tx)
                .await?;
        if any.is_some() {
            return Ok::<bool, sqlx::Error>(false);
        }
        sqlx::query(
            "INSERT INTO customer_portal_settings (title, logo_mime_type, updated_at, updated_by, \
             logo_base64, brand_color) VALUES ('CoPilot', NULL, ?, NULL, NULL, NULL)",
        )
        .bind(now_utc_naive())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    };
    match run.await {
        Ok(created) => {
            if created {
                tracing::info!("Created default customer portal settings");
            }
            created
        }
        Err(e) => {
            tracing::error!("Failed to ensure default customer portal settings: {e}");
            false
        }
    }
}

/// `initialize_job_metadata` (what `init_scheduler()` seeds whoever runs the
/// jobs): each known job's row inserted enabled when missing, an existing
/// row's interval reset (its `enabled` flag kept: every known job can be
/// handed over, and a disabled row is how). Two rows for one job is
/// `one_or_none()`'s `MultipleResultsFound`, as in Python. Returns the jobs
/// inserted.
pub async fn initialize_job_metadata(db: &Db) -> Result<Vec<&'static str>, SeedError> {
    const STEP: &str = "initialize_job_metadata";
    let mut tx = db.pool().begin().await.map_err(fail(STEP))?;
    let mut added = Vec::new();
    for job in KNOWN_JOBS {
        let rows: Vec<(i64, i64)> =
            sqlx::query_as("SELECT id, time_interval FROM scheduled_job_metadata WHERE job_id = ?")
                .bind(job.job_id)
                .fetch_all(&mut *tx)
                .await
                .map_err(fail(STEP))?;
        match rows.as_slice() {
            [] => {
                sqlx::query(
                    "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, \
                     extra_data, enabled, job_description) VALUES (?, NULL, ?, NULL, 1, ?)",
                )
                .bind(job.job_id)
                .bind(job.time_interval)
                .bind(job.description)
                .execute(&mut *tx)
                .await
                .map_err(fail(STEP))?;
                added.push(job.job_id);
            }
            [(id, interval)] => {
                if *interval != job.time_interval {
                    sqlx::query("UPDATE scheduled_job_metadata SET time_interval = ? WHERE id = ?")
                        .bind(job.time_interval)
                        .bind(id)
                        .execute(&mut *tx)
                        .await
                        .map_err(fail(STEP))?;
                }
            }
            _ => {
                return Err(SeedError {
                    step: STEP,
                    message: "Multiple rows were found when one or none was required".into(),
                });
            }
        }
    }
    tx.commit().await.map_err(fail(STEP))?;
    Ok(added)
}
