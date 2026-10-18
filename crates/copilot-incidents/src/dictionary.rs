//! Writes of the ingest field dictionaries (`incident_management_fieldname`,
//! `…assetfieldname`, `…timestampfieldname`, `…alerttitlefieldname`,
//! `…iocfieldname`) — `add_*_name`, `replace_*_name`, `delete_*_name` of
//! `app/incidents/services/db_operations.py`.
//!
//! The quirks are Python's and kept: a delete looks its row up with
//! `scalar_one_or_none()`, so a duplicated entry is a 500; each `replace_*`
//! commits on its own; and the routes that hit a `TypeError` in Python
//! (`replace_ioc_name(…, None)`, `delete_ioc_name(ioc_value=…)`) still fail
//! with a 500 after the same writes.

use sqlx::MySqlConnection;

use copilot_db::Db;
use copilot_web::ApiError;

use crate::config::FieldTable;
use crate::requests::FieldAndAssetNames;

fn internal(e: sqlx::Error) -> ApiError {
    ApiError::internal(e)
}

/// `add_*_name`: insert unless the (source, name) pair exists.
async fn add(
    conn: &mut MySqlConnection,
    table: FieldTable,
    source: &str,
    name: &str,
) -> Result<(), sqlx::Error> {
    let t = table.table();
    let exists: Option<(i32,)> = sqlx::query_as(&format!(
        "SELECT id FROM {t} WHERE source = ? AND field_name = ? LIMIT 1"
    ))
    .bind(source)
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;
    if exists.is_none() {
        sqlx::query(&format!(
            "INSERT INTO {t} (source, field_name) VALUES (?, ?)"
        ))
        .bind(source)
        .bind(name)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// `delete_*_name`'s lookup: the one matching row (`MultipleResultsFound`
/// → 500), deleted when present.
async fn delete_one(
    conn: &mut MySqlConnection,
    table: FieldTable,
    source: &str,
    name: Option<&str>,
) -> Result<(), ApiError> {
    let t = table.table();
    let ids: Vec<(i32,)> = match name {
        Some(name) => sqlx::query_as(&format!(
            "SELECT id FROM {t} WHERE source = ? AND field_name = ?"
        ))
        .bind(source)
        .bind(name)
        .fetch_all(&mut *conn)
        .await
        .map_err(internal)?,
        // `field_name == None` renders `IS NULL`; the column is NOT NULL.
        None => Vec::new(),
    };
    match ids.as_slice() {
        [] => Ok(()),
        [(id,)] => {
            sqlx::query(&format!("DELETE FROM {t} WHERE id = ?"))
                .bind(id)
                .execute(&mut *conn)
                .await
                .map_err(internal)?;
            Ok(())
        }
        _ => Err(ApiError::internal(format!(
            "MultipleResultsFound: {t} {source}/{name:?}"
        ))),
    }
}

/// `POST /fields-assets-title-and-timefield`.
pub async fn create(db: &Db, n: &FieldAndAssetNames) -> Result<(), ApiError> {
    let mut tx = db.pool().begin().await.map_err(internal)?;
    for name in &n.field_names {
        add(&mut tx, FieldTable::Field, &n.source, name)
            .await
            .map_err(internal)?;
    }
    add(&mut tx, FieldTable::Asset, &n.source, &n.asset_name)
        .await
        .map_err(internal)?;
    add(&mut tx, FieldTable::Timestamp, &n.source, &n.timefield_name)
        .await
        .map_err(internal)?;
    add(
        &mut tx,
        FieldTable::AlertTitle,
        &n.source,
        &n.alert_title_name,
    )
    .await
    .map_err(internal)?;
    for name in n.ioc_field_names.iter().flatten() {
        add(&mut tx, FieldTable::Ioc, &n.source, name)
            .await
            .map_err(internal)?;
    }
    tx.commit().await.map_err(internal)
}

async fn replace_list(
    db: &Db,
    table: FieldTable,
    source: &str,
    names: &[String],
) -> Result<(), ApiError> {
    let mut tx = db.pool().begin().await.map_err(internal)?;
    sqlx::query(&format!("DELETE FROM {} WHERE source = ?", table.table()))
        .bind(source)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    for name in names {
        add(&mut tx, table, source, name).await.map_err(internal)?;
    }
    tx.commit().await.map_err(internal)
}

async fn replace_value(
    db: &Db,
    table: FieldTable,
    source: &str,
    name: &str,
) -> Result<(), ApiError> {
    sqlx::query(&format!(
        "UPDATE {} SET field_name = ? WHERE source = ?",
        table.table()
    ))
    .bind(name)
    .bind(source)
    .execute(db.pool())
    .await
    .map_err(internal)?;
    Ok(())
}

/// `PUT /fields-assets-title-and-timefield`: five commits, in Python's order.
pub async fn replace(db: &Db, n: &FieldAndAssetNames) -> Result<(), ApiError> {
    replace_list(db, FieldTable::Field, &n.source, &n.field_names).await?;
    replace_value(db, FieldTable::Asset, &n.source, &n.asset_name).await?;
    replace_value(db, FieldTable::Timestamp, &n.source, &n.timefield_name).await?;
    replace_value(db, FieldTable::AlertTitle, &n.source, &n.alert_title_name).await?;
    match &n.ioc_field_names {
        Some(names) => replace_list(db, FieldTable::Ioc, &n.source, names).await,
        // `for ioc_name in None` — a TypeError once the old rows are staged
        // for deletion; nothing of the IoC step is committed.
        None => Err(ApiError::internal(
            "TypeError: 'NoneType' object is not iterable",
        )),
    }
}

/// `DELETE /delete-fields-assets-title-and-timefield`: one transaction,
/// committed only when no IoC names were sent.
pub async fn delete(db: &Db, n: &FieldAndAssetNames) -> Result<(), ApiError> {
    let mut tx = db.pool().begin().await.map_err(internal)?;
    for name in &n.field_names {
        delete_one(&mut tx, FieldTable::Field, &n.source, Some(name)).await?;
    }
    delete_one(&mut tx, FieldTable::Asset, &n.source, Some(&n.asset_name)).await?;
    delete_one(
        &mut tx,
        FieldTable::Timestamp,
        &n.source,
        Some(&n.timefield_name),
    )
    .await?;
    delete_one(
        &mut tx,
        FieldTable::AlertTitle,
        &n.source,
        Some(&n.alert_title_name),
    )
    .await?;
    if n.ioc_field_names.as_ref().is_some_and(|v| !v.is_empty()) {
        // `delete_ioc_name(ioc_value=…)`: an unexpected keyword argument.
        return Err(ApiError::internal(
            "TypeError: delete_ioc_name() got an unexpected keyword argument 'ioc_value'",
        ));
    }
    tx.commit().await.map_err(internal)
}

/// `DELETE /configured/sources/{source}`: every name the reads report for
/// the source (the first asset / time / title name only), in one commit.
pub async fn delete_source(db: &Db, source: &str) -> Result<(), ApiError> {
    let names = crate::config::source_names(db, source).await?;
    let mut tx = db.pool().begin().await.map_err(internal)?;
    for name in &names.field_names {
        delete_one(&mut tx, FieldTable::Field, source, Some(name)).await?;
    }
    delete_one(
        &mut tx,
        FieldTable::Asset,
        source,
        names.asset_name.as_deref(),
    )
    .await?;
    delete_one(
        &mut tx,
        FieldTable::Timestamp,
        source,
        names.timefield_name.as_deref(),
    )
    .await?;
    delete_one(
        &mut tx,
        FieldTable::AlertTitle,
        source,
        names.alert_title_name.as_deref(),
    )
    .await?;
    for name in &names.ioc_field_names {
        delete_one(&mut tx, FieldTable::Ioc, source, Some(name)).await?;
    }
    tx.commit().await.map_err(internal)
}

/// The deprecated single-name deletes: the lookup runs (a duplicate is a
/// 500) but nothing is committed — Python returns before any commit.
pub async fn deprecated_delete(
    db: &Db,
    table: FieldTable,
    source: &str,
    name: &str,
) -> Result<(), ApiError> {
    let mut tx = db.pool().begin().await.map_err(internal)?;
    delete_one(&mut tx, table, source, Some(name)).await?;
    tx.rollback().await.map_err(internal)
}
