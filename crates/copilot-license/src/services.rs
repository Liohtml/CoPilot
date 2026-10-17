//! The licence helpers of `app/middleware/license.py`: the `license` row,
//! the `license_cache` rows, and Python's operations on whatever JSON the
//! licence server answered.
//!
//! Every function runs the statement SQLAlchemy runs (same columns, no
//! `ORDER BY` where Python has none), so MySQL picks the same rows. A
//! database failure is SQLAlchemy's exception, which nothing catches (a bare
//! 500), except where Python catches it.

use chrono::{Duration, NaiveDateTime};
use copilot_auth::pyvalue::{PyValue, float_repr};
use copilot_db::Db;
use copilot_upstream::json::{Dumps, py_dumps_allow_nan};
use copilot_upstream::py::{PyExc, PyResult, get, getitem, iterate, py_eq, type_name};

use crate::client::LicenseClient;

/// `CACHE_DURATION_HOURS`.
pub const CACHE_DURATION_HOURS: i64 = 1;

/// A database failure as SQLAlchemy raises it (nothing catches it: a bare
/// 500).
pub fn db(e: impl Into<copilot_db::DbError>) -> PyExc {
    PyExc::Other("DBAPIError", e.into().to_string())
}

/// A `dict` in the given order.
pub fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// A `str`.
pub fn s(v: impl Into<String>) -> PyValue {
    PyValue::Str(v.into())
}

/// `key in container` for a `json.loads` value: a dict's keys, a list's
/// items, a string's substrings; `TypeError` for the rest.
pub fn contains(container: &PyValue, key: &str) -> PyResult<bool> {
    match container {
        PyValue::Dict(items) => Ok(items.iter().any(|(k, _)| k == key)),
        PyValue::List(items) => Ok(items.iter().any(|v| py_eq(v, &s(key)))),
        PyValue::Str(text) => Ok(text.contains(key)),
        other => Err(PyExc::TypeError(format!(
            "argument of type '{}' is not iterable",
            type_name(other)
        ))),
    }
}

/// One `license` row.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct LicenseRow {
    /// `id`.
    pub id: i32,
    /// `license_key`.
    pub license_key: String,
    /// `customer_name`.
    pub customer_name: String,
    /// `customer_email`.
    pub customer_email: String,
    /// `company_name`.
    pub company_name: String,
}

const LICENSE_COLUMNS: &str = "license.id, license.license_key, license.customer_name, \
     license.customer_email, license.company_name";

/// `select(License)` then `.scalars().first()`.
pub async fn first_license(db: &Db) -> PyResult<Option<LicenseRow>> {
    sqlx::query_as::<_, LicenseRow>(&format!("SELECT {LICENSE_COLUMNS} FROM license"))
        .fetch_optional(db.pool())
        .await
        .map_err(db_err)
}

fn db_err(e: sqlx::Error) -> PyExc {
    db(e)
}

/// `get_license(session)`: the first row, or the 404.
pub async fn get_license(db: &Db) -> PyResult<LicenseRow> {
    first_license(db)
        .await?
        .ok_or_else(|| PyExc::http(404, "No license found. A license must be created first."))
}

/// `get_license(session).license_key`.
pub async fn license_key(db: &Db) -> PyResult<String> {
    Ok(get_license(db).await?.license_key)
}

/// `select(License).where(License.customer_email == email)` then `.first()`.
pub async fn license_by_email(db: &Db, email: &str) -> PyResult<Option<LicenseRow>> {
    sqlx::query_as::<_, LicenseRow>(&format!(
        "SELECT {LICENSE_COLUMNS} FROM license WHERE license.customer_email = ?"
    ))
    .bind(email)
    .fetch_optional(db.pool())
    .await
    .map_err(db_err)
}

/// `check_if_license_exists`: the 400 when any row exists.
pub async fn check_if_license_exists(db: &Db) -> PyResult<()> {
    if first_license(db).await?.is_some() {
        return Err(PyExc::http(400, "License already exists"));
    }
    Ok(())
}

/// What a non-`str` value becomes in a `varchar` column (the driver's
/// literal, which MySQL turns into text); a list or dict is pymysql's
/// refusal.
pub fn stored_text(v: &PyValue) -> PyResult<Option<String>> {
    Ok(match v {
        PyValue::None => None,
        PyValue::Str(s) => Some(s.clone()),
        PyValue::Bool(b) => Some(if *b { "1" } else { "0" }.into()),
        PyValue::Int(i) => Some(i.clone()),
        PyValue::Float(f) => Some(float_repr(*f)),
        other => {
            return Err(PyExc::TypeError(format!(
                "dict can not be used as parameter: {}",
                type_name(other)
            )));
        }
    })
}

/// `add_license_to_db(session, key, AddLicenseToDB(...))`: one row,
/// committed. The key is whatever Python passed (a table model does not
/// validate); the three names are the validated `AddLicenseToDB` strings.
pub async fn add_license_to_db(
    db: &Db,
    key: &PyValue,
    customer_name: &str,
    customer_email: &str,
    company_name: &str,
) -> PyResult<()> {
    let key = stored_text(key)?;
    sqlx::query(
        "INSERT INTO license (license_key, customer_name, customer_email, company_name) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(key)
    .bind(customer_name)
    .bind(customer_email)
    .bind(company_name)
    .execute(db.pool())
    .await
    .map_err(db_err)?;
    Ok(())
}

/// `license.license_key = new; session.commit()`.
pub async fn replace_key(db: &Db, id: i32, new_key: &str) -> PyResult<()> {
    sqlx::query("UPDATE license SET license_key=? WHERE license.id = ?")
        .bind(new_key)
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(db_err)?;
    Ok(())
}

/// One `license_cache` row, every column (SQLAlchemy's `select(LicenseCache)`:
/// the same column list keeps MySQL's plan, so `.first()` picks the same row).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct CacheRow {
    /// `id`.
    pub id: i32,
    /// `license_key`.
    pub license_key: String,
    /// `feature_name`.
    pub feature_name: String,
    /// `is_enabled`.
    pub is_enabled: bool,
    /// `cached_at`.
    pub cached_at: NaiveDateTime,
    /// `expires_at`.
    pub expires_at: NaiveDateTime,
    /// `license_data`.
    pub license_data: Option<String>,
}

const CACHE_COLUMNS: &str = "license_cache.id, license_cache.license_key, \
     license_cache.feature_name, license_cache.is_enabled, license_cache.cached_at, \
     license_cache.expires_at, license_cache.license_data";

/// `get_cached_feature`: the first unexpired row's `is_enabled`.
pub async fn cached_feature(db: &Db, key: &str, feature: &str) -> PyResult<Option<bool>> {
    let row = sqlx::query_as::<_, CacheRow>(&format!(
        "SELECT {CACHE_COLUMNS} FROM license_cache WHERE license_cache.license_key = ? \
         AND license_cache.feature_name = ? AND license_cache.expires_at > ?"
    ))
    .bind(key)
    .bind(feature)
    .bind(copilot_core::time::now_utc_micros())
    .fetch_optional(db.pool())
    .await
    .map_err(db_err)?;
    Ok(row.map(|r| r.is_enabled))
}

/// The `license_data` of the first unexpired row of the licence
/// (`verify_license_key`'s `.limit(1)`): `Some(None)` for a row without it.
pub async fn cached_license_data(db: &Db, key: &str) -> PyResult<Option<Option<String>>> {
    let row = sqlx::query_as::<_, CacheRow>(&format!(
        "SELECT {CACHE_COLUMNS} FROM license_cache WHERE license_cache.license_key = ? \
         AND license_cache.expires_at > ? LIMIT ?"
    ))
    .bind(key)
    .bind(copilot_core::time::now_utc_micros())
    .bind(1_i64)
    .fetch_optional(db.pool())
    .await
    .map_err(db_err)?;
    Ok(row.map(|r| r.license_data))
}

/// The names of the unexpired, enabled features (`get_license_features`'
/// cache read), in MySQL's order.
pub async fn cached_enabled_features(db: &Db, key: &str) -> PyResult<Vec<String>> {
    let rows = sqlx::query_as::<_, CacheRow>(&format!(
        "SELECT {CACHE_COLUMNS} FROM license_cache WHERE license_cache.license_key = ? \
         AND license_cache.expires_at > ? AND license_cache.is_enabled = true"
    ))
    .bind(key)
    .bind(copilot_core::time::now_utc_micros())
    .fetch_all(db.pool())
    .await
    .map_err(db_err)?;
    Ok(rows.into_iter().map(|r| r.feature_name).collect())
}

/// `normalize_api_response(response)`.
pub fn normalize_api_response(response: PyValue) -> PyResult<PyValue> {
    if contains(&response, "data")? {
        return Ok(response);
    }
    let success = get(&response, "success")?
        .cloned()
        .unwrap_or(PyValue::Bool(true));
    let message = get(&response, "message")?
        .cloned()
        .unwrap_or_else(|| s("Success"));
    Ok(dict(vec![
        ("data", response),
        ("success", success),
        ("message", message),
    ]))
}

/// `extract_license_payload(normalized)`: the licence dict, or the 502.
pub fn extract_license_payload(normalized: &PyValue) -> PyResult<PyValue> {
    let data = get(normalized, "data")?.cloned().unwrap_or(PyValue::None);
    if let PyValue::Dict(_) = data {
        if let Some(license @ PyValue::Dict(_)) = get(&data, "license")? {
            return Ok(license.clone());
        }
    }
    if let Some(license @ PyValue::Dict(_)) = get(normalized, "license")? {
        return Ok(license.clone());
    }
    // `(data or {}).get("message") or normalized.get("message") or "…"`.
    let from_data = if data.truthy() {
        get(&data, "message")?.cloned()
    } else {
        None
    };
    let message = match from_data.filter(PyValue::truthy) {
        Some(m) => m.py_str(),
        None => match get(normalized, "message")?.filter(|m| m.truthy()) {
            Some(m) => m.py_str(),
            None => "License server returned an unexpected response".into(),
        },
    };
    tracing::error!("No license payload in license-server response");
    Err(PyExc::http(502, format!("License server error: {message}")))
}

/// `cache_license_features(session, license_key, license_data)`: the
/// licence's rows replaced by one per data object that has a name; any
/// failure rolls back and is raised again.
pub async fn cache_license_features(db: &Db, key: &str, license_data: &PyValue) -> PyResult<()> {
    let mut tx = db.pool().begin().await.map_err(db_err)?;
    let plan = async {
        sqlx::query("DELETE FROM license_cache WHERE license_cache.license_key = ?")
            .bind(key)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        let now: NaiveDateTime = copilot_core::time::now_utc_micros();
        let expires = now + Duration::hours(CACHE_DURATION_HOURS);
        // `json.dumps(license_data)` (NaN allowed, as `json.loads` read it).
        let license_json = py_dumps_allow_nan(license_data, Dumps::DEFAULT);
        let data_objects = if contains(license_data, "data")?
            && contains(getitem(license_data, "data")?, "license")?
        {
            get(
                getitem(getitem(license_data, "data")?, "license")?,
                "dataObjects",
            )?
            .cloned()
            .unwrap_or(PyValue::List(Vec::new()))
        } else if contains(license_data, "license")? {
            get(getitem(license_data, "license")?, "dataObjects")?
                .cloned()
                .unwrap_or(PyValue::List(Vec::new()))
        } else if contains(license_data, "dataObjects")? {
            get(license_data, "dataObjects")?
                .cloned()
                .unwrap_or(PyValue::List(Vec::new()))
        } else {
            tracing::warn!("Could not find dataObjects in license response");
            PyValue::List(Vec::new())
        };
        let mut rows = Vec::new();
        for data_object in iterate(&data_objects)? {
            let name = get(&data_object, "name")?.cloned().unwrap_or(PyValue::None);
            let enabled =
                get(&data_object, "intValue")?.is_some_and(|v| py_eq(v, &PyValue::Int("1".into())));
            if name.truthy() {
                rows.push((stored_text(&name)?, enabled));
            }
        }
        for (name, enabled) in rows {
            sqlx::query(
                "INSERT INTO license_cache (license_key, feature_name, is_enabled, cached_at, \
                 expires_at, license_data) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(key)
            .bind(name)
            .bind(enabled)
            .bind(now)
            .bind(expires)
            .bind(&license_json)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
        Ok::<(), PyExc>(())
    };
    match plan.await {
        Ok(()) => tx.commit().await.map_err(db_err),
        Err(e) => {
            tracing::error!("Error caching license features: {}", e.display());
            let _ = tx.rollback().await;
            Err(e)
        }
    }
}

/// `invalidate_license_cache(session, license_key)`: a failure is logged
/// and rolled back, never raised.
pub async fn invalidate_license_cache(db: &Db, key: &str) {
    match sqlx::query("DELETE FROM license_cache WHERE license_cache.license_key = ?")
        .bind(key)
        .execute(db.pool())
        .await
    {
        Ok(done) => tracing::info!(
            "Invalidated {} cache entries for license",
            done.rows_affected()
        ),
        Err(e) => tracing::error!("Error invalidating license cache: {e}"),
    }
}

fn not_enabled(feature: &str) -> PyExc {
    PyExc::http(
        400,
        format!(
            "Feature is not enabled. You must purchase the {feature} license to use this feature."
        ),
    )
}

/// `is_feature_enabled(feature_name, session)`: `Ok` when enabled, the 400
/// when not, the 404 without a licence, the 500 (`Unable to verify
/// license: …`) when the licence server's answer cannot be used.
pub async fn is_feature_enabled(db: &Db, client: &LicenseClient, feature: &str) -> PyResult<()> {
    let key = license_key(db).await?;
    if let Some(enabled) = cached_feature(db, &key, feature).await? {
        tracing::info!("Using cached result for feature '{feature}'");
        return if enabled {
            Ok(())
        } else {
            Err(not_enabled(feature))
        };
    }
    tracing::info!("Cache miss for feature '{feature}', fetching from API");
    match verify(db, client, &key, feature).await {
        Ok(()) => Ok(()),
        Err(e @ PyExc::Http(..)) => Err(e),
        Err(e) => Err(PyExc::http(
            500,
            format!("Unable to verify license: {}", e.display()),
        )),
    }
}

/// The `try` block of `is_feature_enabled` after a cache miss.
async fn verify(db: &Db, client: &LicenseClient, key: &str, feature: &str) -> PyResult<()> {
    let result = client
        .post("verify-license", dict(vec![("license_key", s(key))]))
        .await?;
    let normalized = normalize_api_response(result)?;
    cache_license_features(db, key, &normalized).await?;
    let payload = extract_license_payload(&normalized)?;
    let data_objects = get(&payload, "dataObjects")?
        .cloned()
        .unwrap_or(PyValue::List(Vec::new()));
    for data_object in iterate(&data_objects)? {
        if py_eq(getitem(&data_object, "name")?, &s(feature))
            && py_eq(
                getitem(&data_object, "intValue")?,
                &PyValue::Int("1".into()),
            )
        {
            tracing::info!("Feature '{feature}' is enabled (from API)");
            return Ok(());
        }
    }
    Err(not_enabled(feature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn normalize_wraps_unwrapped_answers() {
        let v = normalize_api_response(loads(r#"{"license": {"a": 1}}"#).unwrap()).unwrap();
        assert_eq!(
            v.py_repr(),
            "{'data': {'license': {'a': 1}}, 'success': True, 'message': 'Success'}"
        );
        let wrapped = loads(r#"{"data": 1}"#).unwrap();
        assert_eq!(normalize_api_response(wrapped.clone()).unwrap(), wrapped);
        assert_eq!(
            normalize_api_response(loads("[1]").unwrap()).unwrap_err(),
            PyExc::AttributeError("'list' object has no attribute 'get'".into())
        );
        assert_eq!(
            normalize_api_response(loads("5").unwrap()).unwrap_err(),
            PyExc::TypeError("argument of type 'int' is not iterable".into())
        );
    }

    #[test]
    fn missing_payloads_are_502s() {
        let n =
            loads(r#"{"data": {"message": "Internal server error"}, "success": true}"#).unwrap();
        assert_eq!(
            extract_license_payload(&n).unwrap_err(),
            PyExc::http(502, "License server error: Internal server error")
        );
        let n = loads(r#"{"data": {}, "message": ""}"#).unwrap();
        assert_eq!(
            extract_license_payload(&n).unwrap_err(),
            PyExc::http(
                502,
                "License server error: License server returned an unexpected response"
            )
        );
        let n = loads(r#"{"data": {"license": {"k": 1}}}"#).unwrap();
        assert_eq!(extract_license_payload(&n).unwrap().py_repr(), "{'k': 1}");
    }
}
