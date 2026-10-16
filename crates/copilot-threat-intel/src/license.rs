//! The licence check of `app/middleware/license.py` the threat-intel routes
//! need: `get_license` (the first `license` row) and `is_feature_enabled`
//! (the `license_cache` row of the feature if it has not expired, else the
//! licence server's `POST /verify-license`, whose answer refills the cache).
//!
//! The licence server is called the way `send_post_request` calls it:
//! `requests.post(…, timeout=10)` on a worker thread, `x-api-key` the
//! process's `COPILOT_API_KEY` (`None` when unset), `module-version: 1.0`,
//! `json={"license_key": …}`. Its answer goes through the same Python
//! operations on whatever JSON came back (`normalize_api_response`,
//! `cache_license_features`, `extract_license_payload`), so a malformed answer
//! fails with the exception Python would raise inside the `try`, wrapped as
//! `Unable to verify license: …`.

use chrono::{Duration, NaiveDateTime};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::http::PyRequest;
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_upstream::py::{PyExc, PyResult, get, getitem, iterate, py_eq, type_name};
use http::Method;

use crate::ThreatIntelState;
use crate::py::{contains, db, dict};

/// `get_license(session)`: the first row's key, or the 404.
pub async fn license_key(st: &ThreatIntelState) -> PyResult<String> {
    let row = sqlx::query_scalar::<_, String>("SELECT license.license_key FROM license")
        .fetch_optional(st.ctx.db.pool())
        .await
        .map_err(db)?;
    row.ok_or_else(|| PyExc::http(404, "No license found. A license must be created first."))
}

/// `get_cached_feature`: the first unexpired row's `is_enabled`.
async fn cached_feature(st: &ThreatIntelState, key: &str, feature: &str) -> PyResult<Option<bool>> {
    sqlx::query_scalar::<_, bool>(
        "SELECT license_cache.is_enabled FROM license_cache WHERE license_cache.license_key = ? \
         AND license_cache.feature_name = ? AND license_cache.expires_at > ?",
    )
    .bind(key)
    .bind(feature)
    .bind(copilot_core::time::now_utc_micros())
    .fetch_optional(st.ctx.db.pool())
    .await
    .map_err(db)
}

fn not_enabled(feature: &str) -> PyExc {
    PyExc::http(
        400,
        format!(
            "Feature is not enabled. You must purchase the {feature} license to use this feature."
        ),
    )
}

/// `is_feature_enabled(feature_name, session)`.
pub async fn is_feature_enabled(st: &ThreatIntelState, feature: &str) -> PyResult<()> {
    let key = license_key(st).await?;
    if let Some(enabled) = cached_feature(st, &key, feature).await? {
        tracing::info!("Using cached result for feature '{feature}'");
        return if enabled {
            Ok(())
        } else {
            Err(not_enabled(feature))
        };
    }
    tracing::info!("Cache miss for feature '{feature}', fetching from API");
    match verify(st, &key, feature).await {
        Ok(()) => Ok(()),
        Err(e @ PyExc::Http(..)) => Err(e),
        Err(e) => Err(PyExc::http(
            500,
            format!("Unable to verify license: {}", e.display()),
        )),
    }
}

/// The `try` block of `is_feature_enabled` after a cache miss.
async fn verify(st: &ThreatIntelState, key: &str, feature: &str) -> PyResult<()> {
    let result = send_post_request(
        st,
        "verify-license",
        dict(vec![("license_key", PyValue::Str(key.to_string()))]),
    )
    .await?;
    let normalized = normalize_api_response(result)?;
    cache_license_features(st, key, &normalized).await?;
    let payload = extract_license_payload(&normalized)?;
    let data_objects = get(&payload, "dataObjects")?
        .cloned()
        .unwrap_or(PyValue::List(Vec::new()));
    for data_object in iterate(&data_objects)? {
        if py_eq(
            getitem(&data_object, "name")?,
            &PyValue::Str(feature.to_string()),
        ) && py_eq(
            getitem(&data_object, "intValue")?,
            &PyValue::Int("1".into()),
        ) {
            tracing::info!("Feature '{feature}' is enabled (from API)");
            return Ok(());
        }
    }
    Err(not_enabled(feature))
}

/// `send_post_request(endpoint, data)`.
async fn send_post_request(
    st: &ThreatIntelState,
    endpoint: &str,
    data: PyValue,
) -> PyResult<PyValue> {
    tracing::info!("Sending POST request to {endpoint}");
    let attempt = async {
        let api_key = st
            .api_key
            .as_ref()
            .map_or_else(|| "None".to_string(), |k| k.expose().to_string());
        let request = PyRequest::new(Method::POST, format!("{}{endpoint}", st.urls.license))
            // A `requests` session default that `PyHttp` does not add.
            .header("Connection", "keep-alive")
            .header("x-api-key", api_key)
            .header("module-version", "1.0")
            .json(Some(data));
        let response = st.license_http.send(request).await?;
        if response.status() == 204 {
            return Ok(dict(vec![
                ("success", PyValue::Bool(true)),
                ("message", PyValue::Str("No content".into())),
            ]));
        }
        let payload = match response.json() {
            Ok(v) => v,
            Err(_) => {
                let text = response.text();
                dict(vec![(
                    "message",
                    PyValue::Str(if text.is_empty() {
                        "Unknown license server response".into()
                    } else {
                        text
                    }),
                )])
            }
        };
        if response.status() >= 500 {
            let pick = |k: &str| -> PyResult<Option<PyValue>> {
                Ok(get(&payload, k)?.filter(|v| v.truthy()).cloned())
            };
            let message = match pick("message")? {
                Some(m) => m.py_str(),
                None => match pick("detail")? {
                    Some(d) => d.py_str(),
                    None => "Internal server error".into(),
                },
            };
            tracing::error!(
                "License server error ({}) on {endpoint}: {message}",
                response.status()
            );
            return Err(PyExc::http(502, format!("License server error: {message}")));
        }
        Ok(payload)
    };
    match attempt.await {
        Ok(v) => Ok(v),
        Err(e @ PyExc::Http(..)) => Err(e),
        Err(e) => Err(PyExc::http(
            500,
            format!(
                "Failed to send POST request to {endpoint} with error: {}",
                e.display()
            ),
        )),
    }
}

/// `normalize_api_response(response)`.
fn normalize_api_response(response: PyValue) -> PyResult<PyValue> {
    if contains(&response, "data")? {
        return Ok(response);
    }
    let success = get(&response, "success")?
        .cloned()
        .unwrap_or(PyValue::Bool(true));
    let message = get(&response, "message")?
        .cloned()
        .unwrap_or_else(|| PyValue::Str("Success".into()));
    Ok(dict(vec![
        ("data", response),
        ("success", success),
        ("message", message),
    ]))
}

/// `cache_license_features(session, license_key, license_data)`: the
/// licence's rows replaced by one per data object that has a name; any
/// failure rolls back and is raised again.
async fn cache_license_features(
    st: &ThreatIntelState,
    key: &str,
    license_data: &PyValue,
) -> PyResult<()> {
    let mut tx = st.ctx.db.pool().begin().await.map_err(db)?;
    let plan = async {
        sqlx::query("DELETE FROM license_cache WHERE license_cache.license_key = ?")
            .bind(key)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let now: NaiveDateTime = copilot_core::time::now_utc_micros();
        let expires = now + Duration::hours(1);
        let license_json =
            py_dumps(license_data, Dumps::DEFAULT).map_err(|e| PyExc::TypeError(e.to_string()))?;
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
            .map_err(db)?;
        }
        Ok::<(), PyExc>(())
    };
    match plan.await {
        Ok(()) => tx.commit().await.map_err(db),
        Err(e) => {
            tracing::error!("Error caching license features: {}", e.display());
            let _ = tx.rollback().await;
            Err(e)
        }
    }
}

/// What a non-`str` feature name becomes in the `varchar` column (the
/// driver's literal, which MySQL turns into text).
fn stored_text(v: &PyValue) -> PyResult<String> {
    Ok(match v {
        PyValue::Str(s) => s.clone(),
        PyValue::Bool(b) => if *b { "1" } else { "0" }.into(),
        PyValue::Int(i) => i.clone(),
        PyValue::Float(f) => copilot_auth::pyvalue::float_repr(*f),
        other => {
            return Err(PyExc::TypeError(format!(
                "dict can not be used as parameter: {}",
                type_name(other)
            )));
        }
    })
}

/// `extract_license_payload(normalized)`.
fn extract_license_payload(normalized: &PyValue) -> PyResult<PyValue> {
    let data = get(normalized, "data")?.cloned().unwrap_or(PyValue::None);
    if let PyValue::Dict(_) = data {
        if let Some(license @ PyValue::Dict(_)) = get(&data, "license")? {
            return Ok(license.clone());
        }
    }
    if let Some(license @ PyValue::Dict(_)) = get(normalized, "license")? {
        return Ok(license.clone());
    }
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
