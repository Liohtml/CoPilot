//! The 12 routes of `license_router` (`/api/license`), every one guarded by
//! `require_any_scope("admin", "analyst")` as in Python.
//!
//! Each handler is the Python function line by line: the same calls in the
//! same order, the same subscripts into the licence server's answer (a
//! missing key is the `KeyError`'s bare 500), the same models built from it
//! (their `ValidationError` is the `ValueError` handler's 400 — after the
//! writes that came before them, as in Python).

use axum::Json;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, body::Body};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_upstream::model::{construct, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult, get as py_get, getitem, iterate};
use copilot_upstream::respond::{body_model, model_response};
use copilot_web::error::LoggedError;
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized, WithJson};
use http::StatusCode;
use serde_json::json;

use crate::LicenseState;
use crate::schema::{
    ADD_LICENSE_TO_DB, CANCEL_SUBSCRIPTION_REQUEST, CANCEL_SUBSCRIPTION_RESPONSE,
    CHECKOUT_SESSION_RESPONSE, FEATURE_SUBSCRIPTION_REQUEST, GET_LICENSE_BY_EMAIL_REQUEST,
    GET_LICENSE_FEATURES_RESPONSE, GET_LICENSE_RESPONSE, IS_FEATURE_ENABLED_RESPONSE,
    REPLACE_LICENSE_REQUEST, RETRIEVE_DOCKER_COMPOSE, SUBSCRIPTION_FEATURES_RESPONSE,
    TRIAL_LICENSE_REQUEST, TRIAL_LICENSE_RESPONSE, VERIFY_LICENSE_RESPONSE,
};
use crate::services::{
    self, add_license_to_db, cache_license_features, check_if_license_exists, contains, dict,
    extract_license_payload, get_license, invalidate_license_cache, normalize_api_response, s,
};

type Analyst = Authorized<AdminOrAnalyst>;

/// The router to nest at `/api/license`.
pub fn router(state: LicenseState) -> Router {
    Router::new()
        .route("/subscription_features", get(subscription_features))
        .route(
            "/retrieve_license_by_email",
            post(retrieve_license_by_email),
        )
        .route("/create_checkout_session", post(create_checkout_session))
        .route("/trial_license", post(trial_license))
        .route("/cancel_subscription", post(cancel_subscription))
        .route("/verify_license", get(verify_license))
        .route("/get_license", get(get_license_route))
        .route(
            "/is_feature_enabled/{feature_name}",
            get(is_feature_enabled),
        )
        .route("/get_license_features", get(get_license_features))
        .route("/replace_license_in_db", post(replace_license_in_db))
        .route("/retrieve-docker-compose", post(retrieve_docker_compose))
        .route("/invalidate_cache", post(invalidate_cache))
        .with_state(state)
}

/// `HTTPException(status_code, detail=value)` for any value: Starlette
/// replaces a `None` detail with the status phrase; the handler answers
/// `{"success": false, "message": detail}` (Starlette's `JSONResponse`) and
/// logs `str(detail)`.
fn http_value(status: u16, detail: &PyValue) -> ApiResult {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    match detail {
        PyValue::None => Err(ApiError::http(
            code,
            code.canonical_reason().unwrap_or_default(),
        )),
        PyValue::Str(text) => Err(ApiError::http(code, text.clone())),
        other => {
            let body = dict(vec![
                ("success", PyValue::Bool(false)),
                ("message", other.clone()),
            ]);
            // `json.dumps(…, ensure_ascii=False, allow_nan=False,
            // separators=(",", ":"))`: a NaN cannot be rendered.
            let text = py_dumps(&body, Dumps::HTTPX).map_err(ApiError::internal)?;
            let mut resp = Response::builder()
                .status(code)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(text))
                .map_err(ApiError::internal)?;
            resp.extensions_mut().insert(LoggedError {
                message: other.py_str(),
            });
            Ok(resp)
        }
    }
}

/// `dict.get(key, default)` of a `json.loads` value.
fn get_or(v: &PyValue, key: &str, default: PyValue) -> PyResult<PyValue> {
    Ok(py_get(v, key)?.cloned().unwrap_or(default))
}

/// `normalized_results["data"]["success"] is False`.
fn is_false(v: &PyValue) -> bool {
    matches!(v, PyValue::Bool(false))
}

fn json_ok(value: serde_json::Value) -> ApiResult {
    Ok(Json(value).into_response())
}

/// The validated string a model dump holds.
fn text(dump: &PyValue, key: &str) -> String {
    field(dump, key).as_str().unwrap_or_default().to_string()
}

// --- GET /subscription_features ---------------------------------------------------------------

async fn subscription_features(_a: Analyst, State(st): State<LicenseState>) -> ApiResult {
    let out = match catalog(&st).await {
        Ok(dump) => dump,
        Err(e) => {
            tracing::error!("Error getting subscription catalog: {}", e.display());
            dict(vec![
                ("features", PyValue::List(Vec::new())),
                ("success", PyValue::Bool(false)),
                (
                    "message",
                    s(format!(
                        "Error getting subscription catalog: {}",
                        e.display()
                    )),
                ),
            ])
        }
    };
    Ok(model_response(&out))
}

/// The `try` block of `get_subscription_catalog`.
async fn catalog(st: &LicenseState) -> PyResult<PyValue> {
    let result = st.client.get("features").await?;
    let normalized = normalize_api_response(result)?;
    let features =
        if contains(&normalized, "data")? && contains(getitem(&normalized, "data")?, "features")? {
            getitem(getitem(&normalized, "data")?, "features")?.clone()
        } else if contains(&normalized, "features")? {
            getitem(&normalized, "features")?.clone()
        } else {
            tracing::warn!("No features found in response");
            PyValue::List(Vec::new())
        };
    let success = get_or(&normalized, "success", PyValue::Bool(true))?;
    let message = get_or(
        &normalized,
        "message",
        s("Subscription features retrieved successfully"),
    )?;
    construct(
        &SUBSCRIPTION_FEATURES_RESPONSE,
        &kwargs(vec![
            ("features", features),
            ("success", success),
            ("message", message),
        ]),
    )
}

// --- POST /retrieve_license_by_email ------------------------------------------------------------

async fn retrieve_license_by_email(
    State(st): State<LicenseState>,
    WithJson(_a, body): WithJson<Analyst>,
) -> ApiResult {
    let dump = body_model(&body, &GET_LICENSE_BY_EMAIL_REQUEST)?;
    let email = text(&dump, "email");
    let db = &st.ctx.db;
    if let Some(existing) = services::license_by_email(db, &email).await? {
        let out = construct(
            &GET_LICENSE_RESPONSE,
            &kwargs(vec![
                ("license_key", s(existing.license_key)),
                ("success", PyValue::Bool(true)),
                ("message", s("License already exists in database")),
            ]),
        )?;
        return Ok(model_response(&out));
    }
    let results = st
        .client
        .post(
            "retrieve-license-by-email",
            dict(vec![("email", s(email.clone()))]),
        )
        .await?;
    let n = normalize_api_response(results)?;
    let data = getitem(&n, "data")?;
    if is_false(getitem(data, "success")?) {
        return http_value(400, getitem(data, "message")?);
    }
    let key = getitem(getitem(data, "license")?, "key")?.clone();
    let customer = |k: &str| -> PyResult<PyValue> {
        Ok(getitem(getitem(getitem(data, "license")?, "customer")?, k)?.clone())
    };
    let add = construct(
        &ADD_LICENSE_TO_DB,
        &kwargs(vec![
            ("customer_email", customer("email")?),
            ("customer_name", customer("name")?),
            ("company_name", customer("companyName")?),
        ]),
    )?;
    add_license_to_db(
        db,
        &key,
        &text(&add, "customer_name"),
        &text(&add, "customer_email"),
        &text(&add, "company_name"),
    )
    .await?;
    let out = construct(
        &GET_LICENSE_RESPONSE,
        &kwargs(vec![
            (
                "license_key",
                getitem(getitem(data, "license")?, "key")?.clone(),
            ),
            ("success", getitem(data, "success")?.clone()),
            ("message", getitem(data, "message")?.clone()),
        ]),
    )?;
    Ok(model_response(&out))
}

// --- POST /create_checkout_session --------------------------------------------------------------

async fn create_checkout_session(
    State(st): State<LicenseState>,
    WithJson(_a, body): WithJson<Analyst>,
) -> ApiResult {
    let dump = body_model(&body, &FEATURE_SUBSCRIPTION_REQUEST)?;
    let data = dict(vec![
        ("feature_id", field(&dump, "feature_id").clone()),
        ("cancel_url", field(&dump, "cancel_url").clone()),
        ("success_url", field(&dump, "success_url").clone()),
        ("customer_email", field(&dump, "customer_email").clone()),
        ("company_name", field(&dump, "company_name").clone()),
    ]);
    let results = st.client.post("create-checkout-session", data).await?;
    let n = normalize_api_response(results)?;
    let data = getitem(&n, "data")?;
    if is_false(getitem(data, "success")?) {
        return http_value(400, getitem(data, "message")?);
    }
    let out = construct(
        &CHECKOUT_SESSION_RESPONSE,
        &kwargs(vec![
            ("session", getitem(data, "session")?.clone()),
            ("success", getitem(data, "success")?.clone()),
            ("message", getitem(data, "message")?.clone()),
        ]),
    )?;
    Ok(model_response(&out))
}

// --- POST /trial_license ------------------------------------------------------------------------

async fn trial_license(
    State(st): State<LicenseState>,
    WithJson(_a, body): WithJson<Analyst>,
) -> ApiResult {
    let dump = body_model(&body, &TRIAL_LICENSE_REQUEST)?;
    let db = &st.ctx.db;
    check_if_license_exists(db).await?;
    let data = dict(vec![
        ("period", field(&dump, "period").clone()),
        ("email", field(&dump, "email").clone()),
        ("feature_name", field(&dump, "feature_name").clone()),
        ("customer_name", field(&dump, "customer_name").clone()),
        ("company_name", field(&dump, "company_name").clone()),
    ]);
    let results = st.client.post("trial-license", data).await?;
    let n = normalize_api_response(results)?;
    let data = getitem(&n, "data")?;
    if is_false(getitem(data, "success")?) {
        return http_value(400, getitem(data, "message")?);
    }
    let key = getitem(data, "license_key")?.clone();
    add_license_to_db(
        db,
        &key,
        &text(&dump, "customer_name"),
        &text(&dump, "email"),
        &text(&dump, "company_name"),
    )
    .await?;
    let out = construct(
        &TRIAL_LICENSE_RESPONSE,
        &kwargs(vec![
            ("license_key", getitem(data, "license_key")?.clone()),
            ("success", getitem(data, "success")?.clone()),
            ("message", getitem(data, "message")?.clone()),
        ]),
    )?;
    Ok(model_response(&out))
}

// --- POST /cancel_subscription ------------------------------------------------------------------

async fn cancel_subscription(
    State(st): State<LicenseState>,
    WithJson(_a, body): WithJson<Analyst>,
) -> ApiResult {
    let dump = body_model(&body, &CANCEL_SUBSCRIPTION_REQUEST)?;
    let data = dict(vec![
        ("customer_email", field(&dump, "customer_email").clone()),
        (
            "subscription_price_id",
            field(&dump, "subscription_price_id").clone(),
        ),
        ("feature_name", field(&dump, "feature_name").clone()),
    ]);
    let results = st.client.post("cancel-subscription", data).await?;
    let n = normalize_api_response(results)?;
    let data = getitem(&n, "data")?;
    if is_false(getitem(data, "success")?) {
        return http_value(400, getitem(data, "message")?);
    }
    let out = construct(
        &CANCEL_SUBSCRIPTION_RESPONSE,
        &kwargs(vec![
            ("success", getitem(data, "success")?.clone()),
            ("message", getitem(data, "message")?.clone()),
        ]),
    )?;
    Ok(model_response(&out))
}

// --- GET /verify_license ------------------------------------------------------------------------

/// The cached branch's `try`: `Ok(None)` for what its `except (JSONDecodeError,
/// KeyError, ValueError)` swallows; any other exception escapes.
fn from_cache(raw: &str) -> PyResult<Option<PyValue>> {
    let caught = |e: PyExc| match e {
        PyExc::KeyError(_) | PyExc::ValueError(_) | PyExc::JsonDecode(_) | PyExc::Validation(_) => {
            tracing::warn!(
                "Error parsing cached license data: {}, falling back to API",
                e.text()
            );
            Ok(None)
        }
        other => Err(other),
    };
    let license_data = match copilot_upstream::json::py_loads(raw) {
        Ok(v) => v,
        Err(e) => return caught(PyExc::JsonDecode(e)),
    };
    let attempt = (|| -> PyResult<PyValue> {
        let (license_obj, success) = if contains(&license_data, "data")?
            && contains(getitem(&license_data, "data")?, "license")?
        {
            let data = getitem(&license_data, "data")?;
            (
                getitem(data, "license")?.clone(),
                getitem(data, "success")?.clone(),
            )
        } else if contains(&license_data, "license")? {
            (
                getitem(&license_data, "license")?.clone(),
                get_or(&license_data, "success", PyValue::Bool(true))?,
            )
        } else {
            return Err(PyExc::ValueError(
                "Invalid cached license data format".into(),
            ));
        };
        construct(
            &VERIFY_LICENSE_RESPONSE,
            &kwargs(vec![
                ("license", license_obj),
                ("success", success),
                ("message", s("License verified successfully (from cache)")),
            ]),
        )
    })();
    match attempt {
        Ok(v) => Ok(Some(v)),
        Err(e) => caught(e),
    }
}

async fn verify_license(_a: Analyst, State(st): State<LicenseState>) -> ApiResult {
    let db = &st.ctx.db;
    let license = get_license(db).await?;
    if let Some(Some(raw)) = services::cached_license_data(db, &license.license_key).await? {
        if !raw.is_empty() {
            tracing::info!("Using cached license verification data");
            if let Some(out) = from_cache(&raw)? {
                return Ok(model_response(&out));
            }
        }
    }
    tracing::info!("No valid cache found, verifying license via API");
    let results = st
        .client
        .post(
            "verify-license",
            dict(vec![("license_key", s(license.license_key.clone()))]),
        )
        .await?;
    let n = normalize_api_response(results)?;
    cache_license_features(db, &license.license_key, &n).await?;
    if !get_or(&n, "success", PyValue::Bool(true))?.truthy() {
        return http_value(
            400,
            &get_or(&n, "message", s("License verification failed"))?,
        );
    }
    let license_obj = extract_license_payload(&n)?;
    let data = py_get(&n, "data")?.cloned().unwrap_or(PyValue::None);
    let container = if matches!(data, PyValue::Dict(_)) && contains(&data, "license")? {
        data
    } else {
        n.clone()
    };
    let success = get_or(&container, "success", PyValue::Bool(true))?;
    let message = get_or(&container, "message", s("License verified successfully"))?;
    let out = construct(
        &VERIFY_LICENSE_RESPONSE,
        &kwargs(vec![
            ("license", license_obj),
            ("success", success),
            ("message", message),
        ]),
    )?;
    Ok(model_response(&out))
}

// --- GET /get_license ---------------------------------------------------------------------------

async fn get_license_route(_a: Analyst, State(st): State<LicenseState>) -> ApiResult {
    let license = get_license(&st.ctx.db).await?;
    json_ok(json!({
        "license_key": license.license_key,
        "success": true,
        "message": "License retrieved successfully",
    }))
}

// --- GET /is_feature_enabled/{feature_name} -----------------------------------------------------

async fn is_feature_enabled(
    _a: Analyst,
    State(st): State<LicenseState>,
    Path(feature_name): Path<String>,
) -> ApiResult {
    match services::is_feature_enabled(&st.ctx.db, &st.client, &feature_name).await {
        Ok(()) => {
            let out = construct(
                &IS_FEATURE_ENABLED_RESPONSE,
                &kwargs(vec![
                    ("enabled", PyValue::Bool(true)),
                    ("success", PyValue::Bool(true)),
                    ("message", s(format!("Feature '{feature_name}' is enabled"))),
                ]),
            )?;
            Ok(model_response(&out))
        }
        // `IsFeatureEnabledResponse(status_code=400, message=e.detail)`
        // misses two required fields: its `ValidationError` is the 400.
        Err(PyExc::Http(400, detail)) => Err(construct(
            &IS_FEATURE_ENABLED_RESPONSE,
            &kwargs(vec![
                ("status_code", PyValue::Int("400".into())),
                ("message", s(detail)),
            ]),
        )
        .err()
        .unwrap_or_else(|| PyExc::ValueError("unreachable".into()))
        .into()),
        Err(e) => Err(e.into()),
    }
}

// --- GET /get_license_features ------------------------------------------------------------------

async fn get_license_features(_a: Analyst, State(st): State<LicenseState>) -> ApiResult {
    let db = &st.ctx.db;
    let license = get_license(db).await?;
    let cached = services::cached_enabled_features(db, &license.license_key).await?;
    if !cached.is_empty() {
        tracing::info!("Using cached license features ({} features)", cached.len());
        let out = construct(
            &GET_LICENSE_FEATURES_RESPONSE,
            &kwargs(vec![
                (
                    "features",
                    PyValue::List(cached.into_iter().map(s).collect()),
                ),
                ("success", PyValue::Bool(true)),
                (
                    "message",
                    s("License features retrieved successfully (from cache)"),
                ),
            ]),
        )?;
        return Ok(model_response(&out));
    }
    tracing::info!("No cached features found, fetching from API");
    let results = st
        .client
        .post(
            "license-features",
            dict(vec![("license_key", s(license.license_key.clone()))]),
        )
        .await?;
    if !get_or(&results, "success", PyValue::Bool(true))?.truthy() {
        return http_value(
            400,
            &get_or(&results, "message", s("Failed to get license features"))?,
        );
    }
    let objects = iterate(&get_or(&results, "features", PyValue::List(Vec::new()))?)?
        .into_iter()
        .map(|feature| {
            dict(vec![
                ("name", feature),
                ("intValue", PyValue::Int("1".into())),
            ])
        })
        .collect();
    let fake = dict(vec![(
        "data",
        dict(vec![
            (
                "license",
                dict(vec![("dataObjects", PyValue::List(objects))]),
            ),
            ("success", PyValue::Bool(true)),
        ]),
    )]);
    cache_license_features(db, &license.license_key, &fake).await?;
    let out = construct(
        &GET_LICENSE_FEATURES_RESPONSE,
        &kwargs(vec![
            (
                "features",
                get_or(&results, "features", PyValue::List(Vec::new()))?,
            ),
            ("success", get_or(&results, "success", PyValue::Bool(true))?),
            (
                "message",
                get_or(
                    &results,
                    "message",
                    s("License features retrieved successfully"),
                )?,
            ),
        ]),
    )?;
    Ok(model_response(&out))
}

// --- POST /replace_license_in_db ----------------------------------------------------------------

async fn replace_license_in_db(
    State(st): State<LicenseState>,
    WithJson(_a, body): WithJson<Analyst>,
) -> ApiResult {
    let dump = body_model(&body, &REPLACE_LICENSE_REQUEST)?;
    let new_key = text(&dump, "license_key");
    let db = &st.ctx.db;
    if let Some(license) = services::first_license(db).await? {
        tracing::info!("Replacing the existing license");
        invalidate_license_cache(db, &license.license_key).await;
        services::replace_key(db, license.id, &new_key).await?;
        return json_ok(json!({"success": true, "message": "License replaced successfully"}));
    }
    tracing::info!("No existing license found, creating new license");
    let results = st
        .client
        .post(
            "verify-license",
            dict(vec![("license_key", s(new_key.clone()))]),
        )
        .await?;
    let n = normalize_api_response(results)?;
    if !get_or(&n, "success", PyValue::Bool(true))?.truthy() {
        return Err(ApiError::bad_request("Invalid license key"));
    }
    let license_data = getitem(getitem(&n, "data")?, "license")?;
    let customer = getitem(license_data, "customer")?;
    let add = construct(
        &ADD_LICENSE_TO_DB,
        &kwargs(vec![
            ("customer_email", getitem(customer, "email")?.clone()),
            ("customer_name", getitem(customer, "name")?.clone()),
            ("company_name", getitem(customer, "companyName")?.clone()),
        ]),
    )?;
    add_license_to_db(
        db,
        &s(new_key),
        &text(&add, "customer_name"),
        &text(&add, "customer_email"),
        &text(&add, "company_name"),
    )
    .await?;
    json_ok(json!({"success": true, "message": "License created successfully"}))
}

// --- POST /retrieve-docker-compose --------------------------------------------------------------

async fn retrieve_docker_compose(_a: Analyst, State(st): State<LicenseState>) -> ApiResult {
    let license = get_license(&st.ctx.db).await?;
    let results = st
        .client
        .post(
            "retrieve-docker-compose",
            dict(vec![("license_key", s(license.license_key))]),
        )
        .await?;
    if !get_or(&results, "success", PyValue::Bool(true))?.truthy() {
        return http_value(
            400,
            &get_or(&results, "message", s("Failed to retrieve Docker Compose"))?,
        );
    }
    if !contains(&results, "docker_compose")? {
        let message = get_or(&results, "message", s("Failed to retrieve Docker Compose"))?;
        return Err(ApiError::http(
            StatusCode::BAD_GATEWAY,
            format!("License server error: {}", message.py_str()),
        ));
    }
    let out = construct(
        &RETRIEVE_DOCKER_COMPOSE,
        &kwargs(vec![
            ("docker_compose", get_or(&results, "docker_compose", s(""))?),
            ("success", get_or(&results, "success", PyValue::Bool(true))?),
            (
                "message",
                get_or(
                    &results,
                    "message",
                    s("Docker Compose retrieved successfully"),
                )?,
            ),
        ]),
    )?;
    Ok(model_response(&out))
}

// --- POST /invalidate_cache ---------------------------------------------------------------------

async fn invalidate_cache(_a: Analyst, State(st): State<LicenseState>) -> ApiResult {
    let license = get_license(&st.ctx.db).await?;
    invalidate_license_cache(&st.ctx.db, &license.license_key).await;
    json_ok(json!({"success": true, "message": "License cache invalidated successfully"}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_answers_fall_back_on_what_python_catches() {
        assert_eq!(from_cache("not json").unwrap(), None);
        assert_eq!(from_cache(r#"{"other": 1}"#).unwrap(), None);
        assert_eq!(from_cache(r#"{"data": {"license": {}}}"#).unwrap(), None);
        // A `TypeError` is not caught.
        assert!(matches!(
            from_cache(r#"{"data": 5}"#).unwrap_err(),
            PyExc::TypeError(_)
        ));
        assert!(matches!(
            from_cache(r#"{"license": {}, "success": true}"#),
            Ok(None)
        ));
    }

    #[test]
    fn missing_fields_of_is_feature_enabled_read_as_pydantic_says() {
        let e = construct(
            &IS_FEATURE_ENABLED_RESPONSE,
            &kwargs(vec![
                ("status_code", PyValue::Int("400".into())),
                ("message", s("Feature is not enabled.")),
            ]),
        )
        .unwrap_err();
        assert!(
            e.text().starts_with(
                "2 validation errors for IsFeatureEnabledResponse\nenabled\n  Field required"
            ),
            "{}",
            e.text()
        );
    }
}
