//! `customer_provisioning_default_settings` — port of
//! `app/customer_provisioning/routes/default_settings.py`.
//!
//! The body is the `CustomerProvisioningDefaultSettings` **table** model,
//! which SQLModel does not validate: any JSON object is accepted (anything
//! else is `model_attributes_type`), the fields it names are kept with their
//! JSON types, the five EDR repo fields default to `None`, and it is MySQL
//! that refuses what does not fit (a missing or `null` required column, a
//! value too long — a bare 500). A created row answers with the values as
//! sent (and the `id` MySQL gave), an updated one with the row as re-read.

use copilot_auth::pyvalue::{PyValue, loads};
use copilot_db::Db;
use copilot_upstream::py::{PyExc, PyResult};
use copilot_web::ApiError;
use copilot_web::body::JsonBody;
use copilot_web::validate::{Validator, body_loc};
use serde_json::Value;

use super::store::{self, SETTINGS_COLUMNS, SETTINGS_DEFAULTED, SettingsRow};

/// The body's fields in declaration order: those it names, and the
/// defaulted ones it does not.
pub type Fields = Vec<(&'static str, PyValue)>;

/// Read the body (`Body(...)` of the table model).
pub fn read(body: &JsonBody) -> Result<Fields, ApiError> {
    let mut v = Validator::new();
    let root = body_loc();
    let obj = match body {
        JsonBody::Missing => {
            v.missing(root);
            None
        }
        JsonBody::NotJson => {
            v.object(&Value::Null, &root);
            None
        }
        JsonBody::Value(value) => v.object(value, &root),
    };
    v.finish()?;
    let Some(obj) = obj else {
        return Err(ApiError::internal("unreachable"));
    };
    let mut fields = Vec::new();
    for name in SETTINGS_COLUMNS {
        match obj.get(*name) {
            Some(value) => fields.push((*name, loads(&value.to_string()).unwrap_or(PyValue::None))),
            None if SETTINGS_DEFAULTED.contains(name) => fields.push((*name, PyValue::None)),
            None => {}
        }
    }
    Ok(fields)
}

fn response(message: &str, settings: PyValue) -> PyValue {
    PyValue::Dict(vec![
        ("message".into(), PyValue::Str(message.into())),
        ("success".into(), PyValue::Bool(true)),
        ("customer_provisioning_default_settings".into(), settings),
    ])
}

/// `GET /default_settings`.
pub async fn get(pool: &Db) -> PyResult<PyValue> {
    let row = store::first_settings(pool)
        .await?
        .ok_or_else(|| PyExc::http(404, "No customer provisioning default settings found"))?;
    Ok(response(
        "Customer Provisioning Default Settings retrieved successfully",
        row.dump(),
    ))
}

/// `POST /default_settings`.
pub async fn create(pool: &Db, fields: Fields) -> PyResult<PyValue> {
    if store::first_settings(pool).await?.is_some() {
        return Err(PyExc::http(
            400,
            "Only one customer provisioning default settings can exist",
        ));
    }
    let new_id = store::insert_settings(pool, &fields).await?;
    // The instance as sent (its attributes in the order SQLModel set them:
    // the fields given or defaulted), the primary key MySQL assigned put in
    // place of a `None` one, or set last when the body had none.
    let mut out: Vec<(String, PyValue)> = fields
        .iter()
        .map(|(k, v)| match (*k, v) {
            ("id", PyValue::None) => ("id".to_string(), PyValue::Int(new_id.to_string())),
            _ => ((*k).to_string(), v.clone()),
        })
        .collect();
    if !fields.iter().any(|(k, _)| *k == "id") {
        out.push(("id".to_string(), PyValue::Int(new_id.to_string())));
    }
    Ok(response(
        "Customer Provisioning Default Settings created successfully",
        PyValue::Dict(out),
    ))
}

/// `PUT /default_settings`: the row the body's `id` names, every field the
/// body carries (the defaulted ones too) written, then re-read.
pub async fn update(pool: &Db, fields: Fields) -> PyResult<PyValue> {
    let id = fields
        .iter()
        .find(|(k, _)| *k == "id")
        .map_or(PyValue::None, |(_, v)| v.clone());
    let existing = store::settings_by_id(pool, &id)
        .await?
        .ok_or_else(|| PyExc::http(404, "Settings not found"))?;
    store::update_settings(pool, existing.id, &fields).await?;
    let lookup = if fields.iter().any(|(k, _)| *k == "id") {
        id
    } else {
        PyValue::Int(existing.id.to_string())
    };
    let row: SettingsRow = store::settings_by_id(pool, &lookup).await?.ok_or_else(|| {
        PyExc::Other(
            "InvalidRequestError",
            "Could not refresh instance".to_string(),
        )
    })?;
    Ok(response(
        "Customer Provisioning Default Settings updated successfully",
        row.dump(),
    ))
}

/// `DELETE /default_settings`.
pub async fn delete(pool: &Db) -> PyResult<PyValue> {
    let row = store::first_settings(pool)
        .await?
        .ok_or_else(|| PyExc::http(404, "Settings not found"))?;
    store::delete_settings(pool, row.id).await?;
    Ok(response(
        "Customer Provisioning Default Settings deleted successfully",
        row.dump(),
    ))
}
