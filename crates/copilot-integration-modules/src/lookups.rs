//! The reads the module routes share with the rest of the backend, as the
//! Python helpers do them:
//!
//! - `get_customer_integration_response` (`app/integrations/utils/utils.py`)
//!   over `get_customer_integrations_by_customer_code` — the statements of
//!   `copilot_integrations::integrations::store::customer_integrations`,
//!   which already reproduce its joined and sub-query loads;
//! - `find_customer_integration` (`app/integrations/routes.py`) and
//!   `extract_auth_keys`;
//! - `get_connector_attribute` by name and by id, through the connector
//!   cache (`app/utils.py`);
//! - `get_customer_meta_attribute(code, "customer_meta_iris_customer_id")`
//!   and `get_license`.

use copilot_auth::pyvalue::PyValue;
use copilot_db::Db;
use copilot_db::connectors::ConnectorRow;
use copilot_integrations::integrations::store::{self, CustomerIntegration};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_web::AppContext;
use sqlx::Row;

use crate::error::{Fail, FailResult};

/// `get_customer_integration_response(code, session)`: the customer's
/// integrations, or the 404 when there are none.
pub async fn integration_response(db: &Db, code: &str) -> FailResult<Vec<CustomerIntegration>> {
    let cis = store::customer_integrations(db, Some(code)).await?;
    if cis.is_empty() {
        return Err(PyExc::http(404, "Customer integration settings not found.").into());
    }
    Ok(cis)
}

/// `find_customer_integration(code, name, response)`: the first integration
/// with a subscription to the service `name` (Python's `==`). A subscription
/// without its service is the `AttributeError` Python raises reading
/// `None.service_name`.
pub fn find_customer_integration<'a>(
    cis: &'a [CustomerIntegration],
    name: &str,
) -> PyResult<Option<&'a CustomerIntegration>> {
    for ci in cis {
        for sub in &ci.subscriptions {
            let Some(service) = &sub.service else {
                return Err(PyExc::AttributeError(
                    "'NoneType' object has no attribute 'service_name'".into(),
                ));
            };
            if service.service_name == name {
                return Ok(Some(ci));
            }
        }
    }
    Ok(None)
}

/// `extract_auth_keys(customer_integration, service_name)`: every key of the
/// service's subscriptions as a dict (a later key of the same name replaces
/// the value in place), or the 404 — for no keys, and for whatever raised
/// on the way (`None` integration, a subscription without its service).
pub fn extract_auth_keys(ci: Option<&CustomerIntegration>, service: &str) -> PyResult<PyValue> {
    let missing = || {
        PyExc::http(
            404,
            format!(
                "No auth keys found for {service} integration. Please create auth keys for \
                 {service} integration."
            ),
        )
    };
    let Some(ci) = ci else {
        return Err(missing());
    };
    let mut keys: Vec<(String, PyValue)> = Vec::new();
    for sub in &ci.subscriptions {
        let Some(svc) = &sub.service else {
            return Err(missing());
        };
        if svc.service_name != service {
            continue;
        }
        for key in &sub.keys {
            let value = PyValue::Str(key.auth_value.clone());
            match keys.iter_mut().find(|(k, _)| *k == key.auth_key_name) {
                Some(slot) => slot.1 = value,
                None => keys.push((key.auth_key_name.clone(), value)),
            }
        }
    }
    if keys.is_empty() {
        return Err(missing());
    }
    Ok(PyValue::Dict(keys))
}

/// A connector column the module payloads read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Column {
    /// `connector_url`.
    Url,
    /// `connector_extra_data`.
    ExtraData,
    /// `connector_username`.
    Username,
    /// `connector_password`.
    Password,
}

fn column(row: Option<&ConnectorRow>, column: Column) -> PyValue {
    let Some(row) = row else {
        return PyValue::None;
    };
    let text = |v: &Option<String>| v.clone().map_or(PyValue::None, PyValue::Str);
    match column {
        Column::Url => PyValue::Str(row.connector_url.clone()),
        Column::ExtraData => text(&row.connector_extra_data),
        Column::Username => text(&row.connector_username),
        Column::Password => text(&row.connector_password),
    }
}

/// `get_connector_attribute(connector_name=…, column_name=…)`: `None` when
/// there is no such connector.
pub async fn connector_by_name(ctx: &AppContext, name: &str, col: Column) -> FailResult<PyValue> {
    let row = ctx.connectors.get(name).await?;
    Ok(column(row.as_ref(), col))
}

/// `get_connector_attribute(connector_id=…, column_name=…)`: the row with
/// that primary key (Python reads it by the name it once had under that id,
/// the same row while names are unique).
pub async fn connector_by_id(ctx: &AppContext, id: i64, col: Column) -> FailResult<PyValue> {
    let row = copilot_db::connectors::find_by_id(&ctx.db, id).await?;
    Ok(column(row.as_ref(), col))
}

/// `get_customer_meta_attribute(code, "customer_meta_iris_customer_id",
/// session)`: the first `customersmeta` row's id, `None` without a row.
pub async fn iris_customer_id(db: &Db, code: &str) -> FailResult<PyValue> {
    let rows = sqlx::query(
        "SELECT customersmeta.customer_meta_iris_customer_id FROM customersmeta \
         WHERE customersmeta.customer_code = ?",
    )
    .bind(code)
    .fetch_all(db.pool())
    .await?;
    let Some(row) = rows.first() else {
        return Ok(PyValue::None);
    };
    let id: Option<i32> = row.try_get(0)?;
    Ok(id.map_or(PyValue::None, |i| PyValue::Int(i.to_string())))
}

/// The customers whose metadata carries `iris_id` (the SAP analyses'
/// tenant, §4).
pub async fn iris_owners(db: &Db, iris_id: &str) -> FailResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT customersmeta.customer_code FROM customersmeta \
         WHERE customersmeta.customer_meta_iris_customer_id = ?",
    )
    .bind(iris_id)
    .persistent(false)
    .fetch_all(db.pool())
    .await?;
    rows.iter()
        .map(|r| r.try_get::<String, _>(0).map_err(Fail::from))
        .collect()
}

/// `get_license(session).license_key`: the first `license` row's key, or the
/// 404 (as `copilot_threat_intel::license::license_key`, which needs that
/// crate's state).
pub async fn license_key(db: &Db) -> FailResult<String> {
    let key = sqlx::query_scalar::<_, String>("SELECT license.license_key FROM license")
        .fetch_optional(db.pool())
        .await?;
    key.ok_or_else(|| PyExc::http(404, "No license found. A license must be created first.").into())
}

/// `select(CustomerIntegrations).where(integration_service_name == name)`:
/// the customer code of every row, in the statement's row order (the jobs'
/// loop).
pub async fn customers_with_integration(db: &Db, service_name: &str) -> FailResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT customer_integrations.id, customer_integrations.customer_code, \
         customer_integrations.customer_name, customer_integrations.integration_service_id, \
         customer_integrations.integration_service_name, customer_integrations.instance_name, \
         customer_integrations.deployed \nFROM customer_integrations \nWHERE \
         customer_integrations.integration_service_name = ?",
    )
    .bind(service_name)
    .fetch_all(db.pool())
    .await?;
    rows.iter()
        .map(|r| r.try_get::<String, _>(1).map_err(Fail::from))
        .collect()
}

/// `get_scheduled_job_metadata(job_id)`: `(time_interval, extra_data)` of
/// the first row, `None` without one.
pub async fn job_metadata(db: &Db, job_id: &str) -> FailResult<Option<(i64, Option<String>)>> {
    let rows = sqlx::query(
        "SELECT scheduled_job_metadata.time_interval, scheduled_job_metadata.extra_data \
         FROM scheduled_job_metadata WHERE scheduled_job_metadata.job_id = ?",
    )
    .bind(job_id)
    .fetch_all(db.pool())
    .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let minutes: i32 = row.try_get(0)?;
    let extra: Option<String> = row.try_get(1)?;
    Ok(Some((i64::from(minutes), extra)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_integrations::integrations::store::{AuthKey, Service, Subscription};

    fn sub(id: i64, service: Option<&str>, keys: &[(&str, &str)]) -> Subscription {
        Subscription {
            id,
            customer_id: Some(1),
            service_id: Some(id),
            service: service.map(|s| Service {
                id,
                service_name: s.into(),
                auth_type: "api".into(),
            }),
            keys: keys
                .iter()
                .enumerate()
                .map(|(i, (k, v))| AuthKey {
                    id: i64::try_from(i).unwrap_or_default(),
                    subscription_id: Some(id),
                    auth_key_name: (*k).into(),
                    auth_value: (*v).into(),
                })
                .collect(),
        }
    }

    fn ci(subs: Vec<Subscription>) -> CustomerIntegration {
        CustomerIntegration {
            id: 1,
            customer_code: "c".into(),
            customer_name: "C".into(),
            integration_service_id: 1,
            integration_service_name: "Huntress".into(),
            instance_name: None,
            deployed: None,
            subscriptions: subs,
        }
    }

    #[test]
    fn auth_keys_flatten_like_python() {
        let c = ci(vec![
            sub(
                1,
                Some("Huntress"),
                &[("API_KEY", "a"), ("API_SECRET", "s")],
            ),
            sub(2, Some("Other"), &[("X", "x")]),
            sub(3, Some("Huntress"), &[("API_KEY", "b")]),
        ]);
        let keys = extract_auth_keys(Some(&c), "Huntress").expect("keys");
        assert_eq!(keys.py_repr(), "{'API_KEY': 'b', 'API_SECRET': 's'}");
        let none = extract_auth_keys(None, "SAP SIEM").expect_err("404");
        assert_eq!(
            none.display(),
            "404: No auth keys found for SAP SIEM integration. Please create auth keys for SAP \
             SIEM integration."
        );
        assert!(extract_auth_keys(Some(&c), "Duo").is_err());
        let broken = ci(vec![sub(1, None, &[("A", "a")])]);
        assert!(extract_auth_keys(Some(&broken), "Huntress").is_err());
    }

    #[test]
    fn find_takes_the_first_with_the_service() {
        let cis = vec![ci(vec![sub(1, Some("Other"), &[])]), {
            let mut c = ci(vec![sub(2, Some("Huntress"), &[])]);
            c.id = 2;
            c
        }];
        assert_eq!(
            find_customer_integration(&cis, "Huntress")
                .expect("ok")
                .map(|c| c.id),
            Some(2)
        );
        assert!(
            find_customer_integration(&cis, "Nope")
                .expect("ok")
                .is_none()
        );
        let broken = vec![ci(vec![sub(1, None, &[])])];
        assert_eq!(
            find_customer_integration(&broken, "x")
                .expect_err("raises")
                .text(),
            "'NoneType' object has no attribute 'service_name'"
        );
    }
}
