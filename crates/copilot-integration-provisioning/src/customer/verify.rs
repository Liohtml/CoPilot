//! `verify_required_tools()`: Graylog, the Wazuh manager and Grafana, each
//! through the function its connector's verification uses
//! (`verify_graylog_connection`, `verify_wazuh_manager_connection`,
//! `verify_grafana_connection`), a `connectionSuccessful` of `False` the 500
//! naming the tool. A verifier that answers `None` (no connector row) is the
//! `TypeError` of subscripting it (a bare 500), as in Python.

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_grafana::client::CONNECTOR as GRAFANA;
use copilot_upstream::http::{PyHttp, PyRequest};
use copilot_upstream::model::kwargs;
use copilot_upstream::py::{PyExc, PyResult, getitem};
use http::Method;

use super::Customer;

/// `GRAYLOG_REQUEST_TIMEOUT`.
const GRAYLOG_TIMEOUT: Duration = Duration::from_secs(60);

fn none_subscript() -> PyExc {
    PyExc::TypeError("'NoneType' object is not subscriptable".into())
}

fn db_err(e: impl std::fmt::Display) -> PyExc {
    PyExc::Other("OperationalError", e.to_string())
}

/// `verify_connection(name, func)`.
fn require(name: &str, outcome: Option<bool>) -> PyResult<()> {
    match outcome {
        None => Err(none_subscript()),
        Some(true) => Ok(()),
        Some(false) => Err(PyExc::http(
            500,
            format!(
                "Failed to connect to {name}. {name} connection must be established to proceed."
            ),
        )),
    }
}

/// `verify_required_tools()`.
pub async fn verify_required_tools(c: Customer<'_>) -> PyResult<()> {
    tracing::info!("Verifying required tools");
    require("Graylog", graylog(c).await?)?;
    require("Wazuh-Manager", wazuh_manager(c).await?)?;
    require("Grafana", grafana(c).await?)
}

/// `verify_graylog_credentials`: `GET /api/authz/roles/user/<user>` with
/// Basic auth, certificates not verified; 200 is success, anything else
/// (an exception included) failure.
async fn graylog(c: Customer<'_>) -> PyResult<Option<bool>> {
    let Some(row) = c.ctx.connectors.get("Graylog").await.map_err(db_err)? else {
        tracing::error!("No Graylog connector found in the database");
        return Ok(None);
    };
    let user = row
        .connector_username
        .clone()
        .unwrap_or_else(|| "None".into());
    let url = format!("{}/api/authz/roles/user/{user}", row.connector_url);
    tracing::info!("Verifying the graylog connection to {}", row.connector_url);
    let http = PyHttp::new(GRAYLOG_TIMEOUT, false)
        .map_err(|e| PyExc::Other("Exception", e.to_string()))?;
    let request = PyRequest::new(Method::GET, url).basic(
        row.connector_username.clone(),
        row.connector_password.clone(),
    );
    Ok(Some(match http.send(request).await {
        Ok(resp) => resp.status() == 200,
        Err(e) => {
            tracing::error!(
                "Connection to {} failed with error: {}",
                row.connector_url,
                e.display()
            );
            false
        }
    }))
}

/// `verify_wazuh_manager_credentials`: `GET /security/user/authenticate`.
async fn wazuh_manager(c: Customer<'_>) -> PyResult<Option<bool>> {
    let Some(row) = c
        .ctx
        .connectors
        .get(copilot_wazuh::manager::client::CONNECTOR)
        .await
        .map_err(db_err)?
    else {
        tracing::error!("No Wazuh Manager connector found in the database");
        return Ok(None);
    };
    tracing::info!(
        "Verifying the wazuh-manager connection to {}",
        row.connector_url
    );
    Ok(Some(matches!(
        c.tools.wazuh.manager.authenticate(&row).await,
        Ok(200)
    )))
}

/// `verify_grafana_credentials`: a test user created through the admin API
/// and deleted again. The URL is checked first, outside the `try` (its
/// `ValueError` is the handler's 400).
async fn grafana(c: Customer<'_>) -> PyResult<Option<bool>> {
    // `logger.info(f"… {attributes['connector_url']}")` before the `None`
    // check: a missing row is the `TypeError`.
    let row = c
        .tools
        .grafana
        .row(GRAFANA)
        .await?
        .ok_or_else(none_subscript)?;
    tracing::info!("Verifying the Grafana connection to {}", row.connector_url);
    if !row.connector_url.contains("http://") && !row.connector_url.contains("https://") {
        return Err(PyExc::ValueError("Invalid connector URL format".into()));
    }
    let api = c.tools.grafana.create(GRAFANA).await?;
    let user = kwargs(vec![
        ("name", PyValue::Str("test".into())),
        ("email", PyValue::Str("test@socfortress.co".into())),
        ("login", PyValue::Str("test".into())),
        ("password", PyValue::Str("this_is_a_test_user".into())),
        ("OrgID", PyValue::Int("1".into())),
    ]);
    let outcome: PyResult<()> = async {
        let created = c
            .tools
            .grafana
            .call(&api, Method::POST, "/admin/users", Some(user), Vec::new())
            .await?;
        let message = getitem(&created, "message")?;
        if message != &PyValue::Str("User created".into()) {
            return Err(PyExc::Other(
                "Exception",
                format!("Failed to create user: {}", message.py_str()),
            ));
        }
        let id = getitem(&created, "id")?.py_str();
        c.tools
            .grafana
            .call(
                &api,
                Method::DELETE,
                &format!("/admin/users/{id}"),
                None,
                Vec::new(),
            )
            .await?;
        Ok(())
    }
    .await;
    Ok(Some(match outcome {
        Ok(()) => true,
        Err(e) => {
            tracing::error!("Grafana connection failed with error: {}", e.display());
            false
        }
    }))
}
