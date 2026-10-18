//! `verify_grafana_connection(name)`: the row's URL is logged before the
//! `None` check (a missing row is the `TypeError`: no outcome), the URL with
//! the credentials embedded is built outside the `try` (its `ValueError`:
//! no outcome), then `admin.create_user(test user)` and
//! `admin.delete_user(id)` through `grafana_client` (`copilot-grafana`). The
//! failure message names that URL, credentials and `?verify=false`
//! included, as Python's does.

use async_trait::async_trait;
use http::Method;

use copilot_auth::pyvalue::PyValue;
use copilot_connectors::{ConnectorVerifier, VerifyOutcome};
use copilot_db::connectors::ConnectorCache;
use copilot_grafana::GrafanaClient;
use copilot_grafana::client::build_api;
use copilot_upstream::model::kwargs;
use copilot_upstream::py::{PyExc, PyResult, getitem};

use crate::outcome;

/// The Grafana verifier.
#[derive(Debug, Clone)]
pub struct GrafanaVerifier(pub GrafanaClient);

/// `construct_grafana_url(url, username, password, verify=False)`.
pub fn grafana_url(url: &str, user: &str, password: &str) -> Option<String> {
    let mut out = if url.contains("http://") {
        url.replace("http://", &format!("http://{user}:{password}@"))
    } else if url.contains("https://") {
        url.replace("https://", &format!("https://{user}:{password}@"))
    } else {
        return None;
    };
    out.push_str("?verify=false");
    Some(out)
}

#[async_trait]
impl ConnectorVerifier for GrafanaVerifier {
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome {
        let row = connectors.get(name).await.ok()??;
        let url = row.connector_url.clone();
        tracing::info!("Verifying the Grafana connection to {url}");
        let user = row
            .connector_username
            .clone()
            .unwrap_or_else(|| "None".into());
        let password = row
            .connector_password
            .clone()
            .unwrap_or_else(|| "None".into());
        let full = grafana_url(&url, &user, &password)?;
        // `GrafanaApi.from_url(grafana_url)`: a URL it refuses raises out.
        let api = build_api(
            &url,
            row.connector_username.as_deref(),
            row.connector_password.as_deref(),
        )
        .ok()?;
        let g = &self.0;
        let result: PyResult<()> = async {
            let test_user = kwargs(vec![
                ("name", PyValue::Str("test".into())),
                ("email", PyValue::Str("test@socfortress.co".into())),
                ("login", PyValue::Str("test".into())),
                ("password", PyValue::Str("this_is_a_test_user".into())),
                ("OrgID", PyValue::Int("1".into())),
            ]);
            let created = g
                .call(
                    &api,
                    Method::POST,
                    "/admin/users",
                    Some(test_user),
                    Vec::new(),
                )
                .await?;
            let message = getitem(&created, "message")?;
            if message != &PyValue::Str("User created".into()) {
                return Err(PyExc::Other(
                    "Exception",
                    format!("Failed to create user: {}", message.py_str()),
                ));
            }
            let id = getitem(&created, "id")?.py_str();
            g.call(
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
        match result {
            Ok(()) => {
                tracing::info!("Connection to {full} successful");
                outcome(true, "Grafana connection successful")
            }
            Err(e) => {
                let text = format!("Connection to {full} failed with error: {}", e.display());
                tracing::error!("{text}");
                outcome(false, text)
            }
        }
    }
}
