//! The handlers, by full path, `require_any_scope("admin", "analyst")`.
//!
//! The request models set their `integration_name` in a
//! `model_validator(mode="before")` that assigns into the input
//! (`copilot_integration_provisioning::routes::read_forced`: a body that is
//! not an object is that assignment's `TypeError`, a bare 500). FastAPI's
//! order is kept: the body decoded, the token, the body validated, then the
//! handler — whose first step is the tenant check on the body's customer
//! (Office 365: a deliberate difference, §4; AWS: Python's own check).

use axum::Router;
use axum::extract::State;
use axum::routing::post;
use copilot_integration_provisioning::routes::read_forced;
use copilot_monitoring_alerts::body::WithPyJson;
use copilot_upstream::model::field;
use copilot_upstream::respond::model_response;
use copilot_web::{AdminOrAnalyst, ApiResult, Authorized};

use crate::CloudState;
use crate::rollback::failure_response;
use crate::{aws, office365};

type Reader = Authorized<AdminOrAnalyst>;

/// The routes.
pub fn router(state: CloudState) -> Router {
    Router::new()
        .route("/api/office365/provision", post(provision_office365))
        .route("/api/aws/provision", post(provision_aws))
        .with_state(state)
}

fn opt_text(v: &copilot_auth::pyvalue::PyValue) -> Option<String> {
    match v {
        copilot_auth::pyvalue::PyValue::None => None,
        other => Some(other.py_str()),
    }
}

async fn provision_office365(
    State(st): State<CloudState>,
    WithPyJson(auth, body): WithPyJson<Reader>,
) -> ApiResult {
    let request = read_forced(
        &body,
        &office365::schema::PROVISION_OFFICE365_REQUEST,
        "integration_name",
        "Office365",
    )?;
    let code = field(&request, "customer_code").py_str();
    auth.enforce_customer(&st.ctx, &code).await?;
    let outcome = office365::provision(
        st.tools(),
        &code,
        &field(&request, "integration_name").py_str(),
        opt_text(field(&request, "instance_name")),
    )
    .await;
    Ok(match outcome {
        Ok(dump) => model_response(&dump),
        Err(e) => failure_response(e),
    })
}

async fn provision_aws(
    State(st): State<CloudState>,
    WithPyJson(auth, body): WithPyJson<Reader>,
) -> ApiResult {
    let request = read_forced(
        &body,
        &aws::schema::PROVISION_AWS_REQUEST,
        "integration_name",
        aws::schema::AWS_INTEGRATION_NAME,
    )?;
    let code = field(&request, "customer_code").py_str();
    auth.enforce_customer(&st.ctx, &code).await?;
    let outcome = aws::provision(
        st.tools(),
        &code,
        opt_text(field(&request, "instance_name")),
    )
    .await;
    Ok(match outcome {
        Ok(dump) => model_response(&dump),
        Err(e) => failure_response(e),
    })
}
