//! `/api/sysmon_config` — port of
//! `app/active_response/routes/sysmon_config.py` but the upload.
//!
//! A responder may read their customers' configs and deploy them (#1219);
//! every route keyed by a customer code checks it first
//! (`verify_customer_code_access`), and the list keeps only the caller's
//! customers (`scoped_customer_codes`). A deploy is audited as
//! `response.sysmon_deploy` before anything is fetched, as in Python.
//!
//! Still Python: `POST /upload` (admin) validates the XML with
//! `xml.etree.ElementTree`, whose refusals are expat's error texts (`not
//! well-formed (invalid token): line 3, column 4`, …); no route here matches
//! it (`/{customer_code}` is a `GET`), so the binary forwards it.

use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use http::{HeaderValue, StatusCode};

use copilot_auth::AccessScope;
use copilot_core::audit::AuditRecord;
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::model_response;
use copilot_velociraptor::routes::AdminOrResponder;
use copilot_web::{ApiError, ApiResult, Authorized};

use crate::ResponseState;
use crate::sysmon::schema::{content_response, list_response};
use crate::sysmon::services;

type Responder = Authorized<AdminOrResponder>;

/// The router to nest at `/api/sysmon_config`.
pub fn router(state: ResponseState) -> Router {
    Router::new()
        .route("/", get(list))
        .route("/content/{customer_code}", get(content))
        .route("/{customer_code}", get(download))
        .route("/deploy/{customer_code}", post(deploy))
        .with_state(state)
}

/// `GET /content/{code}`: the config as text.
async fn content(
    auth: Responder,
    State(st): State<ResponseState>,
    Path(customer_code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &customer_code).await?;
    let data = match services::download(&st.store, &customer_code).await {
        Ok(d) => d,
        Err(PyExc::Http(status, detail)) => return Err(PyExc::Http(status, detail).into()),
        Err(e) => {
            return Err(ApiError::server_error(format!(
                "Error retrieving config: {}",
                e.display()
            )));
        }
    };
    let text = String::from_utf8(data.to_vec())
        .map_err(|_| ApiError::server_error("Failed to decode config file as UTF-8"))?;
    Ok(model_response(&content_response(&customer_code, text)))
}

/// `GET ""`: the customers with a config, among the caller's.
async fn list(auth: Responder, State(st): State<ResponseState>) -> ApiResult {
    let mut codes = services::list(&st.store).await;
    let allowed = match auth.access(&st.ctx).await? {
        AccessScope::All => None,
        AccessScope::Customers(c) if c.iter().any(|x| x == "*") => None,
        AccessScope::Customers(c) => Some(c.clone()),
    };
    if let Some(allowed) = allowed {
        codes.retain(|c| allowed.contains(c));
    }
    Ok(model_response(&list_response(codes)))
}

/// `GET /{code}`: the config as a download (`Response(content=…,
/// media_type="application/xml")`, latin-1 headers).
async fn download(
    auth: Responder,
    State(st): State<ResponseState>,
    Path(customer_code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &customer_code).await?;
    let retrieving =
        |e: PyExc| ApiError::server_error(format!("Error retrieving config: {}", e.display()));
    let data = match services::download(&st.store, &customer_code).await {
        Ok(d) => d,
        Err(PyExc::Http(status, detail)) => return Err(PyExc::Http(status, detail).into()),
        Err(e) => return Err(retrieving(e)),
    };
    let disposition = copilot_objectstore::web::latin1(&format!(
        "attachment; filename=sysmon_config_{customer_code}.xml"
    ))
    .map_err(retrieving)?;
    let disposition = HeaderValue::from_bytes(&disposition)
        .map_err(|e| ApiError::internal(format!("header value: {e}")))?;
    let mut resp: Response = (StatusCode::OK, data).into_response();
    let headers = resp.headers_mut();
    headers.insert(http::header::CONTENT_DISPOSITION, disposition);
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    Ok(resp)
}

/// `POST /deploy/{code}`: audited, then fetched and POSTed to the worker;
/// always a `SysmonConfigDeploymentResult`.
async fn deploy(
    auth: Responder,
    State(st): State<ResponseState>,
    Path(customer_code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &customer_code).await?;
    st.ctx.audit.record(
        AuditRecord::new("response.sysmon_deploy")
            .actor(Some(auth.id), Some(&auth.username))
            .customer(Some(&customer_code))
            .entity("sysmon_config", &customer_code)
            .source_ip(auth.source_ip.clone()),
    );
    let dump = services::deploy(
        &st.store,
        &st.ctx.connectors,
        &st.worker,
        &st.env.provision_worker_port,
        &customer_code,
    )
    .await;
    Ok(model_response(&dump))
}
