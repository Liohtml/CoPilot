//! The routes, by full path: `/api/integrations/modules/{huntress,mimecast,
//! duo,cato,sap_siem}` (and the seven SAP SIEM analyses), mounted by
//! `app/routers/modules.py`, and `POST /api/mimecast/invoke`, `/ttp/urls`.
//!
//! Every route is `require_any_scope("admin", "analyst")`. The body is read
//! before the token is checked (a malformed one is the 422 first), validated
//! after it; then the tenant the body names is checked against the
//! caller's customers — `customer_code`, or the SAP analyses'
//! `iris_customer_id` through `customersmeta` (fail closed) — which Python
//! does not do (§4).

use axum::Router;
use axum::extract::State;
use axum::routing::post;
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Model, field};
use copilot_upstream::respond::{body_model, model_response};
use copilot_web::WithJson;
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized, JsonBody};
use http::StatusCode;

use crate::ModulesState;
use crate::collect::{self, Module};
use crate::lookups;
use crate::mimecast;
use crate::sap_siem::{self, ANALYSES, Analysis};
use crate::schema::{self, invoke_response};

type Soc = Authorized<AdminOrAnalyst>;

/// The prefix `app/routers/modules.py` mounts the module routers under.
pub const MODULES: &str = "/api/integrations/modules";

/// Every route, by full path.
pub fn router(state: ModulesState) -> Router {
    let mut r = Router::new()
        .route(&format!("{MODULES}/huntress"), post(huntress))
        .route(&format!("{MODULES}/mimecast"), post(mimecast_module))
        .route(&format!("{MODULES}/duo"), post(duo))
        .route(&format!("{MODULES}/cato"), post(cato))
        .route(&format!("{MODULES}/sap_siem"), post(sap_collect))
        .route("/api/mimecast/invoke", post(mimecast_invoke))
        .route("/api/mimecast/ttp/urls", post(mimecast_ttp));
    for (i, analysis) in ANALYSES.iter().enumerate() {
        r = r.route(
            &format!("{MODULES}/sap_siem/{}", analysis.route),
            post(move |st: State<ModulesState>, body: WithJson<Soc>| sap_analysis(st, body, i)),
        );
    }
    r.with_state(state)
}

fn text(v: &PyValue) -> String {
    v.as_str().unwrap_or_default().to_string()
}

/// The body (`customer_code`, `integration_name`), then the tenant.
async fn module_body(
    st: &ModulesState,
    auth: &Soc,
    body: &JsonBody,
    model: &'static Model,
) -> Result<(String, String), ApiError> {
    let request = body_model(body, model)?;
    let code = text(field(&request, "customer_code"));
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok((code, text(field(&request, "integration_name"))))
}

async fn run_module(
    st: ModulesState,
    auth: Soc,
    body: JsonBody,
    model: &'static Model,
    module: Module,
) -> ApiResult {
    let (code, name) = module_body(&st, &auth, &body, model).await?;
    Ok(model_response(
        &collect::collect(&st, module, &code, &name).await,
    ))
}

async fn huntress(
    State(st): State<ModulesState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    run_module(st, auth, body, &schema::INVOKE_HUNTRESS, Module::Huntress).await
}

async fn mimecast_module(
    State(st): State<ModulesState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    run_module(st, auth, body, &schema::INVOKE_MIMECAST, Module::Mimecast).await
}

async fn duo(State(st): State<ModulesState>, WithJson(auth, body): WithJson<Soc>) -> ApiResult {
    run_module(st, auth, body, &schema::INVOKE_DUO, Module::Duo).await
}

async fn cato(State(st): State<ModulesState>, WithJson(auth, body): WithJson<Soc>) -> ApiResult {
    run_module(st, auth, body, &schema::INVOKE_CATO, Module::Cato).await
}

const SAP_COLLECTED: &str = "SAP SIEM Events collected successfully.";

async fn sap_collect(
    State(st): State<ModulesState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let request = sap_siem::validate_request(&body, sap_siem::utcnow())?;
    auth.enforce_customer(&st.ctx, &text(field(&request, "customer_code")))
        .await?;
    sap_siem::collect(&st, &request).await?;
    Ok(model_response(&invoke_response(true, SAP_COLLECTED)))
}

/// The analyses' tenant: the customers whose metadata carries the IRIS id,
/// every one of them the caller's (none is a refusal).
async fn enforce_iris(st: &ModulesState, auth: &Soc, iris: &PyValue) -> Result<(), ApiError> {
    let scope = auth.access(&st.ctx).await?;
    if scope.is_all() {
        return Ok(());
    }
    let id = iris.py_str();
    let owners = lookups::iris_owners(&st.ctx.db, &id).await?;
    if !owners.is_empty() && owners.iter().all(|o| scope.can_access(o)) {
        Ok(())
    } else {
        Err(ApiError::http(
            StatusCode::FORBIDDEN,
            format!("Access denied to IRIS customer {id}"),
        ))
    }
}

async fn sap_analysis(
    State(st): State<ModulesState>,
    WithJson(auth, body): WithJson<Soc>,
    index: usize,
) -> ApiResult {
    let analysis: &Analysis = &ANALYSES[index];
    let request = body_model(&body, &schema::SAP_ANALYSIS)?;
    let iris = field(&request, "iris_customer_id").clone();
    enforce_iris(&st, &auth, &iris).await?;
    sap_siem::analyse(
        &st,
        analysis,
        field(&request, "threshold").clone(),
        field(&request, "time_range").clone(),
        iris,
    )
    .await?;
    Ok(model_response(&invoke_response(true, SAP_COLLECTED)))
}

/// `MimecastRequest` as FastAPI validates it (with its `time_range`
/// pattern), then the tenant.
async fn mimecast_body(
    st: &ModulesState,
    auth: &Soc,
    body: &JsonBody,
) -> Result<PyValue, ApiError> {
    let request = match body {
        JsonBody::Value(v @ serde_json::Value::Object(_)) => sap_siem::validate_with_pattern(
            &schema::MIMECAST_REQUEST,
            &copilot_upstream::respond::from_json(v),
            true,
        )
        .map_err(|errors| copilot_upstream::respond::validation_error(errors, "body"))?,
        other => body_model(other, &schema::MIMECAST_REQUEST)?,
    };
    auth.enforce_customer(&st.ctx, &text(field(&request, "customer_code")))
        .await?;
    Ok(request)
}

async fn mimecast_invoke(
    State(st): State<ModulesState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let request = mimecast_body(&st, &auth, &body).await?;
    mimecast::invoke(
        &st,
        &text(field(&request, "customer_code")),
        &text(field(&request, "integration_name")),
    )
    .await?;
    Ok(model_response(&invoke_response(
        true,
        "Successfully invoked Mimecast integration.",
    )))
}

async fn mimecast_ttp(
    State(st): State<ModulesState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let request = mimecast_body(&st, &auth, &body).await?;
    tracing::info!(target: "copilot::integration_modules", "Mimecast TTP URL request received");
    mimecast::ttp_urls(
        &st,
        &text(field(&request, "customer_code")),
        &text(field(&request, "integration_name")),
        field(&request, "time_range"),
    )
    .await?;
    Ok(model_response(&invoke_response(
        true,
        "Mimecast TTP URL request successful",
    )))
}
