//! `/api/copilot_action` — port of
//! `app/integrations/copilot_action/routes/copilot_action.py`.
//!
//! Every route is admin/responder (#1219). The inventory routes ask the
//! CoPilot Action service with `COPILOT_API_KEY` (unset or empty: the 500
//! after the query is validated); `/technologies` is static. The invoke
//! names its targets in the body: an empty `agent_names` is a 400, each
//! hostname's tenant is checked (`enforce_hostname_access`, fail-closed)
//! before anything runs, the call is audited as
//! `response.copilot_action_invoke`, and a scoped caller's action runs only
//! on agents of their own customers (§4).

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use serde_json::{Map, Value};

use copilot_auth::AccessScope;
use copilot_auth::pyvalue::PyValue;
use copilot_core::audit::AuditRecord;
use copilot_upstream::model::field;
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::{body_model, model_response};
use copilot_velociraptor::routes::AdminOrResponder;
use copilot_web::validate::{IntRules, StrRules, Validator};
use copilot_web::{ApiError, ApiResult, Authorized, QueryPairs, WithJson};

use crate::ResponseState;
use crate::copilot_action::invoke::{agents_by_hostnames, invoke as run_invoke};
use crate::copilot_action::schema::{INVOKE_BODY, TECHNOLOGIES};
use crate::copilot_action::services::{self, InventoryQuery};

type Responder = Authorized<AdminOrResponder>;

/// The router to nest at `/api/copilot_action`.
pub fn router(state: ResponseState) -> Router {
    Router::new()
        .route("/inventory", get(inventory))
        .route("/inventory/count", get(inventory_count))
        .route("/inventory/{copilot_action_name}", get(by_name))
        .route("/metrics", get(metrics))
        .route("/technologies", get(technologies))
        .route("/invoke", post(invoke))
        .with_state(state)
}

/// `get_license_key()`.
fn license_key(st: &ResponseState) -> Result<String, ApiError> {
    match st.env.copilot_api_key.as_deref().filter(|k| !k.is_empty()) {
        Some(k) => Ok(k.to_string()),
        None => {
            tracing::error!("COPILOT_API_KEY environment variable not set");
            Err(ApiError::server_error(
                "COPILOT_API_KEY environment variable not configured",
            ))
        }
    }
}

fn one(q: &QueryPairs, name: &str) -> Option<Map<String, Value>> {
    let raw = q.get(name)?;
    let mut map = Map::new();
    map.insert(name.into(), Value::String(raw.into()));
    Some(map)
}

/// The four filters both inventory routes take, in declaration order.
fn filters(q: &QueryPairs, v: &mut Validator) -> InventoryQuery {
    let at = vec![copilot_web::validate::LocPart::Key("query".into())];
    let technology =
        one(q, "technology").and_then(|m| v.opt_enum(&m, &at, "technology", TECHNOLOGIES));
    InventoryQuery {
        technology,
        category: q.opt_str(v, "category", StrRules::any()),
        tag: q.opt_str(v, "tag", StrRules::any()),
        q: q.opt_str(v, "q", StrRules::any()),
        limit: 100,
        offset: 0,
        refresh: false,
        include: None,
    }
}

async fn inventory(auth: Responder, State(st): State<ResponseState>, q: QueryPairs) -> ApiResult {
    let _ = &auth;
    let mut v = Validator::new();
    let mut query = filters(&q, &mut v);
    query.limit = q.int_or(
        &mut v,
        "limit",
        IntRules {
            ge: Some(1),
            le: Some(1000),
        },
        100,
    );
    query.offset = q.int_or(
        &mut v,
        "offset",
        IntRules {
            ge: Some(0),
            le: None,
        },
        0,
    );
    let at = vec![copilot_web::validate::LocPart::Key("query".into())];
    query.refresh = one(&q, "refresh").is_some_and(|m| v.bool_or(&m, &at, "refresh", false));
    query.include = q.opt_str(&mut v, "include", StrRules::any());
    v.finish()?;
    let key = license_key(&st)?;
    let dump = services::get_inventory(&st.action, &key, &query).await;
    Ok(model_response(&dump))
}

async fn inventory_count(
    auth: Responder,
    State(st): State<ResponseState>,
    q: QueryPairs,
) -> ApiResult {
    let _ = &auth;
    let mut v = Validator::new();
    let mut query = filters(&q, &mut v);
    v.finish()?;
    let key = license_key(&st)?;
    query.limit = 1;
    let dump = services::get_inventory(&st.action, &key, &query).await;
    let total = field(&dump, "total").clone();
    let n: i128 = match &total {
        PyValue::Int(t) => t.parse().unwrap_or(0),
        _ => 0,
    };
    let int = |x: i128| PyValue::Int(x.to_string());
    let body = PyValue::Dict(vec![
        ("total".into(), total),
        (
            "message".into(),
            PyValue::Str("Successfully retrieved inventory count".into()),
        ),
        ("success".into(), PyValue::Bool(true)),
        ("current_page".into(), int(1)),
        ("total_pages".into(), int((n + 99).div_euclid(100))),
        ("has_next".into(), PyValue::Bool(100 < n)),
        ("has_prev".into(), PyValue::Bool(false)),
        ("items_per_page".into(), int(100)),
        ("total_items".into(), int(n)),
    ]);
    Ok(model_response(&body))
}

/// The route function `get_action_by_name`: the detail dump, or the
/// `HTTPException` it raises.
async fn action_by_name(st: &ResponseState, name: &str) -> Result<PyValue, ApiError> {
    let key = license_key(st)?;
    let dump = match services::get_action_by_name(&st.action, &key, name).await {
        Ok(d) => d,
        Err(PyExc::Http(status, detail)) => return Err(PyExc::Http(status, detail).into()),
        Err(e) => {
            return Err(ApiError::server_error(format!(
                "Error fetching action details: {}",
                e.display()
            )));
        }
    };
    if !matches!(field(&dump, "success"), PyValue::Bool(true)) {
        let message = field(&dump, "message")
            .as_str()
            .unwrap_or_default()
            .to_string();
        return Err(if message.to_lowercase().contains("not found") {
            ApiError::not_found(message)
        } else {
            ApiError::server_error(message)
        });
    }
    Ok(dump)
}

async fn by_name(
    auth: Responder,
    State(st): State<ResponseState>,
    Path(name): Path<String>,
) -> ApiResult {
    let _ = &auth;
    let dump = action_by_name(&st, &name).await?;
    Ok(model_response(&dump))
}

async fn metrics(auth: Responder, State(st): State<ResponseState>) -> ApiResult {
    let _ = &auth;
    let key = license_key(&st)?;
    Ok(model_response(
        &services::get_metrics(&st.action, &key).await,
    ))
}

async fn technologies(auth: Responder) -> ApiResult {
    let _ = &auth;
    Ok(model_response(&PyValue::Dict(vec![
        (
            "technologies".into(),
            PyValue::List(
                TECHNOLOGIES
                    .iter()
                    .map(|t| PyValue::Str((*t).into()))
                    .collect(),
            ),
        ),
        ("total".into(), PyValue::Int(TECHNOLOGIES.len().to_string())),
        (
            "message".into(),
            PyValue::Str("Successfully retrieved available technologies".into()),
        ),
        ("success".into(), PyValue::Bool(true)),
    ])))
}

/// `select(Agents.customer_code).where(Agents.hostname == h)`, first.
async fn owner_of_hostname(st: &ResponseState, hostname: &str) -> Result<Option<String>, ApiError> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT agents.customer_code FROM agents WHERE agents.hostname = ?")
            .bind(hostname)
            .fetch_optional(st.ctx.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(row.and_then(|(c,)| c))
}

async fn invoke(
    State(st): State<ResponseState>,
    WithJson(auth, body): WithJson<Responder>,
) -> ApiResult {
    let dump = body_model(&body, &INVOKE_BODY)?;
    let name = field(&dump, "copilot_action_name")
        .as_str()
        .unwrap_or_default()
        .to_string();
    let names: Vec<String> = match field(&dump, "agent_names") {
        PyValue::List(items) => items
            .iter()
            .filter_map(|i| i.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };
    tracing::info!("Invoking Copilot action '{name}' on {} agents", names.len());
    if names.is_empty() {
        return Err(ApiError::bad_request(
            "Name at least one agent to invoke the action on",
        ));
    }
    for hostname in &names {
        let owner = owner_of_hostname(&st, hostname).await?;
        auth.enforce_owned(&st.ctx, owner.as_deref(), &format!("host {hostname}"))
            .await?;
    }
    st.ctx.audit.record(
        AuditRecord::new("response.copilot_action_invoke")
            .actor(Some(auth.id), Some(&auth.username))
            .entity("copilot_action", &name)
            .values(None, Some(serde_json::json!({"agents": names})))
            .source_ip(auth.source_ip.clone()),
    );
    let customers = match auth.access(&st.ctx).await? {
        AccessScope::All => None,
        AccessScope::Customers(c) if c.iter().any(|x| x == "*") => None,
        AccessScope::Customers(c) => Some(c.clone()),
    };
    let parameters: Vec<(String, PyValue)> = match field(&dump, "parameters") {
        PyValue::Dict(items) => items.clone(),
        _ => Vec::new(),
    };
    let unexpected = |e: PyExc| {
        ApiError::server_error(format!("Error invoking Copilot action: {}", e.display()))
    };
    let agents = match agents_by_hostnames(&st.ctx.db, &names, customers.as_deref()).await {
        Ok(a) => a,
        Err(PyExc::Http(status, detail)) => return Err(PyExc::Http(status, detail).into()),
        Err(e) => return Err(unexpected(e)),
    };
    let action = action_by_name(&st, &name).await?;
    match run_invoke(&st, &action, agents, parameters).await {
        Ok(out) => Ok(model_response(&out)),
        Err(PyExc::Http(status, detail)) => Err(PyExc::Http(status, detail).into()),
        Err(e) => Err(unexpected(e)),
    }
}
