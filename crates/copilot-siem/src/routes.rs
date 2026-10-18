//! `/api/siem/dashboards`, `/api/siem/event_sources` and `/api/siem/events` —
//! port of `app/siem/routes/{dashboards,event_sources,events}.py`.
//!
//! Check order is FastAPI's: the body is read first (malformed JSON is a 422
//! before the token), then the token and its scope, the route's
//! dependencies (`verify_optional_customer_code_access`,
//! `verify_custom_dashboard_access` — a 403 before any 422 of the body),
//! the path, query and body validation, and only then the handler's own
//! tenant checks and the services.
//!
//! A path with an encoded `/` goes to Python: Starlette routes the decoded
//! path, where `…/a%2Fb` is not one segment.

use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::json::pydantic_json;
use copilot_upstream::py::PyExc;
use copilot_web::validate::{IntRules, StrRules, Validator, loc, path_int};
use copilot_web::{
    AdminOnly, AdminOrAnalyst, AnyPortalOrSoc, ApiError, ApiResult, Authorized, QueryPairs,
    WithJson,
};
use http::StatusCode;

use crate::SiemState;
use crate::py::{dict, s};
use crate::schema::{
    Definition, EnableRequest, EventSourceCreate, EventSourceUpdate, ImportRequest,
    PANEL_DATA_RESPONSE, PREVIEW_RESPONSE, PanelDataRequest, PreviewRequest, UpdateRequest,
};
use crate::services::{custom, dashboards, events, sources};

type Any = Authorized<AnyPortalOrSoc>;
type Soc = Authorized<AdminOrAnalyst>;
type Admin = Authorized<AdminOnly>;

/// The three routers with their full paths, behind the encoded-slash
/// hand-off to Python.
pub fn router(state: SiemState) -> Router {
    let dashboards = Router::new()
        .route("/templates", get(list_categories))
        .route("/templates/{category_id}", get(get_category))
        .route("/enabled", get(list_enabled))
        .route("/enabled/{customer_code}", get(list_enabled_of))
        .route("/enable", post(enable))
        .route("/disable/{dashboard_id}", delete(disable))
        .route("/custom", get(list_custom).post(create_custom))
        .route("/custom/import", post(import_custom))
        .route("/custom/preview", post(preview_custom))
        .route(
            "/custom/{template_key}",
            get(get_custom).put(update_custom).delete(delete_custom),
        )
        .route("/custom/{template_key}/export", get(export_custom))
        .route("/panel-data", post(panel_data));
    let event_sources = Router::new().route("/", post(create_source)).route(
        "/{key}",
        get(list_sources).put(update_source).delete(delete_source),
    );
    let events = Router::new()
        .route("/{customer_code}/{source_name}", get(query_events))
        .route(
            "/{customer_code}/{source_name}/document",
            get(event_document),
        )
        .route("/{customer_code}/{source_name}/fields", get(field_mappings));
    Router::new()
        .nest("/api/siem/dashboards", dashboards)
        .nest("/api/siem/event_sources", event_sources)
        .nest("/api/siem/events", events)
        .with_state(state)
}

// --- responses ------------------------------------------------------------------------

/// A `response_model` answer (pydantic-core's JSON).
fn ok(dump: PyValue) -> Response {
    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "application/json")],
        pydantic_json(&dump),
    )
        .into_response()
}

fn done(message: &str) -> PyValue {
    dict(vec![
        ("success", PyValue::Bool(true)),
        ("message", s(message)),
    ])
}

/// `{key: value, "success": True, "message": message}`.
fn wrap(key: &str, value: PyValue, message: &str) -> PyValue {
    dict(vec![
        (key, value),
        ("success", PyValue::Bool(true)),
        ("message", s(message)),
    ])
}

fn fail(e: PyExc) -> ApiError {
    e.unhandled()
}

fn list<T>(rows: &[T], dump: impl Fn(&T) -> Result<PyValue, PyExc>) -> Result<PyValue, ApiError> {
    rows.iter()
        .map(dump)
        .collect::<Result<Vec<_>, _>>()
        .map(PyValue::List)
        .map_err(fail)
}

// --- dashboards: built-in templates -----------------------------------------------------

async fn list_categories(_auth: Any) -> ApiResult {
    let categories = dashboards::list_categories().map_err(fail)?;
    Ok(ok(wrap(
        "categories",
        PyValue::List(categories),
        "Dashboard categories retrieved successfully",
    )))
}

async fn get_category(_auth: Any, Path(category_id): Path<String>) -> ApiResult {
    let category = dashboards::category_detail(&category_id).map_err(fail)?;
    Ok(ok(wrap(
        "category",
        category,
        "Dashboard category retrieved successfully",
    )))
}

// --- dashboards: enabled ------------------------------------------------------------------

async fn list_enabled(State(st): State<SiemState>, auth: Any, q: QueryPairs) -> ApiResult {
    let requested = q.get_all("customer_codes");
    let requested = (!requested.is_empty()).then_some(requested);
    tracing::info!(
        "Listing enabled dashboards for user {} with requested customer_codes={requested:?}",
        auth.username
    );
    let effective = auth
        .access(&st.ctx)
        .await?
        .resolve_effective(requested.as_deref())
        .to_python_list();
    let rows = dashboards::enabled_for(&st, &effective)
        .await
        .map_err(fail)?;
    Ok(ok(wrap(
        "enabled_dashboards",
        list(&rows, dashboards::enabled_dump)?,
        "Enabled dashboards retrieved successfully",
    )))
}

async fn list_enabled_of(
    State(st): State<SiemState>,
    auth: Any,
    Path(customer_code): Path<String>,
) -> ApiResult {
    if !auth.access(&st.ctx).await?.can_access(&customer_code) {
        return Err(ApiError::forbidden(format!(
            "Access denied to customer {customer_code}"
        )));
    }
    dashboards::verify_customer_exists(&st, &customer_code)
        .await
        .map_err(fail)?;
    let rows = dashboards::enabled_of(&st, &customer_code)
        .await
        .map_err(fail)?;
    Ok(ok(wrap(
        "enabled_dashboards",
        list(&rows, dashboards::enabled_dump)?,
        "Enabled dashboards retrieved successfully",
    )))
}

async fn enable(State(st): State<SiemState>, WithJson(auth, body): WithJson<Soc>) -> ApiResult {
    let req = body.model(EnableRequest::read)?;
    // §4: the body names the tenant; Python checked only that it exists.
    auth.enforce_customer(&st.ctx, &req.customer_code).await?;
    tracing::info!("Enabling dashboard for customer {}", req.customer_code);
    dashboards::verify_customer_exists(&st, &req.customer_code)
        .await
        .map_err(fail)?;
    let access = auth.access(&st.ctx).await?.clone();
    let row = dashboards::enable(&st, &req, &access).await.map_err(fail)?;
    Ok(ok(wrap(
        "enabled_dashboard",
        dashboards::enabled_dump(&row).map_err(fail)?,
        "Dashboard enabled successfully",
    )))
}

async fn disable(State(st): State<SiemState>, auth: Soc, Path(raw): Path<String>) -> ApiResult {
    let id = path_int("dashboard_id", &raw)?;
    let owner = dashboards::enabled_owner(&st, id).await.map_err(fail)?;
    auth.enforce_owned(&st.ctx, Some(&owner), &format!("dashboard {id}"))
        .await?;
    tracing::info!("Disabling dashboard {id}");
    dashboards::disable(&st, id).await.map_err(fail)?;
    Ok(ok(done("Dashboard disabled successfully")))
}

// --- dashboards: custom templates --------------------------------------------------------

async fn list_custom(State(st): State<SiemState>, auth: Soc, q: QueryPairs) -> ApiResult {
    // `verify_optional_customer_code_access`.
    let customer_code = q.get("customer_code").map(str::to_string);
    if let Some(code) = customer_code.as_deref().filter(|c| !c.is_empty()) {
        auth.enforce_customer(&st.ctx, code).await?;
    }
    let access = auth.access(&st.ctx).await?.clone();
    let rows = custom::list(&st, customer_code.as_deref(), &access)
        .await
        .map_err(fail)?;
    Ok(ok(wrap(
        "custom_dashboards",
        list(&rows, custom::custom_dump)?,
        "Custom dashboards retrieved successfully",
    )))
}

async fn create_custom(
    State(st): State<SiemState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(|v, obj, at| Definition::read(v, obj, at, true, false))?;
    // §4: a scoped analyst may not file a template under another tenant.
    if let Some(code) = req.customer_code.as_deref().filter(|c| !c.is_empty()) {
        auth.enforce_customer(&st.ctx, code).await?;
    }
    tracing::info!(
        "Creating custom dashboard '{}' for customer {}",
        req.title,
        req.customer_code.as_deref().unwrap_or("ALL")
    );
    let row = custom::create(&st, &req, &auth.username, None, true)
        .await
        .map_err(fail)?;
    Ok(ok(wrap(
        "custom_dashboard",
        custom::custom_dump(&row).map_err(fail)?,
        "Custom dashboard created successfully",
    )))
}

async fn import_custom(
    State(st): State<SiemState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(ImportRequest::read)?;
    // §4: the customer the import files it under, and the template an
    // overwrite replaces, must both be the caller's.
    if let Some(code) = req.customer_code.as_deref().filter(|c| !c.is_empty()) {
        auth.enforce_customer(&st.ctx, code).await?;
    }
    tracing::info!(
        "Importing custom dashboard '{}' (overwrite={})",
        req.definition.title,
        if req.overwrite { "True" } else { "False" }
    );
    let plan = custom::import_plan(&st, &req).await.map_err(fail)?;
    if let custom::ImportPlan::Overwrite(existing) = &plan {
        if let Some(owner) = existing.customer_code.as_deref().filter(|c| !c.is_empty()) {
            auth.enforce_customer(&st.ctx, owner).await?;
        }
    }
    let row = custom::import_apply(&st, &req, plan, &auth.username)
        .await
        .map_err(fail)?;
    Ok(ok(wrap(
        "custom_dashboard",
        custom::custom_dump(&row).map_err(fail)?,
        "Custom dashboard imported successfully",
    )))
}

async fn preview_custom(
    State(st): State<SiemState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(PreviewRequest::read)?;
    tracing::info!(
        "Previewing {} panel(s) against event source {}",
        req.panels.len(),
        req.event_source_id
    );
    let access = auth.access(&st.ctx).await?.clone();
    let data = custom::preview(&st, &req, &access).await.map_err(fail)?;
    let dump = dashboards::respond(
        &PREVIEW_RESPONSE,
        &data.results,
        vec![
            ("template", data.template),
            ("customer_code", s(&data.customer_code)),
            ("source_name", s(&data.source_name)),
            ("success", PyValue::Bool(true)),
            ("message", s("Preview generated successfully")),
        ],
    )
    .map_err(fail)?;
    Ok(ok(dump))
}

/// `verify_custom_dashboard_access(template_key)`: only a scoped template is
/// guarded (NULL means shared).
async fn verify_custom_access(st: &SiemState, auth: &Soc, key: &str) -> Result<(), ApiError> {
    let owner = crate::store::custom_owner(&st.ctx.db, key)
        .await
        .map_err(|e| fail(crate::py::db(e)))?;
    if let Some(owner) = owner.filter(|o| !o.is_empty()) {
        auth.enforce_customer(&st.ctx, &owner).await?;
    }
    Ok(())
}

async fn get_custom(State(st): State<SiemState>, auth: Soc, Path(key): Path<String>) -> ApiResult {
    verify_custom_access(&st, &auth, &key).await?;
    tracing::info!("Getting custom dashboard {key}");
    let row = custom::get(&st, &key).await.map_err(fail)?;
    Ok(ok(wrap(
        "custom_dashboard",
        custom::custom_dump(&row).map_err(fail)?,
        "Custom dashboard retrieved successfully",
    )))
}

async fn update_custom(
    State(st): State<SiemState>,
    Path(key): Path<String>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    verify_custom_access(&st, &auth, &key).await?;
    let req = body.model(UpdateRequest::read)?;
    // §4: re-scoping a template is filing it under that customer.
    if let Some(Some(code)) = &req.customer_code {
        if !code.is_empty() {
            auth.enforce_customer(&st.ctx, code).await?;
        }
    }
    tracing::info!("Updating custom dashboard {key}");
    let row = custom::update(&st, &key, &req).await.map_err(fail)?;
    Ok(ok(wrap(
        "custom_dashboard",
        custom::custom_dump(&row).map_err(fail)?,
        "Custom dashboard updated successfully",
    )))
}

async fn delete_custom(
    State(st): State<SiemState>,
    auth: Soc,
    Path(key): Path<String>,
) -> ApiResult {
    verify_custom_access(&st, &auth, &key).await?;
    tracing::info!("Deleting custom dashboard {key}");
    let n = custom::delete(&st, &key).await.map_err(fail)?;
    let message = if n > 0 {
        format!("Custom dashboard deleted successfully along with {n} enabled dashboard(s)")
    } else {
        "Custom dashboard deleted successfully".to_string()
    };
    Ok(ok(dict(vec![
        ("disabled_dashboards", crate::py::int(n as i64)),
        ("success", PyValue::Bool(true)),
        ("message", s(message)),
    ])))
}

async fn export_custom(
    State(st): State<SiemState>,
    auth: Soc,
    Path(key): Path<String>,
) -> ApiResult {
    verify_custom_access(&st, &auth, &key).await?;
    tracing::info!("Exporting custom dashboard {key}");
    let row = custom::get(&st, &key).await.map_err(fail)?;
    let definition = custom::export(&row).map_err(fail)?;
    Ok(ok(wrap(
        "definition",
        definition,
        "Custom dashboard exported successfully",
    )))
}

// --- dashboards: panel data ----------------------------------------------------------------

async fn panel_data(State(st): State<SiemState>, WithJson(auth, body): WithJson<Any>) -> ApiResult {
    let req = body.model(PanelDataRequest::read)?;
    tracing::info!(
        "Fetching panel data for dashboard {} (timerange={})",
        req.dashboard_id,
        req.timerange
    );
    let access = auth.access(&st.ctx).await?.clone();
    let data = dashboards::panel_data(&st, req.dashboard_id, &req.timerange, &access)
        .await
        .map_err(fail)?;
    let dump = dashboards::respond(
        &PANEL_DATA_RESPONSE,
        &data.results,
        vec![
            ("template", data.template),
            ("dashboard_id", crate::py::int(req.dashboard_id)),
            ("customer_code", s(&data.customer_code)),
            ("source_name", s(&data.source_name)),
            ("accent_color", data.accent_color),
            ("success", PyValue::Bool(true)),
            ("message", s("Panel data retrieved successfully")),
        ],
    )
    .map_err(fail)?;
    Ok(ok(dump))
}

// --- event sources -------------------------------------------------------------------------

async fn list_sources(
    State(st): State<SiemState>,
    auth: Any,
    Path(customer_code): Path<String>,
) -> ApiResult {
    tracing::info!("Getting event sources for customer {customer_code}");
    if !auth.access(&st.ctx).await?.can_access(&customer_code) {
        return Err(ApiError::forbidden(format!(
            "Access denied to customer {customer_code}"
        )));
    }
    dashboards::verify_customer_exists(&st, &customer_code)
        .await
        .map_err(fail)?;
    let rows = sources::list_of(&st, &customer_code).await.map_err(fail)?;
    Ok(ok(wrap(
        "event_sources",
        list(&rows, sources::event_source_dump)?,
        "Event sources retrieved successfully",
    )))
}

async fn create_source(
    State(st): State<SiemState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(EventSourceCreate::read)?;
    // §4: the body names the tenant; Python checked only that it exists.
    auth.enforce_customer(&st.ctx, &req.customer_code).await?;
    tracing::info!("Creating event source for customer {}", req.customer_code);
    dashboards::verify_customer_exists(&st, &req.customer_code)
        .await
        .map_err(fail)?;
    let row = sources::create(&st, &req).await.map_err(fail)?;
    Ok(ok(wrap(
        "event_source",
        sources::event_source_dump(&row).map_err(fail)?,
        "Event source created successfully",
    )))
}

/// FastAPI's body parameter, read into the validator that already holds the
/// path's errors (one 422, the path's first).
fn read_body<T: Default>(
    v: &mut Validator,
    body: &copilot_web::JsonBody,
    read: impl FnOnce(
        &mut Validator,
        &serde_json::Map<String, serde_json::Value>,
        &copilot_web::validate::Loc,
    ) -> T,
) -> T {
    let root = copilot_web::validate::body_loc();
    match body {
        copilot_web::JsonBody::Missing => {
            v.missing(root);
            T::default()
        }
        copilot_web::JsonBody::NotJson => {
            v.object(&serde_json::Value::Null, &root);
            T::default()
        }
        copilot_web::JsonBody::Value(value) => match v.object(value, &root) {
            Some(obj) => read(v, obj, &root),
            None => T::default(),
        },
    }
}

async fn update_source(
    State(st): State<SiemState>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = v
        .check_int(
            &loc("path", "event_source_id"),
            &serde_json::Value::String(raw),
            IntRules::default(),
        )
        .unwrap_or_default();
    let req = read_body(&mut v, &body, EventSourceUpdate::read);
    v.finish()?;
    tracing::info!("Updating event source {id}");
    let row = sources::get_by_id(&st, id).await.map_err(fail)?;
    // §4: Python let any analyst rewrite any tenant's event source.
    auth.enforce_owned(
        &st.ctx,
        Some(&row.customer_code),
        &format!("event source {id}"),
    )
    .await?;
    let row = sources::update(&st, &row, &req).await.map_err(fail)?;
    Ok(ok(wrap(
        "event_source",
        sources::event_source_dump(&row).map_err(fail)?,
        "Event source updated successfully",
    )))
}

async fn delete_source(
    State(st): State<SiemState>,
    _auth: Admin,
    Path(raw): Path<String>,
) -> ApiResult {
    let id = path_int("event_source_id", &raw)?;
    tracing::info!("Deleting event source {id}");
    sources::delete(&st, id).await.map_err(fail)?;
    Ok(ok(done("Event source deleted successfully")))
}

// --- events --------------------------------------------------------------------------------

async fn query_events(
    State(st): State<SiemState>,
    auth: Any,
    Path((customer_code, source_name)): Path<(String, String)>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let timerange = q.get("timerange").unwrap_or("24h").to_string();
    let page_size = q.int_or(
        &mut v,
        "page_size",
        IntRules {
            ge: Some(1),
            le: Some(1000),
        },
        50,
    );
    let scroll_id = q.opt_str(&mut v, "scroll_id", StrRules::any());
    let query = q.opt_str(&mut v, "query", StrRules::any());
    let time_from = q.opt_str(&mut v, "time_from", StrRules::any());
    let time_to = q.opt_str(&mut v, "time_to", StrRules::any());
    v.finish()?;
    tracing::info!("Querying events for customer {customer_code}, source {source_name}");
    if !auth.access(&st.ctx).await?.can_access(&customer_code) {
        return Err(ApiError::forbidden(format!(
            "Access denied to customer {customer_code}"
        )));
    }
    let params = events::EventsQuery {
        timerange,
        page_size,
        scroll_id,
        query,
        time_from,
        time_to,
    };
    let dump = events::query(&st, &customer_code, &source_name, &params)
        .await
        .map_err(fail)?;
    Ok(ok(dump))
}

async fn event_document(
    State(st): State<SiemState>,
    auth: Any,
    Path((customer_code, source_name)): Path<(String, String)>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let index_name = q.get("index_name").map(str::to_string);
    if index_name.is_none() {
        v.missing(loc("query", "index_name"));
    }
    let event_id = q.get("event_id").map(str::to_string);
    if event_id.is_none() {
        v.missing(loc("query", "event_id"));
    }
    v.finish()?;
    let (index_name, event_id) = (index_name.unwrap_or_default(), event_id.unwrap_or_default());
    tracing::info!(
        "Fetching event {event_id} from index {index_name} for customer {customer_code}, source \
         {source_name}"
    );
    if !auth.access(&st.ctx).await?.can_access(&customer_code) {
        return Err(ApiError::forbidden(format!(
            "Access denied to customer {customer_code}"
        )));
    }
    let dump = events::document(&st, &customer_code, &source_name, &index_name, &event_id)
        .await
        .map_err(fail)?;
    Ok(ok(dump))
}

async fn field_mappings(
    State(st): State<SiemState>,
    auth: Any,
    Path((customer_code, source_name)): Path<(String, String)>,
) -> ApiResult {
    tracing::info!("Getting field mappings for customer {customer_code}, source {source_name}");
    if !auth.access(&st.ctx).await?.can_access(&customer_code) {
        return Err(ApiError::forbidden(format!(
            "Access denied to customer {customer_code}"
        )));
    }
    let dump = events::field_mappings(&st, &customer_code, &source_name)
        .await
        .map_err(fail)?;
    Ok(ok(dump))
}
