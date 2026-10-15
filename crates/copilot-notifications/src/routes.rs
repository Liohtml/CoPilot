//! The HTTP surface (`routes/notifications.py`), mounted at full paths
//! because it spans several prefixes (`/api/customers/{code}/…`,
//! `/api/internal_notification_routes`, `/api/notification_channels`,
//! `/api/notifications`).
//!
//! FastAPI's order is kept everywhere: the body is decoded first (a
//! malformed JSON body is a 422 before the token), then the scope guard,
//! the `{customer_code}` tenancy dependency, and only then the endpoint's
//! own path, query and body validation — reported together in one 422.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use http::StatusCode;
use serde_json::{Map, Value, json};

use copilot_web::validate::{IntRules, Loc, Validator, body_loc, loc, path_int};
use copilot_web::{
    AdminOnly, AdminOrAnalyst, ApiError, ApiResult, Authorized, CurrentUser, JsonBody, QueryPairs,
    WithJson, ok,
};

use crate::NotificationsState;
use crate::channels;
use crate::db;
use crate::schema::{
    self, DispatchRequest, Escaped, EventBody, IntegrationCreate, IntegrationUpdate,
    ManualSendRequest, PreviewRequest, RouteCreate, RouteUpdate, TemplateCreate, TemplateUpdate,
};
use crate::services::{admin, dispatch, manual, templates};
use crate::sink;

/// Every route of the module, at its full path.
pub fn router(state: NotificationsState) -> Router {
    let customer = "/api/customers/{customer_code}";
    Router::new()
        // Per-customer routes, their test button and the dispatch log.
        .route(
            &format!("{customer}/notification_routes"),
            get(list_routes).post(create_route),
        )
        .route(
            &format!("{customer}/notification_routes/{{route_id}}"),
            axum::routing::patch(update_route).delete(delete_route),
        )
        .route(
            &format!("{customer}/notification_routes/{{route_id}}/test"),
            post(test_route),
        )
        .route(
            &format!("{customer}/notification_dispatch_log"),
            get(dispatch_log),
        )
        // Per-customer Shuffle integrations.
        .route(
            &format!("{customer}/shuffle_integrations"),
            get(list_integrations).post(create_integration),
        )
        .route(
            &format!("{customer}/shuffle_integrations/{{integration_id}}"),
            axum::routing::patch(update_integration).delete(delete_integration),
        )
        .route(
            &format!("{customer}/shuffle_integrations/{{integration_id}}/apps"),
            get(list_apps),
        )
        .route(
            &format!("{customer}/shuffle_integrations/{{integration_id}}/verify"),
            get(verify_integration),
        )
        // Internal-scope routes.
        .route(
            "/api/internal_notification_routes",
            get(list_internal).post(create_internal),
        )
        .route(
            "/api/internal_notification_routes/{route_id}",
            get(get_internal)
                .patch(update_internal)
                .delete(delete_internal),
        )
        .route(
            "/api/internal_notification_routes/{route_id}/test",
            post(test_internal),
        )
        // Channel catalog and the Resend quota.
        .route("/api/notification_channels", get(list_channels))
        .route("/api/notification_channels/resend/quota", get(resend_quota))
        // Deployment-wide endpoints.
        .route("/api/notifications/send", post(manual_send))
        .route("/api/notifications/send/preview", post(manual_preview))
        .route("/api/notifications/shuffle/orgs", get(list_orgs))
        .route("/api/notifications/dispatch", post(dispatch_route))
        .route(
            "/api/notifications/templates",
            get(list_templates).post(create_template),
        )
        .route(
            "/api/notifications/templates/preview",
            post(preview_template),
        )
        .route(
            "/api/notifications/templates/{template_id}",
            get(get_template)
                .patch(update_template)
                .delete(delete_template),
        )
        .route("/api/notifications/events", post(emit_event))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The endpoint's integer path parameters and its body model, validated
/// together: FastAPI reports path errors, then body errors, in one 422.
fn path_and_body<T>(
    ids: &[(&str, &str)],
    body: &JsonBody,
    read: impl FnOnce(&mut Validator, &Map<String, Value>, &Loc) -> T,
) -> Result<(Vec<i64>, T), ApiError> {
    let mut v = Validator::new();
    let parsed: Vec<Option<i64>> = ids
        .iter()
        .map(|(name, raw)| {
            v.check_int(
                &loc("path", name),
                &Value::String((*raw).to_string()),
                IntRules::default(),
            )
        })
        .collect();
    let root = body_loc();
    let out = match body {
        JsonBody::Missing => {
            v.missing(root);
            None
        }
        JsonBody::NotJson => v
            .object(&Value::Null, &root)
            .map(|obj| read(&mut v, obj, &root)),
        JsonBody::Value(value) => v.object(value, &root).map(|obj| read(&mut v, obj, &root)),
    };
    v.finish()?;
    let ids = parsed
        .into_iter()
        .map(|id| id.ok_or_else(|| ApiError::internal("path_and_body: id without error")))
        .collect::<Result<Vec<_>, _>>()?;
    let out = out.ok_or_else(|| ApiError::internal("path_and_body: object without errors"))?;
    Ok((ids, out))
}

/// `verify_customer_code_access`.
async fn tenancy(s: &NotificationsState, user: &CurrentUser, code: &str) -> Result<(), ApiError> {
    user.enforce_customer(&s.ctx, code).await
}

/// `getattr(current_user, "username", None) or str(current_user.id)`.
fn created_by(user: &CurrentUser) -> String {
    if user.username.is_empty() {
        user.id.to_string()
    } else {
        user.username.clone()
    }
}

fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

/// The template responses put the payload *before* `success` and `message`
/// (`NotificationTemplateResponse`, `NotificationTemplateListResponse`).
fn payload_first(key: &str, payload: Value, message: impl Into<String>) -> Response {
    let mut body = Map::new();
    body.insert(key.into(), payload);
    body.insert("success".into(), Value::Bool(true));
    body.insert("message".into(), Value::String(message.into()));
    json(Value::Object(body))
}

/// A route body whose save-time template check raised something other than
/// a `TemplateError`: Python lets it escape the validator (a bare 500), and
/// it escapes before any other error is reported.
fn escaped_first<T>(escaped: Escaped, result: Result<T, ApiError>) -> Result<T, ApiError> {
    match escaped.0 {
        Some(cause) => Err(ApiError::internal(cause)),
        None => result,
    }
}

fn routes_payload(rows: &[db::RouteRow]) -> Result<Value, ApiError> {
    let routes = rows
        .iter()
        .map(schema::route_read)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({ "routes": routes }))
}

// ---------------------------------------------------------------------------
// Per-customer route CRUD
// ---------------------------------------------------------------------------

async fn list_routes(
    auth: Authorized<AdminOrAnalyst>,
    State(s): State<NotificationsState>,
    Path(customer_code): Path<String>,
) -> ApiResult {
    tenancy(&s, &auth, &customer_code).await?;
    let rows = db::routes_of_customer(s.dispatcher.db(), &customer_code).await?;
    let payload = routes_payload(&rows)?;
    Ok(ok(format!("{} route(s) retrieved", rows.len()), payload))
}

async fn create_route(
    State(s): State<NotificationsState>,
    Path(customer_code): Path<String>,
    WithJson(auth, body): WithJson<Authorized<AdminOrAnalyst>>,
) -> ApiResult {
    tenancy(&s, &auth, &customer_code).await?;
    let mut escaped = Escaped::default();
    let parsed = body.model(|v, o, a| RouteCreate::read(v, o, a, &mut escaped));
    let payload = escaped_first(escaped, parsed)?
        .ok_or_else(|| ApiError::internal("RouteCreate without errors"))?;
    tracing::info!(
        "User {} creating notification route for customer {customer_code}",
        auth.id
    );
    let route = admin::create_route(
        &s.dispatcher,
        Some(&customer_code),
        &payload,
        Some(created_by(&auth)),
    )
    .await?;
    Ok(ok(
        "Route created",
        json!({ "route": schema::route_read(&route)? }),
    ))
}

async fn update_route(
    State(s): State<NotificationsState>,
    Path((customer_code, route_id)): Path<(String, String)>,
    WithJson(auth, body): WithJson<Authorized<AdminOrAnalyst>>,
) -> ApiResult {
    tenancy(&s, &auth, &customer_code).await?;
    let (ids, payload) = path_and_body(&[("route_id", &route_id)], &body, RouteUpdate::read)?;
    let route = admin::update_route(&s.dispatcher, ids[0], Some(&customer_code), &payload).await?;
    Ok(ok(
        "Route updated",
        json!({ "route": schema::route_read(&route)? }),
    ))
}

async fn delete_route(
    auth: Authorized<AdminOrAnalyst>,
    State(s): State<NotificationsState>,
    Path((customer_code, route_id)): Path<(String, String)>,
) -> ApiResult {
    tenancy(&s, &auth, &customer_code).await?;
    let route_id = path_int("route_id", &route_id)?;
    admin::delete_route(&s.dispatcher, route_id, Some(&customer_code)).await?;
    Ok(ok("Route deleted", json!({})))
}

async fn test_route(
    auth: Authorized<AdminOrAnalyst>,
    State(s): State<NotificationsState>,
    Path((customer_code, route_id)): Path<(String, String)>,
) -> ApiResult {
    tenancy(&s, &auth, &customer_code).await?;
    let route_id = path_int("route_id", &route_id)?;
    let route = admin::get_route(&s.dispatcher, route_id, &customer_code).await?;
    Ok(json(dispatch::send_test(&s.dispatcher, &route).await?))
}

async fn test_internal(
    _auth: Authorized<AdminOnly>,
    State(s): State<NotificationsState>,
    Path(route_id): Path<String>,
) -> ApiResult {
    let route_id = path_int("route_id", &route_id)?;
    let route = admin::get_internal_route(&s.dispatcher, route_id).await?;
    Ok(json(dispatch::send_test(&s.dispatcher, &route).await?))
}

// ---------------------------------------------------------------------------
// Manual send
// ---------------------------------------------------------------------------

async fn manual_send(
    State(s): State<NotificationsState>,
    WithJson(auth, body): WithJson<Authorized<AdminOrAnalyst>>,
) -> ApiResult {
    let p = body.model(ManualSendRequest::read)?;
    let outcome = manual::send(
        &s.ctx,
        &s.dispatcher,
        &auth,
        &p.entity_type,
        p.entity_id,
        p.route_id,
        p.include_ai_report,
    )
    .await?;
    Ok(json(outcome))
}

async fn manual_preview(
    State(s): State<NotificationsState>,
    WithJson(auth, body): WithJson<Authorized<AdminOrAnalyst>>,
) -> ApiResult {
    let p = body.model(ManualSendRequest::read)?;
    let rendered = manual::preview(
        &s.ctx,
        &s.dispatcher,
        &auth,
        &p.entity_type,
        p.entity_id,
        p.route_id,
        p.include_ai_report,
    )
    .await?;
    Ok(ok(
        "Preview rendered",
        json!({ "body": rendered.body, "subject": rendered.subject }),
    ))
}

// ---------------------------------------------------------------------------
// Internal-scope routes
// ---------------------------------------------------------------------------

async fn list_internal(
    _auth: Authorized<AdminOnly>,
    State(s): State<NotificationsState>,
) -> ApiResult {
    let rows = db::internal_routes(s.dispatcher.db()).await?;
    let payload = routes_payload(&rows)?;
    Ok(ok(
        format!("{} internal route(s) retrieved", rows.len()),
        payload,
    ))
}

async fn get_internal(
    _auth: Authorized<AdminOnly>,
    State(s): State<NotificationsState>,
    Path(route_id): Path<String>,
) -> ApiResult {
    let route_id = path_int("route_id", &route_id)?;
    let route = admin::get_internal_route(&s.dispatcher, route_id).await?;
    Ok(ok(
        "Internal route retrieved",
        json!({ "route": schema::route_read(&route)? }),
    ))
}

async fn create_internal(
    State(s): State<NotificationsState>,
    WithJson(auth, body): WithJson<Authorized<AdminOnly>>,
) -> ApiResult {
    let mut escaped = Escaped::default();
    let parsed = body.model(|v, o, a| RouteCreate::read(v, o, a, &mut escaped));
    let payload = escaped_first(escaped, parsed)?
        .ok_or_else(|| ApiError::internal("RouteCreate without errors"))?;
    let route =
        admin::create_route(&s.dispatcher, None, &payload, Some(auth.username.clone())).await?;
    Ok(ok(
        "Internal route created",
        json!({ "route": schema::route_read(&route)? }),
    ))
}

async fn update_internal(
    State(s): State<NotificationsState>,
    Path(route_id): Path<String>,
    WithJson(_auth, body): WithJson<Authorized<AdminOnly>>,
) -> ApiResult {
    let (ids, payload) = path_and_body(&[("route_id", &route_id)], &body, RouteUpdate::read)?;
    let route = admin::update_route(&s.dispatcher, ids[0], None, &payload).await?;
    Ok(ok(
        "Internal route updated",
        json!({ "route": schema::route_read(&route)? }),
    ))
}

async fn delete_internal(
    _auth: Authorized<AdminOnly>,
    State(s): State<NotificationsState>,
    Path(route_id): Path<String>,
) -> ApiResult {
    let route_id = path_int("route_id", &route_id)?;
    admin::delete_route(&s.dispatcher, route_id, None).await?;
    Ok(ok("Internal route deleted", json!({})))
}

// ---------------------------------------------------------------------------
// Channel catalog, Resend quota, dispatch log
// ---------------------------------------------------------------------------

async fn list_channels(_auth: Authorized<AdminOrAnalyst>) -> ApiResult {
    let catalog = channels::catalog();
    let count = catalog.as_array().map_or(0, Vec::len);
    Ok(ok(
        format!("{count} channel(s) retrieved"),
        json!({ "channels": catalog }),
    ))
}

async fn resend_quota(
    auth: Authorized<AdminOrAnalyst>,
    State(s): State<NotificationsState>,
    query: QueryPairs,
) -> ApiResult {
    let code = query.get("customer_code").filter(|c| !c.is_empty());
    if let Some(code) = code {
        tenancy(&s, &auth, code).await?;
    }
    let total = admin::sends_this_month(&s.dispatcher, None).await?;
    let scoped = match code {
        Some(code) => Some(admin::sends_this_month(&s.dispatcher, Some(code)).await?),
        None => None,
    };
    let configured = admin::resend_configured(&s.dispatcher).await?;
    Ok(ok(
        format!("{total} email(s) sent this month"),
        json!({
            "sent_this_month": total,
            "limit": channels::resend::FREE_TIER_MONTHLY_LIMIT,
            "customer_sent": scoped,
            "configured": configured,
        }),
    ))
}

async fn dispatch_log(
    auth: Authorized<AdminOrAnalyst>,
    State(s): State<NotificationsState>,
    Path(customer_code): Path<String>,
) -> ApiResult {
    tenancy(&s, &auth, &customer_code).await?;
    let rows = db::log_of_customer(s.dispatcher.db(), &customer_code, 100).await?;
    let entries = rows
        .iter()
        .map(schema::log_read)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ok(
        format!("{} entry/entries retrieved", rows.len()),
        json!({ "entries": entries }),
    ))
}

// ---------------------------------------------------------------------------
// Shuffle
// ---------------------------------------------------------------------------

async fn list_orgs(
    _auth: Authorized<AdminOrAnalyst>,
    State(s): State<NotificationsState>,
) -> ApiResult {
    let orgs = admin::list_orgs(&s.dispatcher).await?;
    Ok(ok(
        format!("{} org(s) retrieved", orgs.len()),
        json!({ "orgs": orgs }),
    ))
}

async fn list_integrations(
    auth: Authorized<AdminOrAnalyst>,
    State(s): State<NotificationsState>,
    Path(customer_code): Path<String>,
) -> ApiResult {
    tenancy(&s, &auth, &customer_code).await?;
    let rows = db::integrations_of_customer(s.dispatcher.db(), &customer_code).await?;
    let items = rows
        .iter()
        .map(schema::integration_read)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ok(
        format!("{} integration(s) retrieved", rows.len()),
        json!({ "integrations": items }),
    ))
}

async fn create_integration(
    State(s): State<NotificationsState>,
    Path(customer_code): Path<String>,
    WithJson(auth, body): WithJson<Authorized<AdminOrAnalyst>>,
) -> ApiResult {
    tenancy(&s, &auth, &customer_code).await?;
    let p = body.model(IntegrationCreate::read)?;
    tracing::info!(
        "User {} adding Shuffle integration ({}) for customer {customer_code}",
        auth.id,
        p.display_name
    );
    let row =
        admin::create_integration(&s.dispatcher, &customer_code, &p, Some(&created_by(&auth)))
            .await?;
    Ok(ok(
        "Integration created",
        json!({ "integration": schema::integration_read(&row)? }),
    ))
}

async fn update_integration(
    State(s): State<NotificationsState>,
    Path((customer_code, integration_id)): Path<(String, String)>,
    WithJson(auth, body): WithJson<Authorized<AdminOrAnalyst>>,
) -> ApiResult {
    tenancy(&s, &auth, &customer_code).await?;
    let (ids, p) = path_and_body(
        &[("integration_id", &integration_id)],
        &body,
        IntegrationUpdate::read,
    )?;
    let row = admin::update_integration(&s.dispatcher, ids[0], &customer_code, &p).await?;
    Ok(ok(
        "Integration updated",
        json!({ "integration": schema::integration_read(&row)? }),
    ))
}

async fn delete_integration(
    auth: Authorized<AdminOrAnalyst>,
    State(s): State<NotificationsState>,
    Path((customer_code, integration_id)): Path<(String, String)>,
) -> ApiResult {
    tenancy(&s, &auth, &customer_code).await?;
    let id = path_int("integration_id", &integration_id)?;
    admin::delete_integration(&s.dispatcher, id, &customer_code).await?;
    Ok(ok("Integration deleted", json!({})))
}

async fn list_apps(
    auth: Authorized<AdminOrAnalyst>,
    State(s): State<NotificationsState>,
    Path((customer_code, integration_id)): Path<(String, String)>,
) -> ApiResult {
    tenancy(&s, &auth, &customer_code).await?;
    let id = path_int("integration_id", &integration_id)?;
    let apps = admin::list_apps(&s.dispatcher, id, &customer_code).await?;
    Ok(ok(
        format!("{} app(s) retrieved", apps.len()),
        json!({ "apps": apps }),
    ))
}

async fn verify_integration(
    auth: Authorized<AdminOrAnalyst>,
    State(s): State<NotificationsState>,
    Path((customer_code, integration_id)): Path<(String, String)>,
) -> ApiResult {
    tenancy(&s, &auth, &customer_code).await?;
    let id = path_int("integration_id", &integration_id)?;
    Ok(json(
        admin::verify_integration(&s.dispatcher, id, &customer_code).await?,
    ))
}

// ---------------------------------------------------------------------------
// Dispatch (Talon)
// ---------------------------------------------------------------------------

async fn dispatch_route(
    State(s): State<NotificationsState>,
    WithJson(auth, body): WithJson<Authorized<AdminOrAnalyst>>,
) -> ApiResult {
    let p = body.model(DispatchRequest::read)?;
    // Not in Python: the body names the tenant, so the caller must be
    // entitled to it (RUST_MIGRATION.md, differences by design).
    tenancy(&s, &auth, &p.customer_code).await?;
    tracing::info!(
        "Notification dispatch requested for customer {} alert {} trigger {} severity {}",
        p.customer_code,
        p.alert_id,
        p.trigger,
        p.severity_assessment
    );
    let event = sink::event_from_dispatch_request(&p);
    Ok(json(dispatch::dispatch_event(&s.dispatcher, event).await?))
}

// ---------------------------------------------------------------------------
// Named templates
// ---------------------------------------------------------------------------

async fn list_templates(
    auth: Authorized<AdminOrAnalyst>,
    State(s): State<NotificationsState>,
    query: QueryPairs,
) -> ApiResult {
    let code = query.get("customer_code");
    if let Some(c) = code.filter(|c| !c.is_empty()) {
        tenancy(&s, &auth, c).await?;
    }
    let access = auth.access(&s.ctx).await?;
    let rows = templates::list(&s.dispatcher, code, query.get("trigger"), access).await?;
    let items = rows
        .iter()
        .map(schema::template_read)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(payload_first(
        "templates",
        Value::Array(items),
        format!("{} template(s) retrieved", rows.len()),
    ))
}

async fn preview_template(
    State(s): State<NotificationsState>,
    WithJson(_auth, body): WithJson<Authorized<AdminOrAnalyst>>,
) -> ApiResult {
    let p = body.model(PreviewRequest::read)?;
    let mut out = templates::preview(&s.dispatcher, &p).await?;
    let failed = out.get("error").is_some_and(|e| !e.is_null());
    out.insert("success".into(), Value::Bool(!failed));
    out.insert(
        "message".into(),
        Value::String(if failed {
            "Template failed to render".into()
        } else {
            "Rendered".into()
        }),
    );
    Ok(json(Value::Object(out)))
}

async fn get_template(
    auth: Authorized<AdminOrAnalyst>,
    State(s): State<NotificationsState>,
    Path(template_id): Path<String>,
) -> ApiResult {
    let id = path_int("template_id", &template_id)?;
    let template = admin::get_template(&s.dispatcher, id).await?;
    if let Some(code) = template.customer_code.as_deref().filter(|c| !c.is_empty()) {
        tenancy(&s, &auth, code).await?;
    }
    Ok(payload_first(
        "template",
        schema::template_read(&template)?,
        "Template retrieved",
    ))
}

async fn create_template(
    State(s): State<NotificationsState>,
    WithJson(auth, body): WithJson<Authorized<AdminOnly>>,
) -> ApiResult {
    let p = body.model(TemplateCreate::read)?;
    let by = created_by(&auth);
    tracing::info!(
        "User {by} creating notification template {}",
        copilot_auth::pyvalue::str_repr(&p.name)
    );
    let template = templates::create(&s.dispatcher, &p, Some(by)).await?;
    Ok(payload_first(
        "template",
        schema::template_read(&template)?,
        "Template created",
    ))
}

async fn update_template(
    State(s): State<NotificationsState>,
    Path(template_id): Path<String>,
    WithJson(_auth, body): WithJson<Authorized<AdminOnly>>,
) -> ApiResult {
    let (ids, p) = path_and_body(
        &[("template_id", &template_id)],
        &body,
        TemplateUpdate::read,
    )?;
    let template = templates::update(&s.dispatcher, ids[0], &p).await?;
    Ok(payload_first(
        "template",
        schema::template_read(&template)?,
        "Template updated",
    ))
}

async fn delete_template(
    _auth: Authorized<AdminOnly>,
    State(s): State<NotificationsState>,
    Path(template_id): Path<String>,
) -> ApiResult {
    let id = path_int("template_id", &template_id)?;
    let template = admin::get_template(&s.dispatcher, id).await?;
    let read = schema::template_read(&template)?;
    let detached = templates::delete(&s.dispatcher, id).await?;
    let message = if detached > 0 {
        format!("Template deleted; {detached} route(s) fell back to their channel default")
    } else {
        "Template deleted".to_string()
    };
    Ok(payload_first("template", read, message))
}

// ---------------------------------------------------------------------------
// The former hand-off endpoint
// ---------------------------------------------------------------------------

async fn emit_event(
    State(s): State<NotificationsState>,
    WithJson(auth, body): WithJson<Authorized<AdminOrAnalyst>>,
) -> ApiResult {
    let e = body.model(EventBody::read)?;
    let owner = db::alert(s.dispatcher.db(), e.entity_id)
        .await?
        .map(|a| a.customer_code);
    let code = owner
        .clone()
        .or_else(|| e.customer_code.clone())
        .unwrap_or_default();
    tenancy(&s, &auth, &code).await?;
    let event = sink::sanitize(
        sink::event_from_body(&e),
        owner.as_deref(),
        s.dispatcher.defaults(),
    )
    .map_err(|r| match r {
        sink::Rejected::NotFound(m) => ApiError::not_found(m),
        sink::Rejected::Refused(m) => ApiError::bad_request(m),
    })?;
    sink::spawn_dispatch(s.dispatcher.clone(), event);
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "success": true, "message": "Notification event queued" })),
    )
        .into_response())
}
