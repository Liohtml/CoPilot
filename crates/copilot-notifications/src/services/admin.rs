//! Configuration: notification routes (customer and internal), Shuffle
//! integrations and their Shuffle lookups, the dispatch log and the Resend
//! quota (`services/notifications.py`, `services/resend_quota.py`).

use chrono::{Datelike, NaiveDate};
use copilot_auth::pyvalue::{self, PyValue, str_repr};
use copilot_web::ApiError;
use serde_json::{Map, Value};

use crate::channels::send::{Unavailable, connector_credentials};
use crate::channels::{Channel, config as channel_config, py_list_repr, shuffle};
use crate::db::{self, IntegrationRow, NewRoute, RouteRow, SetValue, TemplateRow};
use crate::dispatcher::Dispatcher;
use crate::pydantic::{self, PyError};
use crate::pyjson::{self, Dumps};
use crate::schema::{
    IntegrationCreate, IntegrationUpdate, Patch, RouteCreate, RouteUpdate, config_items,
};

const ROUTES: &str = "customer_notification_route";
const INTEGRATIONS: &str = "customer_shuffle_integration";

fn now() -> chrono::NaiveDateTime {
    copilot_core::time::now_utc_naive()
}

/// `get_route`.
pub async fn get_route(d: &Dispatcher, id: i64, customer_code: &str) -> Result<RouteRow, ApiError> {
    db::route_of_customer(d.db(), id, customer_code)
        .await?
        .ok_or_else(|| ApiError::not_found("Route not found"))
}

/// `get_internal_route`.
pub async fn get_internal_route(d: &Dispatcher, id: i64) -> Result<RouteRow, ApiError> {
    db::internal_route(d.db(), id)
        .await?
        .ok_or_else(|| ApiError::not_found("Internal route not found"))
}

/// `_enforce_scope_invariant`.
fn scope_invariant(scope: &str, customer_code: Option<&str>) -> Result<Option<String>, ApiError> {
    let code = customer_code.filter(|c| !c.is_empty());
    if scope == "internal" {
        if code.is_some() {
            return Err(ApiError::bad_request(
                "An internal-scope route must not name a customer.",
            ));
        }
        return Ok(None);
    }
    code.map(|c| Some(c.to_string()))
        .ok_or_else(|| ApiError::bad_request("A customer-scope route requires a customer_code."))
}

/// `_reject_shuffle_for_internal`.
fn reject_shuffle_for_internal(channel: &str) -> Result<(), ApiError> {
    if channel == "shuffle" {
        return Err(ApiError::bad_request(
            "Shuffle is not available for internal routes: a Shuffle integration belongs to a \
             specific customer, and an internal route belongs to none. Use webhook or email.",
        ));
    }
    Ok(())
}

/// `_ensure_integration_belongs_to_customer`.
pub async fn ensure_integration(
    d: &Dispatcher,
    id: i64,
    customer_code: &str,
) -> Result<IntegrationRow, ApiError> {
    db::integration_of_customer(d.db(), id, customer_code)
        .await?
        .ok_or_else(|| {
            ApiError::bad_request(format!(
                "Shuffle integration {id} not found for customer {customer_code}. Cross-tenant \
                 references are refused — create the integration on the target customer first."
            ))
        })
}

/// `_incompatibility`: why a template cannot serve a route with these
/// properties.
pub fn incompatibility(
    t: &TemplateRow,
    channel: &str,
    trigger: &str,
    customer_code: Option<&str>,
) -> Option<String> {
    let owner = t.customer_code.as_deref().filter(|c| !c.is_empty());
    if let (Some(owner), Some(code)) = (owner, customer_code.filter(|c| !c.is_empty())) {
        if owner != code {
            return Some(format!(
                "That template belongs to customer {}, but the route serves {}.",
                str_repr(owner),
                str_repr(code)
            ));
        }
    }
    if let (Some(owner), None) = (owner, customer_code) {
        return Some(format!(
            "That template is scoped to customer {}, so it cannot be used on an internal route.",
            str_repr(owner)
        ));
    }
    if let Some(t_trigger) = t.trigger.as_deref().filter(|t| !t.is_empty()) {
        if t_trigger != trigger {
            return Some(format!(
                "That template is scoped to the {} trigger, but the route fires on {}. A template \
                 written around one trigger's variables renders empty on another.",
                str_repr(t_trigger),
                str_repr(trigger)
            ));
        }
    }
    if let Some(c) = Channel::parse(channel) {
        if !c.template_formats().contains(&t.format.as_str()) {
            return Some(format!(
                "The {} channel cannot render a {} template (supports {}).",
                str_repr(channel),
                str_repr(&t.format),
                py_list_repr(c.template_formats())
            ));
        }
    }
    None
}

/// `get_template` (404 `Template N not found`).
pub async fn get_template(d: &Dispatcher, id: i64) -> Result<TemplateRow, ApiError> {
    db::template(d.db(), id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Template {id} not found")))
}

/// `assert_template_usable`.
async fn assert_template_usable(
    d: &Dispatcher,
    id: i64,
    channel: &str,
    trigger: &str,
    customer_code: Option<&str>,
) -> Result<(), ApiError> {
    let t = get_template(d, id).await?;
    match incompatibility(&t, channel, trigger, customer_code) {
        Some(problem) => Err(ApiError::bad_request(problem)),
        None => Ok(()),
    }
}

fn dumps_config(config: &PyValue) -> String {
    pyjson::dumps(config, Dumps::DEFAULT).unwrap_or_else(|_| "{}".into())
}

/// `create_route` / `create_internal_route`.
pub async fn create_route(
    d: &Dispatcher,
    customer_code: Option<&str>,
    p: &RouteCreate,
    created_by: Option<String>,
) -> Result<RouteRow, ApiError> {
    let internal_endpoint = customer_code.is_none();
    let resolved = if internal_endpoint {
        reject_shuffle_for_internal(p.channel.key())?;
        if p.scope != "internal" {
            return Err(ApiError::bad_request(
                "This endpoint creates internal-scope routes only.",
            ));
        }
        None
    } else {
        let code = customer_code.unwrap_or_default();
        if p.channel == Channel::Shuffle {
            ensure_integration(d, p.shuffle_integration_id.unwrap_or(0), code).await?;
        }
        scope_invariant(&p.scope, Some(code))?
    };
    if let Some(tid) = p.template_id.filter(|t| *t != 0) {
        assert_template_usable(d, tid, p.channel.key(), &p.trigger, resolved.as_deref()).await?;
    }
    let id = db::insert_route(
        d.db(),
        &NewRoute {
            customer_code: resolved,
            scope: if internal_endpoint {
                "internal".into()
            } else {
                p.scope.clone()
            },
            recipient_mode: p.recipient_mode.clone(),
            notify_on_self_assign: p.notify_on_self_assign,
            name: p.name.clone(),
            trigger: p.trigger.clone(),
            channel: p.channel.key().into(),
            destination: p.destination.clone().unwrap_or_default(),
            min_severity: p.min_severity.clone(),
            format_template: p.format_template.clone(),
            template_id: p.template_id,
            enabled: p.enabled,
            created_by,
            shuffle_integration_id: if internal_endpoint {
                None
            } else {
                p.shuffle_integration_id
            },
            config: dumps_config(&p.config),
            created_at: now(),
        },
    )
    .await?;
    db::route(d.db(), id)
        .await?
        .ok_or_else(|| ApiError::internal("inserted route vanished"))
}

/// Re-validate the config of the channel a PATCH leaves the route with.
fn revalidate_config(
    route: &RouteRow,
    channel: &str,
    patch_config: &Patch<Vec<(String, PyValue)>>,
) -> Result<PyValue, ApiError> {
    let Some(c) = Channel::parse(channel) else {
        return Err(ApiError::bad_request(format!(
            "Unsupported channel: {channel}"
        )));
    };
    let raw: PyValue = match patch_config {
        Some(Some(items)) => PyValue::Dict(items.clone()),
        Some(None) => PyValue::Dict(Vec::new()),
        None => match route.config.as_deref().filter(|s| !s.is_empty()) {
            None => PyValue::Dict(Vec::new()),
            Some(text) => pyvalue::loads(text)
                .map_err(|_| ApiError::bad_request("Expecting value: line 1 column 1 (char 0)"))?,
        },
    };
    let result = match &raw {
        PyValue::Dict(items) => channel_config::validate(c, items),
        // `raw_config or {}`: an empty list/str/0 reads as `{}`.
        other if !other.truthy() => channel_config::validate(c, &[]),
        other => Err(vec![PyError::new(
            Vec::new(),
            "model_type",
            format!(
                "Input should be a valid dictionary or instance of {}",
                c.model_name()
            ),
            other.clone(),
        )]),
    };
    result.map_err(|errors| {
        ApiError::bad_request(format!(
            "Invalid config for channel '{channel}': {}",
            pydantic::format(c.model_name(), &errors)
        ))
    })
}

fn set_str(sets: &mut Vec<(&'static str, SetValue)>, col: &'static str, v: &Patch<String>) {
    if let Some(v) = v {
        sets.push((col, v.clone().map_or(SetValue::Null, SetValue::Str)));
    }
}

fn set_int(sets: &mut Vec<(&'static str, SetValue)>, col: &'static str, v: &Patch<i64>) {
    if let Some(v) = v {
        sets.push((col, v.map_or(SetValue::Null, SetValue::Int)));
    }
}

fn set_bool(sets: &mut Vec<(&'static str, SetValue)>, col: &'static str, v: &Patch<bool>) {
    if let Some(v) = v {
        sets.push((col, v.map_or(SetValue::Null, SetValue::Bool)));
    }
}

/// `update_route` (`customer_code: Some`) / `update_internal_route` (`None`).
pub async fn update_route(
    d: &Dispatcher,
    route_id: i64,
    customer_code: Option<&str>,
    p: &RouteUpdate,
) -> Result<RouteRow, ApiError> {
    let internal = customer_code.is_none();
    let route = match customer_code {
        Some(code) => get_route(d, route_id, code).await?,
        None => get_internal_route(d, route_id).await?,
    };
    let new_channel = p
        .channel
        .clone()
        .flatten()
        .unwrap_or_else(|| route.channel.clone());
    let mut scope_patch = p.scope.clone();
    if internal {
        reject_shuffle_for_internal(&new_channel)?;
        if let Some(s) = &p.scope {
            if s.as_deref() != Some("internal") {
                return Err(ApiError::bad_request(
                    "An internal route's scope cannot be changed.",
                ));
            }
        }
        scope_patch = None;
    } else {
        let new_integration = match &p.shuffle_integration_id {
            Some(v) => *v,
            None => route.shuffle_integration_id.map(i64::from),
        };
        if new_channel == "shuffle" {
            if let Some(id) = new_integration.filter(|i| *i != 0) {
                ensure_integration(d, id, customer_code.unwrap_or_default()).await?;
            }
        }
    }
    let mut config_value: Option<PyValue> = None;
    if p.config.is_some() || p.channel.is_some() || p.recipient_mode.is_some() {
        let cfg = revalidate_config(&route, &new_channel, &p.config)?;
        let mode = p
            .recipient_mode
            .clone()
            .flatten()
            .unwrap_or_else(|| route.recipient_mode.clone());
        let channel = Channel::parse(&new_channel)
            .ok_or_else(|| ApiError::bad_request(format!("Unsupported channel: {new_channel}")))?;
        if !channel.recipient_modes().contains(&mode.as_str()) {
            return Err(ApiError::bad_request(format!(
                "Channel '{new_channel}' does not support recipient_mode '{mode}' (supported: {})",
                py_list_repr(channel.recipient_modes())
            )));
        }
        config_value = Some(cfg);
    }
    let mut new_customer: Patch<String> = None;
    if let Some(scope) = &scope_patch {
        let scope_value = scope.clone().unwrap_or_else(|| route.scope.clone());
        let owner = if scope_value == "internal" {
            None
        } else {
            route
                .customer_code
                .clone()
                .filter(|c| !c.is_empty())
                .or_else(|| customer_code.map(str::to_string))
        };
        new_customer = Some(scope_invariant(&scope_value, owner.as_deref())?);
    }
    let effective_template = match &p.template_id {
        Some(v) => *v,
        None => route.template_id.map(i64::from),
    };
    if let Some(tid) = effective_template.filter(|t| *t != 0) {
        if p.template_id.is_some() || p.channel.is_some() || p.trigger.is_some() {
            let trigger = p
                .trigger
                .clone()
                .flatten()
                .unwrap_or_else(|| route.trigger.clone());
            let owner = if internal {
                None
            } else {
                match &new_customer {
                    Some(v) => v.clone(),
                    None => route.customer_code.clone(),
                }
            };
            assert_template_usable(d, tid, &new_channel, &trigger, owner.as_deref()).await?;
        }
    }
    let mut sets: Vec<(&'static str, SetValue)> = Vec::new();
    set_str(&mut sets, "name", &p.name);
    set_str(&mut sets, "trigger", &p.trigger);
    set_str(&mut sets, "channel", &p.channel);
    if let Some(dest) = &p.destination {
        sets.push((
            "destination",
            SetValue::Str(dest.clone().unwrap_or_default()),
        ));
    }
    set_str(&mut sets, "min_severity", &p.min_severity);
    set_str(&mut sets, "format_template", &p.format_template);
    set_int(&mut sets, "template_id", &p.template_id);
    set_bool(&mut sets, "enabled", &p.enabled);
    if !internal {
        set_str(&mut sets, "scope", &scope_patch);
    }
    set_str(&mut sets, "recipient_mode", &p.recipient_mode);
    set_bool(&mut sets, "notify_on_self_assign", &p.notify_on_self_assign);
    set_int(
        &mut sets,
        "shuffle_integration_id",
        &p.shuffle_integration_id,
    );
    if let Some(cfg) = &config_value {
        sets.push(("config", SetValue::Str(dumps_config(cfg))));
    }
    if let Some(code) = new_customer {
        sets.push(("customer_code", code.map_or(SetValue::Null, SetValue::Str)));
    }
    sets.push(("updated_at", SetValue::Time(now())));
    db::update_columns(d.db(), ROUTES, route_id, &sets).await?;
    db::route(d.db(), route_id)
        .await?
        .ok_or_else(|| ApiError::internal("updated route vanished"))
}

/// `delete_route` / `delete_internal_route`.
pub async fn delete_route(
    d: &Dispatcher,
    route_id: i64,
    customer_code: Option<&str>,
) -> Result<(), ApiError> {
    match customer_code {
        Some(code) => get_route(d, route_id, code).await?,
        None => get_internal_route(d, route_id).await?,
    };
    db::delete_by_id(d.db(), ROUTES, route_id).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Shuffle integrations
// ---------------------------------------------------------------------------

/// `create_shuffle_integration`.
pub async fn create_integration(
    d: &Dispatcher,
    customer_code: &str,
    p: &IntegrationCreate,
    created_by: Option<&str>,
) -> Result<IntegrationRow, ApiError> {
    let id = db::insert_integration(
        d.db(),
        customer_code,
        &p.display_name,
        &p.shuffle_org_id,
        p.enabled,
        created_by,
        now(),
    )
    .await?;
    db::integration(d.db(), id)
        .await?
        .ok_or_else(|| ApiError::internal("inserted integration vanished"))
}

/// `update_shuffle_integration`.
pub async fn update_integration(
    d: &Dispatcher,
    id: i64,
    customer_code: &str,
    p: &IntegrationUpdate,
) -> Result<IntegrationRow, ApiError> {
    ensure_integration(d, id, customer_code).await?;
    let mut sets: Vec<(&'static str, SetValue)> = Vec::new();
    set_str(&mut sets, "display_name", &p.display_name);
    set_str(&mut sets, "shuffle_org_id", &p.shuffle_org_id);
    set_bool(&mut sets, "enabled", &p.enabled);
    sets.push(("updated_at", SetValue::Time(now())));
    db::update_columns(d.db(), INTEGRATIONS, id, &sets).await?;
    db::integration(d.db(), id)
        .await?
        .ok_or_else(|| ApiError::internal("updated integration vanished"))
}

/// `delete_shuffle_integration`: refused while routes reference it.
pub async fn delete_integration(
    d: &Dispatcher,
    id: i64,
    customer_code: &str,
) -> Result<(), ApiError> {
    ensure_integration(d, id, customer_code).await?;
    let referencing = db::routes_with_integration(d.db(), id).await?;
    if !referencing.is_empty() {
        let names: Vec<&str> = referencing
            .iter()
            .take(5)
            .map(|r| r.name.as_str())
            .collect();
        return Err(ApiError::http(
            http::StatusCode::CONFLICT,
            format!(
                "Integration is referenced by {} route(s) ({}{}). Delete or re-point those routes \
                 first.",
                referencing.len(),
                names.join(", "),
                if referencing.len() > 5 { "…" } else { "" }
            ),
        ));
    }
    db::delete_by_id(d.db(), INTEGRATIONS, id).await?;
    Ok(())
}

/// The Shuffle connector, or its 503.
async fn shuffle_creds(d: &Dispatcher) -> Result<crate::channels::send::Credentials, ApiError> {
    match connector_credentials(d.connectors(), Channel::Shuffle).await? {
        Ok(c) => Ok(c),
        Err(Unavailable(detail)) => Err(ApiError::http(
            http::StatusCode::SERVICE_UNAVAILABLE,
            detail,
        )),
    }
}

/// Optional string field of a Shuffle object, as a Pydantic `Optional[str]`
/// would take it (`model` names the 400 when it is not one).
fn opt_str_field(
    model: &str,
    name: &str,
    v: Option<&PyValue>,
    falsy_is_none: bool,
) -> Result<Value, ApiError> {
    match v {
        None | Some(PyValue::None) => Ok(Value::Null),
        Some(v) if falsy_is_none && !v.truthy() => Ok(Value::Null),
        Some(PyValue::Str(s)) => Ok(Value::String(s.clone())),
        Some(other) => Err(ApiError::bad_request(pydantic::format(
            model,
            &[PyError::new(
                vec![pydantic::Loc::Key(name.into())],
                "string_type",
                "Input should be a valid string",
                other.clone(),
            )],
        ))),
    }
}

/// `list_apps_for_integration`.
pub async fn list_apps(
    d: &Dispatcher,
    id: i64,
    customer_code: &str,
) -> Result<Vec<Value>, ApiError> {
    let integration = ensure_integration(d, id, customer_code).await?;
    let creds = shuffle_creds(d).await?;
    let raw = shuffle::list_apps(d, &creds, &integration.shuffle_org_id)
        .await
        .map_err(|e| {
            ApiError::http(
                http::StatusCode::BAD_GATEWAY,
                format!("Failed to fetch apps from Shuffle: {e}"),
            )
        })?;
    let mut apps = Vec::new();
    for item in raw {
        let PyValue::Dict(_) = item else { continue };
        let (Some(id), Some(name)) = (
            item.get("id").filter(|v| v.truthy()),
            item.get("name").filter(|v| v.truthy()),
        ) else {
            continue;
        };
        let mut m = Map::new();
        m.insert("id".into(), Value::String(id.py_str()));
        m.insert("name".into(), Value::String(name.py_str()));
        m.insert(
            "description".into(),
            opt_str_field("ShuffleApp", "description", item.get("description"), false)?,
        );
        m.insert(
            "large_image".into(),
            opt_str_field("ShuffleApp", "large_image", item.get("large_image"), false)?,
        );
        apps.push(Value::Object(m));
    }
    Ok(apps)
}

/// `verify_integration`: `{success, message, org_id, app_count, error}`.
pub async fn verify_integration(
    d: &Dispatcher,
    id: i64,
    customer_code: &str,
) -> Result<Value, ApiError> {
    let integration = ensure_integration(d, id, customer_code).await?;
    let creds = shuffle_creds(d).await?;
    let result = shuffle::list_apps(d, &creds, &integration.shuffle_org_id).await;
    let (ok, count, error) = match result {
        Ok(apps) => (true, Value::from(apps.len()), Value::Null),
        Err(e) => (false, Value::Null, Value::String(e)),
    };
    let mut m = Map::new();
    m.insert("success".into(), Value::Bool(ok));
    m.insert(
        "message".into(),
        Value::String(if ok {
            "Shuffle integration reachable".into()
        } else {
            "Shuffle integration check failed".into()
        }),
    );
    m.insert("org_id".into(), Value::String(integration.shuffle_org_id));
    m.insert("app_count".into(), count);
    m.insert("error".into(), error);
    Ok(Value::Object(m))
}

/// `list_orgs`.
pub async fn list_orgs(d: &Dispatcher) -> Result<Vec<Value>, ApiError> {
    let creds = shuffle_creds(d).await?;
    let raw = shuffle::list_orgs(d, &creds).await.map_err(|e| {
        ApiError::http(
            http::StatusCode::BAD_GATEWAY,
            format!("Failed to fetch orgs from Shuffle: {e}"),
        )
    })?;
    let mut orgs = Vec::new();
    for item in raw {
        let PyValue::Dict(_) = item else { continue };
        let (Some(id), Some(name)) = (
            item.get("id").filter(|v| v.truthy()),
            item.get("name").filter(|v| v.truthy()),
        ) else {
            continue;
        };
        let creator = match item.get("creator_org") {
            Some(PyValue::Str(s)) if s.is_empty() || s == "PARENT_ORG_ID" => None,
            other => other,
        };
        let mut m = Map::new();
        m.insert("id".into(), Value::String(id.py_str()));
        m.insert("name".into(), Value::String(name.py_str()));
        m.insert(
            "description".into(),
            opt_str_field("ShuffleOrg", "description", item.get("description"), true)?,
        );
        m.insert(
            "role".into(),
            opt_str_field("ShuffleOrg", "role", item.get("role"), true)?,
        );
        m.insert(
            "creator_org".into(),
            opt_str_field("ShuffleOrg", "creator_org", creator, false)?,
        );
        orgs.push(Value::Object(m));
    }
    Ok(orgs)
}

// ---------------------------------------------------------------------------
// Resend quota
// ---------------------------------------------------------------------------

/// `sends_this_month`.
pub async fn sends_this_month(
    d: &Dispatcher,
    customer_code: Option<&str>,
) -> Result<i64, ApiError> {
    let now = copilot_core::time::now_utc_micros();
    let start = NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .ok_or_else(|| ApiError::internal("month start"))?;
    Ok(db::resend_sends_since(d.db(), start, customer_code).await?)
}

/// Whether the Resend connector has a key (`get_resend_connector` passes).
pub async fn resend_configured(d: &Dispatcher) -> Result<bool, ApiError> {
    Ok(connector_credentials(d.connectors(), Channel::Resend)
        .await?
        .is_ok())
}

/// The config items of a route row (for tests and the update path).
pub fn stored_config(route: &RouteRow) -> Vec<(String, PyValue)> {
    route
        .config
        .as_deref()
        .and_then(|c| pyvalue::loads(c).ok())
        .map(|v| config_items(&v))
        .unwrap_or_default()
}
