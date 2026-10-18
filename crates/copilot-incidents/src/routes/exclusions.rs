//! The Velociraptor Sigma exclusion rules of `/api/incidents/alerts` — port
//! of the rule CRUD in `app/incidents/routes/incident_alert.py` and
//! `VeloSigmaExclusionService` (`app/incidents/services/velo_sigma.py`),
//! admin/analyst only.
//!
//! Every answer shows the row as stored (the service refreshes after each
//! commit). A rule created from an alert (`source_alert_id`) leaves the
//! `Exclusion rule created from this alert: …` comment on it after the
//! commit, best-effort, through the comments *service* (no SLA action, no
//! customer hand-back).
//!
//! Still Python: the rest of `/api/incidents/alerts`. Alert creation and
//! the Sigma ingest read the Wazuh indexer or Graylog; the exclusion draft
//! and dry-run are built on `extract_event_fields` and `_matches_exclusion`,
//! the one flattening and the one matcher the ingest uses (Pydantic event
//! models, Python `re` patterns), and a second copy here could drift from
//! the ingest that decides what is actually suppressed.
//!
//! Difference by design: a rule scoped to a customer belongs to that tenant
//! (like a case template; NULL or empty is every customer's). Python let any
//! analyst list, read, edit, toggle and delete every tenant's rules, and
//! create one for any tenant — suppressing that tenant's alerts. Here a
//! scoped caller sees shared rules and their own customers' (another
//! tenant's reads as missing) and cannot name another customer (403).

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use chrono::NaiveDateTime;
use serde_json::{Map, Value, json};
use sqlx::FromRow;
use sqlx::types::Json;

use copilot_auth::AccessScope;
use copilot_core::time::{mysql_datetime, now_utc_micros, to_pydantic_iso};
use copilot_web::validate::{IntRules, Loc, LocPart, StrRules, Validator, loc};
use copilot_web::{
    AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, CurrentUser, QueryPairs, WithJson,
};

use super::common::{json, message_success, path_int};
use crate::access;
use crate::requests::merge;
use crate::views;
use crate::writes::{self, CommentKind};

type Soc = Authorized<AdminOrAnalyst>;
type Obj = Map<String, Value>;

const TABLE: &str = "incident_management_velo_sigma_exclusion";

const COLS: &str = "id, name, description, channel, title, field_matches, customer_code, \
    created_by, created_at, last_matched_at, match_count, enabled, source_alert_id, source_case_id";

const NOT_FOUND: &str = "Exclusion rule not found";

/// `EXCLUSION_LINK_COMMENT_PREFIX`.
pub const EXCLUSION_LINK_COMMENT_PREFIX: &str = "Exclusion rule created from this alert: ";

/// The router, to be nested at `/api/incidents/alerts`. Every other path
/// of that prefix falls through to the legacy backend.
pub fn alerts(ctx: AppContext) -> Router {
    Router::new()
        .route("/create/velo-sigma/exclusion", get(list).post(create))
        .route(
            "/create/velo-sigma/exclusion/{exclusion_id}",
            get(get_one).patch(update).delete(delete_one),
        )
        .route("/velo-sigma/exclusion/{exclusion_id}/toggle", post(toggle))
        .with_state(ctx)
}

/// A stored rule.
#[derive(Debug, Clone, FromRow)]
struct Rule {
    id: i32,
    name: String,
    description: Option<String>,
    channel: Option<String>,
    title: Option<String>,
    field_matches: Option<Json<Value>>,
    customer_code: Option<String>,
    created_by: String,
    created_at: NaiveDateTime,
    last_matched_at: Option<NaiveDateTime>,
    match_count: i32,
    enabled: bool,
    source_alert_id: Option<i32>,
    source_case_id: Option<i32>,
}

impl Rule {
    /// The JSON value of `field_matches` (SQL NULL and JSON `null` alike).
    fn matches(&self) -> Value {
        self.field_matches
            .as_ref()
            .map(|j| j.0.clone())
            .unwrap_or(Value::Null)
    }

    /// `VeloSigmaExclusionResponse` (base fields first, then the stored
    /// ones). A `field_matches` that is not an object fails the response
    /// model, as in Python.
    fn to_json(&self) -> Result<Value, ApiError> {
        let matches = self.matches();
        if !matches!(matches, Value::Null | Value::Object(_)) {
            return Err(ApiError::internal(format!(
                "exclusion {} field_matches is not a dictionary",
                self.id
            )));
        }
        Ok(json!({
            "name": self.name,
            "description": self.description,
            "channel": self.channel,
            "title": self.title,
            "field_matches": matches,
            "customer_code": self.customer_code,
            "enabled": self.enabled,
            "source_alert_id": self.source_alert_id,
            "source_case_id": self.source_case_id,
            "id": self.id,
            "created_by": self.created_by,
            "created_at": to_pydantic_iso(self.created_at),
            "last_matched_at": self.last_matched_at.map(to_pydantic_iso),
            "match_count": self.match_count,
        }))
    }
}

/// `source_link_comment`.
fn source_link_comment(rule: &Rule) -> String {
    let scope = match rule.customer_code.as_deref() {
        Some(code) if !code.is_empty() => format!("customer {code}"),
        _ => "all customers".to_string(),
    };
    let state = if rule.enabled { "enabled" } else { "disabled" };
    format!(
        "{EXCLUSION_LINK_COMMENT_PREFIX}#{} \"{}\" ({scope}, {state}) by {}",
        rule.id, rule.name, rule.created_by
    )
}

/// Difference by design: a rule scoped to a customer is that customer's;
/// NULL or empty (the matcher's "every customer") is shared.
fn visible(scope: &AccessScope, customer: Option<&str>) -> bool {
    match customer {
        None | Some("") => true,
        Some(code) => scope.can_access(code),
    }
}

/// A customer named in the body must be the caller's.
fn ensure_customer(scope: &AccessScope, customer: Option<&str>) -> Result<(), ApiError> {
    if visible(scope, customer) {
        return Ok(());
    }
    Err(ApiError::forbidden(format!(
        "Access denied to customer {} - insufficient customer permissions",
        customer.unwrap_or_default()
    )))
}

async fn load(ctx: &AppContext, id: i64) -> Result<Option<Rule>, ApiError> {
    sqlx::query_as::<_, Rule>(&format!("SELECT {COLS} FROM {TABLE} WHERE id = ?"))
        .bind(id)
        .fetch_optional(ctx.db.pool())
        .await
        .map_err(ApiError::internal)
}

/// `get_exclusion`, with the tenant check: another tenant's rule is missing.
async fn load_visible(
    ctx: &AppContext,
    user: &CurrentUser,
    id: i64,
) -> Result<Option<Rule>, ApiError> {
    let Some(rule) = load(ctx, id).await? else {
        return Ok(None);
    };
    let scope = user.access(ctx).await?;
    Ok(visible(scope, rule.customer_code.as_deref()).then_some(rule))
}

/// `VeloSigmaExlcusionRouteResponse`.
fn route_response(rule: &Rule, message: &str) -> ApiResult {
    Ok(json(json!({
        "exclusion_response": rule.to_json()?,
        "success": true,
        "message": message,
    })))
}

/// An `Optional[Dict]` field: `dict_type` for anything but an object or null.
fn opt_dict(v: &mut Validator, o: &Obj, at: &Loc, name: &str) -> Option<Value> {
    match o.get(name) {
        None | Some(Value::Null) => None,
        Some(x @ Value::Object(_)) => Some(x.clone()),
        Some(_) => {
            let mut l = at.clone();
            l.push(LocPart::Key(name.into()));
            v.push("dict_type", l, "Input should be a valid dictionary");
            None
        }
    }
}

/// `VeloSigmaExclusionCreate` (its `created_by` is validated, then replaced
/// by the caller).
struct ExclusionCreate {
    name: String,
    description: Option<String>,
    channel: Option<String>,
    title: Option<String>,
    field_matches: Option<Value>,
    customer_code: Option<String>,
    enabled: bool,
    source_alert_id: Option<i64>,
    source_case_id: Option<i64>,
}

impl ExclusionCreate {
    fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        let any = StrRules::any;
        let req = Self {
            name: v.req_str(o, at, "name", any()),
            description: v.opt_str(o, at, "description", any()),
            channel: v.opt_str(o, at, "channel", any()),
            title: v.opt_str(o, at, "title", any()),
            field_matches: opt_dict(v, o, at, "field_matches"),
            customer_code: v.opt_str(o, at, "customer_code", any()),
            enabled: v.bool_or(o, at, "enabled", true),
            source_alert_id: v.opt_int(o, at, "source_alert_id", IntRules::default()),
            source_case_id: v.opt_int(o, at, "source_case_id", IntRules::default()),
        };
        v.opt_str(o, at, "created_by", any());
        req
    }
}

/// An optional field with its `model_fields_set` presence.
type Sent<T> = Option<Option<T>>;

/// `VeloSigmaExclusionUpdate` (`model_dump(exclude_unset=True)`).
struct ExclusionUpdate {
    name: Sent<String>,
    description: Sent<String>,
    channel: Sent<String>,
    title: Sent<String>,
    field_matches: Sent<Value>,
    customer_code: Sent<String>,
    enabled: Sent<bool>,
}

impl ExclusionUpdate {
    fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        fn sent<T>(o: &Obj, name: &str, value: Option<T>) -> Sent<T> {
            o.contains_key(name).then_some(value)
        }
        let any = StrRules::any;
        let name = v.opt_str(o, at, "name", any());
        let description = v.opt_str(o, at, "description", any());
        let channel = v.opt_str(o, at, "channel", any());
        let title = v.opt_str(o, at, "title", any());
        let field_matches = opt_dict(v, o, at, "field_matches");
        let customer_code = v.opt_str(o, at, "customer_code", any());
        let enabled = v.opt_bool(o, at, "enabled");
        Self {
            name: sent(o, "name", name),
            description: sent(o, "description", description),
            channel: sent(o, "channel", channel),
            title: sent(o, "title", title),
            field_matches: sent(o, "field_matches", field_matches),
            customer_code: sent(o, "customer_code", customer_code),
            enabled: sent(o, "enabled", enabled),
        }
    }
}

/// Python's `==` over JSON values: what SQLAlchemy compares before it
/// writes a JSON attribute (`1 == 1.0 == True`, dicts regardless of order).
fn py_eq(a: &Value, b: &Value) -> bool {
    fn num(v: &Value) -> Option<f64> {
        match v {
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Number(n) => n.as_f64(),
            _ => None,
        }
    }
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, p)| y.get(k).is_some_and(|q| py_eq(p, q)))
        }
        (Value::Number(x), Value::Number(y)) => match (x.as_i64(), y.as_i64()) {
            (Some(p), Some(q)) => p == q,
            _ => match (x.as_u64(), y.as_u64()) {
                (Some(p), Some(q)) => p == q,
                _ => num(a) == num(b),
            },
        },
        _ => match (num(a), num(b)) {
            (Some(p), Some(q)) => p == q,
            _ => false,
        },
    }
}

/// A column to write.
enum Set {
    Str(&'static str, Option<String>),
    Bool(&'static str, Option<bool>),
    Json(&'static str, Value),
}

/// `update_exclusion`: `setattr` for each field sent, then the flush writes
/// only the attributes whose value changed (a JSON `None` is stored as JSON
/// `null`, like every write of that column).
async fn apply(ctx: &AppContext, rule: &Rule, changes: Vec<Set>) -> Result<(), ApiError> {
    let changed: Vec<Set> = changes
        .into_iter()
        .filter(|s| match s {
            Set::Str(col, value) => {
                let old = match *col {
                    "name" => Some(rule.name.as_str()),
                    "description" => rule.description.as_deref(),
                    "channel" => rule.channel.as_deref(),
                    "title" => rule.title.as_deref(),
                    _ => rule.customer_code.as_deref(),
                };
                old != value.as_deref()
            }
            Set::Bool(_, value) => *value != Some(rule.enabled),
            Set::Json(_, value) => !py_eq(&rule.matches(), value),
        })
        .collect();
    if changed.is_empty() {
        return Ok(());
    }
    let assignments: Vec<String> = changed
        .iter()
        .map(|s| match s {
            Set::Str(c, _) | Set::Bool(c, _) | Set::Json(c, _) => format!("{c} = ?"),
        })
        .collect();
    let sql = format!("UPDATE {TABLE} SET {} WHERE id = ?", assignments.join(", "));
    let mut q = sqlx::query(&sql);
    for s in &changed {
        q = match s {
            Set::Str(_, value) => q.bind(value.clone()),
            Set::Bool(_, value) => q.bind(*value),
            Set::Json(_, value) => q.bind(Json(value.clone())),
        };
    }
    q.bind(rule.id)
        .execute(ctx.db.pool())
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}

/// `POST /create/velo-sigma/exclusion`.
async fn create(State(ctx): State<AppContext>, WithJson(auth, body): WithJson<Soc>) -> ApiResult {
    let req = body.model(ExclusionCreate::read)?;
    // Provenance (#934): the caller must see the alert / case named.
    if let Some(alert_id) = req.source_alert_id {
        access::ensure_alert(&ctx, &auth, alert_id).await?;
    }
    if let Some(case_id) = req.source_case_id {
        let case = views::case_full(&ctx.db, case_id).await?;
        auth.access(&ctx)
            .await?
            .enforce_owned(case.customer_code.as_deref(), &format!("case {case_id}"))?;
    }
    ensure_customer(auth.access(&ctx).await?, req.customer_code.as_deref())?;
    let inserted = sqlx::query(&format!(
        "INSERT INTO {TABLE} (name, description, channel, title, field_matches, customer_code, \
         created_by, created_at, last_matched_at, match_count, enabled, source_alert_id, \
         source_case_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, ?, ?, ?)"
    ))
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.channel)
    .bind(&req.title)
    .bind(Json(req.field_matches.clone().unwrap_or(Value::Null)))
    .bind(&req.customer_code)
    .bind(&auth.username)
    .bind(mysql_datetime(now_utc_micros()))
    .bind(req.enabled)
    .bind(req.source_alert_id)
    .bind(req.source_case_id)
    .execute(ctx.db.pool())
    .await
    .map_err(ApiError::internal)?;
    let id = inserted.last_insert_id() as i64;
    let rule = load(&ctx, id)
        .await?
        .ok_or_else(|| ApiError::internal("created exclusion vanished"))?;
    if let Some(alert_id) = rule.source_alert_id {
        // `_comment_on_source_alert`: the rule is committed, a failed
        // comment must not report the creation as failed.
        let text = source_link_comment(&rule);
        if let Err(e) = writes::create_comment(
            &ctx.db,
            CommentKind::Alert,
            i64::from(alert_id),
            &text,
            &rule.created_by,
            None,
        )
        .await
        {
            tracing::error!(
                target: "copilot::incidents",
                exclusion = rule.id,
                alert = alert_id,
                error = ?e,
                "exclusion created but the link comment on its alert failed"
            );
        }
    }
    route_response(&rule, "Exclusion rule created successfully")
}

/// `GET /create/velo-sigma/exclusion/{exclusion_id}`.
async fn get_one(auth: Soc, State(ctx): State<AppContext>, Path(raw): Path<String>) -> ApiResult {
    let id = path_int("exclusion_id", &raw)?;
    match load_visible(&ctx, &auth, id).await? {
        None => Err(ApiError::not_found(NOT_FOUND)),
        Some(rule) => route_response(&rule, "Exclusion rule retrieved successfully"),
    }
}

fn query_int(v: &mut Validator, q: &QueryPairs, name: &str) -> Option<i64> {
    let raw = q.get(name)?;
    v.check_int(
        &loc("query", name),
        &Value::String(raw.into()),
        IntRules::default(),
    )
}

/// `GET /create/velo-sigma/exclusion?skip=&limit=&enabled_only=&source_alert_id=&source_case_id=`.
async fn list(auth: Soc, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let skip = query_int(&mut v, &q, "skip").unwrap_or(0);
    let limit = query_int(&mut v, &q, "limit").unwrap_or(100);
    let enabled_only = match q.get("enabled_only") {
        None => false,
        Some(raw) => {
            let obj: Obj = [("enabled_only".to_string(), Value::String(raw.into()))]
                .into_iter()
                .collect();
            v.opt_bool(&obj, &vec![LocPart::Key("query".into())], "enabled_only")
                .unwrap_or(false)
        }
    };
    let source_alert_id = query_int(&mut v, &q, "source_alert_id");
    let source_case_id = query_int(&mut v, &q, "source_case_id");
    v.finish()?;
    let mut sql = format!("SELECT {COLS} FROM {TABLE}");
    let mut clauses: Vec<&str> = Vec::new();
    if enabled_only {
        clauses.push("enabled = 1");
    }
    if source_alert_id.is_some() {
        clauses.push("source_alert_id = ?");
    }
    if source_case_id.is_some() {
        clauses.push("source_case_id = ?");
    }
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY id DESC");
    let mut query = sqlx::query_as::<_, Rule>(&sql);
    for id in [source_alert_id, source_case_id].into_iter().flatten() {
        query = query.bind(id);
    }
    let rows = query
        .fetch_all(ctx.db.pool())
        .await
        .map_err(ApiError::internal)?;
    let scope = auth.access(&ctx).await?;
    let rows: Vec<Rule> = rows
        .into_iter()
        .filter(|r| visible(scope, r.customer_code.as_deref()))
        .collect();
    let total = rows.len();
    // `OFFSET`/`LIMIT` with a negative value is a MySQL syntax error (500).
    let (Ok(start), Ok(count)) = (usize::try_from(skip), usize::try_from(limit)) else {
        return Err(ApiError::internal("negative OFFSET or LIMIT"));
    };
    let exclusions = rows
        .iter()
        .skip(start)
        .take(count)
        .map(Rule::to_json)
        .collect::<Result<Vec<Value>, ApiError>>()?;
    Ok(json(json!({
        "success": true,
        "message": "Exclusion rules retrieved successfully",
        "exclusions": exclusions,
        "pagination": {"total": total, "skip": skip, "limit": limit},
    })))
}

/// `PATCH /create/velo-sigma/exclusion/{exclusion_id}`.
async fn update(
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = v
        .check_int(
            &loc("path", "exclusion_id"),
            &Value::String(raw),
            IntRules::default(),
        )
        .unwrap_or_default();
    let req = merge(v, body.model(ExclusionUpdate::read))?;
    let Some(rule) = load_visible(&ctx, &auth, id).await? else {
        return Err(ApiError::not_found(NOT_FOUND));
    };
    if let Some(code) = &req.customer_code {
        ensure_customer(auth.access(&ctx).await?, code.as_deref())?;
    }
    let mut changes = Vec::new();
    for (col, value) in [
        ("name", req.name),
        ("description", req.description),
        ("channel", req.channel),
        ("title", req.title),
    ] {
        if let Some(value) = value {
            changes.push(Set::Str(col, value));
        }
    }
    if let Some(value) = req.field_matches {
        changes.push(Set::Json("field_matches", value.unwrap_or(Value::Null)));
    }
    if let Some(value) = req.customer_code {
        changes.push(Set::Str("customer_code", value));
    }
    if let Some(value) = req.enabled {
        changes.push(Set::Bool("enabled", value));
    }
    apply(&ctx, &rule, changes).await?;
    let rule = load(&ctx, id)
        .await?
        .ok_or_else(|| ApiError::not_found(NOT_FOUND))?;
    route_response(&rule, "Exclusion rule updated successfully")
}

/// `DELETE /create/velo-sigma/exclusion/{exclusion_id}`.
async fn delete_one(
    auth: Soc,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
) -> ApiResult {
    let id = path_int("exclusion_id", &raw)?;
    if load_visible(&ctx, &auth, id).await?.is_none() {
        return Err(ApiError::not_found(NOT_FOUND));
    }
    sqlx::query(&format!("DELETE FROM {TABLE} WHERE id = ?"))
        .bind(id)
        .execute(ctx.db.pool())
        .await
        .map_err(ApiError::internal)?;
    Ok(message_success("Exclusion rule deleted successfully"))
}

/// `POST /velo-sigma/exclusion/{exclusion_id}/toggle`.
async fn toggle(auth: Soc, State(ctx): State<AppContext>, Path(raw): Path<String>) -> ApiResult {
    let id = path_int("exclusion_id", &raw)?;
    let Some(rule) = load_visible(&ctx, &auth, id).await? else {
        return Err(ApiError::not_found(NOT_FOUND));
    };
    apply(&ctx, &rule, vec![Set::Bool("enabled", Some(!rule.enabled))]).await?;
    let rule = load(&ctx, id)
        .await?
        .ok_or_else(|| ApiError::not_found(NOT_FOUND))?;
    route_response(&rule, "Exclusion rule toggled successfully")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(customer: Option<&str>, enabled: bool) -> Rule {
        Rule {
            id: 7,
            name: "Benign updater".into(),
            description: None,
            channel: None,
            title: None,
            field_matches: None,
            customer_code: customer.map(str::to_string),
            created_by: "analyst1".into(),
            created_at: NaiveDateTime::default(),
            last_matched_at: None,
            match_count: 0,
            enabled,
            source_alert_id: Some(3),
            source_case_id: None,
        }
    }

    #[test]
    fn link_comment_is_the_python_text() {
        assert_eq!(
            source_link_comment(&rule(Some("acme"), true)),
            "Exclusion rule created from this alert: #7 \"Benign updater\" (customer acme, \
             enabled) by analyst1"
        );
        assert_eq!(
            source_link_comment(&rule(Some(""), false)),
            "Exclusion rule created from this alert: #7 \"Benign updater\" (all customers, \
             disabled) by analyst1"
        );
    }

    #[test]
    fn scoped_rules_belong_to_their_tenant() {
        let scope = AccessScope::Customers(vec!["acme".into()]);
        assert!(visible(&scope, None));
        assert!(visible(&scope, Some("")));
        assert!(visible(&scope, Some("acme")));
        assert!(!visible(&scope, Some("other")));
        assert!(!visible(&scope, Some("ACME")));
        assert!(visible(&AccessScope::All, Some("other")));
        assert!(ensure_customer(&scope, Some("other")).is_err());
        assert!(ensure_customer(&scope, None).is_ok());
    }

    #[test]
    fn json_equality_is_pythons() {
        assert!(py_eq(
            &json!({"a": 1, "b": [true]}),
            &json!({"b": [1.0], "a": 1.0})
        ));
        assert!(!py_eq(&json!({"a": "1"}), &json!({"a": 1})));
        assert!(!py_eq(&json!({"a": 1}), &json!({"a": 1, "b": null})));
        assert!(py_eq(&Value::Null, &Value::Null));
        assert!(!py_eq(&Value::Null, &json!({})));
    }
}
