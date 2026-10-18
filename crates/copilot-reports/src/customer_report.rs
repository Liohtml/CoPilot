//! `POST /api/incidents/customer_reports/generate/background`
//! (`routes/customer_report.py`) and the generation it queues
//! (`services/customer_report.py`): the `processing` placeholder row, then,
//! after the answer, the aggregations, case cards, verdict figures, theme,
//! SLA section and charts rendered into the chosen layout, wkhtmltopdf, the
//! PDF stored in MinIO and the row completed — or marked `failed` with the
//! exception's text.
//!
//! Check order is FastAPI's: the body's JSON, the token, the body
//! (`CustomerReportGenerateRequest`: its `date_from < date_to` check after the
//! fields), then the customer access (403), the customer (404). The
//! aggregation statements are SQLAlchemy's, so MySQL breaks count ties the
//! same way.

use std::collections::HashSet;

use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use chrono::NaiveDateTime;
use serde_json::{Map, Value, json};

use copilot_db::Db;
use copilot_incidents::access;
use copilot_incidents::store::{self, Include};
use copilot_jinja::Data;
use copilot_objectstore::{ObjectStore, ops};
use copilot_web::validate::{Loc, LocPart, StrRules, Validator};
use copilot_web::{AnyPortalOrSoc, ApiError, AppContext, Authorized, CurrentUser, WithJson};

use crate::sla::{dict, int, opt_s, s};
use crate::{charts, pdfkit, sla, templates};

type Any = Authorized<AnyPortalOrSoc>;

/// `BUCKET_NAME`.
pub const BUCKET_NAME: &str = "incident-management-reports";
const MAX_CASE_ASSETS: usize = 20;
const MAX_CASE_IOCS: usize = 25;
const MAX_CASE_SHEETS: i64 = 50;

/// `TEMPLATE_FILES`.
const TEMPLATE_FILES: [(&str, &str); 4] = [
    ("full", "customer_incident_report_template.html"),
    ("executive", "customer_incident_report_executive.html"),
    ("operational", "customer_incident_report_operational.html"),
    ("analytics", "customer_incident_report_analytics.html"),
];

/// What the route needs.
#[derive(Clone)]
pub struct CustomerReportState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The MinIO store.
    pub store: ObjectStore,
}

impl axum::extract::FromRef<CustomerReportState> for AppContext {
    fn from_ref(s: &CustomerReportState) -> AppContext {
        s.ctx.clone()
    }
}

/// The route, with its full path.
pub fn router(state: CustomerReportState) -> Router {
    Router::new()
        .route(
            "/api/incidents/customer_reports/generate/background",
            post(generate_background),
        )
        .with_state(state)
}

/// A request `datetime`: the wall clock (what MySQL is sent) and the UTC
/// offset in seconds of an aware value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Moment {
    /// The wall clock.
    pub wall: NaiveDateTime,
    /// `None` for a naive value.
    pub offset: Option<i32>,
}

impl Moment {
    /// `isoformat()`.
    pub fn isoformat(&self) -> String {
        let base = if self.wall.and_utc().timestamp_subsec_micros() != 0 {
            self.wall.format("%Y-%m-%dT%H:%M:%S%.6f").to_string()
        } else {
            self.wall.format("%Y-%m-%dT%H:%M:%S").to_string()
        };
        match self.offset {
            None => base,
            Some(o) => {
                let sign = if o < 0 { '-' } else { '+' };
                let a = o.unsigned_abs();
                let (h, m, s) = (a / 3600, a % 3600 / 60, a % 60);
                if s != 0 {
                    format!("{base}{sign}{h:02}:{m:02}:{s:02}")
                } else {
                    format!("{base}{sign}{h:02}:{m:02}")
                }
            }
        }
    }

    fn instant(&self) -> NaiveDateTime {
        self.wall - chrono::Duration::seconds(i64::from(self.offset.unwrap_or(0)))
    }
}

/// `CustomerReportGenerateRequest`.
#[derive(Debug, Clone)]
pub struct GenerateRequest {
    /// `customer_code`.
    pub customer_code: String,
    /// `date_from`.
    pub date_from: Moment,
    /// `date_to`.
    pub date_to: Moment,
    /// `report_name`.
    pub report_name: Option<String>,
    /// `visible_to_customer`.
    pub visible_to_customer: bool,
    /// `brand_theme`.
    pub brand_theme: String,
    /// `report_template`.
    pub report_template: String,
    /// `include_sla`.
    pub include_sla: bool,
}

fn child(at: &Loc, name: &str) -> Loc {
    let mut l = at.clone();
    l.push(LocPart::Key(name.into()));
    l
}

fn datetime_field(
    v: &mut Validator,
    o: &Map<String, Value>,
    at: &Loc,
    name: &str,
) -> Option<Moment> {
    let l = child(at, name);
    let raw = match o.get(name) {
        None => {
            v.missing(l);
            return None;
        }
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(_) => {
            v.push("datetime_type", l, "Input should be a valid datetime");
            return None;
        }
    };
    match copilot_web::datetime::parse_lax_offset(&raw) {
        Ok((wall, offset)) => Some(Moment { wall, offset }),
        Err(e) => {
            v.push(e.kind, l, e.msg);
            None
        }
    }
}

/// A `Literal[...]` field with a default (`literal_error`).
fn literal(
    v: &mut Validator,
    o: &Map<String, Value>,
    at: &Loc,
    name: &str,
    allowed: &[&str],
    default: &str,
) -> String {
    match o.get(name) {
        None => default.to_string(),
        Some(Value::String(s)) if allowed.contains(&s.as_str()) => s.clone(),
        Some(_) => {
            let quoted: Vec<String> = allowed.iter().map(|a| format!("'{a}'")).collect();
            let expected = match quoted.split_last() {
                Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
                _ => quoted.join(""),
            };
            v.push(
                "literal_error",
                child(at, name),
                format!("Input should be {expected}"),
            );
            String::new()
        }
    }
}

/// What a request body validates to: the request, or the `TypeError` of
/// comparing a naive with an aware datetime (a bare 500).
fn read_request(
    v: &mut Validator,
    o: &Map<String, Value>,
    at: &Loc,
) -> Result<Option<GenerateRequest>, ApiError> {
    let customer_code = v.req_str(o, at, "customer_code", StrRules::default());
    let date_from = datetime_field(v, o, at, "date_from");
    let date_to = datetime_field(v, o, at, "date_to");
    let report_name = v.opt_str(o, at, "report_name", StrRules::default());
    let visible_to_customer = v.bool_or(o, at, "visible_to_customer", false);
    let brand_theme = literal(
        v,
        o,
        at,
        "brand_theme",
        &["socfortress", "customer"],
        "customer",
    );
    let report_template = literal(
        v,
        o,
        at,
        "report_template",
        &["full", "executive", "operational", "analytics"],
        "full",
    );
    let include_sla = v.bool_or(o, at, "include_sla", false);
    if v.has_errors() {
        return Ok(None);
    }
    let (Some(date_from), Some(date_to)) = (date_from, date_to) else {
        return Ok(None);
    };
    // `_validate_range` (mode="after").
    let not_before = match (date_from.offset, date_to.offset) {
        (None, None) => date_from.wall >= date_to.wall,
        (Some(_), Some(_)) => date_from.instant() >= date_to.instant(),
        _ => {
            return Err(ApiError::internal(
                "TypeError: can't compare offset-naive and offset-aware datetimes",
            ));
        }
    };
    if not_before {
        v.push(
            "value_error",
            at.clone(),
            "Value error, date_from must be earlier than date_to",
        );
        return Ok(None);
    }
    Ok(Some(GenerateRequest {
        customer_code,
        date_from,
        date_to,
        report_name,
        visible_to_customer,
        brand_theme,
        report_template,
        include_sla,
    }))
}

/// `RoleEnum(user.role_id).name`, `None` for an unknown id.
pub fn role_name(role_id: Option<i32>) -> Option<&'static str> {
    match role_id? {
        1 => Some("admin"),
        2 => Some("analyst"),
        3 => Some("scheduler"),
        4 => Some("customer_user"),
        5 => Some("responder"),
        _ => None,
    }
}

/// `json.dumps(filters)`.
fn filters_json(req: &GenerateRequest) -> String {
    format!(
        "{{\"date_from\": {}, \"date_to\": {}, \"brand_theme\": {}, \"report_template\": {}, \"include_sla\": {}}}",
        Value::String(req.date_from.isoformat()),
        Value::String(req.date_to.isoformat()),
        Value::String(req.brand_theme.clone()),
        Value::String(req.report_template.clone()),
        if req.include_sla { "true" } else { "false" },
    )
}

struct Customer {
    customer_code: String,
    customer_name: String,
}

async fn customer(db: &Db, code: &str) -> Result<Option<Customer>, ApiError> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT customers.customer_code, customers.customer_name FROM customers \
         WHERE customers.customer_code = ?",
    )
    .bind(code)
    .persistent(false)
    .fetch_optional(db.pool())
    .await
    .map_err(ApiError::internal)?;
    Ok(row.map(|(customer_code, customer_name)| Customer {
        customer_code,
        customer_name,
    }))
}

/// `POST /generate/background`.
async fn generate_background(
    State(st): State<CustomerReportState>,
    WithJson(auth, body): WithJson<Any>,
) -> Result<Response, ApiError> {
    let mut req_out: Result<Option<GenerateRequest>, ApiError> = Ok(None);
    body.model(|v, o, at| {
        req_out = read_request(v, o, at);
    })?;
    let Some(mut req) = req_out? else {
        return Err(ApiError::internal("generate/background: no request"));
    };
    if !access::can_access(&st.ctx, &auth, Some(&req.customer_code)).await? {
        return Err(ApiError::forbidden(format!(
            "Access denied to customer {}",
            req.customer_code
        )));
    }
    if customer(&st.ctx.db, &req.customer_code).await?.is_none() {
        return Err(ApiError::not_found(format!(
            "Customer {} not found",
            req.customer_code
        )));
    }
    let now = copilot_core::time::now_utc_micros();
    let timestamp = now.format("%Y%m%d_%H%M%S").to_string();
    let report_name = req
        .report_name
        .clone()
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("incident_report_{timestamp}"));
    let role = role_name(auth.role_id);
    if role == Some("customer_user") && req.include_sla {
        req.include_sla = false;
    }
    let object_key = format!("{}/{report_name}_{timestamp}.pdf", req.customer_code);
    let file_name = format!("{report_name}.pdf");
    let visible = role == Some("customer_user") || req.visible_to_customer;
    let result = sqlx::query(
        "INSERT INTO incident_management_customer_reports (report_name, customer_code, \
         bucket_name, object_key, file_name, file_size, file_hash, generated_at, generated_by, \
         generated_by_role, date_from, date_to, filters_json, total_alerts, total_cases, \
         open_cases, closed_cases, visible_to_customer, status, error_message) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&report_name)
    .bind(&req.customer_code)
    .bind(BUCKET_NAME)
    .bind(&object_key)
    .bind(&file_name)
    .bind(0i64)
    .bind("pending")
    .bind(now)
    .bind(auth.id)
    .bind(role)
    .bind(req.date_from.wall)
    .bind(req.date_to.wall)
    .bind(filters_json(&req))
    .bind(0i64)
    .bind(0i64)
    .bind(0i64)
    .bind(0i64)
    .bind(visible)
    .bind("processing")
    .bind(None::<String>)
    .persistent(false)
    .execute(st.ctx.db.pool())
    .await
    .map_err(ApiError::internal)?;
    let report_id = result.last_insert_id() as i64;
    let task_state = st.clone();
    let user = (*auth).clone();
    let task_req = req.clone();
    tokio::spawn(async move {
        if let Err(e) = generate_customer_report(&task_state, &user, &task_req, report_id).await {
            tracing::error!("Background incident report generation failed (ID: {report_id}): {e}");
        }
    });
    Ok(axum::Json(json!({
        "success": true,
        "message": "Report generation queued successfully",
        "report_id": report_id,
        "report_name": report_name,
        "customer_code": req.customer_code,
        "status": "processing",
        "check_status_url": "/api/v1/incidents/customer_reports",
        "download_url": format!("/api/v1/incidents/customer_reports/{report_id}/download"),
    }))
    .into_response())
}

/// `generate_customer_report(session, user, request, report_id)`: `Err` is
/// the exception's `str()` (the row already marked `failed` when it exists).
pub async fn generate_customer_report(
    st: &CustomerReportState,
    user: &CurrentUser,
    req: &GenerateRequest,
    report_id: i64,
) -> Result<(), String> {
    let db = &st.ctx.db;
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT report_name, file_name, object_key FROM incident_management_customer_reports \
         WHERE id = ?",
    )
    .bind(report_id)
    .fetch_optional(db.pool())
    .await
    .map_err(|e| e.to_string())?;
    let Some((report_name, file_name, object_key)) = row else {
        return Err(format!("Report {report_id} not found"));
    };
    let _ = (&report_name, user);
    let outcome = generate(st, req, &file_name, &object_key).await;
    match outcome {
        Ok(done) => {
            sqlx::query(
                "UPDATE incident_management_customer_reports SET bucket_name = ?, object_key = ?, \
                 file_name = ?, file_size = ?, file_hash = ?, filters_json = ?, total_alerts = ?, \
                 total_cases = ?, open_cases = ?, closed_cases = ?, status = 'completed', \
                 error_message = NULL WHERE id = ?",
            )
            .bind(BUCKET_NAME)
            .bind(&object_key)
            .bind(&file_name)
            .bind(done.file_size)
            .bind(&done.file_hash)
            .bind(filters_json(req))
            .bind(done.stats.0)
            .bind(done.stats.1)
            .bind(done.stats.2)
            .bind(done.stats.3)
            .bind(report_id)
            .execute(db.pool())
            .await
            .map_err(|e| e.to_string())?;
            tracing::info!(
                "Generated incident report {report_id} for customer {}",
                req.customer_code
            );
            Ok(())
        }
        Err(message) => {
            tracing::error!(
                "Failed to generate incident report for {}: {message}",
                req.customer_code
            );
            let _ = sqlx::query(
                "UPDATE incident_management_customer_reports SET status = 'failed', \
                 error_message = ? WHERE id = ?",
            )
            .bind(&message)
            .bind(report_id)
            .execute(db.pool())
            .await;
            Err(message)
        }
    }
}

struct Done {
    file_size: i64,
    file_hash: String,
    /// total alerts, total cases, open, closed.
    stats: (i64, i64, i64, i64),
}

async fn generate(
    st: &CustomerReportState,
    req: &GenerateRequest,
    _file_name: &str,
    object_key: &str,
) -> Result<Done, String> {
    let Some(cust) = customer(&st.ctx.db, &req.customer_code)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Err(format!("Customer {} not found", req.customer_code));
    };
    let (context, stats) =
        build_report_context(&st.ctx, &cust, req)
            .await
            .map_err(|e| match e {
                ApiError::Internal(m) => m,
                other => other.to_string(),
            })?;
    let template = TEMPLATE_FILES
        .iter()
        .find(|(k, _)| *k == req.report_template)
        .map_or(TEMPLATE_FILES[0].1, |(_, f)| f);
    let brand = match context_get(&context, "brand") {
        Some(Data::Str(b)) if !b.is_empty() => b.clone(),
        _ => "CoPilot".to_string(),
    };
    let html = render(template, context).await?;
    let pdf = pdfkit::html_to_pdf_bytes(&html, &brand, "TLP:RED").await?;
    let stored =
        ops::store_file_in_minio(&st.store, &pdf, BUCKET_NAME, object_key, "application/pdf")
            .await
            .map_err(|e| e.text())?
            .map_err(|e| format!("Failed to store report in MinIO: {e}"))?;
    Ok(Done {
        file_size: stored.file_size,
        file_hash: stored.file_hash,
        stats,
    })
}

fn context_get<'a>(context: &'a Data, key: &str) -> Option<&'a Data> {
    match context {
        Data::Dict(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

/// `env.get_template(name).render(context)` (a context dict's keys as the
/// template's variables).
pub async fn render(template: &str, context: Data) -> Result<String, String> {
    let Data::Dict(vars) = context else {
        return Err("context is not a dict".into());
    };
    let name = template.to_string();
    tokio::task::spawn_blocking(move || templates::incident_env().render(&name, &vars))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.message)
}

// -------------------------------------------------------------- the context

fn fmt_dt(t: Option<NaiveDateTime>) -> String {
    t.map_or_else(
        || sla::EMPTY.to_string(),
        |t| t.format("%Y-%m-%d %H:%M").to_string(),
    )
}

/// `_alert_window` and `_case_active_window` binds.
struct Window {
    code: String,
    from: NaiveDateTime,
    to: NaiveDateTime,
}

const A: &str = "incident_management_alert";
const C: &str = "incident_management_case";

async fn scalar(db: &Db, sql: &str, binds: &[Bind]) -> Result<i64, sqlx::Error> {
    let mut q = sqlx::query_scalar::<_, i64>(sql);
    for b in binds {
        q = match b {
            Bind::S(s) => q.bind(s.clone()),
            Bind::T(t) => q.bind(*t),
            Bind::I(i) => q.bind(*i),
        };
    }
    q.persistent(false).fetch_one(db.pool()).await
}

#[derive(Clone)]
enum Bind {
    S(String),
    T(NaiveDateTime),
    I(i64),
}

fn alert_window_sql() -> String {
    format!(
        "{A}.customer_code = ? AND {A}.alert_creation_time >= ? AND {A}.alert_creation_time <= ?"
    )
}

fn case_active_sql() -> String {
    format!(
        "{C}.customer_code = ? AND {C}.case_creation_time <= ? AND ({C}.case_closed_time IS NULL \
         OR {C}.case_closed_time >= ?)"
    )
}

async fn pairs(db: &Db, sql: &str, binds: &[Bind]) -> Result<Vec<(String, i64)>, sqlx::Error> {
    let mut q = sqlx::query_as::<_, (Option<String>, i64)>(sql);
    for b in binds {
        q = match b {
            Bind::S(s) => q.bind(s.clone()),
            Bind::T(t) => q.bind(*t),
            Bind::I(i) => q.bind(*i),
        };
    }
    Ok(q.persistent(false)
        .fetch_all(db.pool())
        .await?
        .into_iter()
        .map(|(k, n)| {
            (
                k.filter(|k| !k.is_empty())
                    .unwrap_or_else(|| "Unknown".into()),
                n,
            )
        })
        .collect())
}

/// One case's card data (`_build_case_card`), with the related rows loaded
/// as the `selectinload` chain loads them.
struct CaseData {
    row: store::CaseRow,
    alerts: Vec<store::AlertRow>,
    children: store::AlertChildren,
    comments: Vec<store::CaseCommentRow>,
}

const CASE_SELECT: &str = "SELECT incident_management_case.id, incident_management_case.case_name, \
    incident_management_case.case_description, incident_management_case.case_creation_time, \
    incident_management_case.case_status, incident_management_case.case_closed_time, \
    incident_management_case.assigned_to, incident_management_case.customer_code, \
    incident_management_case.notification_invoked_number, incident_management_case.escalated, \
    incident_management_case.severity FROM incident_management_case WHERE ";

async fn fetch_cases(
    db: &Db,
    predicate: &str,
    binds: &[Bind],
    limit: i64,
) -> Result<(Vec<CaseData>, i64), sqlx::Error> {
    let total = scalar(
        db,
        &format!("SELECT count(*) AS count_1 FROM incident_management_case WHERE {predicate}"),
        binds,
    )
    .await?;
    let sql = format!(
        "{CASE_SELECT}{predicate} ORDER BY incident_management_case.case_creation_time DESC LIMIT ?"
    );
    let mut q = sqlx::query_as::<_, store::CaseRow>(&sql);
    for b in binds {
        q = match b {
            Bind::S(s) => q.bind(s.clone()),
            Bind::T(t) => q.bind(*t),
            Bind::I(i) => q.bind(*i),
        };
    }
    let rows = q.bind(limit).persistent(false).fetch_all(db.pool()).await?;
    let ids: Vec<i32> = rows.iter().map(|r| r.id).collect();
    let (links, comments) = store::case_children(db, &ids)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    let mut all_alerts: Vec<i32> = links.values().flatten().copied().collect();
    all_alerts.sort_unstable();
    all_alerts.dedup();
    let alerts = store::alerts_by_ids(db, &all_alerts)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        let linked = links.get(&row.id).cloned().unwrap_or_default();
        let case_alerts: Vec<store::AlertRow> = linked
            .iter()
            .filter_map(|id| alerts.iter().find(|a| a.id == *id).cloned())
            .collect();
        let children = store::alert_children(db, &linked, Include::IOCS)
            .await
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
        let case_comments = comments.get(&row.id).cloned().unwrap_or_default();
        out.push(CaseData {
            row,
            alerts: case_alerts,
            children,
            comments: case_comments,
        });
    }
    Ok((out, total))
}

/// `_CASE_TYPE_RE.search(name)` → the upper-cased type.
fn case_type(name: &str) -> Option<String> {
    let upper: Vec<char> = name.chars().collect();
    for (i, &c) in upper.iter().enumerate() {
        if c != '[' {
            continue;
        }
        for t in ["RFI", "INC", "CONF", "CTI"] {
            let n = t.len();
            let cand: String = upper.iter().skip(i + 1).take(n).collect();
            if cand.eq_ignore_ascii_case(t) && cand.is_ascii() && upper.get(i + 1 + n) == Some(&']')
            {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn priority_from_tags(tags: &[String]) -> Option<&'static str> {
    const KEYWORDS: [(&str, &str); 11] = [
        ("critica", "CRITICA"),
        ("critical", "CRITICA"),
        ("critico", "CRITICA"),
        ("alta", "ALTA"),
        ("high", "ALTA"),
        ("media", "MEDIA"),
        ("medium", "MEDIA"),
        ("baja", "BAJA"),
        ("low", "BAJA"),
        ("info", "INFO"),
        ("informational", "INFO"),
    ];
    for tag in tags {
        let normalised = copilot_web::form::py_strip(tag).to_lowercase();
        if let Some((_, p)) = KEYWORDS.iter().find(|(k, _)| *k == normalised) {
            return Some(p);
        }
    }
    None
}

fn type_label(t: &str) -> &'static str {
    match t {
        "RFI" => "Investigation (RFI)",
        "INC" => "Incident (INC)",
        "CONF" => "Configuration (CONF)",
        _ => "Cyber Intelligence (CTI)",
    }
}

/// `_build_case_card(case)`.
fn case_card(c: &CaseData) -> Data {
    let case = &c.row;
    let titles: Vec<String> = c.alerts.iter().map(|a| a.alert_name.clone()).collect();
    let mut tags: Vec<String> = Vec::new();
    for a in &c.alerts {
        for t in c.children.tags.get(&a.id).into_iter().flatten() {
            if !t.tag.is_empty() && !tags.contains(&t.tag) {
                tags.push(t.tag.clone());
            }
        }
    }
    let mut comments = c.comments.clone();
    comments.sort_by_key(|x| x.created_at);
    let ctype = case_type(&case.case_name);
    let mut assets = Vec::new();
    let mut seen_assets = HashSet::new();
    let mut iocs = Vec::new();
    let mut seen_iocs = HashSet::new();
    for a in &c.alerts {
        for asset in c.children.assets.get(&a.id).into_iter().flatten() {
            if !asset.asset_name.is_empty() && seen_assets.insert(asset.asset_name.clone()) {
                assets.push(dict(vec![
                    ("name", s(asset.asset_name.clone())),
                    ("agent_id", opt_s(asset.agent_id.as_deref())),
                ]));
            }
        }
        for ioc in c.children.iocs.get(&a.id).into_iter().flatten() {
            if !ioc.value.is_empty() && seen_iocs.insert(ioc.value.clone()) {
                iocs.push(dict(vec![
                    ("value", s(ioc.value.clone())),
                    ("type", s(ioc.kind.clone())),
                    ("description", opt_s(ioc.description.as_deref())),
                ]));
            }
        }
    }
    let closed = case.case_closed_time.is_some();
    let status_label = if closed {
        "CLOSED"
    } else if case.case_status == "PENDING_CUSTOMER" {
        "WAITING ON CUSTOMER"
    } else {
        "OPEN"
    };
    let short = |t: Option<NaiveDateTime>| {
        t.map_or_else(
            || sla::EMPTY.to_string(),
            |t| t.format("%d/%m/%y").to_string(),
        )
    };
    let overflow = |n: usize, cap: usize| int(n.saturating_sub(cap) as i64);
    let n_assets = assets.len();
    let n_iocs = iocs.len();
    dict(vec![
        ("id", int(i64::from(case.id))),
        ("name", s(case.case_name.clone())),
        ("type", ctype.clone().map_or(Data::None, Data::Str)),
        (
            "type_label",
            ctype.as_deref().map_or(Data::None, |t| s(type_label(t))),
        ),
        ("priority", priority_from_tags(&tags).map_or(Data::None, s)),
        (
            "taxonomy",
            if tags.is_empty() {
                Data::None
            } else {
                s(tags.iter().take(3).cloned().collect::<Vec<_>>().join(" / "))
            },
        ),
        ("is_closed", Data::Bool(closed)),
        ("status_label", s(status_label)),
        (
            "assigned_to",
            s(case
                .assigned_to
                .clone()
                .filter(|a| !a.is_empty())
                .unwrap_or_else(|| sla::EMPTY.into())),
        ),
        ("creation_time", s(fmt_dt(Some(case.case_creation_time)))),
        ("closed_time", s(fmt_dt(case.case_closed_time))),
        ("reported_short", s(short(Some(case.case_creation_time)))),
        ("closed_short", s(short(case.case_closed_time))),
        ("description", s(case.case_description.clone())),
        ("linked_alert_count", int(c.alerts.len() as i64)),
        (
            "linked_alert_titles",
            Data::List(titles.iter().take(15).cloned().map(Data::Str).collect()),
        ),
        ("linked_alert_overflow", overflow(titles.len(), 15)),
        (
            "assets",
            Data::List(assets.into_iter().take(MAX_CASE_ASSETS).collect()),
        ),
        ("asset_overflow", overflow(n_assets, MAX_CASE_ASSETS)),
        (
            "iocs",
            Data::List(iocs.into_iter().take(MAX_CASE_IOCS).collect()),
        ),
        ("ioc_overflow", overflow(n_iocs, MAX_CASE_IOCS)),
        (
            "comments",
            Data::List(
                comments
                    .iter()
                    .map(|x| {
                        dict(vec![
                            ("user_name", s(x.user_name.clone())),
                            ("created_at", s(fmt_dt(Some(x.created_at)))),
                            ("comment", s(x.comment.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

/// `false_positive_reason_label(reason)`.
pub fn false_positive_reason_label(reason: &str) -> String {
    match reason {
        "" => "Unspecified".into(),
        "EXPECTED_ACTIVITY" => "Expected / legitimate activity".into(),
        "KNOWN_APPLICATION" => "Known application or service".into(),
        "AUTHORIZED_USER" => "Authorized user activity".into(),
        "RULE_TOO_SENSITIVE" => "Detection rule too sensitive".into(),
        "OTHER" => "Other".into(),
        other => other.into(),
    }
}

fn opt_f(v: Option<f64>) -> Data {
    v.map_or(Data::None, Data::Float)
}

/// `resolve_theme(session, brand_theme, customer_code=…)`.
pub async fn resolve_theme(
    db: &Db,
    brand_theme: &str,
    code: Option<&str>,
) -> Result<Data, ApiError> {
    use base64::Engine as _;
    let input = if brand_theme == "socfortress" {
        let logo = format!(
            "data:image/svg+xml;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(templates::SOCFORTRESS_LOGO_SVG)
        );
        copilot_notifications::branding::palette(
            Some(copilot_notifications::branding::SOCF_BASE),
            Some(logo),
            "SOCFortress",
            "SOCFortress",
        )
    } else {
        let global = copilot_db::branding::global_settings(db)
            .await
            .map_err(ApiError::internal)?;
        let custom = match code {
            Some(c) => copilot_db::branding::customer_override(db, c)
                .await
                .map_err(ApiError::internal)?,
            None => None,
        };
        copilot_notifications::branding::customer_theme(
            &copilot_notifications::branding::effective(global.as_ref(), custom.as_ref()),
        )
    };
    Ok(Data::from(&input))
}

fn theme_str(theme: &Data, key: &str) -> Option<String> {
    match context_get(theme, key) {
        Some(Data::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

/// `build_report_context(session, customer, request)` and its `_stats`.
async fn build_report_context(
    ctx: &AppContext,
    cust: &Customer,
    req: &GenerateRequest,
) -> Result<(Data, (i64, i64, i64, i64)), ApiError> {
    let db = &ctx.db;
    let w = Window {
        code: req.customer_code.clone(),
        from: req.date_from.wall,
        to: req.date_to.wall,
    };
    let err = |e: sqlx::Error| ApiError::internal(e);
    let aw = alert_window_sql();
    let wb = [Bind::S(w.code.clone()), Bind::T(w.from), Bind::T(w.to)];
    let cw = case_active_sql();
    let cb = [Bind::S(w.code.clone()), Bind::T(w.to), Bind::T(w.from)];

    let total_alerts = scalar(
        db,
        &format!("SELECT count(*) AS count_1 FROM {A} WHERE {aw}"),
        &wb,
    )
    .await
    .map_err(err)?;
    let by_source = pairs(
        db,
        &format!(
            "SELECT {A}.source, count(*) AS cnt FROM {A} WHERE {aw} GROUP BY {A}.source \
             ORDER BY count(*) DESC"
        ),
        &wb,
    )
    .await
    .map_err(err)?;
    let by_status = pairs(
        db,
        &format!(
            "SELECT {A}.status, count(*) AS cnt FROM {A} WHERE {aw} GROUP BY {A}.status \
             ORDER BY count(*) DESC"
        ),
        &wb,
    )
    .await
    .map_err(err)?;
    let mut lb = wb.to_vec();
    lb.push(Bind::I(15));
    let top_alert_names = pairs(
        db,
        &format!(
            "SELECT {A}.alert_name, count(*) AS cnt FROM {A} WHERE {aw} GROUP BY {A}.alert_name \
             ORDER BY count(*) DESC LIMIT ?"
        ),
        &lb,
    )
    .await
    .map_err(err)?;
    let top_tags = pairs(
        db,
        &format!(
            "SELECT incident_management_alerttag.tag, count(*) AS cnt FROM {A} INNER JOIN \
             incident_management_alert_to_tag ON incident_management_alert_to_tag.alert_id = {A}.id \
             INNER JOIN incident_management_alerttag ON incident_management_alerttag.id = \
             incident_management_alert_to_tag.tag_id WHERE {aw} GROUP BY \
             incident_management_alerttag.tag ORDER BY count(*) DESC LIMIT ?"
        ),
        &lb,
    )
    .await
    .map_err(err)?;
    let total_cases = scalar(
        db,
        &format!("SELECT count(*) AS count_1 FROM {C} WHERE {cw}"),
        &cb,
    )
    .await
    .map_err(err)?;
    let closed_count = scalar(
        db,
        &format!(
            "SELECT count(*) AS count_1 FROM {C} WHERE {cw} AND {C}.case_closed_time IS NOT NULL"
        ),
        &cb,
    )
    .await
    .map_err(err)?;
    let open_count = scalar(
        db,
        &format!("SELECT count(*) AS count_1 FROM {C} WHERE {cw} AND {C}.case_closed_time IS NULL"),
        &cb,
    )
    .await
    .map_err(err)?;
    // cases_reported_by_type
    let created = format!(
        "{C}.customer_code = ? AND {C}.case_creation_time >= ? AND {C}.case_creation_time <= ?"
    );
    let names_sql = format!("SELECT {C}.case_name FROM {C} WHERE {created}");
    let names = sqlx::query_scalar::<_, String>(&names_sql)
        .bind(w.code.clone())
        .bind(w.from)
        .bind(w.to)
        .persistent(false)
        .fetch_all(db.pool())
        .await
        .map_err(err)?;
    let mut counts = [
        ("INC", 0i64),
        ("RFI", 0),
        ("CONF", 0),
        ("CTI", 0),
        ("OTROS", 0),
    ];
    for name in &names {
        let upper = name.to_uppercase();
        let key = ["INC", "RFI", "CONF", "CTI"]
            .into_iter()
            .find(|k| upper.contains(&format!("[{k}]")))
            .unwrap_or("OTROS");
        if let Some(slot) = counts.iter_mut().find(|(k, _)| *k == key) {
            slot.1 += 1;
        }
    }
    let mut cases_by_type: Vec<(String, Data)> = counts
        .iter()
        .map(|(k, n)| ((*k).to_string(), int(*n)))
        .collect();
    cases_by_type.push(("total".into(), int(names.len() as i64)));
    // monthly_trend
    let alert_times = sqlx::query_scalar::<_, Option<NaiveDateTime>>(&format!(
        "SELECT {A}.alert_creation_time FROM {A} WHERE {aw}"
    ))
    .bind(w.code.clone())
    .bind(w.from)
    .bind(w.to)
    .persistent(false)
    .fetch_all(db.pool())
    .await
    .map_err(err)?;
    let case_times = sqlx::query_scalar::<_, Option<NaiveDateTime>>(&format!(
        "SELECT {C}.case_creation_time FROM {C} WHERE {created}"
    ))
    .bind(w.code.clone())
    .bind(w.from)
    .bind(w.to)
    .persistent(false)
    .fetch_all(db.pool())
    .await
    .map_err(err)?;
    let mut buckets: std::collections::BTreeMap<String, (i64, i64)> = Default::default();
    let key = |t: &NaiveDateTime| t.format("%Y-%m").to_string();
    for t in alert_times.iter().flatten() {
        buckets.entry(key(t)).or_default().0 += 1;
    }
    for t in case_times.iter().flatten() {
        buckets.entry(key(t)).or_default().1 += 1;
    }
    let trend: Vec<(String, i64, i64)> = buckets.into_iter().map(|(m, (a, c))| (m, a, c)).collect();
    let trend_data = Data::List(
        trend
            .iter()
            .map(|(m, a, c)| {
                dict(vec![
                    ("month", s(m.clone())),
                    ("alerts", int(*a)),
                    ("cases", int(*c)),
                    (
                        "ratio",
                        Data::Float(if *a != 0 {
                            copilot_core::time::py_round(*c as f64 / *a as f64, 2)
                        } else {
                            0.0
                        }),
                    ),
                ])
            })
            .collect(),
    );
    // Verdict figures, one-customer scope.
    let codes = [w.code.clone()];
    let verdicts = copilot_incidents::verdict_stats::compute(db, Some(&codes), w.from, w.to, 15)
        .await
        .map_err(ApiError::internal)?;
    // Case cards.
    let open_pred = format!("{cw} AND {C}.case_closed_time IS NULL");
    let (open_rows, open_total) = fetch_cases(db, &open_pred, &cb, MAX_CASE_SHEETS)
        .await
        .map_err(err)?;
    let closed_pred = format!(
        "{C}.customer_code = ? AND {C}.case_closed_time IS NOT NULL AND {C}.case_closed_time >= ? \
         AND {C}.case_closed_time <= ?"
    );
    let (closed_rows, closed_total) = fetch_cases(db, &closed_pred, &wb, MAX_CASE_SHEETS)
        .await
        .map_err(err)?;
    let open_cards: Vec<Data> = open_rows.iter().map(case_card).collect();
    let closed_cards: Vec<Data> = closed_rows.iter().map(case_card).collect();
    let theme = resolve_theme(db, &req.brand_theme, Some(&req.customer_code)).await?;
    let sla_ctx = if req.include_sla {
        let data = sla::customer_sla_context(ctx, &req.customer_code, w.from, w.to).await?;
        if req.date_from.offset.is_some() && sla_has_items(&data) {
            return Err(ApiError::internal(
                "can't compare offset-naive and offset-aware datetimes",
            ));
        }
        data
    } else {
        Data::None
    };
    let months: Vec<String> = trend.iter().map(|(m, _, _)| m.clone()).collect();
    let show_evolution = trend.len() >= 2;
    let bar = theme_str(&theme, "chart_bar");
    let charts_data = dict(vec![
        (
            "alerts_by_status",
            if total_alerts != 0 {
                s(charts::donut_png(&by_status, true))
            } else {
                Data::None
            },
        ),
        (
            "alerts_by_source",
            if total_alerts != 0 {
                s(charts::donut_png(&by_source, false))
            } else {
                Data::None
            },
        ),
        (
            "top_alert_names",
            if top_alert_names.is_empty() {
                Data::None
            } else {
                s(charts::hbar_png(&top_alert_names, bar.as_deref()))
            },
        ),
        (
            "top_tags",
            if top_tags.is_empty() {
                Data::None
            } else {
                s(charts::hbar_png(&top_tags, bar.as_deref()))
            },
        ),
        (
            "false_positive_reasons",
            if verdicts.by_reason.is_empty() {
                Data::None
            } else {
                let labelled: Vec<(String, i64)> = verdicts
                    .by_reason
                    .iter()
                    .map(|(r, n)| (false_positive_reason_label(r), *n))
                    .collect();
                s(charts::hbar_png(&labelled, bar.as_deref()))
            },
        ),
        (
            "evolution_alerts",
            if show_evolution {
                let v: Vec<i64> = trend.iter().map(|t| t.1).collect();
                s(charts::evolution_png(
                    &months,
                    &v,
                    theme_str(&theme, "chart_evo_alerts").as_deref(),
                ))
            } else {
                Data::None
            },
        ),
        (
            "evolution_cases",
            if show_evolution {
                let v: Vec<i64> = trend.iter().map(|t| t.2).collect();
                s(charts::evolution_png(
                    &months,
                    &v,
                    theme_str(&theme, "chart_evo_cases").as_deref(),
                ))
            } else {
                Data::None
            },
        ),
    ]);
    let generated = fmt_dt(Some(copilot_core::time::now_utc_micros()));
    let period = dict(vec![
        ("from", s(req.date_from.wall.format("%Y-%m-%d").to_string())),
        ("to", s(req.date_to.wall.format("%Y-%m-%d").to_string())),
    ]);
    let pair_list = |p: &[(String, i64)]| {
        Data::List(
            p.iter()
                .map(|(k, n)| Data::Tuple(vec![s(k.clone()), int(*n)]))
                .collect(),
        )
    };
    let context = dict(vec![
        ("generated_at", s(generated)),
        (
            "customer",
            dict(vec![
                ("code", s(cust.customer_code.clone())),
                ("name", s(cust.customer_name.clone())),
            ]),
        ),
        ("period", period),
        (
            "brand",
            context_get(&theme, "footer_brand")
                .cloned()
                .unwrap_or(Data::None),
        ),
        (
            "logo",
            context_get(&theme, "logo").cloned().unwrap_or(Data::None),
        ),
        ("theme", theme.clone()),
        ("tlp", s("TLP:RED")),
        (
            "metrics",
            dict(vec![
                ("total_alerts", int(total_alerts)),
                ("total_cases", int(total_cases)),
                ("open_cases", int(open_count)),
                ("closed_cases", int(closed_count)),
                ("reported_cases", int(names.len() as i64)),
                ("reviewed_alerts", int(verdicts.reviewed)),
                ("false_positives", int(verdicts.false_positive)),
                ("true_positives", int(verdicts.true_positive)),
                ("false_positive_rate", opt_f(verdicts.false_positive_rate)),
                ("triage_coverage_rate", opt_f(verdicts.coverage_rate)),
            ]),
        ),
        ("alerts_by_source", pair_list(&by_source)),
        ("cases_by_type", Data::Dict(cases_by_type)),
        ("charts", charts_data),
        ("monthly_trend", trend_data),
        (
            "false_positive_rules",
            Data::List(
                verdicts
                    .by_alert_name
                    .iter()
                    .map(|r| {
                        dict(vec![
                            ("alert_name", s(r.alert_name.clone())),
                            ("false_positive", int(r.false_positive)),
                            ("reviewed", int(r.reviewed)),
                            ("rate", opt_f(r.false_positive_rate)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("has_verdicts", Data::Bool(verdicts.reviewed > 0)),
        (
            "open_overflow",
            int((open_total - open_cards.len() as i64).max(0)),
        ),
        ("open_cases", Data::List(open_cards)),
        (
            "closed_overflow",
            int((closed_total - closed_cards.len() as i64).max(0)),
        ),
        ("closed_cases", Data::List(closed_cards)),
        ("has_alerts", Data::Bool(total_alerts > 0)),
        ("has_cases", Data::Bool(total_cases > 0)),
        ("sla", sla_ctx),
    ]);
    Ok((
        context,
        (total_alerts, total_cases, open_count, closed_count),
    ))
}

fn sla_has_items(data: &Data) -> bool {
    let opened = |entity: &str| {
        context_get(data, entity)
            .and_then(|e| context_get(e, "opened"))
            .is_some_and(|v| !matches!(v, Data::Int(0)))
    };
    opened("alerts") || opened("cases")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isoformat_as_python() {
        let wall = chrono::NaiveDate::from_ymd_opt(2026, 1, 2)
            .unwrap()
            .and_hms_micro_opt(3, 4, 5, 60)
            .unwrap();
        assert_eq!(
            Moment { wall, offset: None }.isoformat(),
            "2026-01-02T03:04:05.000060"
        );
        let wall = wall.with_nanosecond(0).unwrap();
        assert_eq!(
            Moment {
                wall,
                offset: Some(0)
            }
            .isoformat(),
            "2026-01-02T03:04:05+00:00"
        );
        assert_eq!(
            Moment {
                wall,
                offset: Some(-(5 * 3600 + 30 * 60))
            }
            .isoformat(),
            "2026-01-02T03:04:05-05:30"
        );
    }

    #[test]
    fn case_types_and_priorities() {
        assert_eq!(case_type("[rfi] check"), Some("RFI".into()));
        assert_eq!(case_type("x [CONF]"), Some("CONF".into()));
        assert_eq!(case_type("[INCX]"), None);
        assert_eq!(priority_from_tags(&[" High ".into()]), Some("ALTA"));
        assert_eq!(priority_from_tags(&["none".into()]), None);
    }

    use chrono::Timelike as _;
}
