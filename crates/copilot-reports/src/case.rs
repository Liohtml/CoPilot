//! `POST /api/incidents/report/generate-report-docx` and
//! `/generate-report-pdf` (`routes/incident_report.py`): a case rendered
//! into a template of the `copilot-case-report-templates` bucket, the
//! DOCX by docxtpl (`copilot-docx`), the PDF by Jinja's sandbox and
//! wkhtmltopdf (`pdfkit`), answered as a Starlette `FileResponse`.
//!
//! Check order is FastAPI's: the body's JSON, the token, the body model
//! (`CaseDownloadDocxRequest`, whose `file_name` validator raises the
//! `AttributeError` of a truthy non-string — a bare 500 before any field
//! error), the case (404 `No cases found`), then — unlike Python, which
//! rendered any tenant's case for any analyst — the case's customer (403,
//! §4), the template (`download_data_store`'s 404), the rendering.

use axum::Router;
use axum::extract::State;
use axum::response::Response;
use axum::routing::post;
use serde_json::{Map, Value};

use copilot_auth::pyvalue::PyValue;
use copilot_db::Db;
use copilot_incidents::access;
use copilot_incidents::store::{self, Include};
use copilot_jinja::{Autoescape, Data, Directory, Environment};
use copilot_objectstore::{ObjectStore, PyExc, ops};
use copilot_web::validate::{StrRules, Validator};
use copilot_web::{AdminOrAnalyst, ApiError, AppContext, Authorized, JsonBody, WithJson};

use crate::{pdfkit, starlette, tempfile};

type Soc = Authorized<AdminOrAnalyst>;

/// The bucket the case report templates live in.
pub const TEMPLATE_BUCKET: &str = "copilot-case-report-templates";
/// The DOCX media type.
pub const DOCX_MEDIA_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

/// What the routes need.
#[derive(Clone)]
pub struct CaseReportState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The MinIO store.
    pub store: ObjectStore,
}

impl axum::extract::FromRef<CaseReportState> for AppContext {
    fn from_ref(s: &CaseReportState) -> AppContext {
        s.ctx.clone()
    }
}

/// The two routes, with their full paths.
pub fn router(state: CaseReportState) -> Router {
    Router::new()
        .route(
            "/api/incidents/report/generate-report-docx",
            post(generate_docx),
        )
        .route(
            "/api/incidents/report/generate-report-pdf",
            post(generate_pdf),
        )
        .with_state(state)
}

/// `CaseDownloadDocxRequest`.
#[derive(Debug, Clone)]
pub struct CaseDownloadRequest {
    /// `case_id`.
    pub case_id: i64,
    /// `template_name`.
    pub template_name: String,
    /// `file_name` after `ensure_docx_extension`.
    pub file_name: Option<String>,
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn py_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

impl CaseDownloadRequest {
    /// `ensure_docx_extension` on a truthy value that is not a string: the
    /// `AttributeError` that aborts the whole validation (a bare 500).
    pub fn attribute_error(body: &JsonBody) -> Option<ApiError> {
        let JsonBody::Value(Value::Object(o)) = body else {
            return None;
        };
        let value = o.get("file_name")?;
        (truthy(value) && !value.is_string()).then(|| {
            ApiError::internal(format!(
                "AttributeError: '{}' object has no attribute 'endswith'",
                py_type(value)
            ))
        })
    }

    /// The model's fields in order.
    pub fn read(
        v: &mut Validator,
        o: &Map<String, Value>,
        at: &copilot_web::validate::Loc,
    ) -> Self {
        let case_id = v.req_int(o, at, "case_id", Default::default());
        let template_name = v.req_str(o, at, "template_name", StrRules::default());
        let file_name = match o.get("file_name") {
            None => Some("case_report.docx".to_string()),
            Some(Value::String(s)) if !s.is_empty() && !s.ends_with(".docx") => {
                Some(format!("{s}.docx"))
            }
            Some(_) => v.opt_str(o, at, "file_name", StrRules::default()),
        };
        Self {
            case_id,
            template_name,
            file_name,
        }
    }
}

fn unhandled(e: PyExc) -> ApiError {
    e.unhandled()
}

/// `int` → `Data` for the JSON of an alert context.
fn py_data(v: &PyValue) -> Data {
    match v {
        PyValue::None => Data::None,
        PyValue::Bool(b) => Data::Bool(*b),
        PyValue::Int(s) => s
            .parse::<i128>()
            .map(Data::Int)
            .unwrap_or_else(|_| Data::Str(s.clone())),
        PyValue::Float(f) => Data::Float(*f),
        PyValue::Str(s) => Data::Str(s.clone()),
        PyValue::List(items) => Data::List(items.iter().map(py_data).collect()),
        PyValue::Dict(items) => {
            Data::Dict(items.iter().map(|(k, v)| (k.clone(), py_data(v))).collect())
        }
    }
}

fn opt_dt(t: Option<chrono::NaiveDateTime>) -> Data {
    t.map_or(Data::None, Data::DateTime)
}

fn opt_str(s: &Option<String>) -> Data {
    s.as_deref()
        .map_or(Data::None, |s| Data::Str(s.to_string()))
}

fn dict(items: Vec<(&str, Data)>) -> Data {
    Data::Dict(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

async fn context_json(db: &Db, id: i32) -> Result<Option<(String, PyValue)>, ApiError> {
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT source, CAST(context AS CHAR) FROM incident_management_alertcontext WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db.pool())
    .await
    .map_err(ApiError::internal)?;
    Ok(row.map(|(source, text)| {
        let value = match text {
            None => PyValue::None,
            Some(t) => copilot_auth::pyvalue::loads(&t).unwrap_or(PyValue::None),
        };
        (source, value)
    }))
}

/// `fetch_case_by_id` then `create_case_context` (and `_pdf`, the same):
/// `None` when no case has that id.
pub async fn case_context(
    db: &Db,
    case_id: i64,
) -> Result<Option<(store::CaseRow, Vec<(String, Data)>)>, ApiError> {
    let Some(case) = store::case(db, case_id).await? else {
        return Ok(None);
    };
    let (links, _) = store::case_children(db, &[case.id]).await?;
    let alert_ids = links.get(&case.id).cloned().unwrap_or_default();
    let alerts = store::alerts_by_ids(db, &alert_ids).await?;
    let children = store::alert_children(db, &alert_ids, Include::IOCS).await?;
    let mut out_alerts = Vec::new();
    for id in &alert_ids {
        let Some(alert) = alerts.iter().find(|a| a.id == *id) else {
            continue;
        };
        let assets = children.assets.get(id).cloned().unwrap_or_default();
        let context = match assets.first() {
            None => Data::None,
            Some(first) => match context_json(db, first.alert_context_id).await? {
                Some((source, value)) => dict(vec![
                    ("source", Data::Str(source)),
                    ("context", py_data(&value)),
                ]),
                None => dict(vec![("source", Data::None), ("context", Data::None)]),
            },
        };
        let tags = children
            .tags
            .get(id)
            .map(|t| t.iter().map(|t| Data::Str(t.tag.clone())).collect())
            .unwrap_or_default();
        let asset_list = assets
            .iter()
            .map(|a| {
                dict(vec![
                    ("asset_name", Data::Str(a.asset_name.clone())),
                    ("agent_id", opt_str(&a.agent_id)),
                ])
            })
            .collect();
        let comments = children
            .comments
            .get(id)
            .map(|cs| {
                cs.iter()
                    .map(|c| {
                        dict(vec![
                            ("comment", Data::Str(c.comment.clone())),
                            ("user_name", Data::Str(c.user_name.clone())),
                            ("created_at", Data::DateTime(c.created_at)),
                        ])
                    })
                    .collect()
            })
            .unwrap_or_default();
        let iocs = children
            .iocs
            .get(id)
            .map(|is| {
                is.iter()
                    .map(|i| {
                        dict(vec![
                            ("ioc_value", Data::Str(i.value.clone())),
                            ("ioc_type", Data::Str(i.kind.clone())),
                            ("ioc_description", opt_str(&i.description)),
                        ])
                    })
                    .collect()
            })
            .unwrap_or_default();
        out_alerts.push(dict(vec![
            ("alert_name", Data::Str(alert.alert_name.clone())),
            (
                "alert_description",
                Data::Str(alert.alert_description.clone()),
            ),
            ("status", Data::Str(alert.status.clone())),
            ("time_closed", opt_dt(alert.time_closed)),
            ("tags", Data::List(tags)),
            ("assets", Data::List(asset_list)),
            ("comments", Data::List(comments)),
            ("context", context),
            ("iocs", Data::List(iocs)),
        ]));
    }
    let vars = vec![(
        "case".to_string(),
        dict(vec![
            ("name", Data::Str(case.case_name.clone())),
            ("description", Data::Str(case.case_description.clone())),
            ("assigned_to", opt_str(&case.assigned_to)),
            (
                "case_creation_time",
                Data::DateTime(case.case_creation_time),
            ),
            ("case_closed_time", opt_dt(case.case_closed_time)),
            ("id", Data::Int(i128::from(case.id))),
            ("alerts", Data::List(out_alerts)),
        ]),
    )];
    Ok(Some((case, vars)))
}

/// The request, the case and its context, the caller's access to it, the
/// template's bytes.
async fn prepare(
    st: &CaseReportState,
    auth: &Soc,
    body: &JsonBody,
) -> Result<(CaseDownloadRequest, Vec<(String, Data)>, bytes::Bytes), ApiError> {
    if let Some(e) = CaseDownloadRequest::attribute_error(body) {
        return Err(e);
    }
    let req = body.model(CaseDownloadRequest::read)?;
    let Some((case, vars)) = case_context(&st.ctx.db, req.case_id).await? else {
        return Err(ApiError::not_found("No cases found"));
    };
    if !access::can_access(&st.ctx, auth, case.customer_code.as_deref()).await? {
        return Err(ApiError::forbidden(format!(
            "Access denied to case {} - insufficient customer permissions",
            case.id
        )));
    }
    let template = ops::download_data_store(&st.store, TEMPLATE_BUCKET, &req.template_name)
        .await
        .map_err(unhandled)?;
    Ok((req, vars, template))
}

fn docx_error(e: copilot_docx::DocxError) -> ApiError {
    match e {
        copilot_docx::DocxError::Value(m) => ApiError::bad_request(m),
        copilot_docx::DocxError::Internal(m) => ApiError::internal(m),
    }
}

fn jinja_error(e: copilot_jinja::Error) -> ApiError {
    docx_error(copilot_docx::docxtpl::jinja_error(e))
}

/// `POST /generate-report-docx`.
async fn generate_docx(
    State(st): State<CaseReportState>,
    headers: http::HeaderMap,
    WithJson(auth, body): WithJson<Soc>,
) -> Result<Response, ApiError> {
    let (req, vars, template) = prepare(&st, &auth, &body).await?;
    let template_path = tempfile::named(".docx", &template).map_err(ApiError::internal)?;
    let path_text = template_path.to_string_lossy().into_owned();
    let rendered = tokio::task::spawn_blocking(move || {
        let env = Environment::new(Autoescape::On);
        copilot_docx::render(
            &template,
            &path_text,
            &env,
            &vars,
            copilot_docx::Clock::now(),
        )
    })
    .await
    .map_err(ApiError::internal);
    tempfile::remove(&template_path);
    let rendered = rendered?.map_err(docx_error)?;
    let out = tempfile::named(".docx", &rendered).map_err(ApiError::internal)?;
    let response =
        starlette::file_response(&out, DOCX_MEDIA_TYPE, req.file_name.as_deref(), &headers);
    tempfile::remove(&out);
    response
}

/// `POST /generate-report-pdf`.
async fn generate_pdf(
    State(st): State<CaseReportState>,
    headers: http::HeaderMap,
    WithJson(auth, body): WithJson<Soc>,
) -> Result<Response, ApiError> {
    let (req, vars, template) = prepare(&st, &auth, &body).await?;
    // `download_template_pdf`: the template in a temporary `.html`, read
    // back through a `FileSystemLoader` on its directory.
    let template_path = tempfile::named(".html", &template).map_err(ApiError::internal)?;
    let result = render_pdf(&template_path, &template, vars).await;
    tempfile::remove(&template_path);
    let pdf_path = result?;
    let response = match &req.file_name {
        None => Err(ApiError::internal(
            "AttributeError: 'NoneType' object has no attribute 'replace'",
        )),
        Some(name) => starlette::file_response(
            &pdf_path,
            "application/pdf",
            Some(&name.replace(".docx", ".pdf")),
            &headers,
        ),
    };
    tempfile::remove(&pdf_path);
    response
}

async fn render_pdf(
    template_path: &std::path::Path,
    template: &[u8],
    vars: Vec<(String, Data)>,
) -> Result<std::path::PathBuf, ApiError> {
    let dir = template_path
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = template_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // `open(filename, encoding="utf-8").read()`: a `UnicodeDecodeError` is
    // the `ValueError` handler's 400.
    let source = match std::str::from_utf8(template) {
        Ok(s) => s.to_string(),
        Err(_) => {
            return Err(ApiError::bad_request(
                copilot_docx::utf8_decode_error(template).unwrap_or_default(),
            ));
        }
    };
    let rendered = tokio::task::spawn_blocking(move || {
        Environment::new(Autoescape::SelectHtml)
            .with_directory(Directory {
                path: dir,
                files: vec![(name.clone(), source)],
            })
            .render(&name, &vars)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(jinja_error)?;
    let html_path = tempfile::named(".html", rendered.as_bytes()).map_err(ApiError::internal)?;
    let pdf = pdfkit::convert_html_to_pdf(&html_path, &[]).await;
    tempfile::remove(&html_path);
    pdf.map_err(|e| ApiError::internal(format!("RuntimeError: {e}")))
}
