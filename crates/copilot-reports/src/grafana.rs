//! `POST /api/reporting/generate-report` (`app/connectors/grafana/routes/
//! reporting.py` and `services/reporting.py`): the Grafana panel report.
//!
//! In Python's order: the body (`GenerateReportRequest`), the licence
//! (`is_feature_enabled("REPORTING")`), then `generate_report` — every
//! panel's `row_id`, `parse_timerange` (`int(timerange[:-1])`: its
//! `ValueError` is the 400), per panel the iframe URL
//! (`GrafanaGenerateIframeLinksRequest`, whose unit check is the 400, the
//! `Grafana` connector's URL — `None`'s `AttributeError` the bare 500 —,
//! `datetime.now()` and `time.mktime`), then a headless Chromium
//! ([`crate::chromium`], driven as Playwright drives it): Grafana's login
//! page, the user and password filled, the login button clicked, network
//! idle — any failure there is the 500 `Failed to login to Grafana` —,
//! `document.body.className` (no `app-grafana` in it: the same 500; the
//! evaluation failing: the bare 500), each panel's `d-solo` page (opened
//! when its URL differs from the previous panel's), the viewport set to
//! the panel's size and a PNG screenshot (any failure leaves the panel
//! `None`, rendered as `None`), the browser closed; the HTML
//! (`report-template.html`, compiled in from the backend's tree, Jinja2
//! without autoescape, panels grouped by row id), a second browser printing
//! it to PDF (`emulate_media(media="screen")`, Letter), and the PDF in
//! base64.
//!
//! Python writes `report.html` and `report.pdf` into its working directory
//! (two reports at once overwrite each other's files, and a failure leaves
//! them behind); here the page goes into a fresh directory of the temporary
//! directory (`copilot-grafana-report-XXXXXX`), removed afterwards, and the
//! PDF is read from the browser's stream (§4). Not tenant-scoped, as in
//! Python: the body names Grafana dashboards, not a customer.

use std::path::Path;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::routing::post;
use base64::Engine as _;
use chrono::Local;
use copilot_auth::pyvalue::PyValue;
use copilot_grafana::schema::{
    GENERATE_REPORT_REQUEST, GENERATE_REPORT_RESPONSE, GRAFANA_GENERATE_IFRAME_LINKS_REQUEST,
};
use copilot_jinja::{Autoescape, Data, Directory, Environment};
use copilot_upstream::model::{construct, kwargs};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_upstream::respond::{body_model, model_response};
use copilot_web::{AdminOrAnalyst, ApiResult, AppContext, Authorized, WithJson};

use crate::chromium::{self, Browser, Page};

/// `reporting/report-template.html`.
const REPORT_TEMPLATE: &str =
    include_str!("../../../backend/app/connectors/grafana/reporting/report-template.html");

/// The connector row the report reads.
const CONNECTOR: &str = "Grafana";

/// The selectors `login_to_page` fills and clicks.
const USER_INPUT: &str = "input[name=\"user\"]";
const PASSWORD_INPUT: &str = "input[name=\"password\"]";
const LOGIN_BUTTON: &str = "button[data-testid=\"data-testid Login button\"]";

/// How long a closing browser may take before it is killed.
const CLOSE_GRACE: Duration = Duration::from_secs(10);

/// Route state.
#[derive(Clone)]
pub struct GrafanaReportState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The licence server.
    pub license: copilot_license::LicenseClient,
}

impl axum::extract::FromRef<GrafanaReportState> for AppContext {
    fn from_ref(s: &GrafanaReportState) -> AppContext {
        s.ctx.clone()
    }
}

impl std::fmt::Debug for GrafanaReportState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrafanaReportState").finish_non_exhaustive()
    }
}

/// The route, at its full path.
pub fn router(state: GrafanaReportState) -> Router {
    Router::new()
        .route("/api/reporting/generate-report", post(create_report))
        .with_state(state)
}

async fn create_report(
    State(st): State<GrafanaReportState>,
    WithJson(_, body): WithJson<Authorized<AdminOrAnalyst>>,
) -> ApiResult {
    tracing::info!("Generating report");
    let request = body_model(&body, &GENERATE_REPORT_REQUEST)?;
    copilot_license::is_feature_enabled(&st.ctx.db, &st.license, "REPORTING")
        .await
        .map_err(PyExc::unhandled)?;
    let answer = generate_report(&st.ctx, &request)
        .await
        .map_err(PyExc::unhandled)?;
    Ok(model_response(&answer))
}

fn get<'a>(v: &'a PyValue, key: &str) -> &'a PyValue {
    static NONE: PyValue = PyValue::None;
    v.get(key).unwrap_or(&NONE)
}

fn list(v: &PyValue) -> &[PyValue] {
    match v {
        PyValue::List(items) => items,
        _ => &[],
    }
}

/// A panel of the request, with what `generate_report` sets on it.
#[derive(Debug, Clone)]
struct Panel {
    fields: PyValue,
    row_id: PyValue,
    url: String,
    base64: Option<String>,
}

/// `parse_timerange(timerange)`: `int(timerange[:-1])` and the last
/// character.
pub fn parse_timerange(timerange: &str) -> PyResult<(String, String)> {
    let chars: Vec<char> = timerange.chars().collect();
    let head: String = chars[..chars.len().saturating_sub(1)].iter().collect();
    let value =
        copilot_yaml::pyint::parse_int(&head, 10).map_err(|e| PyExc::ValueError(e.message))?;
    // `timerange[-1]`: unreachable for "" (`int("")` failed first).
    let unit = chars
        .last()
        .map(char::to_string)
        .ok_or_else(|| PyExc::IndexError("string index out of range".into()))?;
    Ok((value.to_string(), unit))
}

async fn grafana_row(ctx: &AppContext) -> PyResult<copilot_db::connectors::ConnectorRow> {
    copilot_db::connectors::find_by_name(&ctx.db, CONNECTOR)
        .await
        .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?
        .ok_or_else(|| {
            PyExc::AttributeError("'NoneType' object has no attribute 'connector_url'".into())
        })
}

/// `generate_panel_urls_object(panel, timerange, session)`.
async fn panel_url(ctx: &AppContext, panel: &PyValue, value: &str, unit: &str) -> PyResult<String> {
    let request = construct(
        &GRAFANA_GENERATE_IFRAME_LINKS_REQUEST,
        &kwargs(vec![
            (
                "time_range",
                kwargs(vec![
                    ("value", PyValue::Int(value.to_string())),
                    ("unit", PyValue::Str(unit.to_string())),
                ]),
            ),
            ("dashboard_uid", get(panel, "dashboard_uid").clone()),
            ("dashboard_title", get(panel, "dashboard_title").clone()),
            ("org_id", get(panel, "org_id").clone()),
            ("panel_id", get(panel, "panel_id").clone()),
            ("theme", get(panel, "theme").clone()),
        ]),
    )?;
    let url = grafana_row(ctx).await?.connector_url;
    let range = get(&request, "time_range");
    let (from, to) = copilot_grafana::services::unix_timestamps(
        &get(range, "value").py_str(),
        &get(range, "unit").py_str(),
        Local::now().naive_local(),
    )?;
    Ok(format!(
        "{url}/d-solo/{}/{}?orgId={}&from={from}&to={to}&panelId={}&theme={}",
        get(&request, "dashboard_uid").py_str(),
        get(&request, "dashboard_title").py_str(),
        get(&request, "org_id").py_str(),
        get(&request, "panel_id").py_str(),
        get(&request, "theme").py_str(),
    ))
}

fn browser_error(e: chromium::Error) -> PyExc {
    PyExc::Other("Error", e.to_string())
}

fn executable() -> PyResult<std::path::PathBuf> {
    chromium::find_executable().ok_or_else(|| {
        PyExc::Other(
            "Error",
            "BrowserType.launch: Executable doesn't exist (no Chromium headless shell found)"
                .into(),
        )
    })
}

/// `login_to_page(page, session)`.
async fn login(ctx: &AppContext, page: &Page) -> Result<(), String> {
    let url = grafana_row(ctx).await.map_err(|e| e.text())?.connector_url;
    page.goto(&format!("{url}/login"))
        .await
        .map_err(|e| e.to_string())?;
    let user = grafana_row(ctx)
        .await
        .map_err(|e| e.text())?
        .connector_username;
    page.fill(USER_INPUT, user.as_deref().unwrap_or("None"))
        .await
        .map_err(|e| e.to_string())?;
    let password = grafana_row(ctx)
        .await
        .map_err(|e| e.text())?
        .connector_password;
    page.fill(PASSWORD_INPUT, password.as_deref().unwrap_or("None"))
        .await
        .map_err(|e| e.to_string())?;
    page.click(LOGIN_BUTTON).await.map_err(|e| e.to_string())?;
    page.wait_for_networkidle().await.map_err(|e| e.to_string())
}

fn int_of(v: &PyValue) -> Option<i64> {
    v.to_int().and_then(|n| i64::try_from(n).ok())
}

/// `capture_screenshots(page, panels)`.
async fn capture(page: &Page, panels: &mut [Panel]) {
    tracing::info!("Capturing screenshots");
    let mut last_url = String::new();
    for panel in panels.iter_mut() {
        let outcome: Result<Vec<u8>, String> = async {
            if panel.url != last_url {
                page.goto(&panel.url).await.map_err(|e| e.to_string())?;
                page.wait_for_networkidle()
                    .await
                    .map_err(|e| e.to_string())?;
                last_url = panel.url.clone();
            }
            let (Some(width), Some(height)) = (
                int_of(get(&panel.fields, "panel_width")),
                int_of(get(&panel.fields, "panel_height")),
            ) else {
                return Err("width and height out of range".into());
            };
            page.set_viewport_size(width, height)
                .await
                .map_err(|e| e.to_string())?;
            page.screenshot_png().await.map_err(|e| e.to_string())
        }
        .await;
        match outcome {
            Ok(png) => {
                panel.base64 = Some(base64::engine::general_purpose::STANDARD.encode(png));
            }
            Err(e) => {
                tracing::info!(
                    "Failed to capture screenshot for panel {}: {e}",
                    get(&panel.fields, "panel_id").py_str()
                );
                panel.base64 = None;
            }
        }
    }
}

fn data(v: &PyValue) -> Data {
    match v {
        PyValue::None => Data::None,
        PyValue::Bool(b) => Data::Bool(*b),
        PyValue::Int(t) => t.parse().map_or_else(|_| Data::Str(t.clone()), Data::Int),
        PyValue::Float(f) => Data::Float(*f),
        PyValue::Str(s) => Data::Str(s.clone()),
        PyValue::List(items) => Data::List(items.iter().map(data).collect()),
        PyValue::Dict(pairs) => {
            Data::Dict(pairs.iter().map(|(k, v)| (k.clone(), data(v))).collect())
        }
    }
}

/// `generate_html(panels, request)`: the panels grouped by row id, in
/// first-seen order, and the report template.
fn render_html(panels: &[Panel], request: &PyValue) -> PyResult<String> {
    let mut groups: Vec<(String, Vec<Data>)> = Vec::new();
    for panel in panels {
        let mut fields = match data(&panel.fields) {
            Data::Dict(pairs) => pairs,
            _ => Vec::new(),
        };
        let mut set = |key: &str, value: Data| {
            if let Some(slot) = fields.iter_mut().find(|(k, _)| k == key) {
                slot.1 = value;
            } else {
                fields.push((key.to_string(), value));
            }
        };
        set("panel_url", Data::Str(panel.url.clone()));
        set(
            "panel_base64",
            panel.base64.clone().map_or(Data::None, Data::Str),
        );
        set("row_id", data(&panel.row_id));
        let key = panel.row_id.py_str();
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, g)) => g.push(Data::Dict(fields)),
            None => groups.push((key, vec![Data::Dict(fields)])),
        }
    }
    tracing::info!("Rendering HTML with panels: {} panels", panels.len());
    let env = Environment::new(Autoescape::Off).with_directory(Directory {
        path: "/opt/copilot/backend/app/connectors/grafana/services/../reporting".into(),
        files: vec![("report-template.html".into(), REPORT_TEMPLATE.into())],
    });
    let vars = vec![
        (
            "panel_groups".to_string(),
            Data::List(groups.into_iter().map(|(_, g)| Data::List(g)).collect()),
        ),
        (
            "company_name".to_string(),
            data(get(request, "company_name")),
        ),
        (
            "timerange_text".to_string(),
            data(get(request, "timerange_text")),
        ),
        ("logo_base64".to_string(), data(get(request, "logo_base64"))),
    ];
    env.render("report-template.html", &vars)
        .map_err(|e| PyExc::Other("TemplateError", e.message))
}

/// `generate_pdf_from_html`: a second browser, the page loaded from its
/// file with screen media, printed.
async fn pdf_from_html(path: &Path) -> Result<Vec<u8>, chromium::Error> {
    let exe = chromium::find_executable()
        .ok_or_else(|| chromium::Error::Launch("Executable doesn't exist".into()))?;
    let browser = Browser::launch(&exe).await?;
    let page = browser.new_page(false).await?;
    page.emulate_media_screen().await?;
    page.goto(&format!("file://{}", path.display())).await?;
    let pdf = page.pdf().await?;
    browser.close(CLOSE_GRACE).await;
    Ok(pdf)
}

/// `generate_report(request, session)`.
pub async fn generate_report(ctx: &AppContext, request: &PyValue) -> PyResult<PyValue> {
    tracing::info!("Generating report");
    let mut panels = Vec::new();
    for row in list(get(request, "rows")) {
        for panel in list(get(row, "panels")) {
            panels.push(Panel {
                fields: panel.clone(),
                row_id: get(row, "id").clone(),
                url: String::new(),
                base64: None,
            });
        }
    }
    let timerange = get(request, "timerange").as_str().unwrap_or_default();
    let (value, unit) = parse_timerange(timerange)?;
    for panel in &mut panels {
        panel.url = panel_url(ctx, &panel.fields, &value, &unit).await?;
        tracing::info!("Panel URLs: {}", panel.url);
    }

    let exe = executable()?;
    let browser = Browser::launch(&exe).await.map_err(browser_error)?;
    let page = browser.new_page(true).await.map_err(browser_error)?;
    if let Err(e) = login(ctx, &page).await {
        tracing::error!("Failed to login to Grafana: {e}");
        return Err(PyExc::http(500, "Failed to login to Grafana"));
    }
    let class = page
        .evaluate("document.body.className")
        .await
        .map_err(browser_error)?;
    let class = match &class {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    tracing::info!("Body class: {class}");
    if !class.contains("app-grafana") {
        return Err(PyExc::http(500, "Failed to login to Grafana"));
    }
    tracing::info!("Login to Grafana successful");
    capture(&page, &mut panels).await;
    drop(page);
    browser.close(CLOSE_GRACE).await;

    let html = render_html(&panels, request)?;
    let dir = chromium::launch::mkdtemp(&crate::tempfile::temp_dir(), "copilot-grafana-report-")
        .map_err(|e| PyExc::Other("OSError", e.to_string()))?;
    let path = dir.join("report.html");
    let pdf = async {
        std::fs::write(&path, html.as_bytes())
            .map_err(|e| PyExc::Other("OSError", e.to_string()))?;
        pdf_from_html(&path).await.map_err(browser_error)
    }
    .await;
    let _ = std::fs::remove_dir_all(&dir);
    let pdf = pdf?;
    construct(
        &GENERATE_REPORT_RESPONSE,
        &kwargs(vec![
            (
                "base64_result",
                PyValue::Str(base64::engine::general_purpose::STANDARD.encode(pdf)),
            ),
            (
                "message",
                PyValue::Str("Report generated successfully".into()),
            ),
            ("success", PyValue::Bool(true)),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeranges_as_python_reads_them() {
        assert_eq!(
            parse_timerange("7d").unwrap(),
            ("7".to_string(), "d".to_string())
        );
        assert_eq!(
            parse_timerange(" +1_0h").unwrap(),
            ("10".to_string(), "h".to_string())
        );
        assert_eq!(
            parse_timerange("\u{0663}m").unwrap(),
            ("3".to_string(), "m".to_string())
        );
        assert_eq!(
            parse_timerange("").unwrap_err(),
            PyExc::ValueError("invalid literal for int() with base 10: ''".into())
        );
        assert_eq!(
            parse_timerange("d").unwrap_err(),
            PyExc::ValueError("invalid literal for int() with base 10: ''".into())
        );
        assert_eq!(
            parse_timerange("1.5d").unwrap_err(),
            PyExc::ValueError("invalid literal for int() with base 10: '1.5'".into())
        );
    }

    #[test]
    fn the_report_groups_panels_by_row() {
        let panel = |id: i64, b64: Option<&str>| Panel {
            fields: kwargs(vec![("panel_id", PyValue::Int(id.to_string()))]),
            row_id: PyValue::Int(if id < 3 { "1".into() } else { "2".into() }),
            url: "http://g".into(),
            base64: b64.map(str::to_string),
        };
        let request = kwargs(vec![
            ("company_name", PyValue::Str("ACME <b>".into())),
            ("timerange_text", PyValue::Str("Last 7 days".into())),
            (
                "logo_base64",
                PyValue::Str("data:image/png;base64,AA".into()),
            ),
        ]);
        let html = render_html(
            &[
                panel(1, Some("QQ==")),
                panel(3, None),
                panel(2, Some("Qg==")),
            ],
            &request,
        )
        .unwrap();
        assert!(html.contains("<div class=\"cover-company\">ACME <b></div>"));
        assert_eq!(html.matches("class=\"screenshot-row\"").count(), 2);
        let first = html.find("base64,QQ==").unwrap();
        let second = html.find("base64,Qg==").unwrap();
        let none = html.find("base64,None").unwrap();
        assert!(first < second && second < none);
        assert!(html.ends_with("</html>"));
    }
}
