//! `app/siem/services/dashboards.py`: the built-in template catalogue, the
//! enabled dashboards, and the panel data of one enabled dashboard (built-in
//! or custom template, both through [`crate::panels::execute_panels`]).

use copilot_auth::AccessScope;
use copilot_auth::pyvalue::{PyValue, loads};
use copilot_upstream::py::{PyExc, PyResult, get, type_name};

use crate::SiemState;
use crate::panels::{PanelResults, execute_panels};
use crate::py::{db, dict, dt, http, int, model, s};
use crate::schema::{
    CUSTOM_LIBRARY_CARD, DASHBOARD_CATEGORY, DASHBOARD_CATEGORY_WITH_TEMPLATES, DASHBOARD_TEMPLATE,
    DEFAULT_ACCENT, ENABLED_DASHBOARD, EnableRequest,
};
use crate::store::{self, EnabledRow};
use crate::templates::{self, CATEGORIES, Node};

/// `json.loads(path.read_text())` of a compiled-in file.
fn read_json(text: &str) -> PyResult<PyValue> {
    loads(text).map_err(|_| PyExc::JsonDecode("Expecting value: line 1 column 1 (char 0)".into()))
}

/// `Model(**data)`: a `TypeError` unless `data` is a dict.
fn star(m: &'static copilot_upstream::model::Model, data: &PyValue) -> PyResult<PyValue> {
    copilot_upstream::model::construct_star(m, m.name, data)
}

/// `list_categories()`: every category with a `_card.json` (`custom` is
/// reserved and never listed).
pub fn list_categories() -> PyResult<Vec<PyValue>> {
    let mut out = Vec::new();
    for c in CATEGORIES {
        if c.dir == CUSTOM_LIBRARY_CARD {
            continue;
        }
        if let Some(card) = templates::card_of(c) {
            out.push(star(&DASHBOARD_CATEGORY, &read_json(card)?)?);
        }
    }
    Ok(out)
}

/// `get_category_detail(category_id)`.
pub fn category_detail(category_id: &str) -> PyResult<PyValue> {
    let dir = templates::resolve(&[category_id]);
    let card = templates::resolve(&[category_id, "_card.json"]).and_then(Node::file);
    let (Some(Node::Dir(c)), Some(card)) = (dir, card) else {
        return Err(http(
            404,
            format!("Dashboard category '{category_id}' not found"),
        ));
    };
    let card = read_json(card)?;
    let mut list = Vec::new();
    for (_, text) in templates::templates_of(c) {
        list.push(star(&DASHBOARD_TEMPLATE, &read_json(text)?)?);
    }
    let PyValue::Dict(mut fields) = card else {
        return Err(PyExc::TypeError(format!(
            "app.siem.schema.dashboards.DashboardCategoryWithTemplates() argument after ** must \
             be a mapping, not {}",
            type_name(&card)
        )));
    };
    fields.push(("templates".into(), PyValue::List(list)));
    copilot_upstream::model::construct(&DASHBOARD_CATEGORY_WITH_TEMPLATES, &PyValue::Dict(fields))
}

/// `EnabledDashboardResponse.from_orm(row)`.
pub fn enabled_dump(row: &EnabledRow) -> PyResult<PyValue> {
    model(
        &ENABLED_DASHBOARD,
        vec![
            ("id", int(i64::from(row.id))),
            ("customer_code", s(&row.customer_code)),
            ("event_source_id", int(i64::from(row.event_source_id))),
            ("library_card", s(&row.library_card)),
            ("template_id", s(&row.template_id)),
            ("display_name", s(&row.display_name)),
            ("created_at", dt(row.created_at)),
        ],
    )
}

/// `verify_customer_exists(customer_code)` (the routes' helper).
pub async fn verify_customer_exists(st: &SiemState, code: &str) -> PyResult<()> {
    if store::customer_exists(&st.ctx.db, code).await.map_err(db)? {
        Ok(())
    } else {
        Err(http(
            404,
            format!("Customer with customer_code {code} not found"),
        ))
    }
}

/// `get_enabled_dashboards_for_customers(codes)`: `codes` is the caller's
/// resolved set in Python's form (`"*"` in it means every customer).
pub async fn enabled_for(st: &SiemState, codes: &[String]) -> PyResult<Vec<EnabledRow>> {
    let filter = if codes.iter().any(|c| c == "*") {
        None
    } else {
        Some(codes)
    };
    store::enabled_for(&st.ctx.db, filter).await.map_err(db)
}

/// `get_enabled_dashboards(customer_code)`.
pub async fn enabled_of(st: &SiemState, code: &str) -> PyResult<Vec<EnabledRow>> {
    store::enabled_of(&st.ctx.db, code).await.map_err(db)
}

/// `enable_dashboard(request)`: the template (custom row, or the files),
/// the event source, the duplicate check, then the row.
///
/// One check Python lacks (§4): the event source must belong to a customer
/// the caller may see — otherwise a scoped analyst could put another
/// tenant's index behind a dashboard of their own customer.
pub async fn enable(
    st: &SiemState,
    req: &EnableRequest,
    access: &AccessScope,
) -> PyResult<EnabledRow> {
    let dbh = &st.ctx.db;
    if req.library_card == CUSTOM_LIBRARY_CARD {
        let Some(custom) = store::custom(dbh, &req.template_id).await.map_err(db)? else {
            return Err(http(
                404,
                format!("Custom dashboard '{}' not found", req.template_id),
            ));
        };
        if let Some(owner) = custom.customer_code.as_deref().filter(|c| !c.is_empty()) {
            if owner != req.customer_code {
                return Err(http(
                    403,
                    format!(
                        "Custom dashboard '{}' is scoped to customer {owner}",
                        req.template_id
                    ),
                ));
            }
        }
    } else {
        let template = format!("{}.json", req.template_id);
        let card = templates::resolve(&[&req.library_card, "_card.json"]).and_then(Node::file);
        if card.is_none() {
            return Err(http(
                404,
                format!("Dashboard category '{}' not found", req.library_card),
            ));
        }
        if templates::resolve(&[&req.library_card, &template])
            .and_then(Node::file)
            .is_none()
        {
            return Err(http(
                404,
                format!(
                    "Dashboard template '{}' not found in category '{}'",
                    req.template_id, req.library_card
                ),
            ));
        }
    }
    let Some(source) = store::event_source(dbh, req.event_source_id)
        .await
        .map_err(db)?
    else {
        return Err(http(
            404,
            format!("Event source {} not found", req.event_source_id),
        ));
    };
    if !access.can_access(&source.customer_code) {
        return Err(http(
            403,
            format!("Access denied to customer {}", source.customer_code),
        ));
    }
    if store::enabled_exists(
        dbh,
        &req.customer_code,
        req.event_source_id,
        &req.library_card,
        &req.template_id,
    )
    .await
    .map_err(db)?
    {
        return Err(http(
            400,
            "This dashboard is already enabled for this customer and event source",
        ));
    }
    let id = store::insert_enabled(
        dbh,
        &req.customer_code,
        req.event_source_id,
        &req.library_card,
        &req.template_id,
        &req.display_name,
        copilot_core::time::now_utc_micros(),
    )
    .await
    .map_err(db)?;
    store::enabled(dbh, id)
        .await
        .map_err(db)?
        .ok_or_else(|| PyExc::Other("InvalidRequestError", "row vanished".into()))
}

/// `get_enabled_dashboard_customer_code(dashboard_id)`: 404 when unknown.
pub async fn enabled_owner(st: &SiemState, id: i64) -> PyResult<String> {
    match store::enabled(&st.ctx.db, id).await.map_err(db)? {
        Some(row) => Ok(row.customer_code),
        None => Err(http(404, "Enabled dashboard not found")),
    }
}

/// `disable_dashboard(dashboard_id)`.
pub async fn disable(st: &SiemState, id: i64) -> PyResult<()> {
    if store::enabled(&st.ctx.db, id).await.map_err(db)?.is_none() {
        return Err(http(404, "Enabled dashboard not found"));
    }
    store::delete_enabled(&st.ctx.db, id).await.map_err(db)?;
    tracing::info!("Disabled dashboard {id}");
    Ok(())
}

/// What `get_panel_data` hands the route.
#[derive(Debug, Clone)]
pub struct PanelData {
    /// The panel results.
    pub results: PanelResults,
    /// The template (a dict the response model validates).
    pub template: PyValue,
    /// `accent_color`.
    pub accent_color: PyValue,
    /// `customer_code`.
    pub customer_code: String,
    /// `source_name`.
    pub source_name: String,
}

/// `get_panel_data(dashboard_id, timerange)`: the dashboard, the tenant
/// check (before any indexer query), the event source, the template, then
/// every panel.
pub async fn panel_data(
    st: &SiemState,
    dashboard_id: i64,
    timerange: &str,
    access: &AccessScope,
) -> PyResult<PanelData> {
    let dbh = &st.ctx.db;
    let Some(dashboard) = store::enabled(dbh, dashboard_id).await.map_err(db)? else {
        return Err(http(404, "Enabled dashboard not found"));
    };
    if !access.can_access(&dashboard.customer_code) {
        return Err(http(
            403,
            format!("Access denied to customer {}", dashboard.customer_code),
        ));
    }
    let Some(source) = store::event_source(dbh, i64::from(dashboard.event_source_id))
        .await
        .map_err(db)?
    else {
        return Err(http(404, "Event source not found"));
    };
    if !source.enabled {
        return Err(http(400, "Event source is disabled"));
    }
    let mut accent = s(DEFAULT_ACCENT);
    let mut base_query = "*".to_string();
    let template = if dashboard.library_card == CUSTOM_LIBRARY_CARD {
        let Some(custom) = store::custom(dbh, &dashboard.template_id)
            .await
            .map_err(db)?
        else {
            return Err(http(404, "Custom dashboard template not found"));
        };
        let panels = crate::py::from_json(&custom.panels.0);
        let panels = if panels.truthy() {
            panels
        } else {
            PyValue::List(Vec::new())
        };
        if !custom.color.is_empty() {
            accent = s(&custom.color);
        }
        if !custom.default_query.is_empty() {
            base_query = custom.default_query.clone();
        }
        dict(vec![
            ("id", s(&custom.template_key)),
            ("title", s(&custom.title)),
            ("description", s(&custom.description)),
            ("panels", panels),
        ])
    } else {
        let file = format!("{}.json", dashboard.template_id);
        let Some(text) = templates::resolve(&[&dashboard.library_card, &file]).and_then(Node::file)
        else {
            return Err(http(404, "Dashboard template file not found"));
        };
        let template = read_json(text)?;
        if let Some(card) =
            templates::resolve(&[&dashboard.library_card, "_card.json"]).and_then(Node::file)
        {
            let card = read_json(card)?;
            if let Some(color) = get(&card, "color")? {
                accent = color.clone();
            }
        }
        template
    };
    let panels = match get(&template, "panels")? {
        Some(p) => p.clone(),
        None => PyValue::List(Vec::new()),
    };
    let results = execute_panels(
        st,
        &panels,
        &source.index_pattern,
        &source.time_field,
        timerange,
        &base_query,
    )
    .await?;
    Ok(PanelData {
        results,
        template,
        accent_color: accent,
        customer_code: dashboard.customer_code,
        source_name: source.name,
    })
}

/// A panel-data or preview response (`PanelDataResponse(panels=results,
/// …)`): `panels` is its first field, so the key errors of the panel ids
/// that are not `str` come before every other error.
pub fn respond(
    m: &'static copilot_upstream::model::Model,
    results: &PanelResults,
    rest: Vec<(&str, PyValue)>,
) -> PyResult<PyValue> {
    let (panels, key_errors) = crate::py::str_keys(
        &[copilot_upstream::model::Loc::Key("panels".into())],
        results,
    );
    let mut pairs = vec![("panels", panels)];
    pairs.extend(rest);
    crate::py::model_with_key_errors(m, pairs, key_errors, Vec::new())
}
