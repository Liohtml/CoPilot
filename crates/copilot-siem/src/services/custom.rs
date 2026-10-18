//! `app/siem/services/custom_dashboards.py`: UI-authored templates (CRUD,
//! import with `overwrite`, export) and the preview of an unsaved panel set,
//! which runs through the same [`crate::panels::execute_panels`] as a saved
//! dashboard.
//!
//! Python answers every write from the row it re-reads after the flush
//! (`db.refresh`), so MySQL's rounding of `utcnow()` and its key order for
//! the JSON columns are what the caller sees; so here.

use copilot_auth::AccessScope;
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::py::{PyExc, PyResult};
use copilot_web::validate::{FieldError, LocPart, Validator};
use serde_json::{Map, Value};

use crate::SiemState;
use crate::panels::{PanelResults, execute_panels};
use crate::py::{db, dict, dt, from_json, http, int, model, s, to_json};
use crate::schema::{
    CUSTOM_DASHBOARD, Definition, ImportRequest, Panel, PreviewRequest, UpdateRequest, py_slice,
    slugify,
};
use crate::store::{self, CustomChange, CustomRow, CustomScope, NewCustom};

/// `CustomDashboardResponse.model_validate(row)`.
pub fn custom_dump(row: &CustomRow) -> PyResult<PyValue> {
    model(
        &CUSTOM_DASHBOARD,
        vec![
            ("id", int(i64::from(row.id))),
            ("template_key", s(&row.template_key)),
            (
                "customer_code",
                row.customer_code.as_deref().map_or(PyValue::None, s),
            ),
            ("title", s(&row.title)),
            ("description", s(&row.description)),
            ("vendor", s(&row.vendor)),
            ("product", s(&row.product)),
            ("event_type", s(&row.event_type)),
            (
                "tags",
                row.tags.as_ref().map_or(PyValue::None, |t| from_json(&t.0)),
            ),
            ("color", s(&row.color)),
            ("icon", s(&row.icon)),
            ("default_query", s(&row.default_query)),
            ("panels", from_json(&row.panels.0)),
            (
                "created_by",
                row.created_by.as_deref().map_or(PyValue::None, s),
            ),
            ("created_at", dt(row.created_at)),
            ("updated_at", dt(row.updated_at)),
        ],
    )
}

async fn verify_customer_exists(st: &SiemState, code: &str) -> PyResult<()> {
    if store::customer_exists(&st.ctx.db, code).await.map_err(db)? {
        Ok(())
    } else {
        Err(http(
            404,
            format!("Customer with customer_code {code} not found"),
        ))
    }
}

/// `get_custom_dashboard(template_key)`: 404 when unknown.
pub async fn get(st: &SiemState, key: &str) -> PyResult<CustomRow> {
    store::custom(&st.ctx.db, key)
        .await
        .map_err(db)?
        .ok_or_else(|| http(404, format!("Custom dashboard '{key}' not found")))
}

/// `list_custom_dashboards(customer_code, accessible_customers)`.
pub async fn list(
    st: &SiemState,
    customer_code: Option<&str>,
    access: &AccessScope,
) -> PyResult<Vec<CustomRow>> {
    let scope = match customer_code.filter(|c| !c.is_empty()) {
        Some(c) => CustomScope::Customer(c.to_string()),
        None => match access {
            AccessScope::All => CustomScope::All,
            AccessScope::Customers(codes) => CustomScope::Customers(codes.clone()),
        },
    };
    store::custom_list(&st.ctx.db, &scope).await.map_err(db)
}

/// `_unique_template_key(candidate)`: the candidate, else `_2`, `_3`, … .
async fn unique_key(st: &SiemState, candidate: &str) -> PyResult<String> {
    let mut key = candidate.to_string();
    let mut suffix = 2;
    while store::custom_key_taken(&st.ctx.db, &key)
        .await
        .map_err(db)?
    {
        key = format!("{candidate}_{suffix}");
        suffix += 1;
    }
    Ok(key)
}

/// `create_custom_dashboard(request, current_user, requested_key,
/// allow_key_suffix)`.
pub async fn create(
    st: &SiemState,
    req: &Definition,
    username: &str,
    requested_key: Option<&str>,
    allow_key_suffix: bool,
) -> PyResult<CustomRow> {
    if let Some(code) = req.customer_code.as_deref().filter(|c| !c.is_empty()) {
        verify_customer_exists(st, code).await?;
    }
    let source = requested_key
        .filter(|k| !k.is_empty())
        .or(req.template_key.as_deref().filter(|k| !k.is_empty()))
        .unwrap_or(&req.title);
    let candidate = py_slice(&slugify(source, "custom_dashboard"), 255);
    let key = if allow_key_suffix {
        unique_key(st, &candidate).await?
    } else {
        if store::custom_key_taken(&st.ctx.db, &candidate)
            .await
            .map_err(db)?
        {
            return Err(http(
                409,
                format!("A custom dashboard with key '{candidate}' already exists"),
            ));
        }
        candidate
    };
    let tags = Value::Array(req.tags.iter().cloned().map(Value::String).collect());
    let panels = to_json(&req.panels_value());
    let id = store::insert_custom(
        &st.ctx.db,
        &NewCustom {
            template_key: &key,
            customer_code: req.customer_code.as_deref(),
            title: &req.title,
            description: &req.description,
            vendor: &req.vendor,
            product: &req.product,
            event_type: &req.event_type,
            tags: &tags,
            color: &req.color,
            icon: &req.icon,
            default_query: &req.default_query,
            panels: &panels,
            created_by: Some(username),
            created_at: copilot_core::time::now_utc_micros(),
            updated_at: copilot_core::time::now_utc_micros(),
        },
    )
    .await
    .map_err(db)?;
    tracing::info!(
        "Created custom dashboard '{key}' (customer={})",
        req.customer_code.as_deref().unwrap_or("global")
    );
    reread(st, id).await
}

async fn reread(st: &SiemState, id: i64) -> PyResult<CustomRow> {
    store::custom_by_id(&st.ctx.db, id)
        .await
        .map_err(db)?
        .ok_or_else(|| PyExc::Other("InvalidRequestError", "row vanished".into()))
}

/// `update_custom_dashboard(template_key, request)`.
pub async fn update(st: &SiemState, key: &str, req: &UpdateRequest) -> PyResult<CustomRow> {
    let row = get(st, key).await?;
    let new_customer = req.customer_code.clone().flatten();
    if let Some(code) = new_customer.as_deref().filter(|c| !c.is_empty()) {
        verify_customer_exists(st, code).await?;
        // Narrowing a template to one customer would strand dashboards already
        // enabled for other tenants.
        if store::enabled_elsewhere(&st.ctx.db, key, code)
            .await
            .map_err(db)?
        {
            return Err(http(
                400,
                "This dashboard is enabled for other customers; disable those first to scope it \
                 to a single customer",
            ));
        }
    }
    let mut changes: Vec<CustomChange> = Vec::new();
    let text = |name: &'static str, v: &Option<Option<String>>, changes: &mut Vec<CustomChange>| {
        if let Some(Some(value)) = v {
            changes.push(CustomChange::Text(name, value.clone()));
        }
    };
    text("title", &req.title, &mut changes);
    text("description", &req.description, &mut changes);
    text("vendor", &req.vendor, &mut changes);
    text("product", &req.product, &mut changes);
    text("event_type", &req.event_type, &mut changes);
    if let Some(Some(tags)) = &req.tags {
        changes.push(CustomChange::Json(
            "tags",
            Value::Array(tags.iter().cloned().map(Value::String).collect()),
        ));
    }
    text("color", &req.color, &mut changes);
    text("icon", &req.icon, &mut changes);
    text("default_query", &req.default_query, &mut changes);
    if let Some(code) = &new_customer {
        changes.push(CustomChange::Customer(Some(code.clone())));
    }
    if matches!(req.share_globally, Some(Some(true))) {
        changes.push(CustomChange::Customer(None));
    }
    if let Some(Some(panels)) = &req.panels {
        let value = PyValue::List(panels.iter().map(Panel::dump).collect());
        changes.push(CustomChange::Json("panels", to_json(&value)));
    }
    store::update_custom(
        &st.ctx.db,
        i64::from(row.id),
        &changes,
        copilot_core::time::now_utc_micros(),
    )
    .await
    .map_err(db)?;
    tracing::info!("Updated custom dashboard '{key}'");
    get(st, key).await
}

/// `delete_custom_dashboard(template_key)`: the template and every
/// dashboard enabled from it (no foreign key cascades them); the count.
pub async fn delete(st: &SiemState, key: &str) -> PyResult<usize> {
    let row = get(st, key).await?;
    let n = store::enabled_from_custom(&st.ctx.db, key)
        .await
        .map_err(db)?;
    store::delete_custom(&st.ctx.db, i64::from(row.id), key, n > 0)
        .await
        .map_err(db)?;
    tracing::info!("Deleted custom dashboard '{key}' along with {n} enabled dashboard(s)");
    Ok(n)
}

/// The import's outcome before it touches the database: a new template or
/// an overwrite of an existing one.
#[derive(Debug, Clone)]
pub enum ImportPlan {
    /// No template has the key.
    Create(String),
    /// The template under the key (`overwrite` was asked).
    Overwrite(Box<CustomRow>),
}

/// `import_custom_dashboard`'s first half: the key and the existing row
/// (409 unless `overwrite`).
pub async fn import_plan(st: &SiemState, req: &ImportRequest) -> PyResult<ImportPlan> {
    let def = &req.definition;
    let source = def
        .template_key
        .as_deref()
        .filter(|k| !k.is_empty())
        .unwrap_or(&def.title);
    let requested = py_slice(&slugify(source, "custom_dashboard"), 255);
    match store::custom(&st.ctx.db, &requested).await.map_err(db)? {
        Some(_) if !req.overwrite => Err(http(
            409,
            format!(
                "A custom dashboard with key '{requested}' already exists. Re-import with \
                 overwrite to replace it."
            ),
        )),
        Some(row) => Ok(ImportPlan::Overwrite(Box::new(row))),
        None => Ok(ImportPlan::Create(requested)),
    }
}

/// `import_custom_dashboard`'s second half.
pub async fn import_apply(
    st: &SiemState,
    req: &ImportRequest,
    plan: ImportPlan,
    username: &str,
) -> PyResult<CustomRow> {
    let def = &req.definition;
    match plan {
        ImportPlan::Overwrite(row) => {
            let request = UpdateRequest {
                title: Some(Some(def.title.clone())),
                description: Some(Some(def.description.clone())),
                vendor: Some(Some(def.vendor.clone())),
                product: Some(Some(def.product.clone())),
                event_type: Some(Some(def.event_type.clone())),
                tags: Some(Some(def.tags.clone())),
                color: Some(Some(def.color.clone())),
                icon: Some(Some(def.icon.clone())),
                default_query: Some(Some(def.default_query.clone())),
                panels: Some(Some(def.panels.clone())),
                customer_code: Some(req.customer_code.clone()),
                share_globally: Some(Some(req.customer_code.is_none())),
            };
            update(st, &row.template_key, &request).await
        }
        ImportPlan::Create(key) => {
            let mut create_req = def.clone();
            create_req.customer_code = req.customer_code.clone();
            create(st, &create_req, username, Some(&key), false).await
        }
    }
}

/// `export_custom_dashboard(row)`: `CustomDashboardDefinition(...)` of the
/// stored values — re-validated, so panels get their defaults and repeated
/// ids their suffixes; a stored row the definition refuses is its
/// `ValidationError`.
pub fn export(row: &CustomRow) -> PyResult<PyValue> {
    let tags = match row.tags.as_ref().map(|t| &t.0) {
        Some(v) if crate::py::from_json(v).truthy() => v.clone(),
        _ => Value::Array(Vec::new()),
    };
    let panels = if from_json(&row.panels.0).truthy() {
        row.panels.0.clone()
    } else {
        Value::Array(Vec::new())
    };
    let mut input = Map::new();
    input.insert(
        "template_key".into(),
        Value::String(row.template_key.clone()),
    );
    input.insert("title".into(), Value::String(row.title.clone()));
    input.insert("description".into(), Value::String(row.description.clone()));
    input.insert("vendor".into(), Value::String(row.vendor.clone()));
    input.insert("product".into(), Value::String(row.product.clone()));
    input.insert("event_type".into(), Value::String(row.event_type.clone()));
    input.insert("tags".into(), tags);
    input.insert("color".into(), Value::String(row.color.clone()));
    input.insert("icon".into(), Value::String(row.icon.clone()));
    input.insert(
        "default_query".into(),
        Value::String(row.default_query.clone()),
    );
    input.insert("panels".into(), panels);
    let mut v = Validator::new();
    let def = Definition::read(&mut v, &input, &Vec::new(), false, true);
    if v.has_errors() {
        return Err(PyExc::Validation(validation_text(
            "CustomDashboardDefinition",
            v.errors(),
            &Value::Object(input),
        )));
    }
    let panels: Vec<PyValue> = def
        .panels
        .iter()
        .map(|p| {
            dict(vec![
                ("id", s(&p.id)),
                ("title", s(&p.title)),
                ("type", s(&p.kind)),
                ("w", int(p.w)),
                ("h", int(p.h)),
                ("lucene", s(&p.lucene)),
                ("field", p.field.as_deref().map_or(PyValue::None, s)),
                (
                    "fields",
                    p.fields
                        .as_ref()
                        .map_or(PyValue::None, |f| PyValue::List(f.iter().map(s).collect())),
                ),
                ("size", p.size.map_or(PyValue::None, int)),
            ])
        })
        .collect();
    Ok(dict(vec![
        (
            "template_key",
            def.template_key.as_deref().map_or(PyValue::None, s),
        ),
        ("title", s(&def.title)),
        ("description", s(&def.description)),
        ("vendor", s(&def.vendor)),
        ("product", s(&def.product)),
        ("event_type", s(&def.event_type)),
        ("tags", PyValue::List(def.tags.iter().map(s).collect())),
        ("color", s(&def.color)),
        ("icon", s(&def.icon)),
        ("default_query", s(&def.default_query)),
        ("panels", PyValue::List(panels)),
    ]))
}

/// `str(ValidationError)` for errors read off `input` (each line's
/// `input_value` is the value at its location; a missing field's is the
/// object it is missing from).
fn validation_text(title: &str, errors: &[FieldError], input: &Value) -> String {
    let n = errors.len();
    let mut out = format!(
        "{n} validation error{} for {title}",
        if n == 1 { "" } else { "s" }
    );
    for e in errors {
        let mut at = input;
        for part in &e.loc {
            let next = match (part, at) {
                (LocPart::Key(k), Value::Object(m)) => m.get(k),
                (LocPart::Index(i), Value::Array(a)) => a.get(*i),
                _ => None,
            };
            match next {
                Some(v) => at = v,
                None => break,
            }
        }
        let value = from_json(at);
        let loc: Vec<String> = e.loc.iter().map(ToString::to_string).collect();
        out.push('\n');
        if !loc.is_empty() {
            out.push_str(&loc.join("."));
            out.push('\n');
        }
        out.push_str(&format!(
            "  {} [type={}, input_value={}, input_type={}]\n    For further information visit \
             https://errors.pydantic.dev/{}/v/{}",
            e.msg,
            e.kind,
            copilot_upstream::model::input_value(&value),
            copilot_upstream::py::type_name(&value),
            copilot_upstream::model::PYDANTIC_VERSION,
            e.kind
        ));
    }
    out
}

/// What `preview_custom_dashboard` hands the route.
#[derive(Debug, Clone)]
pub struct Preview {
    /// The panel results.
    pub results: PanelResults,
    /// The template the builder renders.
    pub template: PyValue,
    /// The event source's customer.
    pub customer_code: String,
    /// The event source's name.
    pub source_name: String,
}

/// `preview_custom_dashboard(request)`: the event source (its customer is the
/// tenant checked, never the body), then the panels.
pub async fn preview(
    st: &SiemState,
    req: &PreviewRequest,
    access: &AccessScope,
) -> PyResult<Preview> {
    let Some(source) = store::event_source(&st.ctx.db, req.event_source_id)
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
    if !source.enabled {
        return Err(http(400, "Event source is disabled"));
    }
    let panels = PyValue::List(req.panels.iter().map(Panel::dump).collect());
    let results = execute_panels(
        st,
        &panels,
        &source.index_pattern,
        &source.time_field,
        &req.timerange,
        &req.default_query,
    )
    .await?;
    Ok(Preview {
        results,
        template: dict(vec![
            ("id", s("preview")),
            ("title", s("Preview")),
            ("description", s(format!("Preview against {}", source.name))),
            ("panels", panels),
        ]),
        customer_code: source.customer_code,
        source_name: source.name,
    })
}
