//! `app/siem/schema/{dashboards,custom_dashboards,event_sources,events}.py`:
//! the request bodies (read with Pydantic's lax rules and constraints, model
//! validators included) and the response models (validated like Pydantic
//! from what the services hand them, then dumped in field order).

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field as F, Model, Ty};
use copilot_web::form::py_strip;
use copilot_web::validate::{IntRules, Loc, LocPart, StrRules, Validator};
use serde_json::{Map, Value};

/// `CUSTOM_LIBRARY_CARD`: the reserved `library_card` of DB-backed templates.
pub const CUSTOM_LIBRARY_CARD: &str = "custom";

/// `CustomPanelType`.
pub const PANEL_TYPES: &[&str] = &["stat", "histogram", "pie", "bar_h", "table"];

/// `EventType`.
pub const EVENT_TYPES: &[&str] = &["EDR", "EPP", "Cloud Integration", "Network Security"];

fn child(at: &Loc, key: &str) -> Loc {
    let mut l = at.clone();
    l.push(LocPart::Key(key.into()));
    l
}

fn s(v: impl Into<String>) -> PyValue {
    PyValue::Str(v.into())
}

/// Python's `str[:n]` (code points).
pub fn py_slice(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

/// `slugify(value, fallback)`: lower-case, every non-alphanumeric character
/// an `_`, runs of `_` collapsed (Python's `str.strip`, `str.lower` and
/// `str.isalnum`).
pub fn slugify(value: &str, fallback: &str) -> String {
    let lowered = copilot_jinja::unicode::lower(py_strip(value));
    let mapped: String = lowered
        .chars()
        .map(|c| {
            if copilot_jinja::unicode::is_alnum(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    let slug = mapped
        .split('_')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    if slug.is_empty() {
        fallback.to_string()
    } else {
        slug
    }
}

// --- request bodies -------------------------------------------------------------------

/// `EnableDashboardRequest`.
#[derive(Debug, Clone, Default)]
pub struct EnableRequest {
    /// `customer_code`.
    pub customer_code: String,
    /// `event_source_id`.
    pub event_source_id: i64,
    /// `library_card`.
    pub library_card: String,
    /// `template_id`.
    pub template_id: String,
    /// `display_name`.
    pub display_name: String,
}

impl EnableRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            customer_code: v.req_str(obj, at, "customer_code", StrRules::max(50)),
            event_source_id: v.req_int(obj, at, "event_source_id", IntRules::default()),
            library_card: v.req_str(obj, at, "library_card", StrRules::max(255)),
            template_id: v.req_str(obj, at, "template_id", StrRules::max(255)),
            display_name: v.req_str(obj, at, "display_name", StrRules::max(255)),
        }
    }
}

/// `PanelDataRequest`.
#[derive(Debug, Clone, Default)]
pub struct PanelDataRequest {
    /// `dashboard_id`.
    pub dashboard_id: i64,
    /// `timerange`.
    pub timerange: String,
}

impl PanelDataRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            dashboard_id: v.req_int(obj, at, "dashboard_id", IntRules::default()),
            timerange: v.str_or(obj, at, "timerange", StrRules::any(), "24h"),
        }
    }
}

/// A validated `CustomDashboardPanel`, as `model_dump(mode="json",
/// exclude_none=True)` writes it.
#[derive(Debug, Clone, Default)]
pub struct Panel {
    /// `id` (filled from the title when omitted).
    pub id: String,
    /// `title`.
    pub title: String,
    /// `type`.
    pub kind: String,
    /// `w`.
    pub w: i64,
    /// `h`.
    pub h: i64,
    /// `lucene`.
    pub lucene: String,
    /// `field`.
    pub field: Option<String>,
    /// `fields`.
    pub fields: Option<Vec<String>>,
    /// `size`.
    pub size: Option<i64>,
}

impl Panel {
    /// `CustomDashboardPanel`: the fields, then (only when they are valid)
    /// the type requirements and the derived id. `python`: validated from a
    /// Python value (`model_type` for a non-dict) rather than a request body.
    pub fn read(v: &mut Validator, value: &Value, at: &Loc, python: bool) -> Option<Self> {
        let obj = if python {
            v.nested(value, at, "CustomDashboardPanel")
        } else {
            v.object(value, at)
        };
        let obj = obj?;
        let before = v.errors().len();
        let id = v.opt_str(obj, at, "id", StrRules::max(64));
        let title = v.req_str(obj, at, "title", StrRules::max(255).min(1));
        let kind = v.req_enum(obj, at, "type", PANEL_TYPES);
        let w = match obj.get("w") {
            None => 4,
            Some(x) => v
                .check_int(
                    &child(at, "w"),
                    x,
                    IntRules {
                        ge: Some(1),
                        le: Some(12),
                    },
                )
                .unwrap_or_default(),
        };
        let h = match obj.get("h") {
            None => 300,
            Some(x) => v
                .check_int(
                    &child(at, "h"),
                    x,
                    IntRules {
                        ge: Some(60),
                        le: Some(1200),
                    },
                )
                .unwrap_or_default(),
        };
        let lucene = v.str_or(obj, at, "lucene", StrRules::max(4096), "*");
        let lucene = match py_strip(&lucene) {
            "" => "*".to_string(),
            t => t.to_string(),
        };
        let field = v.opt_str(obj, at, "field", StrRules::max(255));
        let fields = match obj.get("fields") {
            None | Some(Value::Null) => None,
            Some(x) => Some(v.str_items(x, &child(at, "fields"))),
        };
        let size = match obj.get("size") {
            None => Some(10),
            Some(Value::Null) => None,
            Some(x) => v.check_int(
                &child(at, "size"),
                x,
                IntRules {
                    ge: Some(1),
                    le: Some(100),
                },
            ),
        };
        if v.errors().len() > before {
            return None;
        }
        let mut panel = Self {
            id: id.clone().unwrap_or_default(),
            title,
            kind,
            w,
            h,
            lucene,
            field,
            fields,
            size,
        };
        if (panel.kind == "pie" || panel.kind == "bar_h")
            && py_strip(panel.field.as_deref().unwrap_or("")).is_empty()
        {
            v.push(
                "value_error",
                at.clone(),
                format!(
                    "Value error, Panel '{}': a '{}' panel requires an aggregation field",
                    panel.title, panel.kind
                ),
            );
            return None;
        }
        if panel.kind == "table" {
            let cleaned: Vec<String> = panel
                .fields
                .clone()
                .unwrap_or_default()
                .iter()
                .filter(|f| !f.is_empty() && !py_strip(f).is_empty())
                .map(|f| py_strip(f).to_string())
                .collect();
            if cleaned.is_empty() {
                v.push(
                    "value_error",
                    at.clone(),
                    format!(
                        "Value error, Panel '{}': a 'table' panel requires at least one field to \
                         display",
                        panel.title
                    ),
                );
                return None;
            }
            panel.fields = Some(cleaned);
        }
        if id.as_deref().unwrap_or("").is_empty() {
            panel.id = py_slice(&slugify(&panel.title, "panel"), 64);
        }
        Some(panel)
    }

    /// `model_dump(mode="json", exclude_none=True)`.
    pub fn dump(&self) -> PyValue {
        let mut d = vec![
            ("id".to_string(), s(&self.id)),
            ("title".to_string(), s(&self.title)),
            ("type".to_string(), s(&self.kind)),
            ("w".to_string(), PyValue::Int(self.w.to_string())),
            ("h".to_string(), PyValue::Int(self.h.to_string())),
            ("lucene".to_string(), s(&self.lucene)),
        ];
        if let Some(f) = &self.field {
            d.push(("field".into(), s(f)));
        }
        if let Some(fs) = &self.fields {
            d.push(("fields".into(), PyValue::List(fs.iter().map(s).collect())));
        }
        if let Some(n) = self.size {
            d.push(("size".into(), PyValue::Int(n.to_string())));
        }
        PyValue::Dict(d)
    }
}

/// `panels: List[CustomDashboardPanel]` with `min_length=1`.
fn read_panels(v: &mut Validator, value: &Value, at: &Loc, python: bool) -> Option<Vec<Panel>> {
    let Value::Array(items) = value else {
        v.push("list_type", at.clone(), "Input should be a valid list");
        return None;
    };
    let mut out = Vec::new();
    let mut ok = true;
    for (i, item) in items.iter().enumerate() {
        let mut il = at.clone();
        il.push(LocPart::Index(i));
        match Panel::read(v, item, &il, python) {
            Some(p) => out.push(p),
            None => ok = false,
        }
    }
    if !ok {
        return None;
    }
    if out.is_empty() {
        v.push(
            "too_short",
            at.clone(),
            "List should have at least 1 item after validation, not 0",
        );
        return None;
    }
    Some(out)
}

/// `CustomDashboardDefinition` (and `CustomDashboardCreateRequest`, which
/// adds `customer_code`).
#[derive(Debug, Clone, Default)]
pub struct Definition {
    /// `template_key`.
    pub template_key: Option<String>,
    /// `title`.
    pub title: String,
    /// `description`.
    pub description: String,
    /// `vendor`.
    pub vendor: String,
    /// `product`.
    pub product: String,
    /// `event_type`.
    pub event_type: String,
    /// `tags`.
    pub tags: Vec<String>,
    /// `color`.
    pub color: String,
    /// `icon`.
    pub icon: String,
    /// `default_query`.
    pub default_query: String,
    /// `panels`.
    pub panels: Vec<Panel>,
    /// `customer_code` (the create request only).
    pub customer_code: Option<String>,
}

impl Definition {
    /// Read the fields; `with_customer` for `CustomDashboardCreateRequest`,
    /// `python` for a definition built from stored values (the export).
    pub fn read(
        v: &mut Validator,
        obj: &Map<String, Value>,
        at: &Loc,
        with_customer: bool,
        python: bool,
    ) -> Self {
        let before = v.errors().len();
        let template_key = v.opt_str(obj, at, "template_key", StrRules::max(255));
        let title = v.req_str(obj, at, "title", StrRules::max(255).min(1));
        let description = v.str_or(obj, at, "description", StrRules::max(2048), "");
        let vendor = v.str_or(obj, at, "vendor", StrRules::max(255), "Custom");
        let product = v.str_or(obj, at, "product", StrRules::max(255), "");
        let event_type = v.str_or(obj, at, "event_type", StrRules::max(50), "Custom");
        let tags = match obj.get("tags") {
            None => Vec::new(),
            Some(x) => v.str_items(x, &child(at, "tags")),
        };
        let color = v.str_or(obj, at, "color", StrRules::max(9), "#38bdf8");
        let icon = v.str_or(obj, at, "icon", StrRules::max(50), "dashboard");
        let default_query = v.str_or(obj, at, "default_query", StrRules::max(4096), "*");
        let default_query = match py_strip(&default_query) {
            "" => "*".to_string(),
            t => t.to_string(),
        };
        let panels = match obj.get("panels") {
            None => {
                v.missing(child(at, "panels"));
                None
            }
            Some(x) => read_panels(v, x, &child(at, "panels"), python),
        };
        let customer_code = if with_customer {
            v.opt_str(obj, at, "customer_code", StrRules::max(50))
        } else {
            None
        };
        let mut def = Self {
            template_key,
            title,
            description,
            vendor,
            product,
            event_type,
            tags,
            color,
            icon,
            default_query,
            panels: panels.unwrap_or_default(),
            customer_code,
        };
        if v.errors().len() == before {
            def.unique_panel_ids();
        }
        def
    }

    /// `_unique_panel_ids`: a repeated id gets `_2`, `_3`, … .
    pub fn unique_panel_ids(&mut self) {
        let mut seen: Vec<(String, usize)> = Vec::new();
        for panel in &mut self.panels {
            let base = if panel.id.is_empty() {
                "panel".to_string()
            } else {
                panel.id.clone()
            };
            match seen.iter_mut().find(|(k, _)| *k == base) {
                Some((_, n)) => {
                    *n += 1;
                    panel.id = format!("{base}_{n}");
                }
                None => seen.push((base, 1)),
            }
        }
    }

    /// The `panels` as stored (`_panels_as_dicts`).
    pub fn panels_value(&self) -> PyValue {
        PyValue::List(self.panels.iter().map(Panel::dump).collect())
    }
}

/// `CustomDashboardUpdateRequest`: each field `Some` only when the body sent
/// it (`exclude_unset`), its value `None` for an explicit `null`.
#[derive(Debug, Clone, Default)]
pub struct UpdateRequest {
    /// `title`.
    pub title: Option<Option<String>>,
    /// `description`.
    pub description: Option<Option<String>>,
    /// `vendor`.
    pub vendor: Option<Option<String>>,
    /// `product`.
    pub product: Option<Option<String>>,
    /// `event_type`.
    pub event_type: Option<Option<String>>,
    /// `tags`.
    pub tags: Option<Option<Vec<String>>>,
    /// `color`.
    pub color: Option<Option<String>>,
    /// `icon`.
    pub icon: Option<Option<String>>,
    /// `default_query`.
    pub default_query: Option<Option<String>>,
    /// `panels`.
    pub panels: Option<Option<Vec<Panel>>>,
    /// `customer_code`.
    pub customer_code: Option<Option<String>>,
    /// `share_globally`.
    pub share_globally: Option<Option<bool>>,
}

fn opt_field(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
    rules: StrRules,
) -> Option<Option<String>> {
    obj.get(name).map(|_| v.opt_str(obj, at, name, rules))
}

impl UpdateRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            title: opt_field(v, obj, at, "title", StrRules::max(255).min(1)),
            description: opt_field(v, obj, at, "description", StrRules::max(2048)),
            vendor: opt_field(v, obj, at, "vendor", StrRules::max(255)),
            product: opt_field(v, obj, at, "product", StrRules::max(255)),
            event_type: opt_field(v, obj, at, "event_type", StrRules::max(50)),
            tags: obj.get("tags").map(|x| match x {
                Value::Null => None,
                x => Some(v.str_items(x, &child(at, "tags"))),
            }),
            color: opt_field(v, obj, at, "color", StrRules::max(9)),
            icon: opt_field(v, obj, at, "icon", StrRules::max(50)),
            default_query: opt_field(v, obj, at, "default_query", StrRules::max(4096)),
            panels: obj.get("panels").map(|x| match x {
                Value::Null => None,
                x => read_panels(v, x, &child(at, "panels"), false),
            }),
            customer_code: opt_field(v, obj, at, "customer_code", StrRules::max(50)),
            share_globally: obj
                .get("share_globally")
                .map(|_| v.opt_bool(obj, at, "share_globally")),
        }
    }
}

/// `CustomDashboardImportRequest`.
#[derive(Debug, Clone, Default)]
pub struct ImportRequest {
    /// `definition`.
    pub definition: Definition,
    /// `customer_code`.
    pub customer_code: Option<String>,
    /// `overwrite`.
    pub overwrite: bool,
}

impl ImportRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let definition = match obj.get("definition") {
            None => {
                v.missing(child(at, "definition"));
                Definition::default()
            }
            Some(x) => {
                let dl = child(at, "definition");
                match v.object(x, &dl) {
                    Some(o) => Definition::read(v, o, &dl, false, false),
                    None => Definition::default(),
                }
            }
        };
        Self {
            definition,
            customer_code: v.opt_str(obj, at, "customer_code", StrRules::max(50)),
            overwrite: v.bool_or(obj, at, "overwrite", false),
        }
    }
}

/// `CustomDashboardPreviewRequest`.
#[derive(Debug, Clone, Default)]
pub struct PreviewRequest {
    /// `event_source_id`.
    pub event_source_id: i64,
    /// `default_query` (no validator: not normalized).
    pub default_query: String,
    /// `panels`.
    pub panels: Vec<Panel>,
    /// `timerange`.
    pub timerange: String,
}

impl PreviewRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let event_source_id = v.req_int(obj, at, "event_source_id", IntRules::default());
        let default_query = v.str_or(obj, at, "default_query", StrRules::max(4096), "*");
        let panels = match obj.get("panels") {
            None => {
                v.missing(child(at, "panels"));
                None
            }
            Some(x) => read_panels(v, x, &child(at, "panels"), false),
        };
        let timerange = v.str_or(obj, at, "timerange", StrRules::any(), "24h");
        Self {
            event_source_id,
            default_query,
            panels: panels.unwrap_or_default(),
            timerange,
        }
    }
}

/// `DisplayColumn`, dumped (`key`, `label`, `width`).
/// `Optional[List[DisplayColumn]]`, dumped as the service dumps it: every
/// field on create (`model_dump()`), only the ones sent on update
/// (`model_dump(exclude_unset=True)` reaches the nested models too).
fn read_display_columns(
    v: &mut Validator,
    value: &Value,
    at: &Loc,
    exclude_unset: bool,
) -> Option<PyValue> {
    let Value::Array(items) = value else {
        v.push("list_type", at.clone(), "Input should be a valid list");
        return None;
    };
    let mut out = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let mut il = at.clone();
        il.push(LocPart::Index(i));
        let Some(obj) = v.object(item, &il) else {
            continue;
        };
        let key = v.req_str(obj, &il, "key", StrRules::any());
        let label = v.req_str(obj, &il, "label", StrRules::any());
        let width = v.opt_int(obj, &il, "width", IntRules::default());
        let mut column = vec![("key".into(), s(key)), ("label".into(), s(label))];
        if !exclude_unset || obj.contains_key("width") {
            column.push((
                "width".into(),
                width.map_or(PyValue::None, |w| PyValue::Int(w.to_string())),
            ));
        }
        out.push(PyValue::Dict(column));
    }
    Some(PyValue::List(out))
}

/// `EventSourceCreate`.
#[derive(Debug, Clone, Default)]
pub struct EventSourceCreate {
    /// `customer_code`.
    pub customer_code: String,
    /// `name`.
    pub name: String,
    /// `index_pattern`.
    pub index_pattern: String,
    /// `event_type`.
    pub event_type: String,
    /// `time_field`.
    pub time_field: String,
    /// `enabled`.
    pub enabled: bool,
    /// `displayed_columns` (`None`: not sent or `null`).
    pub displayed_columns: Option<PyValue>,
}

impl EventSourceCreate {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            customer_code: v.req_str(obj, at, "customer_code", StrRules::max(50)),
            name: v.req_str(obj, at, "name", StrRules::max(255)),
            index_pattern: v.req_str(obj, at, "index_pattern", StrRules::max(1024)),
            event_type: v.req_enum(obj, at, "event_type", EVENT_TYPES),
            time_field: v.str_or(obj, at, "time_field", StrRules::max(255), "timestamp"),
            enabled: v.bool_or(obj, at, "enabled", true),
            displayed_columns: match obj.get("displayed_columns") {
                None | Some(Value::Null) => None,
                Some(x) => read_display_columns(v, x, &child(at, "displayed_columns"), false),
            },
        }
    }
}

/// `EventSourceUpdate`: the fields the body sent (`exclude_unset`).
#[derive(Debug, Clone, Default)]
pub struct EventSourceUpdate {
    /// `name`.
    pub name: Option<Option<String>>,
    /// `index_pattern`.
    pub index_pattern: Option<Option<String>>,
    /// `event_type`.
    pub event_type: Option<Option<String>>,
    /// `time_field`.
    pub time_field: Option<Option<String>>,
    /// `enabled`.
    pub enabled: Option<Option<bool>>,
    /// `displayed_columns`.
    pub displayed_columns: Option<Option<PyValue>>,
}

impl EventSourceUpdate {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            name: opt_field(v, obj, at, "name", StrRules::max(255)),
            index_pattern: opt_field(v, obj, at, "index_pattern", StrRules::max(1024)),
            event_type: obj
                .get("event_type")
                .map(|_| v.opt_enum(obj, at, "event_type", EVENT_TYPES)),
            time_field: opt_field(v, obj, at, "time_field", StrRules::max(255)),
            enabled: obj.get("enabled").map(|_| v.opt_bool(obj, at, "enabled")),
            displayed_columns: obj.get("displayed_columns").map(|x| match x {
                Value::Null => None,
                x => read_display_columns(v, x, &child(at, "displayed_columns"), true),
            }),
        }
    }
}

// --- response models ------------------------------------------------------------------

/// `DashboardPanel`.
pub static DASHBOARD_PANEL: Model = Model::new(
    "DashboardPanel",
    &[
        F::req("id", Ty::Str),
        F::req("title", Ty::Str),
        F::req("type", Ty::Str),
        F::req("w", Ty::Int),
        F::req("h", Ty::Int),
        F::req("lucene", Ty::Str),
        F::opt("field", Ty::Nullable(&Ty::Str)),
        F::opt("fields", Ty::Nullable(&Ty::List(&Ty::Str))),
        F::opt("size", Ty::Nullable(&Ty::Int)),
    ],
);

/// `DashboardTemplate`.
pub static DASHBOARD_TEMPLATE: Model = Model::new(
    "DashboardTemplate",
    &[
        F::req("id", Ty::Str),
        F::req("title", Ty::Str),
        F::req("description", Ty::Str),
        F::req("panels", Ty::List(&Ty::Model(&DASHBOARD_PANEL))),
    ],
);

/// `DashboardCategory`'s fields (with `templates` appended for
/// `DashboardCategoryWithTemplates`).
macro_rules! category_fields {
    ($($extra:expr),*) => {
        &[
            F::req("id", Ty::Str),
            F::req("title", Ty::Str),
            F::req("description", Ty::Str),
            F::req("vendor", Ty::Str),
            F::req("product", Ty::Str),
            F::req("event_type", Ty::Str),
            F::req("tags", Ty::List(&Ty::Str)),
            F::req("color", Ty::Str),
            F::req("icon", Ty::Str),
            $($extra),*
        ]
    };
}

/// `DashboardCategory`.
pub static DASHBOARD_CATEGORY: Model = Model::new("DashboardCategory", category_fields!());

/// `DashboardCategoryWithTemplates`.
pub static DASHBOARD_CATEGORY_WITH_TEMPLATES: Model = Model::new(
    "DashboardCategoryWithTemplates",
    category_fields!(F::req(
        "templates",
        Ty::List(&Ty::Model(&DASHBOARD_TEMPLATE))
    )),
);

/// `EnabledDashboardResponse`.
pub static ENABLED_DASHBOARD: Model = Model::new(
    "EnabledDashboardResponse",
    &[
        F::req("id", Ty::Int),
        F::req("customer_code", Ty::Str),
        F::req("event_source_id", Ty::Int),
        F::req("library_card", Ty::Str),
        F::req("template_id", Ty::Str),
        F::req("display_name", Ty::Str),
        F::req("created_at", Ty::DateTime),
    ],
);

/// `PanelResult`.
pub static PANEL_RESULT: Model = Model::new(
    "PanelResult",
    &[
        F::req("type", Ty::Str),
        F::opt("value", Ty::Nullable(&Ty::Int)),
        F::opt("labels", Ty::Nullable(&Ty::List(&Ty::Str))),
        F::opt("data", Ty::Nullable(&Ty::List(&Ty::Any))),
        F::opt("columns", Ty::Nullable(&Ty::List(&Ty::Str))),
        F::opt("rows", Ty::Nullable(&Ty::List(&Ty::Dict(&Ty::Any)))),
        F::opt("error", Ty::Nullable(&Ty::Str)),
    ],
);

/// `CustomDashboardResponse`.
pub static CUSTOM_DASHBOARD: Model = Model::new(
    "CustomDashboardResponse",
    &[
        F::req("id", Ty::Int),
        F::req("template_key", Ty::Str),
        F::opt("customer_code", Ty::Nullable(&Ty::Str)),
        F::req("title", Ty::Str),
        F::req("description", Ty::Str),
        F::req("vendor", Ty::Str),
        F::req("product", Ty::Str),
        F::req("event_type", Ty::Str),
        F::opt("tags", Ty::Nullable(&Ty::List(&Ty::Str))),
        F::req("color", Ty::Str),
        F::req("icon", Ty::Str),
        F::req("default_query", Ty::Str),
        F::req("panels", Ty::List(&Ty::Dict(&Ty::Any))),
        F::opt("created_by", Ty::Nullable(&Ty::Str)),
        F::req("created_at", Ty::DateTime),
        F::req("updated_at", Ty::DateTime),
    ],
);

/// `DisplayColumn`.
pub static DISPLAY_COLUMN: Model = Model::new(
    "DisplayColumn",
    &[
        F::req("key", Ty::Str),
        F::req("label", Ty::Str),
        F::opt("width", Ty::Nullable(&Ty::Int)),
    ],
);

/// `EventSourceResponse`.
pub static EVENT_SOURCE: Model = Model::new(
    "EventSourceResponse",
    &[
        F::req("id", Ty::Int),
        F::req("customer_code", Ty::Str),
        F::req("name", Ty::Str),
        F::req("index_pattern", Ty::Str),
        F::req("event_type", Ty::Str),
        F::req("time_field", Ty::Str),
        F::req("enabled", Ty::Bool),
        F::opt(
            "displayed_columns",
            Ty::Nullable(&Ty::List(&Ty::Model(&DISPLAY_COLUMN))),
        ),
        F::req("created_at", Ty::DateTime),
        F::req("updated_at", Ty::DateTime),
    ],
);

/// `FieldMapping`.
pub static FIELD_MAPPING: Model = Model::new(
    "FieldMapping",
    &[F::req("field", Ty::Str), F::req("type", Ty::Str)],
);

/// `EventsQueryResponse`.
pub static EVENTS_QUERY_RESPONSE: Model = Model::new(
    "EventsQueryResponse",
    &[
        F::req("events", Ty::List(&Ty::Dict(&Ty::Any))),
        F::req("total", Ty::Int),
        F::opt("scroll_id", Ty::Nullable(&Ty::Str)),
        F::req("page_size", Ty::Int),
        F::req("success", Ty::Bool),
        F::req("message", Ty::Str),
    ],
);

/// `EventDocumentResponse`.
pub static EVENT_DOCUMENT_RESPONSE: Model = Model::new(
    "EventDocumentResponse",
    &[
        F::req("event", Ty::Dict(&Ty::Any)),
        F::req("success", Ty::Bool),
        F::req("message", Ty::Str),
    ],
);

/// `PanelDataResponse`.
pub static PANEL_DATA_RESPONSE: Model = Model::new(
    "PanelDataResponse",
    &[
        F::req("panels", Ty::Dict(&Ty::Model(&PANEL_RESULT))),
        F::req("template", Ty::Model(&DASHBOARD_TEMPLATE)),
        F::req("dashboard_id", Ty::Int),
        F::req("customer_code", Ty::Str),
        F::req("source_name", Ty::Str),
        F::def("accent_color", Ty::Str, accent),
        F::req("success", Ty::Bool),
        F::req("message", Ty::Str),
    ],
);

/// `CustomDashboardPreviewResponse`.
pub static PREVIEW_RESPONSE: Model = Model::new(
    "CustomDashboardPreviewResponse",
    &[
        F::req("panels", Ty::Dict(&Ty::Model(&PANEL_RESULT))),
        F::req("template", Ty::Model(&DASHBOARD_TEMPLATE)),
        F::req("customer_code", Ty::Str),
        F::req("source_name", Ty::Str),
        F::req("success", Ty::Bool),
        F::req("message", Ty::Str),
    ],
);

fn accent() -> PyValue {
    s(DEFAULT_ACCENT)
}

/// `accent_color`'s default.
pub const DEFAULT_ACCENT: &str = "#38bdf8";
