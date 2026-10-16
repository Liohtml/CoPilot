//! The Pydantic models of `app/connectors/grafana/schema/` (`reporting.py`,
//! `user.py`) as [`copilot_upstream::model`] statics, pinned by
//! `model_vectors.json`.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Check, Field, Model, Ty};

fn empty_list() -> PyValue {
    PyValue::List(Vec::new())
}

fn viewer() -> PyValue {
    PyValue::Str("Viewer".into())
}

const DICT: Ty = Ty::Dict(&Ty::Any);

/// `GrafanaOrganizations`.
pub static GRAFANA_ORGANIZATIONS: Model = Model::new(
    "GrafanaOrganizations",
    &[Field::req("id", Ty::Int), Field::req("name", Ty::Str)],
);

/// `GrafanaOrganizationsResponse`.
pub static GRAFANA_ORGANIZATIONS_RESPONSE: Model = Model::new(
    "GrafanaOrganizationsResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("orgs", Ty::List(&Ty::Model(&GRAFANA_ORGANIZATIONS))),
        Field::req("success", Ty::Bool),
    ],
);

/// `GrafanaOrganizationDashboards` (one `/api/search` hit).
pub static GRAFANA_ORGANIZATION_DASHBOARDS: Model = Model::new(
    "GrafanaOrganizationDashboards",
    &[
        Field::req("id", Ty::Int),
        Field::req("uid", Ty::Str),
        Field::req("title", Ty::Str),
        Field::req("uri", Ty::Str),
        Field::req("url", Ty::Str),
        Field::req("slug", Ty::Str),
        Field::req("type", Ty::Str),
        Field::req("tags", Ty::List(&Ty::Str)),
        Field::req("isStarred", Ty::Bool),
        Field::req("sortMeta", Ty::Int),
        Field::opt("folderId", Ty::Nullable(&Ty::Int)),
        Field::opt("folderUid", Ty::Nullable(&Ty::Str)),
        Field::opt("folderTitle", Ty::Nullable(&Ty::Str)),
        Field::opt("folderUrl", Ty::Nullable(&Ty::Str)),
    ],
);

/// `GrafanaDashboardResponse` (`reporting.py`'s).
pub static GRAFANA_DASHBOARD_RESPONSE: Model = Model::new(
    "GrafanaDashboardResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req(
            "dashboards",
            Ty::List(&Ty::Model(&GRAFANA_ORGANIZATION_DASHBOARDS)),
        ),
        Field::req("success", Ty::Bool),
    ],
);

/// `FieldConfigDefaults`.
pub static FIELD_CONFIG_DEFAULTS: Model = Model::new(
    "FieldConfigDefaults",
    &[
        Field::req("color", DICT),
        Field::req("custom", DICT),
        Field::req("mappings", Ty::List(&DICT)),
        Field::req("thresholds", DICT),
    ],
);

/// `FieldConfig`.
pub static FIELD_CONFIG: Model = Model::new(
    "FieldConfig",
    &[
        Field::req("defaults", Ty::Model(&FIELD_CONFIG_DEFAULTS)),
        Field::req("overrides", Ty::List(&DICT)),
    ],
);

/// `GridPos`.
pub static GRID_POS: Model = Model::new(
    "GridPos",
    &[
        Field::req("h", Ty::Int),
        Field::req("w", Ty::Int),
        Field::req("x", Ty::Int),
        Field::req("y", Ty::Int),
    ],
);

/// `PanelOptions`.
pub static PANEL_OPTIONS: Model = Model::new(
    "PanelOptions",
    &[Field::req("legend", DICT), Field::req("tooltip", DICT)],
);

/// `Panel` (a row panel nests its panels).
pub static PANEL: Model = Model::new(
    "Panel",
    &[
        Field::opt("fieldConfig", Ty::Nullable(&Ty::Model(&FIELD_CONFIG))),
        Field::opt("gridPos", Ty::Nullable(&Ty::Model(&GRID_POS))),
        Field::req("id", Ty::Int),
        Field::opt("options", Ty::Nullable(&Ty::Model(&PANEL_OPTIONS))),
        Field::req("title", Ty::Str),
        Field::opt("type", Ty::Nullable(&Ty::Str)),
        Field::opt("collapsed", Ty::Nullable(&Ty::Bool)),
        Field::def("panels", Ty::List(&Ty::Model(&PANEL)), empty_list),
    ],
);

/// `Templating`.
pub static TEMPLATING: Model = Model::new("Templating", &[Field::req("list", Ty::List(&DICT))]);

/// `DashboardDetails`.
pub static DASHBOARD_DETAILS: Model = Model::new(
    "DashboardDetails",
    &[
        Field::req("annotations", DICT),
        Field::req("editable", Ty::Bool),
        Field::req("fiscalYearStartMonth", Ty::Int),
        Field::req("graphTooltip", Ty::Int),
        Field::req("id", Ty::Int),
        Field::req("links", Ty::List(&DICT)),
        Field::req("liveNow", Ty::Bool),
        Field::req("panels", Ty::List(&Ty::Model(&PANEL))),
        Field::req("refresh", Ty::Str),
        Field::req("schemaVersion", Ty::Int),
        Field::req("tags", Ty::List(&Ty::Str)),
        Field::req("templating", Ty::Model(&TEMPLATING)),
        Field::req("time", DICT),
        Field::req("timepicker", DICT),
        Field::req("timezone", Ty::Str),
        Field::req("title", Ty::Str),
        Field::req("uid", Ty::Str),
        Field::req("version", Ty::Int),
        Field::req("weekStart", Ty::Str),
    ],
);

/// `MetaDetails`.
pub static META_DETAILS: Model = Model::new(
    "MetaDetails",
    &[
        Field::req("type", Ty::Str),
        Field::req("canSave", Ty::Bool),
        Field::req("canEdit", Ty::Bool),
        Field::req("canAdmin", Ty::Bool),
        Field::req("canStar", Ty::Bool),
        Field::req("canDelete", Ty::Bool),
        Field::req("slug", Ty::Str),
        Field::req("url", Ty::Str),
        Field::req("expires", Ty::Str),
        Field::req("created", Ty::Str),
        Field::req("updated", Ty::Str),
        Field::req("updatedBy", Ty::Str),
        Field::req("createdBy", Ty::Str),
        Field::req("version", Ty::Int),
        Field::req("hasAcl", Ty::Bool),
        Field::req("isFolder", Ty::Bool),
        Field::req("folderId", Ty::Int),
        Field::req("folderUid", Ty::Str),
        Field::req("folderTitle", Ty::Str),
        Field::req("folderUrl", Ty::Str),
        Field::req("provisioned", Ty::Bool),
        Field::opt("provisionedExternalId", Ty::Nullable(&Ty::Str)),
        Field::req("annotationsPermissions", DICT),
    ],
);

/// `GrafanaDashboardDetails`.
pub static GRAFANA_DASHBOARD_DETAILS: Model = Model::new(
    "GrafanaDashboardDetails",
    &[
        Field::req("meta", Ty::Model(&META_DETAILS)),
        Field::req("dashboard", Ty::Model(&DASHBOARD_DETAILS)),
    ],
);

/// `GrafanaDashboardDetailsResponse`.
pub static GRAFANA_DASHBOARD_DETAILS_RESPONSE: Model = Model::new(
    "GrafanaDashboardDetailsResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("dashboard_details", Ty::Model(&GRAFANA_DASHBOARD_DETAILS)),
        Field::req("success", Ty::Bool),
    ],
);

/// `GrafanaDashboardPanelsResponse`.
pub static GRAFANA_DASHBOARD_PANELS_RESPONSE: Model = Model::new(
    "GrafanaDashboardPanelsResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("panels", Ty::List(&Ty::Model(&PANEL))),
        Field::req("success", Ty::Bool),
    ],
);

/// `TimeRange.validate_unit`: an `HTTPException(400)`, not a validation
/// error, for a unit other than `m`, `h`, `d`.
fn validate_unit(unit: &PyValue) -> Result<PyValue, Check> {
    match unit.as_str() {
        Some("m" | "h" | "d") => Ok(unit.clone()),
        _ => Err(Check::Abort(
            400,
            format!(
                "Invalid time range unit: {}. Must be one of ['m', 'h', 'd']",
                unit.py_str()
            ),
        )),
    }
}

/// `TimeRange`.
pub static TIME_RANGE: Model = Model::new(
    "TimeRange",
    &[
        Field::req("value", Ty::Int),
        Field::req("unit", Ty::Str).after(validate_unit),
    ],
);

/// `GrafanaGenerateIframeLinksRequest`.
pub static GRAFANA_GENERATE_IFRAME_LINKS_REQUEST: Model = Model::new(
    "GrafanaGenerateIframeLinksRequest",
    &[
        Field::req("org_id", Ty::Int),
        Field::req("dashboard_title", Ty::Str),
        Field::req("dashboard_uid", Ty::Str),
        Field::req("panel_id", Ty::Int),
        Field::req("time_range", Ty::Model(&TIME_RANGE)),
        Field::opt("theme", Ty::Nullable(&Ty::Str)),
    ],
);

/// `GrafanaLinksList`.
pub static GRAFANA_LINKS_LIST: Model = Model::new(
    "GrafanaLinksList",
    &[
        Field::req("panel_id", Ty::Int),
        Field::req("panel_url", Ty::Str),
    ],
);

/// `GrafanaGenerateIframeLinksResponse`.
pub static GRAFANA_GENERATE_IFRAME_LINKS_RESPONSE: Model = Model::new(
    "GrafanaGenerateIframeLinksResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("links", Ty::List(&Ty::Model(&GRAFANA_LINKS_LIST))),
        Field::req("success", Ty::Bool),
    ],
);

/// `UserOrganizationAddRequest`.
pub static USER_ORGANIZATION_ADD_REQUEST: Model = Model::new(
    "UserOrganizationAddRequest",
    &[
        Field::req("loginorEmail", Ty::Str),
        Field::def("role", Ty::Str, viewer),
        Field::req("organizationId", Ty::Str),
    ],
);

/// `UserOrganizationAddResponse`.
pub static USER_ORGANIZATION_ADD_RESPONSE: Model = Model::new(
    "UserOrganizationAddResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// Every model, by class name (for the vectors).
pub fn registry() -> Vec<(&'static str, &'static Model)> {
    vec![
        ("GrafanaOrganizations", &GRAFANA_ORGANIZATIONS),
        (
            "GrafanaOrganizationsResponse",
            &GRAFANA_ORGANIZATIONS_RESPONSE,
        ),
        (
            "GrafanaOrganizationDashboards",
            &GRAFANA_ORGANIZATION_DASHBOARDS,
        ),
        ("GrafanaDashboardResponse", &GRAFANA_DASHBOARD_RESPONSE),
        ("Panel", &PANEL),
        ("DashboardDetails", &DASHBOARD_DETAILS),
        ("MetaDetails", &META_DETAILS),
        ("GrafanaDashboardDetails", &GRAFANA_DASHBOARD_DETAILS),
        (
            "GrafanaDashboardDetailsResponse",
            &GRAFANA_DASHBOARD_DETAILS_RESPONSE,
        ),
        (
            "GrafanaDashboardPanelsResponse",
            &GRAFANA_DASHBOARD_PANELS_RESPONSE,
        ),
        ("TimeRange", &TIME_RANGE),
        (
            "GrafanaGenerateIframeLinksRequest",
            &GRAFANA_GENERATE_IFRAME_LINKS_REQUEST,
        ),
        (
            "GrafanaGenerateIframeLinksResponse",
            &GRAFANA_GENERATE_IFRAME_LINKS_RESPONSE,
        ),
        ("UserOrganizationAddRequest", &USER_ORGANIZATION_ADD_REQUEST),
        (
            "UserOrganizationAddResponse",
            &USER_ORGANIZATION_ADD_RESPONSE,
        ),
    ]
}
#[cfg(test)]
mod vectors {
    //! `model_vectors.json`: every model against pydantic, on samples and
    //! their mutations (`scripts/gen-connector-model-vectors.py`).

    use super::*;
    use copilot_auth::pyvalue::loads;
    use copilot_upstream::json::pydantic_json;
    use copilot_upstream::model::{Invalid, format_validation_error, validate};
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    fn patch(base: &PyValue, path: &[Value], op: &str, value: Option<PyValue>) -> PyValue {
        fn walk(v: &mut PyValue, path: &[Value], op: &str, value: Option<PyValue>) {
            let (head, rest) = path.split_first().unwrap();
            match (v, head) {
                (PyValue::Dict(items), Value::String(k)) => {
                    let pos = items.iter().position(|(key, _)| key == k).unwrap();
                    if rest.is_empty() {
                        if op == "del" {
                            items.remove(pos);
                        } else {
                            items[pos].1 = value.unwrap();
                        }
                    } else {
                        walk(&mut items[pos].1, rest, op, value);
                    }
                }
                (PyValue::List(items), Value::Number(n)) => {
                    let i = usize::try_from(n.as_u64().unwrap()).unwrap();
                    if rest.is_empty() {
                        items[i] = value.unwrap();
                    } else {
                        walk(&mut items[i], rest, op, value);
                    }
                }
                other => panic!("bad path {other:?}"),
            }
        }
        let mut out = base.clone();
        walk(&mut out, path, op, value);
        out
    }

    fn run(model: &'static Model, input: &PyValue) -> Result<String, String> {
        match validate(model, input) {
            Ok(dump) => Ok(pydantic_json(&dump)),
            Err(Invalid::Errors(e)) => Err(format_validation_error(model.name, &e)),
            Err(Invalid::Abort(s, d)) => Err(format!("abort {s} {d}")),
        }
    }

    #[test]
    fn models_match_pydantic() {
        let registry = registry();
        let doc: Value = serde_json::from_str(include_str!("model_vectors.json")).unwrap();
        let bases = doc["bases"].as_array().unwrap();
        let mut inputs = Vec::new();
        let mut failures = Vec::new();
        for b in bases {
            let name = b["model"].as_str().unwrap();
            let model = registry
                .iter()
                .find(|(n, _)| *n == name)
                .unwrap_or_else(|| panic!("no model {name}"))
                .1;
            let input = loads(b["input"].as_str().unwrap()).unwrap();
            let got = run(model, &input);
            let want = match b.get("ok") {
                Some(ok) => Ok(ok.as_str().unwrap().to_string()),
                None => Err(b["err"].as_str().unwrap().to_string()),
            };
            if got != want {
                failures.push(format!("base {name}\n  want {want:?}\n  got  {got:?}"));
            }
            inputs.push((model, input));
        }
        let vectors = doc["vectors"].as_array().unwrap();
        assert!(vectors.len() > 500);
        for v in vectors {
            let idx = usize::try_from(v["base"].as_u64().unwrap()).unwrap();
            let (model, base) = &inputs[idx];
            let op = v["op"].as_str().unwrap();
            let value = v.get("value").map(|t| loads(t.as_str().unwrap()).unwrap());
            let input = patch(base, v["path"].as_array().unwrap(), op, value);
            let got = run(model, &input);
            let ok = match (&got, v.get("ok_sha256"), v.get("err")) {
                (Ok(text), Some(sha), _) => {
                    hex::encode(Sha256::digest(text.as_bytes())) == sha.as_str().unwrap()
                }
                (Err(text), _, Some(err)) => text == err.as_str().unwrap(),
                _ => false,
            };
            if !ok {
                failures.push(format!(
                    "{} {:?} {op} {:?}\n  want {:?}\n  got  {got:?}",
                    model.name,
                    v["path"],
                    v.get("value"),
                    v.get("err")
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} vectors differ:\n{}",
            failures.len(),
            bases.len() + vectors.len(),
            failures.join("\n")
        );
    }
}
