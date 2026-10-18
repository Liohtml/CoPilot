//! `load_dashboard_json` and the two edits it makes before upload
//! (`services/dashboards.py`): every `"uid": "replace_datasource_uid"` takes
//! the datasource's uid, and every `url` string that starts with
//! `https://grafana.company.local` has each occurrence of it replaced by the
//! Grafana URL (`str.replace`: all of them, left to right, not recursively).
//! Keys keep their places (a dict's value is assigned in place).

use copilot_auth::pyvalue::{PyValue, loads};
use copilot_upstream::py::{PyExc, PyResult};

use crate::templates::Dashboard;

/// The placeholder the templates carry for the datasource's uid.
pub const UID_PLACEHOLDER: &str = "replace_datasource_uid";
/// The URL the templates' links are written against.
pub const GRAFANA_URL_PLACEHOLDER: &str = "https://grafana.company.local";

/// `replace_uid_value(obj, new_value)`.
pub fn replace_uid_value(obj: &mut PyValue, new_value: &str) {
    match obj {
        PyValue::Dict(items) => {
            for (k, v) in items.iter_mut() {
                if k == "uid" && matches!(v, PyValue::Str(s) if s == UID_PLACEHOLDER) {
                    *v = PyValue::Str(new_value.to_string());
                } else if matches!(v, PyValue::Dict(_) | PyValue::List(_)) {
                    replace_uid_value(v, new_value);
                }
            }
        }
        PyValue::List(items) => {
            for item in items {
                replace_uid_value(item, new_value);
            }
        }
        _ => {}
    }
}

/// `replace_grafana_url(obj, new_value)`.
pub fn replace_grafana_url(obj: &mut PyValue, new_value: &str) {
    match obj {
        PyValue::Dict(items) => {
            for (k, v) in items.iter_mut() {
                match v {
                    PyValue::Str(s) if k == "url" && s.starts_with(GRAFANA_URL_PLACEHOLDER) => {
                        *s = s.replace(GRAFANA_URL_PLACEHOLDER, new_value);
                    }
                    PyValue::Dict(_) | PyValue::List(_) => replace_grafana_url(v, new_value),
                    _ => {}
                }
            }
        }
        PyValue::List(items) => {
            for item in items {
                replace_grafana_url(item, new_value);
            }
        }
        _ => {}
    }
}

/// `load_dashboard_json(dashboard.value, datasource_uid, grafana_url)`: the
/// template's `json.load` value, edited. A missing file is the 404 and a
/// template that is not JSON the 500 Python raises (neither can happen: the
/// unit tests check every member against the embedded files).
pub fn load_dashboard_json(
    dashboard: &Dashboard,
    datasource_uid: &str,
    grafana_url: &str,
) -> PyResult<PyValue> {
    let text = dashboard
        .template()
        .ok_or_else(|| PyExc::http(404, "Dashboard JSON file not found"))?;
    let mut value = loads(text).map_err(|_| PyExc::http(500, "Error decoding JSON from file"))?;
    replace_uid_value(&mut value, datasource_uid);
    replace_grafana_url(&mut value, grafana_url);
    Ok(value)
}
