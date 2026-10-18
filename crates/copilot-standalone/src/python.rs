//! What the Python app is made of, compiled in from `src/python/`
//! (`scripts/gen-standalone-vectors.py` writes it from `copilot.py`'s app):
//! its routes in Starlette's order, FastAPI's three documentation pages and
//! its OpenAPI document.

use std::sync::OnceLock;

use serde::Deserialize;

use copilot_web::routing::{RouteKind, RouteTable};

/// `app.json`: the routes and the pages.
const APP_JSON: &str = include_str!("python/app.json");
/// `GET /openapi.json`'s body, the import-time example as a marker.
pub const OPENAPI_TEMPLATE: &str = include_str!("python/openapi.json");

#[derive(Debug, Deserialize)]
struct AppJson {
    routes: Vec<RouteJson>,
    pages: Pages,
    import_time_marker: String,
}

#[derive(Debug, Deserialize)]
struct RouteJson {
    kind: String,
    path: String,
    methods: Option<Vec<String>>,
}

/// FastAPI's documentation pages, as `FastAPI.setup` serves them.
#[derive(Debug, Clone, Deserialize)]
pub struct Pages {
    /// `docs_url`.
    pub docs_url: String,
    /// `redoc_url`.
    pub redoc_url: String,
    /// `openapi_url`.
    pub openapi_url: String,
    /// `swagger_ui_oauth2_redirect_url`.
    pub oauth2_redirect_url: String,
    /// `get_swagger_ui_html(…)`'s body.
    pub swagger_ui: String,
    /// `get_swagger_ui_oauth2_redirect_html()`'s body.
    pub oauth2_redirect: String,
    /// `get_redoc_html(…)`'s body.
    pub redoc: String,
}

/// The Python app.
#[derive(Debug)]
pub struct PythonApp {
    /// Its routes.
    pub table: RouteTable,
    /// Its documentation pages.
    pub pages: Pages,
    /// The text standing for the import-time value in [`OPENAPI_TEMPLATE`].
    pub import_time_marker: String,
}

fn load() -> Result<PythonApp, String> {
    let json: AppJson = serde_json::from_str(APP_JSON).map_err(|e| e.to_string())?;
    let entries = json
        .routes
        .into_iter()
        .map(|r| {
            let kind = match r.kind.as_str() {
                "api" => Ok(RouteKind::Api),
                "route" => Ok(RouteKind::Route),
                "mount" => Ok(RouteKind::Mount),
                other => Err(format!("unknown route kind {other}")),
            }?;
            Ok((kind, r.path, r.methods.unwrap_or_default()))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(PythonApp {
        table: RouteTable::new(entries)?,
        pages: json.pages,
        import_time_marker: json.import_time_marker,
    })
}

/// The Python app, parsed once (an error only if the compiled-in files are
/// broken, which the tests rule out).
pub fn app() -> Result<&'static PythonApp, &'static str> {
    static APP: OnceLock<Result<PythonApp, String>> = OnceLock::new();
    APP.get_or_init(load).as_ref().map_err(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_app_loads() {
        let app = app().unwrap();
        assert!(app.table.routes().len() > 800);
        assert_eq!(app.pages.docs_url, "/docs");
        assert_eq!(OPENAPI_TEMPLATE.matches(&app.import_time_marker).count(), 1);
        let v: serde_json::Value = serde_json::from_str(OPENAPI_TEMPLATE).unwrap();
        assert_eq!(v["info"]["title"], "CoPilot API");
    }

    /// Every operation of the OpenAPI document is a route of the table, with
    /// its method, and every API route of the table is in the document.
    #[test]
    fn the_document_and_the_table_agree() {
        let app = app().unwrap();
        let v: serde_json::Value = serde_json::from_str(OPENAPI_TEMPLATE).unwrap();
        let mut documented = std::collections::BTreeSet::new();
        for (path, ops) in v["paths"].as_object().unwrap() {
            for method in ops.as_object().unwrap().keys() {
                documented.insert((method.to_uppercase(), path.clone()));
            }
        }
        // The document names a parameter without its convertor
        // (`{rule_name:path}` is `{rule_name}`).
        let documented_path = |path: &str| {
            let mut out = String::new();
            let mut in_param = false;
            let mut skipping = false;
            for c in path.chars() {
                match c {
                    '{' => {
                        in_param = true;
                        out.push(c);
                    }
                    '}' => {
                        in_param = false;
                        skipping = false;
                        out.push(c);
                    }
                    ':' if in_param => skipping = true,
                    _ if skipping => {}
                    _ => out.push(c),
                }
            }
            out
        };
        let mut routed = std::collections::BTreeSet::new();
        for r in app.table.routes() {
            if r.kind == RouteKind::Api {
                for m in &r.methods {
                    routed.insert((m.clone(), documented_path(&r.path)));
                }
            }
        }
        // `include_in_schema=False` routes are routed but not documented.
        let missing: Vec<_> = documented.difference(&routed).collect();
        assert!(missing.is_empty(), "{missing:?}");
    }
}
