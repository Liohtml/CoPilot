//! # copilot-grafana-dashboards — Grafana dashboard provisioning
//!
//! Port of `app/connectors/grafana/{routes,services,schema}/dashboards.py`
//! and of `POST /customer_provisioning/provision/dashboards`, the two routes
//! that upload the dashboard templates to a customer's Grafana organization;
//! the integration and network-connector provisioning
//! (`copilot-integration-provisioning`) calls [`services::provision_dashboards`]
//! as Python's provisioning calls `provision_dashboards`.
//!
//! - [`templates`] — the 4.6 MB of templates, compiled in from the backend's
//!   own tree (`build.rs`), and the dashboard enums
//! - [`edit`]      — `load_dashboard_json` and its two edits (datasource uid,
//!   Grafana URL)
//! - [`schema`]    — the Pydantic models
//! - [`services`]  — `provision_dashboards`, `update_dashboard`
//! - [`routes`]    — the two routes
//!
//! Everything is pinned to the Python functions by
//! `grafana_dashboard_vectors.json` (`scripts/gen-grafana-dashboard-vectors.py`):
//! the embedded files, the enums, the bytes uploaded for every dashboard,
//! the request models and Grafana's answers.

#![warn(missing_docs)]

pub mod edit;
pub mod routes;
pub mod schema;
pub mod services;
pub mod templates;

pub use routes::{DashboardsState, router};

#[cfg(test)]
mod vectors {
    //! `grafana_dashboard_vectors.json` against the Python functions.

    use axum::response::IntoResponse;
    use copilot_auth::pyvalue::{PyValue, loads};
    use copilot_monitoring_alerts::body::PyBody;
    use copilot_upstream::json::{Dumps, py_dumps};
    use copilot_upstream::model::{construct_star, kwargs};
    use copilot_upstream::py::PyExc;
    use copilot_web::ApiError;
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    use crate::edit::{load_dashboard_json, replace_grafana_url, replace_uid_value};
    use crate::schema::{
        DASHBOARD_PROVISION_REQUEST, GRAFANA_DASHBOARD, GRAFANA_DASHBOARD_QUALNAME,
        PROVISION_DASHBOARD_REQUEST,
    };
    use crate::templates::{self, CLASSES, FILES};

    fn doc() -> Value {
        serde_json::from_str(include_str!("grafana_dashboard_vectors.json")).unwrap()
    }

    fn text(v: &Value) -> &str {
        v.as_str().unwrap()
    }

    #[test]
    fn every_template_file_is_embedded() {
        let d = doc();
        let files: Vec<&str> = d["files"].as_array().unwrap().iter().map(text).collect();
        let ours: Vec<&str> = FILES.iter().map(|(rel, _)| *rel).collect();
        assert_eq!(ours, files);
        for (rel, body) in FILES {
            assert!(loads(body).is_ok(), "{rel} does not parse");
        }
    }

    #[test]
    fn the_enums_map_to_the_same_files() {
        let d = doc();
        let classes = d["classes"].as_array().unwrap();
        assert_eq!(classes.len(), CLASSES.len());
        for (want, ours) in classes.iter().zip(CLASSES) {
            assert_eq!(text(&want["name"]), ours.name);
            let members = want["members"].as_array().unwrap();
            assert_eq!(members.len(), ours.members.len(), "{}", ours.name);
            for (m, o) in members.iter().zip(ours.members) {
                assert_eq!(
                    (text(&m[0]), text(&m[1]), text(&m[2])),
                    (o.name, o.folder, o.file)
                );
                assert!(o.template().is_some(), "{} is not embedded", o.name);
            }
        }
        let valid: Vec<(String, String, String)> = d["valid"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| (text(&m[0]).into(), text(&m[1]).into(), text(&m[2]).into()))
            .collect();
        let ours: Vec<(String, String, String)> = templates::valid()
            .iter()
            .map(|o| (o.name.into(), o.folder.into(), o.file.into()))
            .collect();
        assert_eq!(ours, valid);
    }

    #[test]
    fn uploaded_bodies_are_python_s() {
        let d = doc();
        let bodies = d["bodies"].as_array().unwrap();
        assert_eq!(bodies.len(), templates::valid().len() * 3);
        for b in bodies {
            let name = text(&b["name"]);
            let dashboard = templates::find(name).unwrap();
            let json = load_dashboard_json(&dashboard, text(&b["uid"]), text(&b["url"])).unwrap();
            let payload = kwargs(vec![
                ("dashboard", json),
                ("folderId", PyValue::Int(b["folder"].to_string())),
                ("overwrite", PyValue::Bool(true)),
            ]);
            let data = py_dumps(&payload, Dumps::DEFAULT).unwrap();
            assert_eq!(data.len() as u64, b["len"].as_u64().unwrap(), "{name}");
            let sha = hex::encode(Sha256::digest(data.as_bytes()));
            assert_eq!(sha, text(&b["sha256"]), "{name} {}", b["url"]);
        }
    }

    #[test]
    fn edits_are_python_s() {
        let d = doc();
        for e in d["edits"].as_array().unwrap() {
            let mut v = loads(text(&e["input"])).unwrap();
            replace_uid_value(&mut v, text(&e["uid"]));
            replace_grafana_url(&mut v, text(&e["url"]));
            assert_eq!(
                py_dumps(&v, Dumps::DEFAULT).unwrap(),
                text(&e["out"]),
                "{e}"
            );
        }
    }

    async fn answer(e: ApiError) -> (u16, String) {
        let resp = e.into_response();
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    async fn check_requests(kind: &str, model: &'static copilot_upstream::model::Model) {
        let d = doc();
        for v in d["requests"][kind].as_array().unwrap() {
            let input = text(&v["input"]);
            let body = PyBody::read(Some("application/json"), input.as_bytes()).unwrap();
            let status = v["status"].as_u64().unwrap();
            match body.model(model) {
                Ok(dump) => {
                    assert_eq!(status, 200, "{input}");
                    assert_eq!(
                        py_dumps(&dump, Dumps::DEFAULT).unwrap(),
                        text(&v["dump"]),
                        "{input}"
                    );
                }
                Err(e) => {
                    let (got_status, got_body) = answer(e).await;
                    assert_eq!(u64::from(got_status), status, "{input}: {got_body}");
                    assert_eq!(got_body, text(&v["body"]), "{input}");
                }
            }
        }
    }

    #[tokio::test]
    async fn grafana_requests_validate_as_fastapi_does() {
        check_requests("grafana", &DASHBOARD_PROVISION_REQUEST).await;
    }

    #[tokio::test]
    async fn customer_requests_validate_as_fastapi_does() {
        check_requests("customer", &PROVISION_DASHBOARD_REQUEST).await;
    }

    #[test]
    fn grafana_answers_build_the_model_as_python_does() {
        let d = doc();
        for a in d["answers"].as_array().unwrap() {
            let input = loads(text(&a["input"])).unwrap();
            match construct_star(&GRAFANA_DASHBOARD, GRAFANA_DASHBOARD_QUALNAME, &input) {
                Ok(dump) => assert_eq!(
                    py_dumps(&dump, Dumps::DEFAULT).unwrap(),
                    text(&a["ok"]),
                    "{a}"
                ),
                Err(e) => {
                    let kind = match &e {
                        PyExc::Validation(_) => "ValidationError",
                        PyExc::TypeError(_) => "TypeError",
                        _ => "other",
                    };
                    assert_eq!(kind, text(&a["exc"]), "{a}");
                    assert_eq!(e.text(), text(&a["text"]), "{a}");
                }
            }
        }
    }
}
