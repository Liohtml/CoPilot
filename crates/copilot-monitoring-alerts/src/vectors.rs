//! `monitoring_alert_vectors.json`: the catalog, every provisioning
//! function's event definition, the request models, the custom alert, the
//! test event and its GELF frame, and the Event Shipper's port, against the
//! Python module (`scripts/gen-monitoring-alert-vectors.py`).

use axum::response::IntoResponse;
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::json::{Dumps, py_dumps, pydantic_json};
use copilot_upstream::py::PyExc;
use copilot_web::ApiError;
use serde_json::Value;

use crate::body::PyBody;
use crate::catalog::{self, ALERTS, Kind};
use crate::schema::{CUSTOM_REQUEST, PROVISION_REQUEST};
use crate::services;

fn doc() -> Value {
    serde_json::from_str(include_str!("monitoring_alert_vectors.json")).unwrap()
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn int(s: &str) -> PyValue {
    PyValue::Int(s.to_string())
}

async fn answer(e: ApiError) -> (u16, String) {
    let resp = e.into_response();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[test]
fn the_catalog_is_the_enum() {
    let d = doc();
    let members = d["catalog"]["members"].as_array().unwrap();
    assert_eq!(members.len(), ALERTS.len());
    for (m, a) in members.iter().zip(ALERTS) {
        assert_eq!(text(&m["name"]), a.name);
        assert_eq!(text(&m["value"]), a.summary, "{}", a.name);
    }
    let available = PyValue::Dict(vec![
        ("success".into(), PyValue::Bool(true)),
        (
            "message".into(),
            PyValue::Str("Alerts retrieved successfully".into()),
        ),
        (
            "available_monitoring_alerts".into(),
            crate::routes::available_alerts(),
        ),
    ]);
    assert_eq!(pydantic_json(&available), text(&d["catalog"]["available"]));
}

#[test]
fn every_definition_is_python_s() {
    let d = doc();
    let vectors = d["definitions"].as_array().unwrap();
    // Every catalog function but the WAF's, each for every window.
    let functions = ALERTS
        .iter()
        .filter(|a| matches!(a.kind, Kind::Definition(_)))
        .count();
    assert_eq!(functions, 49);
    assert!(vectors.len() >= functions * 3);
    let mut seen = std::collections::BTreeSet::new();
    for v in vectors {
        let name = text(&v["name"]);
        let Some(catalog::Alert {
            kind: Kind::Definition(def),
            ..
        }) = catalog::find(name)
        else {
            panic!("{name} is not a definition")
        };
        seen.insert(name);
        let entity = services::definition_entity(
            def,
            &int(text(&v["search_within_last"])),
            &int(text(&v["execute_every"])),
        )
        .unwrap();
        let version = text(&v["version"]);
        let entity = if version < "5.2" {
            services::without_event_limit(entity)
        } else {
            entity
        };
        assert_eq!(
            py_dumps(&entity, Dumps::DEFAULT).unwrap(),
            text(&v["body"]),
            "{name} {version}"
        );
    }
    assert_eq!(seen.len(), functions);
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
async fn provision_requests_validate_as_fastapi_does() {
    check_requests("provision", &PROVISION_REQUEST).await;
}

#[tokio::test]
async fn custom_requests_validate_as_fastapi_does() {
    check_requests("custom", &CUSTOM_REQUEST).await;
}

#[test]
fn custom_alerts_are_python_s() {
    let d = doc();
    let vectors = d["custom"].as_array().unwrap();
    assert!(vectors.len() >= 6);
    for v in vectors {
        let input = text(&v["input"]);
        let request = PyBody::read(Some("application/json"), input.as_bytes())
            .unwrap()
            .model(&CUSTOM_REQUEST)
            .unwrap();
        match (services::custom_entity(&request), v.get("body")) {
            (Ok(entity), Some(body)) => {
                assert_eq!(py_dumps(&entity, Dumps::DEFAULT).unwrap(), text(body))
            }
            (Err(PyExc::Validation(msg)), None) => assert_eq!(msg, text(&v["error"])),
            (got, _) => panic!("{input}: {got:?}"),
        }
    }
}

#[test]
fn test_events_and_their_frames() {
    let d = doc();
    for v in d["testing"].as_array().unwrap() {
        let input = text(&v["input"]);
        let request = PyBody::read(Some("application/json"), input.as_bytes())
            .unwrap()
            .dict()
            .unwrap();
        match (services::testing_message(&request), v.get("message")) {
            (Ok(message), Some(want)) => {
                assert_eq!(py_dumps(&message, Dumps::DEFAULT).unwrap(), text(want));
                let frame = copilot_graylog::gelf::frame(&message, "parity.host").unwrap();
                assert_eq!(String::from_utf8(frame).unwrap(), text(&v["frame"]));
            }
            (Err(PyExc::TypeError(msg)), None) => {
                assert_eq!(format!("TypeError: {msg}"), text(&v["error"]))
            }
            (got, _) => panic!("{input}: {got:?}"),
        }
    }
}

#[test]
fn the_event_shipper_port_is_asyncio_s() {
    let d = doc();
    for v in d["ports"].as_array().unwrap() {
        let (host, port) = (text(&v["host"]), text(&v["port"]));
        let want = v["resolved"].as_u64().map(|p| u16::try_from(p).unwrap());
        assert_eq!(
            copilot_graylog::gelf::resolve_port_with(host, port, ""),
            want,
            "{host} {port:?}"
        );
    }
}
