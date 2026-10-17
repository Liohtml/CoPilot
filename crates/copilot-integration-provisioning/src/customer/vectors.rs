//! `customer_vectors.json` (`scripts/gen-remaining-provisioning-vectors.py`)
//! against the customer provisioning's Python.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::response::IntoResponse;
use copilot_auth::pyvalue::{PyValue, loads};
use copilot_monitoring_alerts::body::PyBody;
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_upstream::model::{Model, kwargs};
use copilot_web::ApiError;
use serde_json::Value;
use sha2::Digest;

use super::schema::{PROVISION_NEW_CUSTOMER, PROVISION_WORKER_REQUEST};
use super::*;

fn doc() -> Value {
    serde_json::from_str(include_str!("../customer_vectors.json")).unwrap()
}

fn t(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn dumps(v: &PyValue) -> String {
    py_dumps(v, Dumps::DEFAULT).unwrap()
}

fn sha(text: &str) -> String {
    hex::encode(sha2::Sha256::digest(text.as_bytes()))
}

async fn answer(e: ApiError) -> (u16, String) {
    let resp = e.into_response();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn bodies(cases: &Value, model: &'static Model) {
    for case in cases.as_array().unwrap() {
        let input = t(&case["input"]);
        let body = PyBody::read(Some("application/json"), input.as_bytes()).unwrap();
        let status = case["status"].as_u64().unwrap();
        match body.model(model) {
            Ok(dump) => {
                assert_eq!(status, 200, "{input}");
                assert_eq!(dumps(&dump), t(&case["dump"]), "{input}");
            }
            Err(e) => {
                let (got, body) = answer(e).await;
                assert_eq!(u64::from(got), status, "{input}: {body}");
                assert_eq!(body, t(&case["body"]), "{input}");
            }
        }
    }
}

#[tokio::test]
async fn bodies_are_read_as_fastapi_reads_them() {
    let d = doc();
    bodies(&d["provision_new_customer"], &PROVISION_NEW_CUSTOMER).await;
    bodies(&d["provision_worker_request"], &PROVISION_WORKER_REQUEST).await;
}

#[test]
fn the_index_set_and_the_stream_are_python_s() {
    let d = doc();
    for v in d["graylog"].as_array().unwrap() {
        let request = kwargs(vec![
            ("customer_name", PyValue::Str(t(&v["name"]).into())),
            ("customer_code", PyValue::Str(t(&v["code"]).into())),
        ]);
        let name = t(&v["name"]);
        let index_set = crate::graylog::index_set_config(&IndexSet {
            title: format!("{name} - Wazuh EDR EVENTS"),
            description: format!("{name} - Wazuh EDR EVENTS"),
            index_prefix: t(&v["index"]).into(),
            max_indices: PyValue::Int("30".into()),
            shards: PyValue::Int("1".into()),
            replicas: PyValue::Int("0".into()),
            creation_date: "<t>".into(),
        })
        .unwrap();
        assert_eq!(dumps(&index_set), t(&v["index_set"]));
        let stream = wazuh_event_stream(&request, &PyValue::Str("is-1".into())).unwrap();
        assert_eq!(dumps(&stream), t(&v["stream"]));
    }
}

#[test]
fn the_group_configurations_are_python_s() {
    let d = doc();
    for v in d["groups"].as_array().unwrap() {
        let code = t(&v["code"]);
        let cluster = loads(&v["cluster"].to_string()).unwrap();
        let sent = v["sent"].as_array().unwrap();
        assert_eq!(sent.len(), GROUP_TEMPLATES.len());
        for ((group, template), want) in GROUP_TEMPLATES.iter().zip(sent) {
            let group_code = format!("{group}_{code}");
            assert_eq!(
                format!("/groups/{group_code}/configuration"),
                t(&want["endpoint"])
            );
            let config = group_configuration(template, &group_code, &cluster);
            assert_eq!(sha(&config), t(&want["sha256"]), "{group_code}");
        }
    }
}

#[test]
fn the_wazuh_datasource_is_python_s() {
    let d = doc();
    for v in d["datasources"].as_array().unwrap() {
        let url = t(&v["grafana_url"]);
        let payload = crate::grafana::datasource_payload(
            &Datasource {
                name: "WAZUH".into(),
                database: "acme*".into(),
                log_level_field: "syslog_level",
                log_message_field: "rule_description",
                data_links: Some(wazuh_data_links(url)),
            },
            (
                PyValue::Str("https://idx:9200".into()),
                PyValue::Str("u".into()),
                PyValue::Str("p".into()),
            ),
            "2.19.1".into(),
        )
        .unwrap();
        assert_eq!(dumps(&payload), t(&v["payload"]), "{url}");
    }
    for pair in d["iris_index"].as_array().unwrap() {
        assert_eq!(iris_index(t(&pair[0])), t(&pair[1]));
    }
}

#[test]
fn the_stack_is_rendered_as_python_renders_it() {
    let d = doc();
    for v in d["stacks"].as_array().unwrap() {
        let request = loads(t(&v["request"])).unwrap();
        // The defaults `ProvisionNewCustomer` fills in.
        let mut request = match request {
            PyValue::Dict(items) => items,
            _ => unreachable!(),
        };
        for key in [
            "wazuh_logs_port",
            "wazuh_registration_port",
            "wazuh_api_port",
        ] {
            if !request.iter().any(|(k, _)| k == key) {
                request.push((key.into(), PyValue::Str("n/a".into())));
            }
        }
        let request = PyValue::Dict(request);
        let version = loads(&v["version"].to_string()).unwrap();
        let rendered = render_stack(&stack_variables(&request, version, 2));
        match (rendered, v.get("sha256")) {
            (Ok(template), Some(want)) => {
                assert_eq!(sha(&template), t(want), "{}", v["request"]);
                let code = field(&request, "customer_code").py_str().replace(' ', "_");
                assert_eq!(format!("wazuh-worker-{code}"), t(&v["name"]));
            }
            (Err(e), None) => {
                assert_eq!(e.text(), t(&v["exception"][1]), "{}", v["request"]);
            }
            (got, _) => panic!("{}: {got:?} where Python gives {v}", v["request"]),
        }
    }
}
