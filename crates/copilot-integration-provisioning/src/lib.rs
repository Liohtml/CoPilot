//! Provisioning that ends in Grafana dashboards — ports of
//! `app/stack_provisioning/graylog/{routes,services}/{fortinet,sonicwall,
//! sentinelone}.py` ([`network`]) and of the integrations' `/provision`
//! routes (`app/integrations/{huntress,darktrace,duo,cato,carbonblack,
//! mimecast,sap_siem,socfortress_mdr}/`, [`integrations`]).
//!
//! The CrowdStrike, Defender for Endpoint and Bitdefender provisioning
//! ([`collectors`]) also write their collectors' docker-compose and
//! configuration files under the Python backend's `data/` directory
//! (`COPILOT_BACKEND_DATA_DIR`), and Bitdefender pushes its settings to
//! GravityZone. Office 365 and AWS are `copilot-cloud-provisioning`'s.
//!
//! - [`schema`]  — the Pydantic models the flows build and read
//! - [`graylog`] — index sets, streams, pipelines, the id lookups, the
//!   network connectors' content packs (on a named connector)
//! - [`grafana`] — the OpenSearch datasource, the folder, the indexer's
//!   version and node count
//! - [`store`]   — the statements
//! - [`network`] — Fortinet, SonicWall and SentinelOne, one data table
//! - [`integrations`] — the seven Graylog-and-Grafana integrations, one data
//!   table, the scheduler jobs handed to Python; SOCFortress MDR
//! - [`collectors`] — CrowdStrike, Defender for Endpoint and Bitdefender, one
//!   data table: the Graylog and Grafana objects, then the collector's files
//! - [`customer`] — the customer provisioning (`POST /api/customer_provisioning
//!   /provision`, `/provision/wazuh_worker`) and the Portainer worker stack
//!   (`POST /api/portainer/create-wazuh-customer-stack`)
//! - [`routes`]  — the handlers
//!
//! The dashboards themselves are `copilot-grafana-dashboards`'
//! `provision_dashboards`; the content-pack templates and their insert and
//! install are `copilot-provisioning`'s.

#![warn(missing_docs)]

pub mod collectors;
pub mod customer;
pub mod grafana;
pub mod graylog;
pub mod integrations;
pub mod network;
pub mod routes;
pub mod schema;
pub mod store;

use axum::extract::FromRef;
use copilot_core::cloud_env::CloudEnv;
use copilot_db::schema::TableRequirement;
use copilot_gateway::LegacyProxy;
use copilot_grafana::GrafanaClient;
use copilot_graylog::GraylogClient;
use copilot_portainer::PortainerClient;
use copilot_upstream::http::PyHttp;
use copilot_wazuh::WazuhState;
use copilot_web::AppContext;

pub use routes::router;

/// What the routes need.
#[derive(Clone)]
pub struct ProvisioningState {
    /// The shared context (database, tokens, connector rows).
    pub ctx: AppContext,
    /// The Graylog client.
    pub graylog: GraylogClient,
    /// The Grafana client.
    pub grafana: GrafanaClient,
    /// The Wazuh indexer (node count, OpenSearch version).
    pub wazuh: WazuhState,
    /// The Python backend, which registers the integrations' scheduler jobs.
    pub legacy: Option<LegacyProxy>,
    /// What the collectors read from the environment (the backend's data
    /// directory, the GravityZone URL of the tests).
    pub env: CloudEnv,
    /// Portainer (the customer's worker stack).
    pub portainer: PortainerClient,
    /// `requests` (`timeout=60`, certificates verified) for the provisioning
    /// worker and HAProxy services.
    pub worker_http: PyHttp,
}

impl FromRef<ProvisioningState> for AppContext {
    fn from_ref(s: &ProvisioningState) -> Self {
        s.ctx.clone()
    }
}

/// The columns this crate reads and writes.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "customer_network_connectors_meta",
        columns: &[
            "id",
            "customer_code",
            "network_connector_name",
            "graylog_input_id",
            "graylog_index_id",
            "graylog_stream_id",
            "graylog_pipeline_id",
            "graylog_content_pack_input_id",
            "graylog_content_pack_stream_id",
            "grafana_org_id",
            "grafana_dashboard_folder_id",
            "grafana_datasource_uid",
        ],
    },
    TableRequirement {
        table: "customer_network_connectors",
        columns: &[
            "id",
            "customer_code",
            "network_connector_service_name",
            "deployed",
        ],
    },
    TableRequirement {
        table: "customersmeta",
        columns: &[
            "id",
            "customer_code",
            "customer_name",
            "customer_meta_graylog_index",
            "customer_meta_graylog_stream",
            "customer_meta_grafana_org_id",
            "customer_meta_wazuh_group",
            "customer_meta_index_retention",
            "customer_meta_wazuh_registration_port",
            "customer_meta_wazuh_log_ingestion_port",
            "customer_meta_wazuh_api_port",
            "customer_meta_wazuh_auth_password",
            "customer_meta_iris_customer_id",
            "customer_meta_portainer_stack_id",
        ],
    },
    TableRequirement {
        table: "customer_integrations",
        columns: &["customer_code", "integration_service_name", "deployed"],
    },
    TableRequirement {
        table: "custom_alert_creation_settings",
        columns: &[
            "customer_code",
            "customer_name",
            "timefield",
            "iris_customer_id",
            "iris_customer_name",
            "iris_index",
            "grafana_url",
            "custom_message",
            "nvd_url",
        ],
    },
];

#[cfg(test)]
mod vectors {
    //! `integration_provisioning_vectors.json`
    //! (`scripts/gen-integration-provisioning-vectors.py`) against the Python
    //! functions and models.

    use axum::response::IntoResponse;
    use copilot_auth::pyvalue::{PyValue, loads};
    use copilot_monitoring_alerts::body::PyBody;
    use copilot_upstream::json::{Dumps, py_dumps};
    use copilot_upstream::model::{construct, kwargs};
    use copilot_upstream::py::PyExc;
    use copilot_web::ApiError;
    use serde_json::Value;

    use crate::graylog::{self, IndexSet, Keywords};
    use crate::schema::{GRAFANA_DATASOURCE, registry};

    fn doc() -> Value {
        serde_json::from_str(include_str!("integration_provisioning_vectors.json")).unwrap()
    }

    fn text(v: &Value) -> &str {
        v.as_str().unwrap()
    }

    fn py(v: &Value) -> PyValue {
        loads(&v.to_string()).unwrap()
    }

    fn model(name: &str) -> &'static copilot_upstream::model::Model {
        registry()
            .into_iter()
            .find(|(n, _)| *n == name)
            .map(|(_, m)| m)
            .unwrap()
    }

    fn dumps(v: &PyValue) -> String {
        py_dumps(v, Dumps::DEFAULT).unwrap()
    }

    #[test]
    fn the_packs_are_the_enum_s() {
        let d = doc();
        let names: Vec<&str> = d["packs"]["names"]
            .as_array()
            .unwrap()
            .iter()
            .map(text)
            .collect();
        let ours: Vec<&str> = copilot_provisioning::templates::GRAYLOG
            .iter()
            .map(|(n, _)| *n)
            .collect();
        assert_eq!(ours, names);
        for (key, kept) in d["packs"]["kept"].as_object().unwrap() {
            let (tag, protocol) = key.split_once('/').unwrap();
            let protocol = (protocol != "None").then_some(protocol);
            let want: Vec<&str> = kept.as_array().unwrap().iter().map(text).collect();
            assert_eq!(graylog::network_content_packs(tag, protocol), want, "{key}");
        }
    }

    fn keywords(v: &Value) -> Keywords {
        let opt = |k: &str| v[k].as_str().map(str::to_string);
        Keywords {
            customer_name: text(&v["customer_name"]).into(),
            customer_code: text(&v["customer_code"]).into(),
            protocol_type: None,
            syslog_port: v["SYSLOG_PORT"].to_string(),
            tls_cert_file: opt("TLS_CERT_FILE"),
            tls_key_file: opt("TLS_KEY_FILE"),
        }
    }

    #[test]
    fn content_packs_render_as_python_renders_them() {
        let d = doc();
        let r = &d["renders"];
        let uuids: Vec<String> = r["uuids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| text(u).to_string())
            .collect();
        let sets: Vec<Keywords> = r["keywords"]
            .as_array()
            .unwrap()
            .iter()
            .map(keywords)
            .collect();
        let replacements =
            |i: usize| graylog::replacements_with(&sets[i], uuids[0].clone(), uuids[1].clone());
        for v in r["packs"].as_array().unwrap() {
            let template = copilot_provisioning::templates::content_pack(text(&v["pack"])).unwrap();
            let i = usize::try_from(v["keywords"].as_u64().unwrap()).unwrap();
            let out = dumps(&graylog::render_content_pack(&template, &replacements(i)));
            let digest = {
                use sha2::Digest;
                hex::encode(sha2::Sha256::digest(out.as_bytes()))
            };
            assert_eq!(
                out.len() as u64,
                v["len"].as_u64().unwrap(),
                "{}",
                v["pack"]
            );
            assert_eq!(digest, text(&v["sha256"]), "{} {i}", v["pack"]);
        }
        for v in r["small"].as_array().unwrap() {
            let input = loads(text(&v["input"])).unwrap();
            let i = usize::try_from(v["keywords"].as_u64().unwrap()).unwrap();
            let out = dumps(&graylog::render_content_pack(&input, &replacements(i)));
            assert_eq!(out, text(&v["out"]), "{} {i}", text(&v["input"]));
        }
    }

    #[test]
    fn models_validate_as_pydantic_does() {
        let d = doc();
        for (name, cases) in d["models"].as_object().unwrap() {
            for v in cases.as_array().unwrap() {
                let input = loads(text(&v["input"])).unwrap();
                match construct(model(name), &input) {
                    Ok(dump) => assert_eq!(dumps(&dump), text(&v["dump"]), "{name}"),
                    Err(PyExc::Validation(e)) => assert_eq!(e, text(&v["error"]), "{name}"),
                    Err(other) => panic!("{name}: {other:?}"),
                }
            }
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

    #[tokio::test]
    async fn request_bodies_are_read_as_fastapi_reads_them() {
        let d = doc();
        for (name, cases) in d["requests"].as_object().unwrap() {
            let service = match name.as_str() {
                "ProvisionFortinetRequest" => "Fortinet",
                "ProvisionSonicwallRequest" => "Sonicwall",
                _ => "Sentinelone",
            };
            for v in cases.as_array().unwrap() {
                let input = text(&v["input"]);
                let body = PyBody::read(Some("application/json"), input.as_bytes()).unwrap();
                let status = v["status"].as_u64().unwrap();
                match crate::routes::read_forced(&body, model(name), "integration_name", service) {
                    Ok(dump) => {
                        assert_eq!(status, 200, "{name} {input}");
                        assert_eq!(dumps(&dump), text(&v["dump"]), "{name} {input}");
                    }
                    Err(e) => {
                        let (got, body) = answer(e).await;
                        assert_eq!(u64::from(got), status, "{name} {input}: {body}");
                        if status != 500 {
                            assert_eq!(body, text(&v["body"]), "{name} {input}");
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn integrations_are_python_s() {
        use crate::integrations::{INTEGRATIONS, Interval, PROVISION_MDR_REQUEST, Shards};
        let d = doc();
        let all = d["integrations"].as_object().unwrap();
        assert_eq!(all.len(), INTEGRATIONS.len() + 1);
        let allow: Vec<&str> = d["provisioning_jobs"]
            .as_array()
            .unwrap()
            .iter()
            .map(text)
            .collect();
        let name = "Ä \"Name\" \\ x";
        let code = "AbÇ_9";
        for integration in INTEGRATIONS {
            let v = &all[integration.route];
            assert_eq!(text(&v["request"]), integration.request.name);
            // The jobs: each in the hook's allowlist, Python's order and intervals.
            let jobs: Vec<(String, String, String)> = v["jobs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|j| (text(&j[0]).into(), text(&j[1]).into(), j[2].to_string()))
                .collect();
            let ours: Vec<(String, String, String)> = integration
                .jobs
                .iter()
                .map(|(job, interval)| {
                    let minutes = match interval {
                        Interval::Request => "\"request\"".to_string(),
                        Interval::Fixed(n) => n.to_string(),
                    };
                    ((*job).to_string(), (*job).to_string(), minutes)
                })
                .collect();
            assert_eq!(ours, jobs, "{}", integration.route);
            for (job, _) in integration.jobs {
                assert!(allow.contains(job), "{job}");
            }
            // The index set and the stream for one customer.
            let shards = match integration.shards {
                Shards::Nodes => PyValue::Int("3".into()),
                Shards::Fixed(n) => PyValue::Int(n.to_string()),
            };
            let index = graylog::index_set_config(&IndexSet {
                title: format!("{name} - {}", integration.index_title),
                description: format!("{code} - {}", integration.index_description),
                index_prefix: (integration.index_prefix)(code),
                max_indices: PyValue::Int("30".into()),
                shards,
                replicas: PyValue::Int("0".into()),
                creation_date: "<t>".into(),
            })
            .unwrap();
            assert_eq!(
                dumps(&index),
                text(&v["index_set"]),
                "{}",
                integration.route
            );
            let stream = graylog::event_stream_config(
                &format!("{name} - {}", integration.stream_title),
                &format!("{name} - {}", integration.stream_title),
                &PyValue::Str("is-1".into()),
                vec![
                    ("integration", integration.stream_value.to_string()),
                    ("customer_code", code.to_string()),
                ],
            )
            .unwrap();
            assert_eq!(dumps(&stream), text(&v["stream"]), "{}", integration.route);
            check_bodies(
                &v["requests"],
                integration.request,
                Some(integration.request_name),
            )
            .await;
        }
        check_bodies(
            &all["socfortress_mdr"]["requests"],
            &PROVISION_MDR_REQUEST,
            None,
        )
        .await;
    }

    async fn check_bodies(
        cases: &Value,
        model: &'static copilot_upstream::model::Model,
        forced: Option<&str>,
    ) {
        for v in cases.as_array().unwrap() {
            let input = text(&v["input"]);
            let body = PyBody::read(Some("application/json"), input.as_bytes()).unwrap();
            let status = v["status"].as_u64().unwrap();
            let read = match forced {
                Some(value) => crate::routes::read_forced(&body, model, "integration_name", value),
                None => body.model(model),
            };
            match read {
                Ok(dump) => {
                    assert_eq!(status, 200, "{} {input}", model.name);
                    assert_eq!(dumps(&dump), text(&v["dump"]), "{} {input}", model.name);
                }
                Err(e) => {
                    let (got, body) = answer(e).await;
                    assert_eq!(u64::from(got), status, "{} {input}: {body}", model.name);
                    if status != 500 {
                        assert_eq!(body, text(&v["body"]), "{} {input}", model.name);
                    }
                }
            }
        }
    }

    #[test]
    fn the_index_set_and_the_datasource_are_python_s() {
        let d = doc();
        for v in d["index_set"].as_array().unwrap() {
            let dump = graylog::index_set_config(&IndexSet {
                title: text(&v["title"]).into(),
                description: text(&v["title"]).into(),
                index_prefix: text(&v["prefix"]).into(),
                max_indices: py(&v["retention"]),
                shards: py(&v["shards"]),
                replicas: py(&v["replicas"]),
                creation_date: "2026-10-17T08:09:10.123456Z".into(),
            })
            .unwrap();
            assert_eq!(dumps(&dump), text(&v["json"]));
        }
        for v in d["datasource"].as_array().unwrap() {
            let s = |k: &str| py(&v[k]);
            let kwargs = kwargs(vec![
                ("name", s("name")),
                ("type", PyValue::Str("grafana-opensearch-datasource".into())),
                ("typeName", PyValue::Str("OpenSearch".into())),
                ("access", PyValue::Str("proxy".into())),
                ("url", s("url")),
                ("database", s("database")),
                ("basicAuth", PyValue::Bool(true)),
                ("basicAuthUser", s("user")),
                (
                    "secureJsonData",
                    kwargs(vec![("basicAuthPassword", s("password"))]),
                ),
                ("isDefault", PyValue::Bool(false)),
                (
                    "jsonData",
                    kwargs(vec![
                        ("database", s("database")),
                        ("flavor", PyValue::Str("opensearch".into())),
                        ("includeFrozen", PyValue::Bool(false)),
                        ("logLevelField", s("level")),
                        ("logMessageField", s("message")),
                        ("maxConcurrentShardRequests", PyValue::Int("5".into())),
                        ("pplEnabled", PyValue::Bool(true)),
                        ("timeField", PyValue::Str("timestamp".into())),
                        ("tlsSkipVerify", PyValue::Bool(true)),
                        ("version", s("version")),
                    ]),
                ),
                ("readOnly", PyValue::Bool(true)),
            ]);
            match construct(&GRAFANA_DATASOURCE, &kwargs) {
                Ok(dump) => assert_eq!(dumps(&dump), text(&v["dump"])),
                Err(PyExc::Validation(e)) => assert_eq!(e, text(&v["error"])),
                Err(other) => panic!("{other:?}"),
            }
        }
    }
}
