//! Stack and customer provisioning — ports of `app/stack_provisioning/`
//! (mounted under `/api/stack_provisioning` and `/api/stack_decommissioning`)
//! and of `app/customer_provisioning/` (`/api/customer_provisioning`, see
//! [`customer`]).
//!
//! - [`templates`] — the content packs and InfluxDB checks, compiled in
//!   (copies of the backend's template files, pinned to them by a test)
//! - [`schema`]    — the Pydantic models and the request bodies
//! - [`graylog`]   — content-pack provisioning (with the ETW pipeline rule)
//!   and network-connector decommissioning
//! - [`influx`]    — the four InfluxDB monitoring checks, over an httpx-shaped
//!   InfluxDB v2 REST transport
//! - [`routes`]    — the stack-provisioning handlers
//! - [`customer`]  — customer provisioning: default settings, customer meta,
//!   the EDR install commands, decommissioning
//!
//! The network-connector *provisioning* routes (`/graylog/provision/fortinet`,
//! `…/sonicwall`, `…/sentinelone`) are `copilot-integration-provisioning`'s:
//! they render these content packs through [`graylog`]'s connector-aware
//! functions, on `Graylog-Network`.

#![warn(missing_docs)]

pub mod customer;
pub mod graylog;
pub mod influx;
pub mod rollback;
pub mod routes;
pub mod schema;
pub mod templates;

use axum::extract::FromRef;
use copilot_db::schema::TableRequirement;
use copilot_grafana::GrafanaClient;
use copilot_graylog::GraylogClient;
use copilot_influxdb::InfluxClient;
use copilot_web::AppContext;

pub use routes::router;

/// What the stack-provisioning routes need.
#[derive(Clone)]
pub struct StackState {
    /// The shared context (database, tokens, connector rows).
    pub ctx: AppContext,
    /// The Graylog client (the default connector, as the routes use it).
    pub graylog: GraylogClient,
    /// The InfluxDB client (its connector row: URL, token, `ORG,BUCKET`).
    pub influx: InfluxClient,
    /// The Grafana client (network-connector decommissioning).
    pub grafana: GrafanaClient,
}

impl FromRef<StackState> for AppContext {
    fn from_ref(s: &StackState) -> Self {
        s.ctx.clone()
    }
}

/// The columns this crate reads and writes.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "customer_network_connectors_meta",
        columns: graylog::META_COLUMNS,
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
        columns: customer::store::META_COLUMNS,
    },
    TableRequirement {
        table: "customer_provisioning_default_settings",
        columns: customer::store::SETTINGS_COLUMNS,
    },
    TableRequirement {
        table: "customers",
        columns: &["id", "customer_code"],
    },
];

#[cfg(test)]
mod vectors {
    //! `provisioning_vectors.json` (`scripts/gen-provisioning-vectors.py`):
    //! the enums, the ETW rule, the models and the check rendering against
    //! the Python sources.

    use copilot_auth::pyvalue::{PyValue, loads};
    use copilot_upstream::json::{Dumps, py_dumps, pydantic_json};
    use copilot_upstream::model::{construct, field};
    use copilot_upstream::py::PyExc;
    use serde_json::Value;

    use crate::schema::{self, registry};

    fn doc() -> Value {
        serde_json::from_str(include_str!("provisioning_vectors.json")).unwrap()
    }

    fn py(v: &Value) -> PyValue {
        loads(&v.to_string()).unwrap()
    }

    #[test]
    fn enums_and_the_etw_rule() {
        let d = doc();
        let pairs = |v: &Value| -> Vec<(String, String)> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    (
                        p[0].as_str().unwrap().to_string(),
                        p[1].as_str().unwrap().to_string(),
                    )
                })
                .collect()
        };
        let names = |v: &Value| -> Vec<String> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_str().unwrap().to_string())
                .collect()
        };
        let ours = |p: &[(&str, &str)]| -> Vec<(String, String)> {
            p.iter()
                .map(|(a, b)| ((*a).to_string(), (*b).to_string()))
                .collect()
        };
        assert_eq!(
            pairs(&d["enums"]["overview"]),
            ours(schema::CONTENT_PACKS_OVERVIEW)
        );
        assert_eq!(names(&d["enums"]["content_packs"]), schema::CONTENT_PACKS);
        assert_eq!(
            pairs(&d["enums"]["influx_checks"]),
            ours(schema::INFLUX_CHECKS)
        );
        assert_eq!(
            names(&d["enums"]["network_connectors"]),
            schema::NETWORK_CONNECTORS
        );
        assert_eq!(
            d["etw_rule"].as_str().unwrap(),
            crate::graylog::etw_rule_source()
        );
    }

    #[test]
    fn models_validate_like_pydantic() {
        let d = doc();
        let models = registry();
        let mut checked = 0;
        for (name, model) in &models {
            for case in d["models"][*name].as_array().unwrap() {
                let input = py(&case["input"]);
                let got = construct(model, &input);
                match (&got, case.get("err")) {
                    (Err(PyExc::Validation(text)), Some(want)) => {
                        assert_eq!(text, want.as_str().unwrap(), "{name} {input:?}")
                    }
                    (Ok(dump), None) if *name == "ContentPackList" => {
                        let PyValue::List(packs) = field(dump, "content_packs") else {
                            panic!("{name}: no content_packs");
                        };
                        let got: Vec<String> =
                            packs.iter().map(|p| field(p, "name").py_str()).collect();
                        let want: Vec<String> = case["names"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|n| n.as_str().unwrap().to_string())
                            .collect();
                        assert_eq!(got, want, "{name} {input:?}");
                    }
                    (Ok(dump), None) => {
                        assert_eq!(
                            pydantic_json(dump),
                            case["ok"].as_str().unwrap(),
                            "{name} {input:?}"
                        )
                    }
                    (got, want) => panic!("{name} {input:?}: got {got:?}, want {want:?}"),
                }
                checked += 1;
            }
        }
        assert!(checked > 300, "{checked}");
    }

    #[test]
    fn customer_lists_and_edr_commands() {
        let d = doc();
        let c = &d["customer"];
        let names = |v: &Value| -> Vec<String> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(names(&c["dashboards"]), crate::customer::WAZUH_DASHBOARDS);
        assert_eq!(names(&c["subscriptions"]), crate::customer::SUBSCRIPTIONS);
        let text = |v: &Value, k: &str| v[k].as_str().map(str::to_string);
        for case in c["edr"].as_array().unwrap() {
            let (st, me) = (&case["settings"], &case["meta"]);
            let values = crate::customer::edr::EdrValues {
                repo_url: text(st, "repo_url"),
                repo_username: text(st, "repo_username"),
                repo_password: text(st, "repo_password"),
                windows_edr_installer: text(st, "windows_edr_installer"),
                wazuh_domain: text(st, "wazuh_domain"),
                registration_port: text(me, "customer_meta_wazuh_registration_port"),
                logs_port: text(me, "customer_meta_wazuh_log_ingestion_port"),
                registration_password: text(me, "customer_meta_wazuh_auth_password"),
            };
            match (
                crate::customer::edr::build(&values, "ACME"),
                case.get("commands"),
            ) {
                (Ok(got), Some(want)) => {
                    assert_eq!(pydantic_json(&got), want.to_string(), "{case}")
                }
                (Err(PyExc::Http(status, detail)), None) => {
                    assert_eq!(
                        u64::from(status),
                        case["status"].as_u64().unwrap(),
                        "{case}"
                    );
                    assert_eq!(detail, case["detail"].as_str().unwrap(), "{case}");
                }
                (got, _) => panic!("{case}: {got:?}"),
            }
        }
    }

    #[test]
    fn checks_render_like_python() {
        let d = doc();
        let text = Dumps {
            ensure_ascii: false,
            compact: false,
        };
        for case in d["render"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let template = crate::templates::check(name).unwrap();
            let got = crate::influx::render(
                &template,
                &py(&case["org_id"]),
                case["bucket"].as_str().unwrap(),
            );
            match (got, case.get("ok")) {
                (Ok(v), Some(want)) => {
                    assert_eq!(
                        py_dumps(&v, text).unwrap(),
                        want.as_str().unwrap(),
                        "{case}"
                    )
                }
                (Err(e), None) => {
                    let kind = match &e {
                        PyExc::JsonDecode(_) => "JSONDecodeError",
                        PyExc::TypeError(_) => "TypeError",
                        _ => "other",
                    };
                    assert_eq!(kind, case["exc"].as_str().unwrap(), "{case}");
                    assert_eq!(e.text(), case["text"].as_str().unwrap(), "{case}");
                }
                (got, _) => panic!("{case}: got {got:?}"),
            }
        }
    }
}
