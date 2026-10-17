//! `cloud_provisioning_vectors.json`
//! (`scripts/gen-remaining-provisioning-vectors.py`) against the Python
//! functions.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use copilot_upstream::py::PyExc;
use serde_json::Value;

use crate::office365::config::{Keys, configuration_to_push};

fn doc() -> Value {
    serde_json::from_str(include_str!("cloud_provisioning_vectors.json")).unwrap()
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap()
}

#[test]
fn office365_edits_are_python_s() {
    let d = doc();
    for v in d["office365"].as_array().unwrap() {
        let config = text(&v["config"]);
        let k = &v["keys"];
        let keys = Keys {
            tenant_id: text(&k["TENANT_ID"]).into(),
            client_id: text(&k["CLIENT_ID"]).into(),
            client_secret: text(&k["CLIENT_SECRET"]).into(),
            api_type: text(&k["API_TYPE"]).into(),
        };
        match (configuration_to_push(config, &keys), v.get("put")) {
            (Ok(got), Some(want)) => assert_eq!(got, text(want), "{config:?} {k}"),
            (Err(e), None) => {
                let (status, detail) = match &e {
                    PyExc::Http(s, d) => (*s, d.clone()),
                    other => (500, other.text()),
                };
                assert_eq!(u64::from(status), v["error"]["status"].as_u64().unwrap());
                assert_eq!(detail, text(&v["error"]["text"]), "{config:?} {k}");
            }
            (got, _) => panic!("{config:?} {k}: {got:?} where Python gives {v}"),
        }
    }
}

#[test]
fn rule_sources_are_python_s() {
    let d = doc();
    assert_eq!(
        crate::graylog::office365_utc_rule_source("Office365 Timestamp - UTC"),
        text(&d["rules"]["office365_utc"])
    );
}
