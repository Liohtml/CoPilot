//! The Pydantic models of `app/connectors/influxdb/schema/` (`alerts.py`,
//! `metrics.py`) as [`copilot_upstream::model`] statics, pinned by
//! `model_vectors.json`, and the query-parameter vocabularies.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

/// `SeverityFilter` values, in declaration order.
pub const SEVERITY_FILTERS: [&str; 4] = ["ok", "warning", "error", "critical"];
/// `AlertStatus` values, in declaration order.
pub const ALERT_STATUSES: [&str; 3] = ["active", "cleared", "all"];

fn zero() -> PyValue {
    PyValue::Int("0".into())
}

fn empty_dict() -> PyValue {
    PyValue::Dict(Vec::new())
}

fn empty_list() -> PyValue {
    PyValue::List(Vec::new())
}

/// `InfluxDBAlert`.
pub static INFLUXDB_ALERT: Model = Model::new(
    "InfluxDBAlert",
    &[
        Field::req("time", Ty::DateTime),
        Field::req("check_name", Ty::Str),
        Field::req("sensor_type", Ty::Str),
        Field::req("severity", Ty::Str),
        Field::req("message", Ty::Str),
        Field::opt("status", Ty::Nullable(&Ty::Str)),
        Field::opt("check_id", Ty::Nullable(&Ty::Str)),
    ],
);

/// `InfluxDBAlertResponse`.
pub static INFLUXDB_ALERT_RESPONSE: Model = Model::new(
    "InfluxDBAlertResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("alerts", Ty::List(&Ty::Model(&INFLUXDB_ALERT))),
        Field::req("total_count", Ty::Int),
        Field::req("filtered_count", Ty::Int),
        Field::def("active_alerts_count", Ty::Int, zero),
        Field::def("cleared_alerts_count", Ty::Int, zero),
    ],
);

/// `InfluxDBCheckNamesResponse`.
pub static INFLUXDB_CHECK_NAMES_RESPONSE: Model = Model::new(
    "InfluxDBCheckNamesResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("check_names", Ty::List(&Ty::Str)),
        Field::req("total_count", Ty::Int),
    ],
);

/// `MetricsResponse`.
pub static METRICS_RESPONSE: Model = Model::new(
    "MetricsResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::def("data", Ty::Dict(&Ty::Any), empty_dict),
    ],
);

/// `HostsResponse`.
pub static HOSTS_RESPONSE: Model = Model::new(
    "HostsResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::def("hosts", Ty::List(&Ty::Str), empty_list),
    ],
);

/// Every model, by class name (for the vectors).
pub fn registry() -> Vec<(&'static str, &'static Model)> {
    vec![
        ("InfluxDBAlert", &INFLUXDB_ALERT),
        ("InfluxDBAlertResponse", &INFLUXDB_ALERT_RESPONSE),
        ("InfluxDBCheckNamesResponse", &INFLUXDB_CHECK_NAMES_RESPONSE),
        ("MetricsResponse", &METRICS_RESPONSE),
        ("HostsResponse", &HOSTS_RESPONSE),
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
        assert!(vectors.len() > 100);
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
