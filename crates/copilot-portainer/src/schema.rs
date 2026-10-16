//! The Pydantic models of `app/connectors/portainer/schema/` (`nodes.py`,
//! `stack.py`) as [`copilot_upstream::model`] statics, pinned by
//! `model_vectors.json`.

use copilot_upstream::model::{Field, Model, Ty};

const DICT: Ty = Ty::Dict(&Ty::Any);

/// `Version`.
pub static VERSION: Model = Model::new("Version", &[Field::req("Index", Ty::Int)]);

/// `NodeSpec`.
pub static NODE_SPEC: Model = Model::new(
    "NodeSpec",
    &[
        Field::req("Labels", DICT),
        Field::req("Role", Ty::Str),
        Field::req("Availability", Ty::Str),
    ],
);

/// `Platform`.
pub static PLATFORM: Model = Model::new(
    "Platform",
    &[
        Field::req("Architecture", Ty::Str),
        Field::req("OS", Ty::Str),
    ],
);

/// `Resources`.
pub static RESOURCES: Model = Model::new(
    "Resources",
    &[
        Field::req("NanoCPUs", Ty::Int),
        Field::req("MemoryBytes", Ty::Int),
    ],
);

/// `Plugin`.
pub static PLUGIN: Model = Model::new(
    "Plugin",
    &[Field::req("Type", Ty::Str), Field::req("Name", Ty::Str)],
);

/// `TLSInfo`.
pub static TLS_INFO: Model = Model::new(
    "TLSInfo",
    &[
        Field::opt("TrustRoot", Ty::Nullable(&Ty::Str)),
        Field::opt("CertIssuerSubject", Ty::Nullable(&Ty::Str)),
        Field::opt("CertIssuerPublicKey", Ty::Nullable(&Ty::Str)),
    ],
);

/// `Engine`.
pub static ENGINE: Model = Model::new(
    "Engine",
    &[
        Field::req("EngineVersion", Ty::Str),
        Field::req("Plugins", Ty::List(&Ty::Model(&PLUGIN))),
        Field::opt("TLSInfo", Ty::Nullable(&Ty::Model(&TLS_INFO))),
    ],
);

/// `Description`.
pub static DESCRIPTION: Model = Model::new(
    "Description",
    &[
        Field::req("Hostname", Ty::Str),
        Field::req("Platform", Ty::Model(&PLATFORM)),
        Field::req("Resources", Ty::Model(&RESOURCES)),
        Field::req("Engine", Ty::Model(&ENGINE)),
    ],
);

/// `ManagerStatusResults`.
pub static MANAGER_STATUS_RESULTS: Model = Model::new(
    "ManagerStatusResults",
    &[
        Field::req("Leader", Ty::Bool),
        Field::req("Reachability", Ty::Str),
        Field::req("Addr", Ty::Str),
    ],
);

/// `Status`.
pub static STATUS: Model = Model::new(
    "Status",
    &[Field::req("State", Ty::Str), Field::req("Addr", Ty::Str)],
);

/// `Node`.
pub static NODE: Model = Model::new(
    "Node",
    &[
        Field::req("ID", Ty::Str),
        Field::req("Version", Ty::Model(&VERSION)),
        Field::req("CreatedAt", Ty::DateTime),
        Field::req("UpdatedAt", Ty::DateTime),
        Field::req("Spec", Ty::Model(&NODE_SPEC)),
        Field::req("Description", Ty::Model(&DESCRIPTION)),
        Field::req("Status", Ty::Model(&STATUS)),
        Field::opt(
            "ManagerStatus",
            Ty::Nullable(&Ty::Model(&MANAGER_STATUS_RESULTS)),
        ),
    ],
);

/// `NodesResponse`.
pub static NODES_RESPONSE: Model = Model::new(
    "NodesResponse",
    &[
        Field::req("nodes", Ty::List(&Ty::Model(&NODE))),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `ResourceControlResponse`.
pub static RESOURCE_CONTROL_RESPONSE: Model = Model::new(
    "ResourceControlResponse",
    &[
        Field::req("Id", Ty::Int),
        Field::req("ResourceId", Ty::Str),
        Field::req("SubResourceIds", Ty::List(&Ty::Str)),
        Field::req("Type", Ty::Int),
        Field::req("UserAccesses", Ty::List(&Ty::Str)),
        Field::req("TeamAccesses", Ty::List(&Ty::Str)),
        Field::req("Public", Ty::Bool),
        Field::req("AdministratorsOnly", Ty::Bool),
        Field::req("System", Ty::Bool),
    ],
);

/// `StackData`.
pub static STACK_DATA: Model = Model::new(
    "StackData",
    &[
        Field::req("Id", Ty::Int),
        Field::req("Name", Ty::Str),
        Field::req("Type", Ty::Int),
        Field::req("EndpointId", Ty::Int),
        Field::req("SwarmId", Ty::Str),
        Field::req("EntryPoint", Ty::Str),
        Field::req("Env", Ty::List(&Ty::Any)),
        Field::opt(
            "ResourceControl",
            Ty::Nullable(&Ty::Model(&RESOURCE_CONTROL_RESPONSE)),
        ),
        Field::req("Status", Ty::Int),
        Field::req("ProjectPath", Ty::Str),
        Field::req("CreationDate", Ty::Int),
        Field::req("CreatedBy", Ty::Str),
        Field::req("UpdateDate", Ty::Int),
        Field::req("UpdatedBy", Ty::Str),
        Field::opt("AdditionalFiles", Ty::Nullable(&Ty::Any)),
        Field::opt("AutoUpdate", Ty::Nullable(&Ty::Any)),
        Field::opt("Option", Ty::Nullable(&Ty::Any)),
        Field::opt("GitConfig", Ty::Nullable(&Ty::Any)),
        Field::req("FromAppTemplate", Ty::Bool),
        Field::req("Namespace", Ty::Str),
        Field::req("IsComposeFormat", Ty::Bool),
    ],
);

/// `StackResponse`.
pub static STACK_RESPONSE: Model = Model::new(
    "StackResponse",
    &[
        Field::req("data", Ty::Model(&STACK_DATA)),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `StacksResponse`.
pub static STACKS_RESPONSE: Model = Model::new(
    "StacksResponse",
    &[
        Field::req("data", Ty::List(&Ty::Model(&STACK_DATA))),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `DeleteStackResponse`.
pub static DELETE_STACK_RESPONSE: Model = Model::new(
    "DeleteStackResponse",
    &[
        Field::opt("data", Ty::Nullable(&Ty::Any)),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `StackIDResponse`.
pub static STACK_ID_RESPONSE: Model = Model::new(
    "StackIDResponse",
    &[
        Field::req("stack_id", Ty::Int),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// Every model, by class name (for the vectors).
pub fn registry() -> Vec<(&'static str, &'static Model)> {
    vec![
        ("Node", &NODE),
        ("NodesResponse", &NODES_RESPONSE),
        ("StackData", &STACK_DATA),
        ("StackResponse", &STACK_RESPONSE),
        ("StacksResponse", &STACKS_RESPONSE),
        ("DeleteStackResponse", &DELETE_STACK_RESPONSE),
        ("StackIDResponse", &STACK_ID_RESPONSE),
    ]
}

#[cfg(test)]
mod vectors {
    //! `model_vectors.json`: every model against pydantic, on samples and
    //! their mutations (`scripts/gen-connector-model-vectors.py`).

    use super::*;
    use copilot_auth::pyvalue::PyValue;
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
