//! `mcp_vectors.json` (`scripts/gen-copilot-mcp-vectors.py`): the tables, the
//! routing, the request model and the answers' model, recorded from Python.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use copilot_auth::pyvalue::PyValue;
use copilot_threat_intel::schema::MCP_RESPONSE;
use copilot_upstream::json::pydantic_json;
use copilot_upstream::model::{Invalid, Loc, Ty, construct_star, validate_body};
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::from_json;
use copilot_web::{ApiError, JsonBody};
use pretty_assertions::assert_eq;
use serde_json::{Value, json};

use crate::routes::invalid_server;
use crate::schema::{self, ALL, MCP_QUERY_REQUEST, SERVERS};

fn doc() -> Value {
    serde_json::from_str(include_str!("mcp_vectors.json")).unwrap()
}

fn as_json(v: &PyValue) -> Value {
    serde_json::from_str(&pydantic_json(v)).unwrap()
}

#[test]
fn tables_are_pythons() {
    let d = doc();
    let servers: Vec<Value> = SERVERS.iter().map(|s| as_json(&s.dump())).collect();
    assert_eq!(Value::Array(servers), d["servers"]);
    for server in ALL {
        let value = server.value();
        let questions: Vec<Value> = schema::questions(server)
            .iter()
            .map(|q| as_json(&q.dump()))
            .collect();
        assert_eq!(Value::Array(questions), d["questions"][value], "{value}");
        assert_eq!(
            json!(schema::categories(server)),
            d["categories"][value],
            "{value}"
        );
        let (cloud, endpoint) = server.config();
        let base = if cloud {
            "https://mcp.socfortress.co/query"
        } else {
            crate::LOCAL_BASE
        };
        assert_eq!(
            json!({"cloud": cloud, "endpoint": endpoint, "url": format!("{base}/{endpoint}")}),
            d["services"][value],
            "{value}"
        );
    }
}

#[test]
fn request_bodies_validate_as_pydantic() {
    for case in doc()["requests"].as_array().unwrap() {
        let body = JsonBody::Value(case["body"].clone());
        let got = match invalid_server(&body) {
            Some(ApiError::Http { status, detail }) => json!({"http": [status.as_u16(), detail]}),
            Some(other) => panic!("{other:?}"),
            None => {
                match validate_body(&Ty::Model(&MCP_QUERY_REQUEST), &from_json(&case["body"])) {
                    Ok(dump) => json!({"ok": as_json(&dump)}),
                    Err(Invalid::Errors(errors)) => json!({"errors": errors
                    .iter()
                    .map(|e| json!({
                        "type": e.kind,
                        "loc": e.loc.iter().map(|l| match l {
                            Loc::Key(k) => json!(k),
                            Loc::Index(i) => json!(i),
                        }).collect::<Vec<_>>(),
                        "msg": e.msg,
                    }))
                    .collect::<Vec<_>>()}),
                    Err(other) => panic!("{other:?}"),
                }
            }
        };
        assert_eq!(got, case["outcome"], "{}", case["body"]);
    }
}

#[test]
fn answers_build_the_response_model() {
    for case in doc()["answers"].as_array().unwrap() {
        let got = construct_star(
            &MCP_RESPONSE,
            "app.integrations.copilot_mcp.schema.copilot_mcp.MCPQueryResponse",
            &from_json(&case["answer"]),
        );
        let got = match got {
            Ok(dump) => json!({"ok": as_json(&dump)}),
            Err(e) => {
                let class = match &e {
                    PyExc::Validation(_) => "ValidationError",
                    PyExc::TypeError(_) => "TypeError",
                    other => panic!("{other:?}"),
                };
                json!({"error": {"class": class, "text": e.text()}})
            }
        };
        assert_eq!(got, case["outcome"], "{}", case["answer"]);
    }
}
