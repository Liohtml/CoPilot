//! The catalogs pinned to Python's own lists (`startup_vectors.json`,
//! `scripts/gen-startup-vectors.py`).

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use copilot_core::env::EnvFile;

use crate::catalog::*;
use crate::markdown;
use crate::templates::BUILTIN_TEMPLATES;

fn vectors() -> Value {
    serde_json::from_str(include_str!("startup_vectors.json")).expect("startup vectors")
}

fn accepts_word(a: Accepts) -> &'static str {
    match a {
        Accepts::HostOnly => "host_only",
        Accepts::ApiKey => "api_key",
        Accepts::UsernamePassword => "username_password",
        Accepts::File => "file",
    }
}

fn row_json(r: &ConnectorRow) -> Value {
    json!({
        "connector_name": r.name,
        "connector_type": r.kind,
        "connector_url": r.url,
        "connector_username": r.username,
        "connector_password": r.password,
        "connector_api_key": r.api_key,
        "connector_description": r.description,
        "connector_supports": r.supports,
        "connector_configured": true,
        "connector_verified": r.verified,
        "connector_accepts_host_only": r.accepts_host_only,
        "connector_accepts_api_key": r.accepts_api_key,
        "connector_accepts_username_password": r.accepts_username_password,
        "connector_accepts_file": r.accepts_file,
        "connector_accepts_extra_data": r.accepts_extra_data,
        "connector_extra_data": r.extra_data,
    })
}

#[test]
fn connectors_are_pythons_list_and_rows() {
    let v = vectors();
    let list = v["connectors"].as_array().unwrap();
    assert_eq!(list.len(), CONNECTORS.len());
    let env_text: String = v["connector_env"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, val)| format!("{k}={}\n", val.as_str().unwrap()))
        .collect();
    let unset = EnvFile::isolated("");
    let set = EnvFile::isolated(&env_text);
    for (spec, c) in CONNECTORS.iter().zip(list) {
        assert_eq!(
            json!([
                spec.name,
                spec.kind,
                accepts_word(spec.accepts),
                spec.description,
                spec.extra_data_key
            ]),
            c["args"],
            "{}",
            spec.name
        );
        assert_eq!(row_json(&spec.row(&unset)), c["row_unset"], "{}", spec.name);
        assert_eq!(row_json(&spec.row(&set)), c["row_set"], "{}", spec.name);
    }
    assert_eq!(json!(DELETED_CONNECTORS), v["deleted_connectors"]);
}

#[test]
fn roles_buckets_jobs_and_users_are_pythons() {
    let v = vectors();
    let roles: Vec<Value> = ROLES.iter().map(|(i, n, d)| json!([i, n, d])).collect();
    assert_eq!(Value::Array(roles), v["roles"]);
    assert_eq!(json!(BUCKETS), v["buckets"]);
    let jobs: Vec<Value> = KNOWN_JOBS
        .iter()
        .map(|j| {
            json!({
                "job_id": j.job_id,
                "time_interval": j.time_interval,
                "enabled": true,
                "job_description": j.description,
                "last_success": null,
            })
        })
        .collect();
    assert_eq!(Value::Array(jobs), v["jobs"]);
    for (key, u) in [("admin", ADMIN_USER), ("scheduler", SCHEDULER_USER)] {
        assert_eq!(
            json!({
                "username": u.username,
                "email": u.email,
                "role_id": u.role_id,
                "password_length": u.password_length,
            }),
            v["users"][key]
        );
    }
    assert_eq!(
        v["password_classes"],
        json!([
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789",
            "@$!%*?&#"
        ])
    );
    assert_eq!(v["placeholder"], json!(NO_INSTRUCTIONS));
}

#[test]
fn every_known_job_can_be_handed_over() {
    // `initialize_job_metadata` re-enables a job it knows only when the job
    // is not in RUST_CAPABLE_JOBS; every known job is, so no start re-enables
    // a row (and the port never needs that branch).
    let src = include_str!("../../../backend/app/schedulers/handover.py");
    for j in KNOWN_JOBS {
        assert!(
            src.contains(&format!("    \"{}\",\n", j.job_id)),
            "{}",
            j.job_id
        );
    }
}

fn sha(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

#[test]
fn catalogs_and_instructions_are_pythons() {
    let v = vectors();
    for (items, key, details) in [
        (
            INTEGRATIONS,
            "integrations",
            markdown::integration_details as fn(&str) -> Option<&'static str>,
        ),
        (
            NETWORK_CONNECTORS,
            "network_connectors",
            markdown::network_connector_details,
        ),
    ] {
        let expected = v[key].as_array().unwrap();
        assert_eq!(items.len(), expected.len(), "{key}");
        for ((name, description), e) in items.iter().zip(expected) {
            assert_eq!(e["name"], json!(name));
            assert_eq!(e["description"], json!(description));
            assert_eq!(
                e["file"],
                json!(format!("{}.md", markdown::file_stem(name)))
            );
            let text = details(name).unwrap_or(NO_INSTRUCTIONS);
            assert_eq!(e["found"], json!(details(name).is_some()), "{name}");
            assert_eq!(e["details_sha256"], json!(sha(text)), "{name}");
            assert_eq!(e["details_len"], json!(text.chars().count()), "{name}");
        }
    }
    let pairs =
        |p: &[(&str, &str)]| json!(p.iter().map(|(a, b)| json!([a, b])).collect::<Vec<_>>());
    assert_eq!(pairs(INTEGRATION_AUTH_KEYS), v["integration_auth_keys"]);
    assert_eq!(
        pairs(NETWORK_CONNECTOR_AUTH_KEYS),
        v["network_connector_auth_keys"]
    );
}

#[test]
fn templates_and_portal_defaults_are_pythons() {
    let v = vectors();
    let templates: Vec<Value> = BUILTIN_TEMPLATES
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "trigger": t.trigger,
                "format": t.format,
                "subject_template": t.subject_template,
                "body_template": t.body_template,
            })
        })
        .collect();
    assert_eq!(Value::Array(templates), v["templates"]);
    assert_eq!(
        v["portal_defaults"],
        json!({"title": "CoPilot", "logo_base64": null, "logo_mime_type": null, "brand_color": null})
    );
}
