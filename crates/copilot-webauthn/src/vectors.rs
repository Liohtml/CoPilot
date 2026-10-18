//! `webauthn_vectors.json` (`scripts/gen-webauthn-vectors.py`): py_webauthn
//! 2.8 / cbor2 / CoPilot's origin helpers, case by case.

use serde_json::Value;

use copilot_auth::pybase64::{base64url_to_bytes, bytes_to_base64url};

use crate::options::{StoredCredential, authentication_options, registration_options};
use crate::{
    Failure, RelyingParty, cbor, device_name, registration_transports, verify_authentication,
    verify_registration,
};

const VECTORS: &str = include_str!("webauthn_vectors.json");

fn doc() -> Value {
    serde_json::from_str(VECTORS).expect("vectors parse")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn b64(s: &Value) -> Vec<u8> {
    base64url_to_bytes(s.as_str().expect("str")).expect("b64")
}

/// Compare a Rust outcome with the recorded Python one; `None` on a match.
fn mismatch(case: &Value, got: Result<Value, Failure>) -> Option<String> {
    let name = case["name"].as_str().unwrap_or("?");
    let outcome = &case["outcome"];
    let differs = case["message_differs"].as_bool().unwrap_or(false);
    let ok = match (
        outcome
            .as_object()
            .and_then(|o| o.keys().next())
            .map(String::as_str),
        &got,
    ) {
        (Some("ok"), Ok(value)) => *value == outcome["ok"],
        (Some("rejected"), Err(Failure::Rejected(m))) => differs || outcome["rejected"] == *m,
        (Some("internal"), Err(Failure::Internal(_))) => true,
        _ => false,
    };
    (!ok).then(|| format!("{name}: python {outcome} / rust {got:?}"))
}

#[test]
fn base64url_matches_python() {
    for case in doc()["base64url"].as_array().unwrap() {
        let got = base64url_to_bytes(case["input"].as_str().unwrap());
        match case.get("bytes") {
            Some(bytes) => assert_eq!(hex(&got.unwrap()), bytes.as_str().unwrap(), "{case}"),
            None => assert_eq!(
                got.unwrap_err().to_string(),
                case["error"].as_str().unwrap()
            ),
        }
    }
}

#[test]
fn cbor_matches_cbor2() {
    for case in doc()["cbor"].as_array().unwrap() {
        let input = unhex(case["input"].as_str().unwrap());
        let decoded = cbor::decode(&input);
        if case.get("decode_error").is_some() {
            assert!(decoded.is_err(), "{case}");
            continue;
        }
        let encoded = cbor::encode(&decoded.expect("decodes"));
        match case.get("encoded") {
            Some(e) => assert_eq!(hex(&encoded.unwrap()), e.as_str().unwrap(), "{case}"),
            None => assert!(encoded.is_err(), "{case}"),
        }
    }
}

#[test]
fn registration_matches_py_webauthn() {
    let d = doc();
    let (rp_id, origin) = (d["rp_id"].as_str().unwrap(), d["origin"].as_str().unwrap());
    let mut failures = Vec::new();
    for case in d["registration"].as_array().unwrap() {
        let credential = &case["credential"];
        let got = verify_registration(credential, &b64(&case["challenge"]), rp_id, origin)
            .and_then(|r| {
                Ok(serde_json::json!({
                    "credential_id": bytes_to_base64url(&r.credential_id),
                    "public_key": bytes_to_base64url(&r.public_key),
                    "sign_count": r.sign_count,
                    "transports": registration_transports(credential)?,
                }))
            });
        failures.extend(mismatch(case, got));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn authentication_matches_py_webauthn() {
    let d = doc();
    let (rp_id, origin) = (d["rp_id"].as_str().unwrap(), d["origin"].as_str().unwrap());
    let mut failures = Vec::new();
    for case in d["authentication"].as_array().unwrap() {
        let got = verify_authentication(
            &case["credential"],
            &b64(&case["challenge"]),
            rp_id,
            origin,
            &b64(&case["public_key"]),
            case["sign_count"].as_u64().unwrap() as u32,
        )
        .map(|n| serde_json::json!({"new_sign_count": n}));
        failures.extend(mismatch(case, got));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn origins_match_copilot() {
    let mut failures = Vec::new();
    for group in doc()["origins"].as_array().unwrap() {
        let env = &group["env"];
        let var = |k: &str| env.get(k).and_then(Value::as_str);
        let rp = RelyingParty::from_env(
            var("WEBAUTHN_ORIGINS"),
            var("WEBAUTHN_ORIGIN"),
            var("WEBAUTHN_RP_ID"),
            var("WEBAUTHN_RP_NAME"),
        );
        assert_eq!(
            rp.is_configured(),
            Ok(group["configured"].as_bool().unwrap()),
            "{env}"
        );
        assert_eq!(rp.rp_name(), group["rp_name"].as_str().unwrap(), "{env}");
        for row in group["requests"].as_array().unwrap() {
            let got = match rp.resolve_request_origin(row["request"].as_str()) {
                Err(e) => serde_json::json!({"request": row["request"], "error": e}),
                Ok(resolved) => serde_json::json!({
                    "request": row["request"],
                    "resolved": resolved,
                    "rp_id": rp.rp_id_for_origin(&resolved).unwrap(),
                    "ensure": rp.ensure_passkey_origin(&resolved).err(),
                }),
            };
            if got != *row {
                failures.push(format!("{env}: python {row} / rust {got}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn options_match_py_webauthn() {
    let d = doc();
    let o = &d["options"];
    let challenge = b64(&o["challenge"]);
    let stored: Vec<StoredCredential> = o["stored"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| StoredCredential {
            credential_id: s["credential_id"].as_str().unwrap().into(),
            transports: s["transports"].clone(),
        })
        .collect();
    let reg = registration_options(
        "localhost",
        "SOCFortress CoPilot",
        7,
        "alice",
        &challenge,
        &stored,
    )
    .unwrap();
    assert_eq!(Value::Object(reg), o["registration"]);
    let empty = registration_options("example.com", "Acme", 12, "bob", &challenge, &[]).unwrap();
    assert_eq!(Value::Object(empty), o["registration_empty"]);
    let auth = authentication_options("localhost", &challenge, &stored).unwrap();
    assert_eq!(Value::Object(auth), o["authentication"]);
    let anon = authentication_options("localhost", &challenge, &[]).unwrap();
    assert_eq!(Value::Object(anon), o["authentication_usernameless"]);
    // Key order is part of the JSON the browser receives.
    let keys: Vec<&String> = o["registration"].as_object().unwrap().keys().collect();
    let reg = registration_options(
        "localhost",
        "SOCFortress CoPilot",
        7,
        "alice",
        &challenge,
        &stored,
    )
    .unwrap();
    assert_eq!(reg.keys().collect::<Vec<_>>(), keys);
}

#[test]
fn device_names_match_routes() {
    for case in doc()["device_names"].as_array().unwrap() {
        assert_eq!(
            device_name(case["input"].as_str()),
            case["output"].as_str().unwrap(),
            "{case}"
        );
    }
}
