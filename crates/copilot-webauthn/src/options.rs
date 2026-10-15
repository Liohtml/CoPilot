//! `generate_registration_options` / `generate_authentication_options`
//! through `options_to_json`, with CoPilot's arguments: the default
//! algorithms, a 60 s timeout, attestation `none`, resident key and user
//! verification `preferred`, and the user's stored credentials as
//! `excludeCredentials` / `allowCredentials`.

use serde_json::{Map, Value, json};

use copilot_auth::pybase64::{base64url_to_bytes, bytes_to_base64url};

use crate::verify::SUPPORTED_ALGS;

/// `AuthenticatorTransport` values.
const TRANSPORTS: [&str; 7] = [
    "usb",
    "nfc",
    "ble",
    "smart-card",
    "internal",
    "cable",
    "hybrid",
];

/// A stored credential as `_credential_descriptor` reads it.
#[derive(Debug, Clone)]
pub struct StoredCredential {
    /// `user_passkey.credential_id` (base64url).
    pub credential_id: String,
    /// `user_passkey.transports` (a JSON column).
    pub transports: Value,
}

/// Why options could not be built: a `ValueError` (the route's 400) or an
/// unexpected failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionsError {
    /// `ValueError(text)`.
    Value(String),
    /// Anything else (a 500).
    Internal(&'static str),
}

/// `PublicKeyCredentialDescriptor` as JSON: known transports only, omitted
/// when none remain.
fn descriptor(stored: &StoredCredential) -> Result<Value, OptionsError> {
    let id = base64url_to_bytes(&stored.credential_id)
        .map_err(|e| OptionsError::Value(e.to_string()))?;
    let candidates: Vec<Value> = match &stored.transports {
        Value::Null | Value::Bool(false) => Vec::new(),
        Value::Array(items) => items.clone(),
        Value::Object(map) => map.keys().cloned().map(Value::String).collect(),
        Value::String(s) => s.chars().map(|c| Value::String(c.to_string())).collect(),
        Value::Number(n) if n.as_f64() == Some(0.0) => Vec::new(),
        _ => return Err(OptionsError::Internal("TypeError")),
    };
    let known: Vec<Value> = candidates
        .into_iter()
        .filter(|t| t.as_str().is_some_and(|t| TRANSPORTS.contains(&t)))
        .collect();
    let mut out = Map::new();
    out.insert("id".into(), Value::from(bytes_to_base64url(&id)));
    out.insert("type".into(), Value::from("public-key"));
    if !known.is_empty() {
        out.insert("transports".into(), Value::Array(known));
    }
    Ok(Value::Object(out))
}

fn descriptors(stored: &[StoredCredential]) -> Result<Vec<Value>, OptionsError> {
    stored.iter().map(descriptor).collect()
}

/// Registration options for `user_id` / `username` (the user id is
/// `str(user_id).encode()`).
pub fn registration_options(
    rp_id: &str,
    rp_name: &str,
    user_id: i64,
    username: &str,
    challenge: &[u8],
    exclude: &[StoredCredential],
) -> Result<Map<String, Value>, OptionsError> {
    if rp_id.is_empty() {
        return Err(OptionsError::Value(
            "rp_id cannot be an empty string".into(),
        ));
    }
    if rp_name.is_empty() {
        return Err(OptionsError::Value(
            "rp_name cannot be an empty string".into(),
        ));
    }
    if username.is_empty() {
        return Err(OptionsError::Value(
            "user_name cannot be an empty string".into(),
        ));
    }
    let exclude = descriptors(exclude)?;
    let params: Vec<Value> = SUPPORTED_ALGS
        .iter()
        .map(|alg| json!({"type": "public-key", "alg": alg}))
        .collect();
    let value = json!({
        "rp": {"name": rp_name, "id": rp_id},
        "user": {
            "id": bytes_to_base64url(user_id.to_string().as_bytes()),
            "name": username,
            "displayName": username,
        },
        "challenge": bytes_to_base64url(challenge),
        "pubKeyCredParams": params,
        "timeout": 60000,
        "excludeCredentials": exclude,
        "authenticatorSelection": {
            "residentKey": "preferred",
            "requireResidentKey": false,
            "userVerification": "preferred",
        },
        "attestation": "none",
    });
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(OptionsError::Internal("TypeError")),
    }
}

/// Authentication options; `allow` is empty for a username-less login.
pub fn authentication_options(
    rp_id: &str,
    challenge: &[u8],
    allow: &[StoredCredential],
) -> Result<Map<String, Value>, OptionsError> {
    if rp_id.is_empty() {
        return Err(OptionsError::Value(
            "rp_id cannot be an empty string".into(),
        ));
    }
    let allow = descriptors(allow)?;
    let value = json!({
        "challenge": bytes_to_base64url(challenge),
        "timeout": 60000,
        "rpId": rp_id,
        "allowCredentials": allow,
        "userVerification": "preferred",
    });
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(OptionsError::Internal("TypeError")),
    }
}
