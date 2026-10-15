//! # copilot-webauthn — passkeys as CoPilot's py_webauthn calls verify them
//!
//! Port of what `app/auth/services/passkey.py` gets from py_webauthn 2.8:
//! the registration and authentication ceremonies ([`verify`]), the options
//! the browser receives ([`options`]) and the origin / RP-ID rules
//! ([`origin`]). Underneath: `cbor2`-compatible CBOR ([`cbor`]), the
//! credential parsers ([`parse`]) and COSE / certificate keys with the
//! signature checks cryptography performs ([`keys`]).
//!
//! py_webauthn does not type-check what the authenticator and the browser
//! send, and CoPilot reports its exceptions by type: an
//! `InvalidRegistrationResponse` / `InvalidAuthenticationResponse` or any
//! `ValueError` becomes the route's 400 / 401 with the exception's text,
//! anything else escapes as a 500. [`Failure`] keeps that split, and
//! `webauthn_vectors.json` (`scripts/gen-webauthn-vectors.py`) pins both the
//! split and the texts against the Python library.

#![warn(missing_docs)]

pub mod cbor;
pub mod keys;
pub mod options;
pub mod origin;
pub mod parse;
pub mod verify;

pub use origin::RelyingParty;
pub use verify::{Registration, verify_authentication, verify_registration};

/// A ceremony that did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The detail CoPilot returns (400 when registering, 401 at login).
    Rejected(String),
    /// An exception CoPilot lets through — a 500. The name is Python's
    /// exception type, for the log.
    Internal(&'static str),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Rejected(message) => f.write_str(message),
            Failure::Internal(kind) => write!(f, "unhandled {kind}"),
        }
    }
}

/// `"(name or "Passkey").strip()[:128] or "Passkey"` — the routes' device
/// name.
pub fn device_name(name: Option<&str>) -> String {
    let name = name.filter(|n| !n.is_empty()).unwrap_or("Passkey");
    let stripped =
        name.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c));
    let cut: String = stripped.chars().take(128).collect();
    if cut.is_empty() {
        "Passkey".into()
    } else {
        cut
    }
}

/// The `transports` CoPilot stores for a new passkey:
/// `list(credential.get("response", {}).get("transports") or [])`, taken
/// from the request as sent (a string becomes its characters, an object its
/// keys; `true` or a number is a `TypeError`).
pub fn registration_transports(
    credential: &serde_json::Value,
) -> Result<serde_json::Value, Failure> {
    use serde_json::Value;
    let value = credential
        .get("response")
        .and_then(|r| r.get("transports"))
        .unwrap_or(&Value::Null);
    Ok(Value::Array(match value {
        Value::Null | Value::Bool(false) => Vec::new(),
        Value::Number(n) if n.as_f64() == Some(0.0) => Vec::new(),
        Value::Array(items) => items.clone(),
        Value::String(s) => s.chars().map(|c| Value::String(c.to_string())).collect(),
        Value::Object(map) => map.keys().cloned().map(Value::String).collect(),
        Value::Bool(true) | Value::Number(_) => return Err(Failure::Internal("TypeError")),
    }))
}

#[cfg(test)]
mod vectors;
