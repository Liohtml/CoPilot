//! HS256 session tokens, interchangeable with the Python backend's
//! (`app/auth/utils.py`: PyJWT 2.x).
//!
//! Implemented directly on `hmac` + `sha2` (the primitives Talon already
//! uses) rather than a JWT crate, so every rule is PyJWT's: the header must
//! be a JSON object naming `alg: HS256` (a non-string `kid` is refused), the
//! signature is compared in constant time, the payload must be a JSON
//! object. Registered claims are then validated so the outcome matches PyJWT
//! exactly:
//! leeway 0, no required claims (a token without `exp` never expires), the
//! order `iat` → `nbf` → `exp`, `exp <= now` is expired, a non-integer time
//! claim or a non-string `sub` is invalid, and a token carrying `aud` is
//! invalid because the backend never configures an audience.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::alphabet::URL_SAFE;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

use copilot_core::config::Secret;
use copilot_core::roles::scopes_for_role_name;

/// Why a token was not accepted. The `Display` strings are the details the
/// Python backend sends.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// `exp` is in the past.
    #[error("Expired signature")]
    Expired,
    /// Bad signature, malformed token, bad claim types, …
    #[error("Invalid token")]
    Invalid,
    /// The short-lived token `/auth/token` issues while 2FA is outstanding.
    #[error(
        "Two-factor authentication required. Complete 2FA verification to obtain a session token."
    )]
    TwoFactorPending,
    /// The token decoded but carries no `sub` (Python: an uncaught `KeyError`).
    #[error("Token has no subject")]
    MissingSubject,
}

/// The claims CoPilot reads from a session token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClaims {
    /// `sub`: the username.
    pub subject: String,
    /// `scopes`: the role snapshot taken when the token was issued.
    pub scopes: Vec<String>,
}

type HmacSha256 = Hmac<Sha256>;

/// PyJWT's `base64url_decode`: padding optional; encoding never pads.
const B64: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Encodes and decodes CoPilot JWTs with the shared secret.
#[derive(Clone)]
pub struct JwtCodec {
    key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for JwtCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtCodec").finish_non_exhaustive()
    }
}

fn now_secs_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// PyJWT's `int(payload[claim])`: integers, floats (truncated) and decimal
/// strings are accepted; anything else is a `ValueError` → invalid.
fn int_claim(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => n.as_i64().or_else(|| {
            n.as_f64()
                .filter(|f| f.is_finite())
                .map(|f| f.trunc() as i64)
        }),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        Value::Bool(b) => Some(i64::from(*b)),
        _ => None,
    }
}

impl JwtCodec {
    /// Build from the shared secret (used as raw UTF-8 bytes, like PyJWT).
    pub fn new(secret: &Secret) -> Self {
        Self {
            key: Zeroizing::new(secret.expose().as_bytes().to_vec()),
        }
    }

    /// Decode and validate a session token (`AuthHandler.decode_token`).
    pub fn decode_session(&self, token: &str) -> Result<SessionClaims, TokenError> {
        let claims = self.decode_claims(token)?;
        if claims.get("type").and_then(Value::as_str) == Some("2fa_pending") {
            return Err(TokenError::TwoFactorPending);
        }
        let subject = match claims.get("sub") {
            Some(Value::String(s)) => s.clone(),
            Some(_) => return Err(TokenError::Invalid),
            None => return Err(TokenError::MissingSubject),
        };
        let scopes = match claims.get("scopes") {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        };
        Ok(SessionClaims { subject, scopes })
    }

    /// Signature + registered-claim validation; returns the raw claims.
    pub fn decode_claims(&self, token: &str) -> Result<Map<String, Value>, TokenError> {
        let claims = self.verify_signature(token).ok_or(TokenError::Invalid)?;
        validate_registered_claims(&claims, now_secs_f64())?;
        Ok(claims)
    }

    fn mac(&self) -> Option<HmacSha256> {
        HmacSha256::new_from_slice(&self.key).ok()
    }

    /// Header, signature and payload shape (PyJWT `api_jws` + `api_jwt`).
    fn verify_signature(&self, token: &str) -> Option<Map<String, Value>> {
        let (signing_input, signature) = token.rsplit_once('.')?;
        let (header_b64, payload_b64) = signing_input.split_once('.')?;
        if payload_b64.contains('.') {
            return None;
        }
        let header: Value = serde_json::from_slice(&B64.decode(header_b64).ok()?).ok()?;
        let header = header.as_object()?;
        if header.get("alg").and_then(Value::as_str) != Some("HS256") {
            return None;
        }
        if header.get("kid").is_some_and(|k| !k.is_string()) {
            return None;
        }
        let signature = B64.decode(signature).ok()?;
        let mut mac = self.mac()?;
        mac.update(signing_input.as_bytes());
        mac.verify_slice(&signature).ok()?;
        match serde_json::from_slice::<Value>(&B64.decode(payload_b64).ok()?).ok()? {
            Value::Object(claims) => Some(claims),
            _ => None,
        }
    }

    /// Issue a session token (`AuthHandler.encode_token`) for a user whose
    /// role name is `role`. `extra` claims are merged last, like Python's
    /// `extra_claims` (`customer_codes` for portal users).
    pub fn encode_session(
        &self,
        username: &str,
        role: &str,
        ttl: Duration,
        extra: Option<Map<String, Value>>,
    ) -> Result<String, TokenError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut claims = Map::new();
        claims.insert("exp".into(), Value::from(now.saturating_add(ttl.as_secs())));
        claims.insert("iat".into(), Value::from(now));
        claims.insert("sub".into(), Value::from(username));
        claims.insert("scopes".into(), Value::from(scopes_for_role_name(role)));
        if let Some(extra) = extra {
            claims.extend(extra);
        }
        self.encode_claims(&claims)
    }

    /// Sign arbitrary claims with HS256 (`{"alg":"HS256","typ":"JWT"}`).
    pub fn encode_claims(&self, claims: &Map<String, Value>) -> Result<String, TokenError> {
        let header = B64.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = serde_json::to_vec(claims).map_err(|_| TokenError::Invalid)?;
        let signing_input = format!("{header}.{}", B64.encode(payload));
        let mut mac = self.mac().ok_or(TokenError::Invalid)?;
        mac.update(signing_input.as_bytes());
        let signature = B64.encode(mac.finalize().into_bytes());
        Ok(format!("{signing_input}.{signature}"))
    }
}

/// PyJWT `_validate_claims` with leeway 0 and no required claims.
fn validate_registered_claims(claims: &Map<String, Value>, now: f64) -> Result<(), TokenError> {
    if let Some(iat) = claims.get("iat") {
        let iat = int_claim(iat).ok_or(TokenError::Invalid)?;
        if (iat as f64) > now {
            return Err(TokenError::Invalid);
        }
    }
    if let Some(nbf) = claims.get("nbf") {
        let nbf = int_claim(nbf).ok_or(TokenError::Invalid)?;
        if (nbf as f64) > now {
            return Err(TokenError::Invalid);
        }
    }
    if let Some(exp) = claims.get("exp") {
        let exp = int_claim(exp).ok_or(TokenError::Invalid)?;
        if (exp as f64) <= now {
            return Err(TokenError::Expired);
        }
    }
    if claims.contains_key("aud") {
        return Err(TokenError::Invalid);
    }
    if claims.get("jti").is_some_and(|jti| !jti.is_string()) {
        return Err(TokenError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn codec() -> JwtCodec {
        JwtCodec::new(&Secret::new("unit-test-secret"))
    }

    fn sign(claims: Value) -> String {
        codec().encode_claims(claims.as_object().unwrap()).unwrap()
    }

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn round_trip_responder_scopes() {
        let token = codec()
            .encode_session("alice", "responder", Duration::from_secs(60), None)
            .unwrap();
        let claims = codec().decode_session(&token).unwrap();
        assert_eq!(claims.subject, "alice");
        assert_eq!(claims.scopes, vec!["responder", "analyst"]);
    }

    #[test]
    fn expired_and_two_factor() {
        let expired = sign(json!({"sub": "a", "exp": now() - 1}));
        assert_eq!(codec().decode_session(&expired), Err(TokenError::Expired));
        let at_now = sign(json!({"sub": "a", "exp": now()}));
        assert_eq!(codec().decode_session(&at_now), Err(TokenError::Expired));
        let pending = sign(json!({"sub": "a", "exp": now() + 300, "type": "2fa_pending"}));
        assert_eq!(
            codec().decode_session(&pending),
            Err(TokenError::TwoFactorPending)
        );
        // PyJWT checks expiry before the caller looks at `type`.
        let old_pending = sign(json!({"sub": "a", "exp": now() - 5, "type": "2fa_pending"}));
        assert_eq!(
            codec().decode_session(&old_pending),
            Err(TokenError::Expired)
        );
    }

    #[test]
    fn pyjwt_claim_rules() {
        // No exp: valid forever.
        assert!(codec().decode_session(&sign(json!({"sub": "a"}))).is_ok());
        // iat in the future: immature → invalid.
        let future = sign(json!({"sub": "a", "iat": now() + 120}));
        assert_eq!(codec().decode_session(&future), Err(TokenError::Invalid));
        // Future iat wins over past exp (iat is checked first).
        let both = sign(json!({"sub": "a", "iat": now() + 120, "exp": now() - 1}));
        assert_eq!(codec().decode_session(&both), Err(TokenError::Invalid));
        let bad_exp = sign(json!({"sub": "a", "exp": "soon"}));
        assert_eq!(codec().decode_session(&bad_exp), Err(TokenError::Invalid));
        let str_exp = sign(json!({"sub": "a", "exp": (now() + 60).to_string()}));
        assert!(codec().decode_session(&str_exp).is_ok());
        let int_sub = sign(json!({"sub": 7}));
        assert_eq!(codec().decode_session(&int_sub), Err(TokenError::Invalid));
        let aud = sign(json!({"sub": "a", "aud": "x"}));
        assert_eq!(codec().decode_session(&aud), Err(TokenError::Invalid));
        let no_sub = sign(json!({"exp": now() + 60}));
        assert_eq!(
            codec().decode_session(&no_sub),
            Err(TokenError::MissingSubject)
        );
    }

    #[test]
    fn wrong_secret_or_algorithm_is_invalid() {
        let other = JwtCodec::new(&Secret::new("different"));
        let token = other
            .encode_session("a", "admin", Duration::from_secs(60), None)
            .unwrap();
        assert_eq!(codec().decode_session(&token), Err(TokenError::Invalid));
        assert_eq!(
            codec().decode_session("not.a.jwt"),
            Err(TokenError::Invalid)
        );
        // alg=none must never be accepted.
        let none = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhIn0.";
        assert_eq!(codec().decode_session(none), Err(TokenError::Invalid));
    }

    #[test]
    fn accepts_a_pyjwt_token() {
        // jwt.encode({"sub": "alice", "scopes": ["analyst"], "exp": 4102444800,
        //             "iat": 1700000000}, "unit-test-secret", algorithm="HS256")
        let python = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInNjb3BlcyI6WyJhbmFseXN0Il0sImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwfQ.kUDZRyIGhljVURq6IJomQgG_GPhjx4Id5H8lpHe7yYY";
        let claims = codec().decode_session(python).unwrap();
        assert_eq!(claims.subject, "alice");
        assert_eq!(claims.scopes, vec!["analyst"]);
    }

    #[test]
    fn header_rules_follow_pyjwt() {
        let c = codec();
        let token = sign(json!({"sub": "a"}));
        let (_, rest) = token.split_once('.').unwrap();
        // HS512 header with an otherwise valid shape: refused.
        let hs512 = format!("{}.{rest}", B64.encode(br#"{"alg":"HS512","typ":"JWT"}"#));
        assert_eq!(c.decode_session(&hs512), Err(TokenError::Invalid));
        // Tampered payload: signature mismatch.
        let parts: Vec<&str> = token.split('.').collect();
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            B64.encode(br#"{"sub":"admin"}"#),
            parts[2]
        );
        assert_eq!(c.decode_session(&forged), Err(TokenError::Invalid));
        // A padded signature is accepted, as PyJWT's base64url_decode does
        // (the header and payload are signed as sent, so only the last segment
        // can carry padding without breaking the signature).
        let pad = |seg: &str| format!("{seg}{}", "=".repeat((4 - seg.len() % 4) % 4));
        let padded = format!("{}.{}.{}", parts[0], parts[1], pad(parts[2]));
        assert_eq!(c.decode_session(&padded).unwrap().subject, "a");
        // Non-object payload.
        let list_payload = {
            let header = B64.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
            let input = format!("{header}.{}", B64.encode(b"[1,2]"));
            let mut mac = c.mac().unwrap();
            mac.update(input.as_bytes());
            format!("{input}.{}", B64.encode(mac.finalize().into_bytes()))
        };
        assert_eq!(c.decode_session(&list_payload), Err(TokenError::Invalid));
        assert_eq!(c.decode_session("a.b"), Err(TokenError::Invalid));
        assert_eq!(c.decode_session("a.b.c.d"), Err(TokenError::Invalid));
    }

    #[test]
    fn extra_claims_and_missing_scopes() {
        let mut extra = Map::new();
        extra.insert("customer_codes".into(), json!(["acme"]));
        let token = codec()
            .encode_session("p", "customer_user", Duration::from_secs(60), Some(extra))
            .unwrap();
        let raw = codec().decode_claims(&token).unwrap();
        assert_eq!(raw["customer_codes"], json!(["acme"]));
        let unscoped = sign(json!({"sub": "a"}));
        assert!(codec().decode_session(&unscoped).unwrap().scopes.is_empty());
    }
}
