//! Encryption of WAF service tokens at rest — port of
//! `app/customer_waf/services/crypto.py`.
//!
//! A `wafst_…` token is a bearer credential CoPilot has to *send*, so it is
//! Fernet-encrypted (not hashed) with `WAF_TOKEN_ENCRYPTION_KEY` — a key of
//! its own with **no fallback**: not `TOTP_ENCRYPTION_KEY`, not derived from
//! `JWT_SECRET`, so rotating either can never strand the stored WAF tokens.
//! Without the key, saving a WAF is refused; a rotated key makes stored
//! tokens undecryptable, which is reported as its own error (409, "re-enter
//! the token"), never as a WAF authentication failure.
//!
//! Nothing here logs a token or its ciphertext.

use copilot_auth::Fernet;
use copilot_core::config::Secret;
use copilot_web::form::py_strip;

/// The environment variable.
pub const KEY_ENV_VAR: &str = "WAF_TOKEN_ENCRYPTION_KEY";
/// What every service token starts with.
pub const TOKEN_PREFIX: &str = "wafst_";
/// Characters of a token shown in the UI (then `...`).
pub const DISPLAY_PREFIX_LENGTH: usize = 12;

const KEY_GENERATE_HINT: &str = "Generate one with: python -c \"from cryptography.fernet import \
                                 Fernet; print(Fernet.generate_key().decode())\"";

/// `WafTokenCryptoError` and its subclasses: the route answers `status` with
/// `{"detail": message, "reason": "token_crypto", "success": false}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoError {
    /// The class (`WafKeyNotConfiguredError`, …), for logs and tests.
    pub kind: &'static str,
    /// `str(e)`.
    pub message: String,
    /// `status_code`.
    pub status: u16,
}

impl CryptoError {
    fn new(kind: &'static str, message: String, status: u16) -> Self {
        Self {
            kind,
            message,
            status,
        }
    }
}

/// `_fernet()` for the configured value (`os.environ.get(KEY_ENV_VAR)`).
pub fn fernet(raw: Option<&Secret>) -> Result<Fernet, CryptoError> {
    let raw = raw.map(|s| py_strip(s.expose())).unwrap_or_default();
    if raw.is_empty() || raw == "REPLACE_ME" {
        return Err(CryptoError::new(
            "WafKeyNotConfiguredError",
            format!(
                "{KEY_ENV_VAR} is not set, so WAF tokens cannot be stored or used. \
                 {KEY_GENERATE_HINT}"
            ),
            400,
        ));
    }
    Fernet::new(raw).map_err(|_| {
        CryptoError::new(
            "WafKeyMalformedError",
            format!(
                "{KEY_ENV_VAR} is malformed: expected a 32-byte url-safe base64 Fernet key (44 \
                 characters ending in '='). {KEY_GENERATE_HINT}"
            ),
            400,
        )
    })
}

/// `key_configured()`.
pub fn key_configured(raw: Option<&Secret>) -> bool {
    fernet(raw).is_ok()
}

/// `normalize_token`: the pasted token, trimmed, if it is a service token.
pub fn normalize_token(token: &str) -> Result<String, CryptoError> {
    let token = py_strip(token);
    if !token.starts_with(TOKEN_PREFIX) || token.chars().count() <= TOKEN_PREFIX.len() {
        return Err(CryptoError::new(
            "InvalidWafTokenError",
            format!(
                "Not a WAF service token: expected a value starting with '{TOKEN_PREFIX}' (WAF → \
                 Service Tokens). WAF login tokens and site API keys don't work here."
            ),
            400,
        ));
    }
    Ok(token.to_string())
}

/// `display_prefix`.
pub fn display_prefix(token: &str) -> String {
    let head: String = token.chars().take(DISPLAY_PREFIX_LENGTH).collect();
    format!("{head}...")
}

/// `encrypt_token` (normalizes again, as Python does).
pub fn encrypt_token(raw_key: Option<&Secret>, token: &str) -> Result<String, CryptoError> {
    let f = fernet(raw_key)?;
    let token = normalize_token(token)?;
    Ok(f.encrypt(token.as_bytes()))
}

/// `decrypt_token`.
pub fn decrypt_token(raw_key: Option<&Secret>, ciphertext: &str) -> Result<String, CryptoError> {
    let f = fernet(raw_key)?;
    let plain = f.decrypt(ciphertext).ok_or_else(|| {
        CryptoError::new(
            "WafTokenUndecryptableError",
            format!(
                "The stored WAF token can't be decrypted — {KEY_ENV_VAR} has changed since it \
                 was saved. Re-enter the token for this WAF."
            ),
            409,
        )
    })?;
    // `.decode()` of a token CoPilot encrypted: always UTF-8; anything else
    // is a `UnicodeDecodeError` nobody catches.
    String::from_utf8(plain).map_err(|_| {
        CryptoError::new(
            "UnicodeDecodeError",
            "'utf-8' codec can't decode the stored token".into(),
            500,
        )
    })
}
