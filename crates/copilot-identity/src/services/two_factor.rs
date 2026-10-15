//! TOTP 2FA — `app/auth/services/totp.py`.
//!
//! [`FactorError::Rejected`] is Python's `ValueError` (the routes turn it into
//! a 400, or a 401 at login); anything else is an unhandled failure (500).
//! The brute-force guard ([`crate::limiter`]) runs before every check that
//! can fail on a guess: validate, verify-setup, regenerate (and disable,
//! which validates first).

use serde_json::{Value, json};

use copilot_auth::fernet::Fernet;
use copilot_auth::password::hash_password;
use copilot_auth::totp::{self, Totp};
use copilot_db::totp::{self as db, BackupSpend, UserTotpRow};
use copilot_web::ApiError;

use crate::IdentityState;
use crate::limiter;
use crate::qr;
use crate::schema::{SecondFactor, SetupResponse};

/// Why a second-factor operation was refused.
#[derive(Debug)]
pub enum FactorError {
    /// Python's `ValueError(message)`.
    Rejected(String),
    /// Anything else (database, a secret that does not decrypt, …).
    Internal(ApiError),
}

impl From<copilot_db::DbError> for FactorError {
    fn from(e: copilot_db::DbError) -> Self {
        FactorError::Internal(e.into())
    }
}

fn rejected(message: &str) -> FactorError {
    FactorError::Rejected(message.to_string())
}

/// bcrypt 5's refusal of a long password (`checkpw`), seen by the user.
const BCRYPT_TOO_LONG: &str = "password cannot be longer than 72 bytes, truncate manually if necessary (e.g. my_password[:72])";

fn unix_now() -> u64 {
    limiter::now() as u64
}

fn check_limit(st: &IdentityState, user_id: i32) -> Result<(), FactorError> {
    st.limiter
        .check(user_id, limiter::now())
        .map_err(FactorError::Rejected)
}

fn fail(st: &IdentityState, user_id: i32, message: &str) -> FactorError {
    st.limiter.record_failure(user_id, limiter::now());
    rejected(message)
}

/// `_decrypt_secret` + `pyotp.TOTP(secret)`.
fn generator(fernet: &Fernet, row: &UserTotpRow) -> Result<Totp, FactorError> {
    let secret = fernet.decrypt(&row.secret_enc).ok_or_else(|| {
        FactorError::Internal(ApiError::internal(format!(
            "user_totp {}: secret does not decrypt (InvalidToken)",
            row.id
        )))
    })?;
    std::str::from_utf8(&secret)
        .ok()
        .and_then(Totp::new)
        .ok_or_else(|| {
            FactorError::Internal(ApiError::internal(format!(
                "user_totp {}: secret is not base32",
                row.id
            )))
        })
}

/// `is_2fa_enabled`.
pub async fn status(st: &IdentityState, user_id: i32) -> Result<bool, ApiError> {
    Ok(db::is_enabled(&st.ctx.db, user_id).await?)
}

/// `_generate_backup_codes`: plaintext codes and their stored form.
async fn backup_codes() -> Result<(Vec<String>, Value), FactorError> {
    tokio::task::spawn_blocking(|| {
        let codes = totp::generate_backup_codes();
        let mut stored = Vec::with_capacity(codes.len());
        for code in &codes {
            let hash = hash_password(code).map_err(|e| e.to_string())?;
            stored.push(json!({"hash": hash, "used": false}));
        }
        Ok::<_, String>((codes, Value::Array(stored)))
    })
    .await
    .map_err(|e| FactorError::Internal(ApiError::internal(e)))?
    .map_err(|e| FactorError::Internal(ApiError::internal(e)))
}

/// `setup_totp`: a new, not yet active secret with its QR code and codes.
pub async fn setup(
    st: &IdentityState,
    user_id: i32,
    username: &str,
) -> Result<SetupResponse, FactorError> {
    let secret = totp::random_base32();
    let secret_enc = st.fernet.encrypt(secret.as_bytes());
    let (codes, stored) = backup_codes().await?;
    let otpauth_url = totp::provisioning_uri(&secret, username);
    let qr_data_uri =
        qr::qr_data_uri(&otpauth_url).map_err(|e| FactorError::Internal(ApiError::internal(e)))?;
    if !db::save_setup(&st.ctx.db, user_id, &secret_enc, &stored).await? {
        return Err(rejected(
            "2FA is already enabled. Disable it first to reconfigure.",
        ));
    }
    tracing::info!(user_id, "2FA setup initiated");
    Ok(SetupResponse {
        secret,
        otpauth_url,
        qr_data_uri,
        backup_codes: codes,
        message: "Scan the QR code with your authenticator app, then verify with a code.",
    })
}

/// `verify_setup`: the first valid code activates 2FA.
pub async fn verify_setup(st: &IdentityState, user_id: i32, code: &str) -> Result<(), FactorError> {
    check_limit(st, user_id)?;
    let row = db::find(&st.ctx.db, user_id)
        .await?
        .ok_or_else(|| rejected("No 2FA setup found. Call setup first."))?;
    if row.enabled {
        return Err(rejected("2FA is already enabled."));
    }
    let generator = generator(&st.fernet, &row)?;
    let now = unix_now();
    if !generator.verify(code, now) {
        return Err(fail(
            st,
            user_id,
            "Invalid verification code. Check your authenticator app and device clock.",
        ));
    }
    let counter = i64::try_from(totp::counter_at(now)).unwrap_or(i64::MAX);
    if !db::enable(&st.ctx.db, row.id, counter).await? {
        return Err(rejected("2FA is already enabled."));
    }
    st.limiter.clear(user_id);
    tracing::info!(user_id, "2FA activated");
    Ok(())
}

/// Python's truthiness of a JSON value.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `_verify_backup_code`: the index of the first unused stored code that
/// matches. `Err(Ok(msg))` is a `ValueError` from bcrypt; `Err(Err(_))` a
/// malformed list (a `KeyError`/`AttributeError` in Python).
fn match_backup_code(
    codes: &Value,
    normalized: &str,
) -> Result<Option<usize>, Result<String, String>> {
    let list = codes
        .as_array()
        .ok_or_else(|| Err("backup_codes is not a list".to_string()))?;
    for (i, entry) in list.iter().enumerate() {
        let entry = entry
            .as_object()
            .ok_or_else(|| Err(format!("backup code {i} is not an object")))?;
        if entry.get("used").is_some_and(truthy) {
            continue;
        }
        let hash = entry
            .get("hash")
            .and_then(Value::as_str)
            .ok_or_else(|| Err(format!("backup code {i} has no hash")))?;
        if normalized.len() > 72 {
            return Err(Ok(BCRYPT_TOO_LONG.to_string()));
        }
        match bcrypt::verify(normalized, hash) {
            Ok(true) => return Ok(Some(i)),
            Ok(false) => {}
            Err(_) => return Err(Ok("Invalid salt".to_string())),
        }
    }
    Ok(None)
}

/// `validate_totp`: a TOTP code (preferred when both are given) or a
/// backup code.
pub async fn validate(
    st: &IdentityState,
    user_id: i32,
    factor: &SecondFactor,
) -> Result<(), FactorError> {
    check_limit(st, user_id)?;
    if factor.is_empty() {
        return Err(rejected("Provide either a TOTP code or a backup code."));
    }
    if let Some(code) = factor.totp() {
        let row = db::find(&st.ctx.db, user_id)
            .await?
            .filter(|r| r.enabled)
            .ok_or_else(|| rejected("2FA is not enabled for this user."))?;
        let generator = generator(&st.fernet, &row)?;
        let now = unix_now();
        if !generator.verify(code, now) {
            return Err(fail(st, user_id, "Invalid authentication code."));
        }
        let counter = i64::try_from(totp::counter_at(now)).unwrap_or(i64::MAX);
        if !db::claim_counter(&st.ctx.db, row.id, counter).await? {
            return Err(fail(
                st,
                user_id,
                "This code has already been used. Wait for a new code.",
            ));
        }
        st.limiter.clear(user_id);
        return Ok(());
    }
    let normalized = totp::normalize_backup_code(factor.backup().unwrap_or_default());
    let outcome = db::spend_backup_code(&st.ctx.db, user_id, |codes| async move {
        tokio::task::spawn_blocking(move || match_backup_code(&codes, &normalized))
            .await
            .unwrap_or_else(|e| Err(Err(e.to_string())))
    })
    .await?;
    match outcome {
        BackupSpend::NotEnabled => Err(rejected("2FA is not enabled for this user.")),
        BackupSpend::NoMatch => Err(fail(st, user_id, "Invalid backup code.")),
        BackupSpend::Failed(Ok(message)) => Err(FactorError::Rejected(message)),
        BackupSpend::Failed(Err(cause)) => Err(FactorError::Internal(ApiError::internal(cause))),
        BackupSpend::Spent(index) => {
            st.limiter.clear(user_id);
            tracing::info!(user_id, index, "2FA backup code used");
            Ok(())
        }
    }
}

/// `disable_totp`: a valid factor, then the row goes.
pub async fn disable(
    st: &IdentityState,
    user_id: i32,
    factor: &SecondFactor,
) -> Result<(), FactorError> {
    validate(st, user_id, factor).await?;
    db::delete(&st.ctx.db, user_id).await?;
    tracing::info!(user_id, "2FA disabled");
    Ok(())
}

/// `regenerate_backup_codes`: a valid TOTP code replaces every backup code.
pub async fn regenerate(
    st: &IdentityState,
    user_id: i32,
    code: &str,
) -> Result<Vec<String>, FactorError> {
    check_limit(st, user_id)?;
    let row = db::find(&st.ctx.db, user_id)
        .await?
        .filter(|r| r.enabled)
        .ok_or_else(|| rejected("2FA is not enabled."))?;
    let generator = generator(&st.fernet, &row)?;
    if !generator.verify(code, unix_now()) {
        return Err(fail(st, user_id, "Invalid authentication code."));
    }
    let (codes, stored) = backup_codes().await?;
    db::replace_backup_codes(&st.ctx.db, row.id, &stored).await?;
    st.limiter.clear(user_id);
    tracing::info!(user_id, "2FA backup codes regenerated");
    Ok(codes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_code_matching_follows_python() {
        let hash = bcrypt::hash("ABCDEFGHIJ", 4).unwrap();
        let codes = json!([
            {"hash": "not-a-hash", "used": true},
            {"hash": hash, "used": 0},
            {"hash": hash, "used": false}
        ]);
        assert_eq!(match_backup_code(&codes, "ABCDEFGHIJ"), Ok(Some(1)));
        assert_eq!(match_backup_code(&codes, "WRONGWRONG"), Ok(None));
        assert_eq!(
            match_backup_code(&codes, &"X".repeat(73)),
            Err(Ok(BCRYPT_TOO_LONG.to_string()))
        );
        let broken = json!([{"hash": "nope", "used": false}]);
        assert_eq!(
            match_backup_code(&broken, "A"),
            Err(Ok("Invalid salt".to_string()))
        );
        assert!(matches!(
            match_backup_code(&json!([{"used": false}]), "A"),
            Err(Err(_))
        ));
        assert!(matches!(match_backup_code(&json!({}), "A"), Err(Err(_))));
        // Every code used: nothing is checked, so a long input is just wrong.
        let used = json!([{"hash": "x", "used": "yes"}]);
        assert_eq!(match_backup_code(&used, &"X".repeat(80)), Ok(None));
    }
}
