//! Passkeys — `app/auth/services/passkey.py` over [`copilot_webauthn`].
//!
//! Each flow keeps Python's order, since a refusal at one step must not be
//! reported as another: origin (the route), configured, `127.0.0.1`, RP ID,
//! then the challenge (consumed *before* the credential is checked, so a
//! failed attempt burns it), then the ceremony.

use rand::RngCore;
use serde_json::{Map, Value};

use copilot_auth::pybase64::{base64url_to_bytes, bytes_to_base64url};
use copilot_db::passkeys::{self, PasskeyRow};
use copilot_db::users::{self, UserRow};
use copilot_web::ApiError;
use copilot_webauthn::options::{
    OptionsError, StoredCredential, authentication_options, registration_options,
};
use copilot_webauthn::{
    Failure, registration_transports, verify_authentication, verify_registration,
};

use crate::IdentityState;

/// How long a challenge stays valid (`CHALLENGE_TTL_SECONDS`).
pub const CHALLENGE_TTL_SECS: i64 = 300;

/// A refused passkey step: the `ValueError` text (the route picks 400 or
/// 401), or an unexpected failure.
#[derive(Debug)]
pub enum PasskeyError {
    /// `ValueError(text)`.
    Rejected(String),
    /// A 500.
    Internal(ApiError),
}

impl From<ApiError> for PasskeyError {
    fn from(e: ApiError) -> Self {
        PasskeyError::Internal(e)
    }
}

impl From<copilot_db::DbError> for PasskeyError {
    fn from(e: copilot_db::DbError) -> Self {
        PasskeyError::Internal(ApiError::from(e))
    }
}

impl From<Failure> for PasskeyError {
    fn from(f: Failure) -> Self {
        match f {
            Failure::Rejected(m) => PasskeyError::Rejected(m),
            Failure::Internal(kind) => {
                PasskeyError::Internal(ApiError::internal(format!("py_webauthn raised {kind}")))
            }
        }
    }
}

impl From<OptionsError> for PasskeyError {
    fn from(e: OptionsError) -> Self {
        match e {
            OptionsError::Value(m) => PasskeyError::Rejected(m),
            OptionsError::Internal(kind) => {
                PasskeyError::Internal(ApiError::internal(format!("options raised {kind}")))
            }
        }
    }
}

fn rejected(message: impl Into<String>) -> PasskeyError {
    PasskeyError::Rejected(message.into())
}

/// `is_passkey_configured()` (a malformed first origin raises).
pub fn configured(st: &IdentityState) -> Result<bool, PasskeyError> {
    st.relying_party
        .is_configured()
        .map_err(PasskeyError::Rejected)
}

/// `_ensure_passkey_origin` + `_get_rp_id_for_origin`.
fn rp_id(st: &IdentityState, origin: &str) -> Result<String, PasskeyError> {
    st.relying_party
        .ensure_passkey_origin(origin)
        .map_err(PasskeyError::Rejected)?;
    st.relying_party
        .rp_id_for_origin(origin)
        .map_err(PasskeyError::Rejected)
}

fn stored(rows: &[PasskeyRow]) -> Vec<StoredCredential> {
    rows.iter()
        .map(|r| StoredCredential {
            credential_id: r.credential_id.clone(),
            transports: r.transports.0.clone(),
        })
        .collect()
}

/// `generate_challenge()`: 64 random bytes.
fn new_challenge() -> Vec<u8> {
    let mut challenge = vec![0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    challenge
}

/// `_store_challenge`: the challenge under a fresh UUID token.
async fn store_challenge(
    st: &IdentityState,
    challenge: &[u8],
    flow: &str,
    user_id: Option<i32>,
) -> Result<String, PasskeyError> {
    let token = uuid::Uuid::new_v4().to_string();
    let expires_at = copilot_core::time::mysql_datetime(
        copilot_core::time::now_utc_micros() + chrono::Duration::seconds(CHALLENGE_TTL_SECS),
    );
    passkeys::store_challenge(
        &st.ctx.db,
        &token,
        &bytes_to_base64url(challenge),
        flow,
        user_id,
        expires_at,
    )
    .await?;
    Ok(token)
}

/// `_consume_challenge`.
async fn consume_challenge(
    st: &IdentityState,
    token: &str,
    flow: &str,
    user_id: Option<i32>,
) -> Result<Vec<u8>, PasskeyError> {
    let stored = passkeys::consume_challenge(&st.ctx.db, token, flow, user_id)
        .await?
        .map_err(|e| rejected(e.message()))?;
    base64url_to_bytes(&stored).map_err(|e| rejected(e.to_string()))
}

/// `list_user_passkeys`.
pub async fn list(st: &IdentityState, user_id: i32) -> Result<Vec<PasskeyRow>, ApiError> {
    Ok(passkeys::list_for_user(&st.ctx.db, user_id).await?)
}

/// `create_registration_options`.
pub async fn registration_options_for(
    st: &IdentityState,
    user: &UserRow,
    device_name: &str,
    origin: &str,
) -> Result<Map<String, Value>, PasskeyError> {
    if !configured(st)? {
        return Err(rejected("WebAuthn is not configured on this server."));
    }
    let rp_id = rp_id(st, origin)?;
    let existing = passkeys::list_for_user(&st.ctx.db, user.id).await?;
    let challenge = new_challenge();
    let mut payload = registration_options(
        &rp_id,
        st.relying_party.rp_name(),
        i64::from(user.id),
        &user.username,
        &challenge,
        &stored(&existing),
    )?;
    let token = store_challenge(st, &challenge, "register", Some(user.id)).await?;
    payload.insert("challengeToken".into(), Value::from(token));
    payload.insert("deviceName".into(), Value::from(device_name));
    Ok(payload)
}

/// `verify_registration`: store the new passkey.
pub async fn register(
    st: &IdentityState,
    user: &UserRow,
    device_name: &str,
    challenge_token: &str,
    credential: &Value,
    origin: &str,
) -> Result<(), PasskeyError> {
    let rp_id = rp_id(st, origin)?;
    let challenge = consume_challenge(st, challenge_token, "register", Some(user.id)).await?;
    let verified = verify_registration(credential, &challenge, &rp_id, origin)?;
    let transports = registration_transports(credential)?;
    let credential_id = bytes_to_base64url(&verified.credential_id);
    let inserted = passkeys::insert(
        &st.ctx.db,
        user.id,
        &credential_id,
        &bytes_to_base64url(&verified.public_key),
        i64::from(verified.sign_count),
        &transports,
        device_name,
    )
    .await?;
    if inserted.is_none() {
        return Err(rejected("This passkey is already registered."));
    }
    tracing::info!(username = %user.username, user_id = user.id, "passkey registered");
    Ok(())
}

/// `create_authentication_options`.
pub async fn authentication_options_for(
    st: &IdentityState,
    username: Option<&str>,
    origin: &str,
) -> Result<Map<String, Value>, PasskeyError> {
    if !configured(st)? {
        return Err(rejected("WebAuthn is not configured on this server."));
    }
    let rp_id = rp_id(st, origin)?;
    let mut allow = Vec::new();
    let mut user_id = None;
    if let Some(username) = username.filter(|u| !u.is_empty()) {
        let user = match users::find_by_username(&st.ctx.db, username).await {
            Ok(user) => user,
            Err(e) => {
                tracing::error!(err = %e, "user lookup failed during passkey login");
                None
            }
        }
        .ok_or_else(|| rejected("User not found."))?;
        let rows = passkeys::list_for_user(&st.ctx.db, user.id).await?;
        if rows.is_empty() {
            return Err(rejected("No passkeys registered for this user."));
        }
        allow = stored(&rows);
        user_id = Some(user.id);
    }
    let challenge = new_challenge();
    let mut payload = authentication_options(&rp_id, &challenge, &allow)?;
    let token = store_challenge(st, &challenge, "login", user_id).await?;
    payload.insert("challengeToken".into(), Value::from(token));
    Ok(payload)
}

/// `verify_authentication`: the passkey used, with its new counter.
pub async fn authenticate(
    st: &IdentityState,
    challenge_token: &str,
    credential: &Value,
    origin: &str,
) -> Result<PasskeyRow, PasskeyError> {
    let rp_id = rp_id(st, origin)?;
    let challenge = consume_challenge(st, challenge_token, "login", None).await?;
    let credential_id = match credential.get("id") {
        Some(Value::String(id)) if !id.is_empty() => id.clone(),
        None | Some(Value::Null | Value::Bool(false)) => {
            return Err(rejected("Missing credential id."));
        }
        Some(Value::String(_)) => return Err(rejected("Missing credential id.")),
        Some(Value::Number(n)) if n.as_f64() == Some(0.0) => {
            return Err(rejected("Missing credential id."));
        }
        Some(Value::Array(a)) if a.is_empty() => return Err(rejected("Missing credential id.")),
        Some(Value::Object(o)) if o.is_empty() => return Err(rejected("Missing credential id.")),
        // A non-string id reaches the database as a number or a list in
        // Python; py_webauthn then refuses the credential (a 500).
        Some(_) => return Err(ApiError::internal("credential id is not a string").into()),
    };
    let mut stored = passkeys::find_by_credential_id(&st.ctx.db, &credential_id)
        .await?
        .ok_or_else(|| rejected("Unknown passkey."))?;
    let public_key = base64url_to_bytes(&stored.public_key).map_err(|e| rejected(e.to_string()))?;
    let current = u32::try_from(stored.sign_count).unwrap_or(0);
    let new_count =
        verify_authentication(credential, &challenge, &rp_id, origin, &public_key, current)?;
    if !passkeys::record_use(&st.ctx.db, stored.id, i64::from(new_count)).await? {
        return Err(rejected("Passkey no longer exists."));
    }
    stored.sign_count = i32::try_from(new_count).unwrap_or(i32::MAX);
    Ok(stored)
}

/// `delete_user_passkey`.
pub async fn delete(st: &IdentityState, user_id: i32, passkey_id: i64) -> Result<(), PasskeyError> {
    if passkeys::delete_for_user(&st.ctx.db, user_id, passkey_id).await? {
        Ok(())
    } else {
        Err(rejected("Passkey not found."))
    }
}
