//! SSO — `app/auth/services/sso.py` and the helpers of `routes/sso.py`.
//!
//! - **State**: `"<nonce>:<unix_ts>:<hmac_sha256_hex>"` over `nonce:ts` with
//!   `SSO_STATE_SECRET` (else `JWT_SECRET`), valid for 600 s — stateless, so
//!   a login started on one backend finishes on the other.
//! - **ID tokens**: RS256 against the provider's JWKS (`copilot_auth::jws`),
//!   cached per provider for an hour; Azure and Google refetch once when the
//!   token's `kid` is not in the cached set, Cloudflare does not.
//! - **Users**: an existing user with the address signs in; a new address
//!   must be on the allowlist and gets a user named after its local part
//!   (`jane`, `jane1`, …) with the allowlist's role and an unusable random
//!   password.
//!
//! What the browser sees on failure is decided by Python's exception type:
//! a `ValueError` shows its text, anything else a generic message.
//! [`IdpError`] carries that split.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use copilot_auth::jws::{JwkEntry, UnverifiedToken, parse_jwks};
use copilot_auth::pyvalue::{PyValue, loads_bytes};
use copilot_core::config::Secret;
use copilot_db::sso::{self, SsoConfigRow};
use copilot_db::totp;
use copilot_db::users::{self, UserRow};
use copilot_web::ApiError;
use copilot_web::pyurl::{redirect_location, urlencode};

use crate::IdentityState;

/// `_STATE_TTL_SECONDS`.
pub const STATE_TTL_SECS: f64 = 600.0;
/// How long fetched JWKS are trusted.
const KEYS_TTL: Duration = Duration::from_secs(3600);
const TOKEN_TIMEOUT: Duration = Duration::from_secs(15);
const KEYS_TIMEOUT: Duration = Duration::from_secs(10);
const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUER: &str = "https://accounts.google.com";

type Keys = Arc<Vec<JwkEntry>>;

/// Why an exchange or a Cloudflare token failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdpError {
    /// A `ValueError`: its text reaches the user.
    Value(String),
    /// Anything else: the generic message (the cause is logged).
    Other(String),
}

fn other(e: impl std::fmt::Display) -> IdpError {
    IdpError::Other(e.to_string())
}

/// HTTP client, state secret and key caches.
pub struct SsoClient {
    state_secret: Zeroizing<Vec<u8>>,
    idp_override: Option<String>,
    http: reqwest::Client,
    azure_keys: Mutex<HashMap<Option<String>, (Instant, Keys)>>,
    google_keys: Mutex<Option<(Instant, Keys)>>,
    cf_keys: Mutex<HashMap<String, (Instant, Keys)>>,
}

impl std::fmt::Debug for SsoClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsoClient")
            .field("idp_override", &self.idp_override)
            .finish_non_exhaustive()
    }
}

/// `str(value)` for an optional config value in an f-string or a form.
fn py_opt(value: &Option<String>) -> String {
    value.clone().unwrap_or_else(|| "None".into())
}

impl SsoClient {
    /// `secret`: `SSO_STATE_SECRET`, else `JWT_SECRET`. `idp_override`:
    /// `COPILOT_SSO_IDP_URL` (tests).
    pub fn new(secret: &Secret, idp_override: Option<String>) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("copilot/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            state_secret: Zeroizing::new(secret.expose().as_bytes().to_vec()),
            idp_override,
            http,
            azure_keys: Mutex::new(HashMap::new()),
            google_keys: Mutex::new(None),
            cf_keys: Mutex::new(HashMap::new()),
        })
    }

    fn mac(&self, message: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.state_secret)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        mac.update(message.as_bytes());
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// `_generate_state()`.
    pub fn generate_state(&self) -> String {
        let nonce = token_urlsafe(16);
        let ts = copilot_core::time::now_utc().timestamp();
        let message = format!("{nonce}:{ts}");
        let mac = self.mac(&message);
        format!("{message}:{mac}")
    }

    /// `_validate_state(state)`.
    pub fn validate_state(&self, state: &str) -> bool {
        let mut parts = state.rsplitn(3, ':');
        let (Some(mac), Some(ts), Some(nonce)) = (parts.next(), parts.next(), parts.next()) else {
            return false;
        };
        if !mac.is_ascii() {
            return false;
        }
        let expected = self.mac(&format!("{nonce}:{ts}"));
        if !bool::from(mac.as_bytes().ct_eq(expected.as_bytes())) {
            return false;
        }
        let Ok(ts) = ts.trim().parse::<f64>() else {
            return false;
        };
        let now = copilot_core::time::now_utc().timestamp_micros() as f64 / 1e6;
        let age = now - ts;
        (0.0..=STATE_TTL_SECS).contains(&age)
    }

    /// A server-side request URL, redirected to the test IdP when set.
    fn idp_url(&self, url: &str) -> String {
        match &self.idp_override {
            Some(base) => format!("{base}/{}", url.strip_prefix("https://").unwrap_or(url)),
            None => url.to_string(),
        }
    }

    /// `build_azure_auth_url(cfg)`, as the redirect's `Location`.
    pub fn azure_auth_location(&self, cfg: &SsoConfigRow) -> String {
        let query = urlencode(&[
            ("client_id", py_opt(&cfg.azure_client_id)),
            ("response_type", "code".into()),
            ("redirect_uri", py_opt(&cfg.azure_redirect_uri)),
            ("response_mode", "query".into()),
            ("scope", "openid profile email".into()),
            ("state", self.generate_state()),
            ("nonce", token_urlsafe(16)),
            ("prompt", "select_account".into()),
        ]);
        redirect_location(&format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize?{query}",
            py_opt(&cfg.azure_tenant_id)
        ))
    }

    /// `build_google_auth_url(cfg)`, as the redirect's `Location`.
    pub fn google_auth_location(&self, cfg: &SsoConfigRow) -> String {
        let query = urlencode(&[
            ("client_id", py_opt(&cfg.google_client_id)),
            ("response_type", "code".into()),
            ("redirect_uri", py_opt(&cfg.google_redirect_uri)),
            ("scope", "openid email".into()),
            ("state", self.generate_state()),
            ("access_type", "online".into()),
            ("prompt", "select_account".into()),
        ]);
        redirect_location(&format!("{GOOGLE_AUTH_URL}?{query}"))
    }

    /// POST the authorization code; the `id_token` of the answer.
    async fn token(
        &self,
        url: &str,
        form: &[(&str, String)],
        provider: &str,
    ) -> Result<String, IdpError> {
        let resp = self
            .http
            .post(self.idp_url(url))
            .timeout(TOKEN_TIMEOUT)
            .form(form)
            .send()
            .await
            .map_err(other)?;
        if !resp.status().is_success() {
            return Err(IdpError::Other(format!(
                "token endpoint answered {}",
                resp.status()
            )));
        }
        let body = resp.bytes().await.map_err(other)?;
        let data = loads_bytes(&body).map_err(|_| other("token response is not JSON"))?;
        let PyValue::Dict(_) = data else {
            return Err(other("token response is not an object"));
        };
        match data.get("id_token") {
            Some(PyValue::Str(t)) if !t.is_empty() => Ok(t.clone()),
            Some(v) if v.truthy() => Err(other("id_token is not a string")),
            _ => Err(IdpError::Value(format!(
                "No id_token in {provider} response"
            ))),
        }
    }

    async fn fetch_keys(&self, url: &str) -> Result<Keys, IdpError> {
        let resp = self
            .http
            .get(self.idp_url(url))
            .timeout(KEYS_TIMEOUT)
            .send()
            .await
            .map_err(other)?;
        if !resp.status().is_success() {
            return Err(IdpError::Other(format!(
                "JWKS endpoint answered {}",
                resp.status()
            )));
        }
        let body = resp.bytes().await.map_err(other)?;
        Ok(Arc::new(parse_jwks(&body).map_err(other)?))
    }

    async fn azure_keys(&self, tenant: &Option<String>, url: &str) -> Result<Keys, IdpError> {
        let cached = lock(&self.azure_keys)
            .get(tenant)
            .filter(|(at, _)| at.elapsed() < KEYS_TTL)
            .map(|(_, keys)| keys.clone());
        if let Some(keys) = cached {
            return Ok(keys);
        }
        let keys = self.fetch_keys(url).await?;
        lock(&self.azure_keys).insert(tenant.clone(), (Instant::now(), keys.clone()));
        Ok(keys)
    }

    async fn google_keys(&self) -> Result<Keys, IdpError> {
        let cached = lock(&self.google_keys)
            .as_ref()
            .filter(|(at, _)| at.elapsed() < KEYS_TTL)
            .map(|(_, keys)| keys.clone());
        if let Some(keys) = cached {
            return Ok(keys);
        }
        let keys = self.fetch_keys(GOOGLE_JWKS_URL).await?;
        *lock(&self.google_keys) = Some((Instant::now(), keys.clone()));
        Ok(keys)
    }

    async fn cf_keys(&self, team: &str) -> Result<Keys, IdpError> {
        let cached = lock(&self.cf_keys)
            .get(team)
            .filter(|(at, _)| at.elapsed() < KEYS_TTL)
            .map(|(_, keys)| keys.clone());
        if let Some(keys) = cached {
            return Ok(keys);
        }
        let keys = self
            .fetch_keys(&format!("https://{team}/cdn-cgi/access/certs"))
            .await?;
        lock(&self.cf_keys).insert(team.to_string(), (Instant::now(), keys.clone()));
        Ok(keys)
    }

    /// `exchange_azure_code(code, state, cfg)`: the ID token's claims.
    pub async fn exchange_azure(
        &self,
        code: &str,
        state: &str,
        cfg: &SsoConfigRow,
    ) -> Result<PyValue, IdpError> {
        if !self.validate_state(state) {
            return Err(IdpError::Value(
                "Invalid or expired OAuth2 state parameter".into(),
            ));
        }
        let tenant = py_opt(&cfg.azure_tenant_id);
        let id_token = self
            .token(
                &format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"),
                &[
                    ("client_id", form_value(&cfg.azure_client_id)),
                    ("client_secret", form_value(&cfg.azure_client_secret)),
                    ("code", code.to_string()),
                    ("redirect_uri", form_value(&cfg.azure_redirect_uri)),
                    ("grant_type", "authorization_code".into()),
                    ("scope", "openid profile email".into()),
                ],
                "Azure",
            )
            .await?;
        let token = UnverifiedToken::parse(&id_token).map_err(other)?;
        let jwks_url = format!("https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys");
        let mut key = None;
        for _ in 0..2 {
            let keys = self.azure_keys(&cfg.azure_tenant_id, &jwks_url).await?;
            key = keys
                .iter()
                .find(|k| k.matches(token.kid()))
                .map(|k| k.key.clone());
            if key.is_some() {
                break;
            }
            lock(&self.azure_keys).remove(&cfg.azure_tenant_id);
        }
        let key = key.ok_or_else(|| {
            IdpError::Value("Unable to find matching signing key in Azure JWKS".into())
        })?;
        let claims = token
            .verify_rs256(
                &key,
                cfg.azure_client_id.as_deref(),
                &format!("https://login.microsoftonline.com/{tenant}/v2.0"),
                now(),
            )
            .map_err(other)?;
        Ok(PyValue::Dict(claims))
    }

    /// `exchange_google_code(code, state, cfg)`.
    pub async fn exchange_google(
        &self,
        code: &str,
        state: &str,
        cfg: &SsoConfigRow,
    ) -> Result<PyValue, IdpError> {
        if !self.validate_state(state) {
            return Err(IdpError::Value(
                "Invalid or expired OAuth2 state parameter".into(),
            ));
        }
        let id_token = self
            .token(
                GOOGLE_TOKEN_URL,
                &[
                    ("client_id", form_value(&cfg.google_client_id)),
                    ("client_secret", form_value(&cfg.google_client_secret)),
                    ("code", code.to_string()),
                    ("redirect_uri", form_value(&cfg.google_redirect_uri)),
                    ("grant_type", "authorization_code".into()),
                ],
                "Google",
            )
            .await?;
        let token = UnverifiedToken::parse(&id_token).map_err(other)?;
        for _ in 0..2 {
            let keys = self.google_keys().await?;
            if let Some(k) = keys.iter().find(|k| k.matches(token.kid())) {
                let claims = token
                    .verify_rs256(
                        &k.key,
                        cfg.google_client_id.as_deref(),
                        GOOGLE_ISSUER,
                        now(),
                    )
                    .map_err(other)?;
                return Ok(PyValue::Dict(claims));
            }
            *lock(&self.google_keys) = None;
        }
        Err(IdpError::Value(
            "Unable to find matching signing key in Google JWKS".into(),
        ))
    }

    /// `validate_cf_jwt(token, cfg)`.
    pub async fn validate_cloudflare(
        &self,
        token: &str,
        cfg: &SsoConfigRow,
    ) -> Result<PyValue, IdpError> {
        let team = match cfg.cf_team_domain.as_deref() {
            Some(team) if valid_team_domain(team) => team,
            _ => {
                return Err(IdpError::Value(format!(
                    "Invalid Cloudflare team domain '{}'. Must match *.cloudflareaccess.com",
                    py_opt(&cfg.cf_team_domain)
                )));
            }
        };
        let token = UnverifiedToken::parse(token).map_err(other)?;
        let keys = self.cf_keys(team).await?;
        let issuer = format!("https://{team}");
        for k in keys.iter() {
            if k.matches(token.kid()) {
                let claims = token
                    .verify_rs256(&k.key, cfg.cf_audience.as_deref(), &issuer, now())
                    .map_err(other)?;
                return Ok(PyValue::Dict(claims));
            }
        }
        Err(IdpError::Value(
            "Unable to find matching signing key in Cloudflare JWKS".into(),
        ))
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// httpx's form encoding of `None`: the empty string.
fn form_value(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

fn now() -> f64 {
    copilot_core::time::now_utc().timestamp_micros() as f64 / 1e6
}

/// `secrets.token_urlsafe(n)`.
pub fn token_urlsafe(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// `_CF_DOMAIN_RE.match(domain)`: `^[a-zA-Z0-9-]+\.cloudflareaccess\.com$`
/// (`$` also matches before a final newline).
fn valid_team_domain(domain: &str) -> bool {
    let domain = domain.strip_suffix('\n').unwrap_or(domain);
    domain
        .strip_suffix(".cloudflareaccess.com")
        .is_some_and(|team| {
            !team.is_empty() && team.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// Why a signed-in address has no user.
#[derive(Debug)]
pub enum ResolveError {
    /// `ValueError`: not on the allowlist.
    NotAuthorized(String),
    /// A database failure (a 500).
    Internal(ApiError),
}

impl From<copilot_db::DbError> for ResolveError {
    fn from(e: copilot_db::DbError) -> Self {
        ResolveError::Internal(ApiError::from(e))
    }
}

/// `_resolve_sso_user(email)`.
pub async fn resolve_user(st: &IdentityState, email: &str) -> Result<UserRow, ResolveError> {
    if let Some(user) = users::find_by_email(&st.ctx.db, email).await? {
        return Ok(user);
    }
    let Some(allowed) = sso::find_allowed_email(&st.ctx.db, email).await? else {
        return Err(ResolveError::NotAuthorized(format!(
            "Email {email} is not authorized for SSO access. Contact your administrator."
        )));
    };
    // `get_or_create_sso_user`.
    if let Some(user) = users::find_by_email(&st.ctx.db, email).await? {
        return Ok(user);
    }
    let base = email.split('@').next().unwrap_or_default().to_string();
    let mut username = base.clone();
    let mut counter = 1u64;
    while users::username_taken(&st.ctx.db, &username).await? {
        username = format!("{base}{counter}");
        counter += 1;
    }
    let random = token_urlsafe(48);
    let hash = tokio::task::spawn_blocking(move || copilot_auth::password::hash_password(&random))
        .await
        .map_err(|e| ResolveError::Internal(ApiError::internal(e)))?
        .map_err(|e| ResolveError::Internal(ApiError::internal(e)))?;
    let id = users::create_user(&st.ctx.db, &username, &hash, email, allowed.role_id, &[]).await?;
    tracing::info!(%username, %email, role_id = allowed.role_id, "SSO: auto-provisioned user");
    users::find_by_id(&st.ctx.db, id)
        .await?
        .ok_or_else(|| ResolveError::Internal(ApiError::internal("new SSO user vanished")))
}

/// `_issue_token_or_2fa(user)`: a session token (no `customer_codes`, as
/// `encode_token` is called without them), or the 2FA temp token. The bool
/// is `requires_2fa`.
pub async fn issue_token(st: &IdentityState, user: &UserRow) -> Result<(String, bool), ApiError> {
    if totp::is_enabled(&st.ctx.db, user.id).await? {
        let token = st
            .ctx
            .jwt
            .encode_two_factor(&user.username)
            .map_err(ApiError::internal)?;
        return Ok((token, true));
    }
    let role = crate::services::login::role_name(st, &user.username, user.role_id).await?;
    let token = st
        .ctx
        .jwt
        .issue_session(
            &user.username,
            &role,
            st.token_ttl_minutes.saturating_mul(60),
            None,
        )
        .map_err(ApiError::internal)?;
    Ok((token, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trip_and_tampering() {
        let client = SsoClient::new(&Secret::new("s3cret"), None).unwrap();
        let state = client.generate_state();
        assert!(client.validate_state(&state));
        let mut tampered = state.clone();
        tampered.insert(0, 'x');
        assert!(!client.validate_state(&tampered));
        assert!(!client.validate_state("a:b"));
        assert!(!client.validate_state(""));
        let other = SsoClient::new(&Secret::new("other"), None).unwrap();
        assert!(!other.validate_state(&state));
        // An expired one, signed correctly.
        let old = copilot_core::time::now_utc().timestamp() - 601;
        let msg = format!("nonce:{old}");
        assert!(!client.validate_state(&format!("{msg}:{}", client.mac(&msg))));
        let future = copilot_core::time::now_utc().timestamp() + 60;
        let msg = format!("nonce:{future}");
        assert!(!client.validate_state(&format!("{msg}:{}", client.mac(&msg))));
    }

    #[test]
    fn mac_matches_python_hmac() {
        // hmac.new(b"s3cret", b"n:1700000000", hashlib.sha256).hexdigest()
        let client = SsoClient::new(&Secret::new("s3cret"), None).unwrap();
        assert_eq!(
            client.mac("n:1700000000"),
            "e329c1abcf9f2d37b11bf87a2e9d3a8a3cc8fa028fa16d3c338036e2c7a74284"
        );
    }

    #[test]
    fn team_domains() {
        assert!(valid_team_domain("acme.cloudflareaccess.com"));
        assert!(valid_team_domain("acme-1.cloudflareaccess.com\n"));
        assert!(!valid_team_domain(".cloudflareaccess.com"));
        assert!(!valid_team_domain("evil.com/x.cloudflareaccess.com"));
        assert!(!valid_team_domain("acme.cloudflareaccess.com.evil"));
    }

    #[test]
    fn override_keeps_the_path() {
        let client = SsoClient::new(&Secret::new("s"), Some("http://127.0.0.1:9".into())).unwrap();
        assert_eq!(
            client.idp_url("https://login.microsoftonline.com/t/oauth2/v2.0/token"),
            "http://127.0.0.1:9/login.microsoftonline.com/t/oauth2/v2.0/token"
        );
    }
}
