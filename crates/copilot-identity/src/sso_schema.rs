//! SSO shapes — `app/auth/models/sso.py` (`SSOConfigUpdate`,
//! `SSOConfigResponse`, `SSOAllowedEmailInput`, `SSOAllowedEmailOut`,
//! `SSOPublicStatusResponse`).

use chrono::NaiveDateTime;
use serde::Serialize;
use serde_json::{Map, Value};

use copilot_db::sso::SsoConfigRow;
use copilot_web::validate::{Loc, LocPart, StrRules, Validator};

/// `SOC_ROLES`: who SSO may sign in (admin, analyst, responder).
pub const SOC_ROLE_IDS: [i64; 3] = [1, 2, 5];

/// `SSOConfigUpdate` — `PUT /auth/sso/settings`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigUpdate(pub SsoConfigRow);

impl ConfigUpdate {
    /// Read in declaration order. The client secrets are kept as sent; the
    /// route drops empty ones.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let sso_enabled = v.bool_or(obj, at, "sso_enabled", false);
        let azure_enabled = v.bool_or(obj, at, "azure_enabled", false);
        let azure_tenant_id = v.opt_str(obj, at, "azure_tenant_id", StrRules::any());
        let azure_client_id = v.opt_str(obj, at, "azure_client_id", StrRules::any());
        let azure_client_secret = v.opt_str(obj, at, "azure_client_secret", StrRules::any());
        let azure_redirect_uri = v.opt_str(obj, at, "azure_redirect_uri", StrRules::any());
        let google_enabled = v.bool_or(obj, at, "google_enabled", false);
        let google_client_id = v.opt_str(obj, at, "google_client_id", StrRules::any());
        let google_client_secret = v.opt_str(obj, at, "google_client_secret", StrRules::any());
        let google_redirect_uri = v.opt_str(obj, at, "google_redirect_uri", StrRules::any());
        let cf_enabled = v.bool_or(obj, at, "cf_enabled", false);
        let cf_team_domain = v.opt_str(obj, at, "cf_team_domain", StrRules::any());
        let cf_audience = v.opt_str(obj, at, "cf_audience", StrRules::any());
        Self(SsoConfigRow {
            sso_enabled,
            azure_enabled,
            azure_tenant_id,
            azure_client_id,
            azure_client_secret,
            azure_redirect_uri,
            google_enabled,
            google_client_id,
            google_client_secret,
            google_redirect_uri,
            cf_enabled,
            cf_team_domain,
            cf_audience,
        })
    }
}

/// `SSOConfigResponse` — never the secrets, only whether they are set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigResponse {
    /// Global switch.
    pub sso_enabled: bool,
    /// Azure Entra ID.
    pub azure_enabled: bool,
    /// Tenant id.
    pub azure_tenant_id: Option<String>,
    /// Client id.
    pub azure_client_id: Option<String>,
    /// A secret is stored.
    pub azure_client_secret_set: bool,
    /// Redirect URI.
    pub azure_redirect_uri: Option<String>,
    /// Google.
    pub google_enabled: bool,
    /// Client id.
    pub google_client_id: Option<String>,
    /// A secret is stored.
    pub google_client_secret_set: bool,
    /// Redirect URI.
    pub google_redirect_uri: Option<String>,
    /// Cloudflare Access.
    pub cf_enabled: bool,
    /// Team domain.
    pub cf_team_domain: Option<String>,
    /// Audience tag.
    pub cf_audience: Option<String>,
    /// Human-readable status.
    pub message: &'static str,
    /// Always `true`.
    pub success: bool,
}

impl ConfigResponse {
    /// The response for a stored row.
    pub fn from_row(cfg: &SsoConfigRow, message: &'static str) -> Self {
        let set = |s: &Option<String>| s.as_deref().is_some_and(|s| !s.is_empty());
        Self {
            sso_enabled: cfg.sso_enabled,
            azure_enabled: cfg.azure_enabled,
            azure_tenant_id: cfg.azure_tenant_id.clone(),
            azure_client_id: cfg.azure_client_id.clone(),
            azure_client_secret_set: set(&cfg.azure_client_secret),
            azure_redirect_uri: cfg.azure_redirect_uri.clone(),
            google_enabled: cfg.google_enabled,
            google_client_id: cfg.google_client_id.clone(),
            google_client_secret_set: set(&cfg.google_client_secret),
            google_redirect_uri: cfg.google_redirect_uri.clone(),
            cf_enabled: cfg.cf_enabled,
            cf_team_domain: cfg.cf_team_domain.clone(),
            cf_audience: cfg.cf_audience.clone(),
            message,
            success: true,
        }
    }
}

/// `SSOPublicStatusResponse` — `GET /auth/sso/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicStatus {
    /// Global switch.
    pub sso_enabled: bool,
    /// Azure button.
    pub azure_enabled: bool,
    /// Google button.
    pub google_enabled: bool,
    /// Cloudflare Access.
    pub cf_enabled: bool,
    /// Always `null` (declared, never filled).
    pub azure_authorization_url: Option<String>,
    /// Always `null`.
    pub google_authorization_url: Option<String>,
}

/// `SSOAllowedEmailInput` — `POST /auth/sso/allowed-emails`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedEmailInput {
    /// The normalized address (`EmailStr`).
    pub email: String,
    /// The role a new SSO user gets.
    pub role_id: i64,
}

impl AllowedEmailInput {
    /// Read in declaration order; `role_id` must be a SOC role.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let email = v.req_email(obj, at, "email");
        let role_id = match obj.get("role_id") {
            None => 2,
            Some(value) => {
                let mut l = at.clone();
                l.push(LocPart::Key("role_id".into()));
                match v.check_int(&l, value, Default::default()) {
                    Some(n) if SOC_ROLE_IDS.contains(&n) => n,
                    Some(_) => {
                        v.push(
                            "value_error",
                            l,
                            "Value error, SSO users must be admins, analysts or responders",
                        );
                        2
                    }
                    None => 2,
                }
            }
        };
        Self { email, role_id }
    }
}

/// `SSOAllowedEmailOut`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AllowedEmailOut {
    /// Row id.
    pub id: i32,
    /// Address.
    pub email: String,
    /// Role for new users.
    pub role_id: i32,
    /// When it was added.
    #[serde(serialize_with = "copilot_core::time::pydantic::datetime")]
    pub created_at: NaiveDateTime,
}

/// `SSOAllowedEmailListResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AllowedEmailList {
    /// The allowlist, by id.
    pub emails: Vec<AllowedEmailOut>,
    /// `"Allowed emails retrieved"`.
    pub message: &'static str,
    /// Always `true`.
    pub success: bool,
}

/// `POST /auth/sso/allowed-emails`' 201 body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AllowedEmailCreated {
    /// `Email … added to SSO allowlist`.
    pub message: String,
    /// Always `true`.
    pub success: bool,
    /// The new row.
    pub id: i32,
}

/// `{"message", "success"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Done {
    /// Message.
    pub message: &'static str,
    /// Always `true`.
    pub success: bool,
}

/// `POST /auth/sso/cloudflare/verify`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareToken {
    /// Session token, or the 2FA temp token.
    pub access_token: String,
    /// `"bearer"`.
    pub token_type: &'static str,
    /// `"Cloudflare Access authentication successful"`.
    pub message: &'static str,
    /// Always `true`.
    pub success: bool,
    /// Present (and `true`) only when 2FA is outstanding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_2fa: Option<bool>,
}
