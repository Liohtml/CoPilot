//! Shapes of `/api/auth/security/*` (`app/auth/routes/security_admin.py`).

use chrono::NaiveDateTime;
use serde::Serialize;
use serde_json::{Map, Value};

use copilot_web::validate::{Loc, StrRules, Validator};

/// `CustomerSecurityUser`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecurityUser {
    /// User id.
    pub id: i32,
    /// Login name.
    pub username: String,
    /// Email address.
    pub email: String,
    /// `user.role_id`.
    pub role_id: Option<i32>,
    /// `RoleEnum(role_id).name`, `null` for an unknown id.
    pub role_name: Option<String>,
    /// Last successful login.
    #[serde(serialize_with = "copilot_core::time::pydantic::opt_datetime")]
    pub last_login_at: Option<NaiveDateTime>,
    /// A `user_totp` row with `enabled` set.
    pub totp_enabled: bool,
}

/// `CustomerSecurityUsersResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecurityUsers {
    /// The customer's users.
    pub users: Vec<SecurityUser>,
    /// Always `true`.
    pub success: bool,
    /// Always "Users retrieved successfully".
    pub message: &'static str,
}

/// `SmtpStatusResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SmtpStatus {
    /// `SMTP_HOST` is set.
    pub configured: bool,
    /// Always `true`.
    pub success: bool,
    /// Always "SMTP status retrieved".
    pub message: &'static str,
}

/// `ActionResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Action {
    /// Always `true` on success.
    pub success: bool,
    /// What happened.
    pub message: String,
}

/// `TempPasswordTemplateOption`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemplateOption {
    /// Template id.
    pub id: i32,
    /// Display name.
    pub name: String,
    /// Free text.
    pub description: Option<String>,
    /// `text`, `markdown` or `html`.
    pub format: String,
    /// `null` = shared with every customer.
    pub customer_code: Option<String>,
    /// A seeded built-in.
    pub is_default: bool,
}

/// `TempPasswordOptionsResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemplateOptions {
    /// Best match first.
    pub templates: Vec<TemplateOption>,
    /// What a send with no override would use; `null` = the plaintext body.
    pub resolved_template_id: Option<i32>,
    /// The customer whose templates and branding apply.
    pub customer_code: Option<String>,
    /// `SMTP_HOST` is set.
    pub smtp_configured: bool,
    /// Always `true`.
    pub success: bool,
    /// `<n> template(s) available`.
    pub message: String,
}

/// `TempPasswordPreviewRequest` / `SendTempPasswordRequest`: both fields
/// optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TemplateChoice {
    /// The per-send override.
    pub template_id: Option<i64>,
    /// The customer the Security tab is showing.
    pub customer_code: Option<String>,
}

impl TemplateChoice {
    /// Read in declaration order (`Optional[int]`, `Optional[str]`).
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            template_id: v.opt_int(obj, at, "template_id", Default::default()),
            customer_code: v.opt_str(obj, at, "customer_code", StrRules::any()),
        }
    }
}

/// `TempPasswordPreviewResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Preview {
    /// Rendered subject; `null` when rendering failed.
    pub subject: Option<String>,
    /// HTML when the template is HTML, else the text body; "" on failure.
    pub body: String,
    /// `html` or `text`.
    pub format: &'static str,
    /// `<ExceptionType>: <message>` when rendering failed.
    pub error: Option<String>,
    /// `error` is `null`.
    pub success: bool,
    /// "Rendered" or "Template failed to render".
    pub message: &'static str,
}
