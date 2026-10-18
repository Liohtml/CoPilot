//! Passkey shapes — `app/auth/models/passkey.py`.

use chrono::NaiveDateTime;
use serde::Serialize;
use serde_json::{Map, Value};

use copilot_web::validate::{Loc, StrRules, Validator};

/// `PasskeyRegisterOptionsRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterOptionsRequest {
    /// `device_name: str = "Passkey"`.
    pub device_name: String,
}

impl RegisterOptionsRequest {
    /// Read in declaration order.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            device_name: v.str_or(obj, at, "device_name", StrRules::any(), "Passkey"),
        }
    }
}

/// `PasskeyLoginOptionsRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginOptionsRequest {
    /// `username: Optional[str] = None`.
    pub username: Option<String>,
}

impl LoginOptionsRequest {
    /// Read in declaration order.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            username: v.opt_str(obj, at, "username", StrRules::any()),
        }
    }
}

/// `PasskeyVerifyRequest`.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyRequest {
    /// The token `/options` returned.
    pub challenge_token: String,
    /// The browser's `PublicKeyCredential`, as JSON.
    pub credential: Value,
    /// Label for a new passkey.
    pub device_name: Option<String>,
}

impl VerifyRequest {
    /// Read in declaration order.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let challenge_token = v.req_str(obj, at, "challenge_token", StrRules::any());
        let credential = v
            .req_dict(obj, at, "credential")
            .cloned()
            .unwrap_or(Value::Null);
        let device_name = v.opt_str(obj, at, "device_name", StrRules::any());
        Self {
            challenge_token,
            credential,
            device_name,
        }
    }
}

/// `PasskeyItemResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasskeyItem {
    /// Row id.
    pub id: i32,
    /// Label.
    pub device_name: String,
    /// Registered.
    #[serde(serialize_with = "copilot_core::time::pydantic::datetime")]
    pub created_at: NaiveDateTime,
    /// Last login with it.
    #[serde(serialize_with = "copilot_core::time::pydantic::opt_datetime")]
    pub last_used_at: Option<NaiveDateTime>,
    /// Transports.
    pub transports: Vec<String>,
}

/// `PasskeyListResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasskeyList {
    /// The caller's passkeys, newest first.
    pub passkeys: Vec<PasskeyItem>,
    /// `"Passkeys retrieved"`.
    pub message: &'static str,
    /// Always `true`.
    pub success: bool,
}

/// `PasskeyStatusResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasskeyStatus {
    /// Configured (public) / has passkeys (own).
    pub enabled: bool,
    /// How many.
    pub count: usize,
    /// `"Passkey status retrieved"`.
    pub message: &'static str,
    /// Always `true`.
    pub success: bool,
}

/// `PasskeyLoginResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasskeyLogin {
    /// Session token, or the 2FA temp token.
    pub access_token: String,
    /// `"bearer"`.
    pub token_type: &'static str,
    /// The second factor is outstanding.
    pub requires_2fa: bool,
}

/// `{"message", "success"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Done {
    /// Message.
    pub message: &'static str,
    /// Always `true`.
    pub success: bool,
}
