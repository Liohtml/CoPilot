//! Request and response shapes — `OAuth2PasswordRequestForm`,
//! `app/auth/schema/auth.py:Token` and `app/auth/models/totp.py`.

use serde::Serialize;
use serde_json::{Map, Value};

use copilot_web::ApiError;
use copilot_web::body::Form;
use copilot_web::validate::{Loc, LocPart, StrRules, Validator};

/// `OAuth2PasswordRequestForm`: `grant_type` (only `password`), `username`
/// and `password` (required; an empty value counts as absent), and the
/// unused `scope`, `client_id`, `client_secret`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginForm {
    /// `username`.
    pub username: String,
    /// `password`.
    pub password: String,
}

impl LoginForm {
    /// Validate in declaration order.
    pub fn read(form: &Form) -> Result<Self, ApiError> {
        let mut v = Validator::new();
        if let Some(grant_type) = form.text(&mut v, "grant_type") {
            if grant_type != "password" {
                v.push(
                    "string_pattern_mismatch",
                    vec![
                        LocPart::Key("body".into()),
                        LocPart::Key("grant_type".into()),
                    ],
                    "String should match pattern '^password$'",
                );
            }
        }
        let username = form.req_text(&mut v, "username");
        let password = form.req_text(&mut v, "password");
        for name in ["scope", "client_id", "client_secret"] {
            form.text(&mut v, name);
        }
        v.finish()?;
        Ok(Self { username, password })
    }
}

/// `Token` (also the shape of a finished login).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Token {
    /// The session token.
    pub access_token: String,
    /// Always `bearer`.
    pub token_type: &'static str,
}

impl Token {
    /// A bearer token.
    pub fn bearer(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "bearer",
        }
    }
}

/// What `/auth/token` returns while the second factor is outstanding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TwoFactorRequired {
    /// The 2FA temp token (not a session).
    pub access_token: String,
    /// Always `bearer`.
    pub token_type: &'static str,
    /// Always `true`.
    pub requires_2fa: bool,
}

/// `TOTPVerifyRequest` (`code` required).
pub fn read_verify(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> String {
    v.req_str(obj, at, "code", StrRules::any())
}

/// `TOTPDisableRequest`: an optional TOTP code and an optional backup code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecondFactor {
    /// `code`.
    pub code: Option<String>,
    /// `backup_code`.
    pub backup_code: Option<String>,
}

impl SecondFactor {
    /// Read `code` and `backup_code`.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            code: v.opt_str(obj, at, "code", StrRules::any()),
            backup_code: v.opt_str(obj, at, "backup_code", StrRules::any()),
        }
    }

    /// The TOTP code, unless absent or empty (Python's `if code:`).
    pub fn totp(&self) -> Option<&str> {
        self.code.as_deref().filter(|c| !c.is_empty())
    }

    /// The backup code, unless absent or empty.
    pub fn backup(&self) -> Option<&str> {
        self.backup_code.as_deref().filter(|c| !c.is_empty())
    }

    /// `not body.code and not body.backup_code`.
    pub fn is_empty(&self) -> bool {
        self.totp().is_none() && self.backup().is_none()
    }
}

/// `TOTPValidateRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateRequest {
    /// The 2FA temp token from `/auth/token`.
    pub temp_token: String,
    /// The second factor.
    pub factor: SecondFactor,
}

impl ValidateRequest {
    /// Read in declaration order.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let temp_token = v.req_str(obj, at, "temp_token", StrRules::any());
        Self {
            temp_token,
            factor: SecondFactor::read(v, obj, at),
        }
    }
}

/// `TOTPStatusResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusResponse {
    /// Whether 2FA is on.
    pub enabled: bool,
    /// `2FA status retrieved`.
    pub message: &'static str,
    /// Always `true`.
    pub success: bool,
}

/// `TOTPSetupResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetupResponse {
    /// The base32 secret (shown once).
    pub secret: String,
    /// `otpauth://totp/CoPilot:<user>?secret=…&issuer=CoPilot`.
    pub otpauth_url: String,
    /// The URL as a PNG QR code.
    pub qr_data_uri: String,
    /// Plaintext backup codes (shown once).
    pub backup_codes: Vec<String>,
    /// Instructions.
    pub message: &'static str,
}

/// `TOTPBackupCodesResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackupCodesResponse {
    /// The new codes (shown once).
    pub backup_codes: Vec<String>,
    /// Instructions.
    pub message: &'static str,
    /// Always `true`.
    pub success: bool,
}

/// `{"message", "success": true}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Done {
    /// What happened.
    pub message: &'static str,
    /// Always `true`.
    pub success: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_web::form::read_form;
    use serde_json::json;

    fn form(body: &str) -> Form {
        Form(read_form(Some("application/x-www-form-urlencoded"), body.as_bytes()).unwrap())
    }

    fn details(e: ApiError) -> Value {
        match e {
            ApiError::Validation(items) => serde_json::to_value(items).unwrap(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn oauth2_form_rules() {
        assert_eq!(
            LoginForm::read(&form("username=a&password=b&grant_type=password")).unwrap(),
            LoginForm {
                username: "a".into(),
                password: "b".into()
            }
        );
        assert_eq!(
            details(LoginForm::read(&form("grant_type=client&username=&password=")).unwrap_err()),
            json!([
                {"field": "grant_type", "error_type": "string_pattern_mismatch",
                 "message": "Value does not match the required pattern."},
                {"field": "username", "error_type": "missing",
                 "message": "Missing data for required field."},
                {"field": "password", "error_type": "missing",
                 "message": "Missing data for required field."}
            ])
        );
        // An empty grant_type is "not given".
        assert!(LoginForm::read(&form("grant_type=&username=a&password=b")).is_ok());
    }

    #[test]
    fn response_field_order() {
        assert_eq!(
            serde_json::to_string(&TwoFactorRequired {
                access_token: "t".into(),
                token_type: "bearer",
                requires_2fa: true
            })
            .unwrap(),
            r#"{"access_token":"t","token_type":"bearer","requires_2fa":true}"#
        );
        let f = SecondFactor {
            code: Some(String::new()),
            backup_code: None,
        };
        assert!(f.is_empty());
    }
}
