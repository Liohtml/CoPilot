//! User management shapes — `app/auth/models/users.py` (`UserInput`,
//! `UserLogin`, `PasswordReset`), `app/auth/schema/auth.py`
//! (`UpdateUserRoleRequest`) and `app/auth/schema/user.py` (`UserBase`).

use chrono::NaiveDateTime;
use serde::Serialize;
use serde_json::{Map, Value};

use copilot_core::time::pydantic;
use copilot_web::validate::{Loc, LocPart, StrRules, Validator};

/// `RoleEnum` values.
pub const ROLE_IDS: &[i64] = &[1, 2, 3, 4, 5];

/// bcrypt's input limit, enforced as a length: 8–72 characters. (The
/// password `regex=` on these models is not applied by SQLModel under
/// Pydantic 2, so the length is the only rule — kept that way.)
const PASSWORD: StrRules = StrRules {
    min_len: Some(8),
    max_len: Some(72),
    strip_control: false,
};

fn child(at: &Loc, name: &str) -> Loc {
    let mut l = at.clone();
    l.push(LocPart::Key(name.into()));
    l
}

/// `UserInput` — `POST /auth/register`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUser {
    /// Login name.
    pub username: String,
    /// Plain password (hashed by the service).
    pub password: String,
    /// The normalized address (`EmailStr`).
    pub email: String,
    /// `RoleEnum`, analyst by default.
    pub role_id: i64,
    /// Customers to assign.
    pub customer_codes: Vec<String>,
}

impl NewUser {
    /// Read in declaration order.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let username = v.req_str(obj, at, "username", StrRules::any());
        let password = v.req_str(obj, at, "password", PASSWORD);
        let email = v.req_email(obj, at, "email");
        let role_id = v.int_enum_or(obj, at, "role_id", ROLE_IDS, 2);
        let customer_codes = match obj.get("customer_codes") {
            None => Vec::new(),
            Some(value) => v.str_items(value, &child(at, "customer_codes")),
        };
        Self {
            username,
            password,
            email,
            role_id,
            customer_codes,
        }
    }
}

/// `UserLogin` — the deprecated `POST /auth/login`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyLogin {
    /// Login name.
    pub username: String,
    /// Password.
    pub password: String,
}

impl LegacyLogin {
    /// Read in declaration order.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            username: v.req_str(obj, at, "username", StrRules::any()),
            password: v.req_str(obj, at, "password", StrRules::any()),
        }
    }
}

/// `PasswordReset`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordReset {
    /// Whose password.
    pub username: String,
    /// Checked when given (self-service).
    pub current_password: Option<String>,
    /// The new password.
    pub new_password: String,
}

impl PasswordReset {
    /// Read in declaration order.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            username: v.req_str(obj, at, "username", StrRules::any()),
            current_password: v.opt_str(obj, at, "current_password", StrRules::any()),
            new_password: v.req_str(obj, at, "new_password", PASSWORD),
        }
    }
}

/// `UpdateUserRoleRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleChange {
    /// `admin`, `analyst`, … (any case).
    pub role_name: String,
    /// Replaces the user's customers when given.
    pub customer_codes: Option<Vec<String>>,
}

impl RoleChange {
    /// Read in declaration order.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let role_name = v.req_str(obj, at, "role_name", StrRules::any());
        let customer_codes = match obj.get("customer_codes") {
            None | Some(Value::Null) => None,
            Some(value) => Some(v.str_items(value, &child(at, "customer_codes"))),
        };
        Self {
            role_name,
            customer_codes,
        }
    }
}

/// `UserBase`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserBase {
    /// Primary key.
    pub id: i32,
    /// Login name.
    pub username: String,
    /// Address as stored (not re-validated).
    pub email: String,
    /// FK to `role`.
    pub role_id: Option<i32>,
    /// The role's name.
    pub role_name: Option<String>,
    /// Last successful login.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub last_login_at: Option<NaiveDateTime>,
    /// Assigned customers, in the admin's view of the list only.
    pub customer_codes: Option<Vec<String>>,
}

/// `UserBaseResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsersResponse {
    /// The users.
    pub users: Vec<UserBase>,
    /// `Users retrieved successfully`.
    pub message: &'static str,
    /// Always `true`.
    pub success: bool,
}

/// `UserDetailResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserDetailResponse {
    /// Always `true`.
    pub success: bool,
    /// `User retrieved successfully`.
    pub message: &'static str,
    /// The user.
    pub user: UserBase,
}

/// `UserLoginResponse` (the deprecated JSON login).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LegacyLoginResponse {
    /// A session token.
    pub token: String,
    /// `Login successful`.
    pub message: &'static str,
    /// Always `true`.
    pub success: bool,
}

/// The answer of `PUT /users/{id}/role/by-name`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoleChanged {
    /// `User <name> role updated successfully to <role_name>`.
    pub message: String,
    /// Always `true`.
    pub success: bool,
    /// The user.
    pub user_id: i64,
    /// The role name as sent.
    pub new_role_name: String,
    /// Its id.
    pub new_role_id: i32,
}

/// `{"success", "message", "customer_codes"}` — an assignment was replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Assigned {
    /// Always `true`.
    pub success: bool,
    /// `Assigned <n> customers to user <id>`.
    pub message: String,
    /// What is stored now.
    pub customer_codes: Vec<String>,
}

/// `{"success", "customer_codes"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Assignment {
    /// Always `true`.
    pub success: bool,
    /// The user's customers.
    pub customer_codes: Vec<String>,
}

/// `GET /auth/me/customers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MyCustomers {
    /// Always `true`.
    pub success: bool,
    /// `["*"]` for an admin, else the assigned codes.
    pub customer_codes: Vec<String>,
    /// `deployment` | `assigned` | `unassigned`.
    pub scope: &'static str,
}

/// `{"message", "success": true}` with a computed message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Message {
    /// What happened.
    pub message: &'static str,
    /// Always `true`.
    pub success: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_web::ApiError;
    use copilot_web::body::JsonBody;
    use serde_json::json;

    fn details(e: ApiError) -> Value {
        match e {
            ApiError::Validation(items) => serde_json::to_value(items).unwrap(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn user_input_rules() {
        let ok = JsonBody::Value(json!({"username": "u", "password": "lowercase1!",
            "email": "Foo@Example.COM", "role_id": "5", "customer_codes": ["A"]}))
        .model(NewUser::read)
        .unwrap();
        assert_eq!(ok.email, "Foo@example.com");
        assert_eq!(ok.role_id, 5);
        let bad = JsonBody::Value(json!({"password": "short", "email": "nope", "role_id": 9,
            "customer_codes": [1]}))
        .model(NewUser::read)
        .unwrap_err();
        assert_eq!(
            details(bad),
            json!([
                {"field": "username", "error_type": "missing", "message": "Missing data for required field."},
                {"field": "password", "error_type": "string_too_short", "message": "Value is shorter than minimum length."},
                {"field": "email", "error_type": "value_error",
                 "message": "email: value is not a valid email address: An email address must have an @-sign."},
                {"field": "role_id", "error_type": "enum", "message": "Value is not a valid enumeration member."},
                {"field": "0", "error_type": "value_error", "message": "customer_codes.0: Input should be a valid string"}
            ])
        );
        let null_codes = JsonBody::Value(json!({"username": "u", "password": "Passw0rd!",
            "email": "a@b.com", "customer_codes": null}))
        .model(NewUser::read)
        .unwrap_err();
        assert_eq!(details(null_codes)[0]["field"], "customer_codes");
    }

    #[test]
    fn role_change_codes_are_optional() {
        let r = JsonBody::Value(json!({"role_name": "Admin", "customer_codes": null}))
            .model(RoleChange::read)
            .unwrap();
        assert_eq!(r.customer_codes, None);
    }
}
