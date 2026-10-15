//! User management — the users half of `app/auth/routes/auth.py`,
//! `routes/customer_users.py` and `services/customer_assignment.py`.
//!
//! Every write that sets a user's customers follows #1219: an analyst or
//! responder keeps at least one, an admin gets none (they see every customer
//! anyway), and every code must name an existing customer — compared exactly,
//! although MySQL found it case-insensitively. Creating a user, an admin's
//! password reset, a self-service password change, deleting a user and a role
//! change are audited like in Python; replacing a user's customers is not.

use std::collections::HashMap;

use serde_json::json;

use copilot_auth::password::{check_password, hash_password};
use copilot_core::audit::AuditRecord;
use copilot_core::roles::Role;
use copilot_db::users::{self, UserRow};
use copilot_web::{ApiError, CurrentUser};

use crate::IdentityState;
use crate::services::login::{self, audit, is_customer_user};
use crate::users_schema::{
    Assigned, LegacyLogin, LegacyLoginResponse, MyCustomers, NewUser, PasswordReset, RoleChange,
    RoleChanged, UserBase,
};

/// `NEEDS_A_CUSTOMER`.
pub const NEEDS_A_CUSTOMER: &str = "Analysts and responders must be assigned at least one customer";
/// `ADMIN_IS_DEPLOYMENT_WIDE`.
pub const ADMIN_IS_DEPLOYMENT_WIDE: &str =
    "Admins see every customer: assigning customers to an admin has no effect";

/// `encode_token`'s default lifetime, which the deprecated JSON login uses.
const LEGACY_TOKEN_TTL_SECS: i64 = 24 * 60 * 60;

/// The roles `PUT /users/{id}/role/by-name` accepts, in `RoleEnum` order.
const ROLE_NAMES: &[(&str, i32)] = &[
    ("admin", 1),
    ("analyst", 2),
    ("scheduler", 3),
    ("customer_user", 4),
    ("responder", 5),
];

fn is_customer_scoped_soc(role_id: Option<i32>) -> bool {
    matches!(role_id, Some(id) if id == Role::Analyst.id() || id == Role::Responder.id())
}

/// Python's `str.isspace()`.
fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `normalize_codes`: trimmed, de-duplicated, in the order given.
pub fn normalize_codes(codes: &[String]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for code in codes {
        let code = code.trim_matches(is_py_space);
        if !code.is_empty() && !seen.iter().any(|s| s == code) {
            seen.push(code.to_string());
        }
    }
    seen
}

/// `validate_assignment`: the codes to store for a user of `role_id`, or
/// the 400 saying why they cannot be.
pub async fn validate_assignment(
    st: &IdentityState,
    role_id: Option<i32>,
    codes: &[String],
) -> Result<Vec<String>, ApiError> {
    let codes = normalize_codes(codes);
    if role_id == Some(Role::Admin.id()) && !codes.is_empty() {
        return Err(ApiError::bad_request(ADMIN_IS_DEPLOYMENT_WIDE));
    }
    if is_customer_scoped_soc(role_id) && codes.is_empty() {
        return Err(ApiError::bad_request(NEEDS_A_CUSTOMER));
    }
    if !codes.is_empty() {
        let found = users::existing_customer_codes(&st.ctx.db, &codes).await?;
        let unknown: Vec<&str> = codes
            .iter()
            .filter(|c| !found.contains(c))
            .map(String::as_str)
            .collect();
        if !unknown.is_empty() {
            return Err(ApiError::bad_request(format!(
                "Unknown customer code(s): {}",
                unknown.join(", ")
            )));
        }
    }
    Ok(codes)
}

async fn hash(password: &str) -> Result<String, ApiError> {
    let password = password.to_string();
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)
}

async fn check(password: &str, stored: &str) -> Result<bool, ApiError> {
    let (password, stored) = (password.to_string(), stored.to_string());
    tokio::task::spawn_blocking(move || check_password(&password, &stored))
        .await
        .map_err(ApiError::internal)?
        // bcrypt's ValueError reaches the global handler: a 400 with its text.
        .map_err(ApiError::bad_request)
}

/// `find_user`: database errors read as "no such user".
async fn find_user(st: &IdentityState, username: &str) -> Option<(UserRow, String)> {
    match users::find_credentials(&st.ctx.db, username).await {
        Ok(found) => found,
        Err(e) => {
            tracing::error!(err = %e, "user lookup failed");
            None
        }
    }
}

fn base(user: UserRow, roles: &HashMap<i32, String>) -> UserBase {
    UserBase {
        role_name: user.role_id.and_then(|id| roles.get(&id).cloned()),
        id: user.id,
        username: user.username,
        email: user.email,
        role_id: user.role_id,
        last_login_at: user.last_login_at,
        customer_codes: None,
    }
}

fn event(action: &str, actor: &CurrentUser, username: &str) -> AuditRecord {
    AuditRecord::new(action)
        .actor(Some(actor.id), Some(&actor.username))
        .entity("user", username)
        .source_ip(actor.source_ip.clone())
}

/// `register`.
pub async fn register(
    st: &IdentityState,
    actor: &CurrentUser,
    new: &NewUser,
) -> Result<(), ApiError> {
    let existing = users::usernames_and_emails(&st.ctx.db).await?;
    if existing.iter().any(|(_, email)| *email == new.email) {
        return Err(ApiError::bad_request("Email is already registered"));
    }
    if existing
        .iter()
        .any(|(username, _)| *username == new.username)
    {
        return Err(ApiError::bad_request("Username is taken"));
    }
    let role_id = i32::try_from(new.role_id).map_err(ApiError::internal)?;
    let codes = validate_assignment(st, Some(role_id), &new.customer_codes).await?;
    let hashed = hash(&new.password).await?;
    users::create_user(
        &st.ctx.db,
        &new.username,
        &hashed,
        &new.email,
        role_id,
        &codes,
    )
    .await?;
    tracing::info!(username = %new.username, role_id, "user created");
    audit(
        st,
        event("user.create", actor, &new.username).values(
            None,
            Some(json!({
                "username": new.username,
                "email": new.email,
                "role_id": role_id,
                "customer_codes": codes,
            })),
        ),
    );
    Ok(())
}

/// The deprecated `POST /auth/login` (JSON): no audit, no `last_login_at`,
/// a 24-hour token whatever `ACCESS_TOKEN_EXPIRE_MINUTES` says.
pub async fn legacy_login(
    st: &IdentityState,
    req: &LegacyLogin,
) -> Result<LegacyLoginResponse, ApiError> {
    let refused = || ApiError::unauthorized("Invalid username and/or password");
    let (user, stored) = find_user(st, &req.username).await.ok_or_else(refused)?;
    if !check(&req.password, &stored).await? {
        return Err(refused());
    }
    if is_customer_user(user.role_id) {
        tracing::warn!(username = %user.username, "customer user attempted to log in to main portal");
        return Err(ApiError::forbidden(
            "This account is registered for the Customer Portal only. Please log in at the Customer Portal to access your account.",
        ));
    }
    let role = login::role_name(st, &user.username, user.role_id).await?;
    let token = st
        .ctx
        .jwt
        .issue_session(&user.username, &role, LEGACY_TOKEN_TTL_SECS, None)
        .map_err(ApiError::internal)?;
    Ok(LegacyLoginResponse {
        token,
        message: "Login successful",
        success: true,
    })
}

/// `get_users`: an admin also sees each user's customers (sorted).
pub async fn list(
    st: &IdentityState,
    viewer: &CurrentUser,
    search: Option<&str>,
    limit: Option<i64>,
) -> Result<Vec<UserBase>, ApiError> {
    let rows = users::list_users(&st.ctx.db, search, limit).await?;
    let roles = users::role_names(&st.ctx.db).await?;
    let mut list: Vec<UserBase> = rows.into_iter().map(|u| base(u, &roles)).collect();
    if viewer.role_id == Some(Role::Admin.id()) {
        let ids: Vec<i32> = list.iter().map(|u| u.id).collect();
        let mut by_user: HashMap<i32, Vec<String>> = HashMap::new();
        for (user_id, code) in users::assignments_of(&st.ctx.db, &ids).await? {
            by_user.entry(user_id).or_default().push(code);
        }
        for user in &mut list {
            let mut codes = by_user.remove(&user.id).unwrap_or_default();
            codes.sort();
            user.customer_codes = Some(codes);
        }
    }
    Ok(list)
}

/// `get_user_by_id`.
pub async fn detail(st: &IdentityState, user_id: i64) -> Result<UserBase, ApiError> {
    let not_found = || ApiError::not_found(format!("User {user_id} not found"));
    let id = i32::try_from(user_id).map_err(|_| not_found())?;
    let user = match users::find_by_id(&st.ctx.db, id).await {
        Ok(user) => user,
        Err(e) => {
            tracing::error!(err = %e, "user lookup failed");
            None
        }
    }
    .ok_or_else(not_found)?;
    let roles = users::role_names(&st.ctx.db).await?;
    Ok(base(user, &roles))
}

/// `reset_password_via_username` (admin).
pub async fn admin_reset_password(
    st: &IdentityState,
    actor: &CurrentUser,
    req: &PasswordReset,
) -> Result<(), ApiError> {
    let (user, _) = find_user(st, &req.username)
        .await
        .ok_or_else(|| ApiError::not_found("User not found"))?;
    users::set_password(&st.ctx.db, user.id, &hash(&req.new_password).await?).await?;
    audit(
        st,
        event("user.update", actor, &user.username).details("Password reset by admin"),
    );
    Ok(())
}

/// `reset_password_me`: the token must belong to the named user, and the
/// current password is checked when given.
pub async fn self_reset_password(
    st: &IdentityState,
    caller: &CurrentUser,
    req: &PasswordReset,
) -> Result<(), ApiError> {
    let (user, stored) = find_user(st, &req.username)
        .await
        .ok_or_else(|| ApiError::not_found("User not found"))?;
    // verify_reset_token_me: decoded again, compared exactly.
    let claims = st
        .ctx
        .jwt
        .decode_claims(&caller.bearer)
        .map_err(|e| match e {
            copilot_auth::TokenError::Expired => ApiError::unauthorized("Token expired"),
            _ => ApiError::unauthorized("Invalid token"),
        })?;
    let sub = claims
        .get("sub")
        .and_then(|s| s.as_str())
        .ok_or_else(|| ApiError::internal("token without `sub`"))?;
    if sub != user.username {
        return Err(ApiError::unauthorized(
            "Invalid token. Username does not match.",
        ));
    }
    if let Some(current) = &req.current_password {
        if !check(current, &stored).await? {
            return Err(ApiError::bad_request("Current password is incorrect"));
        }
    }
    users::set_password(&st.ctx.db, user.id, &hash(&req.new_password).await?).await?;
    audit(
        st,
        AuditRecord::new("user.update")
            .actor(Some(user.id), Some(&user.username))
            .entity("user", &user.username)
            .source_ip(caller.source_ip.clone())
            .details("Self-service password change"),
    );
    Ok(())
}

async fn user_by_id(st: &IdentityState, user_id: i64) -> Result<Option<UserRow>, ApiError> {
    match i32::try_from(user_id) {
        Ok(id) => Ok(users::find_by_id(&st.ctx.db, id).await?),
        Err(_) => Ok(None),
    }
}

/// `delete_user_by_username` (by id; the built-in admin, id 1, stays).
pub async fn delete(st: &IdentityState, actor: &CurrentUser, user_id: i64) -> Result<(), ApiError> {
    let target = user_by_id(st, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found."))?;
    if target.id == 1 {
        return Err(ApiError::forbidden("Cannot delete admin user"));
    }
    if let Err(e) = users::delete_user(&st.ctx.db, target.id).await {
        tracing::error!(user_id, err = %e, "error deleting user");
        return Err(ApiError::server_error("Error deleting user"));
    }
    tracing::info!(user_id, "user deleted");
    audit(
        st,
        event("user.delete", actor, &target.username).values(
            Some(json!({"username": target.username, "role_id": target.role_id})),
            None,
        ),
    );
    Ok(())
}

/// `update_user_role_by_name`.
pub async fn change_role(
    st: &IdentityState,
    actor: &CurrentUser,
    user_id: i64,
    req: &RoleChange,
) -> Result<RoleChanged, ApiError> {
    let user = user_by_id(st, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;
    let wanted = req.role_name.to_lowercase();
    let Some(&(_, role_id)) = ROLE_NAMES.iter().find(|(name, _)| *name == wanted) else {
        let names: Vec<String> = ROLE_NAMES.iter().map(|(n, _)| format!("'{n}'")).collect();
        return Err(ApiError::bad_request(format!(
            "Invalid role name. Valid roles are: [{}]",
            names.join(", ")
        )));
    };
    let old_codes = users::assigned_customer_codes(&st.ctx.db, user.id).await?;
    let new_codes = match &req.customer_codes {
        Some(codes) => Some(validate_assignment(st, Some(role_id), codes).await?),
        None if is_customer_scoped_soc(Some(role_id)) && old_codes.is_empty() => {
            return Err(ApiError::bad_request(NEEDS_A_CUSTOMER));
        }
        None => None,
    };
    users::set_role(&st.ctx.db, user.id, role_id, new_codes.as_deref()).await?;
    audit(
        st,
        event("user.role_change", actor, &user.username)
            .values(
                Some(json!({"role_id": user.role_id, "customer_codes": old_codes})),
                Some(json!({
                    "role_id": role_id,
                    "customer_codes": new_codes.as_ref().unwrap_or(&old_codes),
                })),
            )
            .details(format!("Role changed to {}", req.role_name)),
    );
    Ok(RoleChanged {
        message: format!(
            "User {} role updated successfully to {}",
            user.username, req.role_name
        ),
        success: true,
        user_id,
        new_role_name: req.role_name.clone(),
        new_role_id: role_id,
    })
}

/// `assign_customer_access`: replace a user's customers (not audited).
pub async fn assign(
    st: &IdentityState,
    user_id: i64,
    codes: &[String],
) -> Result<Assigned, ApiError> {
    let user = user_by_id(st, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;
    let codes = validate_assignment(st, user.role_id, codes).await?;
    users::replace_assignment(&st.ctx.db, user.id, &codes).await?;
    Ok(Assigned {
        success: true,
        message: format!("Assigned {} customers to user {user_id}", codes.len()),
        customer_codes: codes,
    })
}

/// `get_user_customer_access` (no check that the user exists).
pub async fn assignment(st: &IdentityState, user_id: i64) -> Result<Vec<String>, ApiError> {
    match i32::try_from(user_id) {
        Ok(id) => Ok(users::assigned_customer_codes(&st.ctx.db, id).await?),
        Err(_) => Ok(Vec::new()),
    }
}

/// `get_my_customer_access`.
pub async fn my_customers(st: &IdentityState, user: &CurrentUser) -> Result<MyCustomers, ApiError> {
    let codes = match user.role_id {
        Some(id) if id == Role::Admin.id() => vec!["*".to_string()],
        Some(id)
            if id == Role::Analyst.id()
                || id == Role::Responder.id()
                || id == Role::CustomerUser.id() =>
        {
            users::assigned_customer_codes(&st.ctx.db, user.id).await?
        }
        _ => Vec::new(),
    };
    let scope = if codes.iter().any(|c| c == "*") {
        "deployment"
    } else if codes.is_empty() {
        "unassigned"
    } else {
        "assigned"
    };
    Ok(MyCustomers {
        success: true,
        customer_codes: codes,
        scope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_trimmed_and_deduplicated_in_order() {
        let codes: Vec<String> = ["  b", "a", "b ", "", "\u{1c}", "a"]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(normalize_codes(&codes), ["b", "a"]);
    }
}
