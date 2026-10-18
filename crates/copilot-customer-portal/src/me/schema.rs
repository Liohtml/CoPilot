//! Port of `app/customer_portal/schema/me.py`.

use serde::Serialize;

/// `PortalCustomer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortalCustomer {
    /// The key.
    pub customer_code: String,
    /// The name (the code when it has none).
    pub customer_name: String,
}

/// `PortalMeResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortalMeResponse {
    /// Always `true`.
    pub success: bool,
    /// Message.
    pub message: String,
    /// The user.
    pub username: String,
    /// `RoleEnum(role_id).name`.
    pub role: String,
    /// Their customers, by name.
    pub customers: Vec<PortalCustomer>,
}
