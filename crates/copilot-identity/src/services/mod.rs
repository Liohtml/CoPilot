//! Business logic: password login and session tokens ([`login`]), TOTP 2FA
//! ([`two_factor`]), user management ([`users`]), SSO ([`sso`]), passkeys
//! ([`passkeys`]), the admin Security tab ([`security`]) and its
//! temporary-password email ([`temp_password`], [`branding`]).

/// The `branding` template variable lives with the notification templates.
pub use copilot_notifications::branding;
pub mod login;
pub mod passkeys;
pub mod security;
pub mod sso;
pub mod temp_password;
pub mod two_factor;
pub mod users;
