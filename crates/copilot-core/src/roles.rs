//! Roles and token scopes — port of `app/auth/models/users.py` (`RoleEnum`,
//! `ROLE_EXTENDS`, `effective_roles`, `SOC_ROLES`, `CUSTOMER_SCOPED_SOC_ROLES`)
//! and `app/auth/utils.py:role_scopes`.
//!
//! The numeric ids are fixed and seeded explicitly in the `role` table
//! (migration `c1219a2b3c4d`); never derive them from declaration order.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A CoPilot role. Serialized as its lowercase name, the form tokens carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Deployment-wide administrator.
    Admin,
    /// SOC analyst, scoped to the customers assigned to them.
    Analyst,
    /// The built-in user automated jobs act as.
    Scheduler,
    /// Customer Portal user.
    CustomerUser,
    /// An analyst who may also run response actions on their customers (#1219).
    Responder,
}

impl Role {
    /// Every role, in id order.
    pub const ALL: [Role; 5] = [
        Role::Admin,
        Role::Analyst,
        Role::Scheduler,
        Role::CustomerUser,
        Role::Responder,
    ];

    /// The fixed `role.id`.
    pub const fn id(self) -> i32 {
        match self {
            Role::Admin => 1,
            Role::Analyst => 2,
            Role::Scheduler => 3,
            Role::CustomerUser => 4,
            Role::Responder => 5,
        }
    }

    /// Role for a `role.id`.
    pub const fn from_id(id: i32) -> Option<Role> {
        match id {
            1 => Some(Role::Admin),
            2 => Some(Role::Analyst),
            3 => Some(Role::Scheduler),
            4 => Some(Role::CustomerUser),
            5 => Some(Role::Responder),
            _ => None,
        }
    }

    /// The name stored in `role.name` and carried as a token scope.
    pub const fn name(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Analyst => "analyst",
            Role::Scheduler => "scheduler",
            Role::CustomerUser => "customer_user",
            Role::Responder => "responder",
        }
    }

    /// Roles this role extends (`ROLE_EXTENDS`).
    pub const fn extends(self) -> &'static [Role] {
        match self {
            Role::Responder => &[Role::Analyst],
            _ => &[],
        }
    }

    /// The role itself first, then the roles it extends (`effective_roles`).
    pub fn effective(self) -> Vec<Role> {
        let mut out = vec![self];
        out.extend_from_slice(self.extends());
        out
    }

    /// Token scopes for this role (`role_scopes`): `["responder", "analyst"]`
    /// for a responder, the bare name otherwise.
    pub fn scopes(self) -> Vec<String> {
        self.effective()
            .into_iter()
            .map(|r| r.name().to_string())
            .collect()
    }

    /// `SOC_ROLES`: everyone who works in the SOC.
    pub const fn is_soc(self) -> bool {
        matches!(self, Role::Admin | Role::Analyst | Role::Responder)
    }

    /// `CUSTOMER_SCOPED_SOC_ROLES`: SOC staff limited to their assigned
    /// customers — no assignment means no customer.
    pub const fn is_customer_scoped_soc(self) -> bool {
        matches!(self, Role::Analyst | Role::Responder)
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Error for an unknown role name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown role: {0}")]
pub struct UnknownRole(pub String);

impl FromStr for Role {
    type Err = UnknownRole;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Role::ALL
            .into_iter()
            .find(|r| r.name() == s)
            .ok_or_else(|| UnknownRole(s.to_string()))
    }
}

/// `role_scopes(role)` for a role *name*: unknown names pass through as a
/// single scope, exactly like the Python helper's `KeyError` branch.
pub fn scopes_for_role_name(role: &str) -> Vec<String> {
    role.parse::<Role>()
        .map(Role::scopes)
        .unwrap_or_else(|_| vec![role.to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_fixed() {
        for role in Role::ALL {
            assert_eq!(Role::from_id(role.id()), Some(role));
        }
        assert_eq!(Role::Responder.id(), 5);
        assert_eq!(Role::from_id(6), None);
    }

    #[test]
    fn responder_extends_analyst() {
        assert_eq!(Role::Responder.scopes(), vec!["responder", "analyst"]);
        assert_eq!(Role::Analyst.scopes(), vec!["analyst"]);
        assert_eq!(scopes_for_role_name("mystery"), vec!["mystery"]);
    }

    #[test]
    fn role_sets() {
        assert!(Role::Admin.is_soc() && !Role::Admin.is_customer_scoped_soc());
        assert!(Role::Responder.is_customer_scoped_soc());
        assert!(!Role::CustomerUser.is_soc() && !Role::Scheduler.is_soc());
    }

    #[test]
    fn serde_uses_names() {
        assert_eq!(
            serde_json::to_string(&Role::CustomerUser).unwrap(),
            "\"customer_user\""
        );
        assert_eq!("responder".parse::<Role>().unwrap(), Role::Responder);
    }
}
