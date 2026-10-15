//! Tenant scoping — port of `app/middleware/customer_access.py`.
//!
//! Route gating uses the token's `scopes` (a snapshot taken at login); tenant
//! scoping uses the user's *live* `role_id` and `user_customer_access` rows.
//! The two disagree for a demoted admin until their token expires, and that is
//! the Python behaviour on purpose: tenancy follows the database immediately.
//!
//! Decisions here are pure; the rows come from `copilot-db`.

use copilot_core::Role;

/// What a user may see: Python's `["*"]` (admins) or an explicit list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessScope {
    /// Every customer (admins). Python: `["*"]`, never stored.
    All,
    /// Exactly these customers, in `user_customer_access` order; empty = none.
    Customers(Vec<String>),
}

/// A 403 from a tenant check. `Display` is the detail the Python backend sends.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Access denied to {0}")]
pub struct AccessDenied(pub String);

impl AccessScope {
    /// `get_user_accessible_customers`: admin → all; analyst, responder and
    /// customer_user → their rows; scheduler or no role → nothing.
    pub fn for_user(role_id: Option<i32>, assigned: Vec<String>) -> Self {
        match role_id.and_then(Role::from_id) {
            Some(Role::Admin) => AccessScope::All,
            Some(Role::Analyst | Role::Responder | Role::CustomerUser) => {
                AccessScope::Customers(assigned)
            }
            Some(Role::Scheduler) | None => AccessScope::Customers(Vec::new()),
        }
    }

    /// Whether the scope is deployment-wide.
    pub fn is_all(&self) -> bool {
        matches!(self, AccessScope::All)
    }

    /// `check_customer_access`: admins pass any string, even unknown codes.
    pub fn can_access(&self, customer_code: &str) -> bool {
        match self {
            AccessScope::All => true,
            AccessScope::Customers(codes) => codes.iter().any(|c| c == customer_code),
        }
    }

    /// `enforce_customer_access` → `Access denied to customer {code}`.
    pub fn enforce_customer(&self, customer_code: &str) -> Result<(), AccessDenied> {
        if self.can_access(customer_code) {
            Ok(())
        } else {
            Err(AccessDenied(format!("customer {customer_code}")))
        }
    }

    /// `enforce_owned_object_access`: fail closed. An object whose owner
    /// cannot be resolved (`None`/empty — including one that does not exist)
    /// is denied to every scoped caller; admins pass.
    pub fn enforce_owned(&self, owner: Option<&str>, subject: &str) -> Result<(), AccessDenied> {
        match (self, owner) {
            (AccessScope::All, _) => Ok(()),
            (AccessScope::Customers(codes), Some(owner))
                if !owner.is_empty() && codes.iter().any(|c| c == owner) =>
            {
                Ok(())
            }
            _ => Err(AccessDenied(subject.to_string())),
        }
    }

    /// `resolve_effective_customers`: with nothing requested, everything the
    /// user may see; admins get the request verbatim; others get the
    /// intersection, in request order.
    pub fn resolve_effective(&self, requested: Option<&[String]>) -> AccessScope {
        match (self, requested) {
            (_, None) => self.clone(),
            (_, Some([])) => self.clone(),
            (AccessScope::All, Some(req)) => AccessScope::Customers(req.to_vec()),
            (AccessScope::Customers(codes), Some(req)) => AccessScope::Customers(
                req.iter()
                    .filter(|c| codes.iter().any(|a| a == *c))
                    .cloned()
                    .collect(),
            ),
        }
    }

    /// `scoped_customer_codes`: `None` = no filter; `Some(vec![])` = the
    /// caller sees nothing and the route must return an empty result itself
    /// (services read an empty list as "all customers").
    pub fn scoped_customer_codes(&self, requested: Option<&[String]>) -> Option<Vec<String>> {
        match self.resolve_effective(requested) {
            AccessScope::All => None,
            AccessScope::Customers(codes) => Some(codes),
        }
    }

    /// `GET /auth/me/customers` scope label.
    pub fn label(&self) -> &'static str {
        match self {
            AccessScope::All => "deployment",
            AccessScope::Customers(codes) if !codes.is_empty() => "assigned",
            AccessScope::Customers(_) => "unassigned",
        }
    }

    /// The Python list form (`["*"]` for admins).
    pub fn to_python_list(&self) -> Vec<String> {
        match self {
            AccessScope::All => vec!["*".to_string()],
            AccessScope::Customers(codes) => codes.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn role_mapping() {
        assert_eq!(
            AccessScope::for_user(Some(1), codes(&["a"])),
            AccessScope::All
        );
        assert_eq!(
            AccessScope::for_user(Some(5), codes(&["a"])),
            AccessScope::Customers(codes(&["a"]))
        );
        assert_eq!(
            AccessScope::for_user(Some(3), codes(&["a"])),
            AccessScope::Customers(vec![])
        );
        assert_eq!(
            AccessScope::for_user(None, codes(&["a"])),
            AccessScope::Customers(vec![])
        );
    }

    #[test]
    fn enforce_messages_match_python() {
        let s = AccessScope::Customers(codes(&["acme"]));
        assert!(s.enforce_customer("acme").is_ok());
        assert_eq!(
            s.enforce_customer("beta").unwrap_err().to_string(),
            "Access denied to customer beta"
        );
        assert_eq!(
            s.enforce_owned(None, "job x").unwrap_err().to_string(),
            "Access denied to job x"
        );
        assert!(s.enforce_owned(Some(""), "report 1").is_err());
        assert!(s.enforce_owned(Some("acme"), "report 1").is_ok());
        assert!(AccessScope::All.enforce_owned(None, "anything").is_ok());
        assert!(AccessScope::All.enforce_customer("does-not-exist").is_ok());
    }

    #[test]
    fn scoped_codes_semantics() {
        let analyst = AccessScope::Customers(codes(&["a", "b"]));
        assert_eq!(
            analyst.scoped_customer_codes(None),
            Some(codes(&["a", "b"]))
        );
        assert_eq!(
            analyst.scoped_customer_codes(Some(&codes(&["b", "z"]))),
            Some(codes(&["b"]))
        );
        assert_eq!(
            analyst.scoped_customer_codes(Some(&codes(&["z"]))),
            Some(vec![])
        );
        assert_eq!(AccessScope::All.scoped_customer_codes(None), None);
        assert_eq!(
            AccessScope::All.scoped_customer_codes(Some(&codes(&["q"]))),
            Some(codes(&["q"]))
        );
        let none = AccessScope::Customers(vec![]);
        assert_eq!(none.scoped_customer_codes(None), Some(vec![]));
        assert_eq!(none.label(), "unassigned");
        assert_eq!(analyst.label(), "assigned");
        assert_eq!(AccessScope::All.to_python_list(), vec!["*"]);
    }
}
