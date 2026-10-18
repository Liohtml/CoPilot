//! Tag-based alert access (tag RBAC) — port of
//! `app/incidents/middleware/tag_access.py:TagAccessHandler`.
//!
//! Tag RBAC is a second dimension next to customer scoping: with the global
//! switch on (`incident_management_tag_access_settings.enabled`), a scoped
//! SOC user sees only alerts carrying a tag opened to them (per user, or per
//! role including the roles theirs extends), plus untagged alerts as the
//! `untagged_alert_behavior` setting says. Admins, the scheduler and portal
//! users bypass it (a customer always sees all of their own alerts).
//!
//! The Python handler answers the untagged question in **two different
//! ways** and both are kept, because both are observable:
//!
//! | `untagged_alert_behavior` | lists ([`TagScope::for_lists`]) | one alert ([`can_access_alert`]) |
//! |---|---|---|
//! | `visible_to_all` | included | allowed |
//! | `admin_only` | excluded | denied |
//! | `default_tag`, tag set and accessible | included | allowed |
//! | `default_tag`, tag set, not accessible | excluded | denied |
//! | `default_tag`, **no** tag configured | **excluded** | **allowed** |
//! | anything else | excluded | allowed |

use std::collections::BTreeSet;

use copilot_core::Role;

/// `incident_management_tag_access_settings` (the first row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagAccessSettings {
    /// Global switch; off = no tag filtering at all.
    pub enabled: bool,
    /// `admin_only` | `visible_to_all` | `default_tag`.
    pub untagged_alert_behavior: String,
    /// The tag untagged alerts count as under `default_tag`.
    pub default_tag_id: Option<i32>,
}

/// Which tags a user may see (`get_user_accessible_tags`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagSet {
    /// `{"*"}`: no tag restriction.
    All,
    /// Exactly these tag ids (possibly none).
    Tags(BTreeSet<i32>),
}

impl TagSet {
    fn contains(&self, tag: i32) -> bool {
        match self {
            TagSet::All => true,
            TagSet::Tags(t) => t.contains(&tag),
        }
    }
}

/// `UNRESTRICTED_ROLES`: admin, scheduler and customer_user bypass tag RBAC.
pub fn is_unrestricted(role_id: Option<i32>) -> bool {
    matches!(
        role_id.and_then(Role::from_id),
        Some(Role::Admin | Role::Scheduler | Role::CustomerUser)
    )
}

/// Role ids whose `role_tag_access` rows apply: the role and the roles it
/// extends (a responder gets the analyst role's tags, #1219).
pub fn tag_role_ids(role_id: Option<i32>) -> Vec<i32> {
    match role_id {
        None => Vec::new(),
        Some(id) => match Role::from_id(id) {
            Some(role) => role.effective().into_iter().map(Role::id).collect(),
            None => vec![id],
        },
    }
}

/// `get_user_accessible_tags`, given the rows already read.
pub fn accessible_tags(
    settings: Option<&TagAccessSettings>,
    role_id: Option<i32>,
    user_tags: &[i32],
    role_tags: &[i32],
) -> TagSet {
    if !settings.is_some_and(|s| s.enabled) || is_unrestricted(role_id) {
        return TagSet::All;
    }
    TagSet::Tags(user_tags.iter().chain(role_tags).copied().collect())
}

/// What an alert list may contain, tag-wise (`build_alert_query_filters`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagScope {
    /// No tag filter.
    All,
    /// Alerts with one of `tags`, plus untagged ones when `include_untagged`.
    Restricted {
        /// Accessible tag ids.
        tags: BTreeSet<i32>,
        /// Whether alerts without any tag are visible.
        include_untagged: bool,
    },
}

impl TagScope {
    /// The list rule. `tags` is [`accessible_tags`] for the same user.
    pub fn for_lists(
        settings: Option<&TagAccessSettings>,
        role_id: Option<i32>,
        tags: TagSet,
    ) -> Self {
        let Some(s) = settings.filter(|s| s.enabled) else {
            return TagScope::All;
        };
        if is_unrestricted(role_id) {
            return TagScope::All;
        }
        let tags = match tags {
            TagSet::All => return TagScope::All,
            TagSet::Tags(t) => t,
        };
        let include_untagged = match s.untagged_alert_behavior.as_str() {
            "visible_to_all" => true,
            "default_tag" => s
                .default_tag_id
                .is_some_and(|d| d != 0 && tags.contains(&d)),
            _ => false,
        };
        TagScope::Restricted {
            tags,
            include_untagged,
        }
    }

    /// Whether the scope can match no alert at all (Python returns `None`
    /// from `alert_visibility_filters_for_user`, and callers short-circuit).
    pub fn sees_nothing(&self) -> bool {
        matches!(self, TagScope::Restricted { tags, include_untagged: false } if tags.is_empty())
    }
}

/// `can_user_access_alert`: the single-alert rule. `alert_tags` are the
/// alert's `incident_management_alert_to_tag` ids.
pub fn can_access_alert(
    settings: Option<&TagAccessSettings>,
    role_id: Option<i32>,
    alert_tags: &[i32],
    tags: &TagSet,
) -> bool {
    let Some(s) = settings.filter(|s| s.enabled) else {
        return true;
    };
    if is_unrestricted(role_id) {
        return true;
    }
    if alert_tags.is_empty() {
        return match s.untagged_alert_behavior.as_str() {
            "visible_to_all" => true,
            "admin_only" => false,
            "default_tag" => s.default_tag_id.is_none_or(|d| tags.contains(d)),
            _ => true,
        };
    }
    alert_tags.iter().any(|t| tags.contains(*t))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(behavior: &str, default_tag: Option<i32>) -> TagAccessSettings {
        TagAccessSettings {
            enabled: true,
            untagged_alert_behavior: behavior.into(),
            default_tag_id: default_tag,
        }
    }

    fn set(t: &[i32]) -> TagSet {
        TagSet::Tags(t.iter().copied().collect())
    }

    #[test]
    fn disabled_or_unrestricted_means_everything() {
        let off = TagAccessSettings {
            enabled: false,
            ..settings("admin_only", None)
        };
        assert_eq!(accessible_tags(Some(&off), Some(2), &[], &[]), TagSet::All);
        assert_eq!(accessible_tags(None, Some(2), &[], &[]), TagSet::All);
        for role in [1, 3, 4] {
            assert_eq!(
                accessible_tags(Some(&settings("admin_only", None)), Some(role), &[], &[]),
                TagSet::All
            );
            assert!(can_access_alert(
                Some(&settings("admin_only", None)),
                Some(role),
                &[],
                &set(&[])
            ));
        }
        assert_eq!(
            TagScope::for_lists(Some(&settings("admin_only", None)), Some(4), TagSet::All),
            TagScope::All
        );
    }

    #[test]
    fn responder_inherits_analyst_tags() {
        assert_eq!(tag_role_ids(Some(5)), vec![5, 2]);
        assert_eq!(tag_role_ids(Some(2)), vec![2]);
        assert_eq!(tag_role_ids(None), Vec::<i32>::new());
        assert_eq!(
            accessible_tags(Some(&settings("admin_only", None)), Some(5), &[1], &[7]),
            set(&[1, 7])
        );
    }

    #[test]
    fn list_and_single_alert_rules_differ_only_where_python_does() {
        let s = settings("default_tag", None);
        // Lists: no default tag configured → untagged excluded.
        assert_eq!(
            TagScope::for_lists(Some(&s), Some(2), set(&[3])),
            TagScope::Restricted {
                tags: [3].into(),
                include_untagged: false
            }
        );
        // One alert: no default tag configured → untagged allowed.
        assert!(can_access_alert(Some(&s), Some(2), &[], &set(&[3])));

        let s = settings("default_tag", Some(3));
        assert_eq!(
            TagScope::for_lists(Some(&s), Some(2), set(&[3])),
            TagScope::Restricted {
                tags: [3].into(),
                include_untagged: true
            }
        );
        assert!(!can_access_alert(Some(&s), Some(2), &[], &set(&[4])));

        let s = settings("visible_to_all", None);
        assert!(can_access_alert(Some(&s), Some(2), &[], &set(&[])));
        assert!(!TagScope::for_lists(Some(&s), Some(2), set(&[])).sees_nothing());

        let s = settings("admin_only", None);
        assert!(!can_access_alert(Some(&s), Some(2), &[], &set(&[9])));
        assert!(TagScope::for_lists(Some(&s), Some(2), set(&[])).sees_nothing());
    }

    #[test]
    fn tagged_alerts_need_one_accessible_tag() {
        let s = settings("admin_only", None);
        assert!(can_access_alert(Some(&s), Some(2), &[1, 2], &set(&[2])));
        assert!(!can_access_alert(Some(&s), Some(2), &[1, 2], &set(&[3])));
    }
}
