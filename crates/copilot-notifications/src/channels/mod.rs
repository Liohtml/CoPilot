//! The delivery channels (`app/notifications/channels/`): Shuffle, webhook,
//! Resend email and Microsoft Teams. Each knows its config model
//! ([`config`]), what the route form may offer for it ([`Channel`]'s
//! capabilities) and how to deliver one message ([`send`]).

pub mod config;
pub mod resend;
pub mod send;
pub mod shuffle;
pub mod teams;
pub mod webhook;

use serde_json::Value;

/// One channel provider (`ChannelProvider`). The registry order is
/// Python's: Shuffle, webhook, Resend, Teams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// Shuffle's hosted MCP (`shuffle`).
    Shuffle,
    /// A direct HTTP request (`webhook`).
    Webhook,
    /// Email through Resend (`resend`).
    Resend,
    /// A Microsoft Teams incoming webhook (`teams`).
    Teams,
}

impl Channel {
    /// Registry order (`CHANNEL_REGISTRY`).
    pub const ALL: [Channel; 4] = [
        Channel::Shuffle,
        Channel::Webhook,
        Channel::Resend,
        Channel::Teams,
    ];

    /// The `NotificationChannel` values, in enum order.
    pub const KEYS: [&'static str; 4] = ["shuffle", "webhook", "resend", "teams"];

    /// `get_channel(key)`.
    pub fn parse(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.key() == key)
    }

    /// `customer_notification_route.channel`.
    pub const fn key(self) -> &'static str {
        match self {
            Channel::Shuffle => "shuffle",
            Channel::Webhook => "webhook",
            Channel::Resend => "resend",
            Channel::Teams => "teams",
        }
    }

    /// The config model's class name (as `ValidationError` names it).
    pub const fn model_name(self) -> &'static str {
        match self {
            Channel::Shuffle => "ShuffleConfig",
            Channel::Webhook => "WebhookConfig",
            Channel::Resend => "ResendConfig",
            Channel::Teams => "TeamsConfig",
        }
    }

    /// `supports_recipient_modes`, sorted.
    pub const fn recipient_modes(self) -> &'static [&'static str] {
        match self {
            Channel::Resend => &["assignee", "static"],
            _ => &["static"],
        }
    }

    /// `template_formats`, sorted.
    pub const fn template_formats(self) -> &'static [&'static str] {
        match self {
            Channel::Resend => &["html", "markdown", "text"],
            _ => &["markdown", "text"],
        }
    }

    /// `supports_internal_scope`.
    pub const fn supports_internal_scope(self) -> bool {
        !matches!(self, Channel::Shuffle)
    }
}

/// `repr(sorted(set))` of a list of strings: `['assignee', 'static']`.
pub fn py_list_repr(items: &[&str]) -> String {
    let inner: Vec<String> = items.iter().map(|s| format!("'{s}'")).collect();
    format!("[{}]", inner.join(", "))
}

/// `GET /notification_channels`' list: each provider's descriptor, its
/// config model's JSON Schema included, as the Python backend renders it
/// (`channel_catalog.json`, `scripts/gen-notification-vectors.py`).
pub fn catalog() -> Value {
    serde_json::from_str(include_str!("../channel_catalog.json")).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_matches_the_capabilities() {
        let catalog = catalog();
        let list = catalog.as_array().unwrap();
        assert_eq!(list.len(), 4);
        for (entry, channel) in list.iter().zip(Channel::ALL) {
            assert_eq!(entry["key"], channel.key());
            assert_eq!(
                entry["supports_recipient_modes"],
                serde_json::json!(channel.recipient_modes())
            );
            assert_eq!(
                entry["template_formats"],
                serde_json::json!(channel.template_formats())
            );
            assert_eq!(
                entry["supports_internal_scope"],
                channel.supports_internal_scope()
            );
            assert_eq!(entry["config_schema"]["title"], channel.model_name());
        }
        assert_eq!(
            py_list_repr(&["assignee", "static"]),
            "['assignee', 'static']"
        );
    }
}
