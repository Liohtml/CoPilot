//! Notification hand-off to the Python backend.
//!
//! The notification pipeline is still served by Python. A ported module
//! builds the exact `NotificationEvent` (`copilot_core::notify`) and this
//! sink POSTs it to `/api/notifications/events` with the acting user's token,
//! in the background — `emit()` never fails or delays the caller, exactly
//! like `app/notifications/services/emit.py`. The Python side re-derives the
//! dedupe key and link and checks the alert's customer
//! (`app/notifications/services/bridge.py`).

use std::time::Duration;

use copilot_core::notify::{NotificationEvent, NotificationSink};

use crate::legacy::LegacyProxy;

/// Path of the Python bridge endpoint.
pub const BRIDGE_PATH: &str = "/api/notifications/events";

/// Forwards events to the legacy backend.
#[derive(Debug, Clone)]
pub struct LegacyNotificationSink {
    proxy: LegacyProxy,
}

impl LegacyNotificationSink {
    /// Sink over the legacy proxy's backend.
    pub fn new(proxy: LegacyProxy) -> Self {
        Self { proxy }
    }

    /// Deliver one event now (tests, CLI).
    pub async fn deliver(
        &self,
        event: &NotificationEvent,
        bearer: Option<&str>,
    ) -> Result<(), String> {
        let mut req = self
            .proxy
            .client()
            .post(self.proxy.upstream_url(BRIDGE_PATH))
            .timeout(Duration::from_secs(30))
            .json(event);
        if let Some(token) = bearer.filter(|t| !t.is_empty()) {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await.map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Err(format!(
                "{status}: {}",
                body.chars().take(300).collect::<String>()
            ))
        }
    }
}

impl NotificationSink for LegacyNotificationSink {
    fn emit(&self, event: NotificationEvent, bearer: Option<String>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(
                trigger = event.trigger.as_str(),
                "notification emit skipped: no runtime"
            );
            return;
        };
        let sink = self.clone();
        handle.spawn(async move {
            match sink.deliver(&event, bearer.as_deref()).await {
                Ok(()) => tracing::debug!(dedupe = %event.dedupe_key, "notification handed to legacy backend"),
                Err(e) => tracing::warn!(dedupe = %event.dedupe_key, err = %e,
                    "notification hand-off failed"),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_core::notify::{
        AlertEventInput, NotificationDefaults, NotificationSeverity, investigation_complete_event,
    };
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn posts_the_event_with_the_callers_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(BRIDGE_PATH))
            .and(header("authorization", "Bearer tok"))
            .and(body_partial_json(serde_json::json!({
                "trigger": "investigation_complete",
                "entity_id": 9,
                "dedupe_key": "alert:9:investigation_complete"
            })))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;
        let proxy = LegacyProxy::new(url::Url::parse(&server.uri()).unwrap()).unwrap();
        let sink = LegacyNotificationSink::new(proxy);
        let event = investigation_complete_event(
            &NotificationDefaults {
                copilot_url: None,
                default_severity: NotificationSeverity::High,
            },
            &AlertEventInput {
                alert_id: 9,
                customer_code: Some("acme"),
                summary: "s",
                ..Default::default()
            },
        );
        sink.deliver(&event, Some("tok")).await.unwrap();
    }

    #[tokio::test]
    async fn reports_refusals() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("{\"message\":\"no\"}"))
            .mount(&server)
            .await;
        let proxy = LegacyProxy::new(url::Url::parse(&server.uri()).unwrap()).unwrap();
        let sink = LegacyNotificationSink::new(proxy);
        let event = investigation_complete_event(
            &NotificationDefaults {
                copilot_url: None,
                default_severity: NotificationSeverity::High,
            },
            &AlertEventInput {
                alert_id: 1,
                summary: "s",
                ..Default::default()
            },
        );
        let err = sink.deliver(&event, None).await.unwrap_err();
        assert!(err.starts_with("403"));
    }
}
