//! Microsoft Teams delivery (`channels/teams.py`, `dispatch_teams`): an
//! Adaptive Card envelope, cut to Teams' 28 KB ceiling.

use std::time::Instant;

use copilot_auth::pyvalue::PyValue;
use copilot_jinja::Event;

use crate::channels::Channel;
use crate::channels::send::{
    FAILED, SENT, SendResult, cfg_str, elapsed_ms, first_200, parse_config, response_text, secs,
    transport_error,
};
use crate::db::RouteRow;
use crate::dispatcher::Dispatcher;
use crate::pyjson::{self, Dumps};
use crate::services::render::Rendered;

/// `TEAMS_MAX_PAYLOAD_BYTES`.
pub const MAX_PAYLOAD_BYTES: usize = 28 * 1024;

const TIMEOUT_S: u64 = 15;
const TRUNCATED: &str = "\n\n…truncated by CoPilot to fit Teams' 28 KB limit.";

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

fn dict(items: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn style(severity: &str) -> &'static str {
    match severity {
        "Critical" | "High" => "attention",
        "Medium" => "warning",
        "Low" => "good",
        _ => "default",
    }
}

/// `_build_card(event, body, raw_body=…)`.
pub fn build_card(e: &Event, body: &str, raw_body: bool) -> PyValue {
    let mut elements = vec![dict(vec![
        ("type", s("Container")),
        ("style", s(style(&e.severity))),
        ("bleed", PyValue::Bool(true)),
        (
            "items",
            PyValue::List(vec![dict(vec![
                ("type", s("TextBlock")),
                ("text", s(&format!("{} · {}", e.severity, e.subject))),
                ("weight", s("Bolder")),
                ("size", s("Medium")),
                ("wrap", PyValue::Bool(true)),
            ])]),
        ),
    ])];
    if !raw_body {
        let fact = |title: &str, value: &str| dict(vec![("title", s(title)), ("value", s(value))]);
        let mut facts = vec![fact("Trigger", &e.trigger.replace('_', " "))];
        if let Some(c) = e.customer_code.as_deref().filter(|c| !c.is_empty()) {
            facts.push(fact("Customer", c));
        }
        facts.push(fact(
            "Entity",
            &format!("{} #{}", e.entity_type, e.entity_id),
        ));
        if let Some(a) = e.assignee_username.as_deref().filter(|a| !a.is_empty()) {
            facts.push(fact("Assignee", a));
        }
        if let Some(a) = e.actor_username.as_deref().filter(|a| !a.is_empty()) {
            facts.push(fact("By", a));
        }
        elements.push(dict(vec![
            ("type", s("FactSet")),
            ("facts", PyValue::List(facts)),
        ]));
    }
    elements.push(dict(vec![
        ("type", s("TextBlock")),
        ("text", s(body)),
        ("wrap", PyValue::Bool(true)),
    ]));
    let mut content = vec![
        (
            "$schema",
            s("http://adaptivecards.io/schemas/adaptive-card.json"),
        ),
        ("type", s("AdaptiveCard")),
        ("version", s("1.4")),
    ];
    let link = e.link_url.as_deref().filter(|l| !l.is_empty());
    if let Some(link) = link {
        elements.push(dict(vec![
            ("type", s("TextBlock")),
            ("text", s(&format!("[Open in CoPilot]({link})"))),
            ("wrap", PyValue::Bool(true)),
            ("isSubtle", PyValue::Bool(true)),
        ]));
    }
    content.push(("body", PyValue::List(elements)));
    if let Some(link) = link {
        content.push((
            "actions",
            PyValue::List(vec![dict(vec![
                ("type", s("Action.OpenUrl")),
                ("title", s("Open in CoPilot")),
                ("url", s(link)),
            ])]),
        ));
    }
    dict(vec![
        ("type", s("message")),
        (
            "attachments",
            PyValue::List(vec![dict(vec![
                ("contentType", s("application/vnd.microsoft.card.adaptive")),
                ("contentUrl", PyValue::None),
                ("content", dict(content)),
            ])]),
        ),
    ])
}

fn size(card: &PyValue) -> usize {
    pyjson::dumps(card, Dumps::DEFAULT)
        .map(|j| j.len())
        .unwrap_or(usize::MAX)
}

/// `_fit_within_size_limit`: the card, or the longest body prefix that
/// fits (binary search over code points).
pub fn fit(card: PyValue, e: &Event, body: &str) -> PyValue {
    if size(&card) <= MAX_PAYLOAD_BYTES {
        return card;
    }
    let chars: Vec<char> = body.chars().collect();
    let (mut low, mut high) = (0i64, chars.len() as i64);
    let mut best = String::new();
    while low <= high {
        let mid = (low + high) / 2;
        let candidate: String = chars[..mid as usize].iter().collect();
        let trial = build_card(e, &format!("{candidate}{TRUNCATED}"), true);
        if size(&trial) <= MAX_PAYLOAD_BYTES {
            best = candidate;
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }
    build_card(e, &format!("{best}{TRUNCATED}"), true)
}

/// `TeamsChannel.send`.
pub async fn send(d: &Dispatcher, route: &RouteRow, e: &Event, message: &Rendered) -> SendResult {
    let has_template = route
        .format_template
        .as_deref()
        .is_some_and(|t| !t.is_empty());
    let cfg = match parse_config(Channel::Teams, route) {
        Ok(c) => c,
        Err(err) => return SendResult::failed(format!("Invalid teams config: {err}")),
    };
    let Some(url) = cfg_str(&cfg, "webhook_url").filter(|u| !u.is_empty()) else {
        return SendResult::failed("Route config has no webhook_url (data integrity issue)");
    };
    let card = fit(build_card(e, &message.body, has_template), e, &message.body);
    let started = Instant::now();
    let body = match pyjson::dumps(&card, Dumps::HTTPX) {
        Ok(b) => b,
        Err(err) => {
            return SendResult::from_parts(
                FAILED,
                Some(format!("ValueError: {err}")),
                elapsed_ms(started),
                None,
            );
        }
    };
    let result = d
        .outbound()
        .http
        .post(&url)
        .timeout(secs(TIMEOUT_S))
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await;
    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = response_text(resp).await;
            let latency = elapsed_ms(started);
            if status == 429 {
                SendResult::from_parts(
                    FAILED,
                    Some(
                        "Teams rate-limited this request (429). Teams throttles above ~4 \
                         requests/second."
                            .into(),
                    ),
                    latency,
                    None,
                )
            } else if status >= 400 {
                SendResult::from_parts(
                    FAILED,
                    Some(format!("Teams returned {status}: {}", first_200(&text))),
                    latency,
                    None,
                )
            } else {
                SendResult::from_parts(SENT, None, latency, None)
            }
        }
        Err(err) => {
            tracing::warn!(err = %err, "Teams dispatch failed");
            SendResult::from_parts(
                FAILED,
                Some(transport_error(&err)),
                elapsed_ms(started),
                None,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> Event {
        Event {
            customer_code: Some("ACME".into()),
            trigger: "alert_created".into(),
            severity: "High".into(),
            subject: "S".into(),
            summary: "x".into(),
            entity_type: "alert".into(),
            entity_id: 1,
            dedupe_key: "k".into(),
            link_url: Some("https://c/a/1".into()),
            assignee_username: None,
            actor_username: None,
            context: vec![],
        }
    }

    /// `teams_vectors.json`: the card Python posts, for each event, body
    /// and body mode (`scripts/gen-notification-vectors.py`).
    #[test]
    fn cards_match_the_python_provider() {
        use sha2::{Digest, Sha256};
        let vectors: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../teams_vectors.json")).unwrap();
        assert_eq!(vectors.len(), 24);
        for v in vectors {
            let ev = &v["event"];
            let opt = |k: &str| ev[k].as_str().map(str::to_string);
            let e = Event {
                customer_code: opt("customer_code"),
                trigger: opt("trigger").unwrap(),
                severity: opt("severity").unwrap(),
                subject: opt("subject").unwrap(),
                summary: opt("summary").unwrap(),
                entity_type: opt("entity_type").unwrap(),
                entity_id: ev["entity_id"].as_i64().unwrap(),
                dedupe_key: opt("dedupe_key").unwrap(),
                link_url: opt("link_url"),
                assignee_username: opt("assignee_username"),
                actor_username: opt("actor_username"),
                context: vec![],
            };
            let body = v["body"]
                .as_str()
                .unwrap()
                .repeat(v["repeat"].as_u64().unwrap() as usize);
            let raw = v["raw_body"].as_bool().unwrap();
            let card = fit(build_card(&e, &body, raw), &e, &body);
            let ours = pyjson::dumps(&card, Dumps::DEFAULT).unwrap();
            if let Some(expected) = v["card"].as_str() {
                assert_eq!(ours, expected);
            }
            assert_eq!(ours.len() as u64, v["length"].as_u64().unwrap());
            let digest: String = Sha256::digest(ours.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(digest, v["sha256"].as_str().unwrap(), "{}", &ours[..200]);
        }
    }

    #[test]
    fn oversized_bodies_are_cut_to_fit() {
        let body = "é".repeat(40_000);
        let card = fit(build_card(&event(), &body, false), &event(), &body);
        let size = size(&card);
        assert!(size <= MAX_PAYLOAD_BYTES, "{size}");
        assert!(size > MAX_PAYLOAD_BYTES - 10, "{size}");
    }
}
