//! End-to-end tests of the SIEM and threat-intel ports (`copilot-siem`,
//! `copilot-threat-intel`): `/api/siem/dashboards`, `/api/siem/event_sources`,
//! `/api/siem/events` and `/api/threat_intel` on the production router
//! against a real MySQL at the Alembic head, the Wazuh indexer, SOCFortress,
//! VirusTotal and api.first.org replaced by mocks (the threat-intel tests
//! that call out use the crate's router with its URLs on the mock).
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13310/copilot \
//!   cargo test -p copilot --test e2e_siem -- --test-threads=1
//! ```
//!
//! The tests that need the deployment's `Wazuh-Indexer` connector row create
//! it, point it at the mock and delete it again (the harness runs with the
//! connector cache off). Byte-for-byte parity with Python is
//! `backend/tests/e2e/rust_parity_siem_e2e.py`'s job; these pin the tenancy
//! rules and the shapes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

const D: &str = "/api/siem/dashboards";
const S: &str = "/api/siem/event_sources";
const EV: &str = "/api/siem/events";

async fn cleanup(h: &Harness) {
    let s = &h.suffix;
    for sql in [
        format!("DELETE FROM enabled_dashboards WHERE customer_code LIKE '%{s}'"),
        format!(
            "DELETE FROM custom_dashboard_templates WHERE customer_code LIKE '%{s}' \
             OR template_key LIKE '%{s}%'"
        ),
        format!("DELETE FROM event_sources WHERE customer_code LIKE '%{s}'"),
        "DELETE FROM connectors WHERE connector_name = 'Wazuh-Indexer'".to_string(),
    ] {
        h.exec(&sql).await;
    }
}

/// An event source of `customer`; returns its id.
async fn source(h: &Harness, customer: &str, name: &str, pattern: &str) -> i64 {
    sqlx::query(
        "INSERT INTO event_sources (customer_code, name, index_pattern, event_type, time_field, \
         enabled, displayed_columns, created_at, updated_at) VALUES (?, ?, ?, 'EDR', 'timestamp', \
         1, NULL, '2026-10-01 10:00:00', '2026-10-01 10:00:00')",
    )
    .bind(customer)
    .bind(name)
    .bind(pattern)
    .execute(h.db.pool())
    .await
    .unwrap()
    .last_insert_id()
    .try_into()
    .unwrap()
}

/// The `Wazuh-Indexer` connector, pointed at `url`.
async fn indexer(h: &Harness, url: &str) {
    h.exec("DELETE FROM connectors WHERE connector_name = 'Wazuh-Indexer'")
        .await;
    sqlx::query(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, \
         connector_username, connector_password, connector_api_key, connector_description, \
         connector_supports, connector_configured, connector_verified, connector_accepts_host_only, \
         connector_accepts_api_key, connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
         ('Wazuh-Indexer', '4.8', ?, '2026-01-02 03:04:05', 'u', 'p', NULL, 'desc', 'supports', 1, 1, \
         0, 0, 1, 0, 0, NULL, 1)",
    )
    .bind(url)
    .execute(h.db.pool())
    .await
    .unwrap();
}

fn keys(body: &Value, list: &str, key: &str) -> Vec<String> {
    let mut out: Vec<String> = body[list]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t[key].as_str().unwrap().to_string())
        .collect();
    out.sort();
    out
}

fn panels(title: &str) -> Value {
    json!([
        {"title": title, "type": "stat"},
        {"title": "Top agents", "type": "pie", "field": "agent_name"},
        {"title": "Rows", "type": "table", "fields": [" agent_name ", ""]},
    ])
}

#[tokio::test]
async fn built_in_templates_are_compiled_in() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let portal = h.token(&format!("portal{s}"), "customer_user");

    let (status, body) = h
        .call("GET", &format!("{D}/templates"), Some(&portal), None)
        .await;
    assert_eq!(status, 200, "{body}");
    let ids: Vec<&str> = body["categories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "aws_cloudintegration",
            "office365_cloudintegration",
            "wazuh_edr"
        ],
        "sorted by directory, `custom` never listed"
    );
    let (status, body) = h
        .call(
            "GET",
            &format!("{D}/templates/wazuh_edr"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(status, 200);
    let first = body["category"]["templates"][0].as_object().unwrap();
    assert_eq!(
        first.keys().map(String::as_str).collect::<Vec<_>>(),
        ["id", "title", "description", "panels"]
    );
    assert_eq!(first["id"], "EDR_DNS_QUERIES", "sorted by file name");
    for missing in ["nope", "custom", "%2E%2E", "wazuh_edr%00"] {
        let (status, body) = h
            .call(
                "GET",
                &format!("{D}/templates/{missing}"),
                Some(&portal),
                None,
            )
            .await;
        assert_eq!(status, 404, "{missing}: {body}");
    }
    let (status, _) = h.call("GET", &format!("{D}/templates"), None, None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn custom_templates_shared_and_scoped_across_two_tenants() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let src_a = source(&h, &acme, "EDR", "wazuh-a-*").await;
    let src_b = source(&h, &beta, "EDR", "wazuh-b-*").await;

    let mut created = Vec::new();
    for (title, customer) in [
        (format!("Shared {s}"), Value::Null),
        (format!("Acme {s}"), json!(acme)),
        (format!("Beta {s}"), json!(beta)),
    ] {
        let (status, body) = h
            .call(
                "POST",
                &format!("{D}/custom"),
                Some(&admin),
                Some(json!({"title": title, "customer_code": customer, "panels": panels("Total")})),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let row = &body["custom_dashboard"];
        assert_eq!(row["default_query"], "*");
        assert_eq!(
            row["panels"][0]["id"], "total",
            "ids are slugs of the titles"
        );
        assert_eq!(row["panels"][2]["fields"], json!(["agent_name"]));
        assert_eq!(row["created_by"], format!("admin{s}"));
        created.push(row["template_key"].as_str().unwrap().to_string());
    }
    let (shared, acme_key, beta_key) = (&created[0], &created[1], &created[2]);
    assert_eq!(shared, &format!("shared_{s}"));

    // A second dashboard of the same title gets a suffixed key.
    let (_, body) = h
        .call(
            "POST",
            &format!("{D}/custom"),
            Some(&admin),
            Some(json!({"title": format!("Shared {s}"), "panels": panels("Total")})),
        )
        .await;
    assert_eq!(
        body["custom_dashboard"]["template_key"],
        format!("shared_{s}_2")
    );

    // The analyst (acme) sees the shared ones and acme's, never beta's.
    let (status, body) = h
        .call("GET", &format!("{D}/custom"), Some(&analyst), None)
        .await;
    assert_eq!(status, 200);
    let seen = keys(&body, "custom_dashboards", "template_key");
    assert!(seen.contains(shared) && seen.contains(acme_key), "{seen:?}");
    assert!(!seen.contains(beta_key), "{seen:?}");
    let (status, body) = h
        .call(
            "GET",
            &format!("{D}/custom?customer_code={beta}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (403, json!(format!("Access denied to customer {beta}")))
    );
    for (method, uri) in [
        ("GET", format!("{D}/custom/{beta_key}")),
        ("GET", format!("{D}/custom/{beta_key}/export")),
        ("DELETE", format!("{D}/custom/{beta_key}")),
    ] {
        let (status, _) = h.call(method, &uri, Some(&analyst), None).await;
        assert_eq!(status, 403, "{method} {uri}");
    }

    // A scoped template is enabled for its own customer only.
    let enable = |template: &str, customer: &str, src: i64| {
        json!({"customer_code": customer, "event_source_id": src, "library_card": "custom",
               "template_id": template, "display_name": "d"})
    };
    let (status, body) = h
        .call(
            "POST",
            &format!("{D}/enable"),
            Some(&admin),
            Some(enable(beta_key, &acme, src_a)),
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (
            403,
            json!(format!(
                "Custom dashboard '{beta_key}' is scoped to customer {beta}"
            ))
        )
    );
    for (customer, src) in [(&acme, src_a), (&beta, src_b)] {
        let (status, body) = h
            .call(
                "POST",
                &format!("{D}/enable"),
                Some(&admin),
                Some(enable(shared, customer, src)),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }
    let (status, body) = h
        .call(
            "POST",
            &format!("{D}/enable"),
            Some(&analyst),
            Some(enable(acme_key, &acme, src_a)),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // Narrowing a shared template enabled for beta is refused.
    let (status, body) = h
        .call(
            "PUT",
            &format!("{D}/custom/{shared}"),
            Some(&admin),
            Some(json!({"customer_code": acme})),
        )
        .await;
    assert_eq!(status, 400, "{body}");

    // §4: an analyst cannot file anything under beta.
    let (status, _) = h
        .call(
            "POST",
            &format!("{D}/custom"),
            Some(&analyst),
            Some(json!({"title": format!("Sneaky {s}"), "customer_code": beta, "panels": panels("T")})),
        )
        .await;
    assert_eq!(status, 403);
    let (status, _) = h
        .call(
            "POST",
            &format!("{D}/custom/import"),
            Some(&analyst),
            Some(
                json!({"definition": {"template_key": format!("imp_{s}"), "title": "I",
                                       "panels": panels("T")}, "customer_code": beta}),
            ),
        )
        .await;
    assert_eq!(status, 403);
    let (status, _) = h
        .call(
            "POST",
            &format!("{D}/custom/import"),
            Some(&analyst),
            Some(json!({"definition": {"template_key": beta_key, "title": "I", "panels": panels("T")},
                        "overwrite": true})),
        )
        .await;
    assert_eq!(status, 403, "an overwrite replaces beta's template");
    let (status, _) = h
        .call(
            "PUT",
            &format!("{D}/custom/{}", created[0]),
            Some(&analyst),
            Some(json!({"customer_code": beta})),
        )
        .await;
    assert_eq!(status, 403);
    let n = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM custom_dashboard_templates WHERE template_key LIKE '%{s}%' \
             AND (customer_code IS NULL OR customer_code = '{beta}') AND title LIKE 'Sneaky%'"
        ))
        .await;
    assert_eq!(n, 0);

    // Export and import round-trip; a collision is a 409 unless overwrite.
    let (status, body) = h
        .call(
            "GET",
            &format!("{D}/custom/{acme_key}/export"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200);
    let definition = body["definition"].clone();
    assert_eq!(definition["template_key"], json!(acme_key));
    let (status, body) = h
        .call(
            "POST",
            &format!("{D}/custom/import"),
            Some(&analyst),
            Some(json!({"definition": definition})),
        )
        .await;
    assert_eq!(status, 409, "{body}");
    let (status, body) = h
        .call(
            "POST",
            &format!("{D}/custom/import"),
            Some(&analyst),
            Some(json!({"definition": definition, "overwrite": true, "customer_code": acme})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["custom_dashboard"]["customer_code"], json!(acme));

    // Deleting a template removes every dashboard enabled from it.
    let (status, body) = h
        .call(
            "DELETE",
            &format!("{D}/custom/{shared}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["disabled_dashboards"], 2);
    assert_eq!(
        body["message"],
        "Custom dashboard deleted successfully along with 2 enabled dashboard(s)"
    );
    let left = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM enabled_dashboards WHERE template_id = '{shared}'"
        ))
        .await;
    assert_eq!(left, 0);
    cleanup(&h).await;
}

#[tokio::test]
async fn event_sources_and_dashboards_check_the_tenant() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let portal = h.token(&format!("portal{s}"), "customer_user");
    let src_b = source(&h, &beta, "EDR", "wazuh-b-*").await;

    let body = json!({"customer_code": acme, "name": "EDR", "index_pattern": "wazuh-a-*",
                      "event_type": "EDR", "displayed_columns": [{"key": "agent_name", "label": "Agent"}]});
    let (status, created) = h.call("POST", S, Some(&analyst), Some(body.clone())).await;
    assert_eq!(status, 200, "{created}");
    let src_a = created["event_source"]["id"].as_i64().unwrap();
    assert_eq!(
        created["event_source"]["displayed_columns"],
        json!([{"key": "agent_name", "label": "Agent", "width": null}])
    );
    let mut same_name = body.clone();
    same_name["name"] = json!("edr");
    let (status, dup) = h.call("POST", S, Some(&analyst), Some(same_name)).await;
    assert_eq!(status, 400, "names compare under MySQL's collation: {dup}");
    let (status, _) = h
        .call(
            "POST",
            S,
            Some(&analyst),
            Some(json!({"customer_code": beta, "name": "x", "index_pattern": "x", "event_type": "EDR"})),
        )
        .await;
    assert_eq!(status, 403, "§4: the body's customer is checked");
    let (status, body) = h
        .call(
            "PUT",
            &format!("{S}/{src_b}"),
            Some(&analyst),
            Some(json!({"index_pattern": "*"})),
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (403, json!(format!("Access denied to event source {src_b}")))
    );
    let (status, body) = h
        .call(
            "PUT",
            &format!("{S}/{src_a}"),
            Some(&analyst),
            Some(json!({"displayed_columns": [{"key": "k", "label": "K"}]})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let stored: String = sqlx::query_scalar(
        "SELECT CAST(displayed_columns AS CHAR) FROM event_sources WHERE id = ?",
    )
    .bind(src_a)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        stored, r#"[{"key": "k", "label": "K"}]"#,
        "an update stores only the fields sent"
    );
    let (status, body) = h
        .call("GET", &format!("{S}/{acme}"), Some(&portal), None)
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["event_sources"][0]["id"], src_a);
    let (status, _) = h
        .call("GET", &format!("{S}/{beta}"), Some(&portal), None)
        .await;
    assert_eq!(status, 403);
    let (status, _) = h
        .call("DELETE", &format!("{S}/{src_a}"), Some(&analyst), None)
        .await;
    assert_eq!(status, 403, "deleting is admin only");

    let enable = |customer: &str, src: i64| {
        json!({"customer_code": customer, "event_source_id": src, "library_card": "wazuh_edr",
               "template_id": "EDR_OVERVIEW", "display_name": "Overview"})
    };
    for (customer, src) in [(&beta, src_b), (&acme, src_b)] {
        let (status, body) = h
            .call(
                "POST",
                &format!("{D}/enable"),
                Some(&analyst),
                Some(enable(customer, src)),
            )
            .await;
        assert_eq!(
            (status.as_u16(), body["message"].clone()),
            (403, json!(format!("Access denied to customer {beta}"))),
            "§4: the body's customer and the event source's"
        );
    }
    let (status, body) = h
        .call(
            "POST",
            &format!("{D}/enable"),
            Some(&analyst),
            Some(enable(&acme, src_a)),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let mine = body["enabled_dashboard"]["id"].as_i64().unwrap();
    let (status, body) = h
        .call(
            "POST",
            &format!("{D}/enable"),
            Some(&analyst),
            Some(enable(&acme, src_a)),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    let (status, body) = h
        .call(
            "POST",
            &format!("{D}/enable"),
            Some(&admin),
            Some(enable(&beta, src_b)),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let theirs = body["enabled_dashboard"]["id"].as_i64().unwrap();

    let (status, body) = h
        .call("GET", &format!("{D}/enabled"), Some(&portal), None)
        .await;
    assert_eq!(status, 200);
    let ids: Vec<i64> = body["enabled_dashboards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_i64().unwrap())
        .collect();
    assert!(ids.contains(&mine) && !ids.contains(&theirs), "{ids:?}");
    let (status, body) = h
        .call(
            "POST",
            &format!("{D}/panel-data"),
            Some(&portal),
            Some(json!({"dashboard_id": theirs})),
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (403, json!(format!("Access denied to customer {beta}")))
    );
    let (status, _) = h
        .call(
            "DELETE",
            &format!("{D}/disable/{theirs}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 403);
    let (status, body) = h
        .call(
            "DELETE",
            &format!("{D}/disable/{mine}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    cleanup(&h).await;
}

#[tokio::test]
async fn panels_and_events_run_against_the_indexer() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let acme = h.code("acme");
    let portal = h.token(&format!("portal{s}"), "customer_user");
    let es = MockServer::start().await;
    indexer(&h, &es.uri()).await;
    let src = source(&h, &acme, "Wazuh EDR", "wazuh-a-*").await;

    let hits = json!({"total": {"value": 3, "relation": "eq"}, "hits": [
        {"_index": "wazuh-a-1", "_id": "d1", "_source": {"agent_name": "dc01", "data": {"win": {"id": 7}}}},
        {"_index": "wazuh-a-1", "_id": "d2", "_source": {"agent_name": "web01"}},
    ]});
    Mock::given(method("POST"))
        .and(path("/wazuh-a-*/_search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "_scroll_id": "sc-1",
            "hits": hits,
            "aggregations": {"top_values": {"buckets": [{"key": 3, "doc_count": 2}]},
                             "over_time": {"buckets": [{"key_as_string": "t0", "doc_count": 1}]}},
        })))
        .mount(&es)
        .await;
    Mock::given(method("GET"))
        .and(path("/wazuh-a-1/_doc/d1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {"_index": "wazuh-a-1", "_id": "d1", "found": true, "_source": {"agent_name": "dc01"}}
        )))
        .mount(&es)
        .await;
    Mock::given(method("POST"))
        .and(path("/wazuh-a-*/_field_caps"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"fields": {
            "_id": {"_id": {"type": "_id", "metadata_field": true}},
            "msg": {"text": {"type": "text"}},
            "msg.keyword": {"keyword": {"type": "keyword"}},
            "data": {"object": {"type": "object"}},
            "data.id": {"long": {"type": "long"}, "keyword": {"type": "keyword"}},
        }})))
        .mount(&es)
        .await;

    // Panel data of a custom dashboard: the dashboard's query is ANDed in.
    let (status, body) = h
        .call(
            "POST",
            &format!("{D}/custom"),
            Some(&h.token(&format!("admin{s}"), "admin")),
            Some(json!({"title": format!("Panels {s}"), "customer_code": acme,
                        "default_query": "agent_name:dc01", "color": "#123456",
                        "panels": [{"title": "Total", "type": "stat"},
                                   {"title": "Top", "type": "bar_h", "field": "rule"},
                                   {"title": "Rows", "type": "table", "fields": ["agent_name", "data.win"]}]})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let key = body["custom_dashboard"]["template_key"]
        .as_str()
        .unwrap()
        .to_string();
    let dashboard = h
        .exec(&format!(
            "INSERT INTO enabled_dashboards (customer_code, event_source_id, library_card, \
             template_id, display_name, created_at) VALUES ('{acme}', {src}, 'custom', '{key}', \
             'Mine', UTC_TIMESTAMP())"
        ))
        .await;
    let (status, body) = h
        .call(
            "POST",
            &format!("{D}/panel-data"),
            Some(&portal),
            Some(json!({"dashboard_id": dashboard, "timerange": "7d"})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["accent_color"], "#123456");
    assert_eq!(
        body["panels"]["total"],
        json!({"type": "stat", "value": 3, "labels": null,
        "data": null, "columns": null, "rows": null, "error": null})
    );
    assert_eq!(body["panels"]["top"]["labels"], json!(["3"]));
    assert_eq!(
        body["panels"]["rows"]["rows"],
        json!([{"agent_name": "dc01", "data.win": "{\"id\": 7}"}, {"agent_name": "web01", "data.win": null}])
    );
    let sent = es.received_requests().await.unwrap();
    assert_eq!(sent.len(), 3);
    let first: Value = serde_json::from_slice(&sent[0].body).unwrap();
    let must = &first["query"]["bool"]["must"];
    assert_eq!(must.as_array().unwrap().len(), 3, "{first}");
    assert_eq!(must[2]["query_string"]["query"], "agent_name:dc01");
    assert_eq!(
        sent[0]
            .headers
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        sent[0].body.len().to_string()
    );

    // Events: one page (the scroll is cleared when it fits), a document,
    // the field names.
    let page = format!("{EV}/{acme}/Wazuh%20EDR?page_size=2");
    let (status, body) = h.call("GET", &page, Some(&portal), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total"], 3);
    assert_eq!(body["scroll_id"], "sc-1", "2 of 3: the scroll is kept");
    assert_eq!(body["events"][0]["_id"], "d1");
    assert_eq!(body["message"], "Retrieved 2 of 3 events");
    let (status, body) = h
        .call(
            "GET",
            &format!("{EV}/{acme}/Wazuh%20EDR/document?index_name=wazuh-a-1&event_id=d1"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["event"],
        json!({"agent_name": "dc01", "_id": "d1", "_index": "wazuh-a-1"})
    );
    let (status, body) = h
        .call(
            "GET",
            &format!("{EV}/{acme}/Wazuh%20EDR/document?index_name=other-1&event_id=d1"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (
            400,
            json!("Index 'other-1' does not match event source pattern 'wazuh-a-*'")
        )
    );
    let (status, body) = h
        .call(
            "GET",
            &format!("{EV}/{acme}/Wazuh%20EDR/fields"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["fields"],
        json!([{"field": "data.id", "type": "keyword, long"}, {"field": "msg", "type": "text"}])
    );
    let (status, _) = h
        .call(
            "GET",
            &format!("{EV}/{}/Wazuh%20EDR", h.code("beta")),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(status, 403);
    cleanup(&h).await;
}

// --- /api/threat_intel ----------------------------------------------------------------

const TI: &str = "/api/threat_intel";

/// The threat-intel routes with every upstream URL on `upstream` (the
/// parity harness's `COPILOT_*_URL` overrides, set here without touching the
/// process environment).
fn ti_router(h: &Harness, upstream: &str) -> axum::Router {
    let mut st = h.app.threat_intel.clone();
    st.urls = std::sync::Arc::new(copilot_threat_intel::urls::Urls {
        epss: format!("{upstream}/data/v1/epss"),
        intel: format!("{upstream}/search"),
        ai: upstream.to_string(),
        mcp: format!("{upstream}/query"),
        license: format!("{upstream}/"),
        virustotal: format!("{upstream}/api/v3"),
    });
    copilot_threat_intel::router(st)
}

/// `get_license` reads the first `license` row: the test's own is the only
/// one until [`restore_licences`] puts the others back.
async fn own_licence(h: &Harness, key: &str) -> Vec<(i64, String, String, String, String)> {
    let saved = sqlx::query_as::<_, (i64, String, String, String, String)>(
        "SELECT id, license_key, customer_name, customer_email, company_name FROM license",
    )
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    h.exec("DELETE FROM license").await;
    h.exec(&format!(
        "INSERT INTO license (license_key, customer_name, customer_email, company_name) \
         VALUES ('{key}', 'e2e', 'e2e@example.com', 'e2e')"
    ))
    .await;
    saved
}

async fn restore_licences(
    h: &Harness,
    key: &str,
    saved: Vec<(i64, String, String, String, String)>,
) {
    h.exec(&format!(
        "DELETE FROM license_cache WHERE license_key = '{key}'"
    ))
    .await;
    h.exec(&format!("DELETE FROM license WHERE license_key = '{key}'"))
        .await;
    for (id, k, name, email, company) in saved {
        sqlx::query(
            "INSERT INTO license (id, license_key, customer_name, customer_email, company_name) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(k)
        .bind(name)
        .bind(email)
        .bind(company)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
}

async fn virustotal_connector(h: &Harness, url: Option<&str>) {
    h.exec("DELETE FROM connectors WHERE connector_name = 'VirusTotal'")
        .await;
    if let Some(url) = url {
        sqlx::query(
            "INSERT INTO connectors (connector_name, connector_type, connector_url, \
             connector_last_updated, connector_username, connector_password, connector_api_key, \
             connector_description, connector_supports, connector_configured, connector_verified, \
             connector_accepts_host_only, connector_accepts_api_key, \
             connector_accepts_username_password, connector_accepts_file, \
             connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
             ('VirusTotal', '3', ?, '2026-01-02 03:04:05', NULL, NULL, 'vt-e2e', 'desc', \
             'supports', 1, 1, 0, 1, 0, 0, 0, NULL, 1)",
        )
        .bind(url)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn threat_intel_routes_are_for_analysts() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let portal = h.token(&format!("portal{s}"), "customer_user");
    for route in [
        "/epss",
        "/socfortress",
        "/process_name",
        "/virustotal",
        "/ai/analyze-alert",
        "/ai/wazuh-exclusion-rule",
        "/ai/velociraptor-artifact-recommendation",
    ] {
        let (status, _) = h
            .call("POST", &format!("{TI}{route}"), None, Some(json!({})))
            .await;
        assert_eq!(status, 401, "{route}");
        let (status, _) = h
            .call(
                "POST",
                &format!("{TI}{route}"),
                Some(&portal),
                Some(json!({})),
            )
            .await;
        assert_eq!(status, 403, "{route}");
    }
    for uri in ["/virustotal/analysis/x", "/virustotal/file/x"] {
        let (status, _) = h
            .call("GET", &format!("{TI}{uri}"), Some(&portal), None)
            .await;
        assert_eq!(status, 403, "{uri}");
    }
}

#[tokio::test]
async fn epss_and_socfortress_intel_go_through_the_licence_cache() {
    let mut h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let upstream = MockServer::start().await;
    h.router = ti_router(&h, &upstream.uri());
    let key = format!("e2e-lic-{s}");
    let saved = own_licence(&h, &key).await;

    Mock::given(method("GET"))
        .and(path("/data/v1/epss"))
        .and(wiremock::matchers::query_param("cve", "CVE-2024-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status-code": 200,
            "data": [{"cve": "CVE-2024-1", "epss": "0.1", "percentile": "0.5", "date": "2026-10-16"}],
        })))
        .expect(1)
        .mount(&upstream)
        .await;
    let (status, body) = h
        .call(
            "POST",
            &format!("{TI}/epss"),
            Some(&analyst),
            Some(json!({"cve": "CVE-2024-1"})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"][0]["cve"], "CVE-2024-1");
    assert_eq!(body["message"], "EPSS score retrieved successfully");

    Mock::given(method("POST"))
        .and(path("/verify-license"))
        .and(wiremock::matchers::header("module-version", "1.0"))
        .and(wiremock::matchers::body_json(json!({"license_key": key})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"license": {"dataObjects": [
                {"name": "THREAT INTEL", "intValue": 1},
                {"name": "OTHER", "intValue": 0},
            ]}},
        })))
        .expect(1)
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"comment": "c", "score": "90", "type": "Domain-Name", "value": "example.com"},
            "success": true,
            "message": "found",
        })))
        .expect(2)
        .mount(&upstream)
        .await;
    for _ in 0..2 {
        let (status, body) = h
            .call(
                "POST",
                &format!("{TI}/socfortress"),
                Some(&analyst),
                Some(json!({"ioc_value": "example.com"})),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["data"]["score"], 90);
        assert_eq!(body["message"], "found");
    }
    // One licence check (the second call read the cache), its features cached.
    upstream.verify().await;
    let cached = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM license_cache WHERE license_key = '{key}'"
        ))
        .await;
    assert_eq!(cached, 2);
    let search = upstream
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.url.path() == "/search")
        .unwrap();
    assert_eq!(
        search.url.query(),
        Some("value=example.com%26customer_code%3Dsocfortress_copilot"),
        "Python's f-string puts the customer code inside the quoted value"
    );

    h.exec(&format!(
        "UPDATE license_cache SET is_enabled = 0 WHERE license_key = '{key}'"
    ))
    .await;
    let (status, body) = h
        .call(
            "POST",
            &format!("{TI}/socfortress"),
            Some(&analyst),
            Some(json!({"ioc_value": "x.com"})),
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (
            400,
            json!(
                "Feature is not enabled. You must purchase the THREAT INTEL license to use this feature."
            )
        )
    );
    h.exec(&format!("DELETE FROM license WHERE license_key = '{key}'"))
        .await;
    let (status, body) = h
        .call(
            "POST",
            &format!("{TI}/socfortress"),
            Some(&analyst),
            Some(json!({"ioc_value": "x.com"})),
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (
            404,
            json!("No license found. A license must be created first.")
        )
    );
    restore_licences(&h, &key, saved).await;
}

#[tokio::test]
async fn virustotal_lookups_and_file_submissions() {
    let mut h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let upstream = MockServer::start().await;
    h.router = ti_router(&h, &upstream.uri());

    virustotal_connector(&h, None).await;
    let (status, body) = h
        .call(
            "POST",
            &format!("{TI}/virustotal"),
            Some(&analyst),
            Some(json!({"ioc_value": "8.8.8.8"})),
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (500, json!("VirusTotal connector is not verified."))
    );

    virustotal_connector(&h, Some(&format!("{}/api/v3", upstream.uri()))).await;
    Mock::given(method("GET"))
        .and(path("/api/v3/ip_addresses/8.8.8.8"))
        .and(wiremock::matchers::header("x-apikey", "vt-e2e"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "id": "8.8.8.8",
                "type": "ip_address",
                "links": {"self": "https://vt/8.8.8.8"},
                "attributes": {"total_votes": {"harmless": 1, "malicious": 0}, "tags": []},
            },
        })))
        .expect(1)
        .mount(&upstream)
        .await;
    let (status, body) = h
        .call(
            "POST",
            &format!("{TI}/virustotal"),
            Some(&analyst),
            Some(json!({"ioc_value": "8.8.8.8"})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["data"]["id"], "8.8.8.8");
    assert_eq!(
        body["message"],
        "VirusTotal threat intelligence lookup was successful."
    );
    let (status, body) = h
        .call(
            "POST",
            &format!("{TI}/virustotal"),
            Some(&analyst),
            Some(json!({"ioc_value": "https://example.com/x"})),
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (400, json!("URL scanning is currently not supported."))
    );

    Mock::given(method("POST"))
        .and(path("/api/v3/files"))
        .and(wiremock::matchers::header("x-apikey", "vt-e2e"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"type": "analysis", "id": "an-1", "links": {"self": "s"}},
        })))
        .expect(1)
        .mount(&upstream)
        .await;
    let form = |name: &str, password: Option<&str>| {
        let mut body = format!(
            "--XB\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\
             Content-Type: application/octet-stream\r\n\r\nMZ e2e\r\n"
        );
        if let Some(p) = password {
            body.push_str(&format!(
                "--XB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{p}\r\n"
            ));
        }
        body.push_str("--XB--\r\n");
        body
    };
    let (status, body) = h
        .call_raw(
            "POST",
            &format!("{TI}/virustotal/file/submit"),
            Some(&analyst),
            Some("multipart/form-data; boundary=XB"),
            form("sample.exe", Some("pw")),
        )
        .await;
    assert_eq!(status, 400, "a password is for zip files only: {body}");
    assert_eq!(
        body["message"],
        "Password can only be provided for zip files. File 'sample.exe' has extension 'exe' and \
         MIME type 'application/octet-stream', which are not recognized as zip file formats."
    );
    let (status, body) = h
        .call_raw(
            "POST",
            &format!("{TI}/virustotal/file/submit"),
            Some(&analyst),
            Some("multipart/form-data; boundary=XB"),
            form("sample.exe", None),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["id"], "an-1");
    upstream.verify().await;
    let submitted = upstream
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.url.path() == "/api/v3/files")
        .unwrap();
    let text = String::from_utf8_lossy(&submitted.body).into_owned();
    assert!(
        text.contains("name=\"file\"; filename=\"sample.exe\"") && text.contains("MZ e2e"),
        "{text}"
    );
    virustotal_connector(&h, None).await;
}

#[tokio::test]
async fn ai_analysis_comments_only_on_the_callers_alerts() {
    let mut h = harness_or_skip!(None);
    let (acme_alert, beta_alert) = h.seed().await;
    let s = h.suffix.clone();
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let admin = h.token(&format!("admin{s}"), "admin");
    let upstream = MockServer::start().await;
    h.router = ti_router(&h, &upstream.uri());
    indexer(&h, &upstream.uri()).await;
    let key = format!("e2e-lic-{s}");
    let saved = own_licence(&h, &key).await;
    Mock::given(method("GET"))
        .and(path("/ai-alerts/_doc/d1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "_index": "ai-alerts", "_id": "d1", "_version": 1, "found": true,
            "_source": {"timestamp": "t", "syslog_type": "wazuh", "agent_name": "dc01", "message": "x"},
        })))
        .mount(&upstream)
        .await;
    Mock::given(method("POST"))
        .and(path("/analyze-alert"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": "ok", "success": true, "analysis": format!("looks bad {s}"),
            "confidence_score": 0.8, "threat_indicators": "ti", "risk_evaluation": "high",
        })))
        .mount(&upstream)
        .await;
    let body = |alert: i64| json!({"index_name": "ai-alerts", "index_id": "d1", "alert_id": alert});

    // §4: another tenant's alert is refused before anything is sent.
    let (status, resp) = h
        .call(
            "POST",
            &format!("{TI}/ai/analyze-alert"),
            Some(&analyst),
            Some(body(beta_alert)),
        )
        .await;
    assert_eq!(
        (status.as_u16(), resp["message"].clone()),
        (
            403,
            json!(format!(
                "Access denied to alert {beta_alert} - insufficient customer permissions"
            ))
        )
    );
    assert!(upstream.received_requests().await.unwrap().is_empty());

    let (status, resp) = h
        .call(
            "POST",
            &format!("{TI}/ai/analyze-alert"),
            Some(&analyst),
            Some(body(acme_alert)),
        )
        .await;
    assert_eq!(status, 200, "{resp}");
    assert_eq!(resp["analysis"], format!("looks bad {s}"));
    let sent = upstream
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.url.path() == "/analyze-alert")
        .unwrap();
    assert_eq!(
        sent.headers.get("x-api-key").unwrap().to_str().unwrap(),
        key,
        "the licence key is the API key"
    );
    let sent: Value = serde_json::from_slice(&sent.body).unwrap();
    assert_eq!(sent["integration"], "SOCFORTRESS AI");
    assert!(
        sent["alert_payload"].get("message").is_none(),
        "the payload's dropped keys: {sent}"
    );
    let (comment, user) = sqlx::query_as::<_, (String, String)>(
        "SELECT comment, user_name FROM incident_management_comment WHERE alert_id = ?",
    )
    .bind(acme_alert)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        (comment.as_str(), user.as_str()),
        (
            format!("SOCFortress AI Analysis: looks bad {s}").as_str(),
            "admin"
        )
    );

    // An admin's unknown alert: the analysis runs, then the comment fails
    // (Python's order).
    let before = upstream.received_requests().await.unwrap().len();
    let (status, resp) = h
        .call(
            "POST",
            &format!("{TI}/ai/analyze-alert"),
            Some(&admin),
            Some(body(i64::from(i32::MAX))),
        )
        .await;
    assert_eq!(
        (status.as_u16(), resp["message"].clone()),
        (404, json!("Alert not found"))
    );
    assert_eq!(
        upstream.received_requests().await.unwrap().len(),
        before + 2
    );

    h.exec(&format!(
        "DELETE FROM incident_management_comment WHERE alert_id IN ({acme_alert}, {beta_alert})"
    ))
    .await;
    restore_licences(&h, &key, saved).await;
    cleanup(&h).await;
}
