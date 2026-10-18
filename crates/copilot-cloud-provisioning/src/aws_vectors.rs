//! `aws_vectors.json` (`scripts/gen-remaining-provisioning-vectors.py`)
//! against the AWS integration's Python: the aws-s3 wodle reconcile, the
//! auth keys, the services' helpers, the pipeline sources, the notice and
//! `_is_after`. The botocore calls and the validation are pinned in
//! `aws::boto` and `aws::validate`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use copilot_integrations::aws::config::{ConfigError, desired_buckets, reconcile_aws_buckets};
use copilot_integrations::aws::services::{
    decode_service_ids, encode_service_ids, parse_services, s3_log_prefix, wazuh_date,
};
use copilot_integrations::etree;
use copilot_upstream::model::field;
use serde_json::Value;

use crate::aws::boto::tests::doc;
use crate::aws::schema::{aws_config_notice, parse_auth_keys};

fn raw_keys(v: &Value) -> Vec<(String, Option<String>)> {
    v.as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().map(str::to_string)))
        .collect()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn the_wodle_reconcile_is_python_s() {
    let d = doc();
    for v in d["reconcile"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let keys = parse_auth_keys(&raw_keys(&v["keys"])).unwrap();
        let desired = if v["desired"].as_bool().unwrap() {
            desired_buckets(
                &keys.service_configs(),
                &keys.bucket_keys(),
                &keys.only_logs_after(),
            )
        } else {
            Vec::new()
        };
        let outcome = reconcile_aws_buckets(
            v["config"].as_str().unwrap(),
            &desired,
            &keys.bucket_name,
            &keys.account_id,
            v["adopt"].as_bool().unwrap(),
            v["keep"].as_bool().unwrap(),
        );
        let context = format!("{name} {}", v["keys"]);
        match (outcome, v.get("result")) {
            (Ok(r), Some(w)) => {
                assert_eq!(r.config, w["config"].as_str().unwrap(), "{context}");
                assert_eq!(Some(r.changed), w["changed"].as_bool(), "{context}");
                assert_eq!(r.added, strings(&w["added"]), "{context}");
                assert_eq!(r.updated, strings(&w["updated"]), "{context}");
                assert_eq!(r.removed, strings(&w["removed"]), "{context}");
                assert_eq!(
                    Some(r.wodle_created),
                    w["wodle_created"].as_bool(),
                    "{context}"
                );
                assert_eq!(
                    Some(r.wodle_removed),
                    w["wodle_removed"].as_bool(),
                    "{context}"
                );
                assert_eq!(
                    Some(r.wodle_disabled),
                    w["wodle_disabled"].as_bool(),
                    "{context}"
                );
                let previous: Vec<String> =
                    r.previous.iter().map(etree::tostring_unicode).collect();
                assert_eq!(previous, strings(&w["previous"]), "{context}");
            }
            (Err(e), None) => {
                let (class, text) = match e {
                    ConfigError::Refused(t) => ("AwsWazuhConfigError", t),
                    ConfigError::Parse(t) => ("ParseError", t),
                };
                assert_eq!(class, v["error"]["class"].as_str().unwrap(), "{context}");
                assert_eq!(text, v["error"]["text"].as_str().unwrap(), "{context}");
            }
            (got, _) => panic!("{context}: {got:?} where Python gives {v}"),
        }
    }
}

#[test]
fn the_auth_keys_are_validated_as_python_does() {
    let d = doc();
    for v in d["auth_keys"].as_array().unwrap() {
        let context = v["keys"].to_string();
        match (parse_auth_keys(&raw_keys(&v["keys"])), v.get("ok")) {
            (Ok(k), Some(ok)) => {
                assert_eq!(Some(k.access_key_id.as_str()), ok["ACCESS_KEY_ID"].as_str());
                assert_eq!(
                    Some(k.secret_access_key.as_str()),
                    ok["SECRET_ACCESS_KEY"].as_str()
                );
                assert_eq!(Some(k.account_id.as_str()), ok["AWS_ACCOUNT_ID"].as_str());
                assert_eq!(k.account_alias.as_deref(), ok["AWS_ACCOUNT_ALIAS"].as_str());
                assert_eq!(
                    k.organization_id.as_deref(),
                    ok["AWS_ORGANIZATION_ID"].as_str()
                );
                assert_eq!(Some(k.bucket_name.as_str()), ok["BUCKET_NAME"].as_str());
                assert_eq!(Some(k.services.as_str()), ok["SERVICES"].as_str());
                assert_eq!(
                    k.only_logs_after.as_deref(),
                    ok["ONLY_LOGS_AFTER"].as_str(),
                    "{context}"
                );
            }
            (Err(e), None) => assert_eq!(Some(e.as_str()), v["error"].as_str(), "{context}"),
            (got, _) => panic!("{context}: {got:?} where Python gives {v}"),
        }
    }
}

#[test]
fn the_rules_pipeline_and_notice_are_python_s() {
    let d = doc();
    let misc = &d["misc"];
    for (title, source) in crate::aws::aws_rule_sources() {
        assert_eq!(
            Some(source.as_str()),
            misc["rules"][title].as_str(),
            "{title}"
        );
    }
    assert_eq!(misc["rules"].as_object().unwrap().len(), 3);
    assert_eq!(
        crate::aws::aws_pipeline_source(),
        misc["pipeline"].as_str().unwrap()
    );
    for n in misc["notice"].as_array().unwrap() {
        let dump = aws_config_notice(n["detected"].as_bool().unwrap(), n["region"].as_str());
        let want = &n["dump"];
        assert_eq!(
            field(&dump, "detected").py_str(),
            if want["detected"].as_bool().unwrap() {
                "True"
            } else {
                "False"
            }
        );
        for key in ["file_path", "summary", "contents"] {
            assert_eq!(
                field(&dump, key).py_str(),
                want[key].as_str().unwrap(),
                "{key}"
            );
        }
        let steps: Vec<String> = match field(&dump, "steps") {
            copilot_auth::pyvalue::PyValue::List(items) => {
                items.iter().map(|s| s.py_str()).collect()
            }
            other => panic!("{other:?}"),
        };
        assert_eq!(steps, strings(&want["steps"]));
    }
}

#[test]
fn the_services_helpers_are_python_s() {
    let d = doc();
    let misc = &d["misc"];
    for p in misc["prefixes"].as_array().unwrap() {
        let configs = parse_services(p["services"].as_str().unwrap()).unwrap();
        let config = configs
            .iter()
            .find(|c| c.key() == p["key"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            s3_log_prefix(config, "123456789012", p["org"].as_str()),
            p["prefix"].as_str().unwrap(),
            "{p}"
        );
    }
    for pair in misc["decode"].as_array().unwrap() {
        let got = decode_service_ids(pair[0].as_str());
        let want: Vec<(String, String)> = pair[1]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect();
        let mut got_sorted = got.clone();
        got_sorted.sort();
        let mut want_sorted = want.clone();
        want_sorted.sort();
        assert_eq!(got_sorted, want_sorted, "{pair}");
    }
    for pair in misc["encode"].as_array().unwrap() {
        let ids: Vec<(String, String)> = pair[0]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect();
        assert_eq!(
            encode_service_ids(&ids),
            pair[1].as_str().unwrap(),
            "{pair}"
        );
    }
    for pair in misc["wazuh_date"].as_array().unwrap() {
        let parts: Vec<i64> = pair[0]
            .as_str()
            .unwrap()
            .split('-')
            .map(|p| p.parse().unwrap())
            .collect();
        let date = chrono::NaiveDate::from_ymd_opt(
            i32::try_from(parts[0]).unwrap(),
            u32::try_from(parts[1]).unwrap(),
            u32::try_from(parts[2]).unwrap(),
        )
        .unwrap();
        assert_eq!(wazuh_date(date), pair[1].as_str().unwrap());
    }
    for c in misc["same_source"].as_array().unwrap() {
        assert_eq!(
            crate::aws::same_source(c[0].as_str(), c[1].as_str().unwrap()),
            c[2].as_bool().unwrap(),
            "{c}"
        );
    }
    for c in misc["is_after"].as_array().unwrap() {
        let t = (!c["timestamp"].is_null()).then(|| c["timestamp"].clone());
        let m = (!c["marker"].is_null()).then(|| c["marker"].clone());
        let got = crate::aws::notice::is_after(t.as_ref(), m.as_ref());
        match (got, c["result"].get("ok")) {
            (Ok(b), Some(want)) => assert_eq!(Some(b), want.as_bool(), "{c}"),
            (Err(e), None) => {
                assert_eq!(
                    e.text(),
                    c["result"]["exception"][1].as_str().unwrap(),
                    "{c}"
                )
            }
            (got, _) => panic!("{c}: {got:?}"),
        }
    }
}
