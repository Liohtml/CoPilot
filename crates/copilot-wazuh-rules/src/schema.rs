//! The request and response models (`app/connectors/wazuh_manager/schema/
//! {rules,mitre}.py`).

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Check, Field, Model, Ty};

/// `RuleDisable`.
pub static RULE_DISABLE: Model = Model::new(
    "RuleDisable",
    &[
        Field::req("rule_id", Ty::Str),
        Field::req("reason_for_disabling", Ty::Str),
        Field::req("length_of_time", Ty::Str),
    ],
);

/// `RuleEnable`.
pub static RULE_ENABLE: Model = Model::new(
    "RuleEnable",
    &[
        Field::req("rule_id", Ty::Str),
        Field::req("reason_for_enabling", Ty::Str),
    ],
);

/// `"x" in v` for a dict.
fn has(items: &[(String, PyValue)], key: &str) -> bool {
    items.iter().any(|(k, _)| k == key)
}

/// `v[key] != "windows"` (the key is there).
fn not_windows(items: &[(String, PyValue)], key: &str) -> bool {
    items
        .iter()
        .rev()
        .find(|(k, _)| k == key)
        .is_none_or(|(_, v)| *v != PyValue::Str("windows".into()))
}

/// `check_integration`.
fn check_integration(v: &PyValue) -> Result<PyValue, Check> {
    if *v != PyValue::Str("wazuh-rule-exclusion".into()) {
        return Err(Check::Abort(
            400,
            "Invalid integration. Only 'wazuh-rule-exclusion' is supported.".into(),
        ));
    }
    Ok(v.clone())
}

/// `check_rule_group`.
fn check_rule_group(v: &PyValue) -> Result<PyValue, Check> {
    let PyValue::Dict(items) = v else {
        return Ok(v.clone());
    };
    if has(items, "rule_group3") {
        if has(items, "rule_group1")
            && not_windows(items, "rule_group1")
            && not_windows(items, "rule_group3")
        {
            return Err(Check::Abort(
                400,
                "Invalid 'rule_group1' or 'rule_group3'. At least one must be 'windows'.".into(),
            ));
        }
    } else {
        if !has(items, "rule_group1") {
            return Err(Check::Abort(400, "Missing 'rule_group1' in prompt.".into()));
        }
        if not_windows(items, "rule_group1") {
            return Err(Check::Abort(
                400,
                "Invalid 'rule_group1'. Only 'windows' is supported.".into(),
            ));
        }
    }
    Ok(v.clone())
}

/// `RuleExcludeRequest`.
pub static RULE_EXCLUDE_REQUEST: Model = Model::new(
    "RuleExcludeRequest",
    &[
        Field::req("integration", Ty::Str).after(check_integration),
        Field::req("prompt", Ty::Dict(&Ty::Any)).after(check_rule_group),
    ],
);

/// `RuleExcludeResponse`.
pub static RULE_EXCLUDE_RESPONSE: Model = Model::new(
    "RuleExcludeResponse",
    &[
        Field::req("wazuh_rule", Ty::Str),
        Field::req("explanation", Ty::Str),
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
    ],
);

/// `RuleExcludeResponse`'s qualified name (the `**` `TypeError`).
pub const RULE_EXCLUDE_RESPONSE_QUALNAME: &str =
    "app.connectors.wazuh_manager.schema.rules.RuleExcludeResponse";

/// `RuleDisableResponse` / `RuleEnableResponse` as the routes dump them:
/// `{previous_level|new_level, message, success}`.
pub fn level_response(key: &str, level: Option<String>, message: String) -> PyValue {
    PyValue::Dict(vec![
        (key.into(), level.map_or(PyValue::None, PyValue::Str)),
        ("message".into(), PyValue::Str(message)),
        ("success".into(), PyValue::Bool(true)),
    ])
}

/// `AllDisabledRuleResponse` from the rows (each an `AllDisabledRule`).
pub fn all_disabled(rows: &[crate::services::DisabledRule]) -> PyValue {
    let s = |v: &str| PyValue::Str(v.to_string());
    PyValue::Dict(vec![
        (
            "disabled_rules".into(),
            PyValue::List(
                rows.iter()
                    .map(|r| {
                        PyValue::Dict(vec![
                            ("rule_id".into(), s(&r.rule_id)),
                            ("previous_level".into(), s(&r.previous_level)),
                            ("new_level".into(), s(&r.new_level)),
                            ("reason_for_disabling".into(), s(&r.reason_for_disabling)),
                            ("length_of_time".into(), s(&r.length_of_time)),
                            ("disabled_by".into(), s(&r.disabled_by)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("success".into(), PyValue::Bool(true)),
        (
            "message".into(),
            s("Successfully fetched all disabled rules"),
        ),
    ])
}

/// The Atomic Red Team models, over rule-side values (a technique's YAML
/// may hold anything).
pub mod atomic {
    use copilot_searches::pyd::{Default, Field, Model, Ty};

    /// `AtomicTestSummary`.
    pub static ATOMIC_TEST_SUMMARY: Model = Model {
        title: "AtomicTestSummary",
        fields: &[
            Field::req("technique_id", Ty::Str),
            Field::req("technique_name", Ty::Str),
            Field::req("test_count", Ty::Int),
            Field::def("categories", Ty::List(&Ty::Str), Default::EmptyList),
            Field::def("has_prerequisites", Ty::Bool, Default::Bool(false)),
        ],
        after: None,
    };

    /// `AtomicTestsListResponse`.
    pub static ATOMIC_TESTS_LIST_RESPONSE: Model = Model {
        title: "AtomicTestsListResponse",
        fields: &[
            Field::def("success", Ty::Bool, Default::Bool(true)),
            Field::req("message", Ty::Str),
            Field::req("total_techniques", Ty::Int),
            Field::def("total_tests", Ty::Opt(&Ty::Int), Default::None),
            Field::req("tests", Ty::List(&Ty::Model(&ATOMIC_TEST_SUMMARY))),
            Field::req("last_updated", Ty::Str),
            Field::def("page", Ty::Int, Default::Int(1)),
            Field::req("page_size", Ty::Int),
            Field::req("total_pages", Ty::Int),
        ],
        after: None,
    };
}

/// The MITRE alert searches' response models (`schema/mitre.py`).
pub mod mitre_alerts {
    use copilot_searches::pyd::{Default, Field, Model, Ty};

    /// `MitreTechniqueInAlert`.
    pub static MITRE_TECHNIQUE_IN_ALERT: Model = Model {
        title: "MitreTechniqueInAlert",
        fields: &[
            Field::req("technique_id", Ty::Str),
            Field::req("technique_name", Ty::Str),
            Field::req("count", Ty::Int),
            Field::def("last_seen", Ty::Opt(&Ty::Str), Default::None),
            Field::def(
                "tactics",
                Ty::List(&Ty::DictOf(&Ty::Str, &Ty::Str)),
                Default::EmptyList,
            ),
        ],
        after: None,
    };

    /// `MitreTechniquesInAlertsResponse`.
    pub static MITRE_TECHNIQUES_IN_ALERTS_RESPONSE: Model = Model {
        title: "MitreTechniquesInAlertsResponse",
        fields: &[
            Field::def("success", Ty::Bool, Default::Bool(true)),
            Field::req("message", Ty::Str),
            Field::req("total_alerts", Ty::Int),
            Field::req("techniques_count", Ty::Int),
            Field::req(
                "techniques",
                Ty::List(&Ty::Model(&MITRE_TECHNIQUE_IN_ALERT)),
            ),
            Field::req("time_range", Ty::Str),
            Field::req("field_used", Ty::Opt(&Ty::Str)),
            Field::def("page", Ty::Int, Default::Int(1)),
            Field::req("page_size", Ty::Int),
            Field::req("total_pages", Ty::Int),
        ],
        after: None,
    };

    /// `MitreTechniqueAlertsResponse`.
    pub static MITRE_TECHNIQUE_ALERTS_RESPONSE: Model = Model {
        title: "MitreTechniqueAlertsResponse",
        fields: &[
            Field::def("success", Ty::Bool, Default::Bool(true)),
            Field::req("message", Ty::Str),
            Field::req("technique_id", Ty::Str),
            Field::req("technique_name", Ty::Str),
            Field::req("total_alerts", Ty::Int),
            Field::req("alerts", Ty::List(&Ty::Dict)),
            Field::req("field_used", Ty::Opt(&Ty::Str)),
            Field::req("time_range", Ty::Str),
            Field::def("page", Ty::Int, Default::Int(1)),
            Field::req("page_size", Ty::Int),
            Field::req("total_pages", Ty::Int),
        ],
        after: None,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_upstream::model::{Invalid, Loc, validate};
    use copilot_upstream::respond::from_json;
    use serde_json::json;

    #[derive(serde::Deserialize)]
    struct Vectors {
        exclude: Vec<serde_json::Value>,
    }

    /// `RuleExcludeRequest(**body)` against pydantic
    /// (`scripts/gen-wazuh-rules-vectors.py`).
    #[test]
    fn the_exclusion_request_validates_as_pydantic() {
        let v: Vectors =
            serde_json::from_str(include_str!("wazuh_rules_vectors.json")).expect("vectors");
        for probe in v.exclude {
            let body = from_json(&probe["body"]);
            match validate(&RULE_EXCLUDE_REQUEST, &body) {
                Ok(dump) => assert_eq!(dump, from_json(&probe["dump"]), "{}", probe["body"]),
                Err(Invalid::Abort(status, detail)) => {
                    assert_eq!(json!([status, detail]), probe["http"], "{}", probe["body"]);
                }
                Err(Invalid::Errors(errors)) => {
                    let got: Vec<serde_json::Value> = errors
                        .iter()
                        .map(|e| {
                            let loc: Vec<serde_json::Value> = e
                                .loc
                                .iter()
                                .map(|l| match l {
                                    Loc::Key(k) => json!(k),
                                    Loc::Index(i) => json!(i),
                                })
                                .collect();
                            json!({"type": e.kind, "loc": loc, "msg": e.msg})
                        })
                        .collect();
                    assert_eq!(json!(got), probe["errors"], "{}", probe["body"]);
                }
            }
        }
    }
}
