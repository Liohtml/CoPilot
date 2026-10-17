//! The Pydantic models of `schema/copilot_searches.py` the services validate
//! a rule's (or an upstream's) values against. The models the services only
//! fill with values of their own making are written out directly.

use copilot_yaml::Value;

use crate::pyd::{Default as D, Field, Loc, Model, Ty};

const STR_LIST: Ty = Ty::List(&Ty::Str);
const OPT_STR: Ty = Ty::Opt(&Ty::Str);
const OPT_INT: Ty = Ty::Opt(&Ty::Int);

/// `PlatformFilter`'s values.
pub const PLATFORMS: &[&str] = &[
    "all",
    "linux",
    "windows",
    "powershell",
    "cve",
    "cloud",
    "office365",
    "web",
];
/// `RuleStatus`'s values.
pub const STATUSES: &[&str] = &["production", "experimental", "deprecated"];
/// `RuleSeverity`'s values.
pub const SEVERITIES: &[&str] = &["low", "medium", "high", "critical"];
/// `AggregationFunction`'s values.
pub const AGG_FUNCTIONS: &[&str] = &["count", "distinct_count"];

/// `ParameterSchema`.
pub static PARAMETER_SCHEMA: Model = Model {
    title: "ParameterSchema",
    fields: &[
        Field::req("name", Ty::Str),
        Field::req("description", Ty::Str),
        Field::req("type", Ty::Str),
        Field::def("required", Ty::Bool, D::Bool(false)),
        Field::def("default", Ty::Opt(&Ty::Any), D::None),
        Field::def("example", Ty::Opt(&Ty::Any), D::None),
    ],
    after: None,
};

/// `GraylogQuery`.
pub static GRAYLOG_QUERY: Model = Model {
    title: "GraylogQuery",
    fields: &[Field::req("query", Ty::Str)],
    after: None,
};

fn field<'a>(items: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    items
        .iter()
        .find(|(k, _)| k.as_str() == Some(name))
        .map(|(_, v)| v)
}

/// `AggregationConfig` (the field validator on `condition` and the model
/// validator are applied by [`aggregation`]).
pub static AGGREGATION_CONFIG: Model = Model {
    title: "AggregationConfig",
    fields: &[
        Field::def("enabled", Ty::Bool, D::Bool(false)),
        Field::def("function", Ty::Enum(AGG_FUNCTIONS), D::Str("count")),
        Field::def("field", OPT_STR, D::None),
        Field::def("group_by", STR_LIST, D::EmptyList),
        Field::def("window", Ty::Str, D::Str("5m")),
        Field::def("execute_every", OPT_STR, D::None),
        Field::def("threshold", Ty::Int, D::Int(1)).range(Some(1), None),
        Field::def("condition", Ty::Str, D::Str(">")),
    ],
    after: None,
};

/// The conditions `AggregationConfig._validate_condition` allows, as
/// `sorted(allowed)` prints them.
pub const CONDITIONS_SORTED: &str = "['<', '<=', '==', '>', '>=']";

/// `AggregationConfig(**raw)`, its validators included: the dump or the
/// `ValidationError`.
pub fn aggregation(raw: &Value) -> Result<Value, crate::pyd::Invalid> {
    use crate::pyd::{Error, Invalid, validate};
    // The field validator on `condition` runs as part of field validation
    // (after the type check), so a bad condition is reported among the
    // field errors, in field order.
    let condition_error = |v: &Value| -> Option<Error> {
        let t = v.as_str()?;
        if [">", ">=", "<", "<=", "=="].contains(&t) {
            return None;
        }
        Some(Error {
            loc: vec![Loc::Key("condition".into())],
            kind: "value_error",
            msg: format!(
                "Value error, condition must be one of {CONDITIONS_SORTED}, got {}",
                copilot_yaml::str_repr(t)
            ),
            input: v.clone(),
        })
    };
    let given_condition = match raw {
        Value::Dict(items) => field(items, "condition").cloned(),
        _ => None,
    };
    match validate(&AGGREGATION_CONFIG, raw) {
        Ok(dump) => {
            if let Some(err) = given_condition.as_ref().and_then(condition_error) {
                return Err(Invalid {
                    title: "AggregationConfig".into(),
                    errors: vec![err],
                });
            }
            let items = dump.as_dict().unwrap_or_default();
            let function = field(items, "function").and_then(Value::as_str);
            let has_field = field(items, "field").is_some_and(Value::truthy);
            if function == Some("distinct_count") && !has_field {
                return Err(Invalid {
                    title: "AggregationConfig".into(),
                    errors: vec![Error {
                        loc: Vec::new(),
                        kind: "value_error",
                        msg: "Value error, aggregation.field is required when function is \
                              'distinct_count'"
                            .into(),
                        input: raw.clone(),
                    }],
                });
            }
            Ok(dump)
        }
        Err(mut invalid) => {
            // A condition that passed its type check but not the validator is
            // reported in its field's place.
            if let Some(err) = given_condition.as_ref().and_then(condition_error) {
                if !invalid
                    .errors
                    .iter()
                    .any(|e| e.loc.first() == Some(&Loc::Key("condition".into())))
                {
                    invalid.errors.push(err);
                }
            }
            Err(invalid)
        }
    }
}

/// `RuleSummary`.
pub static RULE_SUMMARY: Model = Model {
    title: "RuleSummary",
    fields: &[
        Field::req("id", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("version", Ty::Int),
        Field::req("status", Ty::Str),
        Field::req("type", Ty::Str),
        Field::req("description", Ty::Str),
        Field::req("author", Ty::Str),
        Field::req("date", Ty::Str),
        Field::req("severity", Ty::Str),
        Field::req("risk_score", Ty::Int),
        Field::req("platform", Ty::Str),
        Field::def("category", Ty::Str, D::Str("")),
        Field::def("category_label", Ty::Str, D::Str("")),
        Field::def("mitre_attack_id", STR_LIST, D::EmptyList),
        Field::def("analytic_story", STR_LIST, D::EmptyList),
        Field::def("cve", STR_LIST, D::EmptyList),
        Field::req("file_path", Ty::Str),
        Field::def("has_graylog_query", Ty::Bool, D::Bool(false)),
        Field::def("has_aggregation", Ty::Bool, D::Bool(false)),
        Field::def("provenance", Ty::Str, D::Str("catalog")),
        Field::def("owner_customer_code", OPT_STR, D::None),
    ],
    after: None,
};

/// `RuleDetail`.
pub static RULE_DETAIL: Model = Model {
    title: "RuleDetail",
    fields: &[
        Field::req("id", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("version", Ty::Int),
        Field::req("schema_version", Ty::Str),
        Field::req("status", Ty::Str),
        Field::req("type", Ty::Str),
        Field::req("description", Ty::Str),
        Field::req("author", Ty::Str),
        Field::req("date", Ty::Str),
        Field::req("data_source", STR_LIST),
        Field::req("search", Ty::Dict),
        Field::req("parameters", Ty::List(&Ty::Model(&PARAMETER_SCHEMA))),
        Field::req("how_to_implement", Ty::Str),
        Field::req("known_false_positives", Ty::Str),
        Field::req("references", STR_LIST),
        Field::req("response", Ty::Dict),
        Field::req("tags", Ty::Dict),
        Field::req("file_path", Ty::Str),
        Field::req("raw_yaml", Ty::Str),
        Field::def("graylog", Ty::Opt(&Ty::Model(&GRAYLOG_QUERY)), D::None),
        Field::def("aggregation", Ty::Opt(&Ty::Any), D::None),
        Field::def("provenance", Ty::Str, D::Str("catalog")),
        Field::def("owner_customer_code", OPT_STR, D::None),
    ],
    after: None,
};

/// `RuleStatsResponse` (the counters' keys come from the rules).
pub static RULE_STATS_RESPONSE: Model = Model {
    title: "RuleStatsResponse",
    fields: &[
        Field::req("total_rules", Ty::Int),
        Field::req("by_platform", Ty::DictOf(&Ty::Str, &Ty::Int)),
        Field::def("by_category", Ty::DictOf(&Ty::Str, &Ty::Int), D::EmptyDict),
        Field::req("by_status", Ty::DictOf(&Ty::Str, &Ty::Int)),
        Field::req("by_severity", Ty::DictOf(&Ty::Str, &Ty::Int)),
        Field::req("by_mitre_tactic", Ty::DictOf(&Ty::Str, &Ty::Int)),
        Field::req("rules_with_graylog", Ty::Int),
        Field::def("last_refreshed", Ty::Any, D::None),
        Field::req("cache_ttl_minutes", Ty::Int),
        Field::def("success", Ty::Bool, D::Bool(true)),
        Field::def(
            "message",
            Ty::Str,
            D::Str("Statistics fetched successfully"),
        ),
    ],
    after: None,
};

/// `MitreSubTechnique`.
pub static MITRE_SUB_TECHNIQUE: Model = Model {
    title: "MitreSubTechnique",
    fields: &[
        Field::req("id", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("url", Ty::Str),
        Field::req("rule_count", Ty::Int),
        Field::req("rule_ids", STR_LIST),
    ],
    after: None,
};

/// `MitreTechnique`.
pub static MITRE_TECHNIQUE: Model = Model {
    title: "MitreTechnique",
    fields: &[
        Field::req("id", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("url", Ty::Str),
        Field::req("rule_count", Ty::Int),
        Field::req("rule_ids", STR_LIST),
        Field::req("total_rule_count", Ty::Int),
        Field::req("subtechniques", Ty::List(&Ty::Model(&MITRE_SUB_TECHNIQUE))),
    ],
    after: None,
};

/// `MitreTactic`.
pub static MITRE_TACTIC: Model = Model {
    title: "MitreTactic",
    fields: &[
        Field::req("id", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("short_name", Ty::Str),
        Field::req("url", Ty::Str),
        Field::req("techniques", Ty::List(&Ty::Model(&MITRE_TECHNIQUE))),
    ],
    after: None,
};

/// `MitreCoverageStats`.
pub static MITRE_COVERAGE_STATS: Model = Model {
    title: "MitreCoverageStats",
    fields: &[
        Field::req("total_tactics", Ty::Int),
        Field::req("total_techniques", Ty::Int),
        Field::req("covered_techniques", Ty::Int),
        Field::req("total_rules", Ty::Int),
        Field::def("matrix_last_refreshed", Ty::Any, D::None),
        Field::def("rules_last_refreshed", Ty::Any, D::None),
    ],
    after: None,
};

/// `MitreRuleIndexEntry`.
pub static MITRE_RULE_INDEX_ENTRY: Model = Model {
    title: "MitreRuleIndexEntry",
    fields: &[
        Field::req("id", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("severity", Ty::Str),
        Field::req("platform", Ty::Str),
        Field::req("has_graylog", Ty::Bool),
        Field::def("data_sources", STR_LIST, D::EmptyList),
    ],
    after: None,
};

/// `MitreCoverageResponse`.
pub static MITRE_COVERAGE_RESPONSE: Model = Model {
    title: "MitreCoverageResponse",
    fields: &[
        Field::def("success", Ty::Bool, D::Bool(true)),
        Field::def(
            "message",
            Ty::Str,
            D::Str("MITRE coverage built successfully"),
        ),
        Field::req("tactics", Ty::List(&Ty::Model(&MITRE_TACTIC))),
        Field::def(
            "rules_index",
            Ty::DictOf(&Ty::Str, &Ty::Model(&MITRE_RULE_INDEX_ENTRY)),
            D::EmptyDict,
        ),
        Field::req("stats", Ty::Model(&MITRE_COVERAGE_STATS)),
    ],
    after: None,
};

/// `CatalogStoryDetection`.
pub static CATALOG_STORY_DETECTION: Model = Model {
    title: "CatalogStoryDetection",
    fields: &[
        Field::req("id", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("type", Ty::Str),
        Field::def("severity", OPT_STR, D::None),
        Field::def("mitre_attack_id", STR_LIST, D::EmptyList),
        Field::def("tactics", STR_LIST, D::EmptyList),
        Field::def("description", OPT_STR, D::None),
    ],
    after: None,
};

/// `CatalogStoryDetailResponse`.
pub static CATALOG_STORY_DETAIL_RESPONSE: Model = Model {
    title: "CatalogStoryDetailResponse",
    fields: &[
        Field::def("success", Ty::Bool, D::Bool(true)),
        Field::def(
            "message",
            Ty::Str,
            D::Str("Story detail retrieved successfully"),
        ),
        Field::req("name", Ty::Str),
        Field::req("id", Ty::Str),
        Field::req("description", Ty::Str),
        Field::req("why_it_matters", Ty::Str),
        Field::def(
            "detections",
            Ty::List(&Ty::Model(&CATALOG_STORY_DETECTION)),
            D::EmptyList,
        ),
        Field::def("data_sources", STR_LIST, D::EmptyList),
        Field::def("tactics", STR_LIST, D::EmptyList),
        Field::def("products", STR_LIST, D::EmptyList),
        Field::def("authors", STR_LIST, D::EmptyList),
        Field::def("references", STR_LIST, D::EmptyList),
        Field::def("date", OPT_STR, D::None),
        Field::def("version", OPT_INT, D::None),
        Field::def("detection_count", Ty::Int, D::Int(0)),
    ],
    after: None,
};

/// `CatalogWazuhRuleRow`.
pub static CATALOG_WAZUH_RULE_ROW: Model = Model {
    title: "CatalogWazuhRuleRow",
    fields: &[
        Field::def("id", OPT_INT, D::None),
        Field::def("level", OPT_INT, D::None),
        Field::def("status", OPT_STR, D::None),
        Field::def("description", Ty::Str, D::Str("")),
        Field::def("filename", Ty::Str, D::Str("")),
        Field::def("relative_dirname", Ty::Str, D::Str("")),
        Field::def("groups", STR_LIST, D::EmptyList),
        Field::def("mitre", STR_LIST, D::EmptyList),
        Field::def("hits_7d", Ty::Int, D::Int(0)),
        Field::def("hits_30d", Ty::Int, D::Int(0)),
        Field::def("last_seen", OPT_STR, D::None),
    ],
    after: None,
};

/// `CatalogWazuhRulesResponse`.
pub static CATALOG_WAZUH_RULES_RESPONSE: Model = Model {
    title: "CatalogWazuhRulesResponse",
    fields: &[
        Field::def("success", Ty::Bool, D::Bool(true)),
        Field::def(
            "message",
            Ty::Str,
            D::Str("Wazuh rules listed successfully"),
        ),
        Field::def(
            "rules",
            Ty::List(&Ty::Model(&CATALOG_WAZUH_RULE_ROW)),
            D::EmptyList,
        ),
        Field::def("total", Ty::Int, D::Int(0)),
        Field::def("available", Ty::Bool, D::Bool(true)),
        Field::def("unavailable_reason", OPT_STR, D::None),
        Field::def("last_refresh", Ty::Any, D::None),
        Field::def("firing_stats_available", Ty::Bool, D::Bool(true)),
        Field::def("firing_stats_unavailable_reason", OPT_STR, D::None),
        Field::def("firing_stats_last_refresh", Ty::Any, D::None),
        Field::def("customer_code", Ty::Str, D::Str("")),
    ],
    after: None,
};

/// `CatalogWazuhRuleCompliance`.
pub static CATALOG_WAZUH_RULE_COMPLIANCE: Model = Model {
    title: "CatalogWazuhRuleCompliance",
    fields: &[
        Field::def("pci_dss", STR_LIST, D::EmptyList),
        Field::def("gdpr", STR_LIST, D::EmptyList),
        Field::def("hipaa", STR_LIST, D::EmptyList),
        Field::def("nist_800_53", STR_LIST, D::EmptyList),
        Field::def("tsc", STR_LIST, D::EmptyList),
        Field::def("gpg13", STR_LIST, D::EmptyList),
    ],
    after: None,
};

/// `CatalogWazuhRuleDetailResponse`.
pub static CATALOG_WAZUH_RULE_DETAIL_RESPONSE: Model = Model {
    title: "CatalogWazuhRuleDetailResponse",
    fields: &[
        Field::def("success", Ty::Bool, D::Bool(true)),
        Field::def(
            "message",
            Ty::Str,
            D::Str("Wazuh rule detail retrieved successfully"),
        ),
        Field::def("id", OPT_INT, D::None),
        Field::def("level", OPT_INT, D::None),
        Field::def("status", OPT_STR, D::None),
        Field::def("description", Ty::Str, D::Str("")),
        Field::def("filename", Ty::Str, D::Str("")),
        Field::def("relative_dirname", Ty::Str, D::Str("")),
        Field::def("groups", STR_LIST, D::EmptyList),
        Field::def("mitre", STR_LIST, D::EmptyList),
        Field::def("tactics", STR_LIST, D::EmptyList),
        Field::def(
            "compliance",
            Ty::Model(&CATALOG_WAZUH_RULE_COMPLIANCE),
            D::EmptyDict,
        ),
        Field::def("details", Ty::Dict, D::EmptyDict),
        Field::def("source_xml", Ty::Str, D::Str("")),
        Field::def("hits_7d", Ty::Int, D::Int(0)),
        Field::def("hits_30d", Ty::Int, D::Int(0)),
        Field::def("last_seen", OPT_STR, D::None),
        Field::def("firing_stats_available", Ty::Bool, D::Bool(true)),
        Field::def("firing_stats_unavailable_reason", OPT_STR, D::None),
    ],
    after: None,
};

/// `CatalogCoverageGapRow`.
pub static CATALOG_COVERAGE_GAP_ROW: Model = Model {
    title: "CatalogCoverageGapRow",
    fields: &[
        Field::req("technique_id", Ty::Str),
        Field::req("technique_name", Ty::Str),
        Field::def("tactics", STR_LIST, D::EmptyList),
        Field::def("url", OPT_STR, D::None),
    ],
    after: None,
};

/// `CatalogCoverageGapsResponse`.
pub static CATALOG_COVERAGE_GAPS_RESPONSE: Model = Model {
    title: "CatalogCoverageGapsResponse",
    fields: &[
        Field::def("success", Ty::Bool, D::Bool(true)),
        Field::def(
            "message",
            Ty::Str,
            D::Str("Coverage gaps computed successfully"),
        ),
        Field::def(
            "gaps",
            Ty::List(&Ty::Model(&CATALOG_COVERAGE_GAP_ROW)),
            D::EmptyList,
        ),
        Field::def("gap_count", Ty::Int, D::Int(0)),
        Field::def("covered_count", Ty::Int, D::Int(0)),
        Field::def("total_techniques", Ty::Int, D::Int(0)),
        Field::def("coverage_pct", Ty::Float, D::Float(0.0)),
    ],
    after: None,
};

/// `CatalogCoverageGapDetailResponse`.
pub static CATALOG_COVERAGE_GAP_DETAIL_RESPONSE: Model = Model {
    title: "CatalogCoverageGapDetailResponse",
    fields: &[
        Field::def("success", Ty::Bool, D::Bool(true)),
        Field::def(
            "message",
            Ty::Str,
            D::Str("Coverage gap retrieved successfully"),
        ),
        Field::req("gap", Ty::Model(&CATALOG_COVERAGE_GAP_ROW)),
    ],
    after: None,
};

/// `CatalogLogTestRuleSummary`.
pub static CATALOG_LOG_TEST_RULE_SUMMARY: Model = Model {
    title: "CatalogLogTestRuleSummary",
    fields: &[
        Field::def("id", OPT_INT, D::None),
        Field::def("level", OPT_INT, D::None),
        Field::def("description", Ty::Str, D::Str("")),
        Field::def("groups", STR_LIST, D::EmptyList),
        Field::def("mitre", STR_LIST, D::EmptyList),
        Field::def("pci_dss", STR_LIST, D::EmptyList),
        Field::def("gdpr", STR_LIST, D::EmptyList),
        Field::def("hipaa", STR_LIST, D::EmptyList),
        Field::def("nist_800_53", STR_LIST, D::EmptyList),
        Field::def("firedtimes", OPT_INT, D::None),
    ],
    after: None,
};

/// `CatalogLogTestResponse`.
pub static CATALOG_LOG_TEST_RESPONSE: Model = Model {
    title: "CatalogLogTestResponse",
    fields: &[
        Field::def("success", Ty::Bool, D::Bool(true)),
        Field::def("message", Ty::Str, D::Str("Logtest executed")),
        Field::def("matched", Ty::Bool, D::Bool(false)),
        Field::def(
            "rule",
            Ty::Opt(&Ty::Model(&CATALOG_LOG_TEST_RULE_SUMMARY)),
            D::None,
        ),
        Field::def("tactics", STR_LIST, D::EmptyList),
        Field::def("alert", Ty::Opt(&Ty::Dict), D::None),
        Field::def("unavailable_reason", OPT_STR, D::None),
    ],
    after: None,
};

/// `SearchHit`.
pub static SEARCH_HIT: Model = Model {
    title: "SearchHit",
    fields: &[
        Field::req("index", Ty::Str),
        Field::req("id", Ty::Str),
        Field::def("score", Ty::Opt(&Ty::Float), D::None),
        Field::req("source", Ty::DictOf(&Ty::Str, &Ty::Any)),
    ],
    after: None,
};

/// `ExecuteSearchResponse`.
pub static EXECUTE_SEARCH_RESPONSE: Model = Model {
    title: "ExecuteSearchResponse",
    fields: &[
        Field::def("success", Ty::Bool, D::Bool(true)),
        Field::def("message", Ty::Str, D::Str("Search executed successfully")),
        Field::req("rule_id", Ty::Str),
        Field::req("rule_name", Ty::Str),
        Field::req("total_hits", Ty::Int),
        Field::req("returned_hits", Ty::Int),
        Field::req("took_ms", Ty::Int),
        Field::req("hits", Ty::List(&Ty::Model(&SEARCH_HIT))),
        Field::req("query_executed", Ty::Dict),
    ],
    after: None,
};

/// `GraylogQueryResponse`.
pub static GRAYLOG_QUERY_RESPONSE: Model = Model {
    title: "GraylogQueryResponse",
    fields: &[
        Field::def("success", Ty::Bool, D::Bool(true)),
        Field::def(
            "message",
            Ty::Str,
            D::Str("Graylog query generated successfully"),
        ),
        Field::req("rule_id", Ty::Str),
        Field::req("rule_name", Ty::Str),
        Field::req("graylog_query", Ty::Str),
        Field::req("original_query", Ty::Str),
    ],
    after: None,
};

/// `ProvisionGraylogAlertResponse`.
pub static PROVISION_GRAYLOG_ALERT_RESPONSE: Model = Model {
    title: "ProvisionGraylogAlertResponse",
    fields: &[
        Field::def("success", Ty::Bool, D::Bool(true)),
        Field::req("message", Ty::Str),
        Field::req("rule_id", Ty::Str),
        Field::req("rule_name", Ty::Str),
        Field::req("alert_title", Ty::Str),
        Field::req("graylog_query", Ty::Str),
    ],
    after: None,
};

/// `GraylogAlertProvisionModel` (`monitoring_alert/schema/provision.py`):
/// its `title` and `description`, the two values a rule fills.
pub static GRAYLOG_ALERT_PROVISION_MODEL: Model = Model {
    title: "GraylogAlertProvisionModel",
    fields: &[
        Field::req("title", Ty::Str),
        Field::req("description", Ty::Str),
        Field::req("priority", Ty::Int),
        Field::req("config", Ty::Any),
        Field::req("field_spec", Ty::Any),
        Field::req("key_spec", Ty::Any),
        Field::req("notification_settings", Ty::Any),
        Field::def("notifications", Ty::Any, D::EmptyList),
        Field::req("alert", Ty::Bool),
    ],
    after: None,
};

/// `GraylogAlertProvisionConfig` (`query` is the rule's).
pub static GRAYLOG_ALERT_PROVISION_CONFIG: Model = Model {
    title: "GraylogAlertProvisionConfig",
    fields: &[
        Field::req("query", Ty::Str),
        Field::req("query_parameters", Ty::List(&Ty::Any)),
        Field::req("streams", Ty::List(&Ty::Any)),
        Field::req("search_within_ms", Ty::Int),
        Field::req("execute_every_ms", Ty::Int),
        Field::req("group_by", Ty::List(&Ty::Any)),
        Field::req("series", Ty::List(&Ty::Any)),
        Field::req("conditions", Ty::Dict),
        Field::req("type", Ty::Str),
        Field::def("event_limit", Ty::Int, D::Int(1000)),
    ],
    after: None,
};

/// `GraylogAlertProvisionProvider` (`template` is the rule's alert source).
pub static GRAYLOG_ALERT_PROVISION_PROVIDER: Model = Model {
    title: "GraylogAlertProvisionProvider",
    fields: &[
        Field::req("template", Ty::Str),
        Field::req("type", Ty::Str),
        Field::req("require_values", Ty::Bool),
    ],
    after: None,
};

/// `BacktestTopValue`.
pub static BACKTEST_TOP_VALUE: Model = Model {
    title: "BacktestTopValue",
    fields: &[Field::req("value", Ty::Str), Field::req("count", Ty::Int)],
    after: None,
};

/// `BacktestBucket`.
pub static BACKTEST_BUCKET: Model = Model {
    title: "BacktestBucket",
    fields: &[Field::req("bucket", Ty::Str), Field::req("count", Ty::Int)],
    after: None,
};

/// `BacktestOffender`.
pub static BACKTEST_OFFENDER: Model = Model {
    title: "BacktestOffender",
    fields: &[
        Field::req("group", Ty::Str),
        Field::req("windows_alerting", Ty::Int),
        Field::req("peak", Ty::Int),
    ],
    after: None,
};

/// `BacktestSensitivity`.
pub static BACKTEST_SENSITIVITY: Model = Model {
    title: "BacktestSensitivity",
    fields: &[
        Field::req("threshold", Ty::Int),
        Field::req("alerts", Ty::Int),
    ],
    after: None,
};

/// `BacktestAggregation`.
pub static BACKTEST_AGGREGATION: Model = Model {
    title: "BacktestAggregation",
    fields: &[
        Field::req("window", Ty::Str),
        Field::req("window_seconds", Ty::Int),
        Field::req("function", Ty::Str),
        Field::def("field", OPT_STR, D::None),
        Field::def("group_by", STR_LIST, D::EmptyList),
        Field::req("threshold", Ty::Int),
        Field::req("condition", Ty::Str),
        Field::req("estimated_alerts", Ty::Int),
        Field::def("per_day_alerts", Ty::Float, D::Float(0.0)),
        Field::def(
            "top_offenders",
            Ty::List(&Ty::Model(&BACKTEST_OFFENDER)),
            D::EmptyList,
        ),
        Field::def(
            "sensitivity",
            Ty::List(&Ty::Model(&BACKTEST_SENSITIVITY)),
            D::EmptyList,
        ),
        Field::def("truncated", Ty::Bool, D::Bool(false)),
    ],
    after: None,
};

/// `BacktestResponse`.
pub static BACKTEST_RESPONSE: Model = Model {
    title: "BacktestResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::def("message", Ty::Str, D::Str("")),
        Field::def("error", OPT_STR, D::None),
        Field::def("mode", OPT_STR, D::None),
        Field::def("customer_code", OPT_STR, D::None),
        Field::def("stream_id", OPT_STR, D::None),
        Field::def("range_seconds", OPT_INT, D::None),
        Field::def("query", OPT_STR, D::None),
        Field::def("total_hits", Ty::Int, D::Int(0)),
        Field::def("per_day_avg", Ty::Float, D::Float(0.0)),
        Field::def("fetched", Ty::Int, D::Int(0)),
        Field::def("truncated", Ty::Bool, D::Bool(false)),
        Field::def(
            "per_bucket",
            Ty::List(&Ty::Model(&BACKTEST_BUCKET)),
            D::EmptyList,
        ),
        Field::def("bucket_unit", OPT_STR, D::None),
        Field::def("samples", Ty::List(&Ty::Dict), D::EmptyList),
        Field::def("sample_fields", STR_LIST, D::EmptyList),
        Field::def(
            "top_fields",
            Ty::DictOf(&Ty::Str, &Ty::List(&Ty::Model(&BACKTEST_TOP_VALUE))),
            D::EmptyDict,
        ),
        Field::def(
            "aggregation",
            Ty::Opt(&Ty::Model(&BACKTEST_AGGREGATION)),
            D::None,
        ),
        Field::def("missing_fields", STR_LIST, D::EmptyList),
        Field::def("note", OPT_STR, D::None),
    ],
    after: None,
};

/// `LintFinding` / `ValidateRuleResponse` and `PublishRuleResponse` carry
/// only the linter's own values; `PublishRuleResponse` also GitHub's URLs.
pub static LINT_FINDING: Model = Model {
    title: "LintFinding",
    fields: &[
        Field::req("level", Ty::Str),
        Field::req("code", Ty::Str),
        Field::req("message", Ty::Str),
        Field::def("path", Ty::Str, D::Str("")),
        Field::def("line", OPT_INT, D::None),
    ],
    after: None,
};

/// `PublishRuleResponse`.
pub static PUBLISH_RULE_RESPONSE: Model = Model {
    title: "PublishRuleResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::def("message", Ty::Str, D::Str("")),
        Field::def("error", OPT_STR, D::None),
        Field::def("action", OPT_STR, D::None),
        Field::def("repo", OPT_STR, D::None),
        Field::def("branch", OPT_STR, D::None),
        Field::def("path", OPT_STR, D::None),
        Field::def("commit_url", OPT_STR, D::None),
        Field::def("html_url", OPT_STR, D::None),
        Field::def(
            "findings",
            Ty::List(&Ty::Model(&LINT_FINDING)),
            D::EmptyList,
        ),
    ],
    after: None,
};

/// `TestCustomRepoResponse`.
pub static TEST_CUSTOM_REPO_RESPONSE: Model = Model {
    title: "TestCustomRepoResponse",
    fields: &[
        Field::def("success", Ty::Bool, D::Bool(true)),
        Field::def("message", Ty::Str, D::Str("")),
        Field::def("ok", Ty::Bool, D::Bool(false)),
        Field::def("rules_found", Ty::Int, D::Int(0)),
        Field::def("error", OPT_STR, D::None),
    ],
    after: None,
};
