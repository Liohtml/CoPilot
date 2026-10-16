//! `wazuh_manager/schema/{rules,groups,mitre}.py`: the response models the
//! services build from the manager's answers (their `ValidationError` texts
//! end up in the 500s, their field order and aliases in the 200s).

use crate::pymodel::{Default as D, Field, Model, Ty};

const STR_LIST: Ty = Ty::List(&Ty::Str);

static RULE: Model = Model {
    name: "WazuhRule",
    fields: &[
        Field::req("filename", Ty::Str),
        Field::req("relative_dirname", Ty::Str),
        Field::req("id", Ty::Int),
        Field::req("level", Ty::Int),
        Field::req("status", Ty::Str),
        Field::req("description", Ty::Str),
        Field::new("groups", STR_LIST, D::EmptyList),
        Field::new("pci_dss", STR_LIST, D::EmptyList),
        Field::new("gpg13", STR_LIST, D::EmptyList),
        Field::new("gdpr", STR_LIST, D::EmptyList),
        Field::new("hipaa", STR_LIST, D::EmptyList),
        Field::aliased("nist_800_53", "nist-800-53", STR_LIST, D::EmptyList).or_by_name(),
        Field::new("tsc", STR_LIST, D::EmptyList),
        Field::new("mitre", STR_LIST, D::EmptyList),
        Field::new("details", Ty::Opt(&Ty::Dict(&Ty::Any)), D::Null),
    ],
};

/// `WazuhRulesResponse`.
pub static RULES_RESPONSE: Model = Model {
    name: "WazuhRulesResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::new("results", Ty::List(&Ty::Model(&RULE)), D::EmptyList),
        Field::new("total_items", Ty::Opt(&Ty::Int), D::Null),
    ],
};

static RULE_FILE: Model = Model {
    name: "WazuhRuleFile",
    fields: &[
        Field::req("filename", Ty::Str),
        Field::req("relative_dirname", Ty::Str),
        Field::req("status", Ty::Str),
    ],
};

/// `WazuhRuleFilesResponse`.
pub static RULE_FILES_RESPONSE: Model = Model {
    name: "WazuhRuleFilesResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::new("results", Ty::List(&Ty::Model(&RULE_FILE)), D::EmptyList),
        Field::new("total_items", Ty::Opt(&Ty::Int), D::Null),
    ],
};

/// `WazuhRuleFileContentResponse`.
pub static RULE_FILE_CONTENT_RESPONSE: Model = Model {
    name: "WazuhRuleFileContentResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("filename", Ty::Str),
        Field::req("content", Ty::DictOrStr),
        Field::new("is_raw", Ty::Bool, D::Bool(false)),
        Field::new("total_items", Ty::Opt(&Ty::Int), D::Null),
    ],
};

/// `WazuhRuleFileUploadResponse`.
pub static RULE_FILE_UPLOAD_RESPONSE: Model = Model {
    name: "WazuhRuleFileUploadResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("filename", Ty::Str),
        Field::new("details", Ty::Opt(&Ty::Dict(&Ty::Any)), D::Null),
        Field::new("total_items", Ty::Opt(&Ty::Int), D::Null),
    ],
};

static GROUP: Model = Model {
    name: "WazuhGroup",
    fields: &[
        Field::req("name", Ty::Str),
        Field::req("count", Ty::Int),
        Field::new("mergedSum", Ty::Opt(&Ty::Str), D::Null),
        Field::new("configSum", Ty::Opt(&Ty::Str), D::Null),
    ],
};

/// `WazuhGroupsResponse`.
pub static GROUPS_RESPONSE: Model = Model {
    name: "WazuhGroupsResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::new("results", Ty::List(&Ty::Model(&GROUP)), D::EmptyList),
        Field::new("total_items", Ty::Opt(&Ty::Int), D::Null),
    ],
};

/// `WazuhGroupFileResponse`.
pub static GROUP_FILE_RESPONSE: Model = Model {
    name: "WazuhGroupFileResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("group_id", Ty::Str),
        Field::req("filename", Ty::Str),
        Field::req("content", Ty::DictOrStr),
        Field::new("is_raw", Ty::Bool, D::Bool(false)),
        Field::new("total_items", Ty::Opt(&Ty::Int), D::Null),
    ],
};

static GROUP_FILE: Model = Model {
    name: "WazuhGroupFile",
    fields: &[Field::req("filename", Ty::Str), Field::req("hash", Ty::Str)],
};

/// `WazuhGroupFilesResponse`.
pub static GROUP_FILES_RESPONSE: Model = Model {
    name: "WazuhGroupFilesResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("group_id", Ty::Str),
        Field::new("results", Ty::List(&Ty::Model(&GROUP_FILE)), D::EmptyList),
        Field::new("total_items", Ty::Opt(&Ty::Int), D::Null),
    ],
};

/// `WazuhGroupConfigurationUpdateResponse`.
pub static GROUP_CONFIGURATION_RESPONSE: Model = Model {
    name: "WazuhGroupConfigurationUpdateResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("group_id", Ty::Str),
        Field::new("total_items", Ty::Opt(&Ty::Int), D::Null),
    ],
};

static MITRE_REFERENCE: Model = Model {
    name: "MitreReference",
    fields: &[
        Field::req("url", Ty::Str),
        Field::new("description", Ty::Opt(&Ty::Str), D::Null),
        Field::req("source", Ty::Str),
    ],
};

const REFERENCES: Ty = Ty::List(&Ty::Model(&MITRE_REFERENCE));

static MITRE_TACTIC: Model = Model {
    name: "MitreTacticItem",
    fields: &[
        Field::req("description", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("id", Ty::Str),
        Field::req("modified_time", Ty::Str),
        Field::req("created_time", Ty::Str),
        Field::req("short_name", Ty::Str),
        Field::req("techniques", STR_LIST),
        Field::new("references", STR_LIST, D::EmptyList),
        Field::req("url", Ty::Str),
        Field::req("source", Ty::Str),
        Field::req("external_id", Ty::Str),
    ],
};

static MITRE_TECHNIQUE: Model = Model {
    name: "MitreTechniqueItem",
    fields: &[
        Field::req("description", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("id", Ty::Str),
        Field::req("modified_time", Ty::Str),
        Field::req("created_time", Ty::Str),
        Field::req("tactics", STR_LIST),
        Field::req("url", Ty::Str),
        Field::req("source", Ty::Str),
        Field::req("external_id", Ty::Str),
        Field::new("references", REFERENCES, D::EmptyList),
        Field::new("mitigations", Ty::Opt(&STR_LIST), D::Null),
        Field::new("subtechnique_of", Ty::Opt(&Ty::Str), D::Null),
        Field::new("techniques", Ty::Opt(&STR_LIST), D::Null),
        Field::new("groups", Ty::Opt(&STR_LIST), D::EmptyList),
        Field::new("software", Ty::Opt(&STR_LIST), D::EmptyList),
        Field::new("mitre_detection", Ty::Opt(&Ty::Str), D::Null),
        Field::new("mitre_version", Ty::Opt(&Ty::Str), D::Null),
        Field::new("deprecated", Ty::Opt(&Ty::Int), D::Int(0)),
        Field::new("remote_support", Ty::Opt(&Ty::Int), D::Int(0)),
        Field::new("network_requirements", Ty::Opt(&Ty::Int), D::Int(0)),
        Field::new("platforms", STR_LIST, D::EmptyList),
        Field::new("data_sources", STR_LIST, D::EmptyList),
        Field::new("is_subtechnique", Ty::Bool, D::Bool(false)),
    ],
};

static MITRE_SOFTWARE: Model = Model {
    name: "MitreSoftwareItem",
    fields: &[
        Field::new("mitre_version", Ty::Opt(&Ty::Str), D::Null),
        Field::new("deprecated", Ty::Int, D::Int(0)),
        Field::req("description", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("id", Ty::Str),
        Field::req("modified_time", Ty::Str),
        Field::req("created_time", Ty::Str),
        Field::new("groups", STR_LIST, D::EmptyList),
        Field::new("techniques", STR_LIST, D::EmptyList),
        Field::new("references", REFERENCES, D::EmptyList),
        Field::req("url", Ty::Str),
        Field::req("source", Ty::Str),
        Field::req("external_id", Ty::Str),
        Field::new("platforms", Ty::Opt(&STR_LIST), D::Null),
        Field::new("aliases", Ty::Opt(&STR_LIST), D::Null),
        Field::new("type", Ty::Opt(&Ty::Str), D::Null),
    ],
};

static MITRE_REFERENCE_ITEM: Model = Model {
    name: "MitreReferenceItem",
    fields: &[
        Field::req("url", Ty::Str),
        Field::new("description", Ty::Opt(&Ty::Str), D::Null),
        Field::req("source", Ty::Str),
        Field::new("id", Ty::Opt(&Ty::Str), D::Null),
        Field::new("type", Ty::Opt(&Ty::Str), D::Null),
    ],
};

static MITRE_MITIGATION: Model = Model {
    name: "MitreMitigationItem",
    fields: &[
        Field::new("mitre_version", Ty::Opt(&Ty::Str), D::Null),
        Field::new("deprecated", Ty::Int, D::Int(0)),
        Field::req("description", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("id", Ty::Str),
        Field::req("modified_time", Ty::Str),
        Field::req("created_time", Ty::Str),
        Field::new("techniques", STR_LIST, D::EmptyList),
        Field::new("references", REFERENCES, D::EmptyList),
        Field::req("url", Ty::Str),
        Field::req("source", Ty::Str),
        Field::req("external_id", Ty::Str),
    ],
};

static MITRE_GROUP: Model = Model {
    name: "MitreGroupItem",
    fields: &[
        Field::new("mitre_version", Ty::Opt(&Ty::Str), D::Null),
        Field::new("deprecated", Ty::Int, D::Int(0)),
        Field::new("description", Ty::Opt(&Ty::Str), D::Null),
        Field::req("name", Ty::Str),
        Field::req("id", Ty::Str),
        Field::req("modified_time", Ty::Str),
        Field::req("created_time", Ty::Str),
        Field::new("software", STR_LIST, D::EmptyList),
        Field::new("techniques", STR_LIST, D::EmptyList),
        Field::new("references", REFERENCES, D::EmptyList),
        Field::req("url", Ty::Str),
        Field::req("external_id", Ty::Str),
        Field::req("source", Ty::Str),
        Field::new("aliases", Ty::Opt(&STR_LIST), D::Null),
        Field::new("country", Ty::Opt(&Ty::Str), D::Null),
    ],
};

/// `WazuhMitreTacticsResponse`.
pub static MITRE_TACTICS_RESPONSE: Model = Model {
    name: "WazuhMitreTacticsResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::new("results", Ty::List(&Ty::Model(&MITRE_TACTIC)), D::EmptyList),
    ],
};

/// `WazuhMitreTechniquesResponse`.
pub static MITRE_TECHNIQUES_RESPONSE: Model = Model {
    name: "WazuhMitreTechniquesResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::new(
            "results",
            Ty::List(&Ty::Model(&MITRE_TECHNIQUE)),
            D::EmptyList,
        ),
    ],
};

/// `WazuhMitreSoftwareResponse`.
pub static MITRE_SOFTWARE_RESPONSE: Model = Model {
    name: "WazuhMitreSoftwareResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::new(
            "results",
            Ty::List(&Ty::Model(&MITRE_SOFTWARE)),
            D::EmptyList,
        ),
    ],
};

/// `WazuhMitreReferencesResponse`.
pub static MITRE_REFERENCES_RESPONSE: Model = Model {
    name: "WazuhMitreReferencesResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::new(
            "results",
            Ty::List(&Ty::Model(&MITRE_REFERENCE_ITEM)),
            D::EmptyList,
        ),
        Field::new("total", Ty::Int, D::Int(0)),
    ],
};

/// `WazuhMitreMitigationsResponse`.
pub static MITRE_MITIGATIONS_RESPONSE: Model = Model {
    name: "WazuhMitreMitigationsResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::new(
            "results",
            Ty::List(&Ty::Model(&MITRE_MITIGATION)),
            D::EmptyList,
        ),
        Field::new("total", Ty::Int, D::Int(0)),
    ],
};

/// `WazuhMitreGroupsResponse`.
pub static MITRE_GROUPS_RESPONSE: Model = Model {
    name: "WazuhMitreGroupsResponse",
    fields: &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::new("results", Ty::List(&Ty::Model(&MITRE_GROUP)), D::EmptyList),
        Field::new("total", Ty::Int, D::Int(0)),
    ],
};
