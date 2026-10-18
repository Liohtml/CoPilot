//! `app/integrations/copilot_action/schema/copilot_action.py` and the
//! models of `app/connectors/velociraptor/schema/artifacts.py` the invoke
//! uses, as [`copilot_upstream::model`] statics.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Check, EnumTy, Field, Model, Ty};

/// `Technology`'s values.
pub const TECHNOLOGIES: &[&str] = &[
    "Wazuh",
    "Linux",
    "Windows",
    "macOS",
    "Network",
    "Cloud",
    "Velociraptor",
];

/// `Technology`.
pub static TECHNOLOGY: EnumTy = EnumTy {
    name: "Technology",
    values: TECHNOLOGIES,
};

/// `ScriptParameter.validate_type`'s set, sorted as `sorted(allowed)`.
const PARAMETER_TYPES: &[&str] = &[
    "bool", "boolean", "enum", "float", "int", "integer", "json", "list", "path", "string",
];

fn check_type(v: &PyValue) -> Result<PyValue, Check> {
    match v {
        PyValue::Str(s) if PARAMETER_TYPES.contains(&s.as_str()) => Ok(v.clone()),
        _ => Err(Check::ValueError(format!(
            "type must be one of [{}]",
            PARAMETER_TYPES
                .iter()
                .map(|t| format!("'{t}'"))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

fn empty_list() -> PyValue {
    PyValue::List(Vec::new())
}

fn yes() -> PyValue {
    PyValue::Bool(true)
}

fn metrics_message() -> PyValue {
    PyValue::Str("Successfully retrieved inventory metrics".into())
}

/// `ScriptParameter`.
pub static SCRIPT_PARAMETER: Model = Model::new(
    "ScriptParameter",
    &[
        Field::req("name", Ty::Str),
        Field::req("type", Ty::Str).after(check_type),
        Field::req("required", Ty::Bool),
        Field::opt("description", Ty::Nullable(&Ty::Str)),
        Field::opt(
            "default",
            Ty::Nullable(&Ty::Union(&[
                Ty::Str,
                Ty::Int,
                Ty::Float,
                Ty::Bool,
                Ty::List(&Ty::Any),
                Ty::Dict(&Ty::Any),
            ])),
        ),
        Field::opt("enum", Ty::Nullable(&Ty::List(&Ty::Str))),
        Field::opt("arg_position", Ty::Nullable(&Ty::Str)),
    ],
);

/// `ActiveResponseItem` (its `set_icon_default` model validator is applied
/// to the dump by [`set_icon_defaults`]).
pub static ACTIVE_RESPONSE_ITEM: Model = Model::new(
    "ActiveResponseItem",
    &[
        Field::req("copilot_action_name", Ty::Str),
        Field::req("description", Ty::Str),
        Field::req("technology", Ty::Enum(&TECHNOLOGY)),
        Field::opt("icon", Ty::Nullable(&Ty::Str)),
        Field::def(
            "script_parameters",
            Ty::List(&Ty::Model(&SCRIPT_PARAMETER)),
            empty_list,
        ),
        Field::req("repo_url", Ty::Str),
        Field::opt("script_name", Ty::Nullable(&Ty::Str)),
        Field::opt("version", Ty::Nullable(&Ty::Str)),
        Field::opt("last_updated", Ty::Nullable(&Ty::DateTime)),
        Field::opt("category", Ty::Nullable(&Ty::Str)),
        Field::opt("tags", Ty::Nullable(&Ty::List(&Ty::Str))),
    ],
);

/// `InventoryResponse`.
pub static INVENTORY_RESPONSE: Model = Model::new(
    "InventoryResponse",
    &[
        Field::req(
            "copilot_actions",
            Ty::List(&Ty::Model(&ACTIVE_RESPONSE_ITEM)),
        ),
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
        Field::opt("total", Ty::Nullable(&Ty::Int)),
        Field::opt("count", Ty::Nullable(&Ty::Int)),
        Field::opt("limit", Ty::Nullable(&Ty::Int)),
        Field::opt("offset", Ty::Nullable(&Ty::Int)),
        Field::opt("has_more", Ty::Nullable(&Ty::Bool)),
        Field::opt("next_offset", Ty::Nullable(&Ty::Int)),
        Field::opt("prev_offset", Ty::Nullable(&Ty::Int)),
    ],
);

/// `ActionDetailResponse`.
pub static ACTION_DETAIL_RESPONSE: Model = Model::new(
    "ActionDetailResponse",
    &[
        Field::req("copilot_action", Ty::Model(&ACTIVE_RESPONSE_ITEM)),
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
    ],
);

/// `InventoryMetricsResponse`.
pub static INVENTORY_METRICS_RESPONSE: Model = Model::new(
    "InventoryMetricsResponse",
    &[
        Field::req("status", Ty::Str),
        Field::req("metrics", Ty::Dict(&Ty::Any)),
        Field::def("message", Ty::Str, metrics_message),
        Field::def("success", Ty::Bool, yes),
    ],
);

/// `CollectArtifactResponse` (`message`, `success`, `results` from
/// `BaseResponse`, then `file_info`).
pub static COLLECT_ARTIFACT_RESPONSE: Model = Model::new(
    "CollectArtifactResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
        Field::opt("results", Ty::Nullable(&Ty::List(&Ty::Dict(&Ty::Any)))),
        Field::opt("file_info", Ty::Nullable(&Ty::Dict(&Ty::Any))),
    ],
);

/// `ActiveResponseItem.set_icon_default` on every item of a dump: an absent
/// icon is the technology's value, lower-cased.
pub fn set_icon_defaults(items: &mut PyValue) {
    let PyValue::List(items) = items else {
        return;
    };
    for item in items {
        let PyValue::Dict(fields) = item else {
            continue;
        };
        let technology = fields
            .iter()
            .find(|(k, _)| k == "technology")
            .and_then(|(_, v)| v.as_str())
            .map(str::to_lowercase);
        if let (Some(technology), Some((_, icon))) =
            (technology, fields.iter_mut().find(|(k, _)| k == "icon"))
        {
            if matches!(icon, PyValue::None) {
                *icon = PyValue::Str(technology);
            }
        }
    }
}

/// `ParameterKeyValue`.
pub static PARAMETER_KEY_VALUE: Model = Model::new(
    "ParameterKeyValue",
    &[Field::req("key", Ty::Str), Field::req("value", Ty::Str)],
);

/// `InvokeCopilotActionBody`.
pub static INVOKE_BODY: Model = Model::new(
    "InvokeCopilotActionBody",
    &[
        Field::req("copilot_action_name", Ty::Str),
        Field::req("agent_names", Ty::List(&Ty::Str)),
        Field::opt("artifact_name", Ty::Nullable(&Ty::Str)),
        Field::opt(
            "parameters",
            Ty::Nullable(&Ty::Dict(&Ty::Union(&[
                Ty::Str,
                Ty::List(&Ty::Model(&PARAMETER_KEY_VALUE)),
            ]))),
        ),
    ],
);

/// `InvokeCopilotActionResponse`.
pub static INVOKE_RESPONSE: Model = Model::new(
    "InvokeCopilotActionResponse",
    &[
        Field::req("responses", Ty::List(&Ty::Dict(&Ty::Any))),
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
    ],
);
