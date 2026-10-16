//! `app/connectors/velociraptor/schema/{artifacts,flows}.py`: the Pydantic
//! models VQL rows are validated with, and the request bodies of the ported
//! routes.
//!
//! The flow models are deliberately tolerant, as in Python (every field
//! optional with a default, extra keys ignored): a `flows()` row is whatever
//! the server version emits.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{self, Field, Model, Ty};

/// `ArtifactParameter`.
pub static ARTIFACT_PARAMETER: Model = Model::new(
    "ArtifactParameter",
    &[
        Field::req("name", Ty::Str),
        Field::opt("description", Ty::Nullable(&Ty::Str)),
        Field::opt("type", Ty::Nullable(&Ty::Str)),
        Field::opt("default", Ty::Nullable(&Ty::Union(&[Ty::Str, Ty::Bool]))),
    ],
);

/// `Artifacts`.
pub static ARTIFACTS: Model = Model::new(
    "Artifacts",
    &[
        Field::req("description", Ty::Str),
        Field::req("name", Ty::Str),
        Field::opt("author", Ty::Nullable(&Ty::Str)),
        Field::opt("precondition", Ty::Nullable(&Ty::Str)),
        Field::opt(
            "parameters",
            Ty::Nullable(&Ty::List(&Ty::Model(&ARTIFACT_PARAMETER))),
        ),
    ],
);

/// `Artifacts`' class path, which `Artifacts(**row)`'s `TypeError` names.
pub const ARTIFACTS_QUALNAME: &str = "app.connectors.velociraptor.schema.artifacts.Artifacts";

/// `results: Optional[List[Dict[str, Any]]]` of `BaseResponse`.
const RESULTS: Ty = Ty::Nullable(&Ty::List(&Ty::Dict(&Ty::Any)));

/// `RunCommandResponse` (`BaseResponse`).
pub static RUN_COMMAND_RESPONSE: Model = Model::new(
    "RunCommandResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
        Field::opt("results", RESULTS),
    ],
);

/// `QuarantineResponse` (`BaseResponse`).
pub static QUARANTINE_RESPONSE: Model = Model::new(
    "QuarantineResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
        Field::opt("results", RESULTS),
    ],
);

/// `CollectArtifactResponse`.
pub static COLLECT_ARTIFACT_RESPONSE: Model = Model::new(
    "CollectArtifactResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
        Field::opt("results", RESULTS),
        Field::opt("file_info", Ty::Nullable(&Ty::Dict(&Ty::Any))),
    ],
);

fn empty_str() -> PyValue {
    PyValue::Str(String::new())
}
fn zero() -> PyValue {
    PyValue::Int("0".into())
}
fn no() -> PyValue {
    PyValue::Bool(false)
}
fn empty_list() -> PyValue {
    PyValue::List(Vec::new())
}

/// `FlowSpecParameter`.
pub static FLOW_SPEC_PARAMETER: Model = Model::new(
    "FlowSpecParameter",
    &[
        Field::def("key", Ty::Str, empty_str),
        Field::def("value", Ty::Str, empty_str),
        Field::opt("comment", Ty::Nullable(&Ty::Str)),
    ],
);

/// `FlowSpec`.
pub static FLOW_SPEC: Model = Model::new(
    "FlowSpec",
    &[
        Field::def("artifact", Ty::Str, empty_str),
        Field::opt(
            "parameters",
            Ty::Nullable(&Ty::List(&Ty::Model(&FLOW_SPEC_PARAMETER))),
        ),
    ],
);

/// `FlowRequest`'s `validate_specs` (`mode="before"`): every spec that is
/// a valid `FlowSpec` kept, the others dropped (Python logs them). A
/// `specs` value that cannot be iterated at all raises `TypeError` there;
/// [`flow_session_fails`] catches that case before validation.
fn request_before(value: &PyValue) -> PyValue {
    let PyValue::Dict(items) = value else {
        return value.clone();
    };
    let Some(specs) = items.iter().find(|(k, _)| k == "specs").map(|(_, v)| v) else {
        return value.clone();
    };
    if matches!(specs, PyValue::None) {
        return value.clone();
    }
    let kept: Vec<PyValue> = copilot_upstream::py::iterate(specs)
        .unwrap_or_default()
        .iter()
        .filter_map(|spec| {
            match model::construct_star(
                &FLOW_SPEC,
                "app.connectors.velociraptor.schema.flows.FlowSpec",
                spec,
            ) {
                Ok(dump) => Some(dump),
                Err(e) => {
                    tracing::error!("Failed to validate spec: {}", e.text());
                    None
                }
            }
        })
        .collect();
    PyValue::Dict(
        items
            .iter()
            .map(|(k, v)| {
                if k == "specs" {
                    (k.clone(), PyValue::List(kept.clone()))
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect(),
    )
}

/// `FlowRequest`.
pub static FLOW_REQUEST: Model = Model::new(
    "FlowRequest",
    &[
        Field::def("creator", Ty::Str, empty_str),
        Field::def("user_data", Ty::Str, empty_str),
        Field::def("client_id", Ty::Str, empty_str),
        Field::def("flow_id", Ty::Str, empty_str),
        Field::def("urgent", Ty::Bool, no),
        Field::def("artifacts", Ty::List(&Ty::Str), empty_list),
        Field::opt("specs", Ty::Nullable(&Ty::List(&Ty::Model(&FLOW_SPEC)))),
        Field::def("cpu_limit", Ty::Int, zero),
        Field::def("iops_limit", Ty::Int, zero),
        Field::def("progress_timeout", Ty::Int, zero),
        Field::def("timeout", Ty::Int, zero),
        Field::def("max_rows", Ty::Int, zero),
        Field::def("max_upload_bytes", Ty::Int, zero),
        Field::def("trace_freq_sec", Ty::Int, zero),
        Field::def("allow_custom_overrides", Ty::Bool, no),
        Field::def("log_batch_time", Ty::Int, zero),
        Field::def("compiled_collector_args", Ty::List(&Ty::Str), empty_list),
        Field::def("ops_per_second", Ty::Int, zero),
    ],
);

/// `FlowQueryStat`.
pub static FLOW_QUERY_STAT: Model = Model::new(
    "FlowQueryStat",
    &[
        Field::def("status", Ty::Str, empty_str),
        Field::def("error_message", Ty::Str, empty_str),
        Field::def("backtrace", Ty::Str, empty_str),
        Field::def("duration", Ty::Int, zero),
        Field::def("last_active", Ty::Int, zero),
        Field::def("first_active", Ty::Int, zero),
        Field::def("names_with_response", Ty::List(&Ty::Str), empty_list),
        Field::def("Artifact", Ty::Str, empty_str),
        Field::def("log_rows", Ty::Int, zero),
        Field::def("uploaded_files", Ty::Int, zero),
        Field::def("uploaded_bytes", Ty::Int, zero),
        Field::def("expected_uploaded_bytes", Ty::Int, zero),
        Field::def("result_rows", Ty::Int, zero),
        Field::def("query_id", Ty::Int, zero),
        Field::def("total_queries", Ty::Int, zero),
    ],
);

/// `default_factory=FlowRequest`: an unvalidated `FlowRequest()`.
fn default_request() -> PyValue {
    model::validate(&FLOW_REQUEST, &PyValue::Dict(Vec::new())).unwrap_or(PyValue::None)
}

/// `FlowClientSession`.
pub static FLOW_CLIENT_SESSION: Model = Model::new(
    "FlowClientSession",
    &[
        Field::def("client_id", Ty::Str, empty_str),
        Field::def("session_id", Ty::Str, empty_str),
        Field::def("request", Ty::Model(&FLOW_REQUEST), default_request).before(request_before),
        Field::def("backtrace", Ty::Str, empty_str),
        Field::def("create_time", Ty::Int, zero),
        Field::def("start_time", Ty::Int, zero),
        Field::def("active_time", Ty::Int, zero),
        Field::def("total_uploaded_files", Ty::Int, zero),
        Field::def("total_expected_uploaded_bytes", Ty::Int, zero),
        Field::def("total_uploaded_bytes", Ty::Int, zero),
        Field::def("total_collected_rows", Ty::Int, zero),
        Field::def("total_logs", Ty::Int, zero),
        Field::def("total_requests", Ty::Int, zero),
        Field::def("outstanding_requests", Ty::Int, zero),
        Field::def("next_response_id", Ty::Int, zero),
        Field::def("execution_duration", Ty::Int, zero),
        Field::def("state", Ty::Str, empty_str),
        Field::def("status", Ty::Str, empty_str),
        Field::def("artifacts_with_results", Ty::List(&Ty::Str), empty_list),
        Field::def(
            "query_stats",
            Ty::List(&Ty::Model(&FLOW_QUERY_STAT)),
            empty_list,
        ),
        Field::def("uploaded_files", Ty::List(&Ty::Str), empty_list),
        Field::def("user_notified", Ty::Bool, no),
        Field::def("logs", Ty::List(&Ty::Str), empty_list),
        Field::def("dirty", Ty::Bool, no),
        Field::def("total_loads", Ty::Int, zero),
    ],
);

/// `FlowClientSession(**flow)` raising outside validation: `**` of a
/// non-mapping, or `validate_specs` iterating a `specs` that is no
/// iterable (its `for` is outside the `try`).
pub fn flow_session_fails(flow: &PyValue) -> bool {
    let PyValue::Dict(items) = flow else {
        return true;
    };
    let Some((_, PyValue::Dict(request))) = items.iter().find(|(k, _)| k == "request") else {
        return false;
    };
    matches!(
        request.iter().find(|(k, _)| k == "specs").map(|(_, v)| v),
        Some(PyValue::Int(_) | PyValue::Float(_) | PyValue::Bool(_))
    )
}

/// `CommandArtifactsEnum`.
pub const COMMAND_ARTIFACTS: &[&str] = &[
    "Windows.System.PowerShell",
    "Windows.System.CmdShell",
    "Linux.Sys.BashShell",
];
/// `QuarantineArtifactsEnum`.
pub const QUARANTINE_ARTIFACTS: &[&str] = &[
    "Windows.Remediation.Quarantine",
    "Linux.Remediation.Quarantine",
];
/// `ActionEnum`.
pub const ACTIONS: &[&str] = &["quarantine", "remove_quarantine"];

/// `RunCommandBody`, as the route holds it once `run_remote_command` has
/// replaced the enum by its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCommandBody {
    /// `hostname`.
    pub hostname: String,
    /// `velociraptor_id` (set by the route).
    pub velociraptor_id: Option<String>,
    /// `velociraptor_org` (set by the route).
    pub velociraptor_org: Option<String>,
    /// `command`.
    pub command: Option<String>,
    /// `artifact_name` (`None` when absent: the field's unvalidated default).
    pub artifact_name: Option<String>,
}

/// `QuarantineBody`, as `quarantine_host` holds it (the enums replaced by
/// their values, the artifact by its configured override).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineBody {
    /// `hostname`.
    pub hostname: String,
    /// `velociraptor_id`.
    pub velociraptor_id: Option<String>,
    /// `velociraptor_org`.
    pub velociraptor_org: Option<String>,
    /// `action`.
    pub action: String,
    /// `artifact_name`.
    pub artifact_name: Option<String>,
}

fn repr(v: Option<&str>) -> String {
    v.map_or_else(
        || "None".to_string(),
        |s| PyValue::Str(s.to_string()).py_repr(),
    )
}

impl RunCommandBody {
    /// `str(body)`: Pydantic's `field=repr(value)` pairs.
    pub fn py_str(&self) -> String {
        format!(
            "hostname={} velociraptor_id={} velociraptor_org={} command={} artifact_name={}",
            repr(Some(&self.hostname)),
            repr(self.velociraptor_id.as_deref()),
            repr(self.velociraptor_org.as_deref()),
            repr(self.command.as_deref()),
            repr(self.artifact_name.as_deref()),
        )
    }
}

impl QuarantineBody {
    /// `str(body)`.
    pub fn py_str(&self) -> String {
        format!(
            "hostname={} velociraptor_id={} velociraptor_org={} action={} artifact_name={}",
            repr(Some(&self.hostname)),
            repr(self.velociraptor_id.as_deref()),
            repr(self.velociraptor_org.as_deref()),
            repr(Some(&self.action)),
            repr(self.artifact_name.as_deref()),
        )
    }
}

/// `ParameterKeyValue`.
pub static PARAMETER_KEY_VALUE: Model = Model::new(
    "ParameterKeyValue",
    &[Field::req("key", Ty::Str), Field::req("value", Ty::Str)],
);

/// `CollectArtifactBody`.
pub static COLLECT_ARTIFACT_BODY: Model = Model::new(
    "CollectArtifactBody",
    &[
        Field::req("hostname", Ty::Str),
        Field::opt("velociraptor_id", Ty::Nullable(&Ty::Str)),
        Field::opt("velociraptor_org", Ty::Nullable(&Ty::Str)),
        Field::opt("artifact_name", Ty::Nullable(&Ty::Str)),
        Field::opt(
            "parameters",
            Ty::Nullable(&Ty::Dict(&Ty::Union(&[
                Ty::Str,
                Ty::List(&Ty::Model(&PARAMETER_KEY_VALUE)),
            ]))),
        ),
        Field::def("data_store_only", Ty::Nullable(&Ty::Bool), no),
    ],
);

fn root_disk() -> PyValue {
    PyValue::Str("C:".into())
}

/// `FileCollectionBody`.
pub static FILE_COLLECTION_BODY: Model = Model::new(
    "FileCollectionBody",
    &[
        Field::req("file", Ty::Str),
        Field::def("root_disk", Ty::Str, root_disk),
    ],
);

/// One value of `CollectArtifactBody.parameters`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamValue {
    /// A string.
    Str(String),
    /// `List[ParameterKeyValue]`, as `(key, value)` pairs.
    Pairs(Vec<(String, String)>),
}

/// `CollectArtifactBody`, as the route holds it once it has set the host's
/// client id and org.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectArtifactBody {
    /// `hostname`.
    pub hostname: String,
    /// `velociraptor_id` (set by the route).
    pub velociraptor_id: Option<String>,
    /// `velociraptor_org` (set by the route).
    pub velociraptor_org: Option<String>,
    /// `artifact_name`.
    pub artifact_name: Option<String>,
    /// `parameters`, in the request's key order.
    pub parameters: Option<Vec<(String, ParamValue)>>,
    /// `data_store_only` (`None` when sent as `null`).
    pub data_store_only: Option<bool>,
}

fn opt_text(v: &PyValue) -> Option<String> {
    v.as_str().map(str::to_string)
}

impl CollectArtifactBody {
    /// From the validated [`COLLECT_ARTIFACT_BODY`] dump.
    pub fn from_dump(d: &PyValue) -> Self {
        let parameters = match model::field(d, "parameters") {
            PyValue::Dict(items) => Some(
                items
                    .iter()
                    .map(|(k, v)| {
                        let value = match v {
                            PyValue::List(pairs) => ParamValue::Pairs(
                                pairs
                                    .iter()
                                    .map(|p| {
                                        (
                                            opt_text(model::field(p, "key")).unwrap_or_default(),
                                            opt_text(model::field(p, "value")).unwrap_or_default(),
                                        )
                                    })
                                    .collect(),
                            ),
                            other => ParamValue::Str(opt_text(other).unwrap_or_default()),
                        };
                        (k.clone(), value)
                    })
                    .collect(),
            ),
            _ => None,
        };
        Self {
            hostname: opt_text(model::field(d, "hostname")).unwrap_or_default(),
            velociraptor_id: opt_text(model::field(d, "velociraptor_id")),
            velociraptor_org: opt_text(model::field(d, "velociraptor_org")),
            artifact_name: opt_text(model::field(d, "artifact_name")),
            parameters,
            data_store_only: match model::field(d, "data_store_only") {
                PyValue::Bool(b) => Some(*b),
                _ => None,
            },
        }
    }

    /// `str(body)`.
    pub fn py_str(&self) -> String {
        let parameters = match &self.parameters {
            None => "None".to_string(),
            Some(items) => {
                let parts: Vec<String> = items
                    .iter()
                    .map(|(k, v)| {
                        let value = match v {
                            ParamValue::Str(s) => repr(Some(s)),
                            ParamValue::Pairs(pairs) => format!(
                                "[{}]",
                                pairs
                                    .iter()
                                    .map(|(k, v)| format!(
                                        "ParameterKeyValue(key={}, value={})",
                                        repr(Some(k)),
                                        repr(Some(v))
                                    ))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                        };
                        format!("{}: {value}", repr(Some(k)))
                    })
                    .collect();
                format!("{{{}}}", parts.join(", "))
            }
        };
        let data_store_only = match self.data_store_only {
            None => "None",
            Some(true) => "True",
            Some(false) => "False",
        };
        format!(
            "hostname={} velociraptor_id={} velociraptor_org={} artifact_name={} parameters={} \
             data_store_only={}",
            repr(Some(&self.hostname)),
            repr(self.velociraptor_id.as_deref()),
            repr(self.velociraptor_org.as_deref()),
            repr(self.artifact_name.as_deref()),
            parameters,
            data_store_only,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn bodies_print_as_pydantic_does() {
        let body = RunCommandBody {
            hostname: "web-01".into(),
            velociraptor_id: Some("C.1".into()),
            velociraptor_org: None,
            command: Some("echo 'hi'\n".into()),
            artifact_name: Some("Linux.Sys.BashShell".into()),
        };
        assert_eq!(
            body.py_str(),
            r#"hostname='web-01' velociraptor_id='C.1' velociraptor_org=None command="echo 'hi'\n" artifact_name='Linux.Sys.BashShell'"#
        );
    }

    #[test]
    fn flows_are_read_tolerantly() {
        let row = loads(
            r#"{"session_id": "F.1", "create_time": "5", "request": {"specs": [{"artifact": "A"}, 3, {"artifact": 4}], "urgent": 1}, "extra": true}"#,
        )
        .unwrap();
        let dump = model::validate(&FLOW_CLIENT_SESSION, &row).unwrap();
        let request = model::field(&dump, "request");
        assert_eq!(
            model::field(request, "specs"),
            &loads(r#"[{"artifact": "A", "parameters": null}]"#).unwrap()
        );
        assert_eq!(model::field(request, "urgent"), &PyValue::Bool(true));
        assert_eq!(
            model::field(&dump, "create_time"),
            &PyValue::Int("5".into())
        );
        let empty = model::validate(&FLOW_CLIENT_SESSION, &loads("{}").unwrap()).unwrap();
        assert_eq!(
            model::field(model::field(&empty, "request"), "creator"),
            &PyValue::Str(String::new())
        );
        assert!(flow_session_fails(
            &loads(r#"{"request": {"specs": 5}}"#).unwrap()
        ));
        assert!(flow_session_fails(&loads("[]").unwrap()));
        assert!(!flow_session_fails(
            &loads(r#"{"request": {"specs": "ab"}}"#).unwrap()
        ));
    }
}
