//! The request bodies of `/api/incidents/alerts` as FastAPI validates them
//! (Pydantic's lax rules, errors in declaration order, nested models as
//! `model_attributes_type`), and the few response helpers.

use serde_json::{Map, Value};

use copilot_auth::pyvalue::PyValue;
use copilot_incidents::requests::{PyDateTime, str_list};
use copilot_upstream::model::{Invalid, Loc as ModelLoc, validate_body};
use copilot_web::validate::{IntRules, Loc, LocPart, StrRules, Validator};

use crate::py::to_py;
use crate::sigma::events::{EVENT_UNION, SigmaEvent, parse_event_before};
use crate::sigma::ingest::SigmaAlert;

type Obj = Map<String, Value>;

fn child(at: &Loc, key: &str) -> Loc {
    let mut l = at.clone();
    l.push(LocPart::Key(key.into()));
    l
}

fn any_str() -> StrRules {
    StrRules::any()
}

/// `CreateAlertRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateAlertRequest {
    /// `index_name`.
    pub index_name: String,
    /// `alert_id` (the document id).
    pub alert_id: String,
}

impl CreateAlertRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            index_name: v.req_str(o, at, "index_name", any_str()),
            alert_id: v.req_str(o, at, "alert_id", any_str()),
        }
    }
}

/// `CreateAlertRequestRoute`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateAlertRequestRoute {
    /// `index_name`.
    pub index_name: String,
    /// `index_id`.
    pub index_id: String,
    /// `agent_id`.
    pub agent_id: Option<String>,
    /// `alert_id` (the CoPilot alert).
    pub alert_id: Option<i64>,
}

impl CreateAlertRequestRoute {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            index_name: v.req_str(o, at, "index_name", any_str()),
            index_id: v.req_str(o, at, "index_id", any_str()),
            agent_id: v.opt_str(o, at, "agent_id", any_str()),
            alert_id: v.opt_int(o, at, "alert_id", IntRules::default()),
        }
    }
}

/// A `Dict[str, Any] = {}` field.
fn dict_or_empty(v: &mut Validator, o: &Obj, at: &Loc, key: &str) -> Vec<(String, PyValue)> {
    match o.get(key) {
        None => Vec::new(),
        Some(Value::Object(m)) => m.iter().map(|(k, x)| (k.clone(), to_py(x))).collect(),
        Some(_) => {
            v.push(
                "dict_type",
                child(at, key),
                "Input should be a valid dictionary",
            );
            Vec::new()
        }
    }
}

/// A `List[Any] = []` field.
fn any_list_or_empty(v: &mut Validator, o: &Obj, at: &Loc, key: &str) {
    match o.get(key) {
        None | Some(Value::Array(_)) => {}
        Some(_) => v.push("list_type", child(at, key), "Input should be a valid list"),
    }
}

/// A `List[str] = []` field.
fn str_list_or_empty(v: &mut Validator, o: &Obj, at: &Loc, key: &str) -> Vec<String> {
    match o.get(key) {
        None => Vec::new(),
        Some(value) => v.str_items(value, &child(at, key)),
    }
}

/// A `str = ""` field.
fn str_or_empty(v: &mut Validator, o: &Obj, at: &Loc, key: &str) -> String {
    v.str_or(o, at, key, any_str(), "")
}

/// A nested model, read where the body holds it.
fn nested<'a>(v: &mut Validator, o: &'a Obj, at: &Loc, key: &str) -> Option<&'a Obj> {
    let l = child(at, key);
    match o.get(key) {
        None => {
            v.missing(l);
            None
        }
        Some(value) => v.object(value, &l),
    }
}

/// `ReplayInfo`.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplayInfo {
    /// `timerange_start`.
    pub timerange_start: PyDateTime,
    /// `timerange_end`.
    pub timerange_end: PyDateTime,
    /// `query`.
    pub query: String,
}

/// `GraylogThresholdEventFields` (`extra="allow"`, `populate_by_name`).
#[derive(Debug, Clone, PartialEq)]
pub struct ThresholdFields {
    /// `CUSTOMER_CODE`.
    pub customer_code: String,
    /// `SOURCE`.
    pub source: String,
    /// `model_dump()`.
    pub dump: Vec<(String, PyValue)>,
}

impl ThresholdFields {
    fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        let customer_code = v.req_str(o, at, "CUSTOMER_CODE", any_str());
        let source = v.req_str(o, at, "SOURCE", any_str());
        let description = v.req_str(o, at, "ALERT_DESCRIPTION", any_str());
        let asset = v.opt_str(o, at, "ASSET_NAME", any_str());
        // `additional_fields`: the `__extra__` key, else (by name) its own.
        let extra_key = if o.contains_key("__extra__") {
            Some("__extra__")
        } else if o.contains_key("additional_fields") {
            Some("additional_fields")
        } else {
            None
        };
        let additional = match extra_key {
            Some(k) => dict_or_empty(v, o, at, k),
            None => Vec::new(),
        };
        let mut dump = vec![
            (
                "CUSTOMER_CODE".to_string(),
                PyValue::Str(customer_code.clone()),
            ),
            ("SOURCE".to_string(), PyValue::Str(source.clone())),
            ("ALERT_DESCRIPTION".to_string(), PyValue::Str(description)),
            (
                "ASSET_NAME".to_string(),
                asset.map_or(PyValue::None, PyValue::Str),
            ),
            ("additional_fields".to_string(), PyValue::Dict(additional)),
        ];
        let declared = ["CUSTOMER_CODE", "SOURCE", "ALERT_DESCRIPTION", "ASSET_NAME"];
        for (k, x) in o {
            if declared.contains(&k.as_str()) || Some(k.as_str()) == extra_key {
                continue;
            }
            crate::py::dict_set(&mut dump, k, to_py(x));
        }
        Self {
            customer_code,
            source,
            dump,
        }
    }
}

/// `GraylogThresholdEventNotification`, the parts the route reads.
#[derive(Debug, Clone, PartialEq)]
pub struct ThresholdNotification {
    /// `event.timestamp`.
    pub timestamp: PyDateTime,
    /// `event.message`.
    pub message: String,
    /// `event.event_definition_id`.
    pub event_definition_id: String,
    /// `event.source_streams`.
    pub source_streams: Vec<String>,
    /// `event.group_by_fields`.
    pub group_by_fields: Vec<(String, PyValue)>,
    /// `event.fields`.
    pub fields: ThresholdFields,
    /// `event.replay_info`.
    pub replay: ReplayInfo,
}

/// A `datetime` value as Pydantic reads it from JSON: a string through
/// `copilot_web::datetime` (datetime, else a date at midnight), a number as
/// a unix timestamp in seconds or milliseconds (pydantic-core's
/// `int_as_datetime` / `float_as_datetime`: an aware UTC value).
fn check_datetime(v: &mut Validator, at: &Loc, value: &Value) -> Option<PyDateTime> {
    use speedate::{DateTime, DateTimeConfig, MicrosecondsPrecisionOverflowBehavior, TimeConfig};
    use strum::EnumMessage;

    let number = match value {
        Value::String(raw) => {
            return match copilot_web::datetime::parse_lax_offset(raw) {
                Ok((wall, offset)) => Some(PyDateTime { wall, offset }),
                Err(e) => {
                    v.push(e.kind, at.clone(), e.msg);
                    None
                }
            };
        }
        Value::Number(n) => n,
        _ => {
            v.push(
                "datetime_type",
                at.clone(),
                "Input should be a valid datetime",
            );
            return None;
        }
    };
    let config = DateTimeConfig {
        timestamp_unit: speedate::TimestampUnit::Infer,
        time_config: TimeConfig {
            microseconds_precision_overflow_behavior:
                MicrosecondsPrecisionOverflowBehavior::Truncate,
            unix_timestamp_offset: Some(0),
        },
    };
    let parsed = if let Some(i) = number.as_i64() {
        DateTime::from_timestamp_with_config(i, 0, &config)
    } else if number.is_u64() {
        // Beyond `i64`: pydantic-core does not take it for a timestamp.
        v.push(
            "datetime_type",
            at.clone(),
            "Input should be a valid datetime",
        );
        return None;
    } else {
        let f = number.as_f64().unwrap_or(f64::NAN);
        if f.is_nan() {
            v.push(
                "datetime_parsing",
                at.clone(),
                "Input should be a valid datetime, NaN values not permitted",
            );
            return None;
        }
        DateTime::from_float_with_config(f, &config)
    };
    let dt = match parsed {
        Ok(dt) => dt,
        Err(e) => {
            v.push(
                "datetime_parsing",
                at.clone(),
                format!(
                    "Input should be a valid datetime, {}",
                    e.get_documentation().unwrap_or_default()
                ),
            );
            return None;
        }
    };
    let wall = chrono::NaiveDate::from_ymd_opt(
        i32::from(dt.date.year),
        u32::from(dt.date.month),
        u32::from(dt.date.day),
    )
    .and_then(|d| {
        d.and_hms_micro_opt(
            u32::from(dt.time.hour),
            u32::from(dt.time.minute),
            u32::from(dt.time.second),
            dt.time.microsecond,
        )
    });
    match wall {
        Some(wall) => Some(PyDateTime {
            wall,
            offset: Some(0),
        }),
        None => {
            v.push(
                "datetime_parsing",
                at.clone(),
                "Input should be a valid datetime, date is out of range",
            );
            None
        }
    }
}

/// A required `datetime` field.
fn req_datetime(v: &mut Validator, o: &Obj, at: &Loc, name: &str) -> Option<PyDateTime> {
    let l = child(at, name);
    match o.get(name) {
        None => {
            v.missing(l);
            None
        }
        Some(value) => check_datetime(v, &l, value),
    }
}

/// An `Optional[datetime] = None` field.
fn opt_datetime(v: &mut Validator, o: &Obj, at: &Loc, name: &str) -> Option<PyDateTime> {
    match o.get(name) {
        None | Some(Value::Null) => None,
        Some(value) => check_datetime(v, &child(at, name), value),
    }
}

fn read_replay(v: &mut Validator, o: &Obj, at: &Loc) -> Option<ReplayInfo> {
    let start = req_datetime(v, o, at, "timerange_start");
    let end = req_datetime(v, o, at, "timerange_end");
    let query = v.req_str(o, at, "query", any_str());
    str_list(v, o, at, "streams");
    any_list_or_empty(v, o, at, "filters");
    Some(ReplayInfo {
        timerange_start: start?,
        timerange_end: end?,
        query,
    })
}

impl ThresholdNotification {
    /// Read the body (`None` when it failed; the validator holds why).
    pub fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Option<Self> {
        for key in [
            "event_definition_id",
            "event_definition_type",
            "event_definition_title",
        ] {
            v.req_str(o, at, key, any_str());
        }
        str_or_empty(v, o, at, "event_definition_description");
        v.req_str(o, at, "job_definition_id", any_str());
        v.req_str(o, at, "job_trigger_id", any_str());
        let event = nested(v, o, at, "event");
        let parsed = event.and_then(|e| {
            let at = child(at, "event");
            v.req_str(e, &at, "id", any_str());
            v.req_str(e, &at, "event_definition_type", any_str());
            let definition = v.req_str(e, &at, "event_definition_id", any_str());
            v.opt_str(e, &at, "origin_context", any_str());
            let timestamp = req_datetime(v, e, &at, "timestamp");
            req_datetime(v, e, &at, "timestamp_processing");
            opt_datetime(v, e, &at, "timerange_start");
            opt_datetime(v, e, &at, "timerange_end");
            str_list_or_empty(v, e, &at, "streams");
            let streams = str_list(v, e, &at, "source_streams");
            let message = v.req_str(e, &at, "message", any_str());
            v.req_str(e, &at, "source", any_str());
            any_list_or_empty(v, e, &at, "key_tuple");
            v.req_str(e, &at, "key", any_str());
            v.req_int(e, &at, "priority", IntRules::default());
            dict_or_empty(v, e, &at, "scores");
            any_list_or_empty(v, e, &at, "associated_assets");
            v.req_bool(e, &at, "alert");
            let fields = nested(v, e, &at, "fields")
                .map(|f| ThresholdFields::read(v, f, &child(&at, "fields")));
            let group_by = dict_or_empty(v, e, &at, "group_by_fields");
            let replay = nested(v, e, &at, "replay_info")
                .and_then(|r| read_replay(v, r, &child(&at, "replay_info")));
            Some(Self {
                timestamp: timestamp?,
                message,
                event_definition_id: definition,
                source_streams: streams,
                group_by_fields: group_by,
                fields: fields?,
                replay: replay?,
            })
        });
        any_list_or_empty(v, o, at, "backlog");
        parsed
    }
}

/// `str(datetime)`: `isoformat(" ")`.
pub fn py_datetime_str(t: &PyDateTime) -> String {
    let wall = t.wall;
    let mut out = if wall.and_utc().timestamp_subsec_micros() == 0 {
        wall.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        wall.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
    };
    if let Some(offset) = t.offset {
        let sign = if offset < 0 { '-' } else { '+' };
        let abs = offset.unsigned_abs();
        out.push_str(&format!("{sign}{:02}:{:02}", abs / 3600, (abs % 3600) / 60));
        if abs % 60 != 0 {
            out.push_str(&format!(":{:02}", abs % 60));
        }
    }
    out
}

/// `VelociraptorSigmaAlert`.
pub fn read_sigma(v: &mut Validator, o: &Obj, at: &Loc) -> Option<SigmaAlert> {
    let computer = v.req_str(o, at, "computer", any_str());
    let client_id = v.opt_str(o, at, "clientID", any_str());
    let channel = v.req_str(o, at, "channel", any_str());
    let title = v.req_str(o, at, "title", any_str());
    let level = v.req_str(o, at, "level", any_str());
    let event = read_event(v, o, at);
    let kind = v.str_or(o, at, "type", any_str(), "sigma-alert");
    let source = v.str_or(o, at, "source", any_str(), "velociraptor");
    let index_pattern = v.req_str(o, at, "index_pattern", any_str());
    let source_ref = v.req_str(o, at, "sourceRef", any_str());
    Some(SigmaAlert {
        computer,
        client_id,
        channel,
        title,
        level,
        event: event?,
        kind,
        source,
        index_pattern,
        source_ref,
    })
}

/// `event`: the `parse_event` before-validator, then the union.
fn read_event(v: &mut Validator, o: &Obj, at: &Loc) -> Option<SigmaEvent> {
    let l = child(at, "event");
    let Some(raw) = o.get("event") else {
        v.missing(l);
        return None;
    };
    let value = match parse_event_before(&to_py(raw)) {
        Ok(x) => x,
        Err(text) => {
            v.push("value_error", l, format!("Value error, {text}"));
            return None;
        }
    };
    match validate_body(&EVENT_UNION, &value) {
        Ok(PyValue::Str(s)) => Some(SigmaEvent::Str(s)),
        Ok(PyValue::Dict(d)) => Some(SigmaEvent::Dict(d)),
        Ok(_) => None,
        Err(Invalid::Errors(errors)) => {
            for e in errors {
                let mut loc = l.clone();
                for part in e.loc {
                    loc.push(match part {
                        ModelLoc::Key(k) => LocPart::Key(k),
                        ModelLoc::Index(i) => LocPart::Index(i),
                    });
                }
                v.push(e.kind, loc, e.msg);
            }
            None
        }
        Err(Invalid::Abort(_, _)) => None,
    }
}

/// `VeloSigmaExclusionDryRunRequest`.
pub fn read_dry_run(v: &mut Validator, o: &Obj, at: &Loc) -> crate::sigma::draft::DryRunRule {
    let channel = v.opt_str(o, at, "channel", any_str());
    let title = v.opt_str(o, at, "title", any_str());
    let field_matches = match o.get("field_matches") {
        None | Some(Value::Null) => None,
        Some(Value::Object(m)) => Some(PyValue::Dict(
            m.iter().map(|(k, x)| (k.clone(), to_py(x))).collect(),
        )),
        Some(_) => {
            v.push(
                "dict_type",
                child(at, "field_matches"),
                "Input should be a valid dictionary",
            );
            None
        }
    };
    let customer_code = v.opt_str(o, at, "customer_code", any_str());
    crate::sigma::draft::DryRunRule {
        channel,
        title,
        field_matches,
        customer_code,
    }
}
