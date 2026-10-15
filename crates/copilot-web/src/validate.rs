//! Request validation with Pydantic 2 (lax mode) semantics and FastAPI's
//! error report.
//!
//! The frontends show `message` from a 422 verbatim, so a Rust handler must
//! reject the same inputs with the same words. [`Validator`] reads a JSON
//! body (or query/path values) field by field, coercing exactly where
//! Pydantic's lax mode coerces (`"12"` → 12, `true` → 1, `"yes"` → true, …),
//! and records one [`FieldError`] per failure in declaration order. Readers
//! return a default value on failure; call [`Validator::finish`] before using
//! any of them.
//!
//! [`FieldError`]s are rendered the way
//! `exception_handlers.validation_exception_handler` renders them: a known
//! Pydantic code maps to its canned sentence (`app/utils.py:ErrorType`),
//! everything else becomes `value_error` with `"field.path: reason"`.

use serde::Serialize;
use serde_json::{Map, Value};

use crate::error::ApiError;

/// One element of an error location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocPart {
    /// Object key (or the request location: `body`, `query`, `path`).
    Key(String),
    /// List index.
    Index(usize),
}

impl std::fmt::Display for LocPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocPart::Key(k) => f.write_str(k),
            LocPart::Index(i) => write!(f, "{i}"),
        }
    }
}

/// A location such as `("body", "iocs", 0, "ioc_type")`.
pub type Loc = Vec<LocPart>;

/// Build a location from a request location and a field name.
pub fn loc(location: &str, field: &str) -> Loc {
    vec![LocPart::Key(location.into()), LocPart::Key(field.into())]
}

fn child(parent: &Loc, key: &str) -> Loc {
    let mut l = parent.clone();
    l.push(LocPart::Key(key.into()));
    l
}

/// One Pydantic error (`{"type", "loc", "msg"}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    /// Pydantic error code (`missing`, `string_too_long`, `value_error`, …).
    pub kind: String,
    /// Where.
    pub loc: Loc,
    /// Pydantic's message.
    pub msg: String,
}

/// One entry of the 422 `details` list (`app/utils.py:ValidationErrorItem`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationItem {
    /// Last location element, or `body`.
    pub field: String,
    /// `ErrorType` value.
    pub error_type: String,
    /// Human sentence.
    pub message: Option<String>,
}

/// `ErrorType` members and their canned messages (`ValidationErrorItem.set_message`).
const KNOWN: &[(&str, &str)] = &[
    (
        "value_error.str.regex",
        "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.",
    ),
    (
        "value_error.time_range",
        "Invalid time range. Use 'h' for hours, 'd' for days, and 'w' for weeks.",
    ),
    (
        "json_invalid",
        "Invalid JSON. Please check your JSON syntax and try again.",
    ),
    (
        "value_error.any_str.min_length",
        "Value is shorter than minimum length.",
    ),
    (
        "value_error.any_str.max_length",
        "Value is longer than maximum length.",
    ),
    ("value_error.number.not_a_number", "Input is not a number."),
    ("value_error.number.too_small", "Value is too small."),
    ("value_error.number.too_large", "Value is too large."),
    ("value_error.datetime", "Invalid datetime format."),
    ("value_error.date", "Invalid date format."),
    (
        "value_error.list.min_items",
        "Number of items is less than minimum.",
    ),
    (
        "value_error.list.max_items",
        "Number of items is more than maximum.",
    ),
    ("value_error.list.unique", "Items are not unique."),
    (
        "value_error.none.not_allowed",
        "None is not an allowed value.",
    ),
    ("value_error.missing", "Missing data for required field."),
    ("value_error", "Invalid value."),
    (
        "type_error.enum",
        "Value is not a valid enumeration member.",
    ),
    ("string_too_short", "Value is shorter than minimum length."),
    ("string_too_long", "Value is longer than maximum length."),
    (
        "string_pattern_mismatch",
        "Value does not match the required pattern.",
    ),
    ("int_parsing", "Input is not a valid integer."),
    ("greater_than", "Value is too small."),
    ("greater_than_equal", "Value is too small."),
    ("less_than", "Value is too large."),
    ("less_than_equal", "Value is too large."),
    ("datetime_parsing", "Invalid datetime format."),
    ("date_parsing", "Invalid date format."),
    ("enum", "Value is not a valid enumeration member."),
    ("missing", "Missing data for required field."),
];

const REQUEST_LOCATIONS: &[&str] = &["body", "query", "path", "header", "cookie"];

impl FieldError {
    /// Render as the handler does.
    pub fn to_item(&self) -> ValidationItem {
        let field = self
            .loc
            .last()
            .map_or_else(|| "body".to_string(), ToString::to_string);
        let known = KNOWN.iter().find(|(code, _)| *code == self.kind);
        match known {
            Some((code, canned)) if *code != "value_error" => ValidationItem {
                field,
                error_type: (*code).to_string(),
                message: Some((*canned).to_string()),
            },
            _ => ValidationItem {
                field,
                error_type: "value_error".to_string(),
                message: Some(self.describe()),
            },
        }
    }

    /// `_describe`: `field.path: reason`, location prefix and Pydantic's
    /// `Value error, ` prefix removed.
    fn describe(&self) -> String {
        let raw = self.msg.trim();
        let raw = raw.strip_prefix("Value error, ").unwrap_or(raw);
        let parts: &[LocPart] = match self.loc.first() {
            Some(LocPart::Key(k)) if REQUEST_LOCATIONS.contains(&k.as_str()) => &self.loc[1..],
            _ => &self.loc,
        };
        let path = parts
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(".");
        if path.is_empty() {
            raw.to_string()
        } else {
            format!("{path}: {raw}")
        }
    }
}

/// String constraints.
#[derive(Debug, Clone, Copy, Default)]
pub struct StrRules {
    /// `min_length`.
    pub min_len: Option<usize>,
    /// `max_length`.
    pub max_len: Option<usize>,
    /// Strip C0 control characters (except `\t`, `\n`, `\r`) and DEL *before*
    /// the length checks — the `_strip_control_chars` pre-validator.
    pub strip_control: bool,
}

impl StrRules {
    /// Only a maximum length.
    pub const fn max(n: usize) -> Self {
        Self {
            min_len: None,
            max_len: Some(n),
            strip_control: false,
        }
    }

    /// Unconstrained.
    pub const fn any() -> Self {
        Self {
            min_len: None,
            max_len: None,
            strip_control: false,
        }
    }

    /// Add the control-character strip.
    pub const fn stripped(mut self) -> Self {
        self.strip_control = true;
        self
    }

    /// Add a minimum length.
    pub const fn min(mut self, n: usize) -> Self {
        self.min_len = Some(n);
        self
    }
}

/// `re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", v)`.
pub fn strip_control_chars(v: &str) -> String {
    v.chars()
        .filter(|c| {
            let u = *c as u32;
            !(u <= 0x08 || u == 0x0b || u == 0x0c || (0x0e..=0x1f).contains(&u) || u == 0x7f)
        })
        .collect()
}

/// Integer bounds.
#[derive(Debug, Clone, Copy, Default)]
pub struct IntRules {
    /// `ge`.
    pub ge: Option<i64>,
    /// `le`.
    pub le: Option<i64>,
}

/// Pydantic's `'a', 'b' or 'c'` list.
fn enum_expected(allowed: &[&str]) -> String {
    let quoted: Vec<String> = allowed.iter().map(|a| format!("'{a}'")).collect();
    match quoted.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
    }
}

/// Lax string → int (`" 12 "` is accepted; `"1.0"` is not).
fn parse_int_str(s: &str) -> Result<i64, FieldError> {
    s.trim().parse::<i64>().map_err(|_| FieldError {
        kind: "int_parsing".into(),
        loc: Vec::new(),
        msg: "Input should be a valid integer, unable to parse string as an integer".into(),
    })
}

/// Collects errors while reading a request.
#[derive(Debug, Default)]
pub struct Validator {
    errors: Vec<FieldError>,
}

impl Validator {
    /// Fresh validator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an error.
    pub fn push(&mut self, kind: &str, loc: Loc, msg: impl Into<String>) {
        self.errors.push(FieldError {
            kind: kind.into(),
            loc,
            msg: msg.into(),
        });
    }

    /// Whether anything failed so far.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// The recorded errors.
    pub fn errors(&self) -> &[FieldError] {
        &self.errors
    }

    /// `Ok(())` or the 422.
    pub fn finish(self) -> Result<(), ApiError> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(ApiError::Validation(
                self.errors.iter().map(FieldError::to_item).collect(),
            ))
        }
    }

    /// The request body as an object (`model_attributes_type` otherwise).
    pub fn object<'a>(&mut self, value: &'a Value, at: &Loc) -> Option<&'a Map<String, Value>> {
        match value {
            Value::Object(map) => Some(map),
            _ => {
                self.push(
                    "model_attributes_type",
                    at.clone(),
                    "Input should be a valid dictionary or object to extract fields from",
                );
                None
            }
        }
    }

    /// A nested model (`model_type`).
    pub fn nested<'a>(
        &mut self,
        value: &'a Value,
        at: &Loc,
        model: &str,
    ) -> Option<&'a Map<String, Value>> {
        match value {
            Value::Object(map) => Some(map),
            _ => {
                self.push(
                    "model_type",
                    at.clone(),
                    format!("Input should be a valid dictionary or instance of {model}"),
                );
                None
            }
        }
    }

    fn missing(&mut self, at: Loc) {
        self.push("missing", at, "Field required");
    }

    fn check_str(&mut self, at: &Loc, value: &Value, rules: StrRules) -> Option<String> {
        let Value::String(s) = value else {
            self.push("string_type", at.clone(), "Input should be a valid string");
            return None;
        };
        let s = if rules.strip_control {
            strip_control_chars(s)
        } else {
            s.clone()
        };
        let len = s.chars().count();
        if let Some(min) = rules.min_len.filter(|min| len < *min) {
            let unit = if min == 1 { "character" } else { "characters" };
            self.push(
                "string_too_short",
                at.clone(),
                format!("String should have at least {min} {unit}"),
            );
            return None;
        }
        if let Some(max) = rules.max_len.filter(|max| len > *max) {
            let unit = if max == 1 { "character" } else { "characters" };
            self.push(
                "string_too_long",
                at.clone(),
                format!("String should have at most {max} {unit}"),
            );
            return None;
        }
        Some(s)
    }

    /// Required string field.
    pub fn req_str(
        &mut self,
        obj: &Map<String, Value>,
        at: &Loc,
        name: &str,
        rules: StrRules,
    ) -> String {
        let l = child(at, name);
        match obj.get(name) {
            None => {
                self.missing(l);
                String::new()
            }
            Some(v) => self.check_str(&l, v, rules).unwrap_or_default(),
        }
    }

    /// Optional string field (`None`/absent → `None`).
    pub fn opt_str(
        &mut self,
        obj: &Map<String, Value>,
        at: &Loc,
        name: &str,
        rules: StrRules,
    ) -> Option<String> {
        match obj.get(name) {
            None | Some(Value::Null) => None,
            Some(v) => self.check_str(&child(at, name), v, rules),
        }
    }

    /// String field with a default when absent (explicit `null` is an error,
    /// like a bare `str = "x"` annotation).
    pub fn str_or(
        &mut self,
        obj: &Map<String, Value>,
        at: &Loc,
        name: &str,
        rules: StrRules,
        default: &str,
    ) -> String {
        match obj.get(name) {
            None => default.to_string(),
            Some(v) => self
                .check_str(&child(at, name), v, rules)
                .unwrap_or_default(),
        }
    }

    /// Coerce one value to an integer (lax mode) and check bounds.
    pub fn check_int(&mut self, at: &Loc, value: &Value, rules: IntRules) -> Option<i64> {
        let parsed = match value {
            Value::Number(n) => match n.as_i64() {
                Some(i) => Ok(i),
                None => match n.as_f64() {
                    Some(f) if f.fract() == 0.0 && f.is_finite() => Ok(f as i64),
                    _ => Err(FieldError {
                        kind: "int_from_float".into(),
                        loc: Vec::new(),
                        msg: "Input should be a valid integer, got a number with a fractional part"
                            .into(),
                    }),
                },
            },
            Value::String(s) => parse_int_str(s),
            Value::Bool(b) => Ok(i64::from(*b)),
            _ => Err(FieldError {
                kind: "int_type".into(),
                loc: Vec::new(),
                msg: "Input should be a valid integer".into(),
            }),
        };
        let n = match parsed {
            Ok(n) => n,
            Err(mut e) => {
                e.loc = at.clone();
                self.errors.push(e);
                return None;
            }
        };
        if let Some(ge) = rules.ge.filter(|ge| n < *ge) {
            self.push(
                "greater_than_equal",
                at.clone(),
                format!("Input should be greater than or equal to {ge}"),
            );
            return None;
        }
        if let Some(le) = rules.le.filter(|le| n > *le) {
            self.push(
                "less_than_equal",
                at.clone(),
                format!("Input should be less than or equal to {le}"),
            );
            return None;
        }
        Some(n)
    }

    /// Coerce a string to a datetime (Pydantic lax mode, [`crate::datetime`]).
    pub fn check_datetime(&mut self, at: &Loc, raw: &str) -> Option<chrono::NaiveDateTime> {
        match crate::datetime::parse_lax(raw) {
            Ok(t) => Some(t),
            Err(e) => {
                self.push(e.kind, at.clone(), e.msg);
                None
            }
        }
    }

    /// Required integer field.
    pub fn req_int(
        &mut self,
        obj: &Map<String, Value>,
        at: &Loc,
        name: &str,
        rules: IntRules,
    ) -> i64 {
        let l = child(at, name);
        match obj.get(name) {
            None => {
                self.missing(l);
                0
            }
            Some(v) => self.check_int(&l, v, rules).unwrap_or_default(),
        }
    }

    /// Optional integer field.
    pub fn opt_int(
        &mut self,
        obj: &Map<String, Value>,
        at: &Loc,
        name: &str,
        rules: IntRules,
    ) -> Option<i64> {
        match obj.get(name) {
            None | Some(Value::Null) => None,
            Some(v) => self.check_int(&child(at, name), v, rules),
        }
    }

    fn check_bool(&mut self, at: &Loc, value: &Value) -> Option<bool> {
        let parsed = match value {
            Value::Bool(b) => Some(*b),
            Value::Number(n) => match n.as_i64() {
                Some(0) => Some(false),
                Some(1) => Some(true),
                _ => None,
            },
            Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
                "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
                "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
                _ => None,
            },
            _ => {
                self.push("bool_type", at.clone(), "Input should be a valid boolean");
                return None;
            }
        };
        if parsed.is_none() {
            self.push(
                "bool_parsing",
                at.clone(),
                "Input should be a valid boolean, unable to interpret input",
            );
        }
        parsed
    }

    /// Required boolean field.
    pub fn req_bool(&mut self, obj: &Map<String, Value>, at: &Loc, name: &str) -> bool {
        let l = child(at, name);
        match obj.get(name) {
            None => {
                self.missing(l);
                false
            }
            Some(v) => self.check_bool(&l, v).unwrap_or_default(),
        }
    }

    /// Optional boolean field.
    pub fn opt_bool(&mut self, obj: &Map<String, Value>, at: &Loc, name: &str) -> Option<bool> {
        match obj.get(name) {
            None | Some(Value::Null) => None,
            Some(v) => self.check_bool(&child(at, name), v),
        }
    }

    /// Check one value against a string enum.
    pub fn check_enum(&mut self, at: &Loc, value: &Value, allowed: &[&str]) -> Option<String> {
        match value {
            Value::String(s) if allowed.contains(&s.as_str()) => Some(s.clone()),
            _ => {
                self.push(
                    "enum",
                    at.clone(),
                    format!("Input should be {}", enum_expected(allowed)),
                );
                None
            }
        }
    }

    /// Required enum field.
    pub fn req_enum(
        &mut self,
        obj: &Map<String, Value>,
        at: &Loc,
        name: &str,
        allowed: &[&str],
    ) -> String {
        let l = child(at, name);
        match obj.get(name) {
            None => {
                self.missing(l);
                String::new()
            }
            Some(v) => self.check_enum(&l, v, allowed).unwrap_or_default(),
        }
    }

    /// Optional enum field.
    pub fn opt_enum(
        &mut self,
        obj: &Map<String, Value>,
        at: &Loc,
        name: &str,
        allowed: &[&str],
    ) -> Option<String> {
        match obj.get(name) {
            None | Some(Value::Null) => None,
            Some(v) => self.check_enum(&child(at, name), v, allowed),
        }
    }

    /// Enum field with a default when absent.
    pub fn enum_or(
        &mut self,
        obj: &Map<String, Value>,
        at: &Loc,
        name: &str,
        allowed: &[&str],
        default: &str,
    ) -> String {
        match obj.get(name) {
            None => default.to_string(),
            Some(v) => self
                .check_enum(&child(at, name), v, allowed)
                .unwrap_or_default(),
        }
    }

    /// A list field; `None` absent/`null` handling is the caller's choice via
    /// `required`. Returns the items with their locations.
    pub fn list<'a>(
        &mut self,
        obj: &'a Map<String, Value>,
        at: &Loc,
        name: &str,
        required: bool,
    ) -> Vec<(Loc, &'a Value)> {
        let l = child(at, name);
        match obj.get(name) {
            None if required => {
                self.missing(l);
                Vec::new()
            }
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    let mut il = l.clone();
                    il.push(LocPart::Index(i));
                    (il, v)
                })
                .collect(),
            Some(_) => {
                self.push("list_type", l, "Input should be a valid list");
                Vec::new()
            }
        }
    }
}

/// Parse a request body as JSON the way FastAPI does: an empty body is a
/// missing required body, malformed JSON is `json_invalid`.
pub fn parse_json_body(bytes: &[u8]) -> Result<Value, ApiError> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        let mut v = Validator::new();
        v.missing(vec![LocPart::Key("body".into())]);
        return Err(v.finish().err().unwrap_or(ApiError::RouteNotFound));
    }
    serde_json::from_slice::<Value>(bytes).map_err(|e| {
        let pos = byte_offset(bytes, e.line(), e.column());
        ApiError::Validation(vec![
            FieldError {
                kind: "json_invalid".into(),
                loc: vec![LocPart::Key("body".into()), LocPart::Index(pos)],
                msg: "JSON decode error".into(),
            }
            .to_item(),
        ])
    })
}

fn byte_offset(bytes: &[u8], line: usize, column: usize) -> usize {
    let text = String::from_utf8_lossy(bytes);
    let mut offset = 0;
    for (i, l) in text.split('\n').enumerate() {
        if i + 1 == line {
            return offset + column.saturating_sub(1);
        }
        offset += l.chars().count() + 1;
    }
    offset
}

/// The `body` location.
pub fn body_loc() -> Loc {
    vec![LocPart::Key("body".into())]
}

/// Parse a JSON body into a model: `read` gets the validator, the object and
/// its location, and reads every field (it may add model-level errors once
/// the fields are valid). A non-object body is `model_attributes_type`.
pub fn parse_body_model<T>(
    bytes: &[u8],
    read: impl FnOnce(&mut Validator, &Map<String, Value>, &Loc) -> T,
) -> Result<T, ApiError> {
    let value = parse_json_body(bytes)?;
    let mut v = Validator::new();
    let root = body_loc();
    let out = v.object(&value, &root).map(|obj| read(&mut v, obj, &root));
    v.finish()?;
    out.ok_or_else(|| ApiError::internal("parse_body_model: object without errors"))
}

/// An integer path parameter that both a tenancy dependency and the route
/// declare: FastAPI validates it twice and reports the failure twice.
pub fn path_int_dep(name: &str, raw: &str) -> Result<i64, ApiError> {
    match path_int(name, raw) {
        Err(ApiError::Validation(mut items)) => {
            let again = items.clone();
            items.extend(again);
            Err(ApiError::Validation(items))
        }
        other => other,
    }
}

/// Parse an integer path parameter (`int_parsing` on failure).
pub fn path_int(name: &str, raw: &str) -> Result<i64, ApiError> {
    let mut v = Validator::new();
    let n = v.check_int(
        &loc("path", name),
        &Value::String(raw.to_string()),
        IntRules::default(),
    );
    v.finish()?;
    n.ok_or_else(|| ApiError::internal("path_int: unreachable"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body_loc() -> Loc {
        vec![LocPart::Key("body".into())]
    }

    fn items(v: Validator) -> Vec<ValidationItem> {
        match v.finish() {
            Err(ApiError::Validation(items)) => items,
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn canned_and_described_messages() {
        let mut v = Validator::new();
        let body = json!({"s": 5, "long": "abcd", "e": "z", "n": "x"});
        let obj = body.as_object().unwrap();
        v.req_str(obj, &body_loc(), "s", StrRules::any());
        v.req_str(obj, &body_loc(), "long", StrRules::max(3));
        v.req_enum(obj, &body_loc(), "e", &["scheduled", "manual", "webhook"]);
        v.req_int(obj, &body_loc(), "n", IntRules::default());
        v.req_str(obj, &body_loc(), "absent", StrRules::any());
        let got = items(v);
        assert_eq!(got[0].error_type, "value_error");
        assert_eq!(
            got[0].message.as_deref(),
            Some("s: Input should be a valid string")
        );
        assert_eq!(got[1].error_type, "string_too_long");
        assert_eq!(
            got[1].message.as_deref(),
            Some("Value is longer than maximum length.")
        );
        assert_eq!(got[2].error_type, "enum");
        assert_eq!(
            got[3].message.as_deref(),
            Some("Input is not a valid integer.")
        );
        assert_eq!(got[4].field, "absent");
        assert_eq!(
            got[4].message.as_deref(),
            Some("Missing data for required field.")
        );
    }

    #[test]
    fn lax_coercions() {
        let mut v = Validator::new();
        let body = json!({"i": "12", "t": true, "f": 3.0, "b": "yes", "z": 0});
        let obj = body.as_object().unwrap();
        assert_eq!(v.req_int(obj, &body_loc(), "i", IntRules::default()), 12);
        assert_eq!(v.req_int(obj, &body_loc(), "t", IntRules::default()), 1);
        assert_eq!(v.req_int(obj, &body_loc(), "f", IntRules::default()), 3);
        assert!(v.req_bool(obj, &body_loc(), "b"));
        assert!(!v.req_bool(obj, &body_loc(), "z"));
        assert!(!v.has_errors());
    }

    #[test]
    fn nested_locations_and_bounds() {
        let mut v = Validator::new();
        let body = json!({"iocs": [{"rating": 9}]});
        let obj = body.as_object().unwrap();
        for (l, item) in v.list(obj, &body_loc(), "iocs", true) {
            let o = v.nested(item, &l, "X").unwrap();
            v.opt_int(
                o,
                &l,
                "rating",
                IntRules {
                    ge: Some(1),
                    le: Some(5),
                },
            );
        }
        let got = items(v);
        assert_eq!(got[0].field, "rating");
        assert_eq!(got[0].error_type, "less_than_equal");
    }

    #[test]
    fn value_error_prefix_and_model_level() {
        let mut v = Validator::new();
        v.push(
            "value_error",
            body_loc(),
            "Value error, Report body fields must be non-empty: summary.",
        );
        let got = items(v);
        assert_eq!(got[0].field, "body");
        assert_eq!(
            got[0].message.as_deref(),
            Some("Report body fields must be non-empty: summary.")
        );
    }

    #[test]
    fn control_chars_are_stripped_before_length() {
        assert_eq!(strip_control_chars("a\u{0}b\tc\n\u{7f}"), "ab\tc\n");
        let mut v = Validator::new();
        let body = json!({"t": "\u{1}\u{2}"});
        let obj = body.as_object().unwrap();
        v.req_str(obj, &body_loc(), "t", StrRules::any().stripped().min(1));
        assert_eq!(items(v)[0].error_type, "string_too_short");
    }

    #[test]
    fn body_parsing() {
        assert!(matches!(
            parse_json_body(b"  "),
            Err(ApiError::Validation(_))
        ));
        match parse_json_body(b"{\"a\": }") {
            Err(ApiError::Validation(items)) => {
                assert_eq!(items[0].error_type, "json_invalid");
                assert_eq!(items[0].field, "6");
            }
            other => panic!("{other:?}"),
        }
        assert!(path_int("report_id", "12").is_ok());
        assert!(path_int("report_id", "abc").is_err());
        assert_eq!(enum_expected(&["a", "b", "c"]), "'a', 'b' or 'c'");
        assert_eq!(enum_expected(&["up", "down"]), "'up' or 'down'");
    }
}
