//! The routes' query, path and body parameters as FastAPI validates them:
//! Pydantic's lax coercion of each value (`copilot_upstream::model`, pinned
//! by its vectors — a query value is always a `str`, a body value whatever
//! `json.loads` made of it), then the field's constraints in pydantic-core's
//! order (`le`, `lt`, `ge`, `gt` for numbers; `min_length`, `max_length`,
//! `pattern` for strings; a list's items, then its length). Every failure is
//! recorded in the [`Validator`] that holds the route's other errors, so one
//! 422 lists the path, query and body errors in FastAPI's order.

use std::cmp::Ordering;

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Invalid, Loc as ModelLoc, Ty, validate_ty};
use copilot_upstream::respond::from_json;
use copilot_web::QueryPairs;
use copilot_web::validate::{Loc, LocPart, Validator, loc};
use serde_json::{Map, Value};

/// String constraints.
#[derive(Debug, Clone, Copy, Default)]
pub struct StrSpec {
    /// `min_length`.
    pub min: Option<usize>,
    /// `max_length`.
    pub max: Option<usize>,
    /// `pattern` (searched, as pydantic-core's Rust regex does).
    pub pattern: Option<&'static str>,
}

impl StrSpec {
    /// No constraint.
    pub const ANY: Self = Self {
        min: None,
        max: None,
        pattern: None,
    };

    /// `min_length` and `max_length`.
    pub const fn len(min: usize, max: usize) -> Self {
        Self {
            min: Some(min),
            max: Some(max),
            pattern: None,
        }
    }

    /// Only `max_length`.
    pub const fn max(max: usize) -> Self {
        Self {
            min: None,
            max: Some(max),
            pattern: None,
        }
    }

    /// Only `pattern`.
    pub const fn pattern(pattern: &'static str) -> Self {
        Self {
            min: None,
            max: None,
            pattern: Some(pattern),
        }
    }
}

/// Number bounds (`ge`, `gt`, `le`).
#[derive(Debug, Clone, Copy, Default)]
pub struct NumSpec {
    /// `ge`.
    pub ge: Option<f64>,
    /// `gt`.
    pub gt: Option<f64>,
    /// `le`.
    pub le: Option<f64>,
}

impl NumSpec {
    /// No bound.
    pub const ANY: Self = Self {
        ge: None,
        gt: None,
        le: None,
    };

    /// `ge=lo, le=hi`.
    pub const fn range(lo: f64, hi: f64) -> Self {
        Self {
            ge: Some(lo),
            gt: None,
            le: Some(hi),
        }
    }

    /// Only `ge`.
    pub const fn ge(lo: f64) -> Self {
        Self {
            ge: Some(lo),
            gt: None,
            le: None,
        }
    }
}

fn child(at: &Loc, key: &str) -> Loc {
    let mut l = at.clone();
    l.push(LocPart::Key(key.into()));
    l
}

fn nested(at: &Loc, rel: &[ModelLoc]) -> Loc {
    let mut l = at.clone();
    for part in rel {
        l.push(match part {
            ModelLoc::Key(k) => LocPart::Key(k.clone()),
            ModelLoc::Index(i) => LocPart::Index(*i),
        });
    }
    l
}

/// Lax validation of one value as `ty`; the errors go to `v` at `at`.
fn lax(v: &mut Validator, at: &Loc, ty: &Ty, value: &PyValue) -> Option<PyValue> {
    match validate_ty(ty, value) {
        Ok(out) => Some(out),
        Err(Invalid::Errors(errors)) => {
            for e in errors {
                v.push(e.kind, nested(at, &e.loc), e.msg);
            }
            None
        }
        Err(Invalid::Abort(..)) => None,
    }
}

fn fmt_num(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        copilot_auth::pyvalue::float_repr(n)
    }
}

/// The bounds check of a number (NaN fails every bound, as in pydantic-core).
fn bounds(v: &mut Validator, at: &Loc, n: f64, spec: NumSpec) -> bool {
    if let Some(le) = spec.le {
        if !matches!(n.partial_cmp(&le), Some(Ordering::Less | Ordering::Equal)) {
            v.push(
                "less_than_equal",
                at.clone(),
                format!("Input should be less than or equal to {}", fmt_num(le)),
            );
            return false;
        }
    }
    if let Some(ge) = spec.ge {
        if !matches!(
            n.partial_cmp(&ge),
            Some(Ordering::Greater | Ordering::Equal)
        ) {
            v.push(
                "greater_than_equal",
                at.clone(),
                format!("Input should be greater than or equal to {}", fmt_num(ge)),
            );
            return false;
        }
    }
    if let Some(gt) = spec.gt {
        if !matches!(n.partial_cmp(&gt), Some(Ordering::Greater)) {
            v.push(
                "greater_than",
                at.clone(),
                format!("Input should be greater than {}", fmt_num(gt)),
            );
            return false;
        }
    }
    true
}

/// An `int`'s decimal text as a number for its bounds (huge values keep
/// their sign).
fn int_value(text: &str) -> f64 {
    text.parse::<f64>().unwrap_or(if text.starts_with('-') {
        f64::NEG_INFINITY
    } else {
        f64::INFINITY
    })
}

/// A `str` field (`value` already a string or not).
pub fn check_str(v: &mut Validator, at: &Loc, value: &PyValue, spec: StrSpec) -> Option<String> {
    let PyValue::Str(s) = lax(v, at, &Ty::Str, value)? else {
        return None;
    };
    let n = s.chars().count();
    if let Some(min) = spec.min.filter(|m| n < *m) {
        v.push(
            "string_too_short",
            at.clone(),
            format!(
                "String should have at least {min} character{}",
                if min == 1 { "" } else { "s" }
            ),
        );
        return None;
    }
    if let Some(max) = spec.max.filter(|m| n > *m) {
        v.push(
            "string_too_long",
            at.clone(),
            format!(
                "String should have at most {max} character{}",
                if max == 1 { "" } else { "s" }
            ),
        );
        return None;
    }
    if let Some(p) = spec.pattern {
        let matches = regex::Regex::new(p)
            .map(|r| r.is_match(&s))
            .unwrap_or(false);
        if !matches {
            v.push(
                "string_pattern_mismatch",
                at.clone(),
                format!("String should match pattern '{p}'"),
            );
            return None;
        }
    }
    Some(s)
}

/// A `float` field: its value (`PyValue::Float`).
pub fn check_float(v: &mut Validator, at: &Loc, value: &PyValue, spec: NumSpec) -> Option<f64> {
    let PyValue::Float(f) = lax(v, at, &Ty::Float, value)? else {
        return None;
    };
    bounds(v, at, f, spec).then_some(f)
}

/// An `int` field: its decimal text.
pub fn check_int(v: &mut Validator, at: &Loc, value: &PyValue, spec: NumSpec) -> Option<String> {
    // pydantic-core strips a fractional part of zeros only when there is
    // one: `"5.0"` is 5, `"5."` an `int_parsing` error (the shared engine
    // takes both).
    if let PyValue::Str(s) = value {
        if s.trim().ends_with('.') {
            v.push(
                "int_parsing",
                at.clone(),
                "Input should be a valid integer, unable to parse string as an integer",
            );
            return None;
        }
    }
    let PyValue::Int(i) = lax(v, at, &Ty::Int, value)? else {
        return None;
    };
    bounds(v, at, int_value(&i), spec).then_some(i)
}

/// A `bool` field.
pub fn check_bool(v: &mut Validator, at: &Loc, value: &PyValue) -> Option<bool> {
    match lax(v, at, &Ty::Bool, value)? {
        PyValue::Bool(b) => Some(b),
        _ => None,
    }
}

/// A `Literal[…]` of strings.
pub fn check_literal(
    v: &mut Validator,
    at: &Loc,
    value: &PyValue,
    allowed: &[&str],
) -> Option<String> {
    match value {
        PyValue::Str(s) if allowed.contains(&s.as_str()) => Some(s.clone()),
        _ => {
            let quoted: Vec<String> = allowed.iter().map(|a| format!("'{a}'")).collect();
            let expected = match quoted.split_last() {
                Some((last, [])) => last.clone(),
                Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
                None => String::new(),
            };
            v.push(
                "literal_error",
                at.clone(),
                format!("Input should be {expected}"),
            );
            None
        }
    }
}

/// A `List[str]` field with `min_length`.
pub fn check_str_list(
    v: &mut Validator,
    at: &Loc,
    value: &PyValue,
    min: Option<usize>,
) -> Option<Vec<String>> {
    let PyValue::List(items) = lax(v, at, &Ty::List(&Ty::Str), value)? else {
        return None;
    };
    if let Some(min) = min.filter(|m| items.len() < *m) {
        v.push(
            "too_short",
            at.clone(),
            format!(
                "List should have at least {min} item{} after validation, not {}",
                if min == 1 { "" } else { "s" },
                items.len()
            ),
        );
        return None;
    }
    Some(
        items
            .into_iter()
            .filter_map(|i| match i {
                PyValue::Str(s) => Some(s),
                _ => None,
            })
            .collect(),
    )
}

// --- the query -------------------------------------------------------------------------

fn query_value(q: &QueryPairs, name: &str) -> Option<PyValue> {
    q.get(name).map(|s| PyValue::Str(s.to_string()))
}

/// `Optional[str] = Query(None, …)`.
pub fn q_opt_str(q: &QueryPairs, v: &mut Validator, name: &str, spec: StrSpec) -> Option<String> {
    let value = query_value(q, name)?;
    check_str(v, &loc("query", name), &value, spec)
}

/// `str = Query(default, …)`.
pub fn q_str_or(
    q: &QueryPairs,
    v: &mut Validator,
    name: &str,
    spec: StrSpec,
    default: &str,
) -> String {
    match query_value(q, name) {
        None => default.to_string(),
        Some(value) => check_str(v, &loc("query", name), &value, spec).unwrap_or_default(),
    }
}

/// `str = Query(..., …)`.
pub fn q_req_str(q: &QueryPairs, v: &mut Validator, name: &str, spec: StrSpec) -> String {
    match query_value(q, name) {
        None => {
            v.missing(loc("query", name));
            String::new()
        }
        Some(value) => check_str(v, &loc("query", name), &value, spec).unwrap_or_default(),
    }
}

/// `float = Query(default, …)`.
pub fn q_float_or(
    q: &QueryPairs,
    v: &mut Validator,
    name: &str,
    spec: NumSpec,
    default: f64,
) -> f64 {
    match query_value(q, name) {
        None => default,
        Some(value) => check_float(v, &loc("query", name), &value, spec).unwrap_or(default),
    }
}

/// `int = Query(default, …)`: the decimal text.
pub fn q_int_or(
    q: &QueryPairs,
    v: &mut Validator,
    name: &str,
    spec: NumSpec,
    default: i64,
) -> String {
    match query_value(q, name) {
        None => default.to_string(),
        Some(value) => {
            check_int(v, &loc("query", name), &value, spec).unwrap_or_else(|| default.to_string())
        }
    }
}

/// `bool = Query(default)`.
pub fn q_bool_or(q: &QueryPairs, v: &mut Validator, name: &str, default: bool) -> bool {
    match query_value(q, name) {
        None => default,
        Some(value) => check_bool(v, &loc("query", name), &value).unwrap_or(default),
    }
}

/// An `int` path parameter: the decimal text.
pub fn path_int(v: &mut Validator, name: &str, raw: &str) -> String {
    check_int(
        v,
        &loc("path", name),
        &PyValue::Str(raw.to_string()),
        NumSpec::ANY,
    )
    .unwrap_or_default()
}

// --- the body --------------------------------------------------------------------------

/// One body field: `None` when the key is absent.
pub fn field(obj: &Map<String, Value>, name: &str) -> Option<PyValue> {
    obj.get(name).map(from_json)
}

/// A required `str` field.
pub fn b_req_str(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
    spec: StrSpec,
) -> PyValue {
    let l = child(at, name);
    match field(obj, name) {
        None => {
            v.missing(l);
            PyValue::None
        }
        Some(value) => check_str(v, &l, &value, spec).map_or(PyValue::None, PyValue::Str),
    }
}

/// An `Optional[str] = None` field.
pub fn b_opt_str(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
    spec: StrSpec,
) -> PyValue {
    match field(obj, name) {
        None | Some(PyValue::None) => PyValue::None,
        Some(value) => {
            check_str(v, &child(at, name), &value, spec).map_or(PyValue::None, PyValue::Str)
        }
    }
}

/// A required `float` field.
pub fn b_req_float(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
    spec: NumSpec,
) -> PyValue {
    let l = child(at, name);
    match field(obj, name) {
        None => {
            v.missing(l);
            PyValue::None
        }
        Some(value) => check_float(v, &l, &value, spec).map_or(PyValue::None, PyValue::Float),
    }
}

/// A `float = default` field (`default` is the dumped default, unvalidated
/// as Pydantic leaves it: `Field(1, …)` dumps `1`).
pub fn b_float_or(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
    spec: NumSpec,
    default: PyValue,
) -> PyValue {
    match field(obj, name) {
        None => default,
        Some(value) => {
            check_float(v, &child(at, name), &value, spec).map_or(PyValue::None, PyValue::Float)
        }
    }
}

/// An `Optional[float] = None` field.
pub fn b_opt_float(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
    spec: NumSpec,
) -> PyValue {
    match field(obj, name) {
        None | Some(PyValue::None) => PyValue::None,
        Some(value) => {
            check_float(v, &child(at, name), &value, spec).map_or(PyValue::None, PyValue::Float)
        }
    }
}

/// An `int = default` field.
pub fn b_int_or(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
    spec: NumSpec,
    default: i64,
) -> PyValue {
    match field(obj, name) {
        None => PyValue::Int(default.to_string()),
        Some(value) => {
            check_int(v, &child(at, name), &value, spec).map_or(PyValue::None, PyValue::Int)
        }
    }
}

/// A `bool = default` field.
pub fn b_bool_or(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
    default: bool,
) -> PyValue {
    match field(obj, name) {
        None => PyValue::Bool(default),
        Some(value) => check_bool(v, &child(at, name), &value).map_or(PyValue::None, PyValue::Bool),
    }
}

/// An `Optional[bool] = None` field.
pub fn b_opt_bool(v: &mut Validator, obj: &Map<String, Value>, at: &Loc, name: &str) -> PyValue {
    match field(obj, name) {
        None | Some(PyValue::None) => PyValue::None,
        Some(value) => check_bool(v, &child(at, name), &value).map_or(PyValue::None, PyValue::Bool),
    }
}

/// A required `List[str]` field with `min_length`.
pub fn b_req_str_list(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
    min: Option<usize>,
) -> PyValue {
    let l = child(at, name);
    match field(obj, name) {
        None => {
            v.missing(l);
            PyValue::None
        }
        Some(value) => check_str_list(v, &l, &value, min).map_or(PyValue::None, |items| {
            PyValue::List(items.into_iter().map(PyValue::Str).collect())
        }),
    }
}

/// An `Optional[List[str]] = None` field.
pub fn b_opt_str_list(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
) -> PyValue {
    match field(obj, name) {
        None | Some(PyValue::None) => PyValue::None,
        Some(value) => check_str_list(v, &child(at, name), &value, None)
            .map_or(PyValue::None, |items| {
                PyValue::List(items.into_iter().map(PyValue::Str).collect())
            }),
    }
}

/// A required `Literal[…]` field.
pub fn b_req_literal(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
    allowed: &[&str],
) -> PyValue {
    let l = child(at, name);
    match field(obj, name) {
        None => {
            v.missing(l);
            PyValue::None
        }
        Some(value) => check_literal(v, &l, &value, allowed).map_or(PyValue::None, PyValue::Str),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(v: &Validator) -> Vec<String> {
        v.errors().iter().map(|e| e.kind.clone()).collect()
    }

    #[test]
    fn numbers_check_le_before_ge_and_nan_fails() {
        let mut v = Validator::new();
        let at = loc("body", "days");
        let spec = NumSpec {
            ge: None,
            gt: Some(0.0),
            le: Some(7.0),
        };
        assert_eq!(
            check_float(&mut v, &at, &PyValue::Float(f64::NAN), spec),
            None
        );
        assert_eq!(
            check_float(&mut v, &at, &PyValue::Int("-1".into()), spec),
            None
        );
        assert_eq!(
            check_float(&mut v, &at, &PyValue::Str("inf".into()), spec),
            None
        );
        assert_eq!(
            check_float(&mut v, &at, &PyValue::Str(" 1.5 ".into()), spec),
            Some(1.5)
        );
        assert_eq!(
            kinds(&v),
            ["less_than_equal", "greater_than", "less_than_equal"]
        );
        let mut v = Validator::new();
        assert_eq!(
            check_int(
                &mut v,
                &at,
                &PyValue::Str("99999999999999999999999".into()),
                NumSpec::range(1.0, 500.0)
            ),
            None
        );
        assert_eq!(
            check_int(&mut v, &at, &PyValue::Str("5.0".into()), NumSpec::ANY).as_deref(),
            Some("5")
        );
        assert_eq!(kinds(&v), ["less_than_equal"]);
    }

    #[test]
    fn strings_check_length_then_pattern() {
        let mut v = Validator::new();
        let at = loc("query", "status");
        let spec = StrSpec::pattern("^(open|closed)$");
        assert_eq!(
            check_str(&mut v, &at, &PyValue::Str("open".into()), spec).as_deref(),
            Some("open")
        );
        assert_eq!(
            check_str(&mut v, &at, &PyValue::Str("open\n".into()), spec),
            None
        );
        assert_eq!(
            check_str(&mut v, &at, &PyValue::Int("1".into()), spec),
            None
        );
        assert_eq!(kinds(&v), ["string_pattern_mismatch", "string_type"]);
        let mut v = Validator::new();
        assert_eq!(
            check_bool(&mut v, &at, &PyValue::Str(" true".into())),
            None,
            "pydantic does not strip a bool"
        );
        assert_eq!(
            check_bool(&mut v, &at, &PyValue::Str("YES".into())),
            Some(true)
        );
        assert_eq!(kinds(&v), ["bool_parsing"]);
    }

    #[test]
    fn lists_check_items_then_length() {
        let mut v = Validator::new();
        let at = loc("body", "rule_ids");
        assert_eq!(
            check_str_list(&mut v, &at, &PyValue::List(vec![]), Some(1)),
            None
        );
        assert_eq!(
            check_str_list(
                &mut v,
                &at,
                &PyValue::List(vec![PyValue::Int("1".into())]),
                Some(1)
            ),
            None
        );
        assert_eq!(kinds(&v), ["too_short", "string_type"]);
        assert_eq!(
            v.errors()[1].loc,
            vec![
                LocPart::Key("body".into()),
                LocPart::Key("rule_ids".into()),
                LocPart::Index(0)
            ]
        );
    }
}
