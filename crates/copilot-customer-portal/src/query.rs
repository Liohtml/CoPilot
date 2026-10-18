//! Query parameters as Pydantic reads them (`int`, `bool` from a string),
//! for the routes of this crate.
//!
//! Pydantic's `str` → `int` trims whitespace, accepts a sign, single
//! underscores between digits and a fraction of zeros (`"1.0"`), and has no
//! upper bound; `str` → `bool` matches its words in any case, untrimmed.

use serde_json::Value;

use copilot_web::QueryPairs;
use copilot_web::validate::{Validator, loc};

use crate::branding::schema::py_bool;

/// `int` bounds.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bounds {
    /// `ge`.
    pub ge: Option<i128>,
    /// `le`.
    pub le: Option<i128>,
}

/// Pydantic's `str` → `int`; a value beyond `i128` saturates (only bounds
/// and offsets read it) — `copilot_web::query::pydantic_int`.
pub fn pyd_int(raw: &str) -> Option<i128> {
    copilot_web::query::pydantic_int(raw)
}

/// `int = Query(default, ge=…, le=…)`: the last value, or `default`.
pub fn int_or(
    v: &mut Validator,
    query: &QueryPairs,
    name: &str,
    bounds: Bounds,
    default: i128,
) -> i128 {
    let Some(raw) = query.get(name) else {
        return default;
    };
    let at = loc("query", name);
    let Some(n) = pyd_int(raw) else {
        v.push(
            "int_parsing",
            at,
            "Input should be a valid integer, unable to parse string as an integer",
        );
        return default;
    };
    if let Some(ge) = bounds.ge.filter(|ge| n < *ge) {
        v.push(
            "greater_than_equal",
            at,
            format!("Input should be greater than or equal to {ge}"),
        );
        return default;
    }
    if let Some(le) = bounds.le.filter(|le| n > *le) {
        v.push(
            "less_than_equal",
            at,
            format!("Input should be less than or equal to {le}"),
        );
        return default;
    }
    n
}

/// `bool = Query(default)`.
pub fn bool_or(v: &mut Validator, query: &QueryPairs, name: &str, default: bool) -> bool {
    let Some(raw) = query.get(name) else {
        return default;
    };
    match py_bool(&Value::String(raw.to_string())) {
        Ok(b) => b,
        Err((kind, msg)) => {
            v.push(kind, loc("query", name), msg);
            default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pydantic_int_from_text() {
        assert_eq!(pyd_int(" +1_0.000 "), Some(10));
        assert_eq!(pyd_int("\u{3000} 5"), Some(5));
        assert_eq!(pyd_int("-1.0"), Some(-1));
        assert_eq!(pyd_int("00012"), Some(12));
        for bad in [
            "1.", "1.01", ".0", "5__0", "_5", "5_", "1.0_0", "+-1", "", " ", "1e3", "1 2",
        ] {
            assert_eq!(pyd_int(bad), None, "{bad:?}");
        }
        assert_eq!(pyd_int(&"9".repeat(60)), Some(i128::MAX));
    }
}
