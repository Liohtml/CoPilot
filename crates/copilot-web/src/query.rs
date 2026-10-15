//! Query-string helpers with FastAPI's semantics.

use axum::extract::FromRequestParts;
use http::request::Parts;
use serde_json::Value;

use crate::error::ApiError;
use crate::validate::{IntRules, StrRules, Validator, loc};

/// All query pairs, in order (repeated keys kept).
#[derive(Debug, Clone, Default)]
pub struct QueryPairs(pub Vec<(String, String)>);

impl QueryPairs {
    /// Parse a raw query string.
    pub fn parse(raw: Option<&str>) -> Self {
        Self(
            raw.map(|q| {
                url::form_urlencoded::parse(q.as_bytes())
                    .into_owned()
                    .collect()
            })
            .unwrap_or_default(),
        )
    }

    /// Last value for `key` (Starlette's `query_params[key]`).
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Every value for `key`.
    pub fn get_all(&self, key: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// `Optional[str] = Query(None)` with constraints.
    pub fn opt_str(&self, v: &mut Validator, name: &str, rules: StrRules) -> Option<String> {
        let raw = self.get(name)?;
        let mut map = serde_json::Map::new();
        map.insert(name.into(), Value::String(raw.into()));
        v.opt_str(&map, &query_loc(), name, rules)
    }

    /// `int = Query(default, ge=…, le=…)`.
    pub fn int_or(&self, v: &mut Validator, name: &str, rules: IntRules, default: i64) -> i64 {
        match self.get(name) {
            None => default,
            Some(raw) => v
                .check_int(&loc("query", name), &Value::String(raw.into()), rules)
                .unwrap_or(default),
        }
    }

    /// `customer_codes_query`: `?customer_codes=a&customer_codes=b`, then
    /// `customer_codes[]=`, then the legacy `?customer_code=`; `None` when
    /// none is given.
    pub fn customer_codes(&self) -> Option<Vec<String>> {
        let repeated = self.get_all("customer_codes");
        if !repeated.is_empty() {
            return Some(repeated);
        }
        let bracket = self.get_all("customer_codes[]");
        if !bracket.is_empty() {
            return Some(bracket);
        }
        self.get("customer_code")
            .filter(|c| !c.is_empty())
            .map(|c| vec![c.to_string()])
    }
}

fn query_loc() -> crate::validate::Loc {
    vec![crate::validate::LocPart::Key("query".into())]
}

impl<S: Send + Sync> FromRequestParts<S> for QueryPairs {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::parse(parts.uri.query()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn customer_codes_fallbacks() {
        let q = QueryPairs::parse(Some("customer_codes=a&customer_codes=b&customer_code=z"));
        assert_eq!(q.customer_codes(), Some(vec!["a".into(), "b".into()]));
        let q = QueryPairs::parse(Some("customer_codes%5B%5D=x"));
        assert_eq!(q.customer_codes(), Some(vec!["x".into()]));
        let q = QueryPairs::parse(Some("customer_code=z"));
        assert_eq!(q.customer_codes(), Some(vec!["z".into()]));
        assert_eq!(
            QueryPairs::parse(Some("customer_code=")).customer_codes(),
            None
        );
        assert_eq!(QueryPairs::parse(None).customer_codes(), None);
    }

    #[test]
    fn int_query_bounds() {
        let q = QueryPairs::parse(Some("limit=99&bad=x"));
        let mut v = Validator::new();
        assert_eq!(q.int_or(&mut v, "missing", IntRules::default(), 5), 5);
        q.int_or(
            &mut v,
            "limit",
            IntRules {
                ge: Some(1),
                le: Some(25),
            },
            5,
        );
        q.int_or(&mut v, "bad", IntRules::default(), 5);
        assert_eq!(v.errors().len(), 2);
        assert_eq!(v.errors()[0].kind, "less_than_equal");
    }
}
