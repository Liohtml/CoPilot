//! Query parameters these routes declare beyond what `QueryPairs` reads.

use serde_json::{Map, Value};

use copilot_web::QueryPairs;
use copilot_web::validate::{LocPart, Validator};

fn query_loc() -> Vec<LocPart> {
    vec![LocPart::Key("query".into())]
}

/// `name: bool = Query(default)`: Pydantic's lax string → bool, the last
/// value of a repeated key.
pub fn bool_or(q: &QueryPairs, v: &mut Validator, name: &str, default: bool) -> bool {
    let Some(raw) = q.get(name) else {
        return default;
    };
    let mut map = Map::new();
    map.insert(name.into(), Value::String(raw.into()));
    v.bool_or(&map, &query_loc(), name, default)
}

/// `name: Optional[List[str]] = Query(None)`: every value, `None` without
/// one.
pub fn opt_list(q: &QueryPairs, name: &str) -> Option<Vec<String>> {
    let all = q.get_all(name);
    (!all.is_empty()).then_some(all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn booleans_follow_pydantic() {
        let q = QueryPairs::parse(Some("a=yes&b=0&c=maybe"));
        let mut v = Validator::new();
        assert!(bool_or(&q, &mut v, "a", false));
        assert!(!bool_or(&q, &mut v, "b", true));
        assert!(bool_or(&q, &mut v, "missing", true));
        assert!(!v.has_errors());
        bool_or(&q, &mut v, "c", false);
        assert_eq!(v.errors()[0].kind, "bool_parsing");
    }
}
