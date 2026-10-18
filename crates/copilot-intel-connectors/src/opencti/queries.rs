//! The GraphQL documents CoPilot sends to OpenCTI — `services/queries.py`
//! and `utils/universal.py:VERIFY_QUERY`, character for character (a test
//! reads the Python sources and compares).
//!
//! A document must define exactly the fragments it spreads (OpenCTI's
//! `NoUnusedFragments`), so each query appends only the ones it uses.

macro_rules! core_meta_fragment {
    () => {
        r#"
fragment CoreMeta on StixCoreObject {
    id
    standard_id
    entity_type
    created_at
    updated_at
    createdBy { name }
    objectLabel { value color }
    objectMarking { definition }
}
"#
    };
}

macro_rules! indicator_fragment {
    () => {
        r#"
fragment IndicatorFields on Indicator {
    ...CoreMeta
    name
    description
    pattern
    pattern_type
    x_opencti_main_observable_type
    x_opencti_score
    confidence
    valid_from
    valid_until
    revoked
}
"#
    };
}

/// `CORE_META_FRAGMENT`: the fields every STIX core object carries.
pub const CORE_META_FRAGMENT: &str = core_meta_fragment!();

/// `INDICATOR_FRAGMENT` (spreads `CoreMeta`).
pub const INDICATOR_FRAGMENT: &str = indicator_fragment!();

/// `ABOUT_QUERY`: the platform's version and dependencies, and the account.
pub const ABOUT_QUERY: &str = r#"
query CoPilotAbout {
    about {
        version
        dependencies { name version }
    }
    me { name user_email }
}
"#;

/// `OBSERVABLE_LOOKUP_KEYS`: `value` and every hash, OR-ed in one filter item.
pub const OBSERVABLE_LOOKUP_KEYS: [&str; 5] = [
    "value",
    "hashes.MD5",
    "hashes.SHA-1",
    "hashes.SHA-256",
    "hashes.SHA-512",
];

/// `OBSERVABLE_LOOKUP_QUERY`.
pub const OBSERVABLE_LOOKUP_QUERY: &str = concat!(
    r#"
query CoPilotObservableLookup($filters: FilterGroup, $first: Int, $indicators: Int, $reports: Int) {
    stixCyberObservables(first: $first, filters: $filters) {
        pageInfo { globalCount }
        edges {
            node {
                ...CoreMeta
                observable_value
                x_opencti_description
                x_opencti_score
                ... on StixFile { name hashes { algorithm hash } }
                indicators(first: $indicators) {
                    pageInfo { globalCount }
                    edges { node { ...IndicatorFields } }
                }
                reports(first: $reports) {
                    pageInfo { globalCount }
                    edges { node { id name published } }
                }
            }
        }
    }
}
"#,
    core_meta_fragment!(),
    indicator_fragment!()
);

/// `INDICATORS_QUERY`.
pub const INDICATORS_QUERY: &str = concat!(
    r#"
query CoPilotIndicators($search: String, $filters: FilterGroup, $first: Int, $after: ID) {
    indicators(search: $search, filters: $filters, first: $first, after: $after, orderBy: created_at, orderMode: desc) {
        pageInfo { globalCount hasNextPage endCursor }
        edges { node { ...IndicatorFields } }
    }
}
"#,
    core_meta_fragment!(),
    indicator_fragment!()
);

/// `ENTITY_QUERY`.
pub const ENTITY_QUERY: &str = concat!(
    r#"
query CoPilotEntity($id: String!) {
    stixCoreObject(id: $id) {
        ...CoreMeta
        parent_types
        representative { main secondary }
        externalReferences(first: 25) {
            edges { node { source_name url external_id description } }
        }
        ... on StixDomainObject { confidence }
        ... on StixCyberObservable { x_opencti_score }
        ... on Indicator { x_opencti_score }
    }
}
"#,
    core_meta_fragment!()
);

/// `VERIFY_QUERY` (`utils/universal.py`): what the connector check asks.
pub const VERIFY_QUERY: &str = "query CoPilotVerify { about { version } me { name user_email } }";

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::Path;

    fn read(rel: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../backend/app/connectors/opencti")
            .join(rel);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// The string constants of a module written as `NAME = """…"""`,
    /// `NAME = "…"` or `NAME = ("""…""" + OTHER + …)` (no escapes).
    fn python_strings(source: &str) -> HashMap<String, String> {
        let mut out: HashMap<String, String> = HashMap::new();
        let mut pos = 0;
        while pos < source.len() {
            let line_end = source[pos..].find('\n').map_or(source.len(), |i| pos + i);
            let line = &source[pos..line_end];
            let name: String = line
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || *c == '_' || c.is_ascii_digit())
                .collect();
            let Some(expr) = (!name.is_empty())
                .then(|| line.strip_prefix(&name))
                .flatten()
                .and_then(|l| l.strip_prefix(" = "))
            else {
                pos = line_end + 1;
                continue;
            };
            let start = line_end - line.len() + name.len() + 3;
            let mut i = start;
            let paren = expr.starts_with('(');
            if paren {
                i += 1;
            }
            let mut value = String::new();
            let mut matched = false;
            loop {
                let rest = &source[i..];
                let trimmed = rest.trim_start_matches([' ', '\n']);
                i += rest.len() - trimmed.len();
                if let Some(body) = trimmed.strip_prefix("\"\"\"") {
                    let end = body.find("\"\"\"").expect("closing quotes");
                    value.push_str(&body[..end]);
                    i += 3 + end + 3;
                    matched = true;
                } else if let Some(body) = trimmed.strip_prefix('"') {
                    let end = body.find('"').expect("closing quote");
                    value.push_str(&body[..end]);
                    i += 1 + end + 1;
                    matched = true;
                } else if let Some(r) = trimmed.strip_prefix('+') {
                    i += trimmed.len() - r.len();
                    continue;
                } else if paren && trimmed.starts_with(')') {
                    i += 1;
                    break;
                } else {
                    let ident: String = trimmed
                        .chars()
                        .take_while(|c| c.is_ascii_uppercase() || *c == '_')
                        .collect();
                    match out.get(&ident) {
                        Some(v) if !ident.is_empty() => {
                            value.push_str(&v.clone());
                            i += ident.len();
                            matched = true;
                        }
                        _ => break,
                    }
                }
                if !paren {
                    break;
                }
            }
            if matched {
                out.insert(name, value);
            }
            pos = source[i..].find('\n').map_or(source.len(), |j| i + j + 1);
        }
        out
    }

    #[test]
    fn documents_are_the_python_text() {
        let queries = python_strings(&read("services/queries.py"));
        for (name, rust) in [
            ("CORE_META_FRAGMENT", CORE_META_FRAGMENT),
            ("INDICATOR_FRAGMENT", INDICATOR_FRAGMENT),
            ("ABOUT_QUERY", ABOUT_QUERY),
            ("OBSERVABLE_LOOKUP_QUERY", OBSERVABLE_LOOKUP_QUERY),
            ("INDICATORS_QUERY", INDICATORS_QUERY),
            ("ENTITY_QUERY", ENTITY_QUERY),
        ] {
            assert_eq!(queries.get(name).map(String::as_str), Some(rust), "{name}");
        }
        let universal = python_strings(&read("utils/universal.py"));
        assert_eq!(
            universal.get("VERIFY_QUERY").map(String::as_str),
            Some(VERIFY_QUERY)
        );
        let keys = read("services/queries.py");
        let line = keys
            .lines()
            .find(|l| l.starts_with("OBSERVABLE_LOOKUP_KEYS = "))
            .expect("OBSERVABLE_LOOKUP_KEYS");
        let listed: Vec<String> = OBSERVABLE_LOOKUP_KEYS
            .iter()
            .map(|k| format!("\"{k}\""))
            .collect();
        assert_eq!(
            line,
            format!("OBSERVABLE_LOOKUP_KEYS = [{}]", listed.join(", "))
        );
    }

    #[test]
    fn every_document_defines_exactly_the_fragments_it_spreads() {
        for doc in [
            ABOUT_QUERY,
            OBSERVABLE_LOOKUP_QUERY,
            INDICATORS_QUERY,
            ENTITY_QUERY,
            VERIFY_QUERY,
        ] {
            for fragment in ["CoreMeta", "IndicatorFields"] {
                let spread = doc.contains(&format!("...{fragment}"));
                let defined = doc.contains(&format!("fragment {fragment} on"));
                assert_eq!(spread, defined, "{fragment} in {doc}");
            }
        }
    }
}
