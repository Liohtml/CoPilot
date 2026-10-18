//! `intel_vectors.json` (`scripts/gen-intel-connectors-vectors.py`): the
//! pagination walk, the GraphQL flattening and its models, the errors line,
//! the batch request's validation, the platform URL and the analyzers' data
//! types, against what the Python functions return or raise.

use std::cell::RefCell;

use copilot_auth::pyvalue::{PyValue, loads};
use copilot_upstream::json::pydantic_json;
use copilot_upstream::model::Loc;
use copilot_upstream::py::PyExc;

use crate::cortex::schema::is_valid_datatype;
use crate::opencti::schema::batch_values;
use crate::opencti::services::{parse_entity, parse_indicator, parse_observable};
use crate::opencti::transport::{Envelope, format_graphql_errors, resolve_platform_url, walk};

fn doc() -> PyValue {
    loads(include_str!("intel_vectors.json")).unwrap()
}

fn list<'a>(v: &'a PyValue, key: &str) -> &'a [PyValue] {
    match v.get(key) {
        Some(PyValue::List(items)) => items,
        other => panic!("{key}: {other:?}"),
    }
}

fn text(v: &PyValue, key: &str) -> String {
    v.get(key)
        .and_then(PyValue::as_str)
        .unwrap_or_default()
        .to_string()
}

/// `(class, text)` of a Python exception the vectors recorded.
fn python_error(v: &PyValue) -> Option<(String, String)> {
    v.get("error").map(|e| (text(e, "class"), text(e, "text")))
}

fn rust_error(e: &PyExc) -> (String, String) {
    let class = match e {
        PyExc::KeyError(_) => "KeyError",
        PyExc::TypeError(_) => "TypeError",
        PyExc::AttributeError(_) => "AttributeError",
        PyExc::IndexError(_) => "IndexError",
        PyExc::ValueError(_) => "ValueError",
        PyExc::Validation(_) => "ValidationError",
        PyExc::JsonDecode(_) => "JSONDecodeError",
        PyExc::Http(..) => "HTTPException",
        PyExc::Other(class, _) => class,
    };
    (class.to_string(), e.text())
}

fn envelope(page: &PyValue) -> Envelope {
    Envelope {
        success: page.get("success").is_some_and(PyValue::truthy),
        message: text(page, "message"),
        data: page.get("data").cloned().unwrap_or(PyValue::None),
        errors: page.get("errors").cloned().unwrap_or(PyValue::None),
    }
}

#[test]
fn pagination_walks_like_python() {
    let doc = doc();
    let cases = list(&doc, "paginate");
    assert!(cases.len() >= 15);
    for case in cases {
        let name = text(case, "name");
        let pages: RefCell<Vec<Envelope>> =
            RefCell::new(list(case, "pages").iter().map(envelope).collect());
        let asked: RefCell<Vec<PyValue>> = RefCell::new(Vec::new());
        let path: Vec<String> = list(case, "path").iter().map(PyValue::py_str).collect();
        let path: Vec<&str> = path.iter().map(String::as_str).collect();
        let page_size = case
            .get("page_size")
            .and_then(PyValue::to_int)
            .map_or(100, |n| i64::try_from(n).unwrap());
        let max_items = case
            .get("max_items")
            .and_then(PyValue::to_int)
            .map(|n| i64::try_from(n).unwrap());
        let variables = case.get("variables").cloned();
        let post = |vars: PyValue| {
            asked.borrow_mut().push(vars);
            let page = pages.borrow_mut().remove(0);
            async move { Ok(page) }
        };
        let got = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(walk(post, &path, variables, page_size, max_items));
        assert_eq!(
            PyValue::List(asked.borrow().clone()).py_repr(),
            PyValue::List(list(case, "asked").to_vec()).py_repr(),
            "{name}: pages asked"
        );
        match (got, python_error(case)) {
            (Ok(result), None) => assert_eq!(
                result.py_repr(),
                case.get("result").unwrap().py_repr(),
                "{name}"
            ),
            (Err(e), Some(want)) => assert_eq!(rust_error(&e), want, "{name}"),
            (got, want) => panic!("{name}: {got:?} vs {want:?}"),
        }
    }
}

#[test]
fn nodes_flatten_like_python() {
    let doc = doc();
    let cases = list(&doc, "parse");
    assert!(cases.len() >= 20);
    for case in cases {
        let node = case.get("node").unwrap();
        let got = match text(case, "kind").as_str() {
            "indicator" => parse_indicator(node),
            "observable" => parse_observable(node),
            "entity" => parse_entity(node),
            other => panic!("{other}"),
        };
        match (got, python_error(case)) {
            (Ok(dump), None) => assert_eq!(
                pydantic_json(&dump),
                text(case, "json"),
                "{}",
                node.py_repr()
            ),
            (Err(e), Some(want)) => assert_eq!(rust_error(&e), want, "{}", node.py_repr()),
            (got, want) => panic!("{}: {got:?} vs {want:?}", node.py_repr()),
        }
    }
}

#[test]
fn graphql_errors_flatten_like_python() {
    let doc = doc();
    for case in list(&doc, "graphql_errors") {
        let errors = case.get("errors").unwrap();
        match (format_graphql_errors(errors), python_error(case)) {
            (Ok(line), None) => assert_eq!(line, text(case, "text"), "{}", errors.py_repr()),
            (Err(e), Some(want)) => assert_eq!(rust_error(&e), want, "{}", errors.py_repr()),
            (got, want) => panic!("{}: {got:?} vs {want:?}", errors.py_repr()),
        }
    }
}

#[test]
fn batch_requests_validate_like_pydantic() {
    let doc = doc();
    for case in list(&doc, "batch") {
        let body = case.get("body").unwrap();
        match (batch_values(body), case.get("values"), case.get("errors")) {
            (Ok(values), Some(want), None) => assert_eq!(
                PyValue::List(values.into_iter().map(PyValue::Str).collect()).py_repr(),
                want.py_repr(),
                "{}",
                body.py_repr()
            ),
            (Err(errors), None, Some(PyValue::List(want))) => {
                let got: Vec<String> = errors
                    .iter()
                    .map(|e| {
                        let loc: Vec<String> = e
                            .loc
                            .iter()
                            .map(|l| match l {
                                Loc::Key(k) => format!("'{k}'"),
                                Loc::Index(i) => i.to_string(),
                            })
                            .collect();
                        format!("{} [{}] {}", e.kind, loc.join(", "), e.msg)
                    })
                    .collect();
                let want: Vec<String> = want
                    .iter()
                    .map(|e| {
                        let loc = match e.get("loc") {
                            Some(PyValue::List(items)) => items
                                .iter()
                                .map(PyValue::py_repr)
                                .collect::<Vec<_>>()
                                .join(", "),
                            _ => String::new(),
                        };
                        format!("{} [{loc}] {}", text(e, "type"), text(e, "msg"))
                    })
                    .collect();
                assert_eq!(got, want, "{}", body.py_repr());
            }
            (got, values, errors) => {
                panic!("{}: {got:?} vs {values:?} / {errors:?}", body.py_repr())
            }
        }
    }
}

#[test]
fn platform_urls_resolve_like_python() {
    let doc = doc();
    for case in list(&doc, "platform_urls") {
        let url = text(case, "connector_url");
        let public = case.get("public_url").and_then(PyValue::as_str);
        let got = resolve_platform_url(&url, public);
        match (got, case.get("url"), case.get("error")) {
            (Ok(u), Some(want), None) => assert_eq!(u, want.py_str(), "{url} {public:?}"),
            (Err(PyExc::ValueError(e)), None, Some(want)) => assert_eq!(e, want.py_str()),
            (got, url_, error) => panic!("{public:?}: {got:?} vs {url_:?} / {error:?}"),
        }
    }
}

#[test]
fn data_types_like_python() {
    let doc = doc();
    for case in list(&doc, "datatypes") {
        let value = text(case, "value");
        let want = case.get("type").and_then(PyValue::as_str);
        assert_eq!(is_valid_datatype(&value), want, "{value:?}");
    }
}
