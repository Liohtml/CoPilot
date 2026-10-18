//! cortex4py 2.1 as `utils/universal.py` and `services/analyzers.py` use it:
//! `Api(url, api_key, verify_cert=False)` over `requests` 2.33
//! (`copilot_upstream::http::PyHttp`), the two controllers' calls the routes
//! make, and the library's model objects.
//!
//! - Every call goes to `'{url}/api/' + endpoint` (the URL as stored, so a
//!   trailing `/` makes `//api/`), `Authorization: Bearer <key>`, and for a
//!   POST `Content-Type: application/json` with the body as `json.dumps`
//!   writes it; certificates are not verified and there is no timeout
//!   (Python waits for ever; here ten years).
//! - A failure is re-raised by `Api.__recover` as one of its own exceptions,
//!   whose texts are all the routes ever show: an HTTP error by status
//!   (`Resource not found`, `Authentication error`, `Authorization error`,
//!   `Invalid input exception`), a connection failure `Cortex service is
//!   unavailable`, any other `requests` failure `Cortex request exception`,
//!   anything else `Unexpected exception`.
//! - An answer becomes `Analyzer`/`Job` objects as `_wrap` builds them: a
//!   dict is one object (its `_`-prefixed keys dropped, `None` the class's
//!   defaults), a list a list of them, anything else stays as it is; reading
//!   an attribute such an object lacks is the `AttributeError` CPython
//!   raises, and so on for every odd answer ([`Wrapped`]).

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_db::connectors::ConnectorRow;
use copilot_upstream::http::{PyHttp, PyRequest, PyResponse};
use copilot_upstream::py::{PyExc, PyResult, type_name};
use http::Method;

use crate::py::{dict, s};

/// The connector row's name.
pub const CONNECTOR: &str = "Cortex";

/// `requests` without `timeout=`: no limit (ten years is as good as none).
pub const NO_TIMEOUT: Duration = Duration::from_secs(10 * 365 * 24 * 3600);

/// `Api.__recover(exception)`: the library's own exception for a failure.
fn recover(e: PyExc) -> PyExc {
    let class = match &e {
        PyExc::Other(class, _) => *class,
        PyExc::ValueError(_) => "ValueError",
        _ => "",
    };
    let (name, text) = match class {
        "ConnectionError" | "ConnectTimeout" | "ProxyError" | "SSLError" => {
            ("ServiceUnavailableError", "Cortex service is unavailable")
        }
        "ReadTimeout"
        | "Timeout"
        | "InvalidSchema"
        | "MissingSchema"
        | "InvalidURL"
        | "InvalidHeader"
        | "TooManyRedirects"
        | "ContentDecodingError"
        | "ChunkedEncodingError"
        | "InvalidJSONError"
        | "RequestException" => ("ServerError", "Cortex request exception"),
        _ => ("CortexError", "Unexpected exception"),
    };
    PyExc::Other(name, text.into())
}

/// `raise_for_status()`'s `HTTPError`, recovered by status.
fn recover_status(status: u16) -> PyExc {
    let (name, text) = match status {
        404 => ("NotFoundError", "Resource not found"),
        401 => ("AuthenticationError", "Authentication error"),
        403 => ("AuthorizationError", "Authorization error"),
        _ => ("InvalidInputError", "Invalid input exception"),
    };
    PyExc::Other(name, text.into())
}

/// `cortex4py.api.Api`.
#[derive(Debug, Clone)]
pub struct Api {
    http: PyHttp,
    url: String,
    api_key: String,
}

impl Api {
    /// `Api(url, api_key, verify_cert=False)`: a `TypeError` unless both are
    /// strings (a connector row without an API key).
    pub fn new(http: &PyHttp, row: &ConnectorRow) -> PyResult<Self> {
        let Some(key) = row.connector_api_key.clone() else {
            return Err(PyExc::TypeError(
                "URL and API key are required and must be of type string.".into(),
            ));
        };
        Ok(Self {
            http: http.clone(),
            url: row.connector_url.clone(),
            api_key: key,
        })
    }

    fn endpoint(&self, endpoint: &str) -> String {
        format!("{}/api/{endpoint}", self.url)
    }

    async fn send(&self, req: PyRequest) -> PyResult<PyResponse> {
        let resp = self.http.send(req).await.map_err(recover)?;
        if resp.status() >= 400 {
            return Err(recover_status(resp.status()));
        }
        Ok(resp)
    }

    /// `do_get(endpoint)`.
    pub async fn do_get(&self, endpoint: &str) -> PyResult<PyResponse> {
        let req = PyRequest::new(Method::GET, self.endpoint(endpoint))
            .header("Authorization", format!("Bearer {}", self.api_key));
        self.send(req).await
    }

    /// `do_post(endpoint, data, params)`.
    pub async fn do_post(
        &self,
        endpoint: &str,
        data: PyValue,
        params: Vec<(String, String)>,
    ) -> PyResult<PyResponse> {
        let req = PyRequest::new(Method::POST, self.endpoint(endpoint))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .params(params)
            .json(Some(data));
        self.send(req).await
    }

    /// `AnalyzersController.find_all({}, range="all")`.
    pub async fn find_all_analyzers(&self) -> PyResult<Wrapped> {
        let body = dict(vec![("query", PyValue::Dict(Vec::new()))]);
        let resp = self
            .do_post(
                "analyzer/_search",
                body,
                vec![("range".into(), "all".into())],
            )
            .await?;
        Wrapped::wrap(resp.json()?, Class::Analyzer)
    }

    /// `AnalyzersController.get_by_name(name)` (`_find_one_by(Eq('name',
    /// name))`).
    pub async fn analyzer_by_name(&self, name: &str) -> PyResult<Wrapped> {
        let query = dict(vec![("_field", s("name")), ("_value", s(name))]);
        let resp = self
            .do_post(
                "analyzer/_search",
                dict(vec![("query", query)]),
                vec![("range".into(), "0-1".into())],
            )
            .await?;
        let collection = resp.json()?;
        let first = match &collection {
            PyValue::List(items) => items.first().cloned().unwrap_or(PyValue::None),
            PyValue::Dict(items) if items.is_empty() => PyValue::None,
            PyValue::Dict(_) => return Err(PyExc::KeyError("0".into())),
            PyValue::Str(text) => text
                .chars()
                .next()
                .map_or(PyValue::None, |c| s(c.to_string())),
            other => {
                return Err(PyExc::TypeError(format!(
                    "object of type '{}' has no len()",
                    type_name(other)
                )));
            }
        };
        Wrapped::wrap(first, Class::Analyzer)
    }

    /// `AnalyzersController.run_by_id(analyzer_id, observable, force=1)`
    /// for a non-file observable.
    pub async fn run_by_id(
        &self,
        analyzer_id: &PyValue,
        observable: &PyValue,
    ) -> PyResult<Wrapped> {
        let get = |k: &str| observable.get(k).cloned();
        let mut post = vec![
            ("dataType", get("dataType").unwrap_or(PyValue::None)),
            ("tlp", get("tlp").unwrap_or(PyValue::Int("2".into()))),
            ("pap", get("pap").unwrap_or(PyValue::Int("2".into()))),
        ];
        for key in ["message", "parameters"] {
            if let Some(v) = get(key) {
                post.push((key, v));
            }
        }
        post.push(("data", get("data").unwrap_or(PyValue::None)));
        let resp = self
            .do_post(
                &format!("analyzer/{}/run", analyzer_id.py_str()),
                dict(post),
                vec![("force".into(), "1".into())],
            )
            .await?;
        Wrapped::wrap(resp.json()?, Class::Job)
    }

    /// `JobsController.get_by_id(job_id)`.
    pub async fn job_by_id(&self, job_id: &PyValue) -> PyResult<Wrapped> {
        let resp = self.do_get(&format!("job/{}", job_id.py_str())).await?;
        Wrapped::wrap(resp.json()?, Class::Job)
    }

    /// `JobsController.get_report(job_id)`.
    pub async fn job_report(&self, job_id: &PyValue) -> PyResult<Wrapped> {
        let resp = self
            .do_get(&format!("job/{}/report", job_id.py_str()))
            .await?;
        Wrapped::wrap(resp.json()?, Class::Job)
    }
}

/// cortex4py's model classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// `Analyzer`.
    Analyzer,
    /// `Job`.
    Job,
}

impl Class {
    fn name(self) -> &'static str {
        match self {
            Class::Analyzer => "Analyzer",
            Class::Job => "Job",
        }
    }

    /// The class's `defaults` (what `cls(None)` holds).
    fn defaults(self) -> Vec<(String, PyValue)> {
        let none = |k: &str| (k.to_string(), PyValue::None);
        match self {
            Class::Analyzer => vec![
                none("id"),
                none("name"),
                none("workerDefinitionId"),
                none("description"),
                none("version"),
                none("author"),
                none("url"),
                none("license"),
                ("dataTypeList".into(), PyValue::List(Vec::new())),
                ("configuration".into(), PyValue::Dict(Vec::new())),
                none("rate"),
                none("rateUnit"),
                none("jobCache"),
                none("maxPap"),
                none("maxTlp"),
            ],
            Class::Job => vec![
                none("id"),
                none("type"),
                none("organization"),
                none("workerId"),
                none("workerDefinitionId"),
                none("workerName"),
                none("status"),
                none("dataType"),
                ("tlp".into(), PyValue::Int("1".into())),
                none("data"),
                ("parameters".into(), PyValue::Dict(Vec::new())),
                none("message"),
                none("startDate"),
                none("endDate"),
                none("date"),
            ],
        }
    }
}

/// What `_wrap(data, cls)` returns.
#[derive(Debug, Clone, PartialEq)]
pub enum Wrapped {
    /// A model object: its class and `__dict__`.
    Object(Class, Vec<(String, PyValue)>),
    /// `list(map(cls, data))`.
    List(Vec<Wrapped>),
    /// Anything else, as it came.
    Raw(PyValue),
}

impl Wrapped {
    /// `cls(data)`: `data.items()` (`AttributeError` for anything but a
    /// dict or `None`).
    fn object(data: PyValue, class: Class) -> PyResult<Self> {
        match data {
            PyValue::None => Ok(Wrapped::Object(class, class.defaults())),
            PyValue::Dict(items) => Ok(Wrapped::Object(
                class,
                items
                    .into_iter()
                    .filter(|(k, _)| !k.starts_with('_'))
                    .collect(),
            )),
            other => Err(PyExc::AttributeError(format!(
                "'{}' object has no attribute 'items'",
                type_name(&other)
            ))),
        }
    }

    /// `AbstractController._wrap(data, cls)`.
    pub fn wrap(data: PyValue, class: Class) -> PyResult<Self> {
        match data {
            PyValue::Dict(_) => Self::object(data, class),
            PyValue::List(items) => Ok(Wrapped::List(
                items
                    .into_iter()
                    .map(|item| Self::object(item, class))
                    .collect::<PyResult<_>>()?,
            )),
            other => Ok(Wrapped::Raw(other)),
        }
    }

    fn type_label(&self) -> &'static str {
        match self {
            Wrapped::Object(class, _) => class.name(),
            Wrapped::List(_) => "list",
            Wrapped::Raw(v) => type_name(v),
        }
    }

    /// `is None`.
    pub fn is_none(&self) -> bool {
        matches!(self, Wrapped::Raw(PyValue::None))
    }

    /// `obj.<attr>` for an attribute the classes do not define.
    pub fn attr(&self, attr: &str) -> PyResult<PyValue> {
        if let Wrapped::Object(_, items) = self {
            if let Some((_, v)) = items.iter().find(|(k, _)| k == attr) {
                return Ok(v.clone());
            }
        }
        Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute '{attr}'",
            self.type_label()
        )))
    }

    /// `obj.json()`: an object's `__dict__` (unless a `json` key shadows the
    /// method: calling a value is a `TypeError`).
    pub fn json(&self) -> PyResult<PyValue> {
        match self {
            Wrapped::Object(_, items) => match items.iter().find(|(k, _)| k == "json") {
                Some((_, v)) => Err(PyExc::TypeError(format!(
                    "'{}' object is not callable",
                    type_name(v)
                ))),
                None => Ok(PyValue::Dict(items.clone())),
            },
            other => Err(PyExc::AttributeError(format!(
                "'{}' object has no attribute 'json'",
                other.type_label()
            ))),
        }
    }

    /// `for x in obj`.
    pub fn iterate(&self) -> PyResult<Vec<Wrapped>> {
        match self {
            Wrapped::List(items) => Ok(items.clone()),
            Wrapped::Raw(PyValue::Str(text)) => Ok(text
                .chars()
                .map(|c| Wrapped::Raw(s(c.to_string())))
                .collect()),
            other => Err(PyExc::TypeError(format!(
                "'{}' object is not iterable",
                other.type_label()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    fn w(json: &str, class: Class) -> PyResult<Wrapped> {
        Wrapped::wrap(loads(json).unwrap(), class)
    }

    #[test]
    fn answers_become_cortex4py_objects() {
        let one = w(r#"{"id": "a", "_secret": 1, "name": "N"}"#, Class::Analyzer).unwrap();
        assert_eq!(one.attr("name").unwrap(), s("N"));
        assert_eq!(
            one.attr("_secret").unwrap_err().text(),
            "'Analyzer' object has no attribute '_secret'"
        );
        assert_eq!(
            one.iterate().unwrap_err().text(),
            "'Analyzer' object is not iterable"
        );
        let many = w(r#"[null, {"name": "x"}]"#, Class::Analyzer).unwrap();
        let items = many.iterate().unwrap();
        assert_eq!(items[0].attr("name").unwrap(), PyValue::None);
        assert_eq!(
            w(r#"[1]"#, Class::Analyzer).unwrap_err().text(),
            "'int' object has no attribute 'items'"
        );
        assert_eq!(
            w("null", Class::Job)
                .unwrap()
                .attr("report")
                .unwrap_err()
                .text(),
            "'NoneType' object has no attribute 'report'"
        );
        assert_eq!(
            w(r#"{"json": 1}"#, Class::Job)
                .unwrap()
                .json()
                .unwrap_err()
                .text(),
            "'int' object is not callable"
        );
        assert_eq!(
            w("[]", Class::Job).unwrap().json().unwrap_err().text(),
            "'list' object has no attribute 'json'"
        );
    }

    #[test]
    fn failures_are_the_library_exceptions() {
        assert_eq!(recover_status(404).text(), "Resource not found");
        assert_eq!(recover_status(500).text(), "Invalid input exception");
        assert_eq!(
            recover(PyExc::Other("ConnectionError", "x".into())).text(),
            "Cortex service is unavailable"
        );
        assert_eq!(
            recover(PyExc::Other("InvalidSchema", "x".into())).text(),
            "Cortex request exception"
        );
    }
}
