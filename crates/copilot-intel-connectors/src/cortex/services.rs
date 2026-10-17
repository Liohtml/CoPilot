//! Port of `services/analyzers.py` and the job half of
//! `utils/universal.py` (`run_and_wait_for_analyzer`,
//! `monitor_analyzer_job`, `retrieve_final_report`).
//!
//! Each step reads the `Cortex` row through the connector cache as Python
//! does (three reads for a run: the existence check, `run_analyzer`, and
//! `run_and_wait_for_analyzer`). A job is polled every 5 s until its status
//! is `Success`, at most 60 times (Python blocks its event loop in
//! `time.sleep(5)`; here the task sleeps); a `Failure` ends the wait with
//! the job's `errorMessage`.

use std::future::Future;
use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_db::connectors::ConnectorCache;
use copilot_upstream::http::PyHttp;
use copilot_upstream::model::construct;
use copilot_upstream::py::{PyExc, PyResult, getitem};

use super::client::{Api, CONNECTOR, Wrapped};
use super::schema;
use crate::py::{dict, s};

/// `time.sleep(5)` between two looks at a job.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// The 61st look gives up (`if timer == 60`).
pub const MAX_POLLS: u32 = 60;

fn db_error(e: copilot_db::DbError) -> PyExc {
    PyExc::Other("OperationalError", e.to_string())
}

/// `create_cortex_client("Cortex")`: `None` without a row; `Api()`'s
/// `TypeError` (no API key) is raised.
async fn client(cache: &ConnectorCache, http: &PyHttp) -> PyResult<Option<Api>> {
    match cache.get(CONNECTOR).await.map_err(db_error)? {
        None => {
            tracing::error!("No Wazuh Indexer connector found in the database");
            Ok(None)
        }
        Some(row) => Api::new(http, &row).map(Some),
    }
}

/// `init_cortex_client()` + `handle_api_initialization(api)`.
async fn initialized(cache: &ConnectorCache, http: &PyHttp) -> PyResult<Api> {
    client(cache, http).await?.ok_or_else(|| {
        tracing::error!("API initialization failed");
        PyExc::http(500, "API initialization failed")
    })
}

/// `get_analyzers()`: the names of every analyzer, as `AnalyzersResponse`.
pub async fn analyzers(cache: &ConnectorCache, http: &PyHttp) -> PyResult<PyValue> {
    let api = initialized(cache, http).await?;
    let analyzers = api.find_all_analyzers().await.map_err(|e| {
        tracing::error!("Error fetching analyzers: {}", e.text());
        PyExc::http(500, format!("Error fetching analyzers: {}", e.text()))
    })?;
    let names = analyzers
        .iterate()
        .and_then(|items| {
            items
                .iter()
                .map(|a| a.attr("name"))
                .collect::<PyResult<Vec<_>>>()
        })
        .map_err(|e| {
            tracing::error!("Error processing analyzers: {}", e.text());
            PyExc::http(500, format!("Error processing analyzers: {}", e.text()))
        })?;
    construct(
        &schema::ANALYZERS_RESPONSE,
        &dict(vec![
            ("success", PyValue::Bool(true)),
            ("message", s("Successfully fetched analyzers")),
            ("analyzers", PyValue::List(names)),
        ]),
    )
}

/// The names `get_available_analyzers()` returns (the validated list).
pub async fn analyzer_names(cache: &ConnectorCache, http: &PyHttp) -> PyResult<Vec<String>> {
    let response = analyzers(cache, http).await?;
    Ok(match response.get("analyzers") {
        Some(PyValue::List(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    })
}

/// `run_analyzer(body, data_type)`.
pub async fn run(
    cache: &ConnectorCache,
    http: &PyHttp,
    analyzer_name: &str,
    analyzer_data: &str,
    data_type: &str,
) -> PyResult<PyValue> {
    initialized(cache, http).await?;
    tracing::info!(
        "Running analyzer {analyzer_name} with data {analyzer_data} of type {data_type}"
    );
    let job_data = construct(
        &schema::ANALYZER_JOB_DATA,
        &dict(vec![("data", s(analyzer_data)), ("dataType", s(data_type))]),
    )?;
    let result = run_and_wait(cache, http, analyzer_name, &job_data, |d| {
        tokio::time::sleep(d)
    })
    .await?;
    construct(
        &schema::RUN_ANALYZER_RESPONSE,
        &dict(vec![
            ("success", PyValue::Bool(true)),
            ("message", s("Successfully ran analyzer")),
            ("report", result),
        ]),
    )
}

/// `run_and_wait_for_analyzer(analyzer_name, job_data)`.
async fn run_and_wait<S, F>(
    cache: &ConnectorCache,
    http: &PyHttp,
    analyzer_name: &str,
    job_data: &PyValue,
    sleep: S,
) -> PyResult<PyValue>
where
    S: FnMut(Duration) -> F,
    F: Future<Output = ()>,
{
    let Some(api) = client(cache, http).await? else {
        return Ok(dict(vec![
            ("success", PyValue::Bool(false)),
            ("message", s("API initialization failed")),
        ]));
    };
    let attempt = async {
        let analyzer = api.analyzer_by_name(analyzer_name).await?;
        if analyzer.is_none() {
            return Err(PyExc::Other(
                "CortexError",
                format!("Analyzer {analyzer_name} not found"),
            ));
        }
        let job = api.run_by_id(&analyzer.attr("id")?, job_data).await?;
        monitor(&api, &job, sleep).await
    };
    attempt.await.map_err(|e| {
        PyExc::http(
            500,
            format!("Error running analyzer {analyzer_name}: {}", e.text()),
        )
    })
}

/// A Cortex job as `monitor_analyzer_job` reads it.
pub trait Jobs {
    /// `api.jobs.get_by_id(job_id)`.
    fn job_by_id(&self, job_id: &PyValue) -> impl Future<Output = PyResult<Wrapped>>;
    /// `api.jobs.get_report(job_id)`.
    fn job_report(&self, job_id: &PyValue) -> impl Future<Output = PyResult<Wrapped>>;
}

impl Jobs for Api {
    fn job_by_id(&self, job_id: &PyValue) -> impl Future<Output = PyResult<Wrapped>> {
        Api::job_by_id(self, job_id)
    }

    fn job_report(&self, job_id: &PyValue) -> impl Future<Output = PyResult<Wrapped>> {
        Api::job_report(self, job_id)
    }
}

fn is_str(v: &PyValue, text: &str) -> bool {
    matches!(v, PyValue::Str(s) if s == text)
}

/// `monitor_analyzer_job(api, job)` then `retrieve_final_report`.
pub async fn monitor<J, S, F>(api: &J, job: &Wrapped, mut sleep: S) -> PyResult<PyValue>
where
    J: Jobs,
    S: FnMut(Duration) -> F,
    F: Future<Output = ()>,
{
    let mut r_json = job.json()?;
    let job_id = getitem(&r_json, "id")?.clone();
    tracing::info!("Job ID is: {}", job_id.py_str());
    let mut job_state = getitem(&r_json, "status")?.clone();
    let mut timer: u32 = 0;
    while !is_str(&job_state, "Success") {
        if timer == MAX_POLLS {
            tracing::error!("Job failed to complete after 5 minutes.");
            return Ok(dict(vec![
                ("success", PyValue::Bool(false)),
                ("message", s("Job timed out")),
            ]));
        }
        timer += 1;
        if is_str(&job_state, "Failure") {
            let error_message = getitem(&r_json, "errorMessage")?.clone();
            tracing::error!("Cortex Failure: {}", error_message.py_str());
            return Ok(dict(vec![
                ("success", PyValue::Bool(false)),
                (
                    "message",
                    s(format!("Analyzer failed: {}", error_message.py_str())),
                ),
            ]));
        }
        sleep(POLL_INTERVAL).await;
        r_json = api.job_by_id(&job_id).await?.json()?;
        job_state = getitem(&r_json, "status")?.clone();
    }
    let report = api.job_report(&job_id).await?.attr("report")?;
    let full = getitem(&report, "full")?.clone();
    Ok(dict(vec![
        ("success", PyValue::Bool(true)),
        ("message", s("Analyzer ran successfully")),
        ("report", full),
    ]))
}

#[cfg(test)]
mod tests {
    use super::super::client::Class;
    use super::*;
    use copilot_auth::pyvalue::loads;
    use std::cell::RefCell;

    struct Script {
        polls: RefCell<Vec<&'static str>>,
        report: &'static str,
    }

    impl Jobs for Script {
        fn job_by_id(&self, _: &PyValue) -> impl Future<Output = PyResult<Wrapped>> {
            let next = self.polls.borrow_mut().remove(0);
            async move { Wrapped::wrap(loads(next).unwrap(), Class::Job) }
        }

        fn job_report(&self, _: &PyValue) -> impl Future<Output = PyResult<Wrapped>> {
            let report = self.report;
            async move { Wrapped::wrap(loads(report).unwrap(), Class::Job) }
        }
    }

    fn run(
        first: &str,
        polls: Vec<&'static str>,
        report: &'static str,
    ) -> (PyResult<PyValue>, usize) {
        let script = Script {
            polls: RefCell::new(polls),
            report,
        };
        let job = Wrapped::wrap(loads(first).unwrap(), Class::Job).unwrap();
        let slept = RefCell::new(0usize);
        let out = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(monitor(&script, &job, |_| {
                *slept.borrow_mut() += 1;
                async {}
            }));
        let n = *slept.borrow();
        (out, n)
    }

    #[test]
    fn jobs_are_polled_like_python() {
        let (out, slept) = run(
            r#"{"id": "j", "status": "Waiting"}"#,
            vec![
                r#"{"id": "j", "status": "InProgress"}"#,
                r#"{"status": "Success"}"#,
            ],
            r#"{"report": {"full": {"x": 1}}}"#,
        );
        assert_eq!(slept, 2);
        assert_eq!(
            out.unwrap().py_repr(),
            "{'success': True, 'message': 'Analyzer ran successfully', 'report': {'x': 1}}"
        );
        let (out, slept) = run(
            r#"{"id": "j", "status": "Failure", "errorMessage": "boom"}"#,
            vec![],
            "{}",
        );
        assert_eq!(slept, 0);
        assert_eq!(
            out.unwrap().py_repr(),
            "{'success': False, 'message': 'Analyzer failed: boom'}"
        );
        let waiting = r#"{"id": "j", "status": "Waiting"}"#;
        let (out, slept) = run(waiting, vec![waiting; 60], "{}");
        assert_eq!(slept, 60);
        assert_eq!(
            out.unwrap().py_repr(),
            "{'success': False, 'message': 'Job timed out'}"
        );
        // The 60th poll's Failure is never read: the timer check comes first.
        let mut polls = vec![waiting; 59];
        polls.push(r#"{"id": "j", "status": "Failure", "errorMessage": "late"}"#);
        let (out, _) = run(waiting, polls, "{}");
        assert_eq!(
            out.unwrap().py_repr(),
            "{'success': False, 'message': 'Job timed out'}"
        );
        let (out, _) = run(r#"{"status": "Success"}"#, vec![], "{}");
        assert_eq!(out.unwrap_err().text(), "'id'");
        let (out, _) = run(
            r#"{"id": 1, "status": "Success"}"#,
            vec![],
            r#"{"report": []}"#,
        );
        assert_eq!(
            out.unwrap_err().text(),
            "list indices must be integers or slices, not str"
        );
    }
}
