//! `GET /api/sca/overview/stream`: `stream_sca_for_all_agents` behind the
//! route's `StreamingResponse` — one `event: …\ndata: <json.dumps>\n\n`
//! chunk per event, the agents' results in the order they complete (each
//! wait capped at 60 s), progress every five agents and on the last, then
//! the summary. Starlette's headers; `GZipMiddleware` leaves an event
//! stream alone.

use std::convert::Infallible;
use std::time::Duration;

use axum::body::Body;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use tokio::sync::{Semaphore, mpsc};
use tokio_stream::wrappers::ReceiverStream;

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_web::middleware::Uncompressed;

use crate::AgentReportsState;
use crate::pyfmt::{dict, int, opt, s};

use super::schema::{ScaItem, Totals};
use super::services::{self, Filters, MAX_CONCURRENT};

/// How long the stream waits for the next agent.
const AGENT_WAIT: Duration = Duration::from_secs(60);

/// What the stream collects.
#[derive(Debug, Clone, Default)]
pub struct StreamParams {
    /// The scoped customer codes (`None`: every agent, `Some([])`: none).
    pub codes: Option<Vec<String>>,
    /// `agent_name`.
    pub agent_name: Option<String>,
    /// The policy filters.
    pub filters: Filters,
}

/// One server-sent event as the route formats it.
pub fn frame(event: &str, data: &PyValue) -> Bytes {
    let json = py_dumps(data, Dumps::DEFAULT).unwrap_or_default();
    Bytes::from(format!("event: {event}\ndata: {json}\n\n"))
}

/// The `StreamingResponse`.
pub fn response(st: AgentReportsState, p: StreamParams) -> Response {
    let (tx, rx) = mpsc::channel::<Bytes>(16);
    tokio::spawn(async move {
        if p.codes.as_ref().is_some_and(Vec::is_empty) {
            let _ = tx
                .send(Bytes::from_static(
                    b"event: complete\ndata: {\"results\": [], \"message\": \"No accessible \
                      customers\"}\n\n",
                ))
                .await;
            return;
        }
        produce(&st, &p, &tx).await;
    });
    let body = Body::from_stream(ReceiverStream::new(rx).map(Ok::<_, Infallible>));
    let mut resp = (
        [
            (http::header::CACHE_CONTROL, "no-cache"),
            (http::header::CONNECTION, "keep-alive"),
            (http::HeaderName::from_static("x-accel-buffering"), "no"),
            (
                http::header::CONTENT_TYPE,
                "text/event-stream; charset=utf-8",
            ),
        ],
        body,
    )
        .into_response();
    resp.extensions_mut().insert(Uncompressed);
    resp
}

/// Sends one event; `false` once the client has gone.
async fn emit(tx: &mpsc::Sender<Bytes>, event: &str, data: PyValue) -> bool {
    tx.send(frame(event, &data)).await.is_ok()
}

fn complete_empty(message: String) -> PyValue {
    dict(vec![
        ("total_results", int(0)),
        ("total_agents", int(0)),
        ("message", s(message)),
    ])
}

/// `stream_sca_for_all_agents(...)`.
async fn produce(st: &AgentReportsState, p: &StreamParams, tx: &mpsc::Sender<Bytes>) {
    let agents = match services::agents_of(st, p.codes.as_deref()).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Error in SCA streaming: {}", e.display());
            emit(
                tx,
                "error",
                dict(vec![
                    ("error", s(e.display())),
                    ("message", s("Fatal error during SCA collection")),
                ]),
            )
            .await;
            return;
        }
    };
    if agents.is_empty() {
        emit(tx, "complete", complete_empty("No agents found".into())).await;
        return;
    }
    let agents = services::named(agents, p.agent_name.as_deref());
    if agents.is_empty() {
        let name = p.agent_name.clone().unwrap_or_default();
        emit(
            tx,
            "complete",
            complete_empty(format!("No agents found matching hostname: {name}")),
        )
        .await;
        return;
    }
    let total = agents.len();
    if !emit(
        tx,
        "start",
        dict(vec![
            ("total_agents", int(total)),
            (
                "message",
                s(format!("Starting SCA collection for {total} agents...")),
            ),
        ]),
    )
    .await
    {
        return;
    }
    let gate = Semaphore::new(MAX_CONCURRENT);
    let mut pending: FuturesUnordered<_> = agents
        .iter()
        .map(|agent| {
            let gate = &gate;
            async move {
                (
                    agent,
                    services::collect_one(st, agent, gate, &p.filters).await,
                )
            }
        })
        .collect();
    let mut all: Vec<ScaItem> = Vec::new();
    let (mut processed, mut successful, mut failed) = (0usize, 0usize, 0usize);
    for _ in 0..total {
        match tokio::time::timeout(AGENT_WAIT, pending.next()).await {
            Ok(Some((agent, results))) => {
                processed += 1;
                let sent = if results.is_empty() {
                    emit(
                        tx,
                        "agent_empty",
                        dict(vec![
                            ("agent_id", s(&agent.agent_id)),
                            ("agent_name", s(&agent.hostname)),
                            ("message", s("No SCA data available")),
                        ]),
                    )
                    .await
                } else {
                    successful += 1;
                    let policies: Vec<PyValue> =
                        results.iter().map(ScaItem::stream_policy).collect();
                    let n = results.len();
                    all.extend(results);
                    emit(
                        tx,
                        "agent_result",
                        dict(vec![
                            ("agent_id", s(&agent.agent_id)),
                            ("agent_name", s(&agent.hostname)),
                            ("customer_code", opt(agent.customer_code.clone())),
                            ("policy_count", int(n)),
                            ("policies", PyValue::List(policies)),
                        ]),
                    )
                    .await
                };
                if !sent {
                    return;
                }
                if processed % 5 == 0 || processed == total {
                    let percent = processed as f64 / total as f64 * 100.0;
                    let sent = emit(
                        tx,
                        "progress",
                        dict(vec![
                            ("processed", int(processed)),
                            ("total", int(total)),
                            ("successful", int(successful)),
                            ("failed", int(failed)),
                            ("results_so_far", int(all.len())),
                            (
                                "percent_complete",
                                PyValue::Float(copilot_core::time::py_round(percent, 1)),
                            ),
                        ]),
                    )
                    .await;
                    if !sent {
                        return;
                    }
                }
            }
            Ok(None) => break,
            Err(_) => {
                failed += 1;
                processed += 1;
                if !emit(
                    tx,
                    "agent_error",
                    dict(vec![
                        ("agent_id", s("unknown")),
                        ("message", s("Timeout waiting for agent response")),
                    ]),
                )
                .await
                {
                    return;
                }
            }
        }
    }
    // `asyncio.gather(*tasks)`: the late agents finish before the summary.
    while pending.next().await.is_some() {}
    let refs: Vec<&ScaItem> = all.iter().collect();
    let t = Totals::of(&refs);
    emit(
        tx,
        "complete",
        dict(vec![
            ("total_results", int(all.len())),
            ("total_agents", int(t.agents)),
            ("total_policies", int(t.policies)),
            (
                "average_score",
                PyValue::Float(copilot_core::time::py_round(t.average, 2)),
            ),
            ("total_checks", int(t.checks)),
            ("total_passes", int(t.passes)),
            ("total_fails", int(t.fails)),
            ("total_invalid", int(t.invalid)),
            ("agents_processed", int(processed)),
            ("agents_successful", int(successful)),
            ("agents_failed", int(failed)),
            (
                "message",
                s(format!(
                    "Completed SCA collection: {} results from {} agents",
                    all.len(),
                    t.agents
                )),
            ),
        ]),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_json_dumps_between_the_sse_fields() {
        let f = frame(
            "progress",
            &dict(vec![
                ("processed", int(5)),
                ("percent_complete", PyValue::Float(33.3)),
                ("customer_code", PyValue::None),
                ("message", s("é")),
            ]),
        );
        assert_eq!(
            f,
            Bytes::from(
                "event: progress\ndata: {\"processed\": 5, \"percent_complete\": 33.3, \
                 \"customer_code\": null, \"message\": \"\\u00e9\"}\n\n"
            )
        );
    }
}
