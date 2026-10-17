//! `RequestTimingMiddleware`: every request is registered when it arrives
//! and recorded when its body ends (or the client goes away), under its
//! route template; the answer carries `X-Process-Time-Ms` (the time to its
//! head) and `X-Request-Id`.
//!
//! Applied with `Router::layer` on the whole application, so it runs after
//! routing — where `MatchedPath` names the template Python rebuilds from
//! `path_params` — and wraps every route and the fallback, the proxy to
//! Python included. On a proxied answer the two headers Python's own timer
//! wrote are replaced: the outermost process's are the ones that measure
//! what the client waited for.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use axum::body::{Body, Bytes, HttpBody};
use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use http::HeaderValue;
use http_body::{Frame, SizeHint};

use super::registry::route_template;
use super::{Perf, perf};

const PROCESS_TIME: &str = "x-process-time-ms";
const REQUEST_ID: &str = "x-request-id";

/// A request in flight: recorded once, when its body ends, when it is
/// dropped unfinished (the client went away), or when its handler is
/// dropped before answering.
struct Pending {
    perf: &'static Perf,
    id: u64,
    template: String,
    status: u16,
    done: bool,
}

impl Pending {
    fn finish(&mut self, disconnected: bool) {
        if self.done {
            return;
        }
        self.done = true;
        self.perf
            .requests()
            .finish_request(self.id, self.status, &self.template, disconnected);
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        // The handler's future dropped before it answered: the client left.
        self.finish(true);
    }
}

/// The answer's body, passed through; its end records the request.
struct TimedBody {
    inner: Body,
    pending: Pending,
}

impl HttpBody for TimedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(None) => this.pending.finish(false),
            Poll::Ready(Some(Err(_))) => this.pending.finish(true),
            Poll::Ready(Some(Ok(_))) if this.inner.is_end_stream() => this.pending.finish(false),
            _ => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for TimedBody {
    fn drop(&mut self) {
        // Dropped before its end: the client went away mid-answer.
        let ended = self.inner.is_end_stream();
        self.pending.finish(!ended);
    }
}

/// The middleware (`axum::middleware::from_fn`).
pub async fn timing(req: Request, next: Next) -> Response {
    let perf = perf();
    if !perf.config.enabled {
        return next.run(req).await;
    }
    let raw_path = copilot_web::middleware::decoded_path(req.uri());
    let template = route_template(
        req.extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str),
        &raw_path,
    );
    let id = perf
        .requests()
        .start_request(req.method().as_str(), &raw_path);
    let started = perf.requests().started_at(id).unwrap_or_else(Instant::now);
    let mut pending = Pending {
        perf,
        id,
        template,
        status: 0,
        done: false,
    };
    let mut response = next.run(req).await;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    pending.status = response.status().as_u16();
    let headers = response.headers_mut();
    headers.remove(PROCESS_TIME);
    headers.remove(REQUEST_ID);
    if let Ok(v) = HeaderValue::from_str(&format!("{elapsed_ms:.1}")) {
        headers.append(PROCESS_TIME, v);
    }
    headers.append(REQUEST_ID, HeaderValue::from(id));
    response.map(|inner| Body::new(TimedBody { inner, pending }))
}
