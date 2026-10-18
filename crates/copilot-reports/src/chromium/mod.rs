//! Headless Chromium driven over the DevTools protocol as Playwright 1.59
//! drives it — the part of `async_playwright()` the Grafana report uses:
//! `chromium.launch(headless=True)` (Playwright's switches, a fresh
//! profile directory, `--remote-debugging-pipe`), `browser.new_context()`
//! and `new_page()` (the same setup commands, the 1280×720 viewport, the
//! fonts, the media features, `ignore_https_errors`), and the page's
//! `goto`, `fill`, `click`, `wait_for_load_state("networkidle")`,
//! `evaluate`, `set_viewport_size`, `screenshot(type="png")`,
//! `emulate_media(media="screen")` and `pdf()`, each sending what
//! Playwright sends ([`frames`] keeps the lifecycle Playwright keeps, its
//! own `networkidle` included). What the browser then sends to a site —
//! every request and header — is the browser's, so it is Python's.
//!
//! The protocol runs over the pipe Chromium reads on fd 3 and writes on
//! fd 4 (JSON messages ended by a NUL); the child is started through
//! `/bin/sh`, which moves the two pipe ends there, so the browser's own
//! argument list is exactly Playwright's.

pub mod frames;
pub mod launch;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use base64::Engine as _;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

use frames::Lifecycle;

pub use launch::find_executable;

/// Playwright's default action and navigation timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The id Playwright sends `Browser.close` with (`kBrowserCloseMessageId`).
const BROWSER_CLOSE_ID: i64 = -9999;

/// The retry waits of Playwright's `_retryAction`, then 500 ms.
const RETRY_WAITS_MS: [u64; 5] = [0, 20, 100, 100, 500];

/// A failure of the browser or of an operation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The browser could not be started.
    #[error("Browser launch failed: {0}")]
    Launch(String),
    /// A protocol command failed: `Protocol error (Method): message`.
    #[error("Protocol error ({method}): {message}")]
    Protocol {
        /// The command.
        method: String,
        /// Chromium's message.
        message: String,
    },
    /// The browser went away.
    #[error("Target page, context or browser has been closed")]
    Closed,
    /// An operation ran out of time.
    #[error("Timeout {ms}ms exceeded: {1}", ms = .0.as_millis())]
    Timeout(Duration, String),
    /// A navigation failed (`net::ERR_… at url`).
    #[error("{0}")]
    Navigation(String),
    /// Script in the page threw.
    #[error("{0}")]
    Evaluation(String),
    /// An element could not be acted on.
    #[error("{0}")]
    Element(String),
    /// A local file or pipe.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

type Reply = Result<Value, Error>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What a session's events feed.
#[derive(Clone)]
struct Sink {
    page: Arc<PageShared>,
}

/// The connection: one writer, one reader, the pending commands and the
/// sessions events are routed to.
pub(crate) struct Connection {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    next_id: AtomicI64,
    pending: Mutex<HashMap<i64, (String, oneshot::Sender<Reply>)>>,
    sessions: Mutex<HashMap<String, Sink>>,
    /// `Target.attachedToTarget` of pages, by target id → session id.
    pages: Mutex<HashMap<String, String>>,
    changed: watch::Sender<u64>,
    closed: watch::Sender<bool>,
    stderr: Mutex<Vec<String>>,
}

impl Connection {
    fn message(id: i64, method: &str, params: Option<Value>, session: Option<&str>) -> Vec<u8> {
        let mut m = serde_json::Map::new();
        m.insert("id".into(), json!(id));
        m.insert("method".into(), json!(method));
        if let Some(p) = params {
            m.insert("params".into(), p);
        }
        if let Some(s) = session {
            m.insert("sessionId".into(), json!(s));
        }
        let mut bytes = serde_json::to_vec(&Value::Object(m)).unwrap_or_default();
        bytes.push(0);
        bytes
    }

    /// Write a command now; its answer arrives on the receiver.
    fn send_now(
        &self,
        method: &str,
        params: Option<Value>,
        session: Option<&str>,
    ) -> oneshot::Receiver<Reply> {
        let (tx, rx) = oneshot::channel();
        if *self.closed.borrow() {
            let _ = tx.send(Err(Error::Closed));
            return rx;
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        lock(&self.pending).insert(id, (method.to_string(), tx));
        if self
            .tx
            .send(Self::message(id, method, params, session))
            .is_err()
        {
            if let Some((_, tx)) = lock(&self.pending).remove(&id) {
                let _ = tx.send(Err(Error::Closed));
            }
        }
        rx
    }

    /// A command whose answer nobody waits for (`_sendMayFail`).
    fn fire(&self, method: &str, params: Option<Value>, session: Option<&str>) {
        drop(self.send_now(method, params, session));
    }

    async fn send(&self, method: &str, params: Option<Value>, session: Option<&str>) -> Reply {
        self.send_now(method, params, session)
            .await
            .unwrap_or(Err(Error::Closed))
    }

    fn stderr_tail(&self) -> String {
        lock(&self.stderr).join("\n")
    }

    fn on_message(self: &Arc<Self>, raw: &[u8]) {
        let Ok(msg) = serde_json::from_slice::<Value>(raw) else {
            return;
        };
        if let Some(id) = msg.get("id").and_then(Value::as_i64) {
            if let Some((method, tx)) = lock(&self.pending).remove(&id) {
                let reply = match msg.get("error") {
                    Some(e) => Err(Error::Protocol {
                        method,
                        message: e
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    }),
                    None => Ok(msg.get("result").cloned().unwrap_or(Value::Null)),
                };
                let _ = tx.send(reply);
            }
            return;
        }
        let method = msg
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let session = msg.get("sessionId").and_then(Value::as_str);
        match method {
            "Target.attachedToTarget" => self.attached(session, &params),
            "Target.detachedFromTarget" => {
                if let Some(child) = params.get("sessionId").and_then(Value::as_str) {
                    let sink = lock(&self.sessions).remove(child);
                    if let Some(sink) = sink {
                        if sink.page.session == child {
                            sink.page.update(|s| s.closed = true);
                        }
                    }
                }
            }
            _ => {
                let Some(session) = session else {
                    return;
                };
                let sink = lock(&self.sessions).get(session).cloned();
                if let Some(sink) = sink {
                    sink.page.event(session, method, &params);
                }
            }
        }
    }

    /// `_onAttachedToTarget`: a page is waited for by its creator; a
    /// page's worker or out-of-process frame is set up and resumed;
    /// anything else is resumed (every target starts paused).
    fn attached(self: &Arc<Self>, parent: Option<&str>, params: &Value) {
        let Some(child) = params.get("sessionId").and_then(Value::as_str) else {
            return;
        };
        let info = params.get("targetInfo").cloned().unwrap_or(Value::Null);
        let kind = info.get("type").and_then(Value::as_str).unwrap_or_default();
        let target = info
            .get("targetId")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let parent_sink = parent.and_then(|p| lock(&self.sessions).get(p).cloned());
        match (parent_sink, kind) {
            (None, "page") if parent.is_none() => {
                lock(&self.pages).insert(target.to_string(), child.to_string());
                self.changed.send_modify(|v| *v += 1);
            }
            (Some(sink), "worker") => {
                sink.page.update(|s| s.add_worker(child));
                lock(&self.sessions).insert(child.to_string(), sink);
                self.fire("Runtime.enable", Some(json!({})), Some(child));
                self.fire("Network.enable", None, Some(child));
                self.fire("Runtime.runIfWaitingForDebugger", None, Some(child));
                self.fire("Target.setAutoAttach", Some(auto_attach()), Some(child));
            }
            (Some(sink), "iframe") => {
                let ignore = sink.page.ignore_https_errors;
                let world = sink.page.utility_world.clone();
                lock(&self.sessions).insert(child.to_string(), sink);
                self.fire("Page.enable", None, Some(child));
                self.fire("Log.enable", Some(json!({})), Some(child));
                self.fire(
                    "Page.setLifecycleEventsEnabled",
                    Some(json!({"enabled": true})),
                    Some(child),
                );
                self.fire("Runtime.enable", Some(json!({})), Some(child));
                self.fire(
                    "Page.addScriptToEvaluateOnNewDocument",
                    Some(json!({"source": "", "worldName": world})),
                    Some(child),
                );
                self.fire("Network.enable", None, Some(child));
                self.fire("Target.setAutoAttach", Some(auto_attach()), Some(child));
                self.fire(
                    "Emulation.setFocusEmulationEnabled",
                    Some(json!({"enabled": true})),
                    Some(child),
                );
                if ignore {
                    self.fire(
                        "Security.setIgnoreCertificateErrors",
                        Some(json!({"ignore": true})),
                        Some(child),
                    );
                }
                self.fire("Runtime.runIfWaitingForDebugger", None, Some(child));
            }
            _ => self.fire("Runtime.runIfWaitingForDebugger", None, Some(child)),
        }
    }

    fn shut(&self) {
        let _ = self.closed.send(true);
        let pending: Vec<_> = lock(&self.pending).drain().collect();
        for (_, (_, tx)) in pending {
            let _ = tx.send(Err(Error::Closed));
        }
        let sinks: Vec<_> = lock(&self.sessions).values().cloned().collect();
        for sink in sinks {
            sink.page.update(|s| s.closed = true);
        }
        self.changed.send_modify(|v| *v += 1);
    }
}

fn auto_attach() -> Value {
    json!({"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true})
}

/// A page's shared state: the frames, fed by the reader, waited on by the
/// operations.
struct PageShared {
    state: Mutex<frames::State>,
    version: watch::Sender<u64>,
    session: String,
    utility_world: String,
    ignore_https_errors: bool,
    /// Events that arrived before the frame tree (replayed after it).
    early: Mutex<Option<Vec<(String, String, Value)>>>,
}

impl PageShared {
    fn update(self: &Arc<Self>, f: impl FnOnce(&mut frames::State)) {
        let timers = {
            let mut s = lock(&self.state);
            f(&mut s);
            s.take_timers()
        };
        self.start_timers(timers);
    }

    /// Run the network-idle timers the state asked for, then wake the
    /// waiters.
    fn start_timers(self: &Arc<Self>, timers: Vec<frames::Timer>) {
        for t in timers {
            let page = Arc::clone(self);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(frames::NETWORK_IDLE_MS)).await;
                page.timer_fired(&t);
            });
        }
        self.version.send_modify(|v| *v += 1);
    }

    fn timer_fired(self: &Arc<Self>, t: &frames::Timer) {
        let timers = {
            let mut s = lock(&self.state);
            s.timer_fired(&t.frame, t.generation);
            s.take_timers()
        };
        self.start_timers(timers);
    }

    fn event(self: &Arc<Self>, session: &str, method: &str, params: &Value) {
        {
            let mut early = lock(&self.early);
            if let Some(buffer) = early.as_mut() {
                buffer.push((session.to_string(), method.to_string(), params.clone()));
                return;
            }
        }
        self.update(|s| s.on_event(session, method, params));
    }

    fn frame_tree(self: &Arc<Self>, tree: &Value) {
        self.update(|s| s.frame_tree(tree));
        let early = lock(&self.early).take().unwrap_or_default();
        for (session, method, params) in early {
            self.update(|s| s.on_event(&session, &method, &params));
        }
    }

    /// Wait until `check` answers, the page closes or `deadline` passes.
    async fn wait<T>(
        &self,
        deadline: Instant,
        what: &str,
        mut check: impl FnMut(&frames::State) -> Option<Result<T, Error>>,
    ) -> Result<T, Error> {
        let mut rx = self.version.subscribe();
        loop {
            {
                let s = lock(&self.state);
                if let Some(answer) = check(&s) {
                    return answer;
                }
                if s.closed {
                    return Err(Error::Closed);
                }
            }
            match tokio::time::timeout_at(deadline, rx.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(Error::Closed),
                Err(_) => return Err(Error::Timeout(DEFAULT_TIMEOUT, what.to_string())),
            }
        }
    }
}

/// A launched browser.
pub struct Browser {
    conn: Arc<Connection>,
    child: Child,
    dirs: Vec<PathBuf>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for Browser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Browser").field("dirs", &self.dirs).finish()
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        for t in &self.tasks {
            t.abort();
        }
        for d in &self.dirs {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

async fn writer(mut stdin: ChildStdin, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(bytes) = rx.recv().await {
        if stdin.write_all(&bytes).await.is_err() || stdin.flush().await.is_err() {
            break;
        }
    }
}

async fn reader(conn: Arc<Connection>, stdout: ChildStdout) {
    let mut r = BufReader::new(stdout);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match r.read_until(0, &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if buf.last() == Some(&0) {
                    buf.pop();
                }
                conn.on_message(&buf);
            }
        }
    }
    conn.shut();
}

async fn stderr_drain(conn: Arc<Connection>, stderr: ChildStderr) {
    let mut lines = BufReader::new(stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        tracing::debug!(target: "copilot_reports::chromium", "[browser] {line}");
        let mut tail = lock(&conn.stderr);
        tail.push(line);
        if tail.len() > 40 {
            tail.remove(0);
        }
    }
}

impl Browser {
    /// `chromium.launch(headless=True)` with `executable`.
    pub async fn launch(executable: &std::path::Path) -> Result<Browser, Error> {
        let launched = launch::spawn(executable)?;
        let (tx, rx) = mpsc::unbounded_channel();
        let conn = Arc::new(Connection {
            tx,
            next_id: AtomicI64::new(1),
            pending: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            pages: Mutex::new(HashMap::new()),
            changed: watch::channel(0).0,
            closed: watch::channel(false).0,
            stderr: Mutex::new(Vec::new()),
        });
        let launch::Launched {
            child,
            stdin,
            stdout,
            stderr,
            dirs,
        } = launched;
        let tasks = vec![
            tokio::spawn(writer(stdin, rx)),
            tokio::spawn(reader(Arc::clone(&conn), stdout)),
            tokio::spawn(stderr_drain(Arc::clone(&conn), stderr)),
        ];
        let browser = Browser {
            conn,
            child,
            dirs,
            tasks,
        };
        let version = tokio::time::timeout(
            Duration::from_secs(180),
            browser.conn.send("Browser.getVersion", None, None),
        )
        .await;
        match version {
            Ok(Ok(_)) => {}
            Ok(Err(Error::Closed)) | Err(_) => {
                return Err(Error::Launch(format!(
                    "Target page, context or browser has been closed\nBrowser logs:\n{}",
                    browser.conn.stderr_tail()
                )));
            }
            Ok(Err(e)) => return Err(e),
        }
        browser
            .conn
            .send("Target.setAutoAttach", Some(auto_attach()), None)
            .await?;
        Ok(browser)
    }

    /// `browser.new_context(ignore_https_errors=…)` then
    /// `context.new_page()`.
    pub async fn new_page(&self, ignore_https_errors: bool) -> Result<Page, Error> {
        let conn = &self.conn;
        let context = conn
            .send(
                "Target.createBrowserContext",
                Some(json!({"disposeOnDetach": true})),
                None,
            )
            .await?;
        let context = context
            .get("browserContextId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let downloads = self
            .dirs
            .iter()
            .find(|d| {
                d.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("playwright-artifacts-"))
            })
            .map(|d| d.to_string_lossy().into_owned())
            .unwrap_or_default();
        conn.send(
            "Browser.setDownloadBehavior",
            Some(json!({
                "behavior": "allowAndName",
                "browserContextId": context,
                "downloadPath": downloads,
                "eventsEnabled": true,
            })),
            None,
        )
        .await?;
        let target = conn
            .send(
                "Target.createTarget",
                Some(json!({"url": "about:blank", "browserContextId": context})),
                None,
            )
            .await?;
        let target = target
            .get("targetId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let session = {
            let mut rx = conn.changed.subscribe();
            let deadline = Instant::now() + DEFAULT_TIMEOUT;
            loop {
                if let Some(s) = lock(&conn.pages).remove(&target) {
                    break s;
                }
                if *conn.closed.borrow() {
                    return Err(Error::Closed);
                }
                match tokio::time::timeout_at(deadline, rx.changed()).await {
                    Ok(Ok(())) => {}
                    _ => return Err(Error::Closed),
                }
            }
        };
        let world = format!(
            "__playwright_utility_world_page@{}",
            hex::encode(rand::random::<[u8; 16]>())
        );
        let shared = Arc::new(PageShared {
            state: Mutex::new(frames::State::new(&target, &world)),
            version: watch::channel(0).0,
            session: session.clone(),
            utility_world: world.clone(),
            ignore_https_errors,
            early: Mutex::new(Some(Vec::new())),
        });
        lock(&conn.sessions).insert(
            session.clone(),
            Sink {
                page: Arc::clone(&shared),
            },
        );
        let s = Some(session.as_str());
        let window = conn
            .send("Browser.getWindowForTarget", None, s)
            .await?
            .get("windowId")
            .cloned()
            .unwrap_or(Value::Null);
        let viewport = Viewport {
            width: 1280,
            height: 720,
        };
        // `FrameSession._initialize`: sent at once, answered in any order.
        let mut replies = vec![
            conn.send_now("Page.enable", None, s),
            conn.send_now("Page.getFrameTree", None, s),
            conn.send_now("Log.enable", Some(json!({})), s),
            conn.send_now(
                "Page.setLifecycleEventsEnabled",
                Some(json!({"enabled": true})),
                s,
            ),
            conn.send_now("Runtime.enable", Some(json!({})), s),
            conn.send_now(
                "Page.addScriptToEvaluateOnNewDocument",
                Some(json!({"source": "", "worldName": world})),
                s,
            ),
            conn.send_now("Network.enable", None, s),
            conn.send_now("Target.setAutoAttach", Some(auto_attach()), s),
            conn.send_now(
                "Emulation.setFocusEmulationEnabled",
                Some(json!({"enabled": true})),
                s,
            ),
        ];
        if ignore_https_errors {
            replies.push(conn.send_now(
                "Security.setIgnoreCertificateErrors",
                Some(json!({"ignore": true})),
                s,
            ));
        }
        replies.push(conn.send_now(
            "Browser.setWindowBounds",
            Some(json!({"windowId": window, "bounds": viewport.bounds()})),
            s,
        ));
        replies.push(conn.send_now(
            "Emulation.setDeviceMetricsOverride",
            Some(viewport.metrics()),
            s,
        ));
        replies.push(conn.send_now(
            "Page.setFontFamilies",
            Some(json!({"fontFamilies": {
                "standard": "Times New Roman",
                "fixed": "Monospace",
                "serif": "Times New Roman",
                "sansSerif": "Arial",
                "cursive": "Comic Sans MS",
                "fantasy": "Impact",
            }})),
            s,
        ));
        replies.push(conn.send_now("Emulation.setEmulatedMedia", Some(media_params("")), s));
        replies.push(conn.send_now("Runtime.runIfWaitingForDebugger", None, s));
        let mut first_error = None;
        for (i, rx) in replies.into_iter().enumerate() {
            match rx.await.unwrap_or(Err(Error::Closed)) {
                Ok(v) if i == 1 => {
                    if let Some(tree) = v.get("frameTree") {
                        shared.frame_tree(tree);
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }
        if let Some(e) = first_error {
            return Err(e);
        }
        let main = lock(&shared.state).main_frame().map(str::to_string);
        if let Some(main) = main {
            conn.fire(
                "Page.createIsolatedWorld",
                Some(json!({"frameId": main, "grantUniveralAccess": true, "worldName": world})),
                s,
            );
        }
        Ok(Page {
            conn: Arc::clone(conn),
            shared,
            session,
            window,
            metrics: Mutex::new(Some(viewport)),
        })
    }

    /// `browser.close()`: `Browser.close`, the process waited for (killed
    /// after `grace`), the profile and artifacts directories removed.
    pub async fn close(mut self, grace: Duration) {
        let mut bytes = serde_json::to_vec(&json!({
            "method": "Browser.close", "id": BROWSER_CLOSE_ID, "params": {}
        }))
        .unwrap_or_default();
        bytes.push(0);
        let _ = self.conn.tx.send(bytes);
        if tokio::time::timeout(grace, self.child.wait())
            .await
            .is_err()
        {
            let _ = self.child.kill().await;
        }
    }
}

/// The emulated viewport (`page.set_viewport_size`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Viewport {
    width: i64,
    height: i64,
}

impl Viewport {
    fn bounds(self) -> Value {
        json!({"width": self.width, "height": self.height})
    }

    /// `_updateViewport`'s `metricsOverride` (not mobile, scale 1).
    fn metrics(self) -> Value {
        json!({
            "mobile": false,
            "width": self.width,
            "height": self.height,
            "screenWidth": self.width,
            "screenHeight": self.height,
            "deviceScaleFactor": 1,
            "screenOrientation": {"angle": 0, "type": "landscapePrimary"},
        })
    }
}

/// `Emulation.setEmulatedMedia`'s parameters with the context's defaults.
fn media_params(media: &str) -> Value {
    json!({"media": media, "features": [
        {"name": "prefers-color-scheme", "value": "light"},
        {"name": "prefers-reduced-motion", "value": "no-preference"},
        {"name": "forced-colors", "value": "none"},
        {"name": "prefers-contrast", "value": "no-preference"},
    ]})
}

/// `helper.completeUserURL`.
pub fn complete_user_url(url: &str) -> String {
    if url.starts_with("localhost") || url.starts_with("127.0.0.1") {
        format!("http://{url}")
    } else {
        url.to_string()
    }
}

/// Playwright's `_retryAction` schedule: attempts after 0, 20, 100, 100,
/// 500, then every 500 ms, until the action's timeout.
struct Retry {
    i: usize,
    deadline: Instant,
    last: String,
}

impl Retry {
    fn new() -> Self {
        Self {
            i: 0,
            deadline: Instant::now() + DEFAULT_TIMEOUT,
            last: String::new(),
        }
    }

    /// Wait before the next attempt; `false` once out of time.
    async fn pause(&mut self) -> bool {
        let wait = RETRY_WAITS_MS.get(self.i).copied().unwrap_or(500);
        self.i += 1;
        if wait > 0 {
            if Instant::now() + Duration::from_millis(wait) > self.deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(wait)).await;
        }
        Instant::now() <= self.deadline
    }

    /// An attempt's outcome: done, to retry (`None`), or failed.
    fn outcome<T>(
        &mut self,
        r: Result<Result<Result<T, String>, Error>, tokio::time::error::Elapsed>,
    ) -> Result<Option<T>, Error> {
        match r {
            Ok(Ok(Ok(v))) => Ok(Some(v)),
            Ok(Ok(Err(retry))) => {
                self.last = retry;
                Ok(None)
            }
            // A navigation took the context: retried, as Playwright retries
            // an action whose element was detached.
            Ok(Err(Error::Protocol { message, .. })) => {
                self.last = message;
                Ok(None)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(None),
        }
    }

    fn timeout(&self, action: &str) -> Error {
        Error::Timeout(DEFAULT_TIMEOUT, format!("{action}: {}", self.last))
    }
}

/// A page of the browser.
pub struct Page {
    conn: Arc<Connection>,
    shared: Arc<PageShared>,
    session: String,
    window: Value,
    metrics: Mutex<Option<Viewport>>,
}

impl std::fmt::Debug for Page {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Page")
            .field("session", &self.session)
            .finish()
    }
}

/// The screenshot preparation Playwright evaluates in every frame
/// (`inPagePrepareForScreenshots` of `server/screenshotter.js`).
const PREPARE_FOR_SCREENSHOTS: &str = include_str!("prepare_for_screenshots.js");

/// The element checks and the `fill` of Playwright's injected script, as
/// far as the report's two selectors need them.
const ELEMENT_SCRIPT: &str = include_str!("element.js");

impl Page {
    fn s(&self) -> Option<&str> {
        Some(self.session.as_str())
    }

    async fn send(&self, method: &str, params: Option<Value>) -> Reply {
        self.conn.send(method, params, self.s()).await
    }

    fn main_frame(&self) -> Option<String> {
        lock(&self.shared.state).main_frame().map(str::to_string)
    }

    /// The main frame's context of one world, waited for.
    async fn context(&self, utility: bool, deadline: Instant) -> Result<i64, Error> {
        self.shared
            .wait(deadline, "waiting for the execution context", |s| {
                s.main_context(utility).map(Ok)
            })
            .await
    }

    async fn evaluate_in(
        &self,
        utility: bool,
        expression: &str,
        by_value: bool,
        deadline: Instant,
    ) -> Reply {
        let ctx = self.context(utility, deadline).await?;
        let mut params = json!({
            "expression": expression,
            "contextId": ctx,
            "returnByValue": by_value,
            "awaitPromise": true,
        });
        if !utility {
            params["userGesture"] = json!(true);
        }
        let r = tokio::time::timeout_at(deadline, self.send("Runtime.evaluate", Some(params)))
            .await
            .map_err(|_| Error::Timeout(DEFAULT_TIMEOUT, "evaluating".into()))??;
        if let Some(details) = r.get("exceptionDetails") {
            let text = details
                .pointer("/exception/description")
                .and_then(Value::as_str)
                .or_else(|| details.get("text").and_then(Value::as_str))
                .unwrap_or("Evaluation failed")
                .to_string();
            return Err(Error::Evaluation(text));
        }
        Ok(r.get("result").cloned().unwrap_or(Value::Null))
    }

    fn release(&self, result: &Value) {
        if let Some(id) = result.get("objectId").and_then(Value::as_str) {
            self.conn.fire(
                "Runtime.releaseObject",
                Some(json!({"objectId": id})),
                self.s(),
            );
        }
    }

    /// `page.goto(url)` (`waitUntil="load"`).
    pub async fn goto(&self, url: &str) -> Result<(), Error> {
        let deadline = Instant::now() + DEFAULT_TIMEOUT;
        let url = complete_user_url(url);
        let frame = self.main_frame().ok_or(Error::Closed)?;
        let seen = lock(&self.shared.state).main_navigations().len();
        let navigate = self.send(
            "Page.navigate",
            Some(json!({"url": url, "frameId": frame, "referrerPolicy": "unsafeUrl"})),
        );
        let r = tokio::time::timeout_at(deadline, navigate)
            .await
            .map_err(|_| Error::Timeout(DEFAULT_TIMEOUT, format!("navigating to \"{url}\"")))??;
        if r.get("isDownload").and_then(Value::as_bool) == Some(true) {
            return Err(Error::Navigation("Download is starting".into()));
        }
        if let Some(text) = r.get("errorText").and_then(Value::as_str) {
            return Err(Error::Navigation(format!("{text} at {url}")));
        }
        if let Some(loader) = r.get("loaderId").and_then(Value::as_str) {
            let loader = loader.to_string();
            let what = format!("navigating to \"{url}\", waiting until \"load\"");
            self.shared
                .wait(deadline, &what, |s| {
                    let event = s.main_navigations().iter().skip(seen).find(|n| {
                        n.new_document.as_ref().is_some_and(|d| {
                            d.document_id.as_deref() == Some(loader.as_str()) || n.error.is_none()
                        })
                    })?;
                    let doc = event.new_document.as_ref()?;
                    if doc.document_id.as_deref() != Some(loader.as_str()) {
                        return Some(Err(Error::Navigation(format!(
                            "Navigation to \"{url}\" is interrupted by another navigation to \"{}\"",
                            event.url
                        ))));
                    }
                    Some(match &event.error {
                        Some(e) => Err(Error::Navigation(e.clone())),
                        None => Ok(()),
                    })
                })
                .await?;
        }
        self.wait_for(Lifecycle::Load, deadline).await
    }

    async fn wait_for(&self, event: Lifecycle, deadline: Instant) -> Result<(), Error> {
        let adds = lock(&self.shared.state).main_adds(event);
        if lock(&self.shared.state).main_has(event) {
            return Ok(());
        }
        self.shared
            .wait(deadline, "waiting for the load state", |s| {
                (s.main_adds(event) > adds).then_some(Ok(()))
            })
            .await
    }

    /// `page.wait_for_load_state(state="networkidle")`.
    pub async fn wait_for_networkidle(&self) -> Result<(), Error> {
        self.wait_for(Lifecycle::NetworkIdle, Instant::now() + DEFAULT_TIMEOUT)
            .await
    }

    /// `page.evaluate(expression)` (the main world, by value).
    pub async fn evaluate(&self, expression: &str) -> Result<Value, Error> {
        let r = self
            .evaluate_in(false, expression, true, Instant::now() + DEFAULT_TIMEOUT)
            .await?;
        Ok(r.get("value").cloned().unwrap_or(Value::Null))
    }

    async fn fill_attempt(&self, call: &str) -> Result<Result<bool, String>, Error> {
        let r = self
            .evaluate_in(true, call, true, Instant::now() + DEFAULT_TIMEOUT)
            .await?;
        let status = r.get("value").and_then(Value::as_str).unwrap_or_default();
        Ok(match status {
            "needsinput" => Ok(true),
            "done" => Ok(false),
            s => Err(s.to_string()),
        })
    }

    /// `page.fill(selector, value)`.
    pub async fn fill(&self, selector: &str, value: &str) -> Result<(), Error> {
        let call = format!(
            "({ELEMENT_SCRIPT})({}, \"fill\", {})",
            serde_json::to_string(selector).unwrap_or_default(),
            serde_json::to_string(value).unwrap_or_default()
        );
        let mut retry = Retry::new();
        let needs_input = loop {
            if !retry.pause().await {
                return Err(retry.timeout("page.fill"));
            }
            let r = tokio::time::timeout_at(retry.deadline, self.fill_attempt(&call)).await;
            if let Some(v) = retry.outcome(r)? {
                break v;
            }
        };
        if !needs_input {
            return Ok(());
        }
        if value.is_empty() {
            self.press_delete().await
        } else {
            self.send("Input.insertText", Some(json!({"text": value})))
                .await
                .map(|_| ())
        }
    }

    /// `keyboard.press("Delete")` (a raw key, no text, no commands on
    /// Linux).
    async fn press_delete(&self) -> Result<(), Error> {
        self.send(
            "Input.dispatchKeyEvent",
            Some(json!({
                "type": "rawKeyDown", "modifiers": 0, "windowsVirtualKeyCode": 46,
                "code": "Delete", "key": "Delete", "text": "", "unmodifiedText": "",
                "autoRepeat": false, "location": 0, "isKeypad": false,
            })),
        )
        .await?;
        self.send(
            "Input.dispatchKeyEvent",
            Some(json!({
                "type": "keyUp", "modifiers": 0, "key": "Delete",
                "windowsVirtualKeyCode": 46, "code": "Delete", "location": 0,
            })),
        )
        .await
        .map(|_| ())
    }

    /// `page.click(selector)`: visible, enabled and stable, scrolled into
    /// view, the middle of its first content quad inside the viewport,
    /// the hit target checked, then the three mouse events.
    pub async fn click(&self, selector: &str) -> Result<(), Error> {
        let find = format!(
            "({ELEMENT_SCRIPT})({}, \"click\", \"\")",
            serde_json::to_string(selector).unwrap_or_default()
        );
        let mut retry = Retry::new();
        let (x, y) = loop {
            if !retry.pause().await {
                return Err(retry.timeout("page.click"));
            }
            let r = tokio::time::timeout_at(retry.deadline, self.click_attempt(&find)).await;
            if let Some(v) = retry.outcome(r)? {
                break v;
            }
        };
        let mouse = |kind: &str, button: &str, buttons: u8, force: Option<f64>| {
            let mut p = json!({
                "type": kind, "button": button, "buttons": buttons, "x": x, "y": y,
                "modifiers": 0,
            });
            if kind != "mouseMoved" {
                p["clickCount"] = json!(1);
            }
            if let Some(f) = force {
                p["force"] = json!(f);
            }
            p
        };
        self.send(
            "Input.dispatchMouseEvent",
            Some(mouse("mouseMoved", "none", 0, Some(0.0))),
        )
        .await?;
        self.send(
            "Input.dispatchMouseEvent",
            Some(mouse("mousePressed", "left", 1, Some(0.5))),
        )
        .await?;
        self.send(
            "Input.dispatchMouseEvent",
            Some(mouse("mouseReleased", "left", 0, None)),
        )
        .await?;
        // `inputActionEpilogue`: a round trip, so that the events the
        // click caused have arrived.
        let _ = self.send("Page.enable", None).await;
        Ok(())
    }

    async fn click_attempt(&self, find: &str) -> Result<Result<(f64, f64), String>, Error> {
        let deadline = Instant::now() + DEFAULT_TIMEOUT;
        let handle = self.evaluate_in(true, find, false, deadline).await?;
        if let Some(status) = handle.get("value").and_then(Value::as_str) {
            return Ok(Err(status.to_string()));
        }
        let Some(object) = handle.get("objectId").and_then(Value::as_str) else {
            return Ok(Err("error:notconnected".into()));
        };
        let outcome = self.point_for(object, deadline).await;
        self.release(&handle);
        outcome
    }

    async fn point_for(
        &self,
        object: &str,
        deadline: Instant,
    ) -> Result<Result<(f64, f64), String>, Error> {
        self.send(
            "DOM.scrollIntoViewIfNeeded",
            Some(json!({"objectId": object})),
        )
        .await?;
        let quads = self
            .send("DOM.getContentQuads", Some(json!({"objectId": object})))
            .await?;
        let size = self
            .evaluate_in(
                true,
                "({ width: innerWidth, height: innerHeight })",
                true,
                deadline,
            )
            .await?;
        let width = size
            .pointer("/value/width")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let height = size
            .pointer("/value/height")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let quads: Vec<Vec<(f64, f64)>> = quads
            .get("quads")
            .and_then(Value::as_array)
            .map(|qs| {
                qs.iter()
                    .filter_map(Value::as_array)
                    .map(|q| {
                        q.chunks(2)
                            .map(|p| {
                                (
                                    p.first().and_then(Value::as_f64).unwrap_or(0.0),
                                    p.get(1).and_then(Value::as_f64).unwrap_or(0.0),
                                )
                            })
                            .collect()
                    })
                    .collect()
            })
            .unwrap_or_default();
        if quads.is_empty() {
            return Ok(Err("error:notvisible".into()));
        }
        let Some(quad) = quads
            .iter()
            .map(|q| {
                q.iter()
                    .map(|(x, y)| (x.clamp(0.0, width.max(0.0)), y.clamp(0.0, height.max(0.0))))
                    .collect::<Vec<_>>()
            })
            .find(|q| quad_area(q) > 0.99)
        else {
            return Ok(Err("error:notinviewport".into()));
        };
        let (mut x, mut y) = (0.0, 0.0);
        for (px, py) in &quad {
            x += px / 4.0;
            y += py / 4.0;
        }
        let hit = self
            .send(
                "Runtime.callFunctionOn",
                Some(json!({
                    "functionDeclaration": "function(x, y) { const hit = document.elementFromPoint(x, y); return !!hit && (hit === this || this.contains(hit)); }",
                    "objectId": object,
                    "arguments": [{"value": x}, {"value": y}],
                    "returnByValue": true,
                })),
            )
            .await?;
        if hit.pointer("/result/value").and_then(Value::as_bool) != Some(true) {
            return Ok(Err("element does not receive pointer events".into()));
        }
        Ok(Ok((x, y)))
    }

    /// `page.set_viewport_size({"width": …, "height": …})`: nothing sent
    /// when it is the viewport already applied.
    pub async fn set_viewport_size(&self, width: i64, height: i64) -> Result<(), Error> {
        let viewport = Viewport { width, height };
        if *lock(&self.metrics) == Some(viewport) {
            return Ok(());
        }
        let bounds = self.conn.send_now(
            "Browser.setWindowBounds",
            Some(json!({"windowId": self.window, "bounds": viewport.bounds()})),
            self.s(),
        );
        let metrics = self.conn.send_now(
            "Emulation.setDeviceMetricsOverride",
            Some(viewport.metrics()),
            self.s(),
        );
        let (bounds, metrics) = (
            bounds.await.unwrap_or(Err(Error::Closed)),
            metrics.await.unwrap_or(Err(Error::Closed)),
        );
        bounds?;
        metrics?;
        *lock(&self.metrics) = Some(viewport);
        Ok(())
    }

    /// `page.screenshot(type="png")`: the viewport, the caret hidden.
    pub async fn screenshot_png(&self) -> Result<Vec<u8>, Error> {
        let deadline = Instant::now() + DEFAULT_TIMEOUT;
        let viewport = match *lock(&self.metrics) {
            Some(v) => (v.width as f64, v.height as f64),
            None => (0.0, 0.0),
        };
        let prepare = format!("({PREPARE_FOR_SCREENSHOTS})(undefined, true, false, false)");
        let _ = self.evaluate_in(true, &prepare, true, deadline).await;
        if let Ok(r) = self
            .evaluate_in(true, "document.fonts.ready", false, deadline)
            .await
        {
            self.release(&r);
        }
        let shot = async {
            let metrics = self.send("Page.getLayoutMetrics", None).await?;
            let vv = metrics
                .get("visualViewport")
                .cloned()
                .unwrap_or(Value::Null);
            let num = |k: &str| vv.get(k).and_then(Value::as_f64).unwrap_or(0.0);
            let scale = vv.get("scale").and_then(Value::as_f64).unwrap_or(1.0);
            let clip = json!({
                "x": json_number(num("pageX")),
                "y": json_number(num("pageY")),
                "width": ((viewport.0 / scale) + 1e-3).floor() as i64,
                "height": ((viewport.1 / scale) + 1e-3).floor() as i64,
                "scale": json_number(scale),
            });
            self.send(
                "Page.captureScreenshot",
                Some(json!({"format": "png", "clip": clip, "captureBeyondViewport": false})),
            )
            .await
        }
        .await;
        let _ = self
            .evaluate_in(
                true,
                "window.__pwCleanupScreenshot && window.__pwCleanupScreenshot()",
                true,
                deadline,
            )
            .await;
        let shot = shot?;
        let data = shot.get("data").and_then(Value::as_str).unwrap_or_default();
        base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|e| Error::Evaluation(e.to_string()))
    }

    /// `page.emulate_media(media="screen")`.
    pub async fn emulate_media_screen(&self) -> Result<(), Error> {
        self.send("Emulation.setEmulatedMedia", Some(media_params("screen")))
            .await
            .map(|_| ())
    }

    /// `page.pdf()` with Playwright's defaults (Letter, no margins, no
    /// background), read from the protocol stream.
    pub async fn pdf(&self) -> Result<Vec<u8>, Error> {
        let r = self
            .send(
                "Page.printToPDF",
                Some(json!({
                    "transferMode": "ReturnAsStream",
                    "landscape": false,
                    "displayHeaderFooter": false,
                    "headerTemplate": "",
                    "footerTemplate": "",
                    "printBackground": false,
                    "scale": 1,
                    "paperWidth": 8.5,
                    "paperHeight": 11,
                    "marginTop": 0,
                    "marginBottom": 0,
                    "marginLeft": 0,
                    "marginRight": 0,
                    "pageRanges": "",
                    "preferCSSPageSize": false,
                    "generateTaggedPDF": false,
                    "generateDocumentOutline": false,
                })),
            )
            .await?;
        let handle = r.get("stream").cloned().unwrap_or(Value::Null);
        let mut out = Vec::new();
        loop {
            let chunk = self
                .send("IO.read", Some(json!({"handle": handle})))
                .await?;
            let data = chunk
                .get("data")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if chunk.get("base64Encoded").and_then(Value::as_bool) == Some(true) {
                out.extend(
                    base64::engine::general_purpose::STANDARD
                        .decode(data)
                        .map_err(|e| Error::Evaluation(e.to_string()))?,
                );
            } else {
                out.extend_from_slice(data.as_bytes());
            }
            if chunk.get("eof").and_then(Value::as_bool) == Some(true) {
                break;
            }
        }
        self.send("IO.close", Some(json!({"handle": handle})))
            .await?;
        Ok(out)
    }
}

/// A JavaScript number as JSON: an integral value without a fraction, as
/// `JSON.stringify` writes it.
fn json_number(x: f64) -> Value {
    if x.fract() == 0.0 && x.abs() < 9.0e15 {
        json!(x as i64)
    } else {
        json!(x)
    }
}

fn quad_area(q: &[(f64, f64)]) -> f64 {
    let mut area = 0.0;
    for i in 0..q.len() {
        let (x1, y1) = q[i];
        let (x2, y2) = q[(i + 1) % q.len()];
        area += (x1 * y2 - x2 * y1) / 2.0;
    }
    area.abs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_and_numbers_as_playwright_writes_them() {
        assert_eq!(complete_user_url("localhost:3000"), "http://localhost:3000");
        assert_eq!(
            complete_user_url("127.0.0.1:3000/x"),
            "http://127.0.0.1:3000/x"
        );
        assert_eq!(complete_user_url("https://g"), "https://g");
        assert_eq!(json_number(0.0).to_string(), "0");
        assert_eq!(json_number(1.5).to_string(), "1.5");
        assert_eq!(
            quad_area(&[(0.0, 0.0), (2.0, 0.0), (2.0, 3.0), (0.0, 3.0)]),
            6.0
        );
        let m = Connection::message(3, "Log.enable", Some(json!({})), Some("S"));
        assert_eq!(
            String::from_utf8(m).unwrap(),
            "{\"id\":3,\"method\":\"Log.enable\",\"params\":{},\"sessionId\":\"S\"}\0"
        );
    }
}
