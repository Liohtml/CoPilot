//! The frame tree and its lifecycle as Playwright's `FrameManager` keeps it
//! (`server/frames.js`, `chromium/crPage.js`, `chromium/crNetworkManager.js`
//! of playwright-core 1.59): documents committed and pending, the
//! `commit` / `domcontentloaded` / `load` events, and `networkidle` — not
//! Chromium's, but Playwright's own: a frame is idle once no request it
//! started has been in flight for 500 ms, and the main frame once it and
//! every child frame are.
//!
//! Pure: the page's event loop feeds it the protocol events
//! ([`State::on_event`]) and runs the 500 ms timers it asks for
//! ([`Timer`]), calling [`State::timer_fired`] when one expires.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

/// How long a frame must have no request in flight to be idle.
pub const NETWORK_IDLE_MS: u64 = 500;

/// A lifecycle event, as Playwright names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lifecycle {
    /// The document committed.
    Commit,
    /// `DOMContentLoaded`.
    DomContentLoaded,
    /// `load`.
    Load,
    /// Playwright's network idle.
    NetworkIdle,
}

/// A 500 ms timer to start for a frame; [`State::timer_fired`] is called
/// with the same values when it expires (a stopped timer's generation is
/// stale by then, and ignored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timer {
    /// The frame.
    pub frame: String,
    /// The timer's generation.
    pub generation: u64,
}

/// A document of a frame: Chromium's loader id and the request that loads
/// it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Document {
    /// The loader id (`undefined` until known).
    pub document_id: Option<String>,
    /// The navigation request's id.
    pub request: Option<String>,
}

/// A navigation of a frame, as `_fireInternalFrameNavigation` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Navigation {
    /// The URL after it.
    pub url: String,
    /// The new document (`None`: a same-document navigation).
    pub new_document: Option<Document>,
    /// The error text of an aborted navigation.
    pub error: Option<String>,
}

#[derive(Debug, Default)]
struct Frame {
    parent: Option<String>,
    children: Vec<String>,
    url: String,
    fired: HashSet<Lifecycle>,
    /// How many times each event was added (a waiter for "the next add").
    adds: HashMap<Lifecycle, u64>,
    inflight: Vec<String>,
    idle_self: bool,
    timer: Option<u64>,
    current: Document,
    pending: Option<Document>,
    navigations: Vec<Navigation>,
    detached: bool,
}

#[derive(Debug, Clone)]
struct Request {
    frame: String,
    favicon: bool,
    document_id: Option<String>,
}

/// The frames of one page and the requests in flight.
#[derive(Debug, Default)]
pub struct State {
    frames: HashMap<String, Frame>,
    main: Option<String>,
    requests: HashMap<String, Request>,
    generation: u64,
    timers: Vec<Timer>,
    /// The page's own target id (its main frame's id).
    target_id: String,
    /// Execution contexts: id → (frame, is the default world).
    contexts: HashMap<i64, (String, bool)>,
    /// The utility world's name.
    utility_world: String,
    /// The worker sessions, whose requests belong to the main frame.
    workers: HashSet<String>,
    /// The page crashed or was closed.
    pub closed: bool,
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

impl State {
    /// A page whose target is `target_id`, with Playwright's utility world
    /// named `utility_world`.
    pub fn new(target_id: &str, utility_world: &str) -> Self {
        Self {
            target_id: target_id.to_string(),
            utility_world: utility_world.to_string(),
            ..Self::default()
        }
    }

    /// The timers to start, taken.
    pub fn take_timers(&mut self) -> Vec<Timer> {
        std::mem::take(&mut self.timers)
    }

    /// The main frame's id.
    pub fn main_frame(&self) -> Option<&str> {
        self.main.as_deref()
    }

    /// Mark `session` a dedicated worker's.
    pub fn add_worker(&mut self, session: &str) {
        self.workers.insert(session.to_string());
    }

    /// Whether the main frame has fired `event` on its current document.
    pub fn main_has(&self, event: Lifecycle) -> bool {
        self.main_ref().is_some_and(|f| f.fired.contains(&event))
    }

    /// How many times the main frame has added `event`.
    pub fn main_adds(&self, event: Lifecycle) -> u64 {
        self.main_ref()
            .and_then(|f| f.adds.get(&event).copied())
            .unwrap_or(0)
    }

    /// The main frame's URL.
    pub fn main_url(&self) -> String {
        self.main_ref().map(|f| f.url.clone()).unwrap_or_default()
    }

    /// The main frame's navigations so far (an index to scan from).
    pub fn main_navigations(&self) -> &[Navigation] {
        self.main_ref().map_or(&[], |f| f.navigations.as_slice())
    }

    /// The default (`main`) or utility world's execution context of the
    /// main frame's current document.
    pub fn main_context(&self, utility: bool) -> Option<i64> {
        let main = self.main.as_deref()?;
        self.contexts
            .iter()
            .filter(|(_, (frame, default))| frame == main && *default != utility)
            .map(|(id, _)| *id)
            .max()
    }

    fn main_ref(&self) -> Option<&Frame> {
        self.main.as_ref().and_then(|m| self.frames.get(m))
    }

    // --- the frame manager -----------------------------------------------

    fn new_frame(&mut self, id: &str, parent: Option<String>) {
        let mut frame = Frame {
            parent,
            ..Frame::default()
        };
        frame.fired.insert(Lifecycle::Commit);
        self.frames.insert(id.to_string(), frame);
        self.start_idle_timer(id);
    }

    /// `frameAttached(frameId, parentFrameId)`.
    fn frame_attached(&mut self, id: &str, parent: Option<&str>) {
        let parent = parent.filter(|p| self.frames.contains_key(*p));
        match parent {
            None => {
                if let Some(old) = self.main.clone() {
                    if old != id {
                        if let Some(frame) = self.frames.remove(&old) {
                            for child in &frame.children {
                                if let Some(c) = self.frames.get_mut(child) {
                                    c.parent = Some(id.to_string());
                                }
                            }
                            self.frames.insert(id.to_string(), frame);
                        }
                        self.main = Some(id.to_string());
                    }
                } else {
                    self.main = Some(id.to_string());
                    self.new_frame(id, None);
                }
            }
            Some(parent) => {
                if self.frames.contains_key(id) {
                    return;
                }
                let parent = parent.to_string();
                self.new_frame(id, Some(parent.clone()));
                if let Some(p) = self.frames.get_mut(&parent) {
                    p.children.push(id.to_string());
                }
            }
        }
    }

    fn remove_children(&mut self, id: &str) {
        let children = self
            .frames
            .get(id)
            .map(|f| f.children.clone())
            .unwrap_or_default();
        for child in children {
            self.remove_frame(&child);
        }
        if let Some(f) = self.frames.get_mut(id) {
            f.children.clear();
        }
    }

    fn remove_frame(&mut self, id: &str) {
        self.remove_children(id);
        if let Some(mut frame) = self.frames.remove(id) {
            frame.detached = true;
            if let Some(parent) = frame.parent.as_ref().and_then(|p| self.frames.get_mut(p)) {
                parent.children.retain(|c| c != id);
            }
        }
        self.contexts.retain(|_, (frame, _)| frame != id);
    }

    /// `frameCommittedNewDocumentNavigation`.
    fn committed(&mut self, id: &str, url: String, document_id: Option<String>) {
        if !self.frames.contains_key(id) {
            return;
        }
        self.remove_children(id);
        let Some(frame) = self.frames.get_mut(id) else {
            return;
        };
        frame.url = url.clone();
        let mut keep_pending = None;
        let current = match frame.pending.take() {
            Some(mut pending) => {
                if pending.document_id.is_none() {
                    pending.document_id = document_id.clone();
                }
                if pending.document_id == document_id {
                    pending
                } else {
                    keep_pending = Some(pending);
                    Document {
                        document_id: document_id.clone(),
                        request: None,
                    }
                }
            }
            None => Document {
                document_id: document_id.clone(),
                request: None,
            },
        };
        frame.current = current.clone();
        self.clear_lifecycle(id);
        if let Some(frame) = self.frames.get_mut(id) {
            frame.navigations.push(Navigation {
                url,
                new_document: Some(current),
                error: None,
            });
            frame.pending = keep_pending;
        }
    }

    /// `frameCommittedSameDocumentNavigation`.
    fn same_document(&mut self, id: &str, url: String) {
        let Some(frame) = self.frames.get_mut(id) else {
            return;
        };
        if frame
            .pending
            .as_ref()
            .is_some_and(|p| p.document_id.is_none() && p.request.is_none())
        {
            frame.pending = None;
        }
        frame.url = url.clone();
        frame.navigations.push(Navigation {
            url,
            new_document: None,
            error: None,
        });
    }

    /// `frameAbortedNavigation`.
    fn aborted(&mut self, id: &str, error: String, document_id: Option<&str>) {
        let Some(frame) = self.frames.get_mut(id) else {
            return;
        };
        let Some(pending) = frame.pending.clone() else {
            return;
        };
        if document_id.is_some() && pending.document_id.as_deref() != document_id {
            return;
        }
        frame.pending = None;
        let url = frame.url.clone();
        frame.navigations.push(Navigation {
            url,
            new_document: Some(pending),
            error: Some(error),
        });
    }

    /// `frameRequestedNavigation(frameId, documentId)`.
    fn requested(&mut self, id: &str, document_id: Option<String>) {
        let inflight = self.requests.clone();
        let Some(frame) = self.frames.get_mut(id) else {
            return;
        };
        if frame
            .pending
            .as_ref()
            .is_some_and(|p| p.document_id == document_id)
        {
            return;
        }
        let request = document_id.as_ref().and_then(|d| {
            frame
                .inflight
                .iter()
                .find(|r| {
                    inflight
                        .get(*r)
                        .is_some_and(|q| q.document_id.as_ref() == Some(d))
                })
                .cloned()
        });
        frame.pending = Some(Document {
            document_id,
            request,
        });
    }

    /// `_onLifecycleEvent(event)`.
    fn lifecycle(&mut self, id: &str, event: Lifecycle) {
        let Some(frame) = self.frames.get_mut(id) else {
            return;
        };
        if !frame.fired.insert(event) {
            return;
        }
        *frame.adds.entry(event).or_default() += 1;
        self.recalculate_main(None);
    }

    /// `_onClearLifecycle()`.
    fn clear_lifecycle(&mut self, id: &str) {
        let Some(frame) = self.frames.get_mut(id) else {
            return;
        };
        frame.fired.clear();
        let keep = frame.current.request.clone();
        frame.inflight.retain(|r| Some(r) == keep.as_ref());
        let empty = frame.inflight.is_empty();
        self.stop_idle_timer(id);
        if empty {
            self.start_idle_timer(id);
        }
        self.recalculate_main(Some(id));
        self.lifecycle(id, Lifecycle::Commit);
    }

    fn start_idle_timer(&mut self, id: &str) {
        self.generation += 1;
        let generation = self.generation;
        let Some(frame) = self.frames.get_mut(id) else {
            return;
        };
        if frame.fired.contains(&Lifecycle::NetworkIdle) || frame.detached {
            return;
        }
        frame.timer = Some(generation);
        self.timers.push(Timer {
            frame: id.to_string(),
            generation,
        });
    }

    fn stop_idle_timer(&mut self, id: &str) {
        if let Some(frame) = self.frames.get_mut(id) {
            frame.timer = None;
            frame.idle_self = false;
        }
    }

    /// A timer [`State::take_timers`] handed out expired.
    pub fn timer_fired(&mut self, frame_id: &str, generation: u64) {
        let Some(frame) = self.frames.get_mut(frame_id) else {
            return;
        };
        if frame.timer != Some(generation) {
            return;
        }
        frame.timer = None;
        frame.idle_self = true;
        self.recalculate_main(None);
    }

    fn recalculate_main(&mut self, allow_removing: Option<&str>) {
        if let Some(main) = self.main.clone() {
            self.recalculate(&main, allow_removing);
        }
    }

    /// `_recalculateNetworkIdle(frameThatAllowsRemovingNetworkIdle)`.
    fn recalculate(&mut self, id: &str, allow_removing: Option<&str>) {
        let Some(frame) = self.frames.get(id) else {
            return;
        };
        let mut idle = frame.idle_self;
        for child in frame.children.clone() {
            self.recalculate(&child, allow_removing);
            if !self
                .frames
                .get(&child)
                .is_some_and(|c| c.fired.contains(&Lifecycle::NetworkIdle))
            {
                idle = false;
            }
        }
        let Some(frame) = self.frames.get_mut(id) else {
            return;
        };
        if idle && frame.fired.insert(Lifecycle::NetworkIdle) {
            *frame.adds.entry(Lifecycle::NetworkIdle).or_default() += 1;
        }
        if allow_removing != Some(id) && frame.fired.contains(&Lifecycle::NetworkIdle) && !idle {
            frame.fired.remove(&Lifecycle::NetworkIdle);
        }
    }

    fn inflight_started(&mut self, request_id: &str) {
        let Some(req) = self.requests.get(request_id) else {
            return;
        };
        if req.favicon {
            return;
        }
        let frame_id = req.frame.clone();
        let Some(frame) = self.frames.get_mut(&frame_id) else {
            return;
        };
        if !frame.inflight.iter().any(|r| r == request_id) {
            frame.inflight.push(request_id.to_string());
        }
        if frame.inflight.len() == 1 {
            self.stop_idle_timer(&frame_id);
        }
    }

    fn inflight_finished(&mut self, req: &Request, request_id: &str) {
        if req.favicon {
            return;
        }
        let Some(frame) = self.frames.get_mut(&req.frame) else {
            return;
        };
        let before = frame.inflight.len();
        frame.inflight.retain(|r| r != request_id);
        if frame.inflight.len() == before {
            return;
        }
        if frame.inflight.is_empty() {
            let id = req.frame.clone();
            self.start_idle_timer(&id);
        }
    }

    // --- protocol events -------------------------------------------------

    /// `Page.getFrameTree`'s answer (`_handleFrameTree`).
    pub fn frame_tree(&mut self, tree: &Value) {
        let Some(frame) = tree.get("frame") else {
            return;
        };
        let id = str_of(frame, "id").unwrap_or_default().to_string();
        self.frame_attached(&id, str_of(frame, "parentId"));
        self.navigated(frame);
        if let Some(children) = tree.get("childFrames").and_then(Value::as_array) {
            for child in children {
                self.frame_tree(child);
            }
        }
    }

    fn navigated(&mut self, frame: &Value) {
        let id = str_of(frame, "id").unwrap_or_default();
        let url = format!(
            "{}{}",
            str_of(frame, "url").unwrap_or_default(),
            str_of(frame, "urlFragment").unwrap_or_default()
        );
        let loader = str_of(frame, "loaderId").map(str::to_string);
        self.committed(id, url, loader);
    }

    /// One protocol event of the page's session, or of one of its worker
    /// or frame sessions (`session`).
    pub fn on_event(&mut self, session: &str, method: &str, params: &Value) {
        match method {
            "Page.frameAttached" => {
                if let Some(id) = str_of(params, "frameId") {
                    self.frame_attached(id, str_of(params, "parentFrameId"));
                }
            }
            "Page.frameDetached" => {
                if let Some(id) = str_of(params, "frameId") {
                    if str_of(params, "reason") == Some("swap") {
                        self.remove_children(id);
                    } else if self.frames.contains_key(id) && self.main.as_deref() != Some(id) {
                        self.remove_frame(id);
                        self.recalculate_main(None);
                    }
                }
            }
            "Page.frameNavigated" => {
                if let Some(frame) = params.get("frame") {
                    self.navigated(frame);
                }
            }
            "Page.navigatedWithinDocument" => {
                if let Some(id) = str_of(params, "frameId") {
                    let url = str_of(params, "url").unwrap_or_default().to_string();
                    self.same_document(id, url);
                }
            }
            "Page.frameRequestedNavigation" => {
                if str_of(params, "disposition") == Some("currentTab") {
                    if let Some(id) = str_of(params, "frameId") {
                        self.requested(id, None);
                    }
                }
            }
            "Page.lifecycleEvent" => {
                let id = str_of(params, "frameId").unwrap_or_default();
                match str_of(params, "name") {
                    Some("load") => self.lifecycle(id, Lifecycle::Load),
                    Some("DOMContentLoaded") => self.lifecycle(id, Lifecycle::DomContentLoaded),
                    _ => {}
                }
            }
            "Network.requestWillBeSent" => self.request_will_be_sent(session, params),
            "Network.loadingFinished" => {
                if let Some(id) = str_of(params, "requestId") {
                    if let Some(req) = self.requests.remove(id) {
                        self.inflight_finished(&req, id);
                    }
                }
            }
            "Network.loadingFailed" => {
                if let Some(id) = str_of(params, "requestId") {
                    if let Some(req) = self.requests.remove(id) {
                        self.inflight_finished(&req, id);
                        let pending = self
                            .frames
                            .get(&req.frame)
                            .and_then(|f| f.pending.clone())
                            .filter(|p| p.request.as_deref() == Some(id));
                        if let Some(pending) = pending {
                            let mut text = str_of(params, "errorText")
                                .or_else(|| str_of(params, "blockedReason"))
                                .unwrap_or_default()
                                .to_string();
                            if params.get("canceled").and_then(Value::as_bool) == Some(true) {
                                text.push_str("; maybe frame was detached?");
                            }
                            let frame = req.frame.clone();
                            self.aborted(&frame, text, pending.document_id.as_deref());
                        }
                    }
                }
            }
            "Runtime.executionContextCreated" => {
                let Some(ctx) = params.get("context") else {
                    return;
                };
                let aux = ctx.get("auxData");
                let frame = aux.and_then(|a| str_of(a, "frameId")).unwrap_or_default();
                let default = aux
                    .and_then(|a| a.get("isDefault"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let name = str_of(ctx, "name").unwrap_or_default();
                if !self.frames.contains_key(frame) || (!default && name != self.utility_world) {
                    return;
                }
                if let Some(id) = ctx.get("id").and_then(Value::as_i64) {
                    self.contexts.insert(id, (frame.to_string(), default));
                }
            }
            "Runtime.executionContextDestroyed" => {
                if let Some(id) = params.get("executionContextId").and_then(Value::as_i64) {
                    self.contexts.remove(&id);
                }
            }
            "Runtime.executionContextsCleared" => {
                if !self.workers.contains(session) {
                    self.contexts.clear();
                }
            }
            "Inspector.targetCrashed" => self.closed = true,
            _ => {}
        }
    }

    fn request_will_be_sent(&mut self, session: &str, params: &Value) {
        let Some(request) = params.get("request") else {
            return;
        };
        let url = str_of(request, "url").unwrap_or_default();
        if url.starts_with("data:") {
            return;
        }
        let Some(request_id) = str_of(params, "requestId").map(str::to_string) else {
            return;
        };
        let mut redirected_favicon = false;
        if params.get("redirectResponse").is_some() {
            if let Some(old) = self.requests.remove(&request_id) {
                redirected_favicon = old.favicon;
                self.inflight_finished(&old, &request_id);
            }
        }
        let frame = match str_of(params, "frameId") {
            Some(f) if self.frames.contains_key(f) => Some(f.to_string()),
            Some(f) if f == self.target_id => {
                self.frame_attached(f, None);
                Some(f.to_string())
            }
            Some(_) => None,
            None if self.workers.contains(session) => self.main.clone(),
            None => None,
        };
        let Some(frame) = frame else {
            return;
        };
        let navigation = params.get("loaderId").and_then(Value::as_str) == Some(&request_id)
            && str_of(params, "type") == Some("Document");
        let document_id = navigation.then(|| request_id.clone());
        self.requests.insert(
            request_id.clone(),
            Request {
                frame: frame.clone(),
                favicon: url.ends_with("/favicon.ico") || redirected_favicon,
                document_id: document_id.clone(),
            },
        );
        self.inflight_started(&request_id);
        if let Some(document_id) = document_id {
            if let Some(f) = self.frames.get_mut(&frame) {
                f.pending = Some(Document {
                    document_id: Some(document_id),
                    request: Some(request_id),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn page() -> State {
        let mut s = State::new("T", "world");
        s.frame_tree(&json!({"frame": {"id": "T", "loaderId": "L0", "url": "about:blank"}}));
        s
    }

    fn fire_timers(s: &mut State) {
        for t in s.take_timers() {
            s.timer_fired(&t.frame, t.generation);
        }
    }

    #[test]
    fn idle_after_the_last_request_and_reset_by_a_new_document() {
        let mut s = page();
        assert_eq!(s.main_frame(), Some("T"));
        // A navigation: its request, the commit, a subresource.
        s.on_event(
            "S",
            "Network.requestWillBeSent",
            &json!({"requestId": "L1", "loaderId": "L1", "frameId": "T", "type": "Document",
                    "request": {"url": "http://g/login"}}),
        );
        let stale = s.take_timers();
        s.on_event(
            "S",
            "Page.frameNavigated",
            &json!({"frame": {"id": "T", "loaderId": "L1", "url": "http://g/login"}}),
        );
        assert!(s.main_has(Lifecycle::Commit));
        assert_eq!(
            s.main_navigations()
                .last()
                .and_then(|n| n.new_document.clone()),
            Some(Document {
                document_id: Some("L1".into()),
                request: Some("L1".into())
            })
        );
        s.on_event("S", "Network.loadingFinished", &json!({"requestId": "L1"}));
        s.on_event(
            "S",
            "Network.requestWillBeSent",
            &json!({"requestId": "r2", "loaderId": "L1", "frameId": "T", "type": "Script",
                    "request": {"url": "http://g/app.js"}}),
        );
        // The timer started when the document finished was stopped.
        for t in s.take_timers() {
            s.timer_fired(&t.frame, t.generation);
        }
        for t in stale {
            s.timer_fired(&t.frame, t.generation);
        }
        assert!(!s.main_has(Lifecycle::NetworkIdle));
        s.on_event("S", "Network.loadingFinished", &json!({"requestId": "r2"}));
        s.on_event(
            "S",
            "Page.lifecycleEvent",
            &json!({"frameId": "T", "name": "load", "loaderId": "L1"}),
        );
        assert!(s.main_has(Lifecycle::Load));
        fire_timers(&mut s);
        assert!(s.main_has(Lifecycle::NetworkIdle));
        assert_eq!(s.main_adds(Lifecycle::NetworkIdle), 1);
        // A new document clears the events.
        s.on_event(
            "S",
            "Page.frameNavigated",
            &json!({"frame": {"id": "T", "loaderId": "L3", "url": "http://g/"}}),
        );
        assert!(!s.main_has(Lifecycle::NetworkIdle));
        assert!(!s.main_has(Lifecycle::Load));
        fire_timers(&mut s);
        assert!(s.main_has(Lifecycle::NetworkIdle));
        assert_eq!(s.main_adds(Lifecycle::NetworkIdle), 2);
    }

    #[test]
    fn favicons_data_urls_and_unknown_frames_do_not_count() {
        let mut s = page();
        fire_timers(&mut s);
        assert!(s.main_has(Lifecycle::NetworkIdle));
        for (id, url, frame) in [
            ("a", "http://g/favicon.ico", "T"),
            ("b", "data:image/png;base64,AA", "T"),
            ("c", "http://g/x", "other"),
        ] {
            s.on_event(
                "S",
                "Network.requestWillBeSent",
                &json!({"requestId": id, "loaderId": "L0", "frameId": frame, "type": "Other",
                        "request": {"url": url}}),
            );
        }
        assert!(s.main_has(Lifecycle::NetworkIdle));
    }

    #[test]
    fn a_failed_navigation_request_aborts_the_pending_document() {
        let mut s = page();
        s.on_event(
            "S",
            "Network.requestWillBeSent",
            &json!({"requestId": "L9", "loaderId": "L9", "frameId": "T", "type": "Document",
                    "request": {"url": "http://g/down"}}),
        );
        s.on_event(
            "S",
            "Network.loadingFailed",
            &json!({"requestId": "L9", "errorText": "net::ERR_CONNECTION_REFUSED"}),
        );
        let nav = s.main_navigations().last().cloned().unwrap();
        assert_eq!(nav.error.as_deref(), Some("net::ERR_CONNECTION_REFUSED"));
        assert_eq!(
            nav.new_document.and_then(|d| d.document_id),
            Some("L9".to_string())
        );
    }

    #[test]
    fn a_busy_child_frame_keeps_the_main_frame_busy() {
        let mut s = page();
        s.on_event(
            "S",
            "Page.frameAttached",
            &json!({"frameId": "C", "parentFrameId": "T"}),
        );
        s.on_event(
            "S",
            "Network.requestWillBeSent",
            &json!({"requestId": "q", "loaderId": "LC", "frameId": "C", "type": "XHR",
                    "request": {"url": "http://g/api"}}),
        );
        fire_timers(&mut s);
        assert!(!s.main_has(Lifecycle::NetworkIdle));
        s.on_event("S", "Network.loadingFinished", &json!({"requestId": "q"}));
        fire_timers(&mut s);
        assert!(s.main_has(Lifecycle::NetworkIdle));
    }

    #[test]
    fn worker_requests_belong_to_the_main_frame() {
        let mut s = page();
        s.add_worker("W");
        s.on_event(
            "W",
            "Network.requestWillBeSent",
            &json!({"requestId": "w1", "loaderId": "", "type": "Fetch",
                    "request": {"url": "http://g/api/live"}}),
        );
        fire_timers(&mut s);
        assert!(!s.main_has(Lifecycle::NetworkIdle));
    }

    #[test]
    fn contexts_of_the_two_worlds() {
        let mut s = page();
        s.on_event(
            "S",
            "Runtime.executionContextCreated",
            &json!({"context": {"id": 1, "name": "", "auxData": {"frameId": "T", "isDefault": true}}}),
        );
        s.on_event(
            "S",
            "Runtime.executionContextCreated",
            &json!({"context": {"id": 2, "name": "world", "auxData": {"frameId": "T", "isDefault": false}}}),
        );
        s.on_event(
            "S",
            "Runtime.executionContextCreated",
            &json!({"context": {"id": 3, "name": "other", "auxData": {"frameId": "T", "isDefault": false}}}),
        );
        assert_eq!(s.main_context(false), Some(1));
        assert_eq!(s.main_context(true), Some(2));
        s.on_event(
            "S",
            "Runtime.executionContextDestroyed",
            &json!({"executionContextId": 2}),
        );
        assert_eq!(s.main_context(true), None);
    }
}
