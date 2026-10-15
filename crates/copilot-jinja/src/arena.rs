//! Breaking reference cycles after a render.
//!
//! Python collects the cycles a template builds (a macro defined at the top
//! level refers to the frame that holds it; a list can contain itself). Here
//! every list, dict, object and scope created while a render is running is
//! remembered weakly, and emptied when the render ends, so nothing it built
//! outlives it.

use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use crate::value::{Dict, Object, Value};

enum Tracked {
    List(Weak<RefCell<Vec<Value>>>),
    Dict(Weak<RefCell<Dict>>),
    Object(Weak<dyn Object>),
    Scope(Weak<crate::vm::Scope>),
}

thread_local! {
    static ACTIVE: Cell<usize> = const { Cell::new(0) };
    static TRACKED: RefCell<Vec<Tracked>> = const { RefCell::new(Vec::new()) };
}

fn track(t: Tracked) {
    if ACTIVE.with(Cell::get) > 0 {
        TRACKED.with(|v| v.borrow_mut().push(t));
    }
}

pub(crate) fn track_list(rc: &Rc<RefCell<Vec<Value>>>) {
    track(Tracked::List(Rc::downgrade(rc)));
}

pub(crate) fn track_dict(rc: &Rc<RefCell<Dict>>) {
    track(Tracked::Dict(Rc::downgrade(rc)));
}

pub(crate) fn track_object(rc: &Rc<dyn Object>) {
    track(Tracked::Object(Rc::downgrade(rc)));
}

pub(crate) fn track_scope(rc: &Rc<crate::vm::Scope>) {
    track(Tracked::Scope(Rc::downgrade(rc)));
}

/// While alive, everything created is tracked; dropping it empties what is
/// still alive.
pub(crate) struct RenderGuard {
    start: usize,
}

impl RenderGuard {
    pub(crate) fn new() -> Self {
        ACTIVE.with(|a| a.set(a.get() + 1));
        let start = TRACKED.with(|v| v.borrow().len());
        Self { start }
    }
}

impl Drop for RenderGuard {
    fn drop(&mut self) {
        let tracked: Vec<Tracked> = TRACKED.with(|v| {
            let mut v = v.borrow_mut();
            let start = self.start.min(v.len());
            v.split_off(start)
        });
        ACTIVE.with(|a| a.set(a.get().saturating_sub(1)));
        for t in tracked {
            match t {
                Tracked::List(w) => {
                    if let Some(rc) = w.upgrade() {
                        if let Ok(mut l) = rc.try_borrow_mut() {
                            l.clear();
                        }
                    }
                }
                Tracked::Dict(w) => {
                    if let Some(rc) = w.upgrade() {
                        if let Ok(mut d) = rc.try_borrow_mut() {
                            d.entries.clear();
                        }
                    }
                }
                Tracked::Object(w) => {
                    if let Some(rc) = w.upgrade() {
                        rc.clear();
                    }
                }
                Tracked::Scope(w) => {
                    if let Some(rc) = w.upgrade() {
                        rc.clear();
                    }
                }
            }
        }
    }
}
