//! Running a compiled template: what the Python module Jinja2 generates
//! would do (`jinja2/runtime.py` for the objects it uses).
//!
//! Each Python function the generator writes (the root, a block, a macro, a
//! recursive loop, a loop filter) runs in its own [`Scope`]; a nested function
//! reads the variables of the scope it was defined in, as a Python closure
//! does.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::{Rc, Weak};

use crate::arena;
use crate::ast::*;
use crate::attrs;
use crate::callargs;
use crate::compiler::{self, Template};
use crate::error::{Error, Result};
use crate::filters::{self, FilterCx};
use crate::jtests;
use crate::markup;
use crate::objects::{self, Builtin, BuiltinKind, Method, Namespace};
use crate::ops::{self, BinOp};
use crate::pyrepr::{self, str_repr};
use crate::tables;
use crate::value::{Object, PyIter, Undefined, Value};

/// Loop iterations, macro calls and filtered items a render may take. Python
/// has no such limit; this keeps a template from running unbounded.
pub const MAX_STEPS: u64 = 5_000_000;

/// Python's recursion limit, in Python frames: a macro call costs five.
const MAX_DEPTH: usize = 990;

/// How much a buffer (a macro's or block's output) may hold.
const MAX_BUFFER: usize = 64 << 20;

const ENV_CALL: &str = "jinja2.sandbox.SandboxedEnvironment.call()";

/// Positional and keyword arguments of a call.
type CallArgs = (Vec<Value>, Vec<(Rc<str>, Value)>);

/// The attributes `hasattr` finds on any Python object.
const OBJECT_ATTRS: &[&str] = &[
    "__class__",
    "__delattr__",
    "__dict__",
    "__dir__",
    "__doc__",
    "__eq__",
    "__format__",
    "__ge__",
    "__getattribute__",
    "__getstate__",
    "__gt__",
    "__hash__",
    "__init__",
    "__init_subclass__",
    "__le__",
    "__lt__",
    "__module__",
    "__ne__",
    "__new__",
    "__reduce__",
    "__reduce_ex__",
    "__repr__",
    "__setattr__",
    "__sizeof__",
    "__str__",
    "__subclasshook__",
    "__weakref__",
];

fn internal() -> Error {
    Error::new("AssertionError", "internal template engine error")
}

fn no_loader() -> Error {
    Error::type_error("no loader for this environment specified")
}

/// `StrictUndefined(hint, name=name)`.
fn undefined_named(hint: String, name: &str) -> Value {
    Value::Undefined(Rc::new(Undefined {
        hint: Some(hint),
        obj: None,
        name: Some(Value::str(name)),
        exc: "UndefinedError",
        strict: crate::value::strict_undefined(),
    }))
}

/// The plain `Undefined` an inline `if` without `else` gives.
fn cond_undefined(hint: String) -> Value {
    Value::Undefined(Rc::new(Undefined {
        hint: Some(hint),
        obj: None,
        name: None,
        exc: "UndefinedError",
        strict: false,
    }))
}

// --- context and scopes ------------------------------------------------------------

/// A template `Context`: the render's variables and what top-level
/// assignments add.
pub struct Context {
    vars: RefCell<Vec<(Rc<str>, Value)>>,
    parent: Rc<HashMap<Rc<str>, Value>>,
}

impl Context {
    fn resolve_or_missing(&self, key: &str) -> Option<Value> {
        if let Some((_, v)) = self.vars.borrow().iter().find(|(k, _)| &**k == key) {
            return Some(v.clone());
        }
        self.parent.get(key).cloned()
    }

    fn set_var(&self, name: &Rc<str>, value: Value) {
        let mut vars = self.vars.borrow_mut();
        match vars.iter_mut().find(|(k, _)| k == name) {
            Some(slot) => slot.1 = value,
            None => vars.push((name.clone(), value)),
        }
    }

    /// `context.derived(locals)`.
    fn derived(&self, locals: Vec<(Rc<str>, Value)>) -> Rc<Context> {
        let mut parent: HashMap<Rc<str>, Value> = (*self.parent).clone();
        for (k, v) in self.vars.borrow().iter() {
            parent.insert(k.clone(), v.clone());
        }
        for (k, v) in locals {
            parent.insert(k, v);
        }
        Rc::new(Context {
            vars: RefCell::new(Vec::new()),
            parent: Rc::new(parent),
        })
    }
}

/// The variables of one running Python function, by frame level.
pub struct Scope {
    vars: RefCell<Vec<HashMap<Rc<str>, Option<Value>>>>,
    parent: Option<Rc<Scope>>,
    ctx: Rc<Context>,
}

impl Scope {
    fn new(parent: Option<Rc<Scope>>, ctx: Rc<Context>) -> Rc<Scope> {
        let rc = Rc::new(Scope {
            vars: RefCell::new(Vec::new()),
            parent,
            ctx,
        });
        arena::track_scope(&rc);
        rc
    }

    /// The variable's value: `None` when this function and the ones around
    /// it never bound it, `Some(None)` when it is `missing`.
    fn get(&self, level: usize, name: &str) -> Option<Option<Value>> {
        if let Some(v) = self.vars.borrow().get(level).and_then(|m| m.get(name)) {
            return Some(v.clone());
        }
        self.parent.as_ref().and_then(|p| p.get(level, name))
    }

    fn local_missing(&self, level: usize, name: &str) -> bool {
        !matches!(
            self.vars.borrow().get(level).and_then(|m| m.get(name)),
            Some(Some(_))
        )
    }

    fn set(&self, level: usize, name: &Rc<str>, value: Option<Value>) {
        let mut vars = self.vars.borrow_mut();
        while vars.len() <= level {
            vars.push(HashMap::new());
        }
        vars[level].insert(name.clone(), value);
    }

    /// Drops every variable (and the context's), breaking reference cycles
    /// once the render is over.
    pub(crate) fn clear(&self) {
        if let Ok(mut v) = self.vars.try_borrow_mut() {
            v.clear();
        }
        if let Ok(mut v) = self.ctx.vars.try_borrow_mut() {
            v.clear();
        }
    }
}

// --- output ----------------------------------------------------------------------------

/// What a function writes: the root's output or a buffer, joined like
/// `"".join(chunks)` when it ends.
pub(crate) struct Sink {
    out: String,
    chunks: usize,
    bad: Option<(usize, String)>,
    cap: Option<usize>,
    bytes: usize,
}

impl Sink {
    fn buffer() -> Self {
        Self {
            out: String::new(),
            chunks: 0,
            bad: None,
            cap: None,
            bytes: 0,
        }
    }

    fn root(cap: usize) -> Self {
        Self {
            cap: Some(cap),
            ..Self::buffer()
        }
    }

    fn text(&mut self, s: &str) -> Result<()> {
        self.chunks += 1;
        self.bytes += s.len();
        match self.cap {
            Some(cap) => {
                if self.bytes <= cap {
                    self.out.push_str(s);
                }
            }
            None => {
                if self.bytes > MAX_BUFFER {
                    return Err(Error::memory());
                }
                self.out.push_str(s);
            }
        }
        Ok(())
    }

    /// A chunk written as is (a filter block's or call block's result).
    fn value(&mut self, v: Value) -> Result<()> {
        match v.as_str() {
            Some(s) => self.text(s),
            None => {
                if self.bad.is_none() {
                    self.bad = Some((self.chunks, v.type_name()));
                }
                self.chunks += 1;
                Ok(())
            }
        }
    }

    fn finish(self) -> Result<String> {
        if let Some((i, t)) = self.bad {
            return Err(Error::type_error(format!(
                "sequence item {i}: expected str instance, {t} found"
            )));
        }
        Ok(self.out)
    }
}

/// A rendered template: its text (complete while within the cap) and its
/// size in UTF-8 bytes.
pub struct Rendered {
    /// The output.
    pub text: String,
    /// `len(output.encode("utf-8"))`.
    pub bytes: usize,
}

// --- the machine -------------------------------------------------------------------------

pub(crate) struct VmState {
    blocks: Vec<Rc<BlockDef>>,
    autoescape: RefCell<Value>,
    steps: Cell<u64>,
    depth: Cell<usize>,
}

/// A handle on the running render.
#[derive(Clone)]
pub(crate) struct Vm(Rc<VmState>);

impl std::fmt::Debug for Vm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Vm")
    }
}

struct DepthGuard<'a>(&'a VmState, usize);

impl Drop for DepthGuard<'_> {
    fn drop(&mut self) {
        self.0.depth.set(self.0.depth.get().saturating_sub(self.1));
    }
}

/// The environment's globals.
fn globals() -> HashMap<Rc<str>, Value> {
    let mut g = HashMap::new();
    for (name, kind) in [
        ("range", BuiltinKind::Range),
        ("dict", BuiltinKind::Dict),
        ("lipsum", BuiltinKind::Lipsum),
        ("cycler", BuiltinKind::Cycler),
        ("joiner", BuiltinKind::Joiner),
        ("namespace", BuiltinKind::Namespace),
    ] {
        g.insert(Rc::from(name), Builtin::value(kind));
    }
    g
}

/// `template.render(**vars)`, with the output capped at `cap` bytes (the
/// size is still counted past it).
pub fn render(t: &Template, vars: Vec<(Rc<str>, Value)>, cap: usize) -> Result<Rendered> {
    let _guard = arena::RenderGuard::new();
    let mut parent = globals();
    for (k, v) in vars {
        parent.insert(k, v);
    }
    let ctx = Rc::new(Context {
        vars: RefCell::new(Vec::new()),
        parent: Rc::new(parent),
    });
    let vm = Vm(Rc::new(VmState {
        blocks: t.blocks.clone(),
        autoescape: RefCell::new(Value::Bool(t.autoescape)),
        steps: Cell::new(0),
        depth: Cell::new(2),
    }));
    let scope = Scope::new(None, ctx.clone());
    if t.self_param {
        scope.set(0, &Rc::from("self"), Some(vm.template_reference(&ctx)));
    }
    vm.enter_frame(&t.frame, &scope);
    let mut sink = Sink::root(cap);
    vm.exec_body(&t.body, &scope, &mut sink)?;
    let bytes = sink.bytes;
    let text = sink.finish()?;
    Ok(Rendered { text, bytes })
}

impl Vm {
    fn autoescape(&self) -> Value {
        self.0.autoescape.borrow().clone()
    }

    fn step(&self) -> Result<()> {
        let n = self.0.steps.get() + 1;
        self.0.steps.set(n);
        if n > MAX_STEPS {
            return Err(Error::new(
                "RuntimeError",
                format!("the template did not finish within {MAX_STEPS} steps"),
            ));
        }
        Ok(())
    }

    fn enter(&self, frames: usize) -> Result<DepthGuard<'_>> {
        let d = self.0.depth.get() + frames;
        if d > MAX_DEPTH {
            return Err(Error::new(
                "RecursionError",
                "maximum recursion depth exceeded",
            ));
        }
        self.0.depth.set(d);
        Ok(DepthGuard(&self.0, frames))
    }

    fn template_reference(&self, ctx: &Rc<Context>) -> Value {
        Value::object(TemplateReference {
            vm: self.clone(),
            ctx: RefCell::new(Some(ctx.clone())),
        })
    }

    fn enter_frame(&self, spec: &FrameSpec, scope: &Rc<Scope>) {
        for (name, load) in &spec.loads {
            match load {
                Load::Param => {}
                Load::Resolve(n) => {
                    let v = scope.ctx.resolve_or_missing(n);
                    scope.set(spec.level, name, v);
                }
                Load::Alias(level) => {
                    let v = scope.get(*level, name).flatten();
                    scope.set(spec.level, name, v);
                }
                Load::Undefined => scope.set(spec.level, name, None),
            }
        }
    }

    fn leave_frame(&self, spec: &FrameSpec, scope: &Rc<Scope>) {
        for (name, _) in &spec.loads {
            scope.set(spec.level, name, None);
        }
    }

    // --- statements ------------------------------------------------------------------

    fn exec_body(&self, body: &[Stmt], scope: &Rc<Scope>, sink: &mut Sink) -> Result<()> {
        for s in body {
            self.exec(s, scope, sink)?;
        }
        Ok(())
    }

    fn exec(&self, s: &Stmt, scope: &Rc<Scope>, sink: &mut Sink) -> Result<()> {
        match s {
            Stmt::Output(o) => {
                for item in &o.items {
                    match item {
                        OutItem::Text(t) => sink.text(t)?,
                        OutItem::Expr(e) => {
                            let escape = match o.escape {
                                Escape::Off => false,
                                Escape::On => true,
                                Escape::Volatile => ops::truthy(&self.autoescape())?,
                            };
                            let v = self.eval(e, scope)?;
                            let text = if escape {
                                markup::escape_value(&v)?
                            } else {
                                pyrepr::str(&v)?
                            };
                            sink.text(&text)?;
                        }
                    }
                }
                Ok(())
            }
            Stmt::For(f) => self.exec_for(f, scope, sink),
            Stmt::If(i) => {
                if ops::truthy(&self.eval(&i.test, scope)?)? {
                    return self.exec_body(&i.body, scope, sink);
                }
                for (t, b) in &i.elif {
                    if ops::truthy(&self.eval(t, scope)?)? {
                        return self.exec_body(b, scope, sink);
                    }
                }
                self.exec_body(&i.else_, scope, sink)
            }
            Stmt::Macro(m) => {
                let name = m.name.clone().ok_or_else(internal)?;
                let v = self.macro_value(m, scope);
                if m.toplevel {
                    scope.ctx.set_var(&name, v.clone());
                }
                scope.set(m.store_level, &name, Some(v));
                Ok(())
            }
            Stmt::CallBlock(c) => {
                let caller = self.macro_value(&c.caller, scope);
                let Expr::Call(call) = &c.call else {
                    return Err(internal());
                };
                let v = self.eval_call(call, scope, Some((Rc::from("caller"), caller)))?;
                sink.value(v)
            }
            Stmt::FilterBlock(fb) => {
                self.enter_frame(&fb.frame, scope);
                let mut buf = Some(Sink::buffer());
                if let Some(b) = buf.as_mut() {
                    self.exec_body(&fb.body, scope, b)?;
                }
                let v = self.eval_block_filter(&fb.filter, scope, &mut buf)?;
                sink.value(v)?;
                self.leave_frame(&fb.frame, scope);
                Ok(())
            }
            Stmt::With(w) => {
                self.enter_frame(&w.frame, scope);
                for (t, v) in w.targets.iter().zip(&w.values) {
                    self.check_ns(t, scope)?;
                    let v = self.eval(v, scope)?;
                    self.assign(t, v, scope)?;
                }
                self.exec_body(&w.body, scope, sink)?;
                self.leave_frame(&w.frame, scope);
                Ok(())
            }
            Stmt::Block(b) => {
                if b.required {
                    return Err(Error::runtime(format!(
                        "Required block {} not found",
                        str_repr(&b.name)
                    )));
                }
                let ctx = if b.scoped {
                    let locals = b
                        .locals
                        .iter()
                        .filter_map(|(n, level)| {
                            scope.get(*level, n).flatten().map(|v| (n.clone(), v))
                        })
                        .collect();
                    scope.ctx.derived(locals)
                } else {
                    scope.ctx.clone()
                };
                self.run_block(&b.name, &ctx, sink)
            }
            Stmt::Extends(e) => {
                self.eval(e, scope)?;
                Err(no_loader())
            }
            Stmt::Load(l) => {
                let v = self.eval(&l.template, scope)?;
                match l.kind {
                    LoadKind::Import | LoadKind::IncludeOne => Err(no_loader()),
                    LoadKind::IncludeSelect => self.select_template(&v, l.ignore_missing),
                    LoadKind::IncludeEither => {
                        if v.is_str() || v.is_undefined() {
                            Err(no_loader())
                        } else {
                            self.select_template(&v, l.ignore_missing)
                        }
                    }
                }
            }
            Stmt::Assign(a) => {
                self.check_ns(&a.target, scope)?;
                let v = self.eval(&a.value, scope)?;
                self.assign(&a.target, v, scope)?;
                self.export(&a.export, scope);
                Ok(())
            }
            Stmt::AssignBlock(a) => {
                self.enter_frame(&a.frame, scope);
                let mut buf = Some(Sink::buffer());
                if let Some(b) = buf.as_mut() {
                    self.exec_body(&a.body, scope, b)?;
                }
                self.check_ns(&a.target, scope)?;
                let markup = ops::truthy(&self.autoescape())?;
                let v = match &a.filter {
                    Some(f) => self.eval_block_filter(f, scope, &mut buf)?,
                    None => Value::str(buf.take().ok_or_else(internal)?.finish()?),
                };
                let v = if markup { to_markup(&v)? } else { v };
                self.assign(&a.target, v, scope)?;
                self.export(&a.export, scope);
                self.leave_frame(&a.frame, scope);
                Ok(())
            }
            Stmt::Scope(sc) => {
                self.enter_frame(&sc.frame, scope);
                self.exec_body(&sc.body, scope, sink)?;
                self.leave_frame(&sc.frame, scope);
                Ok(())
            }
            Stmt::EvalContextModifier(m) => {
                let saved = self.autoescape();
                let v = self.eval(&m.autoescape, scope)?;
                *self.0.autoescape.borrow_mut() = v;
                self.exec_body(&m.body, scope, sink)?;
                *self.0.autoescape.borrow_mut() = saved;
                Ok(())
            }
        }
    }

    fn select_template(&self, names: &Value, ignore_missing: bool) -> Result<()> {
        if let Value::Undefined(u) = names {
            return Err(u.error());
        }
        if !ops::truthy(names)? {
            if ignore_missing {
                return Ok(());
            }
            return Err(Error::new(
                "TemplatesNotFound",
                "Tried to select from an empty list of templates.",
            ));
        }
        let mut it = ops::py_iter(names)?;
        if it.next()?.is_some() {
            return Err(no_loader());
        }
        if ignore_missing {
            return Ok(());
        }
        Err(Error::new(
            "TemplatesNotFound",
            "none of the templates given were found: ",
        ))
    }

    fn export(&self, names: &[(Rc<str>, usize)], scope: &Rc<Scope>) {
        for (name, level) in names {
            if let Some(Some(v)) = scope.get(*level, name) {
                scope.ctx.set_var(name, v);
            }
        }
    }

    /// The `isinstance(ns, Namespace)` checks written before an assignment
    /// to `ns.attr`.
    fn check_ns(&self, target: &Expr, scope: &Rc<Scope>) -> Result<()> {
        match target {
            Expr::StoreNs(n, _, level) => {
                let ok = scope
                    .get(*level, n)
                    .flatten()
                    .is_some_and(|v| v.downcast::<Namespace>().is_some());
                if !ok {
                    return Err(Error::runtime(
                        "cannot assign attribute on non-namespace object",
                    ));
                }
                Ok(())
            }
            Expr::Tuple(items, _) => items.iter().try_for_each(|i| self.check_ns(i, scope)),
            _ => Ok(()),
        }
    }

    fn assign(&self, target: &Expr, value: Value, scope: &Rc<Scope>) -> Result<()> {
        match target {
            Expr::Store(n, level) => {
                scope.set(*level, n, Some(value));
                Ok(())
            }
            Expr::StoreNs(n, attr, level) => {
                let ns = scope.get(*level, n).flatten();
                match ns.as_ref().and_then(|v| v.downcast::<Namespace>()) {
                    Some(ns) => ns.set(attr, value),
                    None => Err(Error::runtime(
                        "cannot assign attribute on non-namespace object",
                    )),
                }
            }
            Expr::Tuple(items, _) => {
                let values = ops::unpack(&value, items.len())?;
                for (t, v) in items.iter().zip(values) {
                    self.assign(t, v, scope)?;
                }
                Ok(())
            }
            _ => Err(internal()),
        }
    }

    /// The loop target read back (`yield <target>` in a loop filter).
    fn target_value(&self, target: &Expr, scope: &Rc<Scope>) -> Result<Value> {
        match target {
            Expr::Store(n, level) => Ok(scope.get(*level, n).flatten().unwrap_or(Value::None)),
            Expr::Tuple(items, _) => {
                let mut out = Vec::with_capacity(items.len());
                for i in items {
                    out.push(self.target_value(i, scope)?);
                }
                Ok(Value::tuple(out))
            }
            _ => Err(internal()),
        }
    }

    // --- loops -------------------------------------------------------------------------

    fn exec_for(&self, f: &Rc<For>, scope: &Rc<Scope>, sink: &mut Sink) -> Result<()> {
        let iterable = self.eval(&f.iter, scope)?;
        if f.recursive {
            let v = self.run_loop(f, scope, iterable, 0)?;
            return sink.value(v);
        }
        self.loop_in(f, scope, scope, iterable, None, 0, sink)
    }

    /// The `loop` function of a recursive loop.
    fn run_loop(
        &self,
        f: &Rc<For>,
        def_scope: &Rc<Scope>,
        reciter: Value,
        depth: usize,
    ) -> Result<Value> {
        let _g = self.enter(2)?;
        let lscope = Scope::new(Some(def_scope.clone()), def_scope.ctx.clone());
        let mut buf = Sink::buffer();
        let recurse = Recurse {
            f: f.clone(),
            scope: def_scope.clone(),
        };
        self.loop_in(
            f,
            &lscope,
            def_scope,
            reciter,
            Some(recurse),
            depth,
            &mut buf,
        )?;
        let markup = match f.escape {
            Escape::Off => false,
            Escape::On => true,
            Escape::Volatile => ops::truthy(&self.autoescape())?,
        };
        let s = buf.finish()?;
        Ok(if markup {
            Value::markup(s)
        } else {
            Value::str(s)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn loop_in(
        &self,
        f: &Rc<For>,
        scope: &Rc<Scope>,
        filter_parent: &Rc<Scope>,
        iterable: Value,
        recurse: Option<Recurse>,
        depth0: usize,
        sink: &mut Sink,
    ) -> Result<()> {
        let level = f.frame.level;
        let source = match &f.test {
            Some(_) => self.loop_filter(f, filter_parent, iterable),
            None => iterable,
        };
        let mut iterated = false;
        if f.extended {
            let loop_name: Rc<str> = Rc::from("loop");
            scope.set(level, &loop_name, None);
            let lc_value = LoopContext::value(self, source, recurse, depth0)?;
            let lc = lc_value.downcast::<LoopContext>().ok_or_else(internal)?;
            while let Some(item) = lc.advance()? {
                self.step()?;
                self.assign(&f.target, item, scope)?;
                scope.set(level, &loop_name, Some(lc_value.clone()));
                self.enter_frame(&f.frame, scope);
                self.exec_body(&f.body, scope, sink)?;
                iterated = true;
            }
        } else {
            let mut it = ops::py_iter(&source)?;
            while let Some(item) = it.next()? {
                self.step()?;
                self.assign(&f.target, item, scope)?;
                self.enter_frame(&f.frame, scope);
                self.exec_body(&f.body, scope, sink)?;
                iterated = true;
            }
        }
        if f.reset_after {
            self.leave_frame(&f.frame, scope);
        }
        if !f.else_.is_empty() && !iterated {
            self.enter_frame(&f.else_frame, scope);
            self.exec_body(&f.else_, scope, sink)?;
            self.leave_frame(&f.else_frame, scope);
        }
        Ok(())
    }

    /// The generator function that applies a loop's `if`.
    fn loop_filter(&self, f: &Rc<For>, parent: &Rc<Scope>, fiter: Value) -> Value {
        let vm = self.clone();
        let f = f.clone();
        let parent = parent.clone();
        let mut state: Option<(Rc<Scope>, PyIter)> = None;
        objects::Generator::value("t_1", move || {
            if state.is_none() {
                let scope = Scope::new(Some(parent.clone()), parent.ctx.clone());
                vm.enter_frame(&f.test_frame, &scope);
                let it = ops::py_iter(&fiter)?;
                state = Some((scope, it));
            }
            let Some((scope, it)) = state.as_mut() else {
                return Ok(None);
            };
            let test = f.test.as_ref().ok_or_else(internal)?;
            while let Some(item) = it.next()? {
                vm.step()?;
                vm.assign(&f.target, item, scope)?;
                if ops::truthy(&vm.eval(test, scope)?)? {
                    return vm.target_value(&f.target, scope).map(Some);
                }
            }
            Ok(None)
        })
    }

    // --- blocks and macros -------------------------------------------------------------

    fn run_block(&self, name: &str, ctx: &Rc<Context>, sink: &mut Sink) -> Result<()> {
        let def = self
            .0
            .blocks
            .iter()
            .find(|d| &*d.name == name)
            .cloned()
            .ok_or_else(internal)?;
        let _g = self.enter(1)?;
        let bscope = Scope::new(None, ctx.clone());
        if def.self_param {
            bscope.set(0, &Rc::from("self"), Some(self.template_reference(ctx)));
        }
        if def.super_param {
            bscope.set(
                0,
                &Rc::from("super"),
                Some(undefined_named(
                    format!("there is no parent block called {}.", str_repr(name)),
                    "super",
                )),
            );
        }
        self.enter_frame(&def.frame, &bscope);
        self.exec_body(&def.body, &bscope, sink)
    }

    fn macro_value(&self, def: &Rc<MacroDef>, scope: &Rc<Scope>) -> Value {
        Value::object(Macro {
            vm: self.clone(),
            def: def.clone(),
            scope: RefCell::new(Some(scope.clone())),
        })
    }

    /// `Macro.__call__` with the evaluation context the call passes.
    fn call_macro(
        &self,
        m: &Macro,
        args: Vec<Value>,
        mut kwargs: Vec<(Rc<str>, Value)>,
    ) -> Result<Value> {
        let def = &m.def;
        let name_repr = match &def.name {
            Some(n) => str_repr(n),
            None => "None".to_string(),
        };
        let autoescape = self.autoescape();
        let count = def.args.len();
        let mut arguments: Vec<Option<Value>> =
            args.iter().take(count).cloned().map(Some).collect();
        let off = arguments.len();
        let pop = |kwargs: &mut Vec<(Rc<str>, Value)>, name: &str| -> Option<Value> {
            let i = kwargs.iter().position(|(k, _)| &**k == name)?;
            Some(kwargs.remove(i).1)
        };
        let mut found_caller = false;
        if off != count {
            for name in &def.args[off..] {
                let v = pop(&mut kwargs, name);
                if &**name == "caller" {
                    found_caller = true;
                }
                arguments.push(v);
            }
        } else {
            found_caller = def.args.iter().any(|a| &**a == "caller");
        }
        if def.caller && !found_caller {
            let caller = match pop(&mut kwargs, "caller") {
                None | Some(Value::None) => undefined_named("No caller defined".into(), "caller"),
                Some(v) => v,
            };
            arguments.push(Some(caller));
        }
        if def.catch_kwargs {
            let pairs = kwargs.drain(..).map(|(k, v)| (Value::Str(k), v)).collect();
            arguments.push(Some(Value::dict(pairs)?));
        } else if let Some((first, _)) = kwargs.first() {
            if kwargs.iter().any(|(k, _)| &**k == "caller") {
                return Err(Error::type_error(format!(
                    "macro {name_repr} was invoked with two values for the special caller argument. \
                     This is most likely a bug."
                )));
            }
            return Err(Error::type_error(format!(
                "macro {name_repr} takes no keyword argument {}",
                str_repr(first)
            )));
        }
        if def.catch_varargs {
            arguments.push(Some(Value::tuple(
                args.iter().skip(count).cloned().collect(),
            )));
        } else if args.len() > count {
            return Err(Error::type_error(format!(
                "macro {name_repr} takes not more than {count} argument(s)"
            )));
        }
        if arguments.len() != def.params.len() {
            let n = def.params.len();
            return Err(Error::type_error(format!(
                "macro() takes {n} positional argument{} but {} {} given",
                if n == 1 { "" } else { "s" },
                arguments.len(),
                if arguments.len() == 1 { "was" } else { "were" }
            )));
        }
        let _g = self.enter(5)?;
        self.step()?;
        let def_scope = m.scope.borrow().clone().ok_or_else(internal)?;
        let scope = Scope::new(Some(def_scope.clone()), def_scope.ctx.clone());
        let level = def.frame.level;
        for (p, v) in def.params.iter().zip(arguments) {
            scope.set(level, p, v);
        }
        let mut buf = Sink::buffer();
        self.enter_frame(&def.frame, &scope);
        let nargs = def.args.len();
        let ndefaults = def.defaults.len();
        for (idx, arg) in def.args.iter().enumerate() {
            if scope.local_missing(level, arg) {
                let v = if idx + ndefaults >= nargs {
                    self.eval(&def.defaults[idx + ndefaults - nargs], &scope)?
                } else {
                    undefined_named(format!("parameter {} was not provided", str_repr(arg)), arg)
                };
                scope.set(level, arg, Some(v));
            }
        }
        self.exec_body(&def.body, &scope, &mut buf)?;
        let rv = buf.finish()?;
        Ok(if ops::truthy(&autoescape)? {
            Value::markup(rv)
        } else {
            Value::str(rv)
        })
    }

    // --- expressions -----------------------------------------------------------------

    fn eval(&self, e: &Expr, scope: &Rc<Scope>) -> Result<Value> {
        match e {
            Expr::Const(v) => {
                check_literal(v)?;
                Ok(v.fresh())
            }
            Expr::TemplateData(d) => Ok(if ops::truthy(&self.autoescape())? {
                Value::Markup(d.clone())
            } else {
                Value::Str(d.clone())
            }),
            Expr::Load(n, level, raw) => Ok(match scope.get(*level, n) {
                Some(Some(v)) => v,
                _ if *raw => Value::object(Missing),
                _ => Value::undefined_name(n),
            }),
            Expr::Name(..)
            | Expr::NsRef(..)
            | Expr::Store(..)
            | Expr::StoreNs(..)
            | Expr::Slice(..) => Err(internal()),
            Expr::Tuple(items, _) => {
                let mut out = Vec::with_capacity(items.len());
                for i in items {
                    out.push(self.eval(i, scope)?);
                }
                Ok(Value::tuple(out))
            }
            Expr::List(items) => {
                let mut out = Vec::with_capacity(items.len());
                for i in items {
                    out.push(self.eval(i, scope)?);
                }
                Ok(Value::list(out))
            }
            Expr::Dict(pairs) => {
                let mut kv = Vec::with_capacity(pairs.len());
                for (k, v) in pairs {
                    let k = self.eval(k, scope)?;
                    let v = self.eval(v, scope)?;
                    kv.push((k, v));
                }
                Value::dict(kv)
            }
            Expr::Bin(BinKind::And, l, r) => {
                let l = self.eval(l, scope)?;
                if !ops::truthy(&l)? {
                    return Ok(l);
                }
                self.eval(r, scope)
            }
            Expr::Bin(BinKind::Or, l, r) => {
                let l = self.eval(l, scope)?;
                if ops::truthy(&l)? {
                    return Ok(l);
                }
                self.eval(r, scope)
            }
            Expr::Bin(k, l, r) => {
                let l = self.eval(l, scope)?;
                let r = self.eval(r, scope)?;
                let op = match k {
                    BinKind::Add => BinOp::Add,
                    BinKind::Sub => BinOp::Sub,
                    BinKind::Mul => BinOp::Mul,
                    BinKind::Div => BinOp::Div,
                    BinKind::FloorDiv => BinOp::FloorDiv,
                    BinKind::Mod => BinOp::Mod,
                    BinKind::Pow => BinOp::Pow,
                    BinKind::And | BinKind::Or => return Err(internal()),
                };
                ops::binop(op, &l, &r)
            }
            Expr::Unary(k, n) => {
                let v = self.eval(n, scope)?;
                match k {
                    UnKind::Not => Ok(Value::Bool(!ops::truthy(&v)?)),
                    UnKind::Neg => ops::unary(true, &v),
                    UnKind::Pos => ops::unary(false, &v),
                }
            }
            Expr::Concat(items, markup) => {
                let mut values = Vec::with_capacity(items.len());
                for i in items {
                    values.push(self.eval(i, scope)?);
                }
                if *markup {
                    markup_join(values)
                } else {
                    str_join(values)
                }
            }
            Expr::Compare(first, ops_) => {
                let mut value = self.eval(first, scope)?;
                for (op, o) in ops_ {
                    let new = self.eval(o, scope)?;
                    if !compiler::compare(*op, &value, &new)? {
                        return Ok(Value::Bool(false));
                    }
                    value = new;
                }
                Ok(Value::Bool(true))
            }
            Expr::Cond(c) => {
                if ops::truthy(&self.eval(&c.test, scope)?)? {
                    return self.eval(&c.expr1, scope);
                }
                match &c.expr2 {
                    Some(e2) => self.eval(e2, scope),
                    None => Ok(cond_undefined(format!(
                        "the inline if-expression on line {} evaluated to false and no else section \
                         was defined.",
                        c.lineno
                    ))),
                }
            }
            Expr::Getattr(n, attr) => {
                let v = self.eval(n, scope)?;
                attrs::getattr(&v, attr)
            }
            Expr::Getitem(n, a) => {
                let obj = self.eval(n, scope)?;
                if let Expr::Slice(x, y, z) = &**a {
                    let part = |p: &Option<Box<Expr>>| -> Result<Value> {
                        match p {
                            None => Ok(Value::None),
                            Some(p) => self.eval(p, scope),
                        }
                    };
                    let start = part(x)?;
                    let stop = part(y)?;
                    let step = part(z)?;
                    return attrs::subscript(&obj, &attrs::slice_object(start, stop, step));
                }
                let key = self.eval(a, scope)?;
                attrs::getitem(&obj, &key)
            }
            Expr::Call(c) => self.eval_call(c, scope, None),
            Expr::Filter(fc) => {
                let node = fc.node.as_ref().ok_or_else(internal)?;
                let v = self.eval(node, scope)?;
                self.apply_filter(fc, v, scope)
            }
            Expr::Test(fc) => {
                let node = fc.node.as_ref().ok_or_else(internal)?;
                let v = self.eval(node, scope)?;
                let (args, kwargs) = self.eval_args(&fc.args, scope, "jinja2.tests", None)?;
                if !jtests::test_exists(&fc.name) {
                    return Err(Error::runtime(format!(
                        "No test named {} found.",
                        str_repr(&fc.name)
                    )));
                }
                let cx = FilterCx {
                    autoescape: self.autoescape(),
                };
                jtests::call_test(&cx, &fc.name, v, args, kwargs)
            }
        }
    }

    fn apply_filter(&self, fc: &FilterCall, value: Value, scope: &Rc<Scope>) -> Result<Value> {
        let (args, kwargs) = self.eval_args(&fc.args, scope, "jinja2.filters", None)?;
        if filters::filter_pass(&fc.name).is_none() {
            return Err(Error::runtime(format!(
                "No filter named {} found.",
                str_repr(&fc.name)
            )));
        }
        let cx = FilterCx {
            autoescape: self.autoescape(),
        };
        filters::call_filter(&cx, &fc.name, value, args, kwargs)
    }

    /// A filter chain over a filter block's or set block's output.
    fn eval_block_filter(
        &self,
        e: &Expr,
        scope: &Rc<Scope>,
        body: &mut Option<Sink>,
    ) -> Result<Value> {
        let Expr::Filter(fc) = e else {
            return self.eval(e, scope);
        };
        let v = match &fc.node {
            Some(inner) => self.eval_block_filter(inner, scope, body)?,
            None => {
                let markup = match fc.body_escape {
                    Escape::Off => false,
                    Escape::On => true,
                    Escape::Volatile => ops::truthy(&self.autoescape())?,
                };
                let s = body.take().ok_or_else(internal)?.finish()?;
                if markup {
                    Value::markup(s)
                } else {
                    Value::str(s)
                }
            }
        };
        self.apply_filter(fc, v, scope)
    }

    fn eval_call(
        &self,
        c: &Call,
        scope: &Rc<Scope>,
        extra: Option<(Rc<str>, Value)>,
    ) -> Result<Value> {
        let f = self.eval(&c.node, scope)?;
        let (args, kwargs) = self.eval_args(&c.args, scope, ENV_CALL, extra)?;
        attrs::call(&f, args, kwargs)
    }

    /// Evaluates call arguments in CPython's order: positional, `*args`,
    /// keywords, `**kwargs`.
    fn eval_args(
        &self,
        a: &Args,
        scope: &Rc<Scope>,
        func: &str,
        extra: Option<(Rc<str>, Value)>,
    ) -> Result<CallArgs> {
        let mut args = Vec::with_capacity(a.args.len());
        for e in &a.args {
            args.push(self.eval(e, scope)?);
        }
        if let Some(d) = &a.dyn_args {
            let v = self.eval(d, scope)?;
            let mut it = match ops::py_iter(&v) {
                Ok(it) => it,
                Err(e) if e.kind == "TypeError" && e.message.ends_with("is not iterable") => {
                    return Err(Error::type_error(format!(
                        "Value after * must be an iterable, not {}",
                        v.type_name()
                    )));
                }
                Err(e) => return Err(e),
            };
            while let Some(x) = it.next()? {
                args.push(x);
                ops::check_size(args.len())?;
            }
        }
        let mut kwargs: Vec<(Rc<str>, Value)> = Vec::with_capacity(a.kwargs.len());
        let push = |kwargs: &mut Vec<(Rc<str>, Value)>, k: Rc<str>, v: Value| -> Result<()> {
            if kwargs.iter().any(|(n, _)| *n == k) {
                return Err(Error::type_error(format!(
                    "{func} got multiple values for keyword argument '{k}'"
                )));
            }
            kwargs.push((k, v));
            Ok(())
        };
        for (k, e) in &a.kwargs {
            let v = self.eval(e, scope)?;
            push(&mut kwargs, k.clone(), v)?;
        }
        if let Some((k, v)) = extra {
            push(&mut kwargs, k, v)?;
        }
        if let Some(d) = &a.dyn_kwargs {
            let v = self.eval(d, scope)?;
            match &v {
                Value::Dict(d) => {
                    let entries = d.borrow().entries.clone();
                    for (k, v) in entries {
                        let Some(name) = k.as_str() else {
                            return Err(Error::type_error("keywords must be strings"));
                        };
                        push(&mut kwargs, Rc::from(name), v)?;
                    }
                }
                Value::Undefined(u) => return Err(u.error()),
                other => {
                    return Err(Error::type_error(format!(
                        "{func} argument after ** must be a mapping, not {}",
                        other.type_name()
                    )));
                }
            }
        }
        Ok((args, kwargs))
    }
}

/// A constant written into the generated code as a literal: `inf` and
/// `nan` are names Python does not know.
fn check_literal(v: &Value) -> Result<()> {
    match v {
        Value::Float(f) if !f.is_finite() => Err(Error::new(
            "NameError",
            format!(
                "name '{}' is not defined",
                if f.is_nan() { "nan" } else { "inf" }
            ),
        )),
        Value::List(l) => l.borrow().iter().try_for_each(check_literal),
        Value::Tuple(t) => t.iter().try_for_each(check_literal),
        Value::Dict(d) => d.borrow().entries.iter().try_for_each(|(k, v)| {
            check_literal(k)?;
            check_literal(v)
        }),
        _ => Ok(()),
    }
}

/// `Markup(value)`.
fn to_markup(v: &Value) -> Result<Value> {
    match v {
        Value::Markup(_) => Ok(v.clone()),
        other => Ok(Value::markup(pyrepr::str(other)?)),
    }
}

/// `markup_join`: `~` under autoescape.
fn markup_join(values: Vec<Value>) -> Result<Value> {
    let mut buf: Vec<Value> = Vec::with_capacity(values.len());
    let mut iter = values.into_iter();
    while let Some(v) = iter.next() {
        let s = markup::soft_str(&v)?;
        let is_markup = s.is_markup();
        buf.push(s);
        if is_markup {
            let mut out = String::new();
            for b in &buf {
                out.push_str(&markup::escape_value(b)?);
            }
            for rest in iter {
                let s = markup::soft_str(&rest)?;
                out.push_str(&markup::escape_value(&s)?);
            }
            return Ok(Value::markup(out));
        }
    }
    let mut out = String::new();
    for b in &buf {
        out.push_str(b.as_str().unwrap_or_default());
    }
    Ok(Value::str(out))
}

/// `str_join`: `~` without autoescape.
fn str_join(values: Vec<Value>) -> Result<Value> {
    let mut out = String::new();
    for v in &values {
        out.push_str(&pyrepr::str(v)?);
    }
    Ok(Value::str(out))
}

// --- runtime objects ---------------------------------------------------------------

/// A macro (`jinja2.runtime.Macro`).
pub(crate) struct Macro {
    vm: Vm,
    def: Rc<MacroDef>,
    scope: RefCell<Option<Rc<Scope>>>,
}

impl std::fmt::Debug for Macro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.repr().unwrap_or_default())
    }
}

impl Object for Macro {
    fn type_name(&self) -> &str {
        "Macro"
    }

    fn module(&self) -> &str {
        "jinja2.runtime"
    }

    fn repr(&self) -> Result<String> {
        Ok(match &self.def.name {
            Some(n) => format!("<Macro {}>", str_repr(n)),
            None => "<Macro anonymous>".to_string(),
        })
    }

    fn attrs(&self) -> &'static [&'static str] {
        tables::ATTRS_MACRO
    }

    fn getattr(&self, _me: &Value, name: &str) -> Option<Result<Value>> {
        let d = &self.def;
        Some(Ok(match name {
            "name" => d
                .name
                .as_ref()
                .map_or(Value::None, |n| Value::Str(n.clone())),
            "arguments" => Value::tuple(d.args.iter().map(|a| Value::Str(a.clone())).collect()),
            "catch_kwargs" => Value::Bool(d.catch_kwargs),
            "catch_varargs" => Value::Bool(d.catch_varargs),
            "caller" => Value::Bool(d.caller),
            "explicit_caller" => Value::Bool(d.args.iter().any(|a| &**a == "caller")),
            _ => return None,
        }))
    }

    fn call(
        &self,
        _me: &Value,
        args: Vec<Value>,
        kwargs: Vec<(Rc<str>, Value)>,
    ) -> Option<Result<Value>> {
        Some(self.vm.call_macro(self, args, kwargs))
    }

    fn clear(&self) {
        if let Ok(mut s) = self.scope.try_borrow_mut() {
            *s = None;
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// What a recursive loop's `loop(...)` calls.
struct Recurse {
    f: Rc<For>,
    scope: Rc<Scope>,
}

/// `jinja2.runtime.LoopContext`.
pub(crate) struct LoopContext {
    vm: Vm,
    me: RefCell<Weak<dyn Object>>,
    iterable: RefCell<Value>,
    iterator: RefCell<PyIter>,
    index0: Cell<i64>,
    length: Cell<Option<usize>>,
    after: RefCell<Option<Value>>,
    current: RefCell<Option<Value>>,
    before: RefCell<Option<Value>>,
    last_changed: RefCell<Option<Vec<Value>>>,
    recurse: RefCell<Option<Recurse>>,
    depth0: usize,
}

impl std::fmt::Debug for LoopContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<LoopContext>")
    }
}

impl LoopContext {
    fn value(vm: &Vm, iterable: Value, recurse: Option<Recurse>, depth0: usize) -> Result<Value> {
        let iterator = ops::py_iter(&iterable)?;
        let v = Value::object(LoopContext {
            vm: vm.clone(),
            me: RefCell::new(Weak::<LoopContext>::new()),
            iterable: RefCell::new(iterable),
            iterator: RefCell::new(iterator),
            index0: Cell::new(-1),
            length: Cell::new(None),
            after: RefCell::new(None),
            current: RefCell::new(None),
            before: RefCell::new(None),
            last_changed: RefCell::new(None),
            recurse: RefCell::new(recurse),
            depth0,
        });
        if let Value::Object(rc) = &v {
            if let Some(lc) = v.downcast::<LoopContext>() {
                *lc.me.borrow_mut() = Rc::downgrade(rc);
            }
        }
        Ok(v)
    }

    fn pull(&self) -> Result<Option<Value>> {
        let mut it = std::mem::replace(&mut *self.iterator.borrow_mut(), PyIter::Done);
        let r = it.next();
        *self.iterator.borrow_mut() = it;
        r
    }

    /// `__next__`, without the `(item, self)` pairing.
    fn advance(&self) -> Result<Option<Value>> {
        let after = self.after.borrow_mut().take();
        let rv = match after {
            Some(a) => a,
            None => match self.pull()? {
                Some(v) => v,
                None => return Ok(None),
            },
        };
        self.index0.set(self.index0.get() + 1);
        let current = self.current.borrow_mut().take();
        *self.before.borrow_mut() = current;
        *self.current.borrow_mut() = Some(rv.clone());
        Ok(Some(rv))
    }

    fn peek(&self) -> Result<Option<Value>> {
        if let Some(a) = self.after.borrow().clone() {
            return Ok(Some(a));
        }
        let next = self.pull()?;
        *self.after.borrow_mut() = next.clone();
        Ok(next)
    }

    fn length(&self) -> Result<usize> {
        if let Some(n) = self.length.get() {
            return Ok(n);
        }
        let iterable = self.iterable.borrow().clone();
        let n = match ops::len(&iterable) {
            Ok(n) => n,
            Err(e) if e.kind == "TypeError" => {
                let it = std::mem::replace(&mut *self.iterator.borrow_mut(), PyIter::Done);
                let items = it.collect()?;
                let n = items.len() as i64
                    + self.index0.get()
                    + 1
                    + i64::from(self.after.borrow().is_some());
                *self.iterator.borrow_mut() = PyIter::Seq(items.into());
                usize::try_from(n).unwrap_or(0)
            }
            Err(e) => return Err(e),
        };
        self.length.set(Some(n));
        Ok(n)
    }
}

impl Object for LoopContext {
    fn type_name(&self) -> &str {
        "LoopContext"
    }

    fn module(&self) -> &str {
        "jinja2.runtime"
    }

    fn repr(&self) -> Result<String> {
        Ok(format!(
            "<LoopContext {}/{}>",
            self.index0.get() + 1,
            self.length()?
        ))
    }

    fn len(&self) -> Option<Result<usize>> {
        Some(self.length())
    }

    fn iter(&self, me: &Value) -> Option<Result<PyIter>> {
        Some(Ok(PyIter::Obj(me.clone())))
    }

    fn next(&self) -> Option<Result<Option<Value>>> {
        let me = self.me.borrow().upgrade().map(Value::Object);
        Some(
            self.advance()
                .map(|item| item.map(|i| Value::tuple(vec![i, me.unwrap_or(Value::None)]))),
        )
    }

    fn attrs(&self) -> &'static [&'static str] {
        tables::ATTRS_LOOP
    }

    fn getattr(&self, me: &Value, name: &str) -> Option<Result<Value>> {
        let index0 = self.index0.get();
        Some(Ok(match name {
            "index0" => Value::int(index0),
            "index" => Value::int(index0 + 1),
            "depth0" => Value::int(self.depth0 as i64),
            "depth" => Value::int(self.depth0 as i64 + 1),
            "first" => Value::Bool(index0 == 0),
            "length" => return Some(self.length().map(|n| Value::int(n as i64))),
            "revindex" => return Some(self.length().map(|n| Value::int(n as i64 - index0))),
            "revindex0" => return Some(self.length().map(|n| Value::int(n as i64 - index0 - 1))),
            "last" => return Some(self.peek().map(|p| Value::Bool(p.is_none()))),
            "previtem" => {
                if index0 == 0 {
                    Value::undefined_hint("there is no previous item")
                } else {
                    self.before.borrow().clone().unwrap_or(Value::None)
                }
            }
            "nextitem" => {
                return Some(
                    self.peek().map(|p| {
                        p.unwrap_or_else(|| Value::undefined_hint("there is no next item"))
                    }),
                );
            }
            "cycle" | "changed" => Method::value(me, name),
            _ => return None,
        }))
    }

    fn call(
        &self,
        _me: &Value,
        args: Vec<Value>,
        kwargs: Vec<(Rc<str>, Value)>,
    ) -> Option<Result<Value>> {
        Some((|| {
            let bound = callargs::bind_values(
                "LoopContext.__call__",
                &["self", "iterable"],
                &[],
                std::iter::once(Value::None).chain(args).collect(),
                kwargs,
            )?;
            let recurse = self.recurse.borrow();
            let Some(r) = recurse.as_ref() else {
                return Err(Error::type_error(
                    "The loop must have the 'recursive' marker to be called recursively.",
                ));
            };
            let (f, scope) = (r.f.clone(), r.scope.clone());
            drop(recurse);
            self.vm
                .run_loop(&f, &scope, bound[1].clone(), self.depth0 + 1)
        })())
    }

    fn call_method(
        &self,
        _me: &Value,
        name: &str,
        args: Vec<Value>,
        kwargs: Vec<(Rc<str>, Value)>,
    ) -> Option<Result<Value>> {
        if let Some((k, _)) = kwargs.first() {
            return Some(Err(Error::type_error(format!(
                "LoopContext.{name}() got an unexpected keyword argument '{k}'"
            ))));
        }
        Some(match name {
            "cycle" => {
                if args.is_empty() {
                    Err(Error::type_error("no items for cycling given"))
                } else {
                    let n = args.len() as i64;
                    let i = self.index0.get().rem_euclid(n) as usize;
                    Ok(args[i].clone())
                }
            }
            "changed" => (|| {
                let changed = match &*self.last_changed.borrow() {
                    None => true,
                    Some(last) => {
                        last.len() != args.len()
                            || last.iter().zip(&args).try_fold(false, |acc, (a, b)| {
                                Ok::<bool, Error>(acc || !ops::eq(a, b)?)
                            })?
                    }
                };
                if changed {
                    *self.last_changed.borrow_mut() = Some(args);
                }
                Ok(Value::Bool(changed))
            })(),
            _ => return None,
        })
    }

    fn clear(&self) {
        if let Ok(mut r) = self.recurse.try_borrow_mut() {
            *r = None;
        }
        if let Ok(mut i) = self.iterator.try_borrow_mut() {
            *i = PyIter::Done;
        }
        if let Ok(mut i) = self.iterable.try_borrow_mut() {
            *i = Value::None;
        }
        for cell in [&self.after, &self.current, &self.before] {
            if let Ok(mut c) = cell.try_borrow_mut() {
                *c = None;
            }
        }
        if let Ok(mut c) = self.last_changed.try_borrow_mut() {
            *c = None;
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `jinja2.utils.missing`, read where the generated code does not check
/// for it.
#[derive(Debug)]
pub(crate) struct Missing;

impl Object for Missing {
    fn type_name(&self) -> &str {
        "MissingType"
    }

    fn module(&self) -> &str {
        "jinja2.utils"
    }

    fn repr(&self) -> Result<String> {
        Ok("missing".into())
    }

    fn attrs(&self) -> &'static [&'static str] {
        OBJECT_ATTRS
    }

    fn eq(&self, other: &Value) -> Option<bool> {
        Some(other.downcast::<Missing>().is_some())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `self` in a template (`jinja2.runtime.TemplateReference`).
pub(crate) struct TemplateReference {
    vm: Vm,
    ctx: RefCell<Option<Rc<Context>>>,
}

impl std::fmt::Debug for TemplateReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<TemplateReference None>")
    }
}

impl Object for TemplateReference {
    fn type_name(&self) -> &str {
        "TemplateReference"
    }

    fn module(&self) -> &str {
        "jinja2.runtime"
    }

    fn repr(&self) -> Result<String> {
        Ok("<TemplateReference None>".into())
    }

    fn attrs(&self) -> &'static [&'static str] {
        OBJECT_ATTRS
    }

    fn getitem(&self, key: &Value) -> Option<Result<Value>> {
        let found = key
            .as_str()
            .and_then(|k| self.vm.0.blocks.iter().find(|b| &*b.name == k))
            .map(|b| b.name.clone());
        Some(match (found, self.ctx.borrow().clone()) {
            (Some(name), Some(ctx)) => Ok(Value::object(BlockReference {
                vm: self.vm.clone(),
                name,
                ctx: RefCell::new(Some(ctx)),
                depth: 0,
            })),
            _ => pyrepr::repr(key).and_then(|r| Err(Error::key(r))),
        })
    }

    fn clear(&self) {
        if let Ok(mut c) = self.ctx.try_borrow_mut() {
            *c = None;
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `self.<block>` (`jinja2.runtime.BlockReference`).
pub(crate) struct BlockReference {
    vm: Vm,
    name: Rc<str>,
    ctx: RefCell<Option<Rc<Context>>>,
    depth: usize,
}

impl std::fmt::Debug for BlockReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<BlockReference>")
    }
}

impl Object for BlockReference {
    fn type_name(&self) -> &str {
        "BlockReference"
    }

    fn module(&self) -> &str {
        "jinja2.runtime"
    }

    fn repr(&self) -> Result<String> {
        Ok(format!(
            "<jinja2.runtime.BlockReference object at {}>",
            objects::addr(self)
        ))
    }

    fn attrs(&self) -> &'static [&'static str] {
        &[
            "__call__",
            "__class__",
            "__dict__",
            "__doc__",
            "__init__",
            "__module__",
            "__repr__",
            "_context",
            "_depth",
            "_stack",
            "name",
            "super",
        ]
    }

    fn getattr(&self, _me: &Value, name: &str) -> Option<Result<Value>> {
        Some(Ok(match name {
            "name" => Value::Str(self.name.clone()),
            "super" => undefined_named(
                format!("there is no parent block called {}.", str_repr(&self.name)),
                "super",
            ),
            _ => return None,
        }))
    }

    fn call(
        &self,
        _me: &Value,
        args: Vec<Value>,
        kwargs: Vec<(Rc<str>, Value)>,
    ) -> Option<Result<Value>> {
        Some((|| {
            callargs::bind_values(
                "BlockReference.__call__",
                &["self"],
                &[],
                vec![Value::None],
                kwargs,
            )?;
            if !args.is_empty() {
                return Err(Error::type_error(format!(
                    "BlockReference.__call__() takes 1 positional argument but {} were given",
                    args.len() + 1
                )));
            }
            let ctx = self.ctx.borrow().clone().ok_or_else(internal)?;
            let _ = self.depth;
            let mut buf = Sink::buffer();
            self.vm.run_block(&self.name, &ctx, &mut buf)?;
            let rv = buf.finish()?;
            Ok(if ops::truthy(&self.vm.autoescape())? {
                Value::markup(rv)
            } else {
                Value::str(rv)
            })
        })())
    }

    fn clear(&self) {
        if let Ok(mut c) = self.ctx.try_borrow_mut() {
            *c = None;
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
