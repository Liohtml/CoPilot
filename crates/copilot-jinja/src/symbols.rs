//! Which frame each name belongs to (`jinja2/idtracking.py`), and the
//! searches the compiler makes over the tree (`find_undeclared`, `find_all`).
//!
//! A name is identified by the frame level that defines it: Jinja2 compiles
//! `x` to the Python variable `l_<level>_x`, and that is what decides which
//! assignment a read sees.

use std::collections::BTreeSet;
use std::rc::Rc;

use crate::ast::*;
use crate::error::{Error, Result};
use crate::pyrepr::str_repr;

/// A compiled variable: `l_<level>_<name>`.
pub type Ident = (usize, Rc<str>);

/// How a frame's variable is initialised on entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadInstr {
    /// Bound by the construct.
    Param,
    /// `resolve(name)` from the context.
    Resolve(Rc<str>),
    /// Copied from an outer frame's variable.
    Alias(Ident),
    /// `missing`.
    Undefined,
}

/// `Symbols`.
#[derive(Debug, Clone, Default)]
pub struct Symbols {
    /// The frame level.
    pub level: usize,
    /// The enclosing frame's symbols, as they were when this frame was made.
    pub parent: Option<Rc<Symbols>>,
    refs: Vec<Rc<str>>,
    loads: Vec<(Ident, LoadInstr)>,
    stores: BTreeSet<Rc<str>>,
}

impl Symbols {
    /// `Symbols(parent, level)`.
    pub fn new(parent: Option<Rc<Symbols>>, level: Option<usize>) -> Self {
        let level = level.unwrap_or_else(|| parent.as_ref().map_or(0, |p| p.level + 1));
        Self {
            level,
            parent,
            ..Self::default()
        }
    }

    fn set_load(&mut self, ident: Ident, load: LoadInstr) {
        match self.loads.iter_mut().find(|(i, _)| *i == ident) {
            Some(slot) => slot.1 = load,
            None => self.loads.push((ident, load)),
        }
    }

    fn define_ref(&mut self, name: &Rc<str>, load: Option<LoadInstr>) -> Ident {
        let ident = (self.level, name.clone());
        if !self.refs.contains(name) {
            self.refs.push(name.clone());
        }
        if let Some(load) = load {
            self.set_load(ident.clone(), load);
        }
        ident
    }

    /// `find_load`.
    pub fn find_load(&self, ident: &Ident) -> Option<LoadInstr> {
        if let Some((_, l)) = self.loads.iter().find(|(i, _)| i == ident) {
            return Some(l.clone());
        }
        self.parent.as_ref().and_then(|p| p.find_load(ident))
    }

    /// `find_ref`.
    pub fn find_ref(&self, name: &str) -> Option<Ident> {
        if self.refs.iter().any(|r| &**r == name) {
            return Some((self.level, Rc::from(name)));
        }
        self.parent.as_ref().and_then(|p| p.find_ref(name))
    }

    /// `ref`: the variable a name compiles to.
    pub fn ref_(&self, name: &str) -> Result<Ident> {
        self.find_ref(name).ok_or_else(|| {
            Error::new(
                "AssertionError",
                format!(
                    "Tried to resolve a name to a reference that was unknown to the frame ({})",
                    str_repr(name)
                ),
            )
        })
    }

    /// `store`.
    pub fn store(&mut self, name: &Rc<str>) {
        self.stores.insert(name.clone());
        if self.refs.contains(name) {
            return;
        }
        if let Some(parent) = &self.parent {
            if let Some(outer) = parent.find_ref(name) {
                self.define_ref(name, Some(LoadInstr::Alias(outer)));
                return;
            }
        }
        self.define_ref(name, Some(LoadInstr::Undefined));
    }

    /// `declare_parameter`.
    pub fn declare_parameter(&mut self, name: &Rc<str>) -> Ident {
        self.stores.insert(name.clone());
        self.define_ref(name, Some(LoadInstr::Param))
    }

    /// `load`.
    pub fn load(&mut self, name: &Rc<str>) {
        if self.find_ref(name).is_none() {
            self.define_ref(name, Some(LoadInstr::Resolve(name.clone())));
        }
    }

    /// `branch_update`: names assigned in only some branches of an `if`.
    pub fn branch_update(&mut self, branches: Vec<Symbols>) {
        let mut stores: BTreeSet<Rc<str>> = BTreeSet::new();
        for b in &branches {
            stores.extend(b.stores.iter().cloned());
        }
        for s in &self.stores {
            stores.remove(s);
        }
        for b in branches {
            for r in b.refs {
                if !self.refs.contains(&r) {
                    self.refs.push(r);
                }
            }
            for (i, l) in b.loads {
                self.set_load(i, l);
            }
            self.stores.extend(b.stores);
        }
        for name in stores {
            let Some(target) = self.find_ref(&name) else {
                continue;
            };
            let outer = self.parent.as_ref().and_then(|p| p.find_ref(&name));
            match outer {
                Some(outer) => self.set_load(target, LoadInstr::Alias(outer)),
                None => self.set_load(target, LoadInstr::Resolve(name.clone())),
            }
        }
    }

    /// `dump_stores`: every name assigned here or in an enclosing frame, with
    /// the variable it reads as from here.
    pub fn dump_stores(&self) -> Vec<(Rc<str>, Ident)> {
        let mut out: Vec<(Rc<str>, Ident)> = Vec::new();
        let mut node: Option<&Symbols> = Some(self);
        while let Some(n) = node {
            for name in &n.stores {
                if !out.iter().any(|(k, _)| k == name) {
                    if let Some(r) = self.find_ref(name) {
                        out.push((name.clone(), r));
                    }
                }
            }
            node = n.parent.as_deref();
        }
        out
    }

    /// `dump_param_targets`: this frame's parameters.
    pub fn param_targets(&self) -> Vec<Ident> {
        self.loads
            .iter()
            .filter(|(_, l)| *l == LoadInstr::Param)
            .map(|(i, _)| i.clone())
            .collect()
    }

    /// The names assigned in this frame.
    pub fn stores(&self) -> &BTreeSet<Rc<str>> {
        &self.stores
    }

    /// The frame's load instructions, as a [`FrameSpec`].
    pub fn frame_spec(&self) -> FrameSpec {
        FrameSpec {
            level: self.level,
            loads: self
                .loads
                .iter()
                .map(|((_, name), l)| {
                    (
                        name.clone(),
                        match l {
                            LoadInstr::Param => Load::Param,
                            LoadInstr::Resolve(n) => Load::Resolve(n.clone()),
                            LoadInstr::Alias((level, _)) => Load::Alias(*level),
                            LoadInstr::Undefined => Load::Undefined,
                        },
                    )
                })
                .collect(),
        }
    }

    // --- RootVisitor ---------------------------------------------------------------

    /// `analyze_node` for the template.
    pub fn analyze_template(&mut self, body: &[Stmt]) {
        for s in body {
            self.visit_stmt(s);
        }
    }

    /// `analyze_node` for a macro or a call block's caller.
    pub fn analyze_macro(&mut self, m: &MacroDef) {
        for a in &m.args {
            self.declare_parameter(a);
        }
        for d in &m.defaults {
            self.visit_expr(d, false);
        }
        for s in &m.body {
            self.visit_stmt(s);
        }
    }

    /// `analyze_node` for a block.
    pub fn analyze_block(&mut self, body: &[Stmt]) {
        for s in body {
            self.visit_stmt(s);
        }
    }

    /// `analyze_node` for a `for` loop branch.
    pub fn analyze_for(&mut self, f: &For, branch: ForBranch) {
        match branch {
            ForBranch::Body => {
                self.visit_expr(&f.target, true);
                for s in &f.body {
                    self.visit_stmt(s);
                }
            }
            ForBranch::Else => {
                for s in &f.else_ {
                    self.visit_stmt(s);
                }
            }
            ForBranch::Test => {
                self.visit_expr(&f.target, true);
                if let Some(t) = &f.test {
                    self.visit_expr(t, false);
                }
            }
        }
    }

    /// `analyze_node` for `with`.
    pub fn analyze_with(&mut self, w: &With) {
        for t in &w.targets {
            self.visit_expr(t, false);
        }
        for s in &w.body {
            self.visit_stmt(s);
        }
    }

    /// `analyze_node` for a filter block.
    pub fn analyze_filter_block(&mut self, f: &FilterBlock) {
        for s in &f.body {
            self.visit_stmt(s);
        }
        self.visit_expr(&f.filter, false);
    }

    /// `analyze_node` for a set block (its body only).
    pub fn analyze_body(&mut self, body: &[Stmt]) {
        for s in body {
            self.visit_stmt(s);
        }
    }

    // --- FrameSymbolVisitor ------------------------------------------------------

    fn visit_if_branches(
        &mut self,
        test: &Expr,
        body: &[Stmt],
        elif: &[(Expr, Vec<Stmt>)],
        else_: &[Stmt],
    ) {
        self.visit_expr(test, false);
        let mut body_symbols = self.clone();
        for s in body {
            body_symbols.visit_stmt(s);
        }
        let mut elif_symbols = self.clone();
        for (t, b) in elif {
            elif_symbols.visit_if_branches(t, b, &[], &[]);
        }
        let mut else_symbols = self.clone();
        for s in else_ {
            else_symbols.visit_stmt(s);
        }
        self.branch_update(vec![body_symbols, elif_symbols, else_symbols]);
    }

    /// `FrameSymbolVisitor.visit` for a statement.
    pub fn visit_stmt(&mut self, s: &Stmt) {
        match s {
            Stmt::Output(o) => {
                for item in &o.items {
                    if let OutItem::Expr(e) = item {
                        self.visit_expr(e, false);
                    }
                }
            }
            Stmt::For(f) => self.visit_expr(&f.iter, false),
            Stmt::If(i) => self.visit_if_branches(&i.test, &i.body, &i.elif, &i.else_),
            Stmt::Macro(m) => {
                if let Some(n) = &m.name {
                    self.store(n);
                }
            }
            Stmt::CallBlock(c) => self.visit_expr(&c.call, false),
            Stmt::FilterBlock(f) => self.visit_expr(&f.filter, false),
            Stmt::With(w) => {
                for v in &w.values {
                    self.visit_expr(v, false);
                }
            }
            Stmt::Block(_) | Stmt::Scope(_) => {}
            Stmt::Extends(e) => self.visit_expr(&e.template, false),
            Stmt::Load(l) => {
                self.visit_expr(&l.template, false);
                for t in &l.targets {
                    self.store(t);
                }
            }
            Stmt::Assign(a) => {
                self.visit_expr(&a.value, false);
                self.visit_expr(&a.target, false);
            }
            Stmt::AssignBlock(a) => self.visit_expr(&a.target, false),
            Stmt::EvalContextModifier(m) => {
                self.visit_expr(&m.autoescape, false);
                for s in &m.body {
                    self.visit_stmt(s);
                }
            }
        }
    }

    fn visit_args(&mut self, a: &Args) {
        for e in &a.args {
            self.visit_expr(e, false);
        }
        for (_, e) in &a.kwargs {
            self.visit_expr(e, false);
        }
        if let Some(e) = &a.dyn_args {
            self.visit_expr(e, false);
        }
        if let Some(e) = &a.dyn_kwargs {
            self.visit_expr(e, false);
        }
    }

    fn visit_call(&mut self, c: &Call) {
        self.visit_expr(&c.node, false);
        self.visit_args(&c.args);
    }

    /// `FrameSymbolVisitor.visit` for an expression.
    pub fn visit_expr(&mut self, e: &Expr, param: bool) {
        match e {
            Expr::Name(n, ctx) => {
                if param || *ctx == Ctx::Param {
                    self.declare_parameter(n);
                } else if *ctx == Ctx::Store {
                    self.store(n);
                } else {
                    self.load(n);
                }
            }
            Expr::NsRef(n, _) => self.load(n),
            Expr::Const(_)
            | Expr::TemplateData(_)
            | Expr::Load(..)
            | Expr::Store(..)
            | Expr::StoreNs(..) => {}
            Expr::Tuple(items, _) | Expr::List(items) => {
                for i in items {
                    self.visit_expr(i, param);
                }
            }
            Expr::Dict(pairs) => {
                for (k, v) in pairs {
                    self.visit_expr(k, param);
                    self.visit_expr(v, param);
                }
            }
            Expr::Bin(_, l, r) => {
                self.visit_expr(l, param);
                self.visit_expr(r, param);
            }
            Expr::Unary(_, n) => self.visit_expr(n, param),
            Expr::Concat(items, _) => {
                for i in items {
                    self.visit_expr(i, param);
                }
            }
            Expr::Compare(first, ops) => {
                self.visit_expr(first, param);
                for (_, o) in ops {
                    self.visit_expr(o, param);
                }
            }
            Expr::Cond(c) => {
                self.visit_expr(&c.test, param);
                self.visit_expr(&c.expr1, param);
                if let Some(e2) = &c.expr2 {
                    self.visit_expr(e2, param);
                }
            }
            Expr::Getattr(n, _) => self.visit_expr(n, param),
            Expr::Getitem(n, a) => {
                self.visit_expr(n, param);
                self.visit_expr(a, param);
            }
            Expr::Slice(a, b, c) => {
                for x in [a, b, c].into_iter().flatten() {
                    self.visit_expr(x, param);
                }
            }
            Expr::Call(c) => self.visit_call(c),
            Expr::Filter(f) | Expr::Test(f) => {
                if let Some(n) = &f.node {
                    self.visit_expr(n, param);
                }
                self.visit_args(&f.args);
            }
        }
    }
}

/// Which part of a `for` loop a frame is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForBranch {
    /// The body.
    Body,
    /// The `else` body.
    Else,
    /// The `if` filter.
    Test,
}

// --- find_undeclared ---------------------------------------------------------------

struct Undeclared {
    names: Vec<&'static str>,
    found: Vec<&'static str>,
}

impl Undeclared {
    /// `false` once every name was found (`VisitorExit`).
    fn name(&mut self, n: &str, ctx: Ctx) -> bool {
        let pos = self.names.iter().position(|x| *x == n);
        match pos {
            Some(i) if ctx == Ctx::Load => {
                let name = self.names[i];
                if !self.found.contains(&name) {
                    self.found.push(name);
                }
                let same = self.found.len() == self.names.len()
                    && self.found.iter().all(|f| self.names.contains(f));
                if same {
                    return false;
                }
            }
            Some(i) => {
                self.names.remove(i);
            }
            None => {}
        }
        true
    }

    fn stmts(&mut self, body: &[Stmt]) -> bool {
        body.iter().all(|s| self.stmt(s))
    }

    fn macro_def(&mut self, m: &MacroDef) -> bool {
        for a in &m.args {
            if !self.name(a, Ctx::Param) {
                return false;
            }
        }
        m.defaults.iter().all(|d| self.expr(d)) && self.stmts(&m.body)
    }

    fn stmt(&mut self, s: &Stmt) -> bool {
        match s {
            Stmt::Output(o) => o.items.iter().all(|i| match i {
                OutItem::Expr(e) => self.expr(e),
                OutItem::Text(_) => true,
            }),
            Stmt::For(f) => {
                self.expr(&f.target)
                    && self.expr(&f.iter)
                    && self.stmts(&f.body)
                    && self.stmts(&f.else_)
                    && f.test.as_ref().is_none_or(|t| self.expr(t))
            }
            Stmt::If(i) => {
                self.expr(&i.test)
                    && self.stmts(&i.body)
                    && i.elif.iter().all(|(t, b)| self.expr(t) && self.stmts(b))
                    && self.stmts(&i.else_)
            }
            Stmt::Macro(m) => self.macro_def(m),
            Stmt::CallBlock(c) => self.expr(&c.call) && self.macro_def(&c.caller),
            Stmt::FilterBlock(f) => self.stmts(&f.body) && self.expr(&f.filter),
            Stmt::With(w) => {
                w.targets.iter().all(|t| self.expr(t))
                    && w.values.iter().all(|v| self.expr(v))
                    && self.stmts(&w.body)
            }
            Stmt::Block(_) => true,
            Stmt::Extends(e) => self.expr(&e.template),
            Stmt::Load(l) => self.expr(&l.template),
            Stmt::Assign(a) => self.expr(&a.target) && self.expr(&a.value),
            Stmt::AssignBlock(a) => {
                self.expr(&a.target)
                    && a.filter.as_ref().is_none_or(|f| self.expr(f))
                    && self.stmts(&a.body)
            }
            Stmt::Scope(s) => self.stmts(&s.body),
            Stmt::EvalContextModifier(m) => self.expr(&m.autoescape) && self.stmts(&m.body),
        }
    }

    fn args(&mut self, a: &Args) -> bool {
        a.args.iter().all(|e| self.expr(e))
            && a.kwargs.iter().all(|(_, e)| self.expr(e))
            && a.dyn_args.as_ref().is_none_or(|e| self.expr(e))
            && a.dyn_kwargs.as_ref().is_none_or(|e| self.expr(e))
    }

    fn call(&mut self, c: &Call) -> bool {
        self.expr(&c.node) && self.args(&c.args)
    }

    fn expr(&mut self, e: &Expr) -> bool {
        match e {
            Expr::Name(n, ctx) => self.name(n, *ctx),
            Expr::Load(n, ..) => self.name(n, Ctx::Load),
            Expr::Store(n, _) => self.name(n, Ctx::Store),
            Expr::NsRef(..) | Expr::StoreNs(..) | Expr::Const(_) | Expr::TemplateData(_) => true,
            Expr::Tuple(items, _) | Expr::List(items) | Expr::Concat(items, _) => {
                items.iter().all(|i| self.expr(i))
            }
            Expr::Dict(pairs) => pairs.iter().all(|(k, v)| self.expr(k) && self.expr(v)),
            Expr::Bin(_, l, r) => self.expr(l) && self.expr(r),
            Expr::Unary(_, n) | Expr::Getattr(n, _) => self.expr(n),
            Expr::Compare(first, ops) => self.expr(first) && ops.iter().all(|(_, o)| self.expr(o)),
            Expr::Cond(c) => {
                self.expr(&c.test)
                    && self.expr(&c.expr1)
                    && c.expr2.as_ref().is_none_or(|e| self.expr(e))
            }
            Expr::Getitem(n, a) => self.expr(n) && self.expr(a),
            Expr::Slice(a, b, c) => [a, b, c].into_iter().flatten().all(|x| self.expr(x)),
            Expr::Call(c) => self.call(c),
            Expr::Filter(f) | Expr::Test(f) => {
                f.node.as_ref().is_none_or(|n| self.expr(n)) && self.args(&f.args)
            }
        }
    }
}

/// `find_undeclared(nodes, names)`: which of `names` the statements read
/// before (in tree order) anything binds them. Blocks are not searched.
pub fn find_undeclared(body: &[Stmt], names: &[&'static str]) -> Vec<&'static str> {
    let mut v = Undeclared {
        names: names.to_vec(),
        found: Vec::new(),
    };
    v.stmts(body);
    v.found
}

// --- find_all ------------------------------------------------------------------------

/// What `find_all` over a loop needs to know: a scoped block anywhere in it,
/// and a variable named `loop` assigned anywhere in it.
#[derive(Debug, Default, Clone, Copy)]
pub struct Subtree {
    /// `any(block.scoped for block in node.find_all(Block))`.
    pub scoped_block: bool,
    /// A `Name("loop", "store")` somewhere below.
    pub stores_loop: bool,
}

impl Subtree {
    fn merge(&mut self, o: Subtree) {
        self.scoped_block |= o.scoped_block;
        self.stores_loop |= o.stores_loop;
    }
}

/// Searches statements (the bodies of extracted blocks through the flags
/// recorded on them).
pub fn subtree_stmts(body: &[Stmt]) -> Subtree {
    let mut out = Subtree::default();
    for s in body {
        out.merge(subtree_stmt(s));
    }
    out
}

fn subtree_macro(m: &MacroDef) -> Subtree {
    let mut out = Subtree::default();
    for d in &m.defaults {
        out.merge(subtree_expr(d));
    }
    out.merge(subtree_stmts(&m.body));
    out
}

fn subtree_stmt(s: &Stmt) -> Subtree {
    let mut out = Subtree::default();
    match s {
        Stmt::Output(o) => {
            for i in &o.items {
                if let OutItem::Expr(e) = i {
                    out.merge(subtree_expr(e));
                }
            }
        }
        Stmt::For(f) => out.merge(subtree_for(f)),
        Stmt::If(i) => {
            out.merge(subtree_expr(&i.test));
            out.merge(subtree_stmts(&i.body));
            for (t, b) in &i.elif {
                out.merge(subtree_expr(t));
                out.merge(subtree_stmts(b));
            }
            out.merge(subtree_stmts(&i.else_));
        }
        Stmt::Macro(m) => out.merge(subtree_macro(m)),
        Stmt::CallBlock(c) => {
            out.merge(subtree_expr(&c.call));
            out.merge(subtree_macro(&c.caller));
        }
        Stmt::FilterBlock(f) => {
            out.merge(subtree_stmts(&f.body));
            out.merge(subtree_expr(&f.filter));
        }
        Stmt::With(w) => {
            for t in &w.targets {
                out.merge(subtree_expr(t));
            }
            for v in &w.values {
                out.merge(subtree_expr(v));
            }
            out.merge(subtree_stmts(&w.body));
        }
        Stmt::Block(b) => {
            out.scoped_block |= b.scoped || b.subtree_scoped;
            out.stores_loop |= b.subtree_stores_loop;
            out.merge(subtree_stmts(&b.body));
        }
        Stmt::Extends(e) => out.merge(subtree_expr(&e.template)),
        Stmt::Load(l) => out.merge(subtree_expr(&l.template)),
        Stmt::Assign(a) => {
            out.merge(subtree_expr(&a.target));
            out.merge(subtree_expr(&a.value));
        }
        Stmt::AssignBlock(a) => {
            out.merge(subtree_expr(&a.target));
            if let Some(f) = &a.filter {
                out.merge(subtree_expr(f));
            }
            out.merge(subtree_stmts(&a.body));
        }
        Stmt::Scope(s) => out.merge(subtree_stmts(&s.body)),
        Stmt::EvalContextModifier(m) => {
            out.merge(subtree_expr(&m.autoescape));
            out.merge(subtree_stmts(&m.body));
        }
    }
    out
}

/// The search over a whole `for` statement.
pub fn subtree_for(f: &For) -> Subtree {
    let mut out = subtree_expr(&f.target);
    out.merge(subtree_expr(&f.iter));
    out.merge(subtree_stmts(&f.body));
    out.merge(subtree_stmts(&f.else_));
    if let Some(t) = &f.test {
        out.merge(subtree_expr(t));
    }
    out
}

fn subtree_args(a: &Args) -> Subtree {
    let mut out = Subtree::default();
    for e in a.args.iter().chain(a.kwargs.iter().map(|(_, e)| e)) {
        out.merge(subtree_expr(e));
    }
    for e in [&a.dyn_args, &a.dyn_kwargs].into_iter().flatten() {
        out.merge(subtree_expr(e));
    }
    out
}

fn subtree_call(c: &Call) -> Subtree {
    let mut out = subtree_expr(&c.node);
    out.merge(subtree_args(&c.args));
    out
}

fn subtree_expr(e: &Expr) -> Subtree {
    let mut out = Subtree::default();
    match e {
        Expr::Name(n, ctx) => out.stores_loop = *ctx == Ctx::Store && &**n == "loop",
        Expr::Store(n, _) => out.stores_loop = &**n == "loop",
        Expr::Load(..)
        | Expr::NsRef(..)
        | Expr::StoreNs(..)
        | Expr::Const(_)
        | Expr::TemplateData(_) => {}
        Expr::Tuple(items, _) | Expr::List(items) | Expr::Concat(items, _) => {
            for i in items {
                out.merge(subtree_expr(i));
            }
        }
        Expr::Dict(pairs) => {
            for (k, v) in pairs {
                out.merge(subtree_expr(k));
                out.merge(subtree_expr(v));
            }
        }
        Expr::Bin(_, l, r) | Expr::Getitem(l, r) => {
            out.merge(subtree_expr(l));
            out.merge(subtree_expr(r));
        }
        Expr::Unary(_, n) | Expr::Getattr(n, _) => out.merge(subtree_expr(n)),
        Expr::Compare(first, ops) => {
            out.merge(subtree_expr(first));
            for (_, o) in ops {
                out.merge(subtree_expr(o));
            }
        }
        Expr::Cond(c) => {
            out.merge(subtree_expr(&c.test));
            out.merge(subtree_expr(&c.expr1));
            if let Some(e2) = &c.expr2 {
                out.merge(subtree_expr(e2));
            }
        }
        Expr::Slice(a, b, c) => {
            for x in [a, b, c].into_iter().flatten() {
                out.merge(subtree_expr(x));
            }
        }
        Expr::Call(c) => out.merge(subtree_call(c)),
        Expr::Filter(f) | Expr::Test(f) => {
            if let Some(n) = &f.node {
                out.merge(subtree_expr(n));
            }
            out.merge(subtree_args(&f.args));
        }
    }
    out
}

/// `node.find(Extends) is not None` over the whole template.
pub fn has_extends(body: &[Stmt]) -> bool {
    body.iter().any(|s| match s {
        Stmt::Extends(_) => true,
        Stmt::For(f) => has_extends(&f.body) || has_extends(&f.else_),
        Stmt::If(i) => {
            has_extends(&i.body)
                || i.elif.iter().any(|(_, b)| has_extends(b))
                || has_extends(&i.else_)
        }
        Stmt::Macro(m) => has_extends(&m.body),
        Stmt::CallBlock(c) => has_extends(&c.caller.body),
        Stmt::FilterBlock(f) => has_extends(&f.body),
        Stmt::With(w) => has_extends(&w.body),
        Stmt::Block(b) => has_extends(&b.body),
        Stmt::AssignBlock(a) => has_extends(&a.body),
        Stmt::Scope(s) => has_extends(&s.body),
        Stmt::EvalContextModifier(m) => has_extends(&m.body),
        Stmt::Output(_) | Stmt::Load(_) | Stmt::Assign(_) => false,
    })
}
