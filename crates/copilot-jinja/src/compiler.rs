//! What Jinja2's code generator (`jinja2/compiler.py`) decides at compile
//! time, applied to the tree instead of emitted as Python: which frame each
//! name belongs to, the constant folding of its optimizer, how output is
//! escaped, and the compile-time errors, raised in the order the generator
//! would reach them.

use std::rc::Rc;

use crate::ast::*;
use crate::attrs;
use crate::error::{Error, Result};
use crate::filters::{self, FilterCx, Pass};
use crate::jtests;
use crate::markup;
use crate::ops::{self, BinOp, CmpOp};
use crate::parser::Parser;
use crate::pyrepr;
use crate::symbols::{self, ForBranch, Ident, LoadInstr, Symbols};
use crate::value::Value;

/// A compiled template.
#[derive(Debug)]
pub struct Template {
    pub(crate) body: Vec<Stmt>,
    pub(crate) frame: FrameSpec,
    pub(crate) self_param: bool,
    pub(crate) blocks: Vec<Rc<BlockDef>>,
    pub(crate) autoescape: bool,
}

/// Parses and compiles `source` (`Environment.from_string`).
pub fn compile(source: &str, autoescape: bool) -> Result<Template> {
    let body = Parser::new(source)?.parse()?;
    Compiler::new(autoescape).template(body)
}

/// The compile-time `EvalContext`.
#[derive(Clone)]
struct EvalCtx {
    autoescape: Value,
    volatile: bool,
}

/// A code generator `Frame`.
#[derive(Clone)]
struct Frame {
    symbols: Symbols,
    toplevel: bool,
    rootlevel: bool,
    loop_frame: bool,
    block_frame: bool,
    soft_frame: bool,
    require_output_check: bool,
}

impl Frame {
    fn new() -> Self {
        Self {
            symbols: Symbols::new(None, None),
            toplevel: false,
            rootlevel: false,
            loop_frame: false,
            block_frame: false,
            soft_frame: false,
            require_output_check: false,
        }
    }

    fn inner(&self) -> Self {
        Self {
            symbols: Symbols::new(Some(Rc::new(self.symbols.clone())), None),
            toplevel: false,
            rootlevel: false,
            loop_frame: false,
            block_frame: false,
            soft_frame: false,
            require_output_check: self.require_output_check,
        }
    }

    fn soft(&self) -> Self {
        let mut f = self.clone();
        f.rootlevel = false;
        f.soft_frame = true;
        f
    }
}

/// Why constant folding gave up: `Impossible`, or an exception the
/// optimizer lets through.
enum Fold {
    Impossible,
    Raise(Error),
}

type Folded = std::result::Result<Value, Fold>;

fn raise(e: Error) -> Fold {
    Fold::Raise(e)
}

/// What visiting a statement means for the rest of its body.
enum Step {
    Keep,
    Drop,
    /// `CompilerExit`: nothing after this statement is generated.
    Exit,
}

struct Compiler {
    eval: EvalCtx,
    has_known_extends: bool,
    extends_so_far: usize,
    assign_stack: Vec<Vec<Rc<str>>>,
    param_def_block: Vec<Vec<Ident>>,
    misplaced_slice: bool,
}

fn internal() -> Error {
    Error::new("AssertionError", "internal compiler error")
}

/// `has_safe_repr`: what the optimizer may write back as a literal.
fn has_safe_repr(v: &Value) -> bool {
    match v {
        Value::None
        | Value::Bool(_)
        | Value::Int(_)
        | Value::Float(_)
        | Value::Str(_)
        | Value::Markup(_) => true,
        Value::Tuple(t) => t.iter().all(has_safe_repr),
        Value::List(l) => l.borrow().iter().all(has_safe_repr),
        Value::Dict(d) => {
            let d = d.borrow();
            !d.default_str
                && d.entries
                    .iter()
                    .all(|(k, v)| has_safe_repr(k) && has_safe_repr(v))
        }
        _ => false,
    }
}

fn binop_of(k: BinKind) -> Option<BinOp> {
    Some(match k {
        BinKind::Add => BinOp::Add,
        BinKind::Sub => BinOp::Sub,
        BinKind::Mul => BinOp::Mul,
        BinKind::Div => BinOp::Div,
        BinKind::FloorDiv => BinOp::FloorDiv,
        BinKind::Mod => BinOp::Mod,
        BinKind::Pow => BinOp::Pow,
        BinKind::And | BinKind::Or => return None,
    })
}

/// One comparison of a chain (`_cmpop_to_func`).
pub(crate) fn compare(op: CmpKind, a: &Value, b: &Value) -> Result<bool> {
    Ok(match op {
        CmpKind::Eq => ops::compare(CmpOp::Eq, a, b)?,
        CmpKind::Ne => ops::compare(CmpOp::Ne, a, b)?,
        CmpKind::Gt => ops::compare(CmpOp::Gt, a, b)?,
        CmpKind::GtEq => ops::compare(CmpOp::Ge, a, b)?,
        CmpKind::Lt => ops::compare(CmpOp::Lt, a, b)?,
        CmpKind::LtEq => ops::compare(CmpOp::Le, a, b)?,
        CmpKind::In => ops::contains(a, b)?,
        CmpKind::NotIn => !ops::contains(a, b)?,
    })
}

fn is_opt(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Bin(..)
            | Expr::Unary(..)
            | Expr::Concat(..)
            | Expr::Compare(..)
            | Expr::Cond(_)
            | Expr::Getattr(..)
            | Expr::Getitem(..)
            | Expr::Call(_)
            | Expr::Filter(_)
            | Expr::Test(_)
    )
}

impl Compiler {
    fn new(autoescape: bool) -> Self {
        Self {
            eval: EvalCtx {
                autoescape: Value::Bool(autoescape),
                volatile: false,
            },
            has_known_extends: false,
            extends_so_far: 0,
            assign_stack: Vec::new(),
            param_def_block: Vec::new(),
            misplaced_slice: false,
        }
    }

    /// `bool(frame.eval_ctx.autoescape)`.
    fn ae(&self) -> Result<bool> {
        ops::truthy(&self.eval.autoescape)
    }

    fn escape_mode(&self) -> Result<Escape> {
        Ok(if self.eval.volatile {
            Escape::Volatile
        } else if self.ae()? {
            Escape::On
        } else {
            Escape::Off
        })
    }

    // --- the template ------------------------------------------------------------------

    fn template(mut self, mut body: Vec<Stmt>) -> Result<Template> {
        let autoescape = ops::truthy(&self.eval.autoescape)?;
        let have_extends = symbols::has_extends(&body);
        let mut blocks: Vec<(Rc<str>, Vec<Stmt>)> = Vec::new();
        extract_blocks(&mut body, &mut blocks)?;

        let mut frame = Frame::new();
        let self_param = symbols::find_undeclared(&body, &["self"]).contains(&"self");
        if self_param {
            frame.symbols.declare_parameter(&Rc::from("self"));
        }
        frame.symbols.analyze_template(&body);
        frame.toplevel = true;
        frame.rootlevel = true;
        frame.require_output_check = have_extends && !self.has_known_extends;
        self.blockvisit(&mut body, &frame)?;
        let root_spec = frame.symbols.frame_spec();

        let mut defs = Vec::new();
        for (name, mut bbody) in blocks {
            let mut bframe = Frame::new();
            bframe.block_frame = true;
            let undeclared = symbols::find_undeclared(&bbody, &["self", "super"]);
            let self_param = undeclared.contains(&"self");
            let super_param = undeclared.contains(&"super");
            if self_param {
                bframe.symbols.declare_parameter(&Rc::from("self"));
            }
            if super_param {
                bframe.symbols.declare_parameter(&Rc::from("super"));
            }
            bframe.symbols.analyze_block(&bbody);
            self.blockvisit(&mut bbody, &bframe)?;
            defs.push(Rc::new(BlockDef {
                name,
                body: bbody,
                frame: bframe.symbols.frame_spec(),
                self_param,
                super_param,
            }));
        }
        if self.misplaced_slice {
            // The generated Python does not compile: a slice outside a subscript.
            return Err(Error::new("SyntaxError", "invalid syntax (<template>)"));
        }
        Ok(Template {
            body,
            frame: root_spec,
            self_param,
            blocks: defs,
            autoescape,
        })
    }

    // --- statements --------------------------------------------------------------------

    /// `blockvisit`: stops at `CompilerExit`.
    fn blockvisit(&mut self, body: &mut Vec<Stmt>, frame: &Frame) -> Result<()> {
        let mut i = 0;
        while i < body.len() {
            match self.visit_stmt(&mut body[i], frame)? {
                Step::Keep => i += 1,
                Step::Drop => {
                    body.remove(i);
                }
                Step::Exit => {
                    body.truncate(i);
                    break;
                }
            }
        }
        Ok(())
    }

    fn visit_stmt(&mut self, s: &mut Stmt, frame: &Frame) -> Result<Step> {
        match s {
            Stmt::Output(o) => self.visit_output(o, frame),
            Stmt::For(f) => {
                let f = Rc::get_mut(f).ok_or_else(internal)?;
                self.visit_for(f, frame)?;
                Ok(Step::Keep)
            }
            Stmt::If(i) => {
                let soft = frame.soft();
                self.visit_expr(&mut i.test, &soft, false)?;
                self.blockvisit(&mut i.body, &soft)?;
                for (t, b) in i.elif.iter_mut() {
                    self.visit_expr(t, &soft, false)?;
                    self.blockvisit(b, &soft)?;
                }
                self.blockvisit(&mut i.else_, &soft)?;
                Ok(Step::Keep)
            }
            Stmt::Macro(m) => {
                let m = Rc::get_mut(m).ok_or_else(internal)?;
                self.macro_body(m, frame)?;
                let name = m.name.clone().ok_or_else(internal)?;
                m.store_level = frame.symbols.ref_(&name)?.0;
                m.toplevel = frame.toplevel;
                Ok(Step::Keep)
            }
            Stmt::CallBlock(c) => {
                let caller = Rc::get_mut(&mut c.caller).ok_or_else(internal)?;
                self.macro_body(caller, frame)?;
                self.visit_expr(&mut c.call, frame, false)?;
                Ok(Step::Keep)
            }
            Stmt::FilterBlock(fb) => {
                let mut filter_frame = frame.inner();
                filter_frame.symbols.analyze_filter_block(fb);
                self.blockvisit(&mut fb.body, &filter_frame)?;
                self.visit_expr(&mut fb.filter, &filter_frame, false)?;
                fb.frame = filter_frame.symbols.frame_spec();
                Ok(Step::Keep)
            }
            Stmt::With(w) => {
                let mut with_frame = frame.inner();
                with_frame.symbols.analyze_with(w);
                for (t, v) in w.targets.iter_mut().zip(w.values.iter_mut()) {
                    self.visit_expr(t, &with_frame, false)?;
                    self.visit_expr(v, frame, false)?;
                }
                self.blockvisit(&mut w.body, &with_frame)?;
                w.frame = with_frame.symbols.frame_spec();
                Ok(Step::Keep)
            }
            Stmt::Block(b) => {
                if frame.toplevel && self.has_known_extends {
                    return Ok(Step::Drop);
                }
                if b.scoped {
                    b.locals = frame
                        .symbols
                        .dump_stores()
                        .into_iter()
                        .map(|(n, (level, _))| (n, level))
                        .collect();
                }
                Ok(Step::Keep)
            }
            Stmt::Extends(e) => {
                if !frame.toplevel {
                    return Err(Error::assertion(
                        "cannot use extend from a non top-level scope",
                    ));
                }
                if self.extends_so_far > 0 && self.has_known_extends {
                    return Ok(Step::Exit);
                }
                self.visit_expr(e, frame, false)?;
                if frame.rootlevel {
                    self.has_known_extends = true;
                }
                self.extends_so_far += 1;
                Ok(Step::Keep)
            }
            Stmt::Load(l) => {
                if l.kind == LoadKind::Import && l.targets.len() == 1 {
                    frame.symbols.ref_(&l.targets[0])?;
                }
                self.visit_expr(&mut l.template, frame, false)?;
                Ok(Step::Keep)
            }
            Stmt::Assign(a) => {
                self.assign_stack.push(Vec::new());
                self.visit_expr(&mut a.target, frame, false)?;
                self.visit_expr(&mut a.value, frame, false)?;
                a.export = self.pop_assign_tracking(frame)?;
                Ok(Step::Keep)
            }
            Stmt::AssignBlock(a) => {
                self.assign_stack.push(Vec::new());
                let mut block_frame = frame.inner();
                block_frame.require_output_check = false;
                block_frame.symbols.analyze_body(&a.body);
                self.blockvisit(&mut a.body, &block_frame)?;
                self.visit_expr(&mut a.target, frame, false)?;
                if let Some(f) = &mut a.filter {
                    self.visit_expr(f, &block_frame, false)?;
                }
                a.export = self.pop_assign_tracking(frame)?;
                a.frame = block_frame.symbols.frame_spec();
                Ok(Step::Keep)
            }
            Stmt::Scope(sc) => {
                let mut scope_frame = frame.inner();
                scope_frame.symbols.analyze_body(&sc.body);
                self.blockvisit(&mut sc.body, &scope_frame)?;
                sc.frame = scope_frame.symbols.frame_spec();
                Ok(Step::Keep)
            }
            Stmt::EvalContextModifier(m) => {
                let saved = self.eval.clone();
                self.visit_expr(&mut m.autoescape, frame, false)?;
                match self.as_const(&m.autoescape) {
                    Ok(v) => self.eval.autoescape = v,
                    Err(Fold::Impossible) => self.eval.volatile = true,
                    Err(Fold::Raise(e)) => return Err(e),
                }
                let mut i = 0;
                while i < m.body.len() {
                    match self.visit_stmt(&mut m.body[i], frame)? {
                        Step::Keep => i += 1,
                        Step::Drop => {
                            m.body.remove(i);
                        }
                        Step::Exit => {
                            // `CompilerExit` unwinds past the revert.
                            m.body.truncate(i);
                            return Ok(Step::Exit);
                        }
                    }
                }
                self.eval = saved;
                Ok(Step::Keep)
            }
        }
    }

    /// `pop_assign_tracking`: the names a top-level assignment exports.
    fn pop_assign_tracking(&mut self, frame: &Frame) -> Result<Vec<(Rc<str>, usize)>> {
        let vars = self.assign_stack.pop().unwrap_or_default();
        if (!frame.block_frame && !frame.loop_frame && !frame.toplevel) || vars.is_empty() {
            return Ok(Vec::new());
        }
        // Loop and block frames record into `_loop_vars` / `_block_vars`,
        // which only context functions read; none are installed.
        if frame.loop_frame || frame.block_frame {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for name in vars {
            let (level, _) = frame.symbols.ref_(&name)?;
            out.push((name, level));
        }
        Ok(out)
    }

    fn visit_output(&mut self, o: &mut Output, frame: &Frame) -> Result<Step> {
        if self.has_known_extends && frame.require_output_check {
            return Ok(Step::Drop);
        }
        let items = std::mem::take(&mut o.items);
        let mut out: Vec<OutItem> = Vec::new();
        for item in items {
            let OutItem::Expr(e) = item else {
                out.push(item);
                continue;
            };
            match self.output_const(&e) {
                Some(text) => match out.last_mut() {
                    Some(OutItem::Text(t)) => t.push_str(&text),
                    _ => out.push(OutItem::Text(text)),
                },
                None => out.push(OutItem::Expr(e)),
            }
        }
        for item in out.iter_mut() {
            if let OutItem::Expr(e) = item {
                o.escape = self.escape_mode()?;
                self.visit_expr(e, frame, false)?;
            }
        }
        o.items = out;
        Ok(Step::Keep)
    }

    /// `_output_child_to_const`, any failure meaning "at runtime".
    fn output_const(&self, e: &Expr) -> Option<String> {
        let v = self.as_const(e).ok()?;
        let v = if self.ae().ok()? {
            markup::escape(&v).ok()?
        } else {
            v
        };
        pyrepr::str(&v).ok()
    }

    fn visit_for(&mut self, f: &mut For, frame: &Frame) -> Result<()> {
        let mut loop_frame = frame.inner();
        loop_frame.loop_frame = true;
        let mut test_frame = frame.inner();
        let mut else_frame = frame.inner();
        let sub = symbols::subtree_for(f);
        let extended = f.recursive
            || symbols::find_undeclared(&f.body, &["loop"]).contains(&"loop")
            || sub.scoped_block;
        if extended {
            loop_frame.symbols.declare_parameter(&Rc::from("loop"));
        }
        loop_frame.symbols.analyze_for(f, ForBranch::Body);
        if !f.else_.is_empty() {
            else_frame.symbols.analyze_for(f, ForBranch::Else);
        }
        if f.test.is_some() {
            test_frame.symbols.analyze_for(f, ForBranch::Test);
            self.visit_expr(&mut f.target, &loop_frame, false)?;
            if let Some(test) = &mut f.test {
                self.visit_expr(test, &test_frame, false)?;
            }
        }
        if sub.stores_loop {
            return Err(Error::assertion(
                "Can't assign to special loop variable in for-loop target",
            ));
        }
        self.visit_expr(&mut f.target, &loop_frame, false)?;
        if !f.recursive {
            self.visit_expr(&mut f.iter, frame, false)?;
        }
        self.blockvisit(&mut f.body, &loop_frame)?;
        if !f.else_.is_empty() {
            self.blockvisit(&mut f.else_, &else_frame)?;
        }
        if f.recursive {
            f.escape = self.escape_mode()?;
            self.visit_expr(&mut f.iter, frame, false)?;
        }
        if let Some(top) = self.assign_stack.last_mut() {
            top.retain(|n| !loop_frame.symbols.stores().contains(n));
        }
        f.extended = extended;
        f.frame = loop_frame.symbols.frame_spec();
        f.else_frame = else_frame.symbols.frame_spec();
        f.test_frame = test_frame.symbols.frame_spec();
        f.reset_after = !(f.recursive && f.else_.is_empty());
        Ok(())
    }

    /// `macro_body`: compiles a macro's or a call block's function.
    fn macro_body(&mut self, m: &mut MacroDef, frame: &Frame) -> Result<()> {
        let mut mframe = frame.inner();
        mframe.symbols.analyze_macro(m);
        let mut explicit_caller = None;
        let mut skip_special: Vec<&str> = Vec::new();
        let mut params: Vec<Rc<str>> = Vec::new();
        for (idx, a) in m.args.iter().enumerate() {
            if &**a == "caller" {
                explicit_caller = Some(idx);
            }
            if matches!(&**a, "kwargs" | "varargs") {
                skip_special.push(if &**a == "kwargs" {
                    "kwargs"
                } else {
                    "varargs"
                });
            }
            mframe.symbols.ref_(a)?;
            params.push(a.clone());
        }
        let undeclared = symbols::find_undeclared(&m.body, &["caller", "kwargs", "varargs"]);
        if undeclared.contains(&"caller") {
            if let Some(idx) = explicit_caller {
                if m.args.len() - idx > m.defaults.len() {
                    return Err(Error::assertion(
                        "When defining macros or call blocks the special \"caller\" argument must be \
                         omitted or be given a default.",
                    ));
                }
            } else {
                mframe.symbols.declare_parameter(&Rc::from("caller"));
                params.push(Rc::from("caller"));
            }
            m.caller = true;
        }
        if undeclared.contains(&"kwargs") && !skip_special.contains(&"kwargs") {
            mframe.symbols.declare_parameter(&Rc::from("kwargs"));
            params.push(Rc::from("kwargs"));
            m.catch_kwargs = true;
        }
        if undeclared.contains(&"varargs") && !skip_special.contains(&"varargs") {
            mframe.symbols.declare_parameter(&Rc::from("varargs"));
            params.push(Rc::from("varargs"));
            m.catch_varargs = true;
        }
        mframe.require_output_check = false;
        mframe.symbols.analyze_macro(m);
        let nargs = m.args.len();
        let ndefaults = m.defaults.len();
        self.param_def_block.push(mframe.symbols.param_targets());
        for idx in 0..nargs {
            if idx + ndefaults >= nargs {
                let d = &mut m.defaults[idx + ndefaults - nargs];
                self.visit_expr(d, &mframe, false)?;
            }
            let ident = (mframe.symbols.level, m.args[idx].clone());
            if let Some(b) = self.param_def_block.last_mut() {
                b.retain(|i| *i != ident);
            }
        }
        self.param_def_block.pop();
        self.blockvisit(&mut m.body, &mframe)?;
        m.frame = mframe.symbols.frame_spec();
        m.params = params;
        Ok(())
    }

    // --- expressions -------------------------------------------------------------------

    /// Visits an expression as the generator would: folding at the first
    /// node its optimizer runs on, then compiling what is left.
    fn visit_expr(&mut self, e: &mut Expr, frame: &Frame, folded: bool) -> Result<()> {
        let mut folded = folded;
        let is_filter = matches!(e, Expr::Filter(_));
        if is_opt(e) && !folded && !self.eval.volatile {
            self.optimize(e)?;
            folded = true;
        }
        match e {
            Expr::Const(v) => {
                // `repr(value)` goes into the generated code.
                pyrepr::repr(v)?;
            }
            Expr::TemplateData(_) => {
                if !self.eval.volatile {
                    self.ae()?;
                }
            }
            Expr::Name(n, ctx) => {
                let n = n.clone();
                let ctx = *ctx;
                let (level, _) = frame.symbols.ref_(&n)?;
                if ctx == Ctx::Load {
                    let ident = (level, n.clone());
                    let raw = matches!(frame.symbols.find_load(&ident), Some(LoadInstr::Param))
                        && !self
                            .param_def_block
                            .last()
                            .is_some_and(|b| b.contains(&ident));
                    *e = Expr::Load(n, level, raw);
                } else {
                    if ctx == Ctx::Store
                        && (frame.toplevel || frame.loop_frame || frame.block_frame)
                    {
                        self.track(&n);
                    }
                    *e = Expr::Store(n, level);
                }
            }
            Expr::Store(n, _) => {
                let n = n.clone();
                if frame.toplevel || frame.loop_frame || frame.block_frame {
                    self.track(&n);
                }
            }
            Expr::NsRef(n, attr) => {
                let (level, _) = frame.symbols.ref_(n)?;
                *e = Expr::StoreNs(n.clone(), attr.clone(), level);
            }
            Expr::Load(..) | Expr::StoreNs(..) => {}
            Expr::Tuple(items, _) | Expr::List(items) => {
                for i in items {
                    self.visit_expr(i, frame, folded)?;
                }
            }
            Expr::Dict(pairs) => {
                for (k, v) in pairs {
                    self.visit_expr(k, frame, folded)?;
                    self.visit_expr(v, frame, folded)?;
                }
            }
            Expr::Bin(_, l, r) => {
                self.visit_expr(l, frame, folded)?;
                self.visit_expr(r, frame, folded)?;
            }
            Expr::Unary(_, n) | Expr::Getattr(n, _) => self.visit_expr(n, frame, folded)?,
            Expr::Concat(items, markup) => {
                *markup = !self.eval.volatile && self.ae()?;
                for i in items {
                    self.visit_expr(i, frame, folded)?;
                }
            }
            Expr::Compare(first, ops) => {
                self.visit_expr(first, frame, folded)?;
                for (_, o) in ops {
                    self.visit_expr(o, frame, folded)?;
                }
            }
            Expr::Cond(c) => {
                let soft = frame.soft();
                self.visit_expr(&mut c.expr1, &soft, folded)?;
                self.visit_expr(&mut c.test, &soft, folded)?;
                if let Some(e2) = &mut c.expr2 {
                    self.visit_expr(e2, &soft, folded)?;
                }
            }
            Expr::Getitem(n, a) => {
                self.visit_expr(n, frame, folded)?;
                if let Expr::Slice(x, y, z) = &mut **a {
                    for part in [x, y, z].into_iter().flatten() {
                        self.visit_expr(part, frame, folded)?;
                    }
                } else {
                    self.visit_expr(a, frame, folded)?;
                }
            }
            Expr::Slice(x, y, z) => {
                self.misplaced_slice = true;
                for part in [x, y, z].into_iter().flatten() {
                    self.visit_expr(part, frame, folded)?;
                }
            }
            Expr::Call(c) => {
                self.visit_expr(&mut c.node, frame, folded)?;
                self.visit_args(&mut c.args, frame, folded)?;
            }
            Expr::Filter(f) | Expr::Test(f) => {
                let known = if is_filter {
                    filters::filter_pass(&f.name).is_some()
                } else {
                    jtests::test_exists(&f.name)
                };
                if !known && !frame.soft_frame {
                    return Err(Error::assertion(format!(
                        "No {} named {}.",
                        if is_filter { "filter" } else { "test" },
                        pyrepr::str_repr(&f.name)
                    )));
                }
                match &mut f.node {
                    Some(n) => self.visit_expr(n, frame, folded)?,
                    None => f.body_escape = self.escape_mode()?,
                }
                self.visit_args(&mut f.args, frame, folded)?;
            }
        }
        Ok(())
    }

    fn track(&mut self, name: &Rc<str>) {
        if let Some(top) = self.assign_stack.last_mut() {
            if !top.contains(name) {
                top.push(name.clone());
            }
        }
    }

    fn visit_args(&mut self, a: &mut Args, frame: &Frame, folded: bool) -> Result<()> {
        for e in a.args.iter_mut() {
            self.visit_expr(e, frame, folded)?;
        }
        for (_, e) in a.kwargs.iter_mut() {
            self.visit_expr(e, frame, folded)?;
        }
        if let Some(e) = &mut a.dyn_args {
            self.visit_expr(e, frame, folded)?;
        }
        if let Some(e) = &mut a.dyn_kwargs {
            self.visit_expr(e, frame, folded)?;
        }
        Ok(())
    }

    // --- constant folding ----------------------------------------------------------

    /// The `Optimizer`: folds every foldable node below, bottom-up.
    fn optimize(&self, e: &mut Expr) -> Result<()> {
        match e {
            Expr::Tuple(items, _) | Expr::List(items) | Expr::Concat(items, _) => {
                for i in items {
                    self.optimize(i)?;
                }
            }
            Expr::Dict(pairs) => {
                for (k, v) in pairs {
                    self.optimize(k)?;
                    self.optimize(v)?;
                }
            }
            Expr::Bin(_, l, r) | Expr::Getitem(l, r) => {
                self.optimize(l)?;
                self.optimize(r)?;
            }
            Expr::Unary(_, n) | Expr::Getattr(n, _) => self.optimize(n)?,
            Expr::Compare(first, ops) => {
                self.optimize(first)?;
                for (_, o) in ops {
                    self.optimize(o)?;
                }
            }
            Expr::Cond(c) => {
                self.optimize(&mut c.test)?;
                self.optimize(&mut c.expr1)?;
                if let Some(e2) = &mut c.expr2 {
                    self.optimize(e2)?;
                }
            }
            Expr::Slice(a, b, c) => {
                for x in [a, b, c].into_iter().flatten() {
                    self.optimize(x)?;
                }
            }
            Expr::Call(c) => {
                self.optimize(&mut c.node)?;
                self.optimize_args(&mut c.args)?;
            }
            Expr::Filter(f) | Expr::Test(f) => {
                if let Some(n) = &mut f.node {
                    self.optimize(n)?;
                }
                self.optimize_args(&mut f.args)?;
            }
            Expr::Name(..)
            | Expr::NsRef(..)
            | Expr::Load(..)
            | Expr::Store(..)
            | Expr::StoreNs(..)
            | Expr::Const(_)
            | Expr::TemplateData(_) => {}
        }
        match self.as_const(e) {
            Ok(v) if has_safe_repr(&v) => *e = Expr::Const(v),
            Ok(_) | Err(Fold::Impossible) => {}
            Err(Fold::Raise(err)) => return Err(err),
        }
        Ok(())
    }

    fn optimize_args(&self, a: &mut Args) -> Result<()> {
        for e in a.args.iter_mut() {
            self.optimize(e)?;
        }
        for (_, e) in a.kwargs.iter_mut() {
            self.optimize(e)?;
        }
        if let Some(e) = &mut a.dyn_args {
            self.optimize(e)?;
        }
        if let Some(e) = &mut a.dyn_kwargs {
            self.optimize(e)?;
        }
        Ok(())
    }

    /// `node.as_const(eval_ctx)`.
    fn as_const(&self, e: &Expr) -> Folded {
        match e {
            Expr::Const(v) => Ok(v.clone()),
            Expr::TemplateData(d) => {
                if self.eval.volatile {
                    return Err(Fold::Impossible);
                }
                if self.ae().map_err(raise)? {
                    Ok(Value::Markup(d.clone()))
                } else {
                    Ok(Value::Str(d.clone()))
                }
            }
            Expr::Name(..)
            | Expr::NsRef(..)
            | Expr::Load(..)
            | Expr::Store(..)
            | Expr::StoreNs(..) => Err(Fold::Impossible),
            Expr::Call(_) => Err(Fold::Impossible),
            Expr::Tuple(items, _) => {
                let mut out = Vec::with_capacity(items.len());
                for i in items {
                    out.push(self.as_const(i)?);
                }
                Ok(Value::tuple(out))
            }
            Expr::List(items) => {
                let mut out = Vec::with_capacity(items.len());
                for i in items {
                    out.push(self.as_const(i)?);
                }
                Ok(Value::list(out))
            }
            Expr::Dict(pairs) => {
                let mut d = crate::value::Dict::default();
                for (k, v) in pairs {
                    let k = self.as_const(k)?;
                    let v = self.as_const(v)?;
                    d.set(k, v).map_err(raise)?;
                }
                Ok(Value::from_dict(d))
            }
            Expr::Bin(BinKind::And, l, r) => {
                let l = self.as_const(l)?;
                if !ops::truthy(&l).map_err(raise)? {
                    return Ok(l);
                }
                self.as_const(r)
            }
            Expr::Bin(BinKind::Or, l, r) => {
                let l = self.as_const(l)?;
                if ops::truthy(&l).map_err(raise)? {
                    return Ok(l);
                }
                self.as_const(r)
            }
            Expr::Bin(k, l, r) => {
                let op = binop_of(*k).ok_or(Fold::Impossible)?;
                let l = self.as_const(l).map_err(|_| Fold::Impossible)?;
                let r = self.as_const(r).map_err(|_| Fold::Impossible)?;
                ops::binop(op, &l, &r).map_err(|_| Fold::Impossible)
            }
            Expr::Unary(k, n) => {
                let v = self.as_const(n).map_err(|_| Fold::Impossible)?;
                match k {
                    UnKind::Not => ops::truthy(&v)
                        .map(|b| Value::Bool(!b))
                        .map_err(|_| Fold::Impossible),
                    UnKind::Neg => ops::unary(true, &v).map_err(|_| Fold::Impossible),
                    UnKind::Pos => ops::unary(false, &v).map_err(|_| Fold::Impossible),
                }
            }
            Expr::Concat(items, _) => {
                let mut s = String::new();
                for i in items {
                    let v = self.as_const(i)?;
                    s.push_str(&pyrepr::str(&v).map_err(raise)?);
                }
                Ok(Value::str(s))
            }
            Expr::Compare(first, ops_) => {
                let mut value = self.as_const(first)?;
                let mut result = Value::Bool(true);
                for (op, o) in ops_ {
                    let new = self.as_const(o).map_err(|_| Fold::Impossible)?;
                    let r = compare(*op, &value, &new).map_err(|_| Fold::Impossible)?;
                    if !r {
                        return Ok(Value::Bool(false));
                    }
                    result = Value::Bool(r);
                    value = new;
                }
                Ok(result)
            }
            Expr::Cond(c) => {
                let t = self.as_const(&c.test)?;
                if ops::truthy(&t).map_err(raise)? {
                    return self.as_const(&c.expr1);
                }
                match &c.expr2 {
                    None => Err(Fold::Impossible),
                    Some(e2) => self.as_const(e2),
                }
            }
            Expr::Getattr(n, attr) => {
                let v = self.as_const(n).map_err(|_| Fold::Impossible)?;
                attrs::getattr(&v, attr).map_err(|_| Fold::Impossible)
            }
            Expr::Getitem(n, a) => {
                let v = self.as_const(n).map_err(|_| Fold::Impossible)?;
                let k = self.as_const(a).map_err(|_| Fold::Impossible)?;
                attrs::getitem(&v, &k).map_err(|_| Fold::Impossible)
            }
            Expr::Slice(a, b, c) => {
                let part = |x: &Option<Box<Expr>>| -> Folded {
                    match x {
                        None => Ok(Value::None),
                        Some(x) => self.as_const(x),
                    }
                };
                let start = part(a)?;
                let stop = part(b)?;
                let step = part(c)?;
                Ok(attrs::slice_object(start, stop, step))
            }
            Expr::Filter(f) | Expr::Test(f) => {
                let is_filter = matches!(e, Expr::Filter(_));
                let Some(node) = &f.node else {
                    return Err(Fold::Impossible);
                };
                if self.eval.volatile {
                    return Err(Fold::Impossible);
                }
                let pass = if is_filter {
                    filters::filter_pass(&f.name)
                } else if jtests::test_exists(&f.name) {
                    Some(if jtests::test_passes_env(&f.name) {
                        Pass::Env
                    } else {
                        Pass::None
                    })
                } else {
                    None
                };
                match pass {
                    None | Some(Pass::Context) => return Err(Fold::Impossible),
                    Some(_) => {}
                }
                let mut args = Vec::new();
                for a in &f.args.args {
                    args.push(self.as_const(a)?);
                }
                let mut kwargs: Vec<(Rc<str>, Value)> = Vec::new();
                for (k, v) in &f.args.kwargs {
                    let v = self.as_const(v)?;
                    match kwargs.iter_mut().find(|(n, _)| n == k) {
                        Some(slot) => slot.1 = v,
                        None => kwargs.push((k.clone(), v)),
                    }
                }
                if let Some(d) = &f.args.dyn_args {
                    let v = self.as_const(d).map_err(|_| Fold::Impossible)?;
                    args.extend(ops::iterate(&v).map_err(|_| Fold::Impossible)?);
                }
                if let Some(d) = &f.args.dyn_kwargs {
                    let v = self.as_const(d).map_err(|_| Fold::Impossible)?;
                    let Value::Dict(d) = v else {
                        return Err(Fold::Impossible);
                    };
                    for (k, v) in d.borrow().entries.iter() {
                        let Some(k) = k.as_str() else {
                            return Err(Fold::Impossible);
                        };
                        let k: Rc<str> = Rc::from(k);
                        match kwargs.iter_mut().find(|(n, _)| *n == k) {
                            Some(slot) => slot.1 = v.clone(),
                            None => kwargs.push((k, v.clone())),
                        }
                    }
                }
                let value = self.as_const(node)?;
                let cx = FilterCx {
                    autoescape: self.eval.autoescape.clone(),
                };
                let r = if is_filter {
                    filters::call_filter(&cx, &f.name, value, args, kwargs)
                } else {
                    jtests::call_test(&cx, &f.name, value, args, kwargs)
                };
                r.map_err(|_| Fold::Impossible)
            }
        }
    }
}

/// `find_all(Block)` in document order: moves every block's body into
/// `out`, refusing a name defined twice.
fn extract_blocks(body: &mut [Stmt], out: &mut Vec<(Rc<str>, Vec<Stmt>)>) -> Result<()> {
    for s in body.iter_mut() {
        match s {
            Stmt::Block(b) => {
                if out.iter().any(|(n, _)| *n == b.name) {
                    return Err(Error::assertion(format!(
                        "block {} defined twice",
                        pyrepr::str_repr(&b.name)
                    )));
                }
                let idx = out.len();
                out.push((b.name.clone(), Vec::new()));
                let mut inner = std::mem::take(&mut b.body);
                extract_blocks(&mut inner, out)?;
                let sub = symbols::subtree_stmts(&inner);
                b.subtree_scoped = sub.scoped_block;
                b.subtree_stores_loop = sub.stores_loop;
                out[idx].1 = inner;
            }
            Stmt::For(f) => {
                let f = Rc::get_mut(f).ok_or_else(internal)?;
                extract_blocks(&mut f.body, out)?;
                extract_blocks(&mut f.else_, out)?;
            }
            Stmt::If(i) => {
                extract_blocks(&mut i.body, out)?;
                for (_, b) in i.elif.iter_mut() {
                    extract_blocks(b, out)?;
                }
                extract_blocks(&mut i.else_, out)?;
            }
            Stmt::Macro(m) => {
                let m = Rc::get_mut(m).ok_or_else(internal)?;
                extract_blocks(&mut m.body, out)?;
            }
            Stmt::CallBlock(c) => {
                let m = Rc::get_mut(&mut c.caller).ok_or_else(internal)?;
                extract_blocks(&mut m.body, out)?;
            }
            Stmt::FilterBlock(f) => extract_blocks(&mut f.body, out)?,
            Stmt::With(w) => extract_blocks(&mut w.body, out)?,
            Stmt::AssignBlock(a) => extract_blocks(&mut a.body, out)?,
            Stmt::Scope(sc) => extract_blocks(&mut sc.body, out)?,
            Stmt::EvalContextModifier(m) => extract_blocks(&mut m.body, out)?,
            Stmt::Output(_) | Stmt::Extends(_) | Stmt::Load(_) | Stmt::Assign(_) => {}
        }
    }
    Ok(())
}
