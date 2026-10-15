//! The template tree (`jinja2/nodes.py`), plus what compilation adds to it:
//! frames, folded constants and the evaluation context each node was
//! compiled under.

use std::rc::Rc;

use crate::value::Value;

/// A name's role (`Name.ctx`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ctx {
    /// Read.
    Load,
    /// Assigned.
    Store,
    /// A parameter.
    Param,
}

/// A binary operator node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinKind {
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `//`
    FloorDiv,
    /// `%`
    Mod,
    /// `**`
    Pow,
    /// `and`
    And,
    /// `or`
    Or,
}

/// A unary operator node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnKind {
    /// `not`
    Not,
    /// `-`
    Neg,
    /// `+`
    Pos,
}

/// A comparison operand (`Operand.op`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpKind {
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `>`
    Gt,
    /// `>=`
    GtEq,
    /// `<`
    Lt,
    /// `<=`
    LtEq,
    /// `in`
    In,
    /// `not in`
    NotIn,
}

/// How the compiled code decides on HTML escaping: fixed at compile time, or
/// read from the runtime evaluation context when `{% autoescape %}` was given
/// a value that is not a constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Escape {
    /// `str(...)`.
    #[default]
    Off,
    /// `escape(...)`.
    On,
    /// Decided at runtime.
    Volatile,
}

/// An expression.
#[derive(Debug, Clone)]
pub enum Expr {
    /// A literal or folded constant. Mutable values are copied on use; one
    /// holding a float Python cannot write back as a literal (`inf`, `nan`)
    /// raises `NameError` when evaluated.
    Const(Value),
    /// Template text (only inside an output).
    TemplateData(Rc<str>),
    /// A variable, as parsed.
    Name(Rc<str>, Ctx),
    /// `ns.attr` as an assignment target, as parsed.
    NsRef(Rc<str>, Rc<str>),
    /// A variable read, resolved to the frame level that holds it; `true`
    /// when the generated code reads it as is (a parameter), so `missing`
    /// shows through instead of becoming an `Undefined`.
    Load(Rc<str>, usize, bool),
    /// A variable assigned (or bound as a parameter), resolved.
    Store(Rc<str>, usize),
    /// `ns.attr` assigned, the namespace resolved.
    StoreNs(Rc<str>, Rc<str>, usize),
    /// `(a, b)`
    Tuple(Vec<Expr>, Ctx),
    /// `[a, b]`
    List(Vec<Expr>),
    /// `{k: v}`
    Dict(Vec<(Expr, Expr)>),
    /// A binary operator.
    Bin(BinKind, Box<Expr>, Box<Expr>),
    /// A unary operator.
    Unary(UnKind, Box<Expr>),
    /// `a ~ b ~ c`; `true` joins with `markup_join`.
    Concat(Vec<Expr>, bool),
    /// `a < b <= c`
    Compare(Box<Expr>, Vec<(CmpKind, Expr)>),
    /// `a if test else b`
    Cond(Box<CondExpr>),
    /// `node.attr`
    Getattr(Box<Expr>, Rc<str>),
    /// `node[arg]`
    Getitem(Box<Expr>, Box<Expr>),
    /// `start:stop:step` inside a subscript.
    Slice(Option<Box<Expr>>, Option<Box<Expr>>, Option<Box<Expr>>),
    /// A call.
    Call(Box<Call>),
    /// `node|name(...)`
    Filter(Box<FilterCall>),
    /// `node is name(...)`
    Test(Box<FilterCall>),
}

/// `CondExpr`.
#[derive(Debug, Clone)]
pub struct CondExpr {
    /// The condition.
    pub test: Expr,
    /// The value when true.
    pub expr1: Expr,
    /// The value when false.
    pub expr2: Option<Expr>,
    /// Where it starts.
    pub lineno: usize,
}

/// Call arguments.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// Positional.
    pub args: Vec<Expr>,
    /// `key=value`.
    pub kwargs: Vec<(Rc<str>, Expr)>,
    /// `*args`.
    pub dyn_args: Option<Expr>,
    /// `**kwargs`.
    pub dyn_kwargs: Option<Expr>,
}

/// `Call`.
#[derive(Debug, Clone)]
pub struct Call {
    /// What is called.
    pub node: Expr,
    /// The arguments.
    pub args: Args,
}

/// `Filter` / `Test`.
#[derive(Debug, Clone)]
pub struct FilterCall {
    /// The filtered value; `None` for a filter block's body.
    pub node: Option<Expr>,
    /// The filter or test name.
    pub name: Rc<str>,
    /// The arguments.
    pub args: Args,
    /// How a missing `node` (a block's buffer) is wrapped.
    pub body_escape: Escape,
}

/// An assignment target with its unpacking structure.
pub type Target = Expr;

/// How a frame's names start (`idtracking` load instructions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Load {
    /// Set by the construct (loop target, macro argument, …).
    Param,
    /// Looked up in the context.
    Resolve(Rc<str>),
    /// Copied from the same name at an enclosing frame level.
    Alias(usize),
    /// Not set yet.
    Undefined,
}

/// The names a frame defines and how each starts.
#[derive(Debug, Clone, Default)]
pub struct FrameSpec {
    /// The frame's level: its names are `(level, name)`.
    pub level: usize,
    /// In definition order.
    pub loads: Vec<(Rc<str>, Load)>,
}

/// A statement.
#[derive(Debug, Clone)]
pub enum Stmt {
    /// Text and `{{ ... }}`.
    Output(Output),
    /// `{% for %}`
    For(Rc<For>),
    /// `{% if %}`
    If(Box<If>),
    /// `{% macro %}`
    Macro(Rc<MacroDef>),
    /// `{% call %}`
    CallBlock(Box<CallBlock>),
    /// `{% filter %}`
    FilterBlock(Box<FilterBlock>),
    /// `{% with %}`
    With(Box<With>),
    /// `{% block %}`
    Block(Box<BlockStmt>),
    /// `{% extends %}`
    Extends(Expr),
    /// `{% include %}`, `{% import %}`, `{% from ... import %}`: anything
    /// that loads another template.
    Load(Box<LoadTemplate>),
    /// `{% set x = ... %}`
    Assign(Box<Assign>),
    /// `{% set x %}...{% endset %}`
    AssignBlock(Box<AssignBlock>),
    /// A new frame (`{% autoescape %}` is one wrapped around its modifier).
    Scope(Box<Scope>),
    /// `{% autoescape %}`'s body.
    EvalContextModifier(Box<EvalContextModifier>),
}

/// `Output`.
#[derive(Debug, Clone, Default)]
pub struct Output {
    /// Constant runs and expressions, one output chunk each.
    pub items: Vec<OutItem>,
    /// How expressions are turned into text.
    pub escape: Escape,
}

/// One chunk of an output.
#[derive(Debug, Clone)]
pub enum OutItem {
    /// Text known at compile time.
    Text(String),
    /// An expression (for the parser: also template data).
    Expr(Expr),
}

/// `For`.
#[derive(Debug, Clone)]
pub struct For {
    /// The loop variable(s).
    pub target: Target,
    /// The iterable.
    pub iter: Expr,
    /// The body.
    pub body: Vec<Stmt>,
    /// `{% else %}`.
    pub else_: Vec<Stmt>,
    /// `if ...` after the iterable.
    pub test: Option<Expr>,
    /// `recursive`.
    pub recursive: bool,
    /// Whether `loop` is available.
    pub extended: bool,
    /// The loop body's frame.
    pub frame: FrameSpec,
    /// The `else` body's frame.
    pub else_frame: FrameSpec,
    /// The test's frame.
    pub test_frame: FrameSpec,
    /// How a recursive loop's output is returned.
    pub escape: Escape,
    /// Whether leaving the loop resets its names (not for a recursive loop
    /// without `else`, whose names live in its own function).
    pub reset_after: bool,
}

/// `If`.
#[derive(Debug, Clone)]
pub struct If {
    /// The condition.
    pub test: Expr,
    /// The body.
    pub body: Vec<Stmt>,
    /// `{% elif %}` branches.
    pub elif: Vec<(Expr, Vec<Stmt>)>,
    /// `{% else %}`.
    pub else_: Vec<Stmt>,
}

/// `Macro` or a `CallBlock`'s caller.
#[derive(Debug, Clone)]
pub struct MacroDef {
    /// `None` for a call block's caller.
    pub name: Option<Rc<str>>,
    /// Parameter names.
    pub args: Vec<Rc<str>>,
    /// Defaults of the last parameters.
    pub defaults: Vec<Expr>,
    /// The body.
    pub body: Vec<Stmt>,
    /// The body's frame.
    pub frame: FrameSpec,
    /// Reads `caller`.
    pub caller: bool,
    /// Reads `kwargs`.
    pub catch_kwargs: bool,
    /// Reads `varargs`.
    pub catch_varargs: bool,
    /// Defined at the top level (also stored in the context).
    pub toplevel: bool,
    /// The generated function's parameters: the arguments, then `caller`,
    /// `kwargs` and `varargs` as the body reads them.
    pub params: Vec<Rc<str>>,
    /// The frame level the macro's name is stored at.
    pub store_level: usize,
}

/// `CallBlock`.
#[derive(Debug, Clone)]
pub struct CallBlock {
    /// The call (an [`Expr::Call`]), made with `caller=`.
    pub call: Expr,
    /// The caller macro.
    pub caller: Rc<MacroDef>,
}

/// `FilterBlock`.
#[derive(Debug, Clone)]
pub struct FilterBlock {
    /// The body.
    pub body: Vec<Stmt>,
    /// The filter chain, applied to the body.
    pub filter: Expr,
    /// The body's frame.
    pub frame: FrameSpec,
}

/// `With`.
#[derive(Debug, Clone)]
pub struct With {
    /// Targets.
    pub targets: Vec<Target>,
    /// Values, evaluated in the enclosing frame.
    pub values: Vec<Expr>,
    /// The body.
    pub body: Vec<Stmt>,
    /// The body's frame.
    pub frame: FrameSpec,
}

/// `Block`.
#[derive(Debug, Clone)]
pub struct BlockStmt {
    /// The name.
    pub name: Rc<str>,
    /// The body (moved into the template's block functions when compiled).
    pub body: Vec<Stmt>,
    /// `scoped`.
    pub scoped: bool,
    /// `required`.
    pub required: bool,
    /// For a scoped block: the names the enclosing frames assigned, passed
    /// to the block's context.
    pub locals: Vec<(Rc<str>, usize)>,
    /// A scoped block is this one or nested in it.
    pub subtree_scoped: bool,
    /// The body (nested blocks included) assigns a variable named `loop`.
    pub subtree_stores_loop: bool,
}

/// A block's function.
#[derive(Debug)]
pub struct BlockDef {
    /// The name.
    pub name: Rc<str>,
    /// The body.
    pub body: Vec<Stmt>,
    /// Its frame.
    pub frame: FrameSpec,
    /// Binds `self`.
    pub self_param: bool,
    /// Binds `super`.
    pub super_param: bool,
}

/// Which loading statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadKind {
    /// `{% include %}` with a constant name.
    IncludeOne,
    /// `{% include %}` with a constant list of names.
    IncludeSelect,
    /// `{% include %}` with a name or list decided at runtime.
    IncludeEither,
    /// `{% import %}` / `{% from %}`.
    Import,
}

/// `Include`, `Import`, `FromImport`.
#[derive(Debug, Clone)]
pub struct LoadTemplate {
    /// Which statement.
    pub kind: LoadKind,
    /// The template name expression.
    pub template: Expr,
    /// The names an import assigns.
    pub targets: Vec<Rc<str>>,
    /// `ignore missing`.
    pub ignore_missing: bool,
}

/// `Assign`.
#[derive(Debug, Clone)]
pub struct Assign {
    /// The target.
    pub target: Target,
    /// The value.
    pub value: Expr,
    /// Names copied into the context afterwards (top-level assignments).
    pub export: Vec<(Rc<str>, usize)>,
}

/// `AssignBlock`.
#[derive(Debug, Clone)]
pub struct AssignBlock {
    /// The target.
    pub target: Target,
    /// An optional filter chain.
    pub filter: Option<Expr>,
    /// The body.
    pub body: Vec<Stmt>,
    /// The body's frame.
    pub frame: FrameSpec,
    /// Names copied into the context afterwards.
    pub export: Vec<(Rc<str>, usize)>,
}

/// `Scope`.
#[derive(Debug, Clone)]
pub struct Scope {
    /// The body.
    pub body: Vec<Stmt>,
    /// Its frame.
    pub frame: FrameSpec,
}

/// `ScopedEvalContextModifier`.
#[derive(Debug, Clone)]
pub struct EvalContextModifier {
    /// The new `autoescape`.
    pub autoescape: Expr,
    /// The body.
    pub body: Vec<Stmt>,
}
