//! Jinja2's parser (`jinja2/parser.py`), with its error messages.

use std::rc::Rc;

use crate::ast::*;
use crate::error::{Error, Result};
use crate::lexer::{Tok, Token, TokenStream, describe, describe_expr};
use crate::pyrepr::str_repr;
use crate::value::Value;

/// How deeply expressions may nest before the parser gives up, standing in
/// for Python's recursion limit.
const MAX_NESTING: usize = 200;

const STATEMENT_KEYWORDS: &[&str] = &[
    "for",
    "if",
    "block",
    "extends",
    "print",
    "macro",
    "include",
    "from",
    "import",
    "set",
    "with",
    "autoescape",
];

/// End tokens: `name:<value>` or a token type.
type EndTokens = &'static [&'static str];

/// The parser.
pub struct Parser {
    stream: TokenStream,
    tag_stack: Vec<Rc<str>>,
    end_token_stack: Vec<EndTokens>,
    depth: usize,
}

fn syntax(msg: impl Into<String>) -> Error {
    Error::syntax(msg)
}

/// `token.test(expr)` for `name:<value>` or a type name.
fn test(tok: &Tok, expr: &str) -> bool {
    match expr.split_once(':') {
        Some(("name", value)) => tok.is_name(value),
        Some((ty, _)) => tok.type_name() == ty,
        None => tok.type_name() == expr,
    }
}

fn test_any(tok: &Tok, exprs: &[&str]) -> bool {
    exprs.iter().any(|e| test(tok, e))
}

/// `can_assign` and the name Python gives the node in "can't assign to".
fn can_assign(e: &Expr) -> std::result::Result<(), &'static str> {
    match e {
        Expr::Name(n, _) => {
            if matches!(&**n, "true" | "false" | "none" | "True" | "False" | "None") {
                Err("name")
            } else {
                Ok(())
            }
        }
        Expr::NsRef(..) => Ok(()),
        Expr::Tuple(items, _) => {
            if items.iter().all(|i| can_assign(i).is_ok()) {
                Ok(())
            } else {
                Err("tuple")
            }
        }
        Expr::Const(_) => Err("const"),
        Expr::Load(..) | Expr::Store(..) | Expr::StoreNs(..) => Ok(()),
        Expr::TemplateData(_) => Err("templatedata"),
        Expr::List(_) => Err("list"),
        Expr::Dict(_) => Err("dict"),
        Expr::Getattr(..) => Err("getattr"),
        Expr::Getitem(..) => Err("getitem"),
        Expr::Slice(..) => Err("slice"),
        Expr::Call(_) => Err("call"),
        Expr::Filter(_) => Err("filter"),
        Expr::Test(_) => Err("test"),
        Expr::Cond(_) => Err("condexpr"),
        Expr::Compare(..) => Err("compare"),
        Expr::Concat(..) => Err("concat"),
        Expr::Unary(UnKind::Not, _) => Err("not"),
        Expr::Unary(UnKind::Neg, _) => Err("neg"),
        Expr::Unary(UnKind::Pos, _) => Err("pos"),
        Expr::Bin(k, ..) => Err(match k {
            BinKind::Add => "add",
            BinKind::Sub => "sub",
            BinKind::Mul => "mul",
            BinKind::Div => "div",
            BinKind::FloorDiv => "floordiv",
            BinKind::Mod => "mod",
            BinKind::Pow => "pow",
            BinKind::And => "and",
            BinKind::Or => "or",
        }),
    }
}

/// `set_ctx`: every name and tuple below takes the role.
fn set_ctx(e: &mut Expr, ctx: Ctx) {
    match e {
        Expr::Name(_, c) => *c = ctx,
        Expr::Tuple(items, c) => {
            *c = ctx;
            for i in items {
                set_ctx(i, ctx);
            }
        }
        _ => {}
    }
}

impl Parser {
    /// A parser over `source`.
    pub fn new(source: &str) -> Result<Self> {
        Ok(Self {
            stream: TokenStream::new(source)?,
            tag_stack: Vec::new(),
            end_token_stack: Vec::new(),
            depth: 0,
        })
    }

    fn cur(&self) -> &Tok {
        &self.stream.current.tok
    }

    fn lineno(&self) -> usize {
        self.stream.current.lineno
    }

    fn next(&mut self) -> Result<Token> {
        self.stream.next()
    }

    fn fail_ut_eof(&self, name: Option<&str>, stack: &[EndTokens]) -> Error {
        let mut expected: Vec<String> = Vec::new();
        for exprs in stack {
            for e in exprs.iter() {
                expected.push(describe_expr(e));
            }
        }
        let currently_looking = stack.last().map(|exprs| {
            exprs
                .iter()
                .map(|e| str_repr(&describe_expr(e)))
                .collect::<Vec<_>>()
                .join(" or ")
        });
        let mut message = vec![match name {
            None => "Unexpected end of template.".to_string(),
            Some(n) => format!("Encountered unknown tag {}.", str_repr(n)),
        }];
        if let Some(looking) = currently_looking.filter(|l| !l.is_empty()) {
            if name.is_some_and(|n| expected.iter().any(|e| e == n)) {
                message.push(format!(
                    "You probably made a nesting mistake. Jinja is expecting this tag, but \
                     currently looking for {looking}."
                ));
            } else {
                message.push(format!(
                    "Jinja was looking for the following tags: {looking}."
                ));
            }
        }
        if let Some(tag) = self.tag_stack.last() {
            message.push(format!(
                "The innermost block that needs to be closed is {}.",
                str_repr(tag)
            ));
        }
        syntax(message.join(" "))
    }

    fn fail_eof(&self, end_tokens: Option<EndTokens>) -> Error {
        let mut stack = self.end_token_stack.clone();
        if let Some(e) = end_tokens {
            stack.push(e);
        }
        self.fail_ut_eof(None, &stack)
    }

    fn is_tuple_end(&self, extra: Option<EndTokens>) -> bool {
        if matches!(self.cur(), Tok::VariableEnd | Tok::BlockEnd | Tok::RParen) {
            return true;
        }
        extra.is_some_and(|e| test_any(self.cur(), e))
    }

    /// Parses the whole template.
    pub fn parse(mut self) -> Result<Vec<Stmt>> {
        self.subparse(None)
    }

    fn parse_statement(&mut self) -> Result<Vec<Stmt>> {
        let token = self.stream.current.clone();
        let Tok::Name(name) = &token.tok else {
            return Err(syntax("tag name expected"));
        };
        let name = name.clone();
        self.tag_stack.push(name.clone());
        let result = if STATEMENT_KEYWORDS.contains(&&*name) {
            match &*name {
                "for" => self.parse_for().map(|s| vec![s]),
                "if" => self.parse_if().map(|s| vec![s]),
                "block" => self.parse_block().map(|s| vec![s]),
                "extends" => self.parse_extends().map(|s| vec![s]),
                "print" => self.parse_print().map(|s| vec![s]),
                "macro" => self.parse_macro().map(|s| vec![s]),
                "include" => self.parse_include().map(|s| vec![s]),
                "from" => self.parse_from().map(|s| vec![s]),
                "import" => self.parse_import().map(|s| vec![s]),
                "set" => self.parse_set().map(|s| vec![s]),
                "with" => self.parse_with().map(|s| vec![s]),
                _ => self.parse_autoescape().map(|s| vec![s]),
            }
        } else if &*name == "call" {
            self.parse_call_block().map(|s| vec![s])
        } else if &*name == "filter" {
            self.parse_filter_block().map(|s| vec![s])
        } else {
            self.tag_stack.pop();
            return Err(self.fail_ut_eof(Some(&name), &self.end_token_stack));
        };
        self.tag_stack.pop();
        result
    }

    fn parse_statements(&mut self, end_tokens: EndTokens, drop_needle: bool) -> Result<Vec<Stmt>> {
        self.stream.skip_if_type("colon")?;
        self.stream.expect_type("block_end")?;
        let result = self.subparse(Some(end_tokens))?;
        if *self.cur() == Tok::Eof {
            return Err(self.fail_eof(Some(end_tokens)));
        }
        if drop_needle {
            self.next()?;
        }
        Ok(result)
    }

    fn parse_set(&mut self) -> Result<Stmt> {
        let lineno = self.next()?.lineno;
        let _ = lineno;
        let target = self.parse_assign_target(true, false, None, true)?;
        if self.stream.skip_if_type("assign")? {
            let value = self.parse_tuple(false, true, None, false, false)?;
            return Ok(Stmt::Assign(Box::new(Assign {
                target,
                value,
                export: Vec::new(),
            })));
        }
        let filter = self.parse_filter(None, false)?;
        let body = self.parse_statements(&["name:endset"], true)?;
        Ok(Stmt::AssignBlock(Box::new(AssignBlock {
            target,
            filter,
            body,
            frame: FrameSpec::default(),
            export: Vec::new(),
        })))
    }

    fn parse_for(&mut self) -> Result<Stmt> {
        self.stream.expect_name("for")?;
        let target = self.parse_assign_target(true, false, Some(&["name:in"]), false)?;
        self.stream.expect_name("in")?;
        let iter = self.parse_tuple(false, false, Some(&["name:recursive"]), false, false)?;
        let mut test = None;
        if self.stream.skip_if_name("if")? {
            test = Some(self.parse_expression(true)?);
        }
        let recursive = self.stream.skip_if_name("recursive")?;
        let body = self.parse_statements(&["name:endfor", "name:else"], false)?;
        let else_ = if self.next()?.tok.is_name("endfor") {
            Vec::new()
        } else {
            self.parse_statements(&["name:endfor"], true)?
        };
        Ok(Stmt::For(Rc::new(For {
            target,
            iter,
            body,
            else_,
            test,
            recursive,
            extended: false,
            frame: FrameSpec::default(),
            else_frame: FrameSpec::default(),
            test_frame: FrameSpec::default(),
            escape: Escape::Off,
            reset_after: true,
        })))
    }

    fn parse_if(&mut self) -> Result<Stmt> {
        self.stream.expect_name("if")?;
        let mut branches: Vec<(Expr, Vec<Stmt>)> = Vec::new();
        let mut else_ = Vec::new();
        loop {
            let test = self.parse_tuple(false, false, None, false, false)?;
            let body = self.parse_statements(&["name:elif", "name:else", "name:endif"], false)?;
            branches.push((test, body));
            let token = self.next()?;
            if token.tok.is_name("elif") {
                continue;
            } else if token.tok.is_name("else") {
                else_ = self.parse_statements(&["name:endif"], true)?;
            }
            break;
        }
        let mut branches = branches.into_iter();
        let (test, body) = branches
            .next()
            .ok_or_else(|| syntax("internal parsing error"))?;
        Ok(Stmt::If(Box::new(If {
            test,
            body,
            elif: branches.collect(),
            else_,
        })))
    }

    fn parse_with(&mut self) -> Result<Stmt> {
        self.next()?;
        let mut targets = Vec::new();
        let mut values = Vec::new();
        while *self.cur() != Tok::BlockEnd {
            if !targets.is_empty() {
                self.stream.expect_type("comma")?;
            }
            let mut target = self.parse_assign_target(true, false, None, false)?;
            set_ctx(&mut target, Ctx::Param);
            targets.push(target);
            self.stream.expect_type("assign")?;
            values.push(self.parse_expression(true)?);
        }
        let body = self.parse_statements(&["name:endwith"], true)?;
        Ok(Stmt::With(Box::new(With {
            targets,
            values,
            body,
            frame: FrameSpec::default(),
        })))
    }

    fn parse_autoescape(&mut self) -> Result<Stmt> {
        self.next()?;
        let autoescape = self.parse_expression(true)?;
        let body = self.parse_statements(&["name:endautoescape"], true)?;
        Ok(Stmt::Scope(Box::new(Scope {
            body: vec![Stmt::EvalContextModifier(Box::new(EvalContextModifier {
                autoescape,
                body,
            }))],
            frame: FrameSpec::default(),
        })))
    }

    fn parse_block(&mut self) -> Result<Stmt> {
        self.next()?;
        let name = match self.stream.expect_type("name")?.tok {
            Tok::Name(n) => n,
            _ => return Err(syntax("internal parsing error")),
        };
        let scoped = self.stream.skip_if_name("scoped")?;
        let required = self.stream.skip_if_name("required")?;
        if *self.cur() == Tok::Sub {
            return Err(syntax(
                "Block names in Jinja have to be valid Python identifiers and may not contain \
                 hyphens, use an underscore instead.",
            ));
        }
        let body = self.parse_statements(&["name:endblock"], true)?;
        if required {
            for stmt in &body {
                let ok = match stmt {
                    Stmt::Output(o) => o.items.iter().all(|i| match i {
                        OutItem::Expr(Expr::TemplateData(d)) => {
                            !d.is_empty() && d.chars().all(crate::unicode::is_space)
                        }
                        _ => false,
                    }),
                    _ => false,
                };
                if !ok {
                    return Err(syntax(
                        "Required blocks can only contain comments or whitespace",
                    ));
                }
            }
        }
        self.stream.skip_if_name(&name)?;
        Ok(Stmt::Block(Box::new(BlockStmt {
            name,
            body,
            scoped,
            required,
            locals: Vec::new(),
            subtree_scoped: false,
            subtree_stores_loop: false,
        })))
    }

    fn parse_extends(&mut self) -> Result<Stmt> {
        self.next()?;
        Ok(Stmt::Extends(self.parse_expression(true)?))
    }

    fn parse_import_context(&mut self) -> Result<()> {
        if test_any(self.cur(), &["name:with", "name:without"])
            && self.stream.look()?.tok.is_name("context")
        {
            self.next()?;
            self.stream.skip(1)?;
        }
        Ok(())
    }

    fn parse_include(&mut self) -> Result<Stmt> {
        self.next()?;
        let template = self.parse_expression(true)?;
        let mut ignore_missing = false;
        if self.cur().is_name("ignore") && self.stream.look()?.tok.is_name("missing") {
            ignore_missing = true;
            self.stream.skip(2)?;
        }
        self.parse_import_context()?;
        let kind = match &template {
            Expr::Const(Value::Str(_)) => LoadKind::IncludeOne,
            Expr::Const(Value::Tuple(_) | Value::List(_)) | Expr::Tuple(..) | Expr::List(_) => {
                LoadKind::IncludeSelect
            }
            _ => LoadKind::IncludeEither,
        };
        Ok(Stmt::Load(Box::new(LoadTemplate {
            kind,
            template,
            targets: Vec::new(),
            ignore_missing,
        })))
    }

    fn parse_import(&mut self) -> Result<Stmt> {
        self.next()?;
        let template = self.parse_expression(true)?;
        self.stream.expect_name("as")?;
        let Expr::Name(target, _) = self.parse_assign_target(true, true, None, false)? else {
            return Err(syntax("internal parsing error"));
        };
        self.parse_import_context()?;
        Ok(Stmt::Load(Box::new(LoadTemplate {
            kind: LoadKind::Import,
            template,
            targets: vec![target],
            ignore_missing: false,
        })))
    }

    fn parse_from(&mut self) -> Result<Stmt> {
        self.next()?;
        let template = self.parse_expression(true)?;
        self.stream.expect_name("import")?;
        let mut names: Vec<Rc<str>> = Vec::new();
        loop {
            if !names.is_empty() {
                self.stream.expect_type("comma")?;
            }
            if matches!(self.cur(), Tok::Name(_)) {
                if self.parse_from_context()? {
                    break;
                }
                let Expr::Name(target, _) = self.parse_assign_target(true, true, None, false)?
                else {
                    return Err(syntax("internal parsing error"));
                };
                if target.starts_with('_') {
                    return Err(Error::assertion(
                        "names starting with an underline can not be imported",
                    ));
                }
                if self.stream.skip_if_name("as")? {
                    let Expr::Name(alias, _) = self.parse_assign_target(true, true, None, false)?
                    else {
                        return Err(syntax("internal parsing error"));
                    };
                    names.push(alias);
                } else {
                    names.push(target);
                }
                if self.parse_from_context()? || *self.cur() != Tok::Comma {
                    break;
                }
            } else {
                self.stream.expect_type("name")?;
            }
        }
        Ok(Stmt::Load(Box::new(LoadTemplate {
            kind: LoadKind::Import,
            template,
            targets: names,
            ignore_missing: false,
        })))
    }

    fn parse_from_context(&mut self) -> Result<bool> {
        if matches!(self.cur().name(), Some("with" | "without"))
            && self.stream.look()?.tok.is_name("context")
        {
            self.next()?;
            self.stream.skip(1)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn parse_signature(&mut self) -> Result<(Vec<Rc<str>>, Vec<Expr>)> {
        let mut args = Vec::new();
        let mut defaults = Vec::new();
        self.stream.expect_type("lparen")?;
        while *self.cur() != Tok::RParen {
            if !args.is_empty() {
                self.stream.expect_type("comma")?;
            }
            let arg = self.parse_assign_target(true, true, None, false)?;
            let Expr::Name(name, _) = arg else {
                return Err(syntax("internal parsing error"));
            };
            if self.stream.skip_if_type("assign")? {
                defaults.push(self.parse_expression(true)?);
            } else if !defaults.is_empty() {
                return Err(syntax("non-default argument follows default argument"));
            }
            args.push(name);
        }
        self.stream.expect_type("rparen")?;
        Ok((args, defaults))
    }

    fn macro_def(
        name: Option<Rc<str>>,
        args: Vec<Rc<str>>,
        defaults: Vec<Expr>,
        body: Vec<Stmt>,
    ) -> MacroDef {
        MacroDef {
            name,
            args,
            defaults,
            body,
            frame: FrameSpec::default(),
            caller: false,
            catch_kwargs: false,
            catch_varargs: false,
            toplevel: false,
            params: Vec::new(),
            store_level: 0,
        }
    }

    fn parse_call_block(&mut self) -> Result<Stmt> {
        self.next()?;
        let (args, defaults) = if *self.cur() == Tok::LParen {
            self.parse_signature()?
        } else {
            (Vec::new(), Vec::new())
        };
        let call = self.parse_expression(true)?;
        if !matches!(call, Expr::Call(_)) {
            return Err(syntax("expected call"));
        }
        let body = self.parse_statements(&["name:endcall"], true)?;
        Ok(Stmt::CallBlock(Box::new(CallBlock {
            call,
            caller: Rc::new(Self::macro_def(None, args, defaults, body)),
        })))
    }

    fn parse_filter_block(&mut self) -> Result<Stmt> {
        self.next()?;
        let filter = self
            .parse_filter(None, true)?
            .ok_or_else(|| syntax("internal parsing error"))?;
        let body = self.parse_statements(&["name:endfilter"], true)?;
        Ok(Stmt::FilterBlock(Box::new(FilterBlock {
            body,
            filter,
            frame: FrameSpec::default(),
        })))
    }

    fn parse_macro(&mut self) -> Result<Stmt> {
        self.next()?;
        let Expr::Name(name, _) = self.parse_assign_target(true, true, None, false)? else {
            return Err(syntax("internal parsing error"));
        };
        let (args, defaults) = self.parse_signature()?;
        let body = self.parse_statements(&["name:endmacro"], true)?;
        Ok(Stmt::Macro(Rc::new(Self::macro_def(
            Some(name),
            args,
            defaults,
            body,
        ))))
    }

    fn parse_print(&mut self) -> Result<Stmt> {
        self.next()?;
        let mut items = Vec::new();
        while *self.cur() != Tok::BlockEnd {
            if !items.is_empty() {
                self.stream.expect_type("comma")?;
            }
            items.push(OutItem::Expr(self.parse_expression(true)?));
        }
        Ok(Stmt::Output(Output {
            items,
            escape: Escape::Off,
        }))
    }

    fn parse_assign_target(
        &mut self,
        with_tuple: bool,
        name_only: bool,
        extra_end_rules: Option<EndTokens>,
        with_namespace: bool,
    ) -> Result<Expr> {
        let mut target = if name_only {
            let token = self.stream.expect_type("name")?;
            let Tok::Name(n) = token.tok else {
                return Err(syntax("internal parsing error"));
            };
            Expr::Name(n, Ctx::Store)
        } else {
            let mut t = if with_tuple {
                self.parse_tuple(true, true, extra_end_rules, false, with_namespace)?
            } else {
                self.parse_primary(with_namespace)?
            };
            set_ctx(&mut t, Ctx::Store);
            t
        };
        if let Err(kind) = can_assign(&target) {
            return Err(syntax(format!("can't assign to {}", str_repr(kind))));
        }
        if name_only {
            set_ctx(&mut target, Ctx::Store);
        }
        Ok(target)
    }

    fn parse_expression(&mut self, with_condexpr: bool) -> Result<Expr> {
        self.depth += 1;
        if self.depth > MAX_NESTING {
            return Err(Error::new(
                "RecursionError",
                "maximum recursion depth exceeded while parsing the template",
            ));
        }
        let r = if with_condexpr {
            self.parse_condexpr()
        } else {
            self.parse_or()
        };
        self.depth -= 1;
        r
    }

    fn parse_condexpr(&mut self) -> Result<Expr> {
        let mut lineno = self.lineno();
        let mut expr1 = self.parse_or()?;
        while self.stream.skip_if_name("if")? {
            let expr2 = self.parse_or()?;
            let expr3 = if self.stream.skip_if_name("else")? {
                Some(self.parse_condexpr()?)
            } else {
                None
            };
            expr1 = Expr::Cond(Box::new(CondExpr {
                test: expr2,
                expr1,
                expr2: expr3,
                lineno,
            }));
            lineno = self.lineno();
        }
        Ok(expr1)
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut left = self.parse_and()?;
        while self.stream.skip_if_name("or")? {
            let right = self.parse_and()?;
            left = Expr::Bin(BinKind::Or, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut left = self.parse_not()?;
        while self.stream.skip_if_name("and")? {
            let right = self.parse_not()?;
            left = Expr::Bin(BinKind::And, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr> {
        if self.cur().is_name("not") {
            self.next()?;
            self.depth += 1;
            if self.depth > MAX_NESTING {
                return Err(Error::new(
                    "RecursionError",
                    "maximum recursion depth exceeded while parsing the template",
                ));
            }
            let inner = self.parse_not();
            self.depth -= 1;
            return Ok(Expr::Unary(UnKind::Not, Box::new(inner?)));
        }
        self.parse_compare()
    }

    fn parse_compare(&mut self) -> Result<Expr> {
        let expr = self.parse_math1()?;
        let mut ops = Vec::new();
        loop {
            let kind = match self.cur() {
                Tok::Eq => Some(CmpKind::Eq),
                Tok::Ne => Some(CmpKind::Ne),
                Tok::Lt => Some(CmpKind::Lt),
                Tok::LtEq => Some(CmpKind::LtEq),
                Tok::Gt => Some(CmpKind::Gt),
                Tok::GtEq => Some(CmpKind::GtEq),
                _ => None,
            };
            if let Some(kind) = kind {
                self.next()?;
                ops.push((kind, self.parse_math1()?));
            } else if self.stream.skip_if_name("in")? {
                ops.push((CmpKind::In, self.parse_math1()?));
            } else if self.cur().is_name("not") && self.stream.look()?.tok.is_name("in") {
                self.stream.skip(2)?;
                ops.push((CmpKind::NotIn, self.parse_math1()?));
            } else {
                break;
            }
        }
        if ops.is_empty() {
            return Ok(expr);
        }
        Ok(Expr::Compare(Box::new(expr), ops))
    }

    fn parse_math1(&mut self) -> Result<Expr> {
        let mut left = self.parse_concat()?;
        loop {
            let kind = match self.cur() {
                Tok::Add => BinKind::Add,
                Tok::Sub => BinKind::Sub,
                _ => break,
            };
            self.next()?;
            let right = self.parse_concat()?;
            left = Expr::Bin(kind, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_concat(&mut self) -> Result<Expr> {
        let mut args = vec![self.parse_math2()?];
        while *self.cur() == Tok::Tilde {
            self.next()?;
            args.push(self.parse_math2()?);
        }
        if args.len() == 1 {
            return Ok(args.pop().unwrap_or(Expr::Const(Value::None)));
        }
        Ok(Expr::Concat(args, false))
    }

    fn parse_math2(&mut self) -> Result<Expr> {
        let mut left = self.parse_pow()?;
        loop {
            let kind = match self.cur() {
                Tok::Mul => BinKind::Mul,
                Tok::Div => BinKind::Div,
                Tok::FloorDiv => BinKind::FloorDiv,
                Tok::Mod => BinKind::Mod,
                _ => break,
            };
            self.next()?;
            let right = self.parse_pow()?;
            left = Expr::Bin(kind, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_pow(&mut self) -> Result<Expr> {
        let mut left = self.parse_unary(true)?;
        while *self.cur() == Tok::Pow {
            self.next()?;
            let right = self.parse_unary(true)?;
            left = Expr::Bin(BinKind::Pow, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self, with_filter: bool) -> Result<Expr> {
        let node = match self.cur() {
            Tok::Sub | Tok::Add => {
                let neg = *self.cur() == Tok::Sub;
                self.next()?;
                self.depth += 1;
                if self.depth > MAX_NESTING {
                    return Err(Error::new(
                        "RecursionError",
                        "maximum recursion depth exceeded while parsing the template",
                    ));
                }
                let inner = self.parse_unary(false);
                self.depth -= 1;
                Expr::Unary(
                    if neg { UnKind::Neg } else { UnKind::Pos },
                    Box::new(inner?),
                )
            }
            _ => self.parse_primary(false)?,
        };
        let node = self.parse_postfix(node)?;
        if with_filter {
            return self.parse_filter_expr(node);
        }
        Ok(node)
    }

    fn parse_primary(&mut self, with_namespace: bool) -> Result<Expr> {
        let token = self.stream.current.clone();
        match &token.tok {
            Tok::Name(n) => {
                self.next()?;
                Ok(match &**n {
                    "true" | "True" => Expr::Const(Value::Bool(true)),
                    "false" | "False" => Expr::Const(Value::Bool(false)),
                    "none" | "None" => Expr::Const(Value::None),
                    _ if with_namespace && *self.cur() == Tok::Dot => {
                        self.next()?;
                        let attr = self.stream.expect_type("name")?;
                        let Tok::Name(attr) = attr.tok else {
                            return Err(syntax("internal parsing error"));
                        };
                        Expr::NsRef(n.clone(), attr)
                    }
                    _ => Expr::Name(n.clone(), Ctx::Load),
                })
            }
            Tok::Str(s) => {
                self.next()?;
                let mut buf = s.to_string();
                while let Tok::Str(more) = self.cur() {
                    buf.push_str(more);
                    self.next()?;
                }
                Ok(Expr::Const(Value::str(buf)))
            }
            Tok::Integer(i) => {
                self.next()?;
                Ok(Expr::Const(Value::Int(i.clone())))
            }
            Tok::Float(f) => {
                self.next()?;
                Ok(Expr::Const(Value::Float(*f)))
            }
            Tok::LParen => {
                self.next()?;
                let node = self.parse_tuple(false, true, None, true, false)?;
                self.stream.expect_type("rparen")?;
                Ok(node)
            }
            Tok::LBracket => self.parse_list(),
            Tok::LBrace => self.parse_dict(),
            other => Err(syntax(format!("unexpected {}", str_repr(&describe(other))))),
        }
    }

    fn parse_tuple(
        &mut self,
        simplified: bool,
        with_condexpr: bool,
        extra_end_rules: Option<EndTokens>,
        explicit_parentheses: bool,
        with_namespace: bool,
    ) -> Result<Expr> {
        let mut args = Vec::new();
        let mut is_tuple = false;
        loop {
            if !args.is_empty() {
                self.stream.expect_type("comma")?;
            }
            if self.is_tuple_end(extra_end_rules) {
                break;
            }
            args.push(if simplified {
                self.parse_primary(with_namespace)?
            } else {
                self.parse_expression(with_condexpr)?
            });
            if *self.cur() == Tok::Comma {
                is_tuple = true;
            } else {
                break;
            }
        }
        if !is_tuple {
            if let Some(a) = args.pop() {
                return Ok(a);
            }
            if !explicit_parentheses {
                return Err(syntax(format!(
                    "Expected an expression, got {}",
                    str_repr(&describe(self.cur()))
                )));
            }
        }
        Ok(Expr::Tuple(args, Ctx::Load))
    }

    fn parse_list(&mut self) -> Result<Expr> {
        self.stream.expect_type("lbracket")?;
        let mut items = Vec::new();
        while *self.cur() != Tok::RBracket {
            if !items.is_empty() {
                self.stream.expect_type("comma")?;
            }
            if *self.cur() == Tok::RBracket {
                break;
            }
            items.push(self.parse_expression(true)?);
        }
        self.stream.expect_type("rbracket")?;
        Ok(Expr::List(items))
    }

    fn parse_dict(&mut self) -> Result<Expr> {
        self.stream.expect_type("lbrace")?;
        let mut items = Vec::new();
        while *self.cur() != Tok::RBrace {
            if !items.is_empty() {
                self.stream.expect_type("comma")?;
            }
            if *self.cur() == Tok::RBrace {
                break;
            }
            let key = self.parse_expression(true)?;
            self.stream.expect_type("colon")?;
            let value = self.parse_expression(true)?;
            items.push((key, value));
        }
        self.stream.expect_type("rbrace")?;
        Ok(Expr::Dict(items))
    }

    fn parse_postfix(&mut self, mut node: Expr) -> Result<Expr> {
        loop {
            match self.cur() {
                Tok::Dot | Tok::LBracket => node = self.parse_subscript(node)?,
                Tok::LParen => node = self.parse_call(node)?,
                _ => break,
            }
        }
        Ok(node)
    }

    fn parse_filter_expr(&mut self, mut node: Expr) -> Result<Expr> {
        loop {
            match self.cur() {
                Tok::Pipe => {
                    node = self
                        .parse_filter(Some(node), false)?
                        .ok_or_else(|| syntax("internal parsing error"))?;
                }
                Tok::Name(n) if &**n == "is" => node = self.parse_test(node)?,
                Tok::LParen => node = self.parse_call(node)?,
                _ => break,
            }
        }
        Ok(node)
    }

    fn parse_subscript(&mut self, node: Expr) -> Result<Expr> {
        let token = self.next()?;
        if token.tok == Tok::Dot {
            let attr_token = self.stream.current.clone();
            self.next()?;
            return match attr_token.tok {
                Tok::Name(n) => Ok(Expr::Getattr(Box::new(node), n)),
                Tok::Integer(i) => Ok(Expr::Getitem(
                    Box::new(node),
                    Box::new(Expr::Const(Value::Int(i))),
                )),
                _ => Err(syntax("expected name or number")),
            };
        }
        if token.tok == Tok::LBracket {
            let mut args = Vec::new();
            while *self.cur() != Tok::RBracket {
                if !args.is_empty() {
                    self.stream.expect_type("comma")?;
                }
                args.push(self.parse_subscribed()?);
            }
            self.stream.expect_type("rbracket")?;
            let arg = if args.len() == 1 {
                args.pop().unwrap_or(Expr::Const(Value::None))
            } else {
                Expr::Tuple(args, Ctx::Load)
            };
            return Ok(Expr::Getitem(Box::new(node), Box::new(arg)));
        }
        Err(syntax("expected subscript expression"))
    }

    fn parse_subscribed(&mut self) -> Result<Expr> {
        let mut args: Vec<Option<Box<Expr>>> = Vec::new();
        if *self.cur() == Tok::Colon {
            self.next()?;
            args.push(None);
        } else {
            let node = self.parse_expression(true)?;
            if *self.cur() != Tok::Colon {
                return Ok(node);
            }
            self.next()?;
            args.push(Some(Box::new(node)));
        }
        if *self.cur() == Tok::Colon {
            args.push(None);
        } else if !matches!(self.cur(), Tok::RBracket | Tok::Comma) {
            args.push(Some(Box::new(self.parse_expression(true)?)));
        } else {
            args.push(None);
        }
        if *self.cur() == Tok::Colon {
            self.next()?;
            if !matches!(self.cur(), Tok::RBracket | Tok::Comma) {
                args.push(Some(Box::new(self.parse_expression(true)?)));
            } else {
                args.push(None);
            }
        } else {
            args.push(None);
        }
        let mut it = args.into_iter();
        let start = it.next().flatten();
        let stop = it.next().flatten();
        let step = it.next().flatten();
        Ok(Expr::Slice(start, stop, step))
    }

    fn parse_call_args(&mut self) -> Result<Args> {
        self.stream.expect_type("lparen")?;
        let mut a = Args::default();
        let mut require_comma = false;
        let invalid = || syntax("invalid syntax for function call expression");
        while *self.cur() != Tok::RParen {
            if require_comma {
                self.stream.expect_type("comma")?;
                if *self.cur() == Tok::RParen {
                    break;
                }
            }
            if *self.cur() == Tok::Mul {
                if a.dyn_args.is_some() || a.dyn_kwargs.is_some() {
                    return Err(invalid());
                }
                self.next()?;
                a.dyn_args = Some(self.parse_expression(true)?);
            } else if *self.cur() == Tok::Pow {
                if a.dyn_kwargs.is_some() {
                    return Err(invalid());
                }
                self.next()?;
                a.dyn_kwargs = Some(self.parse_expression(true)?);
            } else if matches!(self.cur(), Tok::Name(_)) && self.stream.look()?.tok == Tok::Assign {
                if a.dyn_kwargs.is_some() {
                    return Err(invalid());
                }
                let key = match &self.stream.current.tok {
                    Tok::Name(n) => n.clone(),
                    _ => return Err(invalid()),
                };
                self.stream.skip(2)?;
                let value = self.parse_expression(true)?;
                a.kwargs.push((key, value));
            } else {
                if a.dyn_args.is_some() || a.dyn_kwargs.is_some() || !a.kwargs.is_empty() {
                    return Err(invalid());
                }
                a.args.push(self.parse_expression(true)?);
            }
            require_comma = true;
        }
        self.stream.expect_type("rparen")?;
        Ok(a)
    }

    fn parse_call(&mut self, node: Expr) -> Result<Expr> {
        let args = self.parse_call_args()?;
        Ok(Expr::Call(Box::new(Call { node, args })))
    }

    fn dotted_name(&mut self) -> Result<Rc<str>> {
        let token = self.stream.expect_type("name")?;
        let Tok::Name(n) = token.tok else {
            return Err(syntax("internal parsing error"));
        };
        let mut name = n.to_string();
        while *self.cur() == Tok::Dot {
            self.next()?;
            let part = self.stream.expect_type("name")?;
            if let Tok::Name(p) = part.tok {
                name.push('.');
                name.push_str(&p);
            }
        }
        Ok(Rc::from(name))
    }

    fn parse_filter(
        &mut self,
        mut node: Option<Expr>,
        mut start_inline: bool,
    ) -> Result<Option<Expr>> {
        while *self.cur() == Tok::Pipe || start_inline {
            if !start_inline {
                self.next()?;
            }
            let name = self.dotted_name()?;
            let args = if *self.cur() == Tok::LParen {
                self.parse_call_args()?
            } else {
                Args::default()
            };
            node = Some(Expr::Filter(Box::new(FilterCall {
                node,
                name,
                args,
                body_escape: Escape::Off,
            })));
            start_inline = false;
        }
        Ok(node)
    }

    fn parse_test(&mut self, node: Expr) -> Result<Expr> {
        self.next()?;
        let negated = self.stream.skip_if_name("not")?;
        let name = self.dotted_name()?;
        let args = if *self.cur() == Tok::LParen {
            self.parse_call_args()?
        } else if matches!(
            self.cur(),
            Tok::Name(_)
                | Tok::Str(_)
                | Tok::Integer(_)
                | Tok::Float(_)
                | Tok::LParen
                | Tok::LBracket
                | Tok::LBrace
        ) && !test_any(self.cur(), &["name:else", "name:or", "name:and"])
        {
            if self.cur().is_name("is") {
                return Err(syntax("You cannot chain multiple tests with is"));
            }
            let arg = self.parse_primary(false)?;
            let arg = self.parse_postfix(arg)?;
            Args {
                args: vec![arg],
                ..Args::default()
            }
        } else {
            Args::default()
        };
        let test = Expr::Test(Box::new(FilterCall {
            node: Some(node),
            name,
            args,
            body_escape: Escape::Off,
        }));
        Ok(if negated {
            Expr::Unary(UnKind::Not, Box::new(test))
        } else {
            test
        })
    }

    fn subparse(&mut self, end_tokens: Option<EndTokens>) -> Result<Vec<Stmt>> {
        let mut body: Vec<Stmt> = Vec::new();
        let mut data: Vec<OutItem> = Vec::new();
        if let Some(e) = end_tokens {
            self.end_token_stack.push(e);
        }
        let result = self.subparse_inner(end_tokens, &mut body, &mut data);
        if end_tokens.is_some() {
            self.end_token_stack.pop();
        }
        result?;
        Ok(body)
    }

    fn subparse_inner(
        &mut self,
        end_tokens: Option<EndTokens>,
        body: &mut Vec<Stmt>,
        data: &mut Vec<OutItem>,
    ) -> Result<()> {
        let flush = |body: &mut Vec<Stmt>, data: &mut Vec<OutItem>| {
            if !data.is_empty() {
                body.push(Stmt::Output(Output {
                    items: std::mem::take(data),
                    escape: Escape::Off,
                }));
            }
        };
        while self.stream.has_more() {
            match self.cur().clone() {
                Tok::Data(d) => {
                    if !d.is_empty() {
                        data.push(OutItem::Expr(Expr::TemplateData(d)));
                    }
                    self.next()?;
                }
                Tok::VariableBegin => {
                    self.next()?;
                    data.push(OutItem::Expr(
                        self.parse_tuple(false, true, None, false, false)?,
                    ));
                    self.stream.expect_type("variable_end")?;
                }
                Tok::BlockBegin => {
                    flush(body, data);
                    self.next()?;
                    if let Some(e) = end_tokens {
                        if test_any(self.cur(), e) {
                            return Ok(());
                        }
                    }
                    let stmts = self.parse_statement()?;
                    body.extend(stmts);
                    self.stream.expect_type("block_end")?;
                }
                _ => return Err(Error::new("AssertionError", "internal parsing error")),
            }
        }
        flush(body, data);
        Ok(())
    }
}
