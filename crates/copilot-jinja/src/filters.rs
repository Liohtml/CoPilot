//! Jinja2 3.1's built-in filters (`jinja2/filters.py`).

use std::rc::Rc;

use num_bigint_dig::BigInt;
use num_traits::{ToPrimitive, Zero};

use crate::attrs;
use crate::builtins;
use crate::callargs::{self, Sig};
use crate::error::{Error, Result};
use crate::json;
use crate::markup;
use crate::methods;
use crate::objects::{self, Generator, GroupTuple, RevIter};
use crate::ops::{self, BinOp, CmpOp};
use crate::pprint;
use crate::pyrepr;
use crate::unicode;
use crate::value::{PyIter, Value};

/// What a filter receives besides its arguments: the evaluation context's
/// `autoescape` (the runtime one, or the compile-time one when folding).
#[derive(Clone)]
pub struct FilterCx {
    /// `eval_ctx.autoescape`.
    pub autoescape: Value,
}

impl FilterCx {
    /// `bool(eval_ctx.autoescape)`.
    pub fn autoescape(&self) -> Result<bool> {
        ops::truthy(&self.autoescape)
    }
}

/// Which argument Jinja passes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pass {
    /// Nothing.
    None,
    /// `environment`.
    Env,
    /// `eval_ctx`.
    EvalCtx,
    /// `context` (never folded at compile time).
    Context,
}

/// The filters' names.
pub const FILTER_NAMES: &[&str] = &[
    "abs",
    "attr",
    "batch",
    "capitalize",
    "center",
    "count",
    "d",
    "default",
    "dictsort",
    "e",
    "escape",
    "filesizeformat",
    "first",
    "float",
    "forceescape",
    "format",
    "groupby",
    "indent",
    "int",
    "join",
    "last",
    "length",
    "list",
    "lower",
    "items",
    "map",
    "min",
    "max",
    "pprint",
    "random",
    "reject",
    "rejectattr",
    "replace",
    "reverse",
    "round",
    "safe",
    "select",
    "selectattr",
    "slice",
    "sort",
    "string",
    "striptags",
    "sum",
    "title",
    "trim",
    "truncate",
    "unique",
    "upper",
    "urlencode",
    "urlize",
    "wordcount",
    "wordwrap",
    "xmlattr",
    "tojson",
];

/// How a filter is passed its first argument.
pub fn filter_pass(name: &str) -> Option<Pass> {
    Some(match name {
        "attr" | "first" | "groupby" | "last" | "min" | "max" | "sort" | "sum" | "truncate"
        | "unique" | "wordwrap" => Pass::Env,
        "join" | "list" | "replace" | "urlize" | "xmlattr" | "tojson" => Pass::EvalCtx,
        "map" | "random" | "reject" | "rejectattr" | "select" | "selectattr" => Pass::Context,
        n if FILTER_NAMES.contains(&n) => Pass::None,
        _ => return None,
    })
}

type Kwargs = Vec<(Rc<str>, Value)>;

/// A boxed attribute getter.
type Getter = Box<dyn Fn(&Value) -> Result<Value>>;

/// Binds `value` and `args` to a filter's Python signature, its pass
/// argument (if any) counted as the first parameter.
fn bind(
    name: &str,
    pass: bool,
    params: &[&str],
    defaults: Vec<Value>,
    value: Value,
    args: Vec<Value>,
    kwargs: Kwargs,
) -> Result<Vec<Value>> {
    let mut all = Vec::with_capacity(args.len() + 2);
    if pass {
        all.push(Value::None);
    }
    all.push(value);
    all.extend(args);
    let sig = Sig {
        name,
        params,
        defaults,
        ..Sig::default()
    };
    let mut bound = callargs::bind_sig(&sig, all, kwargs)?.args;
    if pass {
        bound.remove(0);
    }
    Ok(bound)
}

fn posonly_one(name: &str, value: Value, args: Vec<Value>, kwargs: Kwargs) -> Result<Value> {
    let sig = Sig {
        name,
        params: &["s"],
        posonly: 1,
        ..Sig::default()
    };
    let mut all = vec![value];
    all.extend(args);
    Ok(callargs::bind_sig(&sig, all, kwargs)?.args.remove(0))
}

fn c_one(name: &str, value: Value, mut args: Vec<Value>, kwargs: Kwargs) -> Result<Value> {
    args.insert(0, value);
    callargs::exactly_one(name, args, &kwargs)
}

/// `ignore_case`.
fn ignore_case(v: Value) -> Value {
    match v.as_str() {
        Some(s) if !v.is_markup() => Value::str(unicode::lower(s)),
        Some(s) => Value::markup(unicode::lower(s)),
        None => v,
    }
}

/// `_prepare_attribute_parts`.
fn attribute_parts(attr: &Value) -> Result<Vec<Value>> {
    match attr {
        Value::None => Ok(Vec::new()),
        v if v.is_str() => {
            let s = v.as_str().unwrap_or_default();
            let mut out = Vec::new();
            for part in s.split('.') {
                if !part.is_empty() && part.chars().all(unicode::is_digit) {
                    out.push(Value::Int(builtins::parse_int(part, 10)?));
                } else {
                    out.push(Value::str(part));
                }
            }
            Ok(out)
        }
        other => Ok(vec![other.clone()]),
    }
}

/// `make_attrgetter`.
fn attrgetter(
    attribute: &Value,
    lower: bool,
    default: Option<Value>,
) -> Result<impl Fn(&Value) -> Result<Value> + use<>> {
    let parts = attribute_parts(attribute)?;
    let default = default.filter(|d| !matches!(d, Value::None));
    Ok(move |item: &Value| -> Result<Value> {
        let mut item = item.clone();
        for part in &parts {
            item = attrs::getitem(&item, part)?;
            if let Some(d) = &default {
                if item.is_undefined() {
                    item = d.clone();
                }
            }
        }
        Ok(if lower { ignore_case(item) } else { item })
    })
}

/// `make_multi_attrgetter`: a list key per item.
fn multi_attrgetter(
    attribute: &Value,
    lower: bool,
) -> Result<impl Fn(&Value) -> Result<Value> + use<>> {
    let split: Vec<Value> = match attribute.as_str() {
        Some(s) => s.split(',').map(Value::str).collect(),
        None => vec![attribute.clone()],
    };
    let parts: Vec<Vec<Value>> = split.iter().map(attribute_parts).collect::<Result<_>>()?;
    Ok(move |item: &Value| -> Result<Value> {
        let mut items = Vec::with_capacity(parts.len());
        for p in &parts {
            let mut it = item.clone();
            for part in p {
                it = attrs::getitem(&it, part)?;
            }
            items.push(if lower { ignore_case(it) } else { it });
        }
        Ok(Value::list(items))
    })
}

fn sorted_by(
    items: Vec<Value>,
    key: &dyn Fn(&Value) -> Result<Value>,
    reverse: bool,
) -> Result<Vec<Value>> {
    let keys = items.iter().map(key).collect::<Result<Vec<_>>>()?;
    ops::sort_by_keys(items, keys, reverse)
}

fn reverse_flag(v: &Value) -> Result<bool> {
    Ok(!methods::index_value(v)?.is_zero())
}

/// `str(value)` that keeps `Markup` (`soft_str`).
fn soft(v: &Value) -> Result<Value> {
    markup::soft_str(v)
}

fn str_method(recv: &Value, name: &str, args: Vec<Value>) -> Result<Value> {
    methods::call_method(recv, name, args, Vec::new())
}

/// Calls the filter `name` on `value`.
pub fn call_filter(
    cx: &FilterCx,
    name: &str,
    value: Value,
    args: Vec<Value>,
    kwargs: Kwargs,
) -> Result<Value> {
    let none = || Value::None;
    match name {
        "abs" => builtins::py_abs(&c_one("abs", value, args, kwargs)?),
        "count" | "length" => {
            let v = c_one("len", value, args, kwargs)?;
            Ok(Value::int(ops::len(&v)? as i64))
        }
        "e" | "escape" => markup::escape(&posonly_one("escape", value, args, kwargs)?),
        "string" => soft(&posonly_one("soft_str", value, args, kwargs)?),
        "attr" => {
            let b = bind(
                "do_attr",
                true,
                &["environment", "obj", "name"],
                vec![],
                value,
                args,
                kwargs,
            )?;
            do_attr(&b[0], &b[1])
        }
        "batch" => {
            let b = bind(
                "do_batch",
                false,
                &["value", "linecount", "fill_with"],
                vec![none()],
                value,
                args,
                kwargs,
            )?;
            Ok(do_batch(b[0].clone(), b[1].clone(), b[2].clone()))
        }
        "capitalize" => {
            let b = bind("do_capitalize", false, &["s"], vec![], value, args, kwargs)?;
            str_method(&soft(&b[0])?, "capitalize", vec![])
        }
        "center" => {
            let b = bind(
                "do_center",
                false,
                &["value", "width"],
                vec![Value::int(80)],
                value,
                args,
                kwargs,
            )?;
            str_method(&soft(&b[0])?, "center", vec![b[1].clone()])
        }
        "d" | "default" => {
            let b = bind(
                "do_default",
                false,
                &["value", "default_value", "boolean"],
                vec![Value::str(""), Value::Bool(false)],
                value,
                args,
                kwargs,
            )?;
            if b[0].is_undefined() || (ops::truthy(&b[2])? && !ops::truthy(&b[0])?) {
                Ok(b[1].clone())
            } else {
                Ok(b[0].clone())
            }
        }
        "dictsort" => {
            let b = bind(
                "do_dictsort",
                false,
                &["value", "case_sensitive", "by", "reverse"],
                vec![Value::Bool(false), Value::str("key"), Value::Bool(false)],
                value,
                args,
                kwargs,
            )?;
            do_dictsort(&b[0], &b[1], &b[2], &b[3])
        }
        "filesizeformat" => {
            let b = bind(
                "do_filesizeformat",
                false,
                &["value", "binary"],
                vec![Value::Bool(false)],
                value,
                args,
                kwargs,
            )?;
            do_filesizeformat(&b[0], &b[1])
        }
        "first" => {
            let b = bind(
                "sync_do_first",
                true,
                &["environment", "seq"],
                vec![],
                value,
                args,
                kwargs,
            )?;
            let mut it = ops::py_iter(&b[0])?;
            Ok(it
                .next()?
                .unwrap_or_else(|| Value::undefined_hint("No first item, sequence was empty.")))
        }
        "last" => {
            let b = bind(
                "do_last",
                true,
                &["environment", "seq"],
                vec![],
                value,
                args,
                kwargs,
            )?;
            let rev = py_reversed(&b[0])?;
            let mut it = ops::py_iter(&rev)?;
            Ok(it
                .next()?
                .unwrap_or_else(|| Value::undefined_hint("No last item, sequence was empty.")))
        }
        "float" => {
            let b = bind(
                "do_float",
                false,
                &["value", "default"],
                vec![Value::Float(0.0)],
                value,
                args,
                kwargs,
            )?;
            match builtins::py_float(&b[0]) {
                Ok(f) => Ok(Value::Float(f)),
                Err(e) if matches!(e.kind, "TypeError" | "ValueError") => Ok(b[1].clone()),
                Err(e) => Err(e),
            }
        }
        "int" => {
            let b = bind(
                "do_int",
                false,
                &["value", "default", "base"],
                vec![Value::int(0), Value::int(10)],
                value,
                args,
                kwargs,
            )?;
            do_int(&b[0], &b[1], &b[2])
        }
        "forceescape" => {
            let b = bind(
                "do_forceescape",
                false,
                &["value"],
                vec![],
                value,
                args,
                kwargs,
            )?;
            Ok(Value::markup(markup::escape_str(&pyrepr::str(&b[0])?)))
        }
        "format" => {
            let sig = Sig {
                name: "do_format",
                params: &["value"],
                varargs: true,
                varkw: true,
                ..Sig::default()
            };
            let mut all = vec![value];
            all.extend(args);
            let b = callargs::bind_sig(&sig, all, kwargs)?;
            if !b.varargs.is_empty() && !b.varkw.is_empty() {
                return Err(Error::filter_argument(
                    "can't handle positional and keyword arguments at the same time",
                ));
            }
            let s = soft(&b.args[0])?;
            let operand = if b.varkw.is_empty() {
                Value::tuple(b.varargs)
            } else {
                Value::str_dict(
                    b.varkw
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v))
                        .collect(),
                )
            };
            ops::binop(BinOp::Mod, &s, &operand)
        }
        "groupby" => {
            let b = bind(
                "sync_do_groupby",
                true,
                &[
                    "environment",
                    "value",
                    "attribute",
                    "default",
                    "case_sensitive",
                ],
                vec![none(), Value::Bool(false)],
                value,
                args,
                kwargs,
            )?;
            do_groupby(&b[0], &b[1], &b[2], &b[3])
        }
        "indent" => {
            let b = bind(
                "do_indent",
                false,
                &["s", "width", "first", "blank"],
                vec![Value::int(4), Value::Bool(false), Value::Bool(false)],
                value,
                args,
                kwargs,
            )?;
            do_indent(&b[0], &b[1], &b[2], &b[3])
        }
        "join" => {
            let b = bind(
                "sync_do_join",
                true,
                &["eval_ctx", "value", "d", "attribute"],
                vec![Value::str(""), none()],
                value,
                args,
                kwargs,
            )?;
            do_join(cx, &b[0], &b[1], &b[2])
        }
        "list" => {
            let b = bind(
                "sync_do_list",
                false,
                &["value"],
                vec![],
                value,
                args,
                kwargs,
            )?;
            Ok(Value::list(ops::iterate(&b[0])?))
        }
        "lower" | "upper" => {
            let b = bind(
                if name == "lower" {
                    "do_lower"
                } else {
                    "do_upper"
                },
                false,
                &["s"],
                vec![],
                value,
                args,
                kwargs,
            )?;
            str_method(&soft(&b[0])?, name, vec![])
        }
        "items" => {
            let b = bind("do_items", false, &["value"], vec![], value, args, kwargs)?;
            Ok(do_items(b[0].clone()))
        }
        "map" => {
            let sig = Sig {
                name: "sync_do_map",
                params: &["context", "value"],
                varargs: true,
                varkw: true,
                ..Sig::default()
            };
            let b = callargs::bind_sig(
                &sig,
                vec![Value::None, value].into_iter().chain(args).collect(),
                kwargs,
            )?;
            Ok(do_map(cx.clone(), b.args[1].clone(), b.varargs, b.varkw))
        }
        "min" | "max" => {
            let b = bind(
                if name == "min" { "do_min" } else { "do_max" },
                true,
                &["environment", "value", "case_sensitive", "attribute"],
                vec![Value::Bool(false), none()],
                value,
                args,
                kwargs,
            )?;
            min_or_max(&b[0], name == "max", &b[1], &b[2])
        }
        "pprint" => {
            let b = bind("do_pprint", false, &["value"], vec![], value, args, kwargs)?;
            Ok(Value::str(pprint::pformat(&b[0])?))
        }
        "random" => {
            let b = bind(
                "do_random",
                true,
                &["context", "seq"],
                vec![],
                value,
                args,
                kwargs,
            )?;
            let n = ops::len(&b[0])?;
            if n == 0 {
                return Ok(Value::undefined_hint("No random item, sequence was empty."));
            }
            attrs::subscript(&b[0], &Value::int(builtins::random_below(n as u64) as i64))
        }
        "reject" | "select" | "rejectattr" | "selectattr" => {
            let fname = match name {
                "reject" => "sync_do_reject",
                "select" => "sync_do_select",
                "rejectattr" => "sync_do_rejectattr",
                _ => "sync_do_selectattr",
            };
            let sig = Sig {
                name: fname,
                params: &["context", "value"],
                varargs: true,
                varkw: true,
                ..Sig::default()
            };
            let b = callargs::bind_sig(
                &sig,
                vec![Value::None, value].into_iter().chain(args).collect(),
                kwargs,
            )?;
            Ok(select_or_reject(
                cx.clone(),
                b.args[1].clone(),
                b.varargs,
                b.varkw,
                name.starts_with("reject"),
                name.ends_with("attr"),
            ))
        }
        "replace" => {
            let b = bind(
                "do_replace",
                true,
                &["eval_ctx", "s", "old", "new", "count"],
                vec![none()],
                value,
                args,
                kwargs,
            )?;
            do_replace(cx, &b[0], &b[1], &b[2], &b[3])
        }
        "reverse" => {
            let b = bind("do_reverse", false, &["value"], vec![], value, args, kwargs)?;
            do_reverse(&b[0])
        }
        "round" => {
            let b = bind(
                "do_round",
                false,
                &["value", "precision", "method"],
                vec![Value::int(0), Value::str("common")],
                value,
                args,
                kwargs,
            )?;
            do_round(&b[0], &b[1], &b[2])
        }
        "safe" => {
            let b = bind(
                "do_mark_safe",
                false,
                &["value"],
                vec![],
                value,
                args,
                kwargs,
            )?;
            markup::mark_safe(&b[0])
        }
        "slice" => {
            let b = bind(
                "sync_do_slice",
                false,
                &["value", "slices", "fill_with"],
                vec![none()],
                value,
                args,
                kwargs,
            )?;
            Ok(do_slice(b[0].clone(), b[1].clone(), b[2].clone()))
        }
        "sort" => {
            let b = bind(
                "do_sort",
                true,
                &[
                    "environment",
                    "value",
                    "reverse",
                    "case_sensitive",
                    "attribute",
                ],
                vec![Value::Bool(false), Value::Bool(false), none()],
                value,
                args,
                kwargs,
            )?;
            let key = multi_attrgetter(&b[3], !ops::truthy(&b[2])?)?;
            let items = ops::iterate(&b[0])?;
            Ok(Value::list(sorted_by(items, &key, reverse_flag(&b[1])?)?))
        }
        "striptags" => {
            let b = bind(
                "do_striptags",
                false,
                &["value"],
                vec![],
                value,
                args,
                kwargs,
            )?;
            Ok(Value::str(markup::striptags(&pyrepr::str(&b[0])?)))
        }
        "sum" => {
            let b = bind(
                "sync_do_sum",
                true,
                &["environment", "iterable", "attribute", "start"],
                vec![none(), Value::int(0)],
                value,
                args,
                kwargs,
            )?;
            let getter = if matches!(b[1], Value::None) {
                None
            } else {
                Some(attrgetter(&b[1], false, None)?)
            };
            let mut it = ops::py_iter(&b[0])?;
            builtins::py_sum_with(&mut it, b[2].clone(), |v| match &getter {
                Some(g) => g(&v),
                None => Ok(v),
            })
        }
        "title" => {
            let b = bind("do_title", false, &["s"], vec![], value, args, kwargs)?;
            Ok(Value::str(do_title(&pyrepr::str(&soft(&b[0])?)?)))
        }
        "trim" => {
            let b = bind(
                "do_trim",
                false,
                &["value", "chars"],
                vec![none()],
                value,
                args,
                kwargs,
            )?;
            str_method(&soft(&b[0])?, "strip", vec![b[1].clone()])
        }
        "truncate" => {
            let b = bind(
                "do_truncate",
                true,
                &["env", "s", "length", "killwords", "end", "leeway"],
                vec![
                    Value::int(255),
                    Value::Bool(false),
                    Value::str("..."),
                    none(),
                ],
                value,
                args,
                kwargs,
            )?;
            do_truncate(&b[0], &b[1], &b[2], &b[3], &b[4])
        }
        "unique" => {
            let b = bind(
                "sync_do_unique",
                true,
                &["environment", "value", "case_sensitive", "attribute"],
                vec![Value::Bool(false), none()],
                value,
                args,
                kwargs,
            )?;
            do_unique(b[0].clone(), &b[1], &b[2])
        }
        "urlencode" => {
            let b = bind(
                "do_urlencode",
                false,
                &["value"],
                vec![],
                value,
                args,
                kwargs,
            )?;
            do_urlencode(&b[0])
        }
        "urlize" => {
            let b = bind(
                "do_urlize",
                true,
                &[
                    "eval_ctx",
                    "value",
                    "trim_url_limit",
                    "nofollow",
                    "target",
                    "rel",
                    "extra_schemes",
                ],
                vec![none(), Value::Bool(false), none(), none(), none()],
                value,
                args,
                kwargs,
            )?;
            do_urlize(cx, &b)
        }
        "wordcount" => {
            let b = bind("do_wordcount", false, &["s"], vec![], value, args, kwargs)?;
            let s = pyrepr::str(&soft(&b[0])?)?;
            let mut count = 0;
            let mut in_word = false;
            for c in s.chars() {
                let w = unicode::is_word(c);
                if w && !in_word {
                    count += 1;
                }
                in_word = w;
            }
            Ok(Value::int(count))
        }
        "wordwrap" => {
            let b = bind(
                "do_wordwrap",
                true,
                &[
                    "environment",
                    "s",
                    "width",
                    "break_long_words",
                    "wrapstring",
                    "break_on_hyphens",
                ],
                vec![Value::int(79), Value::Bool(true), none(), Value::Bool(true)],
                value,
                args,
                kwargs,
            )?;
            do_wordwrap(&b)
        }
        "xmlattr" => {
            let b = bind(
                "do_xmlattr",
                true,
                &["eval_ctx", "d", "autospace"],
                vec![Value::Bool(true)],
                value,
                args,
                kwargs,
            )?;
            do_xmlattr(cx, &b[0], &b[1])
        }
        "tojson" => {
            let b = bind(
                "do_tojson",
                true,
                &["eval_ctx", "value", "indent"],
                vec![none()],
                value,
                args,
                kwargs,
            )?;
            let indent = match &b[1] {
                Value::None => json::Indent::None,
                v if v.is_str() => json::Indent::Text(v.as_str().unwrap_or_default().to_string()),
                v => match ops::as_int(v) {
                    Some(n) => {
                        json::Indent::Text(" ".repeat(n.to_usize().unwrap_or(0).min(1 << 16)))
                    }
                    None => {
                        return Err(Error::type_error(format!(
                            "can't multiply sequence by non-int of type '{}'",
                            v.type_name()
                        )));
                    }
                },
            };
            Ok(Value::markup(json::htmlsafe_dumps(&b[0], &indent)?))
        }
        other => Err(Error::runtime(format!(
            "No filter named {}.",
            pyrepr::str_repr(other)
        ))),
    }
}

/// `items()` of a value: a dict's pairs, or Python's `AttributeError`.
fn items_of(v: &Value) -> Result<Vec<(Value, Value)>> {
    match v {
        Value::Dict(d) => Ok(d.borrow().entries.clone()),
        Value::Undefined(u) => Err(u.error()),
        other => Err(Error::new(
            "AttributeError",
            format!("'{}' object has no attribute 'items'", other.type_name()),
        )),
    }
}

fn do_attr(obj: &Value, name: &Value) -> Result<Value> {
    let Some(n) = name.as_str() else {
        return Err(Error::type_error(format!(
            "attribute name must be string, not '{}'",
            name.type_name()
        )));
    };
    if let Value::Undefined(u) = obj {
        if !(n.starts_with("__") && n.ends_with("__")) {
            return Err(u.error());
        }
    }
    if crate::attrs::has_attribute(obj, n)? {
        attrs::getattr(obj, n)
    } else {
        Ok(Value::undefined_member(obj, Value::str(n)))
    }
}

fn do_batch(value: Value, linecount: Value, fill_with: Value) -> Value {
    let mut it: Option<PyIter> = None;
    let mut tmp: Vec<Value> = Vec::new();
    let mut done = false;
    Generator::value("do_batch", move || {
        if done {
            return Ok(None);
        }
        if it.is_none() {
            it = Some(ops::py_iter(&value)?);
        }
        let Some(iter) = it.as_mut() else {
            return Ok(None);
        };
        loop {
            match iter.next()? {
                Some(item) => {
                    if ops::eq(&Value::int(tmp.len() as i64), &linecount)? {
                        let out = std::mem::take(&mut tmp);
                        tmp.push(item);
                        return Ok(Some(Value::list(out)));
                    }
                    tmp.push(item);
                    ops::check_size(tmp.len())?;
                }
                None => {
                    done = true;
                    if tmp.is_empty() {
                        return Ok(None);
                    }
                    let mut out = Value::list(std::mem::take(&mut tmp));
                    if !matches!(fill_with, Value::None) {
                        let n = Value::int(ops::len(&out)? as i64);
                        if ops::compare(CmpOp::Lt, &n, &linecount)? {
                            let missing = ops::binop(BinOp::Sub, &linecount, &n)?;
                            let fill = ops::binop(
                                BinOp::Mul,
                                &Value::list(vec![fill_with.clone()]),
                                &missing,
                            )?;
                            out = ops::binop(BinOp::Add, &out, &fill)?;
                        }
                    }
                    return Ok(Some(out));
                }
            }
        }
    })
}

fn do_dictsort(
    value: &Value,
    case_sensitive: &Value,
    by: &Value,
    reverse: &Value,
) -> Result<Value> {
    let pos = if ops::eq(by, &Value::str("key"))? {
        0
    } else if ops::eq(by, &Value::str("value"))? {
        1
    } else {
        return Err(Error::filter_argument(
            "You can only sort by either \"key\" or \"value\"",
        ));
    };
    let items = items_of(value)?;
    let lower = !ops::truthy(case_sensitive)?;
    let pairs: Vec<Value> = items
        .into_iter()
        .map(|(k, v)| Value::tuple(vec![k, v]))
        .collect();
    let key = move |item: &Value| -> Result<Value> {
        let v = match item {
            Value::Tuple(t) => t[pos].clone(),
            _ => Value::None,
        };
        Ok(if lower { ignore_case(v) } else { v })
    };
    Ok(Value::list(sorted_by(pairs, &key, reverse_flag(reverse)?)?))
}

fn do_filesizeformat(value: &Value, binary: &Value) -> Result<Value> {
    let bytes = builtins::py_float(value)?;
    let binary = ops::truthy(binary)?;
    let base: f64 = if binary { 1024.0 } else { 1000.0 };
    let prefixes = if binary {
        ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"]
    } else {
        ["kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
    };
    if bytes == 1.0 {
        return Ok(Value::str("1 Byte"));
    }
    if bytes < base {
        let i = ops::float_to_int(bytes)?;
        return Ok(Value::str(format!("{} Bytes", pyrepr::int_str(&i)?)));
    }
    let base_int = if binary { 1024u32 } else { 1000u32 };
    let mut last = (0.0, "");
    for (i, prefix) in prefixes.iter().enumerate() {
        let unit = num_traits::pow(BigInt::from(base_int), i + 2);
        let unit_f = ops::int_to_f64(&unit)?;
        if bytes < unit_f {
            let v = base * bytes / unit_f;
            return Ok(Value::str(format!(
                "{} {prefix}",
                crate::format::format_value(&Value::Float(v), ".1f")?
            )));
        }
        last = (base * bytes / unit_f, prefix);
    }
    Ok(Value::str(format!(
        "{} {}",
        crate::format::format_value(&Value::Float(last.0), ".1f")?,
        last.1
    )))
}

fn do_int(value: &Value, default: &Value, base: &Value) -> Result<Value> {
    let first = if value.is_str() {
        builtins::py_int(value, Some(base))
    } else {
        builtins::py_int(value, None)
    };
    match first {
        Ok(i) => Ok(Value::Int(i)),
        Err(e) if matches!(e.kind, "TypeError" | "ValueError") => match builtins::py_float(value) {
            Ok(f) => match ops::float_to_int(f) {
                Ok(i) => Ok(Value::Int(i)),
                Err(e) if matches!(e.kind, "ValueError" | "OverflowError") => Ok(default.clone()),
                Err(e) => Err(e),
            },
            Err(e) if matches!(e.kind, "TypeError" | "ValueError" | "OverflowError") => {
                Ok(default.clone())
            }
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    }
}

fn do_groupby(
    value: &Value,
    attribute: &Value,
    default: &Value,
    case_sensitive: &Value,
) -> Result<Value> {
    let lower = !ops::truthy(case_sensitive)?;
    let default = Some(default.clone());
    let expr = attrgetter(attribute, lower, default.clone())?;
    let items = ops::iterate(value)?;
    let sorted = sorted_by(items, &expr, false)?;
    let mut groups: Vec<(Value, Vec<Value>)> = Vec::new();
    for item in sorted {
        let k = expr(&item)?;
        match groups.last_mut() {
            Some((gk, members)) if ops::eq(gk, &k)? => members.push(item),
            _ => groups.push((k, vec![item])),
        }
    }
    let out_expr = attrgetter(attribute, false, default)?;
    let mut out = Vec::new();
    for (k, members) in groups {
        let grouper = if lower { out_expr(&members[0])? } else { k };
        out.push(Value::object(GroupTuple {
            items: Rc::from(vec![grouper, Value::list(members)]),
        }));
    }
    Ok(Value::list(out))
}

fn do_indent(s: &Value, width: &Value, first: &Value, blank: &Value) -> Result<Value> {
    let indention = if width.is_str() {
        width.as_str().unwrap_or_default().to_string()
    } else {
        match ops::binop(BinOp::Mul, &Value::str(" "), width)? {
            Value::Str(s) => s.to_string(),
            other => pyrepr::str(&other)?,
        }
    };
    let markup = s.is_markup();
    let wrap = |t: String| {
        if markup {
            Value::markup(t)
        } else {
            Value::str(t)
        }
    };
    let newline = wrap("\n".into());
    let indention_v = wrap(indention.clone());
    let s = match s {
        Value::Undefined(u) => return Err(u.error()),
        v if v.is_str() => ops::binop(BinOp::Add, v, &newline)?,
        Value::List(_) => {
            return Err(Error::new(
                "AttributeError",
                "'list' object has no attribute 'splitlines'",
            ));
        }
        v => {
            return Err(Error::type_error(format!(
                "unsupported operand type(s) for +=: '{}' and 'str'",
                v.type_name()
            )));
        }
    };
    let text = s.as_str().unwrap_or_default().to_string();
    let lines = unicode::splitlines(&text, false);
    let mut rv = if ops::truthy(blank)? {
        let sep = ops::binop(BinOp::Add, &newline, &indention_v)?;
        let items = Value::list(lines.into_iter().map(&wrap).collect());
        methods::call_method(&sep, "join", vec![items], Vec::new())?
    } else {
        let mut lines = lines.into_iter();
        let mut rv = wrap(lines.next().unwrap_or_default());
        let rest: Vec<String> = lines.collect();
        if !rest.is_empty() {
            let mut parts = Vec::new();
            for line in rest {
                let line_v = wrap(line.clone());
                parts.push(if line.is_empty() {
                    line_v
                } else {
                    ops::binop(BinOp::Add, &indention_v, &line_v)?
                });
            }
            let joined =
                methods::call_method(&newline, "join", vec![Value::list(parts)], Vec::new())?;
            rv = ops::binop(BinOp::Add, &rv, &ops::binop(BinOp::Add, &newline, &joined)?)?;
        }
        rv
    };
    if ops::truthy(first)? {
        rv = ops::binop(BinOp::Add, &indention_v, &rv)?;
    }
    Ok(rv)
}

fn do_join(cx: &FilterCx, value: &Value, d: &Value, attribute: &Value) -> Result<Value> {
    let getter = if matches!(attribute, Value::None) {
        None
    } else {
        Some(attrgetter(attribute, false, None)?)
    };
    // `map(make_attrgetter(...), value)` takes `iter(value)` right away.
    let mut early = if getter.is_some() {
        Some(ops::py_iter(value)?)
    } else {
        None
    };
    let next_item = |it: &mut Option<PyIter>| -> Result<Option<Value>> {
        let iter = match it {
            Some(i) => i,
            None => {
                *it = Some(ops::py_iter(value)?);
                it.as_mut().ok_or_else(|| Error::runtime("iterator"))?
            }
        };
        match iter.next()? {
            Some(v) => Ok(Some(match &getter {
                Some(g) => g(&v)?,
                None => v,
            })),
            None => Ok(None),
        }
    };
    if !cx.autoescape()? {
        let sep = pyrepr::str(d)?;
        let mut parts = Vec::new();
        while let Some(it) = next_item(&mut early)? {
            parts.push(pyrepr::str(&it)?);
            ops::check_size(parts.len())?;
        }
        let out = parts.join(&sep);
        ops::check_size(out.len())?;
        return Ok(Value::str(out));
    }
    let mut items = Vec::new();
    while let Some(it) = next_item(&mut early)? {
        items.push(it);
        ops::check_size(items.len())?;
    }
    if !d.is_markup() {
        let do_escape = items.iter().any(Value::is_markup);
        let mut parts = Vec::with_capacity(items.len());
        for it in &items {
            parts.push(if it.is_markup() {
                it.clone()
            } else {
                Value::str(pyrepr::str(it)?)
            });
        }
        let sep = if do_escape {
            markup::escape(d)?
        } else {
            Value::str(pyrepr::str(d)?)
        };
        return methods::call_method(&sep, "join", vec![Value::list(parts)], Vec::new());
    }
    let parts: Vec<Value> = items.iter().map(soft).collect::<Result<_>>()?;
    methods::call_method(d, "join", vec![Value::list(parts)], Vec::new())
}

fn do_items(value: Value) -> Value {
    let mut state: Option<std::vec::IntoIter<(Value, Value)>> = None;
    Generator::value("do_items", move || {
        if state.is_none() {
            if value.is_undefined() {
                return Ok(None);
            }
            let Value::Dict(d) = &value else {
                return Err(Error::type_error("Can only get item pairs from a mapping."));
            };
            state = Some(d.borrow().entries.clone().into_iter());
        }
        Ok(state
            .as_mut()
            .and_then(Iterator::next)
            .map(|(k, v)| Value::tuple(vec![k, v])))
    })
}

fn do_map(cx: FilterCx, value: Value, args: Vec<Value>, kwargs: Kwargs) -> Value {
    type MapFn = Box<dyn Fn(Value) -> Result<Value>>;
    let mut state: Option<(PyIter, MapFn)> = None;
    let mut started = false;
    Generator::value("sync_do_map", move || {
        if !started {
            started = true;
            if !ops::truthy(&value)? {
                return Ok(None);
            }
            let func: MapFn = if args.is_empty() && kwargs.iter().any(|(k, _)| &**k == "attribute")
            {
                let mut kw = kwargs.clone();
                let attribute = take_kw(&mut kw, "attribute").unwrap_or(Value::None);
                let default = take_kw(&mut kw, "default");
                if let Some((k, _)) = kw.first() {
                    return Err(Error::filter_argument(format!(
                        "Unexpected keyword argument {}",
                        pyrepr::str_repr(k)
                    )));
                }
                let getter = attrgetter(&attribute, false, default)?;
                Box::new(move |item| getter(&item))
            } else {
                let Some(name) = args.first().cloned() else {
                    return Err(Error::filter_argument("map requires a filter argument"));
                };
                let rest = args[1..].to_vec();
                let kw = kwargs.clone();
                let cx = cx.clone();
                Box::new(move |item| call_named_filter(&cx, &name, item, rest.clone(), kw.clone()))
            };
            state = Some((ops::py_iter(&value)?, func));
        }
        let Some((it, func)) = state.as_mut() else {
            return Ok(None);
        };
        match it.next()? {
            Some(item) => Ok(Some(func(item)?)),
            None => Ok(None),
        }
    })
}

fn take_kw(kw: &mut Kwargs, name: &str) -> Option<Value> {
    let i = kw.iter().position(|(k, _)| &**k == name)?;
    Some(kw.remove(i).1)
}

/// `environment.call_filter(name, value, args, kwargs, context=context)`.
fn call_named_filter(
    cx: &FilterCx,
    name: &Value,
    value: Value,
    args: Vec<Value>,
    kwargs: Kwargs,
) -> Result<Value> {
    ops::check_hashable(name)?;
    match name {
        Value::Str(n) | Value::Markup(n) if filter_pass(n).is_some() => {
            call_filter(cx, n, value, args, kwargs)
        }
        _ => Err(unknown_callable("filter", name)),
    }
}

fn unknown_callable(kind: &str, name: &Value) -> Error {
    let mut msg = format!(
        "No {kind} named {}.",
        pyrepr::repr(name).unwrap_or_default()
    );
    if let Value::Undefined(u) = name {
        msg = format!(
            "{msg} ({}; did you forget to quote the callable name?)",
            u.message()
        );
    }
    Error::runtime(msg)
}

/// `environment.call_test(name, value, args, kwargs, context)`.
pub fn call_named_test(
    cx: &FilterCx,
    name: &Value,
    value: Value,
    args: Vec<Value>,
    kwargs: Kwargs,
) -> Result<Value> {
    ops::check_hashable(name)?;
    match name {
        Value::Str(n) | Value::Markup(n) if crate::jtests::test_exists(n) => {
            crate::jtests::call_test(cx, n, value, args, kwargs)
        }
        _ => Err(unknown_callable("test", name)),
    }
}

fn select_or_reject(
    cx: FilterCx,
    value: Value,
    args: Vec<Value>,
    kwargs: Kwargs,
    reject: bool,
    lookup_attr: bool,
) -> Value {
    type Func = Box<dyn Fn(Value) -> Result<bool>>;
    let mut state: Option<(PyIter, Func)> = None;
    let mut started = false;
    Generator::value("select_or_reject", move || {
        if !started {
            started = true;
            if !ops::truthy(&value)? {
                return Ok(None);
            }
            let (getter, off): (Option<Getter>, usize) = if lookup_attr {
                let Some(attr) = args.first() else {
                    return Err(Error::filter_argument(
                        "Missing parameter for attribute name",
                    ));
                };
                (Some(Box::new(attrgetter(attr, false, None)?)), 1)
            } else {
                (None, 0)
            };
            let test: Option<(Value, Vec<Value>)> =
                args.get(off).map(|n| (n.clone(), args[off + 1..].to_vec()));
            let kw = kwargs.clone();
            let cx = cx.clone();
            let func: Func = Box::new(move |item: Value| -> Result<bool> {
                let item = match &getter {
                    Some(g) => g(&item)?,
                    None => item,
                };
                let r = match &test {
                    Some((name, targs)) => ops::truthy(&call_named_test(
                        &cx,
                        name,
                        item,
                        targs.clone(),
                        kw.clone(),
                    )?)?,
                    None => ops::truthy(&item)?,
                };
                Ok(if reject { !r } else { r })
            });
            state = Some((ops::py_iter(&value)?, func));
        }
        let Some((it, func)) = state.as_mut() else {
            return Ok(None);
        };
        while let Some(item) = it.next()? {
            if func(item.clone())? {
                return Ok(Some(item));
            }
        }
        Ok(None)
    })
}

fn min_or_max(
    value: &Value,
    max: bool,
    case_sensitive: &Value,
    attribute: &Value,
) -> Result<Value> {
    let mut it = ops::py_iter(value)?;
    let Some(first) = it.next()? else {
        return Ok(Value::undefined_hint(
            "No aggregated item, sequence was empty.",
        ));
    };
    let key = attrgetter(attribute, !ops::truthy(case_sensitive)?, None)?;
    let mut best = first.clone();
    let mut best_key = key(&first)?;
    while let Some(item) = it.next()? {
        let k = key(&item)?;
        let better = if max {
            ops::compare(CmpOp::Gt, &k, &best_key)?
        } else {
            ops::compare(CmpOp::Lt, &k, &best_key)?
        };
        if better {
            best = item;
            best_key = k;
        }
    }
    Ok(best)
}

fn do_replace(cx: &FilterCx, s: &Value, old: &Value, new: &Value, count: &Value) -> Result<Value> {
    let count = if matches!(count, Value::None) {
        Value::int(-1)
    } else {
        count.clone()
    };
    if !cx.autoescape()? {
        let recv = Value::str(pyrepr::str(s)?);
        let old = Value::str(pyrepr::str(old)?);
        let new = Value::str(pyrepr::str(new)?);
        return methods::call_method(&recv, "replace", vec![old, new, count], Vec::new());
    }
    let recv = if old.is_markup() || (new.is_markup() && !s.is_markup()) {
        markup::escape(s)?
    } else {
        soft(s)?
    };
    methods::call_method(
        &recv,
        "replace",
        vec![soft(old)?, soft(new)?, count],
        Vec::new(),
    )
}

/// `reversed(value)`.
fn py_reversed(value: &Value) -> Result<Value> {
    Ok(match value {
        Value::List(l) => RevIter::value("list_reverseiterator", l.borrow().clone()),
        Value::Tuple(_) | Value::Str(_) | Value::Markup(_) | Value::StrEnum(_) => {
            RevIter::value("reversed", ops::iterate(value)?)
        }
        Value::Dict(d) => RevIter::value("dict_reversekeyiterator", d.borrow().keys()),
        Value::Undefined(u) => {
            if u.strict {
                return Err(u.error());
            }
            RevIter::value("reversed", Vec::new())
        }
        Value::Object(o) if matches!(o.type_name(), "range" | "_GroupTuple" | "bytes") => {
            RevIter::value(
                if o.type_name() == "range" {
                    "range_iterator"
                } else {
                    "reversed"
                },
                ops::iterate(value)?,
            )
        }
        other => {
            return Err(Error::type_error(format!(
                "'{}' object is not reversible",
                other.type_name()
            )));
        }
    })
}

fn do_reverse(value: &Value) -> Result<Value> {
    if let Some(s) = value.as_str() {
        let r: String = s.chars().rev().collect();
        return Ok(if value.is_markup() {
            Value::markup(r)
        } else {
            Value::str(r)
        });
    }
    match py_reversed(value) {
        Ok(v) => Ok(v),
        Err(e) if e.kind == "TypeError" => match ops::iterate(value) {
            Ok(mut items) => {
                items.reverse();
                Ok(Value::list(items))
            }
            Err(e) if e.kind == "TypeError" => {
                Err(Error::filter_argument("argument must be iterable"))
            }
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    }
}

fn do_round(value: &Value, precision: &Value, method: &Value) -> Result<Value> {
    ops::check_hashable(method)?;
    let m = method
        .as_str()
        .filter(|m| matches!(*m, "common" | "ceil" | "floor"));
    let Some(m) = m else {
        return Err(Error::filter_argument(
            "method must be common, ceil or floor",
        ));
    };
    if m == "common" {
        return builtins::py_round(value, precision);
    }
    let scale = ops::binop(BinOp::Pow, &Value::int(10), precision)?;
    let scaled = ops::binop(BinOp::Mul, value, &scale)?;
    let f = match &scaled {
        Value::Float(f) => *f,
        v => match ops::as_int(v) {
            Some(i) => return ops::binop(BinOp::Div, &Value::Int(i), &scale),
            None => {
                return Err(Error::type_error(format!(
                    "must be real number, not {}",
                    v.type_name()
                )));
            }
        },
    };
    let rounded = if m == "floor" { f.floor() } else { f.ceil() };
    let i = ops::float_to_int(rounded)?;
    ops::binop(BinOp::Div, &Value::Int(i), &scale)
}

fn do_slice(value: Value, slices: Value, fill_with: Value) -> Value {
    let mut state: Option<(Vec<Value>, i64, i64, i64, i64)> = None;
    let mut slice_number: i64 = 0;
    Generator::value("sync_do_slice", move || {
        if state.is_none() {
            let seq = ops::iterate(&value)?;
            let n = methods::index_value(&slices)?;
            let n = n
                .to_i64()
                .ok_or_else(|| Error::overflow("Python int too large to convert to C ssize_t"))?;
            if n == 0 {
                return Err(Error::zero_division("integer division or modulo by zero"));
            }
            let length = seq.len() as i64;
            let per = length.div_euclid(n);
            let extra = length.rem_euclid(n);
            state = Some((seq, n, per, extra, 0));
        }
        let Some((seq, n, per, extra, offset)) = state.as_mut() else {
            return Ok(None);
        };
        if slice_number >= *n {
            return Ok(None);
        }
        let start = *offset + slice_number * *per;
        if slice_number < *extra {
            *offset += 1;
        }
        let end = *offset + (slice_number + 1) * *per;
        let len = seq.len() as i64;
        let (a, b) = (start.clamp(0, len) as usize, end.clamp(0, len) as usize);
        let mut tmp: Vec<Value> = if a < b {
            seq[a..b].to_vec()
        } else {
            Vec::new()
        };
        if !matches!(fill_with, Value::None) && slice_number >= *extra {
            tmp.push(fill_with.clone());
        }
        slice_number += 1;
        Ok(Some(Value::list(tmp)))
    })
}

/// `do_title`: each part of `re.split(r"([-\s({\[<]+)", s)` with its first
/// character upper-cased and the rest lower-cased.
fn do_title(s: &str) -> String {
    let is_sep = |c: char| c == '-' || unicode::is_space(c) || matches!(c, '(' | '{' | '[' | '<');
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let sep = is_sep(chars[i]);
        let start = i;
        while i < chars.len() && is_sep(chars[i]) == sep {
            i += 1;
        }
        let first: String = chars[start].to_string();
        let rest: String = chars[start + 1..i].iter().collect();
        out.push_str(&unicode::upper(&first));
        out.push_str(&unicode::lower(&rest));
    }
    out
}

fn do_truncate(
    s: &Value,
    length: &Value,
    killwords: &Value,
    end: &Value,
    leeway: &Value,
) -> Result<Value> {
    let leeway = if matches!(leeway, Value::None) {
        Value::int(5)
    } else {
        leeway.clone()
    };
    let end_len = ops::len(end)?;
    if !ops::compare(CmpOp::Ge, length, &Value::int(end_len as i64))? {
        return Err(Error::new(
            "AssertionError",
            format!("expected length >= {end_len}, got {}", pyrepr::str(length)?),
        ));
    }
    if !ops::compare(CmpOp::Ge, &leeway, &Value::int(0))? {
        return Err(Error::new(
            "AssertionError",
            format!("expected leeway >= 0, got {}", pyrepr::str(&leeway)?),
        ));
    }
    let n = ops::len(s)?;
    let limit = ops::binop(BinOp::Add, length, &leeway)?;
    if ops::compare(CmpOp::Le, &Value::int(n as i64), &limit)? {
        return Ok(s.clone());
    }
    let cut = ops::binop(BinOp::Sub, length, &Value::int(end_len as i64))?;
    let head = attrs::subscript(s, &attrs::slice_object(Value::None, cut, Value::None))?;
    if ops::truthy(killwords)? {
        return ops::binop(BinOp::Add, &head, end);
    }
    let parts = methods::call_method(
        &head,
        "rsplit",
        vec![Value::str(" "), Value::int(1)],
        Vec::new(),
    )?;
    let first = attrs::subscript(&parts, &Value::int(0))?;
    ops::binop(BinOp::Add, &first, end)
}

fn do_unique(value: Value, case_sensitive: &Value, attribute: &Value) -> Result<Value> {
    let lower = !ops::truthy(case_sensitive)?;
    let attribute = attribute.clone();
    let mut state: Option<(PyIter, Getter)> = None;
    let mut seen: Vec<Value> = Vec::new();
    Ok(Generator::value("sync_do_unique", move || {
        if state.is_none() {
            let getter = attrgetter(&attribute, lower, None)?;
            state = Some((ops::py_iter(&value)?, Box::new(getter)));
        }
        let Some((iter, getter)) = state.as_mut() else {
            return Ok(None);
        };
        while let Some(item) = iter.next()? {
            let key = getter(&item)?;
            ops::check_hashable(&key)?;
            let mut found = false;
            for s in &seen {
                if ops::same_object(s, &key) || ops::eq(s, &key)? {
                    found = true;
                    break;
                }
            }
            if !found {
                seen.push(key);
                return Ok(Some(item));
            }
        }
        Ok(None)
    }))
}

/// `url_quote(obj, for_qs)`.
fn url_quote(v: &Value, for_qs: bool) -> Result<String> {
    let bytes: Vec<u8> = match v.downcast::<objects::Bytes>() {
        Some(b) => b.data.clone(),
        None => pyrepr::str(v)?.into_bytes(),
    };
    let mut out = String::new();
    for b in bytes {
        let safe = b.is_ascii_alphanumeric()
            || matches!(b, b'_' | b'.' | b'-' | b'~')
            || (!for_qs && b == b'/');
        if safe {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    if for_qs {
        out = out.replace("%20", "+");
    }
    Ok(out)
}

fn do_urlencode(value: &Value) -> Result<Value> {
    let iterable =
        !value.is_str() && ops::py_iter(value).is_ok() || matches!(value, Value::Undefined(_));
    if value.is_str() || !iterable {
        return Ok(Value::str(url_quote(value, false)?));
    }
    let items: Vec<Value> = match value {
        Value::Dict(d) => d
            .borrow()
            .entries
            .iter()
            .map(|(k, v)| Value::tuple(vec![k.clone(), v.clone()]))
            .collect(),
        other => ops::iterate(other)?,
    };
    let mut parts = Vec::new();
    for item in items {
        let pair = ops::unpack(&item, 2)?;
        parts.push(format!(
            "{}={}",
            url_quote(&pair[0], true)?,
            url_quote(&pair[1], true)?
        ));
    }
    Ok(Value::str(parts.join("&")))
}

fn do_urlize(cx: &FilterCx, b: &[Value]) -> Result<Value> {
    let (value, trim, nofollow, target, rel, extra) = (&b[0], &b[1], &b[2], &b[3], &b[4], &b[5]);
    let mut rel_parts: Vec<String> = match rel {
        Value::None => Vec::new(),
        v => {
            let s = if ops::truthy(v)? {
                pyrepr::str(v)?
            } else {
                String::new()
            };
            unicode::split_whitespace(&s)
                .into_iter()
                .map(String::from)
                .collect()
        }
    };
    if ops::truthy(nofollow)? {
        rel_parts.push("nofollow".into());
    }
    rel_parts.push("noopener".into());
    rel_parts.sort();
    rel_parts.dedup();
    let rel = rel_parts.join(" ");
    let target = match target {
        Value::None => None,
        v => Some(pyrepr::str(v)?),
    };
    let extra_schemes: Vec<String> = match extra {
        Value::None => Vec::new(),
        v => {
            let mut out = Vec::new();
            for s in ops::iterate(v)? {
                let text = pyrepr::str(&s)?;
                let valid = {
                    let body = text.trim_end_matches('/');
                    let slashes = text.len() - body.len();
                    body.ends_with(':')
                        && slashes <= 2
                        && body[..body.len() - 1].chars().count() >= 2
                        && body[..body.len() - 1]
                            .chars()
                            .all(|c| unicode::is_word(c) || matches!(c, '.' | '+' | '-'))
                };
                if !valid {
                    return Err(Error::filter_argument(format!(
                        "{} is not a valid URI scheme prefix.",
                        pyrepr::repr(&s)?
                    )));
                }
                out.push(text);
            }
            out
        }
    };
    let trim = match trim {
        Value::None => None,
        v => Some(methods::index_value(v)?.to_usize().unwrap_or(0)),
    };
    let rv = crate::urlize::urlize(
        &markup::escape_value(value)?,
        trim,
        Some(&rel).filter(|r| !r.is_empty()).map(String::as_str),
        target.as_deref(),
        &extra_schemes,
    );
    Ok(if cx.autoescape()? {
        Value::markup(rv)
    } else {
        Value::str(rv)
    })
}

fn do_wordwrap(b: &[Value]) -> Result<Value> {
    let (s, width, break_long, wrapstring, hyphens) = (&b[0], &b[1], &b[2], &b[3], &b[4]);
    let wrapstring = match wrapstring {
        Value::None => "\n".to_string(),
        v => pyrepr::str(v)?,
    };
    let Some(text) = s.as_str() else {
        if let Value::Undefined(u) = s {
            return Err(u.error());
        }
        return Err(Error::new(
            "AttributeError",
            format!("'{}' object has no attribute 'splitlines'", s.type_name()),
        ));
    };
    let width = methods::index_value(width)?.to_i64().unwrap_or(i64::MAX);
    let break_long = ops::truthy(break_long)?;
    let hyphens = ops::truthy(hyphens)?;
    let mut lines = Vec::new();
    for line in unicode::splitlines(text, false) {
        lines.push(crate::textwrap::wrap(&line, width, break_long, hyphens)?.join(&wrapstring));
    }
    Ok(Value::str(lines.join(&wrapstring)))
}

fn do_xmlattr(cx: &FilterCx, d: &Value, autospace: &Value) -> Result<Value> {
    let mut items = Vec::new();
    for (key, value) in items_of(d)? {
        if matches!(value, Value::None) || value.is_undefined() {
            continue;
        }
        let Some(k) = key.as_str() else {
            return Err(Error::type_error(format!(
                "expected string or bytes-like object, got '{}'",
                key.type_name()
            )));
        };
        if k.chars()
            .any(|c| c.is_ascii_whitespace() || c == '\u{b}' || matches!(c, '/' | '>' | '='))
        {
            return Err(Error::value_error(format!(
                "Invalid character in attribute name: {}",
                pyrepr::repr(&key)?
            )));
        }
        items.push(format!(
            "{}=\"{}\"",
            markup::escape_value(&key)?,
            markup::escape_value(&value)?
        ));
    }
    let mut rv = items.join(" ");
    if ops::truthy(autospace)? && !rv.is_empty() {
        rv.insert(0, ' ');
    }
    Ok(if cx.autoescape()? {
        Value::markup(rv)
    } else {
        Value::str(rv)
    })
}
