//! Values with Python's types: what a Jinja2 template sees and builds.

use std::any::Any;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::rc::Rc;

use num_bigint_dig::BigInt;

use crate::arena;
use crate::error::{Error, Result};

/// A Python value.
#[derive(Clone)]
pub enum Value {
    /// `None`.
    None,
    /// `bool`.
    Bool(bool),
    /// `int`, arbitrary precision.
    Int(BigInt),
    /// `float`.
    Float(f64),
    /// `str`.
    Str(Rc<str>),
    /// `markupsafe.Markup`: a `str` already safe for HTML.
    Markup(Rc<str>),
    /// A member of a `(str, Enum)` class: a `str` whose `str()` is
    /// `Class.MEMBER`.
    StrEnum(Rc<StrEnum>),
    /// `list` (mutable, shared).
    List(Rc<RefCell<Vec<Value>>>),
    /// `tuple`.
    Tuple(Rc<[Value]>),
    /// `dict`, or `collections.defaultdict(str)`.
    Dict(Rc<RefCell<Dict>>),
    /// Jinja2's `Undefined` / `StrictUndefined`.
    Undefined(Rc<Undefined>),
    /// Anything else: ranges, loop contexts, macros, host objects, …
    Object(Rc<dyn Object>),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match crate::pyrepr::repr(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => f.write_str("<value>"),
        }
    }
}

impl Value {
    /// A `str`.
    pub fn str(s: impl AsRef<str>) -> Self {
        Value::Str(Rc::from(s.as_ref()))
    }

    /// A `Markup`.
    pub fn markup(s: impl AsRef<str>) -> Self {
        Value::Markup(Rc::from(s.as_ref()))
    }

    /// An `int`.
    pub fn int(i: i64) -> Self {
        Value::Int(BigInt::from(i))
    }

    /// A `list`.
    pub fn list(items: Vec<Value>) -> Self {
        let rc = Rc::new(RefCell::new(items));
        arena::track_list(&rc);
        Value::List(rc)
    }

    /// A `tuple`.
    pub fn tuple(items: Vec<Value>) -> Self {
        Value::Tuple(Rc::from(items))
    }

    /// A `dict` value.
    pub fn from_dict(d: Dict) -> Self {
        let rc = Rc::new(RefCell::new(d));
        arena::track_dict(&rc);
        Value::Dict(rc)
    }

    /// A `dict` from ordered pairs (later duplicates win, like a literal).
    pub fn dict(entries: Vec<(Value, Value)>) -> Result<Self> {
        let mut d = Dict::default();
        for (k, v) in entries {
            d.set(k, v)?;
        }
        Ok(Value::from_dict(d))
    }

    /// A `dict` from string keys.
    pub fn str_dict<K: AsRef<str>>(entries: Vec<(K, Value)>) -> Self {
        let mut d = Dict::default();
        for (k, v) in entries {
            d.entries.push((Value::str(k), v));
        }
        Value::from_dict(d)
    }

    /// An object.
    pub fn object<T: Object>(o: T) -> Self {
        let rc: Rc<dyn Object> = Rc::new(o);
        arena::track_object(&rc);
        Value::Object(rc)
    }

    /// `environment.undefined(name=name)`: a missing variable.
    pub fn undefined_name(name: &str) -> Self {
        Value::Undefined(Rc::new(Undefined {
            hint: None,
            obj: None,
            name: Some(Value::str(name)),
            exc: "UndefinedError",
            strict: strict_undefined(),
        }))
    }

    /// `environment.undefined(hint)`.
    pub fn undefined_hint(hint: impl Into<String>) -> Self {
        Value::Undefined(Rc::new(Undefined {
            hint: Some(hint.into()),
            obj: None,
            name: None,
            exc: "UndefinedError",
            strict: strict_undefined(),
        }))
    }

    /// `environment.undefined(obj=obj, name=name)`: a missing attribute or
    /// item.
    pub fn undefined_member(obj: &Value, name: Value) -> Self {
        Value::Undefined(Rc::new(Undefined {
            hint: None,
            obj: Some(obj.clone()),
            name: Some(name),
            exc: "UndefinedError",
            strict: strict_undefined(),
        }))
    }

    /// The sandbox's `unsafe_undefined`: using it raises `SecurityError`.
    pub fn unsafe_undefined(obj: &Value, attr: &str) -> Self {
        Value::Undefined(Rc::new(Undefined {
            hint: Some(format!(
                "access to attribute {} of {} object is unsafe.",
                crate::pyrepr::str_repr(attr),
                crate::pyrepr::str_repr(&obj.type_name())
            )),
            obj: Some(obj.clone()),
            name: Some(Value::str(attr)),
            exc: "SecurityError",
            strict: strict_undefined(),
        }))
    }

    /// Whether this is an `Undefined`.
    pub fn is_undefined(&self) -> bool {
        matches!(self, Value::Undefined(_))
    }

    /// The text of a `str` instance (`str`, `Markup`, a str-enum member).
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) | Value::Markup(s) => Some(s),
            Value::StrEnum(e) => Some(&e.value),
            _ => None,
        }
    }

    /// `isinstance(v, str)`.
    pub fn is_str(&self) -> bool {
        self.as_str().is_some()
    }

    /// `hasattr(v, "__html__")`.
    pub fn is_markup(&self) -> bool {
        matches!(self, Value::Markup(_))
    }

    /// The object, when this is one of type `T`.
    pub fn downcast<T: Object>(&self) -> Option<&T> {
        match self {
            Value::Object(o) => o.as_any().downcast_ref::<T>(),
            _ => None,
        }
    }

    /// `type(v).__name__`.
    pub fn type_name(&self) -> String {
        match self {
            Value::None => "NoneType".into(),
            Value::Bool(_) => "bool".into(),
            Value::Int(_) => "int".into(),
            Value::Float(_) => "float".into(),
            Value::Str(_) => "str".into(),
            Value::Markup(_) => "Markup".into(),
            Value::StrEnum(e) => e.class.to_string(),
            Value::List(_) => "list".into(),
            Value::Tuple(_) => "tuple".into(),
            Value::Dict(d) => {
                if d.borrow().default_str {
                    "defaultdict".into()
                } else {
                    "dict".into()
                }
            }
            Value::Undefined(u) => {
                if u.strict {
                    "StrictUndefined".into()
                } else {
                    "Undefined".into()
                }
            }
            Value::Object(o) => o.type_name().to_string(),
        }
    }

    /// `type(v).__module__`.
    pub fn module(&self) -> String {
        match self {
            Value::Markup(_) => "markupsafe".into(),
            Value::StrEnum(e) => e.module.to_string(),
            Value::Dict(d) if d.borrow().default_str => "collections".into(),
            Value::Undefined(_) => "jinja2.runtime".into(),
            Value::Object(o) => o.module().to_string(),
            _ => "builtins".into(),
        }
    }

    /// Jinja2's `object_type_repr`: `None`, `int object`,
    /// `markupsafe.Markup object`, …
    pub fn object_type_repr(&self) -> String {
        if let Value::None = self {
            return "None".into();
        }
        let module = self.module();
        if module == "builtins" {
            format!("{} object", self.type_name())
        } else {
            format!("{module}.{} object", self.type_name())
        }
    }

    /// A deep copy of a constant (Python re-evaluates a constant's literal
    /// each time, so a folded list is a new list each time).
    pub fn fresh(&self) -> Value {
        match self {
            Value::List(l) => Value::list(l.borrow().iter().map(Value::fresh).collect()),
            Value::Tuple(t) => Value::tuple(t.iter().map(Value::fresh).collect()),
            Value::Dict(d) => {
                let d = d.borrow();
                Value::from_dict(Dict {
                    entries: d
                        .entries
                        .iter()
                        .map(|(k, v)| (k.fresh(), v.fresh()))
                        .collect(),
                    default_str: d.default_str,
                })
            }
            other => other.clone(),
        }
    }
}

thread_local! {
    static STRICT_UNDEFINED: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// Whether the environment rendering on this thread is `undefined=
/// StrictUndefined` (the notification renderer) rather than Jinja's default
/// `Undefined` (the report renderers).
pub fn strict_undefined() -> bool {
    STRICT_UNDEFINED.with(std::cell::Cell::get)
}

/// While alive, the thread's environment uses the given undefined class.
pub(crate) struct UndefinedMode(bool);

impl UndefinedMode {
    pub(crate) fn set(strict: bool) -> Self {
        Self(STRICT_UNDEFINED.with(|s| s.replace(strict)))
    }
}

impl Drop for UndefinedMode {
    fn drop(&mut self) {
        STRICT_UNDEFINED.with(|s| s.set(self.0));
    }
}

/// A member of a `(str, Enum)` class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrEnum {
    /// `type(member).__name__`.
    pub class: &'static str,
    /// `type(member).__module__`.
    pub module: &'static str,
    /// `member.name`.
    pub name: String,
    /// `member.value`.
    pub value: String,
    /// Every member of the class, `(name, value)`, in definition order.
    pub members: &'static [(&'static str, &'static str)],
}

/// Jinja2's `Undefined`: `strict` is `StrictUndefined`, which fails on every
/// use but `is defined`, `is undefined` and the `default` filter; the plain
/// one (an inline `if` without `else`) prints as nothing.
#[derive(Debug, Clone)]
pub struct Undefined {
    /// A fixed message.
    pub hint: Option<String>,
    /// The object the lookup was made on (`None` = a plain name).
    pub obj: Option<Value>,
    /// The name or key looked up.
    pub name: Option<Value>,
    /// The exception raised on use (`UndefinedError`, `SecurityError`).
    pub exc: &'static str,
    /// `StrictUndefined`.
    pub strict: bool,
}

impl Undefined {
    /// `_undefined_message`.
    pub fn message(&self) -> String {
        if let Some(hint) = &self.hint {
            if !hint.is_empty() {
                return hint.clone();
            }
        }
        let name = match &self.name {
            Some(n) => crate::pyrepr::repr(n).unwrap_or_default(),
            None => "None".into(),
        };
        match &self.obj {
            None => format!("{name} is undefined"),
            Some(obj) => {
                if self.name.as_ref().is_some_and(Value::is_str) {
                    format!(
                        "{} has no attribute {name}",
                        crate::pyrepr::str_repr(&obj.object_type_repr())
                    )
                } else {
                    format!("{} has no element {name}", obj.object_type_repr())
                }
            }
        }
    }

    /// The exception using this value raises.
    pub fn error(&self) -> Error {
        Error::new(self.exc, self.message())
    }
}

/// A `dict`: insertion-ordered, keys compared with Python's `==`.
#[derive(Debug, Clone, Default)]
pub struct Dict {
    /// `(key, value)` in insertion order.
    pub entries: Vec<(Value, Value)>,
    /// `collections.defaultdict(str)`: a missing key reads (and inserts) `""`.
    pub default_str: bool,
}

impl Dict {
    /// The position of `key`.
    pub fn position(&self, key: &Value) -> Result<Option<usize>> {
        crate::ops::check_hashable(key)?;
        for (i, (k, _)) in self.entries.iter().enumerate() {
            if crate::ops::eq(k, key)? {
                return Ok(Some(i));
            }
        }
        Ok(None)
    }

    /// `d.get(key)`.
    pub fn get(&self, key: &Value) -> Result<Option<Value>> {
        Ok(self.position(key)?.map(|i| self.entries[i].1.clone()))
    }

    /// `d[key] = value` (an existing key keeps its place and its object).
    pub fn set(&mut self, key: Value, value: Value) -> Result<()> {
        match self.position(&key)? {
            Some(i) => self.entries[i].1 = value,
            None => self.entries.push((key, value)),
        }
        Ok(())
    }

    /// The keys.
    pub fn keys(&self) -> Vec<Value> {
        self.entries.iter().map(|(k, _)| k.clone()).collect()
    }
}

/// An iterator over a value (`iter(v)`), advanced with [`PyIter::next`].
pub enum PyIter {
    /// Items known in advance.
    Seq(VecDeque<Value>),
    /// A list, read as it is when each item is taken (Python's list
    /// iterator sees appends made during the loop).
    List(Rc<RefCell<Vec<Value>>>, usize),
    /// A dict's keys; changing its size during iteration is an error.
    Dict(Rc<RefCell<Dict>>, usize, usize),
    /// An iterator object (a generator, a loop context, …).
    Obj(Value),
    /// Exhausted.
    Done,
}

impl PyIter {
    /// `next(it)`, `None` at the end.
    pub fn next(&mut self) -> Result<Option<Value>> {
        let out = match self {
            PyIter::Seq(items) => items.pop_front(),
            PyIter::List(list, i) => {
                let item = list.borrow().get(*i).cloned();
                *i += 1;
                item
            }
            PyIter::Dict(d, i, len) => {
                let d = d.borrow();
                if d.entries.len() != *len {
                    return Err(Error::new(
                        "RuntimeError",
                        "dictionary changed size during iteration",
                    ));
                }
                let item = d.entries.get(*i).map(|(k, _)| k.clone());
                *i += 1;
                item
            }
            PyIter::Obj(v) => match v {
                Value::Object(o) => match o.next() {
                    Some(r) => r?,
                    None => None,
                },
                _ => None,
            },
            PyIter::Done => None,
        };
        if out.is_none() {
            *self = PyIter::Done;
        }
        Ok(out)
    }

    /// Every remaining item.
    pub fn collect(mut self) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        while let Some(v) = self.next()? {
            out.push(v);
            crate::ops::check_size(out.len())?;
        }
        Ok(out)
    }
}

/// A Python object that is not one of the built-in value types.
pub trait Object: Any + fmt::Debug {
    /// `type(obj).__name__`.
    fn type_name(&self) -> &str;

    /// `type(obj).__module__`.
    fn module(&self) -> &str {
        "builtins"
    }

    /// `repr(obj)`.
    fn repr(&self) -> Result<String>;

    /// `str(obj)`.
    fn str(&self) -> Result<String> {
        self.repr()
    }

    /// `len(obj)`; `None` when the type has no `__len__`.
    fn len(&self) -> Option<Result<usize>> {
        None
    }

    /// `bool(obj)`.
    fn truthy(&self) -> Result<bool> {
        match self.len() {
            Some(n) => Ok(n? > 0),
            None => Ok(true),
        }
    }

    /// `iter(obj)`; `None` when it is not iterable.
    fn iter(&self, me: &Value) -> Option<Result<PyIter>> {
        let _ = me;
        None
    }

    /// `next(obj)` for an iterator object.
    fn next(&self) -> Option<Result<Option<Value>>> {
        None
    }

    /// The attributes `hasattr` finds, for the sandbox's decision between
    /// "unsafe" and "missing".
    fn attrs(&self) -> &'static [&'static str] {
        &[]
    }

    /// `getattr(obj, name)` for a public attribute; `None` is an
    /// `AttributeError`.
    fn getattr(&self, me: &Value, name: &str) -> Option<Result<Value>> {
        let _ = (me, name);
        None
    }

    /// `obj[key]`: `None` when the type is not subscriptable; a lookup error
    /// is an `Err`.
    fn getitem(&self, key: &Value) -> Option<Result<Value>> {
        let _ = key;
        None
    }

    /// `obj(*args, **kwargs)`; `None` when it is not callable.
    fn call(
        &self,
        me: &Value,
        args: Vec<Value>,
        kwargs: Vec<(Rc<str>, Value)>,
    ) -> Option<Result<Value>> {
        let _ = (me, args, kwargs);
        None
    }

    /// `obj.name(*args, **kwargs)` for a method the object's `getattr`
    /// returned as a [`crate::objects::Method`].
    fn call_method(
        &self,
        me: &Value,
        name: &str,
        args: Vec<Value>,
        kwargs: Vec<(Rc<str>, Value)>,
    ) -> Option<Result<Value>> {
        let _ = (me, name, args, kwargs);
        None
    }

    /// `obj == other`; `None` falls back to identity.
    fn eq(&self, other: &Value) -> Option<bool> {
        let _ = other;
        None
    }

    /// `item in obj` when the type defines `__contains__`.
    fn contains(&self, item: &Value) -> Option<Result<bool>> {
        let _ = item;
        None
    }

    /// `hash(obj)` succeeds.
    fn hashable(&self) -> bool {
        true
    }

    /// Drops what the object holds, breaking reference cycles once a render
    /// is over.
    fn clear(&self) {}

    /// For downcasting.
    fn as_any(&self) -> &dyn Any;
}
