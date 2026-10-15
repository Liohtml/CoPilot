//! Python objects a template can reach besides the built-in value types:
//! `range`, Jinja's `Namespace`, `Cycler` and `Joiner`, generators, dict
//! views, `_GroupTuple`, reverse iterators, `bytes`, bound methods and the
//! global functions and classes.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

use num_bigint_dig::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, ToPrimitive, Zero};

use crate::error::{Error, Result};
use crate::ops;
use crate::pyrepr;
use crate::tables;
use crate::value::{Dict, Object, PyIter, Value};

/// A fake address for reprs that show one (`<... at 0x...>`). Python's
/// differ from run to run anyway.
pub fn addr<T: ?Sized>(p: *const T) -> String {
    format!("0x{:x}", p as *const u8 as usize)
}

/// `isinstance(v, tuple)` for a tuple subclass: its items.
pub fn as_tuple(v: &Value) -> Option<Vec<Value>> {
    match v {
        Value::Tuple(t) => Some(t.to_vec()),
        _ => v.downcast::<GroupTuple>().map(|g| g.items.to_vec()),
    }
}

/// `hasattr(type(obj), "__getitem__")`.
pub fn is_subscriptable(o: &dyn Object) -> bool {
    o.getitem(&Value::None).is_some()
}

// --- range ---------------------------------------------------------------------

/// `range`.
#[derive(Debug)]
pub struct Range {
    /// `start`.
    pub start: BigInt,
    /// `stop` as given.
    pub stop: BigInt,
    /// `step`.
    pub step: BigInt,
}

impl Range {
    /// `len(range)` without a size limit.
    pub fn length(&self) -> BigInt {
        let (lo, hi, step) = if self.step.is_positive() {
            (&self.start, &self.stop, self.step.clone())
        } else {
            (&self.stop, &self.start, -self.step.clone())
        };
        if lo >= hi {
            return BigInt::zero();
        }
        let diff: BigInt = hi - lo - BigInt::one();
        diff.div_floor(&step) + BigInt::one()
    }

    fn item(&self, i: &BigInt) -> BigInt {
        &self.start + i * &self.step
    }

    fn len_usize(&self) -> Result<usize> {
        self.length()
            .to_usize()
            .ok_or_else(|| Error::overflow("Python int too large to convert to C ssize_t"))
    }
}

impl Object for Range {
    fn type_name(&self) -> &str {
        "range"
    }

    fn repr(&self) -> Result<String> {
        if self.step.is_one() {
            Ok(format!(
                "range({}, {})",
                pyrepr::int_str(&self.start)?,
                pyrepr::int_str(&self.stop)?
            ))
        } else {
            Ok(format!(
                "range({}, {}, {})",
                pyrepr::int_str(&self.start)?,
                pyrepr::int_str(&self.stop)?,
                pyrepr::int_str(&self.step)?
            ))
        }
    }

    fn len(&self) -> Option<Result<usize>> {
        Some(self.len_usize())
    }

    fn iter(&self, _me: &Value) -> Option<Result<PyIter>> {
        Some(self.len_usize().and_then(|n| {
            ops::check_size(n)?;
            let mut items = VecDeque::with_capacity(n);
            let mut v = self.start.clone();
            for _ in 0..n {
                items.push_back(Value::Int(v.clone()));
                v += &self.step;
            }
            Ok(PyIter::Seq(items))
        }))
    }

    fn attrs(&self) -> &'static [&'static str] {
        tables::ATTRS_RANGE
    }

    fn getattr(&self, me: &Value, name: &str) -> Option<Result<Value>> {
        Some(Ok(match name {
            "start" => Value::Int(self.start.clone()),
            "stop" => Value::Int(self.stop.clone()),
            "step" => Value::Int(self.step.clone()),
            "count" | "index" => Method::value(me, name),
            _ => return None,
        }))
    }

    fn getitem(&self, key: &Value) -> Option<Result<Value>> {
        Some((|| {
            let len = self.length();
            if let Some(i) = ops::as_int(key) {
                let i = if i.is_negative() { i + &len } else { i };
                if i.is_negative() || i >= len {
                    return Err(Error::index("range object index out of range"));
                }
                return Ok(Value::Int(self.item(&i)));
            }
            if let Some(sl) = key.downcast::<SliceObj>() {
                let n = len
                    .to_isize()
                    .ok_or_else(|| Error::overflow("range too large"))?;
                let (a, b, s) = ops::slice_indices(&sl.start, &sl.stop, &sl.step, n)?;
                let step = &self.step * BigInt::from(s);
                let start = self.item(&BigInt::from(a));
                let stop = self.item(&BigInt::from(b));
                return Ok(Value::object(Range { start, stop, step }));
            }
            Err(Error::type_error(format!(
                "range indices must be integers or slices, not {}",
                key.type_name()
            )))
        })())
    }

    fn eq(&self, other: &Value) -> Option<bool> {
        let o = other.downcast::<Range>()?;
        let (n, m) = (self.length(), o.length());
        Some(if n != m {
            false
        } else if n.is_zero() {
            true
        } else if self.start != o.start {
            false
        } else {
            n.is_one() || self.step == o.step
        })
    }

    fn contains(&self, item: &Value) -> Option<Result<bool>> {
        let i = match item {
            Value::Bool(b) => Some(BigInt::from(u8::from(*b))),
            Value::Int(i) => Some(i.clone()),
            _ => None,
        };
        if let Some(i) = i {
            let in_bounds = if self.step.is_positive() {
                self.start <= i && i < self.stop
            } else {
                self.stop < i && i <= self.start
            };
            return Some(Ok(
                in_bounds && (&i - &self.start).mod_floor(&self.step).is_zero()
            ));
        }
        None
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A `slice` object (only built for subscripts).
#[derive(Debug)]
pub struct SliceObj {
    /// `start`.
    pub start: Value,
    /// `stop`.
    pub stop: Value,
    /// `step`.
    pub step: Value,
}

impl Object for SliceObj {
    fn type_name(&self) -> &str {
        "slice"
    }

    fn repr(&self) -> Result<String> {
        Ok(format!(
            "slice({}, {}, {})",
            pyrepr::repr(&self.start)?,
            pyrepr::repr(&self.stop)?,
            pyrepr::repr(&self.step)?
        ))
    }

    fn hashable(&self) -> bool {
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// --- jinja2.utils ----------------------------------------------------------------

/// `jinja2.utils.Namespace`.
#[derive(Debug)]
pub struct Namespace {
    /// The attributes (a `dict` value).
    pub attrs: Value,
}

impl Namespace {
    /// `ns[name] = value`.
    pub fn set(&self, name: &str, value: Value) -> Result<()> {
        match &self.attrs {
            Value::Dict(d) => d.borrow_mut().set(Value::str(name), value),
            _ => Ok(()),
        }
    }
}

impl Object for Namespace {
    fn type_name(&self) -> &str {
        "Namespace"
    }

    fn module(&self) -> &str {
        "jinja2.utils"
    }

    fn repr(&self) -> Result<String> {
        Ok(format!("<Namespace {}>", pyrepr::repr(&self.attrs)?))
    }

    fn attrs(&self) -> &'static [&'static str] {
        tables::ATTRS_NAMESPACE
    }

    fn getattr(&self, _me: &Value, name: &str) -> Option<Result<Value>> {
        let Value::Dict(d) = &self.attrs else {
            return None;
        };
        match d.borrow().get(&Value::str(name)) {
            Ok(Some(v)) => Some(Ok(v)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }

    fn clear(&self) {
        if let Value::Dict(d) = &self.attrs {
            if let Ok(mut d) = d.try_borrow_mut() {
                d.entries.clear();
            }
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `jinja2.utils.Cycler`.
#[derive(Debug)]
pub struct Cycler {
    items: Vec<Value>,
    pos: Cell<usize>,
}

impl Cycler {
    fn current(&self) -> Value {
        self.items[self.pos.get() % self.items.len()].clone()
    }
}

impl Object for Cycler {
    fn type_name(&self) -> &str {
        "Cycler"
    }

    fn module(&self) -> &str {
        "jinja2.utils"
    }

    fn repr(&self) -> Result<String> {
        Ok(format!("<jinja2.utils.Cycler object at {}>", addr(self)))
    }

    fn attrs(&self) -> &'static [&'static str] {
        tables::ATTRS_CYCLER
    }

    fn getattr(&self, me: &Value, name: &str) -> Option<Result<Value>> {
        Some(Ok(match name {
            "items" => Value::tuple(self.items.clone()),
            "pos" => Value::int(self.pos.get() as i64),
            "current" => self.current(),
            "next" | "reset" => Method::value(me, name),
            _ => return None,
        }))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `cycler.next()` / `cycler.reset()`.
pub fn cycler_method(
    c: &Cycler,
    name: &str,
    args: &[Value],
    kwargs: &[(Rc<str>, Value)],
) -> Result<Value> {
    let qual = format!("Cycler.{name}");
    crate::callargs::bind(&qual, &["self"], &[], args.len() + 1, kwargs)?;
    if name == "next" {
        let rv = c.current();
        c.pos.set((c.pos.get() + 1) % c.items.len());
        Ok(rv)
    } else {
        c.pos.set(0);
        Ok(Value::None)
    }
}

/// `jinja2.utils.Joiner`.
#[derive(Debug)]
pub struct Joiner {
    sep: Value,
    used: Cell<bool>,
}

impl Object for Joiner {
    fn type_name(&self) -> &str {
        "Joiner"
    }

    fn module(&self) -> &str {
        "jinja2.utils"
    }

    fn repr(&self) -> Result<String> {
        Ok(format!("<jinja2.utils.Joiner object at {}>", addr(self)))
    }

    fn attrs(&self) -> &'static [&'static str] {
        tables::ATTRS_JOINER
    }

    fn getattr(&self, _me: &Value, name: &str) -> Option<Result<Value>> {
        Some(Ok(match name {
            "sep" => self.sep.clone(),
            "used" => Value::Bool(self.used.get()),
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
            crate::callargs::bind("Joiner.__call__", &["self"], &[], args.len() + 1, &kwargs)?;
            if !self.used.get() {
                self.used.set(true);
                return Ok(Value::str(""));
            }
            Ok(self.sep.clone())
        })())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// --- generators and iterators -------------------------------------------------------

type GenFn = Box<dyn FnMut() -> Result<Option<Value>>>;

/// A generator object (`select`, `map`, `batch`, … are generator functions).
pub struct Generator {
    name: &'static str,
    state: RefCell<Option<GenFn>>,
    running: Cell<bool>,
}

impl std::fmt::Debug for Generator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<generator object {}>", self.name)
    }
}

impl Generator {
    /// A generator that runs `step` for each item until it returns `None`.
    pub fn value(
        name: &'static str,
        step: impl FnMut() -> Result<Option<Value>> + 'static,
    ) -> Value {
        Value::object(Generator {
            name,
            state: RefCell::new(Some(Box::new(step))),
            running: Cell::new(false),
        })
    }
}

impl Object for Generator {
    fn type_name(&self) -> &str {
        "generator"
    }

    fn repr(&self) -> Result<String> {
        Ok(format!(
            "<generator object {} at {}>",
            self.name,
            addr(self)
        ))
    }

    fn iter(&self, me: &Value) -> Option<Result<PyIter>> {
        Some(Ok(PyIter::Obj(me.clone())))
    }

    fn next(&self) -> Option<Result<Option<Value>>> {
        if self.running.get() {
            return Some(Err(Error::value_error("generator already executing")));
        }
        let Some(mut step) = self.state.borrow_mut().take() else {
            return Some(Ok(None));
        };
        self.running.set(true);
        let r = step();
        self.running.set(false);
        if let Ok(Some(_)) = r {
            *self.state.borrow_mut() = Some(step);
        }
        Some(r)
    }

    fn attrs(&self) -> &'static [&'static str] {
        tables::ATTRS_GENERATOR
    }

    fn getattr(&self, me: &Value, name: &str) -> Option<Result<Value>> {
        Some(Ok(match name {
            "gi_running" => Value::Bool(self.running.get()),
            "gi_suspended" => Value::Bool(false),
            "gi_yieldfrom" => Value::None,
            "close" | "send" | "throw" => Method::value(me, name),
            _ => return None,
        }))
    }

    fn clear(&self) {
        if let Ok(mut s) = self.state.try_borrow_mut() {
            *s = None;
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `generator.close()`.
pub fn generator_close(g: &Generator) {
    if let Ok(mut s) = g.state.try_borrow_mut() {
        *s = None;
    }
}

/// `reversed(...)`: a one-pass iterator over a snapshot.
#[derive(Debug)]
pub struct RevIter {
    name: &'static str,
    items: RefCell<VecDeque<Value>>,
}

impl RevIter {
    /// A reverse iterator of the given Python type.
    pub fn value(name: &'static str, items: Vec<Value>) -> Value {
        Value::object(RevIter {
            name,
            items: RefCell::new(items.into_iter().rev().collect()),
        })
    }
}

impl Object for RevIter {
    fn type_name(&self) -> &str {
        self.name
    }

    fn repr(&self) -> Result<String> {
        Ok(format!("<{} object at {}>", self.name, addr(self)))
    }

    fn iter(&self, me: &Value) -> Option<Result<PyIter>> {
        Some(Ok(PyIter::Obj(me.clone())))
    }

    fn next(&self) -> Option<Result<Option<Value>>> {
        Some(Ok(self.items.borrow_mut().pop_front()))
    }

    fn attrs(&self) -> &'static [&'static str] {
        tables::ATTRS_LIST_REVERSEITERATOR
    }

    fn clear(&self) {
        if let Ok(mut i) = self.items.try_borrow_mut() {
            i.clear();
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Which dict view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewKind {
    /// `dict_keys`
    Keys,
    /// `dict_values`
    Values,
    /// `dict_items`
    Items,
}

/// A live dict view.
#[derive(Debug)]
pub struct DictView {
    /// Which view.
    pub kind: ViewKind,
    /// The dict.
    pub dict: Rc<RefCell<Dict>>,
}

impl DictView {
    fn items(&self) -> Vec<Value> {
        let d = self.dict.borrow();
        match self.kind {
            ViewKind::Keys => d.keys(),
            ViewKind::Values => d.entries.iter().map(|(_, v)| v.clone()).collect(),
            ViewKind::Items => d
                .entries
                .iter()
                .map(|(k, v)| Value::tuple(vec![k.clone(), v.clone()]))
                .collect(),
        }
    }
}

impl Object for DictView {
    fn type_name(&self) -> &str {
        match self.kind {
            ViewKind::Keys => "dict_keys",
            ViewKind::Values => "dict_values",
            ViewKind::Items => "dict_items",
        }
    }

    fn repr(&self) -> Result<String> {
        Ok(format!(
            "{}([{}])",
            self.type_name(),
            pyrepr::join_reprs(&self.items())?
        ))
    }

    fn len(&self) -> Option<Result<usize>> {
        Some(Ok(self.dict.borrow().entries.len()))
    }

    fn iter(&self, _me: &Value) -> Option<Result<PyIter>> {
        Some(Ok(PyIter::Seq(self.items().into())))
    }

    fn attrs(&self) -> &'static [&'static str] {
        match self.kind {
            ViewKind::Keys => tables::ATTRS_DICT_KEYS,
            ViewKind::Values => tables::ATTRS_DICT_VALUES,
            ViewKind::Items => tables::ATTRS_DICT_ITEMS,
        }
    }

    fn getattr(&self, me: &Value, name: &str) -> Option<Result<Value>> {
        match name {
            "isdisjoint" if self.kind != ViewKind::Values => Some(Ok(Method::value(me, name))),
            "mapping" => Some(Err(Error::unsupported("A dict view's mapping"))),
            _ => None,
        }
    }

    fn eq(&self, other: &Value) -> Option<bool> {
        if self.kind == ViewKind::Values {
            return None;
        }
        let o = other.downcast::<DictView>()?;
        if o.kind != self.kind {
            return Some(false);
        }
        let (a, b) = (self.items(), o.items());
        if a.len() != b.len() {
            return Some(false);
        }
        Some(
            a.iter()
                .all(|x| b.iter().any(|y| ops::eq(x, y).unwrap_or(false))),
        )
    }

    fn contains(&self, item: &Value) -> Option<Result<bool>> {
        match self.kind {
            ViewKind::Keys => Some(self.dict.borrow().position(item).map(|p| p.is_some())),
            ViewKind::Items => Some((|| {
                let Some(pair) = as_tuple(item).filter(|t| t.len() == 2) else {
                    return Ok(false);
                };
                match self.dict.borrow().get(&pair[0])? {
                    Some(v) => ops::eq(&v, &pair[1]),
                    None => Ok(false),
                }
            })()),
            ViewKind::Values => None,
        }
    }

    fn hashable(&self) -> bool {
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `jinja2.filters._GroupTuple`, a `(grouper, list)` named tuple.
#[derive(Debug)]
pub struct GroupTuple {
    /// `(grouper, list)`.
    pub items: Rc<[Value]>,
}

impl Object for GroupTuple {
    fn type_name(&self) -> &str {
        "_GroupTuple"
    }

    fn module(&self) -> &str {
        "jinja2.filters"
    }

    fn repr(&self) -> Result<String> {
        pyrepr::repr(&Value::Tuple(self.items.clone()))
    }

    fn len(&self) -> Option<Result<usize>> {
        Some(Ok(self.items.len()))
    }

    fn iter(&self, _me: &Value) -> Option<Result<PyIter>> {
        Some(Ok(PyIter::Seq(self.items.iter().cloned().collect())))
    }

    fn attrs(&self) -> &'static [&'static str] {
        tables::ATTRS_GROUP_TUPLE
    }

    fn getattr(&self, me: &Value, name: &str) -> Option<Result<Value>> {
        Some(Ok(match name {
            "grouper" => self.items[0].clone(),
            "list" => self.items[1].clone(),
            "count" | "index" => Method::value(me, name),
            _ => return None,
        }))
    }

    fn getitem(&self, key: &Value) -> Option<Result<Value>> {
        Some(crate::attrs::subscript(
            &Value::Tuple(self.items.clone()),
            key,
        ))
    }

    fn eq(&self, other: &Value) -> Option<bool> {
        let o = as_tuple(other)?;
        Some(
            o.len() == self.items.len()
                && self
                    .items
                    .iter()
                    .zip(&o)
                    .all(|(a, b)| ops::eq(a, b).unwrap_or(false)),
        )
    }

    fn hashable(&self) -> bool {
        ops::check_hashable(&Value::Tuple(self.items.clone())).is_ok()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `bytes`.
#[derive(Debug)]
pub struct Bytes {
    /// The bytes.
    pub data: Vec<u8>,
}

impl Object for Bytes {
    fn type_name(&self) -> &str {
        "bytes"
    }

    fn repr(&self) -> Result<String> {
        let quote = if self.data.contains(&b'\'') && !self.data.contains(&b'"') {
            '"'
        } else {
            '\''
        };
        let mut out = String::from("b");
        out.push(quote);
        for &b in &self.data {
            match b {
                b'\\' => out.push_str("\\\\"),
                b'\t' => out.push_str("\\t"),
                b'\n' => out.push_str("\\n"),
                b'\r' => out.push_str("\\r"),
                b if b as char == quote => {
                    out.push('\\');
                    out.push(quote);
                }
                0x20..=0x7e => out.push(b as char),
                b => out.push_str(&format!("\\x{b:02x}")),
            }
        }
        out.push(quote);
        Ok(out)
    }

    fn len(&self) -> Option<Result<usize>> {
        Some(Ok(self.data.len()))
    }

    fn iter(&self, _me: &Value) -> Option<Result<PyIter>> {
        Some(Ok(PyIter::Seq(
            self.data
                .iter()
                .map(|b| Value::int(i64::from(*b)))
                .collect(),
        )))
    }

    fn attrs(&self) -> &'static [&'static str] {
        tables::ATTRS_BYTES
    }

    fn getattr(&self, me: &Value, name: &str) -> Option<Result<Value>> {
        match name {
            "decode" => Some(Ok(Method::value(me, name))),
            _ => Some(Err(Error::unsupported(format!("bytes.{name}")))),
        }
    }

    fn getitem(&self, key: &Value) -> Option<Result<Value>> {
        Some((|| {
            let Some(i) = ops::as_int(key) else {
                return Err(Error::type_error(format!(
                    "byte indices must be integers or slices, not {}",
                    key.type_name()
                )));
            };
            let n = BigInt::from(self.data.len());
            let i = if i.is_negative() { i + &n } else { i };
            match i.to_usize().and_then(|i| self.data.get(i)) {
                Some(b) => Ok(Value::int(i64::from(*b))),
                None => Err(Error::index("index out of range")),
            }
        })())
    }

    fn eq(&self, other: &Value) -> Option<bool> {
        other.downcast::<Bytes>().map(|o| o.data == self.data)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// --- callables ---------------------------------------------------------------------------

/// A bound method: `obj.name`.
#[derive(Debug)]
pub struct Method {
    /// The object.
    pub recv: Value,
    /// The method name.
    pub name: Rc<str>,
}

impl Method {
    /// A bound method value.
    pub fn value(recv: &Value, name: &str) -> Value {
        Value::object(Method {
            recv: recv.clone(),
            name: Rc::from(name),
        })
    }

    /// The sandbox's `wrap_str_format`: a function standing in for a
    /// string's `format` / `format_map`.
    fn wrapped_format(&self) -> Option<String> {
        if !matches!(&*self.name, "format" | "format_map") || !self.recv.is_str() {
            return None;
        }
        let class = if self.recv.is_markup() {
            "Markup"
        } else {
            "str"
        };
        Some(format!("{class}.{}", self.name))
    }

    fn is_builtin(&self) -> bool {
        match &self.recv {
            Value::Markup(_) => !crate::methods::MARKUP_PYTHON_METHODS.contains(&&*self.name),
            Value::Object(o) => !matches!(
                o.type_name(),
                "Cycler" | "NotificationEvent" | "LoopContext"
            ),
            _ => true,
        }
    }
}

impl Object for Method {
    fn type_name(&self) -> &str {
        if self.wrapped_format().is_some() {
            "function"
        } else if self.is_builtin() {
            "builtin_function_or_method"
        } else {
            "method"
        }
    }

    fn repr(&self) -> Result<String> {
        if let Some(qualname) = self.wrapped_format() {
            return Ok(format!("<function {qualname} at {}>", addr(self)));
        }
        if self.is_builtin() {
            return Ok(format!(
                "<built-in method {} of {} object at {}>",
                self.name,
                self.recv.type_name(),
                addr(self)
            ));
        }
        let class = match &self.recv {
            Value::Object(o) if o.type_name() == "NotificationEvent" => "BaseModel".to_string(),
            other => other.type_name(),
        };
        Ok(format!(
            "<bound method {class}.{} of {}>",
            self.name,
            pyrepr::repr(&self.recv)?
        ))
    }

    fn attrs(&self) -> &'static [&'static str] {
        if self.wrapped_format().is_some() {
            tables::ATTRS_FUNCTION
        } else if self.is_builtin() {
            tables::ATTRS_BUILTIN_METHOD
        } else {
            tables::ATTRS_METHOD
        }
    }

    fn call(
        &self,
        _me: &Value,
        args: Vec<Value>,
        kwargs: Vec<(Rc<str>, Value)>,
    ) -> Option<Result<Value>> {
        Some(crate::methods::call_method(
            &self.recv, &self.name, args, kwargs,
        ))
    }

    fn eq(&self, other: &Value) -> Option<bool> {
        let o = other.downcast::<Method>()?;
        Some(o.name == self.name && ops::same_object(&o.recv, &self.recv))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// The global functions and classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinKind {
    /// `range` (the sandbox's `safe_range`).
    Range,
    /// `dict`.
    Dict,
    /// `lipsum`.
    Lipsum,
    /// `cycler`.
    Cycler,
    /// `joiner`.
    Joiner,
    /// `namespace`.
    Namespace,
    /// `str`, a `defaultdict(str)`'s factory.
    Str,
}

/// A global function or class.
#[derive(Debug)]
pub struct Builtin {
    /// Which.
    pub kind: BuiltinKind,
}

impl Builtin {
    /// The value.
    pub fn value(kind: BuiltinKind) -> Value {
        Value::object(Builtin { kind })
    }

    fn is_class(&self) -> bool {
        !matches!(self.kind, BuiltinKind::Range | BuiltinKind::Lipsum)
    }
}

impl Object for Builtin {
    fn type_name(&self) -> &str {
        if self.is_class() { "type" } else { "function" }
    }

    fn repr(&self) -> Result<String> {
        Ok(match self.kind {
            BuiltinKind::Range => format!("<function safe_range at {}>", addr(self)),
            BuiltinKind::Lipsum => format!("<function generate_lorem_ipsum at {}>", addr(self)),
            BuiltinKind::Dict => "<class 'dict'>".into(),
            BuiltinKind::Str => "<class 'str'>".into(),
            BuiltinKind::Cycler => "<class 'jinja2.utils.Cycler'>".into(),
            BuiltinKind::Joiner => "<class 'jinja2.utils.Joiner'>".into(),
            BuiltinKind::Namespace => "<class 'jinja2.utils.Namespace'>".into(),
        })
    }

    fn attrs(&self) -> &'static [&'static str] {
        if self.is_class() {
            tables::ATTRS_TYPE
        } else {
            tables::ATTRS_FUNCTION
        }
    }

    fn getattr(&self, _me: &Value, name: &str) -> Option<Result<Value>> {
        let _ = name;
        Some(Err(Error::unsupported(format!(
            "An attribute of {}",
            self.repr().unwrap_or_default()
        ))))
    }

    fn call(
        &self,
        _me: &Value,
        args: Vec<Value>,
        kwargs: Vec<(Rc<str>, Value)>,
    ) -> Option<Result<Value>> {
        Some(match self.kind {
            BuiltinKind::Range => safe_range(args, kwargs),
            BuiltinKind::Dict => crate::builtins::py_dict(args, kwargs),
            BuiltinKind::Lipsum => crate::builtins::lipsum(args, kwargs),
            BuiltinKind::Str => crate::builtins::str_call(args, kwargs),
            BuiltinKind::Cycler => {
                if let Some((k, _)) = kwargs.first() {
                    Err(Error::type_error(format!(
                        "Cycler.__init__() got an unexpected keyword argument '{k}'"
                    )))
                } else if args.is_empty() {
                    Err(Error::new(
                        "RuntimeError",
                        "at least one item has to be provided",
                    ))
                } else {
                    Ok(Value::object(Cycler {
                        items: args,
                        pos: Cell::new(0),
                    }))
                }
            }
            BuiltinKind::Joiner => (|| {
                let bound = crate::callargs::bind_values(
                    "Joiner.__init__",
                    &["self", "sep"],
                    &[Value::str(", ")],
                    std::iter::once(Value::None).chain(args).collect(),
                    kwargs,
                )?;
                Ok(Value::object(Joiner {
                    sep: bound[1].clone(),
                    used: Cell::new(false),
                }))
            })(),
            BuiltinKind::Namespace => (|| {
                let d = crate::builtins::py_dict(args, kwargs)?;
                Ok(Value::object(Namespace { attrs: d }))
            })(),
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// The sandbox's `safe_range`.
pub fn safe_range(args: Vec<Value>, kwargs: Vec<(Rc<str>, Value)>) -> Result<Value> {
    if let Some((k, _)) = kwargs.first() {
        return Err(Error::type_error(format!(
            "safe_range() got an unexpected keyword argument '{k}'"
        )));
    }
    match args.len() {
        0 => {
            return Err(Error::type_error(
                "range expected at least 1 argument, got 0",
            ));
        }
        n if n > 3 => {
            return Err(Error::type_error(format!(
                "range expected at most 3 arguments, got {n}"
            )));
        }
        _ => {}
    }
    let mut ints = Vec::new();
    for a in &args {
        match ops::as_int(a) {
            Some(i) => ints.push(i),
            None => {
                if let Value::Undefined(u) = a {
                    return Err(u.error());
                }
                return Err(Error::type_error(format!(
                    "'{}' object cannot be interpreted as an integer",
                    a.type_name()
                )));
            }
        }
    }
    let (start, stop, step) = match ints.len() {
        1 => (BigInt::zero(), ints[0].clone(), BigInt::one()),
        2 => (ints[0].clone(), ints[1].clone(), BigInt::one()),
        _ => (ints[0].clone(), ints[1].clone(), ints[2].clone()),
    };
    if step.is_zero() {
        return Err(Error::value_error("range() arg 3 must not be zero"));
    }
    let r = Range { start, stop, step };
    let len = r.length();
    if len.to_isize().is_none() {
        return Err(Error::overflow(
            "Python int too large to convert to C ssize_t",
        ));
    }
    if len > BigInt::from(crate::MAX_RANGE) {
        return Err(Error::overflow(format!(
            "Range too big. The sandbox blocks ranges larger than MAX_RANGE ({}).",
            crate::MAX_RANGE
        )));
    }
    Ok(Value::object(r))
}
