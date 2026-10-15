//! A read-only pickle decoder for APScheduler's job store.
//!
//! `SQLAlchemyJobStore` keeps each job as `pickle.dumps(job.__getstate__(),
//! HIGHEST_PROTOCOL)`: a dict of plain values (`id`, `name`, `func`, …) with
//! a few objects inside (the trigger, timezones, `datetime`s). This decoder
//! runs the pickle machine over the opcodes such a dump uses and builds a
//! [`Value`] tree. Nothing is *executed*: a global is only a name
//! ([`Value::Global`]) and calling it (`REDUCE`, `NEWOBJ`, `BUILD`) only
//! records the call ([`Value::Call`]), which the caller interprets for the
//! few types it knows (`datetime`, `zoneinfo`, `timezone`, pytz). Anything
//! outside that opcode set is an error — the routes then let the Python
//! backend answer instead of guessing.
//!
//! Containers are values, not shared references: a structure that refers to
//! itself decodes as a snapshot. Job states never do.

use std::fmt;

/// A decoded pickle value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `None`.
    None,
    /// `True` / `False`.
    Bool(bool),
    /// An `int` that fits in 128 bits.
    Int(i128),
    /// A `float`.
    Float(f64),
    /// A `str`.
    Str(String),
    /// `bytes` / `bytearray`.
    Bytes(Vec<u8>),
    /// A `tuple`.
    Tuple(Vec<Value>),
    /// A `list`.
    List(Vec<Value>),
    /// A `dict`, in insertion order.
    Dict(Vec<(Value, Value)>),
    /// A `set` / `frozenset`.
    Set(Vec<Value>),
    /// A global (`module`, `qualname`), never imported.
    Global {
        /// Module.
        module: String,
        /// Qualified name.
        name: String,
    },
    /// `func(*args)` (`REDUCE`; `NEWOBJ` records `cls.__new__(cls, *args)`
    /// the same way), plus the `BUILD` state applied to the result.
    Call {
        /// The callable.
        func: Box<Value>,
        /// The positional arguments (a tuple).
        args: Box<Value>,
        /// The `__setstate__` argument, if any.
        state: Option<Box<Value>>,
    },
}

impl Value {
    /// The value under string key `key` of a dict.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Dict(items) => items
                .iter()
                .find(|(k, _)| matches!(k, Value::Str(s) if s == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The items of a tuple or list.
    pub fn items(&self) -> Option<&[Value]> {
        match self {
            Value::Tuple(v) | Value::List(v) => Some(v),
            _ => None,
        }
    }

    /// Whether this is the global `module.name`.
    pub fn is_global(&self, module: &str, name: &str) -> bool {
        matches!(self, Value::Global { module: m, name: n } if m == module && n == name)
    }
}

/// Why a pickle could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickleError(pub String);

impl fmt::Display for PickleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unpickling: {}", self.0)
    }
}

impl std::error::Error for PickleError {}

fn err<T>(msg: impl Into<String>) -> Result<T, PickleError> {
    Err(PickleError(msg.into()))
}

/// A stack item: a value or a `MARK`.
#[derive(Debug, Clone)]
enum Item {
    Mark,
    Value(Value),
}

struct Machine<'a> {
    data: &'a [u8],
    pos: usize,
    stack: Vec<Item>,
    memo: Vec<Option<Value>>,
}

/// Longest container or string accepted (a job state is a few hundred bytes).
const MAX_LEN: usize = 16 << 20;

impl<'a> Machine<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PickleError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.data.len())
            .ok_or_else(|| PickleError("truncated pickle".into()))?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, PickleError> {
        Ok(self.take(1)?[0])
    }

    fn le_u16(&mut self) -> Result<u16, PickleError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn le_u32(&mut self) -> Result<u32, PickleError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn le_u64(&mut self) -> Result<u64, PickleError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    fn len(&mut self, n: u64) -> Result<usize, PickleError> {
        usize::try_from(n)
            .ok()
            .filter(|n| *n <= MAX_LEN)
            .ok_or_else(|| PickleError("length out of range".into()))
    }

    fn line(&mut self) -> Result<&'a str, PickleError> {
        let rest = &self.data[self.pos..];
        let Some(nl) = rest.iter().position(|b| *b == b'\n') else {
            return err("unterminated text argument");
        };
        let line = &rest[..nl];
        self.pos += nl + 1;
        std::str::from_utf8(line).map_err(|_| PickleError("non-UTF-8 text argument".into()))
    }

    fn push(&mut self, v: Value) {
        self.stack.push(Item::Value(v));
    }

    fn pop(&mut self) -> Result<Value, PickleError> {
        match self.stack.pop() {
            Some(Item::Value(v)) => Ok(v),
            Some(Item::Mark) => err("unexpected MARK"),
            None => err("stack underflow"),
        }
    }

    fn top(&mut self) -> Result<&mut Value, PickleError> {
        match self.stack.last_mut() {
            Some(Item::Value(v)) => Ok(v),
            _ => err("no value on the stack"),
        }
    }

    /// Everything above the topmost MARK (which is removed).
    fn pop_mark(&mut self) -> Result<Vec<Value>, PickleError> {
        let Some(at) = self.stack.iter().rposition(|i| matches!(i, Item::Mark)) else {
            return err("MARK not found");
        };
        let items = self.stack.split_off(at + 1);
        self.stack.pop();
        items
            .into_iter()
            .map(|i| match i {
                Item::Value(v) => Ok(v),
                Item::Mark => err("nested MARK"),
            })
            .collect()
    }

    fn memo_put(&mut self, idx: usize) -> Result<(), PickleError> {
        let v = match self.stack.last() {
            Some(Item::Value(v)) => v.clone(),
            _ => return err("nothing to memoize"),
        };
        if idx > MAX_LEN {
            return err("memo index out of range");
        }
        if self.memo.len() <= idx {
            self.memo.resize(idx + 1, None);
        }
        self.memo[idx] = Some(v);
        Ok(())
    }

    fn memo_get(&mut self, idx: usize) -> Result<(), PickleError> {
        match self.memo.get(idx).cloned().flatten() {
            Some(v) => {
                self.push(v);
                Ok(())
            }
            None => err(format!("memo {idx} is empty")),
        }
    }

    fn set_items(target: &mut Value, pairs: Vec<Value>) -> Result<(), PickleError> {
        let Value::Dict(items) = target else {
            return err("SETITEMS on a non-dict");
        };
        if pairs.len() % 2 != 0 {
            return err("odd SETITEMS");
        }
        let mut it = pairs.into_iter();
        while let (Some(k), Some(v)) = (it.next(), it.next()) {
            match items.iter_mut().find(|(key, _)| *key == k) {
                Some(slot) => slot.1 = v,
                None => items.push((k, v)),
            }
        }
        Ok(())
    }

    fn run(mut self) -> Result<Value, PickleError> {
        loop {
            let op = self.u8()?;
            match op {
                // PROTO
                0x80 => {
                    let proto = self.u8()?;
                    if proto > 5 {
                        return err(format!("unsupported protocol {proto}"));
                    }
                }
                // FRAME
                0x95 => {
                    self.le_u64()?;
                }
                // STOP
                b'.' => return self.pop(),
                b'(' => self.stack.push(Item::Mark),
                b'0' => {
                    self.stack.pop();
                }
                b'1' => {
                    self.pop_mark()?;
                }
                b'2' => {
                    let v = self.top()?.clone();
                    self.push(v);
                }
                b'N' => self.push(Value::None),
                0x88 => self.push(Value::Bool(true)),
                0x89 => self.push(Value::Bool(false)),
                // BININT, BININT1, BININT2
                b'J' => {
                    let v = self.le_u32()?;
                    self.push(Value::Int(i128::from(i32::from_le_bytes(v.to_le_bytes()))));
                }
                b'K' => {
                    let v = self.u8()?;
                    self.push(Value::Int(i128::from(v)));
                }
                b'M' => {
                    let v = self.le_u16()?;
                    self.push(Value::Int(i128::from(v)));
                }
                // LONG1, LONG4: little-endian two's complement
                0x8a | 0x8b => {
                    let n = if op == 0x8a {
                        u64::from(self.u8()?)
                    } else {
                        u64::from(self.le_u32()?)
                    };
                    let n = self.len(n)?;
                    if n > 16 {
                        return err("integer too large");
                    }
                    let bytes = self.take(n)?;
                    let mut v: i128 = 0;
                    for (i, b) in bytes.iter().enumerate() {
                        v |= i128::from(*b) << (8 * i);
                    }
                    if n > 0 && n < 16 && bytes[n - 1] & 0x80 != 0 {
                        v -= 1i128 << (8 * n);
                    }
                    self.push(Value::Int(v));
                }
                // BINFLOAT (big-endian)
                b'G' => {
                    let b = self.take(8)?;
                    let mut a = [0u8; 8];
                    a.copy_from_slice(b);
                    self.push(Value::Float(f64::from_be_bytes(a)));
                }
                // SHORT_BINUNICODE, BINUNICODE, BINUNICODE8
                0x8c | b'X' | 0x8d => {
                    let n = match op {
                        0x8c => u64::from(self.u8()?),
                        b'X' => u64::from(self.le_u32()?),
                        _ => self.le_u64()?,
                    };
                    let n = self.len(n)?;
                    let s = std::str::from_utf8(self.take(n)?)
                        .map_err(|_| PickleError("invalid UTF-8 string".into()))?;
                    self.push(Value::Str(s.to_string()));
                }
                // SHORT_BINBYTES, BINBYTES, BINBYTES8, BYTEARRAY8
                b'C' | b'B' | 0x8e | 0x96 => {
                    let n = match op {
                        b'C' => u64::from(self.u8()?),
                        b'B' => u64::from(self.le_u32()?),
                        _ => self.le_u64()?,
                    };
                    let n = self.len(n)?;
                    let b = self.take(n)?.to_vec();
                    self.push(Value::Bytes(b));
                }
                b')' => self.push(Value::Tuple(Vec::new())),
                b't' => {
                    let items = self.pop_mark()?;
                    self.push(Value::Tuple(items));
                }
                0x85..=0x87 => {
                    let n = usize::from(op - 0x84);
                    if self.stack.len() < n {
                        return err("stack underflow");
                    }
                    let mut items = Vec::with_capacity(n);
                    for _ in 0..n {
                        items.push(self.pop()?);
                    }
                    items.reverse();
                    self.push(Value::Tuple(items));
                }
                b']' => self.push(Value::List(Vec::new())),
                b'l' => {
                    let items = self.pop_mark()?;
                    self.push(Value::List(items));
                }
                b'a' => {
                    let v = self.pop()?;
                    match self.top()? {
                        Value::List(items) => items.push(v),
                        _ => return err("APPEND on a non-list"),
                    }
                }
                b'e' => {
                    let vs = self.pop_mark()?;
                    match self.top()? {
                        Value::List(items) => items.extend(vs),
                        _ => return err("APPENDS on a non-list"),
                    }
                }
                b'}' => self.push(Value::Dict(Vec::new())),
                b'd' => {
                    let pairs = self.pop_mark()?;
                    let mut d = Value::Dict(Vec::new());
                    Self::set_items(&mut d, pairs)?;
                    self.push(d);
                }
                b's' => {
                    let v = self.pop()?;
                    let k = self.pop()?;
                    Self::set_items(self.top()?, vec![k, v])?;
                }
                b'u' => {
                    let pairs = self.pop_mark()?;
                    Self::set_items(self.top()?, pairs)?;
                }
                0x8f => self.push(Value::Set(Vec::new())),
                0x90 => {
                    let vs = self.pop_mark()?;
                    match self.top()? {
                        Value::Set(items) => items.extend(vs),
                        _ => return err("ADDITEMS on a non-set"),
                    }
                }
                0x91 => {
                    let items = self.pop_mark()?;
                    self.push(Value::Set(items));
                }
                // MEMOIZE, BINPUT, LONG_BINPUT, PUT
                0x94 => {
                    let idx = self.memo.len();
                    self.memo_put(idx)?;
                }
                b'q' => {
                    let idx = usize::from(self.u8()?);
                    self.memo_put(idx)?;
                }
                b'r' => {
                    let idx = self.le_u32()?;
                    let idx = self.len(u64::from(idx))?;
                    self.memo_put(idx)?;
                }
                b'p' => {
                    let idx: usize = self
                        .line()?
                        .trim()
                        .parse()
                        .map_err(|_| PickleError("bad PUT index".into()))?;
                    self.memo_put(idx)?;
                }
                // BINGET, LONG_BINGET, GET
                b'h' => {
                    let idx = usize::from(self.u8()?);
                    self.memo_get(idx)?;
                }
                b'j' => {
                    let idx = self.le_u32()?;
                    let idx = self.len(u64::from(idx))?;
                    self.memo_get(idx)?;
                }
                b'g' => {
                    let idx: usize = self
                        .line()?
                        .trim()
                        .parse()
                        .map_err(|_| PickleError("bad GET index".into()))?;
                    self.memo_get(idx)?;
                }
                // GLOBAL, STACK_GLOBAL
                b'c' => {
                    let module = self.line()?.to_string();
                    let name = self.line()?.to_string();
                    self.push(Value::Global { module, name });
                }
                0x93 => {
                    let name = self.pop()?;
                    let module = self.pop()?;
                    match (module, name) {
                        (Value::Str(module), Value::Str(name)) => {
                            self.push(Value::Global { module, name })
                        }
                        _ => return err("STACK_GLOBAL needs two strings"),
                    }
                }
                // REDUCE, NEWOBJ
                b'R' | 0x81 => {
                    let args = self.pop()?;
                    let func = self.pop()?;
                    self.push(Value::Call {
                        func: Box::new(func),
                        args: Box::new(args),
                        state: None,
                    });
                }
                // NEWOBJ_EX: cls, args, kwargs (kwargs kept in the state slot)
                0x92 => {
                    let kwargs = self.pop()?;
                    let args = self.pop()?;
                    let cls = self.pop()?;
                    self.push(Value::Call {
                        func: Box::new(cls),
                        args: Box::new(args),
                        state: Some(Box::new(kwargs)),
                    });
                }
                // BUILD
                b'b' => {
                    let state = self.pop()?;
                    match self.top()? {
                        Value::Call { state: slot, .. } => *slot = Some(Box::new(state)),
                        _ => return err("BUILD on a non-object"),
                    }
                }
                other => return err(format!("unsupported opcode 0x{other:02x}")),
            }
        }
    }
}

/// Decode one pickle.
pub fn loads(data: &[u8]) -> Result<Value, PickleError> {
    Machine {
        data,
        pos: 0,
        stack: Vec::new(),
        memo: Vec::new(),
    }
    .run()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn scalars_and_containers() {
        // pickle.dumps({'a': (1, -2, 300, 70000, 2**40, -2**63), 'b': [None, True, 1.5], 'c': b'x', 's': {1}}, 5)
        let data: &[u8] = b"\x80\x05\x95O\x00\x00\x00\x00\x00\x00\x00}\x94(\x8c\x01a\x94(K\x01J\xfe\xff\xff\xffM,\x01J\x70\x11\x01\x00\x8a\x06\x00\x00\x00\x00\x00\x01\x8a\x08\x00\x00\x00\x00\x00\x00\x00\x80t\x94\x8c\x01b\x94]\x94(N\x88G?\xf8\x00\x00\x00\x00\x00\x00e\x8c\x01c\x94C\x01x\x94\x8c\x01s\x94\x8f\x94(K\x01\x90u.";
        let v = loads(data).unwrap();
        assert_eq!(
            v.get("a").unwrap().items().unwrap(),
            &[
                Value::Int(1),
                Value::Int(-2),
                Value::Int(300),
                Value::Int(70000),
                Value::Int(1 << 40),
                Value::Int(-(1i128 << 63)),
            ]
        );
        assert_eq!(
            v.get("b").unwrap(),
            &Value::List(vec![Value::None, Value::Bool(true), Value::Float(1.5)])
        );
        assert_eq!(v.get("c").unwrap(), &Value::Bytes(b"x".to_vec()));
        assert_eq!(v.get("s").unwrap(), &Value::Set(vec![Value::Int(1)]));
    }

    #[test]
    fn refuses_what_it_does_not_know() {
        // PERSID
        assert!(loads(b"\x80\x05P1\n.").is_err());
        assert!(loads(b"\x80\x05}").is_err(), "no STOP");
        assert!(loads(b"\x80\x05h\x00.").is_err(), "empty memo");
        assert!(loads(b"\x80\x06N.").is_err(), "protocol 6");
    }
}
