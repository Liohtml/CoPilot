//! CBOR as `cbor2` 5.9 reads and writes it — py_webauthn's `parse_cbor` /
//! `encode_cbor`.
//!
//! py_webauthn decodes the credential public key out of the authenticator
//! data and *re-encodes* it: the stored key is the re-encoding, and its length
//! (not the input's) moves the pointer to the extensions and the
//! leftover-bytes check. So the decoder keeps what Python keeps and the
//! encoder writes what `cbor2.dumps` writes:
//! - decoding stops after the first item (trailing bytes are ignored);
//! - maps merge keys Python considers equal (`1`, `True` and `1.0` are one
//!   key; the first key stays, the last value wins);
//! - indefinite strings, arrays and maps come back definite; integers come
//!   back in their shortest form; bignums (tags 2/3) become integers;
//!   half/single floats come back as doubles (NaN and ±inf as half floats);
//!   tag 55799 is dropped;
//! - other tags are kept as tags — `cbor2` turns a few semantic ones (dates,
//!   decimals, …) into Python objects, which no authenticator sends.

use num_bigint_dig::BigUint;

use copilot_auth::pyvalue::{bytes_repr, float_repr, str_repr};

/// A decoded CBOR item.
#[derive(Debug, Clone)]
pub enum Cbor {
    /// An integer: `magnitude` (big-endian, no leading zeros) for a
    /// non-negative value, `-1 - magnitude` when `negative`.
    Int {
        /// Major type 1 (or tag 3).
        negative: bool,
        /// The CBOR argument.
        magnitude: Vec<u8>,
    },
    /// A byte string.
    Bytes(Vec<u8>),
    /// A text string.
    Text(String),
    /// An array (a `list`, or a `tuple` as a map key).
    Array(Vec<Cbor>),
    /// A map, in insertion order.
    Map(Vec<(Cbor, Cbor)>),
    /// `True` / `False`.
    Bool(bool),
    /// `None`.
    Null,
    /// `undefined`.
    Undefined,
    /// A simple value other than the four above.
    Simple(u8),
    /// A float.
    Float(f64),
    /// A tag `cbor2` keeps as `CBORTag`.
    Tag(u64, Box<Cbor>),
    /// The break marker, read where no indefinite container expects it.
    Break,
}

/// Decoding or encoding failed (`InvalidCBORData`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Could not decode CBOR data")]
pub struct CborError;

const MAX_DEPTH: usize = 500;

fn strip(mut magnitude: Vec<u8>) -> Vec<u8> {
    let zeros = magnitude.iter().take_while(|b| **b == 0).count();
    magnitude.drain(..zeros);
    magnitude
}

impl Cbor {
    /// A small integer.
    pub fn int(value: i64) -> Cbor {
        if value >= 0 {
            Cbor::Int {
                negative: false,
                magnitude: strip((value as u64).to_be_bytes().to_vec()),
            }
        } else {
            Cbor::Int {
                negative: true,
                magnitude: strip(((-1 - value) as u64).to_be_bytes().to_vec()),
            }
        }
    }

    /// The value as an `i128`, for integers and booleans (Python's `bool` is
    /// an `int`).
    pub fn as_int(&self) -> Option<i128> {
        match self {
            Cbor::Bool(b) => Some(i128::from(*b)),
            Cbor::Int {
                negative,
                magnitude,
            } if magnitude.len() <= 15 => {
                let mut v: i128 = 0;
                for b in magnitude {
                    v = (v << 8) | i128::from(*b);
                }
                Some(if *negative { -1 - v } else { v })
            }
            _ => None,
        }
    }

    /// Python's `==`.
    pub fn py_eq(&self, other: &Cbor) -> bool {
        use Cbor::*;
        match (self, other) {
            (Int { .. } | Bool(_), Int { .. } | Bool(_)) => match (self.as_int(), other.as_int()) {
                (Some(a), Some(b)) => a == b,
                _ => matches!(
                    (self, other),
                    (Int { negative: a, magnitude: x }, Int { negative: b, magnitude: y })
                        if a == b && x == y
                ),
            },
            (Float(f), Int { .. } | Bool(_)) | (Int { .. } | Bool(_), Float(f)) => {
                let int = if matches!(self, Float(_)) {
                    other
                } else {
                    self
                };
                f.is_finite()
                    && f.fract() == 0.0
                    && int
                        .as_int()
                        .is_some_and(|i| (i as f64) == *f && *f as i128 == i)
            }
            (Float(a), Float(b)) => a == b,
            (Bytes(a), Bytes(b)) => a == b,
            (Text(a), Text(b)) => a == b,
            (Array(a), Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.py_eq(y)),
            (Map(a), Map(b)) => {
                a.len() == b.len()
                    && a.iter().all(|(k, v)| {
                        b.iter()
                            .find(|(k2, _)| k.py_eq(k2))
                            .is_some_and(|(_, v2)| v.py_eq(v2))
                    })
            }
            (Null, Null) | (Undefined, Undefined) | (Break, Break) => true,
            (Simple(a), Simple(b)) => a == b,
            (Tag(t, v), Tag(t2, v2)) => t == t2 && v.py_eq(v2),
            _ => false,
        }
    }

    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            Cbor::Int {
                magnitude,
                negative,
            } => *negative || !magnitude.is_empty(),
            Cbor::Bytes(b) => !b.is_empty(),
            Cbor::Text(t) => !t.is_empty(),
            Cbor::Array(a) => !a.is_empty(),
            Cbor::Map(m) => !m.is_empty(),
            Cbor::Bool(b) => *b,
            Cbor::Null | Cbor::Undefined => false,
            Cbor::Float(f) => *f != 0.0,
            Cbor::Simple(_) | Cbor::Tag(..) | Cbor::Break => true,
        }
    }

    /// `mapping[key]` for a text key, as `"sig" in val` / `val["sig"]`.
    pub fn get_text(&self, key: &str) -> Option<&Cbor> {
        match self {
            Cbor::Map(items) => items
                .iter()
                .find(|(k, _)| matches!(k, Cbor::Text(t) if t == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// `value[index]` for an integer index: a dict lookup, or list / str /
    /// bytes indexing (negative from the end). `Err` names the exception.
    pub fn get_index(&self, index: i64) -> Result<Cbor, &'static str> {
        fn at<T: Clone>(items: &[T], index: i64) -> Result<T, &'static str> {
            let len = items.len() as i64;
            let i = if index < 0 { len + index } else { index };
            if (0..len).contains(&i) {
                Ok(items[i as usize].clone())
            } else {
                Err("IndexError")
            }
        }
        match self {
            Cbor::Map(items) => {
                let key = Cbor::int(index);
                items
                    .iter()
                    .find(|(k, _)| k.py_eq(&key))
                    .map(|(_, v)| v.clone())
                    .ok_or("KeyError")
            }
            Cbor::Array(items) => at(items, index),
            Cbor::Text(t) => {
                let chars: Vec<char> = t.chars().collect();
                at(&chars, index).map(|c| Cbor::Text(c.to_string()))
            }
            Cbor::Bytes(b) => at(b, index).map(|b| Cbor::int(i64::from(b))),
            _ => Err("TypeError"),
        }
    }

    /// `len(value)` where Python has one.
    pub fn py_len(&self) -> Option<usize> {
        match self {
            Cbor::Bytes(b) => Some(b.len()),
            Cbor::Text(t) => Some(t.chars().count()),
            Cbor::Array(a) => Some(a.len()),
            Cbor::Map(m) => Some(m.len()),
            _ => None,
        }
    }

    /// `bytes(value)` (py_webauthn's `byteslike_to_bytes`).
    pub fn py_bytes(&self) -> Option<Vec<u8>> {
        fn byte(item: &Cbor) -> Option<u8> {
            item.as_int().and_then(|i| u8::try_from(i).ok())
        }
        match self {
            Cbor::Bytes(b) => Some(b.clone()),
            Cbor::Int {
                negative: false, ..
            }
            | Cbor::Bool(_) => {
                let n = usize::try_from(self.as_int()?).ok()?;
                (n <= 1 << 20).then(|| vec![0; n])
            }
            Cbor::Array(items) => items.iter().map(byte).collect(),
            Cbor::Map(items) => items.iter().map(|(k, _)| byte(k)).collect(),
            _ => None,
        }
    }

    /// `str(value)` — what an f-string prints.
    pub fn py_str(&self) -> String {
        match self {
            Cbor::Text(t) => t.clone(),
            other => other.py_repr(),
        }
    }

    /// `repr(value)`.
    pub fn py_repr(&self) -> String {
        match self {
            Cbor::Int {
                negative,
                magnitude,
            } => {
                let value = BigUint::from_bytes_be(magnitude);
                if *negative {
                    format!("-{}", value + 1u8)
                } else {
                    value.to_string()
                }
            }
            Cbor::Bytes(b) => bytes_repr(b),
            Cbor::Text(t) => str_repr(t),
            Cbor::Array(items) => {
                let inner: Vec<String> = items.iter().map(Cbor::py_repr).collect();
                format!("[{}]", inner.join(", "))
            }
            Cbor::Map(items) => {
                let inner: Vec<String> = items
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k.py_repr(), v.py_repr()))
                    .collect();
                format!("{{{}}}", inner.join(", "))
            }
            Cbor::Bool(true) => "True".into(),
            Cbor::Bool(false) => "False".into(),
            Cbor::Null => "None".into(),
            Cbor::Undefined => "undefined".into(),
            Cbor::Simple(v) => format!("CBORSimpleValue(value={v})"),
            Cbor::Float(f) => float_repr(*f),
            Cbor::Tag(t, v) => format!("CBORTag({t}, {})", v.py_repr()),
            Cbor::Break => "break_marker".into(),
        }
    }
}

struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Decoder<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError)?;
        let slice = self.data.get(self.pos..end).ok_or(CborError)?;
        self.pos = end;
        Ok(slice)
    }

    /// The argument of an initial byte; `None` for indefinite length.
    fn argument(&mut self, info: u8) -> Result<Option<u64>, CborError> {
        let bytes = match info {
            0..=23 => return Ok(Some(u64::from(info))),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            31 => return Ok(None),
            _ => return Err(CborError),
        };
        let mut v = 0u64;
        for b in self.take(bytes)? {
            v = (v << 8) | u64::from(*b);
        }
        Ok(Some(v))
    }

    fn length(&mut self, info: u8) -> Result<Option<usize>, CborError> {
        self.argument(info)?
            .map(|n| usize::try_from(n).map_err(|_| CborError))
            .transpose()
    }

    fn string_chunks(&mut self, major: u8) -> Result<Vec<Vec<u8>>, CborError> {
        let mut chunks = Vec::new();
        loop {
            let initial = *self.take(1)?.first().ok_or(CborError)?;
            if initial == 0xff {
                return Ok(chunks);
            }
            if initial >> 5 != major {
                return Err(CborError);
            }
            let n = self.length(initial & 0x1f)?.ok_or(CborError)?;
            chunks.push(self.take(n)?.to_vec());
        }
    }

    fn item(&mut self, depth: usize) -> Result<Cbor, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError);
        }
        let initial = *self.take(1)?.first().ok_or(CborError)?;
        let (major, info) = (initial >> 5, initial & 0x1f);
        match major {
            0 | 1 => {
                let n = self.argument(info)?.ok_or(CborError)?;
                Ok(Cbor::Int {
                    negative: major == 1,
                    magnitude: strip(n.to_be_bytes().to_vec()),
                })
            }
            2 => match self.length(info)? {
                Some(n) => Ok(Cbor::Bytes(self.take(n)?.to_vec())),
                None => Ok(Cbor::Bytes(self.string_chunks(2)?.concat())),
            },
            3 => {
                let chunks = match self.length(info)? {
                    Some(n) => vec![self.take(n)?.to_vec()],
                    None => self.string_chunks(3)?,
                };
                let mut text = String::new();
                for chunk in chunks {
                    text.push_str(std::str::from_utf8(&chunk).map_err(|_| CborError)?);
                }
                Ok(Cbor::Text(text))
            }
            4 => {
                let mut items = Vec::new();
                match self.length(info)? {
                    Some(n) => {
                        for _ in 0..n {
                            items.push(self.item(depth + 1)?);
                        }
                    }
                    None => loop {
                        match self.item(depth + 1)? {
                            Cbor::Break => break,
                            item => items.push(item),
                        }
                    },
                }
                Ok(Cbor::Array(items))
            }
            5 => {
                let mut items: Vec<(Cbor, Cbor)> = Vec::new();
                let count = self.length(info)?;
                let mut read = 0usize;
                loop {
                    if count.is_some_and(|n| read == n) {
                        break;
                    }
                    let key = self.item(depth + 1)?;
                    if count.is_none() && matches!(key, Cbor::Break) {
                        break;
                    }
                    let value = self.item(depth + 1)?;
                    match items.iter_mut().find(|(k, _)| k.py_eq(&key)) {
                        Some(slot) => slot.1 = value,
                        None => items.push((key, value)),
                    }
                    read += 1;
                }
                Ok(Cbor::Map(items))
            }
            6 => {
                let tag = self.argument(info)?.ok_or(CborError)?;
                let value = self.item(depth + 1)?;
                match (tag, value) {
                    (2 | 3, Cbor::Bytes(b)) => Ok(Cbor::Int {
                        negative: tag == 3,
                        magnitude: strip(b),
                    }),
                    (2 | 3, _) => Err(CborError),
                    (55799, value) => Ok(value),
                    (tag, value) => Ok(Cbor::Tag(tag, Box::new(value))),
                }
            }
            _ => match info {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                22 => Ok(Cbor::Null),
                23 => Ok(Cbor::Undefined),
                0..=19 => Ok(Cbor::Simple(info)),
                24 => Ok(Cbor::Simple(*self.take(1)?.first().ok_or(CborError)?)),
                25 => {
                    let b = self.take(2)?;
                    Ok(Cbor::Float(half_to_f64(u16::from_be_bytes([b[0], b[1]]))))
                }
                26 => {
                    let b = self.take(4)?;
                    Ok(Cbor::Float(f64::from(f32::from_be_bytes([
                        b[0], b[1], b[2], b[3],
                    ]))))
                }
                27 => {
                    let b = self.take(8)?;
                    let mut raw = [0u8; 8];
                    raw.copy_from_slice(b);
                    Ok(Cbor::Float(f64::from_be_bytes(raw)))
                }
                31 => Ok(Cbor::Break),
                _ => Err(CborError),
            },
        }
    }
}

fn half_to_f64(h: u16) -> f64 {
    let sign = if h & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exp = i32::from((h >> 10) & 0x1f);
    let frac = f64::from(h & 0x3ff);
    sign * match exp {
        0 => frac * 2f64.powi(-24),
        31 if frac == 0.0 => f64::INFINITY,
        31 => f64::NAN,
        e => (1.0 + frac / 1024.0) * 2f64.powi(e - 15),
    }
}

/// `cbor2.loads(data)`: the first item; anything after it is ignored.
pub fn decode(data: &[u8]) -> Result<Cbor, CborError> {
    Decoder { data, pos: 0 }.item(0)
}

fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let m = major << 5;
    if value < 24 {
        out.push(m | value as u8);
    } else if value < 0x100 {
        out.extend_from_slice(&[m | 24, value as u8]);
    } else if value < 0x1_0000 {
        out.push(m | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value < 0x1_0000_0000 {
        out.push(m | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_into(item: &Cbor, out: &mut Vec<u8>) -> Result<(), CborError> {
    match item {
        Cbor::Int {
            negative,
            magnitude,
        } => {
            if magnitude.len() <= 8 {
                let mut v = 0u64;
                for b in magnitude {
                    v = (v << 8) | u64::from(*b);
                }
                head(out, u8::from(*negative), v);
            } else {
                head(out, 6, if *negative { 3 } else { 2 });
                head(out, 2, magnitude.len() as u64);
                out.extend_from_slice(magnitude);
            }
        }
        Cbor::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Cbor::Text(t) => {
            head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Cbor::Array(items) => {
            head(out, 4, items.len() as u64);
            for i in items {
                encode_into(i, out)?;
            }
        }
        Cbor::Map(items) => {
            head(out, 5, items.len() as u64);
            for (k, v) in items {
                encode_into(k, out)?;
                encode_into(v, out)?;
            }
        }
        Cbor::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Cbor::Null => out.push(0xf6),
        Cbor::Undefined => out.push(0xf7),
        Cbor::Simple(v) => {
            if *v < 24 {
                out.push(0xe0 | v);
            } else {
                out.extend_from_slice(&[0xf8, *v]);
            }
        }
        Cbor::Float(f) => {
            if f.is_nan() {
                out.extend_from_slice(&[0xf9, 0x7e, 0x00]);
            } else if f.is_infinite() {
                out.extend_from_slice(if *f > 0.0 {
                    &[0xf9, 0x7c, 0x00]
                } else {
                    &[0xf9, 0xfc, 0x00]
                });
            } else {
                out.push(0xfb);
                out.extend_from_slice(&f.to_be_bytes());
            }
        }
        Cbor::Tag(t, v) => {
            head(out, 6, *t);
            encode_into(v, out)?;
        }
        Cbor::Break => return Err(CborError),
    }
    Ok(())
}

/// `cbor2.dumps(value)`.
pub fn encode(item: &Cbor) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    encode_into(item, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(hex: &str) -> Result<String, &'static str> {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let item = decode(&bytes).map_err(|_| "decode")?;
        let out = encode(&item).map_err(|_| "encode")?;
        Ok(out.iter().map(|b| format!("{b:02x}")).collect())
    }

    #[test]
    fn matches_cbor2() {
        assert_eq!(round("3806").unwrap(), "26");
        assert_eq!(round("a20102f503").unwrap(), "a10103");
        assert_eq!(round("c2420001").unwrap(), "01");
        assert_eq!(round("f93c00").unwrap(), "fb3ff0000000000000");
        assert_eq!(round("ff"), Err("encode"));
        assert_eq!(round("1c"), Err("decode"));
    }

    #[test]
    fn python_equality_and_repr() {
        assert!(Cbor::int(1).py_eq(&Cbor::Bool(true)));
        assert!(Cbor::Float(-7.0).py_eq(&Cbor::int(-7)));
        assert!(!Cbor::Text("1".into()).py_eq(&Cbor::int(1)));
        assert_eq!(Cbor::int(-65535).py_str(), "-65535");
        assert_eq!(Cbor::Bytes(b"none".to_vec()).py_str(), "b'none'");
    }
}
