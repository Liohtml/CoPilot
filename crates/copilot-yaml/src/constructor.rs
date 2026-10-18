//! `yaml/constructor.py`'s `BaseConstructor` and `SafeConstructor`: nodes
//! into Python objects.
//!
//! The objects live in an arena so that what Python shares stays shared (an
//! alias is the anchored object itself, a recursive structure contains
//! itself) and dict keys compare as Python compares them (`1 == 1.0 ==
//! True`, two aware datetimes at the same instant, the one `.nan` object).
//! Collections are built as PyYAML's generators build them: the empty
//! container first, its content later, breadth first through
//! `state_generators` — which decides which of two errors is raised.

use num_bigint_dig::BigInt;
use num_traits::{ToPrimitive, Zero};

use crate::composer::{Node, NodeValue, timestamp_groups};
use crate::error::{LoadError, MarkedError, MarkedKind, PyException};
use crate::pyint::{self, check_date, check_time, timedelta_repr};
use crate::repr::str_repr;
use crate::value::{Date, DateTime};

/// A Python object.
#[derive(Debug, Clone)]
pub(crate) enum Obj {
    None,
    Bool(bool),
    Int(BigInt),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    Date(Date),
    DateTime(DateTime),
    List(Vec<usize>),
    Tuple(Vec<usize>),
    Dict(Vec<(usize, usize)>),
    Set(Vec<usize>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fill {
    Seq,
    Map,
    Set,
    Omap,
    Pairs,
}

fn constructor_error(
    context: Option<&str>,
    context_mark: Option<crate::error::Mark>,
    problem: impl Into<String>,
    problem_mark: crate::error::Mark,
) -> LoadError {
    MarkedError::new(
        MarkedKind::Constructor,
        context,
        context_mark,
        problem,
        Some(problem_mark),
    )
    .into()
}

type CResult<T> = Result<T, LoadError>;

pub(crate) struct Constructor<'n> {
    nodes: &'n mut Vec<Node>,
    pub(crate) objs: Vec<Obj>,
    constructed: Vec<Option<usize>>,
    recursive: Vec<bool>,
    state_generators: Vec<(usize, usize, Fill)>,
    /// `SafeConstructor.nan_value`: one object, whatever the document says.
    nan: usize,
}

impl<'n> Constructor<'n> {
    pub(crate) fn new(nodes: &'n mut Vec<Node>) -> Self {
        let n = nodes.len();
        Self {
            nodes,
            objs: vec![Obj::Float(f64::NAN)],
            constructed: vec![None; n],
            recursive: vec![false; n],
            state_generators: Vec::new(),
            nan: 0,
        }
    }

    fn alloc(&mut self, obj: Obj) -> usize {
        self.objs.push(obj);
        self.objs.len() - 1
    }

    /// `construct_document(node)`.
    pub(crate) fn construct_document(&mut self, node: usize) -> CResult<usize> {
        let data = self.construct_object(node)?;
        while !self.state_generators.is_empty() {
            let generators = std::mem::take(&mut self.state_generators);
            for (node, obj, fill) in generators {
                self.fill(node, obj, fill)?;
            }
        }
        Ok(data)
    }

    /// `construct_object(node, deep=False)`.
    fn construct_object(&mut self, node: usize) -> CResult<usize> {
        if let Some(obj) = self.constructed[node] {
            return Ok(obj);
        }
        if self.recursive[node] {
            return Err(constructor_error(
                None,
                None,
                "found unconstructable recursive node",
                self.nodes[node].start_mark.clone(),
            ));
        }
        self.recursive[node] = true;
        let tag = self.nodes[node].tag.clone();
        let generator = match tag.as_str() {
            "tag:yaml.org,2002:seq" => Some((Obj::List(Vec::new()), Fill::Seq)),
            "tag:yaml.org,2002:map" => Some((Obj::Dict(Vec::new()), Fill::Map)),
            "tag:yaml.org,2002:set" => Some((Obj::Set(Vec::new()), Fill::Set)),
            "tag:yaml.org,2002:omap" => Some((Obj::List(Vec::new()), Fill::Omap)),
            "tag:yaml.org,2002:pairs" => Some((Obj::List(Vec::new()), Fill::Pairs)),
            _ => None,
        };
        let data = match generator {
            Some((empty, fill)) => {
                let obj = self.alloc(empty);
                self.state_generators.push((node, obj, fill));
                obj
            }
            None => {
                let obj = self.construct_scalar_like(node, &tag)?;
                self.alloc_or_shared(obj)
            }
        };
        self.constructed[node] = Some(data);
        self.recursive[node] = false;
        Ok(data)
    }

    fn alloc_or_shared(&mut self, obj: Built) -> usize {
        match obj {
            Built::Nan => self.nan,
            Built::Obj(o) => self.alloc(o),
        }
    }

    fn construct_scalar_like(&mut self, node: usize, tag: &str) -> CResult<Built> {
        Ok(Built::Obj(match tag {
            "tag:yaml.org,2002:null" => {
                self.construct_scalar(node)?;
                Obj::None
            }
            "tag:yaml.org,2002:bool" => {
                let value = self.construct_scalar(node)?;
                let lower = copilot_jinja::unicode::lower(&value);
                match lower.as_str() {
                    "yes" | "true" | "on" => Obj::Bool(true),
                    "no" | "false" | "off" => Obj::Bool(false),
                    _ => return Err(PyException::new("KeyError", str_repr(&lower)).into()),
                }
            }
            "tag:yaml.org,2002:int" => Obj::Int(self.construct_yaml_int(node)?),
            "tag:yaml.org,2002:float" => return self.construct_yaml_float(node),
            "tag:yaml.org,2002:binary" => self.construct_yaml_binary(node)?,
            "tag:yaml.org,2002:timestamp" => self.construct_yaml_timestamp(node)?,
            "tag:yaml.org,2002:str" => Obj::Str(self.construct_scalar(node)?),
            _ => {
                return Err(constructor_error(
                    None,
                    None,
                    format!(
                        "could not determine a constructor for the tag {}",
                        str_repr(tag)
                    ),
                    self.nodes[node].start_mark.clone(),
                ));
            }
        }))
    }

    /// `SafeConstructor.construct_scalar(node)`.
    fn construct_scalar(&mut self, node: usize) -> CResult<String> {
        if let NodeValue::Mapping(items) = &self.nodes[node].value {
            let items = items.clone();
            for (key, value) in items {
                if self.nodes[key].tag == "tag:yaml.org,2002:value" {
                    return self.construct_scalar(value);
                }
            }
        }
        match &self.nodes[node].value {
            NodeValue::Scalar(v) => Ok(v.clone()),
            _ => Err(constructor_error(
                None,
                None,
                format!(
                    "expected a scalar node, but found {}",
                    self.nodes[node].id()
                ),
                self.nodes[node].start_mark.clone(),
            )),
        }
    }

    fn construct_yaml_int(&mut self, node: usize) -> CResult<BigInt> {
        let raw = self.construct_scalar(node)?;
        let mut value: String = raw.replace('_', "");
        let first = first_char(&value)?;
        let negative = first == '-';
        if first == '+' || first == '-' {
            value = value[1..].to_string();
        }
        let sign = |n: BigInt| if negative { -n } else { n };
        if value == "0" {
            return Ok(BigInt::zero());
        }
        if let Some(rest) = value.strip_prefix("0b") {
            return Ok(sign(pyint::parse_int(rest, 2)?));
        }
        if let Some(rest) = value.strip_prefix("0x") {
            return Ok(sign(pyint::parse_int(rest, 16)?));
        }
        if first_char(&value)? == '0' {
            return Ok(sign(pyint::parse_int(&value, 8)?));
        }
        if value.contains(':') {
            let mut digits: Vec<BigInt> = Vec::new();
            for part in value.split(':') {
                digits.push(pyint::parse_int(part, 10)?);
            }
            digits.reverse();
            let mut base = BigInt::from(1);
            let mut total = BigInt::zero();
            for digit in digits {
                total += digit * &base;
                base *= 60;
            }
            return Ok(sign(total));
        }
        Ok(sign(pyint::parse_int(&value, 10)?))
    }

    fn construct_yaml_float(&mut self, node: usize) -> CResult<Built> {
        let raw = self.construct_scalar(node)?;
        let mut value = copilot_jinja::unicode::lower(&raw.replace('_', ""));
        let first = first_char(&value)?;
        let sign: f64 = if first == '-' { -1.0 } else { 1.0 };
        if first == '+' || first == '-' {
            value = value[first.len_utf8()..].to_string();
        }
        if value == ".inf" {
            return Ok(Built::Obj(Obj::Float(sign * f64::INFINITY)));
        }
        if value == ".nan" {
            return Ok(Built::Nan);
        }
        if value.contains(':') {
            let mut digits: Vec<f64> = Vec::new();
            for part in value.split(':') {
                digits.push(pyint::parse_float(part)?);
            }
            digits.reverse();
            let mut base: i64 = 1;
            let mut total = 0.0f64;
            let mut big_base: Option<BigInt> = None;
            for digit in digits {
                // `value += digit * base` with an int `base` (exact until it
                // no longer fits a float multiplication's int argument).
                let b = match &big_base {
                    Some(b) => b.to_f64().unwrap_or(f64::INFINITY),
                    None => base as f64,
                };
                total += digit * b;
                match big_base.as_mut() {
                    Some(b) => *b *= 60,
                    None => match base.checked_mul(60) {
                        Some(n) => base = n,
                        None => big_base = Some(BigInt::from(base) * 60),
                    },
                }
            }
            return Ok(Built::Obj(Obj::Float(sign * total)));
        }
        Ok(Built::Obj(Obj::Float(sign * pyint::parse_float(&value)?)))
    }

    fn construct_yaml_binary(&mut self, node: usize) -> CResult<Obj> {
        let value = self.construct_scalar(node)?;
        if let Some(message) = pyint::ascii_encode_error(&value) {
            return Err(constructor_error(
                None,
                None,
                format!("failed to convert base64 data into ascii: {message}"),
                self.nodes[node].start_mark.clone(),
            ));
        }
        match copilot_auth::pybase64::a2b_base64(value.as_bytes()) {
            Ok(bytes) => Ok(Obj::Bytes(bytes)),
            Err(e) => Err(constructor_error(
                None,
                None,
                format!("failed to decode base64 data: {e}"),
                self.nodes[node].start_mark.clone(),
            )),
        }
    }

    fn construct_yaml_timestamp(&mut self, node: usize) -> CResult<Obj> {
        self.construct_scalar(node)?;
        let NodeValue::Scalar(text) = &self.nodes[node].value else {
            // `self.timestamp_regexp.match(node.value)` on a list.
            return Err(PyException::new(
                "TypeError",
                "expected string or bytes-like object, got 'list'",
            )
            .into());
        };
        let Some(m) = timestamp_groups(text) else {
            return Err(PyException::new(
                "AttributeError",
                "'NoneType' object has no attribute 'groupdict'",
            )
            .into());
        };
        let num = |name: &str| -> i64 {
            m.name(name)
                .map(|g| g.as_str().parse::<i64>().unwrap_or(0))
                .unwrap_or(0)
        };
        let year = num("year");
        let month = num("month");
        let day = num("day");
        let hour_present = m.name("hour").is_some_and(|g| !g.as_str().is_empty());
        if !hour_present {
            check_date(year, month, day)?;
            return Ok(Obj::Date(Date {
                year: year as i32,
                month: month as u8,
                day: day as u8,
            }));
        }
        let hour = num("hour");
        let minute = num("minute");
        let second = num("second");
        let mut fraction = 0u32;
        if let Some(f) = m.name("fraction").map(|g| g.as_str()) {
            if !f.is_empty() {
                let mut digits: String = f.chars().take(6).collect();
                while digits.len() < 6 {
                    digits.push('0');
                }
                fraction = digits.parse::<u32>().unwrap_or(0);
            }
        }
        let mut offset: Option<i32> = None;
        if let Some(sign) = m.name("tz_sign").map(|g| g.as_str()) {
            let tz_hour = num("tz_hour");
            let tz_minute = m
                .name("tz_minute")
                .map(|g| g.as_str().parse::<i64>().unwrap_or(0))
                .unwrap_or(0);
            let mut seconds = tz_hour * 3600 + tz_minute * 60;
            if sign == "-" {
                seconds = -seconds;
            }
            if seconds <= -86400 || seconds >= 86400 {
                return Err(PyException::value_error(format!(
                    "offset must be a timedelta strictly between -timedelta(hours=24) and \
                     timedelta(hours=24), not {}.",
                    timedelta_repr(seconds)
                ))
                .into());
            }
            offset = Some(seconds as i32);
        } else if m.name("tz").is_some_and(|g| !g.as_str().is_empty()) {
            offset = Some(0);
        }
        check_date(year, month, day)?;
        check_time(hour, minute, second)?;
        Ok(Obj::DateTime(DateTime {
            date: Date {
                year: year as i32,
                month: month as u8,
                day: day as u8,
            },
            hour: hour as u8,
            minute: minute as u8,
            second: second as u8,
            microsecond: fraction,
            offset,
        }))
    }

    // --- collections ----------------------------------------------------------

    fn fill(&mut self, node: usize, obj: usize, fill: Fill) -> CResult<()> {
        match fill {
            Fill::Seq => {
                let items = self.construct_sequence(node)?;
                self.objs[obj] = Obj::List(items);
            }
            Fill::Map => {
                let items = self.construct_mapping(node)?;
                self.objs[obj] = Obj::Dict(items);
            }
            Fill::Set => {
                let items = self.construct_mapping(node)?;
                let mut keys: Vec<usize> = Vec::new();
                for (k, _) in items {
                    if !keys.iter().any(|e| self.key_eq(*e, k)) {
                        keys.push(k);
                    }
                }
                self.objs[obj] = Obj::Set(keys);
            }
            Fill::Omap | Fill::Pairs => {
                let what = if fill == Fill::Omap {
                    "while constructing an ordered map"
                } else {
                    "while constructing pairs"
                };
                let mark = self.nodes[node].start_mark.clone();
                let NodeValue::Sequence(children) = self.nodes[node].value.clone() else {
                    return Err(constructor_error(
                        Some(what),
                        Some(mark.clone()),
                        format!("expected a sequence, but found {}", self.nodes[node].id()),
                        mark,
                    ));
                };
                for sub in children {
                    let NodeValue::Mapping(pairs) = self.nodes[sub].value.clone() else {
                        return Err(constructor_error(
                            Some(what),
                            Some(mark.clone()),
                            format!(
                                "expected a mapping of length 1, but found {}",
                                self.nodes[sub].id()
                            ),
                            self.nodes[sub].start_mark.clone(),
                        ));
                    };
                    if pairs.len() != 1 {
                        return Err(constructor_error(
                            Some(what),
                            Some(mark.clone()),
                            format!(
                                "expected a single mapping item, but found {} items",
                                pairs.len()
                            ),
                            self.nodes[sub].start_mark.clone(),
                        ));
                    }
                    let (key_node, value_node) = pairs[0];
                    let key = self.construct_object(key_node)?;
                    let value = self.construct_object(value_node)?;
                    let pair = self.alloc(Obj::Tuple(vec![key, value]));
                    if let Obj::List(items) = &mut self.objs[obj] {
                        items.push(pair);
                    }
                }
            }
        }
        Ok(())
    }

    fn construct_sequence(&mut self, node: usize) -> CResult<Vec<usize>> {
        let NodeValue::Sequence(children) = self.nodes[node].value.clone() else {
            return Err(constructor_error(
                None,
                None,
                format!(
                    "expected a sequence node, but found {}",
                    self.nodes[node].id()
                ),
                self.nodes[node].start_mark.clone(),
            ));
        };
        let mut out = Vec::with_capacity(children.len());
        for child in children {
            out.push(self.construct_object(child)?);
        }
        Ok(out)
    }

    /// `SafeConstructor.flatten_mapping(node)`.
    fn flatten_mapping(&mut self, node: usize) -> CResult<()> {
        let mut merge: Vec<(usize, usize)> = Vec::new();
        let mut index = 0;
        loop {
            let NodeValue::Mapping(items) = &self.nodes[node].value else {
                return Ok(());
            };
            if index >= items.len() {
                break;
            }
            let (key_node, value_node) = items[index];
            let key_tag = self.nodes[key_node].tag.clone();
            if key_tag == "tag:yaml.org,2002:merge" {
                if let NodeValue::Mapping(items) = &mut self.nodes[node].value {
                    items.remove(index);
                }
                match self.nodes[value_node].value.clone() {
                    NodeValue::Mapping(_) => {
                        self.flatten_mapping(value_node)?;
                        if let NodeValue::Mapping(sub) = &self.nodes[value_node].value {
                            merge.extend(sub.iter().copied());
                        }
                    }
                    NodeValue::Sequence(subnodes) => {
                        let mut submerge: Vec<Vec<(usize, usize)>> = Vec::new();
                        for subnode in subnodes {
                            if !matches!(self.nodes[subnode].value, NodeValue::Mapping(_)) {
                                return Err(constructor_error(
                                    Some("while constructing a mapping"),
                                    Some(self.nodes[node].start_mark.clone()),
                                    format!(
                                        "expected a mapping for merging, but found {}",
                                        self.nodes[subnode].id()
                                    ),
                                    self.nodes[subnode].start_mark.clone(),
                                ));
                            }
                            self.flatten_mapping(subnode)?;
                            if let NodeValue::Mapping(sub) = &self.nodes[subnode].value {
                                submerge.push(sub.clone());
                            }
                        }
                        submerge.reverse();
                        for value in submerge {
                            merge.extend(value);
                        }
                    }
                    NodeValue::Scalar(_) => {
                        return Err(constructor_error(
                            Some("while constructing a mapping"),
                            Some(self.nodes[node].start_mark.clone()),
                            format!(
                                "expected a mapping or list of mappings for merging, but found {}",
                                self.nodes[value_node].id()
                            ),
                            self.nodes[value_node].start_mark.clone(),
                        ));
                    }
                }
            } else if key_tag == "tag:yaml.org,2002:value" {
                self.nodes[key_node].tag = "tag:yaml.org,2002:str".to_string();
                index += 1;
            } else {
                index += 1;
            }
        }
        if !merge.is_empty() {
            if let NodeValue::Mapping(items) = &mut self.nodes[node].value {
                merge.extend(items.iter().copied());
                *items = merge;
            }
        }
        Ok(())
    }

    /// `SafeConstructor.construct_mapping(node)`.
    fn construct_mapping(&mut self, node: usize) -> CResult<Vec<(usize, usize)>> {
        if matches!(self.nodes[node].value, NodeValue::Mapping(_)) {
            self.flatten_mapping(node)?;
        }
        let NodeValue::Mapping(pairs) = self.nodes[node].value.clone() else {
            return Err(constructor_error(
                None,
                None,
                format!(
                    "expected a mapping node, but found {}",
                    self.nodes[node].id()
                ),
                self.nodes[node].start_mark.clone(),
            ));
        };
        let mut mapping: Vec<(usize, usize)> = Vec::new();
        for (key_node, value_node) in pairs {
            let key = self.construct_object(key_node)?;
            if !self.hashable(key) {
                return Err(constructor_error(
                    Some("while constructing a mapping"),
                    Some(self.nodes[node].start_mark.clone()),
                    "found unhashable key",
                    self.nodes[key_node].start_mark.clone(),
                ));
            }
            let value = self.construct_object(value_node)?;
            match mapping.iter_mut().find(|(k, _)| self.key_eq_ids(*k, key)) {
                Some(slot) => slot.1 = value,
                None => mapping.push((key, value)),
            }
        }
        Ok(mapping)
    }

    fn hashable(&self, obj: usize) -> bool {
        !matches!(self.objs[obj], Obj::List(_) | Obj::Dict(_) | Obj::Set(_))
    }

    fn key_eq_ids(&self, a: usize, b: usize) -> bool {
        a == b || self.key_eq(a, b)
    }

    /// Python's `==` between two hashable objects (identity first).
    fn key_eq(&self, a: usize, b: usize) -> bool {
        if a == b {
            return true;
        }
        key_eq(&self.objs[a], &self.objs[b])
    }
}

/// What a scalar constructor returned: an object, or the shared `.nan`.
enum Built {
    Obj(Obj),
    Nan,
}

fn first_char(value: &str) -> Result<char, PyException> {
    value
        .chars()
        .next()
        .ok_or_else(|| PyException::new("IndexError", "string index out of range"))
}

fn number(o: &Obj) -> Option<Num<'_>> {
    match o {
        Obj::Bool(b) => Some(Num::Int(BigInt::from(u8::from(*b)))),
        Obj::Int(i) => Some(Num::IntRef(i)),
        Obj::Float(f) => Some(Num::Float(*f)),
        _ => None,
    }
}

enum Num<'a> {
    Int(BigInt),
    IntRef(&'a BigInt),
    Float(f64),
}

impl Num<'_> {
    fn int(&self) -> Option<&BigInt> {
        match self {
            Num::Int(i) => Some(i),
            Num::IntRef(i) => Some(i),
            Num::Float(_) => None,
        }
    }
}

/// Python's `==` for an int and a float: exact.
pub(crate) fn int_float_eq(i: &BigInt, f: f64) -> bool {
    if !f.is_finite() || f.fract() != 0.0 {
        return false;
    }
    match pyint::float_to_bigint(f) {
        Some(g) => &g == i,
        None => false,
    }
}

fn key_eq(a: &Obj, b: &Obj) -> bool {
    if let (Some(x), Some(y)) = (number(a), number(b)) {
        return match (x.int(), y.int(), &x, &y) {
            (Some(i), Some(j), _, _) => i == j,
            (Some(i), None, _, Num::Float(f)) => int_float_eq(i, *f),
            (None, Some(j), Num::Float(f), _) => int_float_eq(j, *f),
            (_, _, Num::Float(f), Num::Float(g)) => f == g,
            _ => false,
        };
    }
    match (a, b) {
        (Obj::None, Obj::None) => true,
        (Obj::Str(x), Obj::Str(y)) => x == y,
        (Obj::Bytes(x), Obj::Bytes(y)) => x == y,
        (Obj::Date(x), Obj::Date(y)) => x == y,
        (Obj::DateTime(x), Obj::DateTime(y)) => x.py_eq(y),
        _ => false,
    }
}
