//! The methods of Python's built-in types, as a template calls them
//! (`name.upper()`, `items.append(x)`, `d.get(k)`), with CPython's errors.

use std::rc::Rc;

use num_bigint_dig::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};

use crate::error::{Error, Result};
use crate::objects::{self, Bytes, DictView, Method, ViewKind};
use crate::ops;
use crate::pyrepr;
use crate::tables;
use crate::unicode;
use crate::value::{Dict, PyIter, Value};

/// The `Markup` methods written in Python (their bound methods are
/// `<bound method ...>`, the others `<built-in method ...>`).
pub const MARKUP_PYTHON_METHODS: &[&str] = &[
    "join",
    "split",
    "rsplit",
    "splitlines",
    "unescape",
    "striptags",
    "escape",
    "capitalize",
    "title",
    "lower",
    "upper",
    "replace",
    "ljust",
    "rjust",
    "lstrip",
    "rstrip",
    "center",
    "strip",
    "translate",
    "expandtabs",
    "swapcase",
    "zfill",
    "casefold",
    "removeprefix",
    "removesuffix",
    "partition",
    "rpartition",
    "format",
    "format_map",
];

type Kwargs = Vec<(Rc<str>, Value)>;

/// The table key of a receiver's type.
fn type_key(v: &Value) -> Option<&'static str> {
    Some(match v {
        Value::Str(_) | Value::StrEnum(_) => "str",
        Value::Markup(_) => "Markup",
        Value::List(_) => "list",
        Value::Dict(_) => "dict",
        Value::Tuple(_) => "tuple",
        Value::Int(_) | Value::Bool(_) => "int",
        Value::Float(_) => "float",
        Value::Object(o) if o.type_name() == "bytes" => "bytes",
        _ => return None,
    })
}

fn extrapolate(msg: &str, from: usize, n: usize) -> String {
    msg.replace(&format!("({from} given)"), &format!("({n} given)"))
        .replace(&format!("got {from}"), &format!("got {n}"))
        .replace(
            &format!("but {} were", from + 1),
            &format!("but {} were", n + 1),
        )
        .replace(&format!("but {from} were"), &format!("but {n} were"))
}

/// Raises the `TypeError` Python raises for `nargs` positional arguments or
/// an unknown keyword (anything not in `accepted`).
fn check_arity(
    ty: &str,
    name: &str,
    nargs: usize,
    kwargs: &Kwargs,
    accepted: &[&str],
) -> Result<()> {
    let Ok(i) = tables::ARITY.binary_search_by(|(t, m, _, _)| (*t, *m).cmp(&(ty, name))) else {
        return Ok(());
    };
    let (_, _, counts, kw_msg) = tables::ARITY[i];
    if let Some((_, m)) = counts.iter().find(|(n, _)| usize::from(*n) == nargs) {
        return Err(Error::type_error(*m));
    }
    if nargs > 5 {
        if let Some((_, m)) = counts.iter().find(|(n, _)| *n == 5) {
            return Err(Error::type_error(extrapolate(m, 5, nargs)));
        }
    }
    for (k, _) in kwargs {
        if !accepted.contains(&&**k) && !kw_msg.is_empty() {
            return Err(Error::type_error(kw_msg.replace("{kw}", k)));
        }
    }
    Ok(())
}

/// The positional argument at `i`, or the keyword `name`, or `None`.
fn arg(args: &[Value], kwargs: &Kwargs, i: usize, name: &str) -> Option<Value> {
    args.get(i).cloned().or_else(|| {
        kwargs
            .iter()
            .find(|(k, _)| &**k == name)
            .map(|(_, v)| v.clone())
    })
}

/// `operator.index(v)`.
pub fn index_value(v: &Value) -> Result<BigInt> {
    ops::as_int(v).ok_or_else(|| {
        Error::type_error(format!(
            "'{}' object cannot be interpreted as an integer",
            v.type_name()
        ))
    })
}

/// An index clamped to `isize` (`PyNumber_AsSsize_t` with clipping).
fn index_isize(v: &Value) -> Result<isize> {
    let i = index_value(v)?;
    Ok(i.to_isize().unwrap_or(if i.is_negative() {
        isize::MIN
    } else {
        isize::MAX
    }))
}

/// An index that must fit (`OverflowError` otherwise).
fn index_exact(v: &Value) -> Result<isize> {
    let i = index_value(v)?;
    i.to_isize()
        .ok_or_else(|| Error::overflow("Python int too large to convert to C ssize_t"))
}

/// `_PyEval_SliceIndex`: `None` keeps the default.
fn slice_index(v: Option<&Value>, default: isize) -> Result<isize> {
    match v {
        None | Some(Value::None) => Ok(default),
        Some(v) => match ops::as_int(v) {
            Some(i) => Ok(i.to_isize().unwrap_or(if i.is_negative() {
                isize::MIN
            } else {
                isize::MAX
            })),
            None => Err(Error::type_error(
                "slice indices must be integers or None or have an __index__ method",
            )),
        },
    }
}

/// `ADJUST_INDICES`.
fn adjust(start: isize, end: isize, len: usize) -> (isize, isize) {
    let len = len as isize;
    let mut end = end;
    let mut start = start;
    if end > len {
        end = len;
    } else if end < 0 {
        end += len;
        if end < 0 {
            end = 0;
        }
    }
    if start < 0 {
        start += len;
        if start < 0 {
            start = 0;
        }
    }
    (start, end)
}

fn need_str(v: &Value, what: impl FnOnce(&Value) -> String) -> Result<&str> {
    match v {
        Value::Undefined(u) if u.strict => Err(u.error()),
        _ => v.as_str().ok_or_else(|| Error::type_error(what(v))),
    }
}

fn chars(s: &str) -> Vec<char> {
    s.chars().collect()
}

fn find_in(hay: &[char], needle: &[char], start: usize, end: usize) -> Option<usize> {
    if needle.len() > end.saturating_sub(start) {
        return None;
    }
    (start..=end - needle.len()).find(|&i| hay[i..i + needle.len()] == *needle)
}

fn rfind_in(hay: &[char], needle: &[char], start: usize, end: usize) -> Option<usize> {
    if needle.len() > end.saturating_sub(start) {
        return None;
    }
    (start..=end - needle.len())
        .rev()
        .find(|&i| hay[i..i + needle.len()] == *needle)
}

/// Wraps a result string in the receiver's kind (`Markup` methods return
/// `Markup`).
fn same_kind(recv: &Value, s: String) -> Value {
    if recv.is_markup() {
        Value::markup(s)
    } else {
        Value::str(s)
    }
}

fn fill_char(v: Option<Value>, markup: bool) -> Result<char> {
    let Some(v) = v else { return Ok(' ') };
    let s = if markup {
        crate::markup::escape_value(&v)?
    } else {
        match v.as_str() {
            Some(s) => s.to_string(),
            None => {
                return Err(Error::type_error(format!(
                    "The fill character must be a unicode character, not {}",
                    v.type_name()
                )));
            }
        }
    };
    let mut it = s.chars();
    match (it.next(), it.next()) {
        (Some(c), None) => Ok(c),
        _ => Err(Error::type_error(
            "The fill character must be exactly one character long",
        )),
    }
}

fn pad(s: &str, left: usize, right: usize, fill: char) -> String {
    let mut out = String::with_capacity(s.len() + left + right);
    out.extend(std::iter::repeat_n(fill, left));
    out.push_str(s);
    out.extend(std::iter::repeat_n(fill, right));
    out
}

fn width_of(v: &Value) -> Result<usize> {
    let w = index_isize(v)?;
    let w = w.max(0) as usize;
    ops::check_size(w)?;
    Ok(w)
}

/// `str.split` / `str.rsplit`.
fn split(s: &str, sep: Option<&str>, maxsplit: isize, right: bool) -> Result<Vec<String>> {
    let max = if maxsplit < 0 {
        usize::MAX
    } else {
        maxsplit as usize
    };
    let c = chars(s);
    match sep {
        None => {
            let mut out = Vec::new();
            if !right {
                let mut i = 0;
                let n = c.len();
                let mut count = 0;
                while i < n && unicode::is_space(c[i]) {
                    i += 1;
                }
                while i < n {
                    if count == max {
                        out.push(c[i..].iter().collect());
                        break;
                    }
                    let j = i;
                    while i < n && !unicode::is_space(c[i]) {
                        i += 1;
                    }
                    out.push(c[j..i].iter().collect());
                    count += 1;
                    while i < n && unicode::is_space(c[i]) {
                        i += 1;
                    }
                }
            } else {
                let mut i = c.len();
                let mut count = 0;
                while i > 0 && unicode::is_space(c[i - 1]) {
                    i -= 1;
                }
                while i > 0 {
                    if count == max {
                        out.push(c[..i].iter().collect());
                        break;
                    }
                    let j = i;
                    while i > 0 && !unicode::is_space(c[i - 1]) {
                        i -= 1;
                    }
                    out.push(c[i..j].iter().collect());
                    count += 1;
                    while i > 0 && unicode::is_space(c[i - 1]) {
                        i -= 1;
                    }
                }
                out.reverse();
            }
            Ok(out)
        }
        Some(sep) => {
            if sep.is_empty() {
                return Err(Error::value_error("empty separator"));
            }
            let parts: Vec<&str> = if right {
                let mut p: Vec<&str> = if max == usize::MAX {
                    s.rsplit(sep).collect()
                } else {
                    s.rsplitn(max.saturating_add(1), sep).collect()
                };
                p.reverse();
                p
            } else if max == usize::MAX {
                s.split(sep).collect()
            } else {
                s.splitn(max.saturating_add(1), sep).collect()
            };
            Ok(parts.into_iter().map(String::from).collect())
        }
    }
}

fn strip_with(
    s: &str,
    chars_arg: Option<&Value>,
    name: &str,
    left: bool,
    right: bool,
) -> Result<String> {
    let set: Option<Vec<char>> = match chars_arg {
        None | Some(Value::None) => None,
        Some(v) => match v.as_str() {
            Some(c) => Some(c.chars().collect()),
            None => {
                if let Value::Undefined(u) = v {
                    if u.strict {
                        return Err(u.error());
                    }
                }
                return Err(Error::type_error(format!("{name} arg must be None or str")));
            }
        },
    };
    let pred = |c: char| match &set {
        None => unicode::is_space(c),
        Some(set) => set.contains(&c),
    };
    let mut r = s;
    if left {
        r = r.trim_start_matches(pred);
    }
    if right {
        r = r.trim_end_matches(pred);
    }
    Ok(r.to_string())
}

fn starts_or_ends(s: &str, name: &str, args: &[Value], end_match: bool) -> Result<Value> {
    let c = chars(s);
    let start = slice_index(args.get(1), 0)?;
    let end = slice_index(args.get(2), isize::MAX)?;
    let candidates: Vec<String> = match &args[0] {
        Value::Undefined(u) if u.strict => return Err(u.error()),
        v if v.is_str() => vec![v.as_str().unwrap_or_default().to_string()],
        v => match objects::as_tuple(v) {
            Some(items) => {
                let mut out = Vec::new();
                for it in items {
                    match it.as_str() {
                        Some(x) => out.push(x.to_string()),
                        None => {
                            return Err(Error::type_error(format!(
                                "tuple for {name} must only contain str, not {}",
                                it.type_name()
                            )));
                        }
                    }
                }
                out
            }
            None => {
                return Err(Error::type_error(format!(
                    "{name} first arg must be str or a tuple of str, not {}",
                    v.type_name()
                )));
            }
        },
    };
    let (start, end) = adjust(start, end, c.len());
    for sub in candidates {
        let sub: Vec<char> = sub.chars().collect();
        let end_ = end - sub.len() as isize;
        if end_ < start {
            continue;
        }
        if sub.is_empty() {
            return Ok(Value::Bool(true));
        }
        let at = if end_match {
            end_ as usize
        } else {
            start as usize
        };
        if c[at..at + sub.len()] == *sub {
            return Ok(Value::Bool(true));
        }
    }
    Ok(Value::Bool(false))
}

/// `encoding` normalised the way `codecs.lookup` does for the encodings
/// supported here.
fn codec(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase().replace(['-', ' '], "_");
    Some(match n.as_str() {
        "utf_8" | "utf8" | "u8" | "utf" | "cp65001" => "utf-8",
        "ascii" | "us_ascii" | "646" => "ascii",
        "latin_1" | "latin1" | "iso_8859_1" | "iso8859_1" | "8859" | "cp819" | "latin" | "l1" => {
            "latin-1"
        }
        _ => return None,
    })
}

fn encode(s: &str, encoding: &str, errors: &str) -> Result<Vec<u8>> {
    let Some(c) = codec(encoding) else {
        return Err(Error::unsupported(format!(
            "The encoding {}",
            pyrepr::str_repr(encoding)
        )));
    };
    if c == "utf-8" {
        return Ok(s.as_bytes().to_vec());
    }
    let limit = if c == "ascii" { 0x80 } else { 0x100 };
    let mut out = Vec::new();
    for (i, ch) in s.chars().enumerate() {
        let n = ch as u32;
        if n < limit {
            out.push(n as u8);
            continue;
        }
        match errors {
            "ignore" => {}
            "replace" => out.push(b'?'),
            "strict" => {
                return Err(Error::new(
                    "UnicodeEncodeError",
                    format!(
                        "'{}' codec can't encode character {} in position {i}: ordinal not in range({limit})",
                        if c == "ascii" { "ascii" } else { "latin-1" },
                        pyrepr::str_repr(&ch.to_string())
                    ),
                ));
            }
            other => {
                return Err(Error::unsupported(format!(
                    "The error handler {}",
                    pyrepr::str_repr(other)
                )));
            }
        }
    }
    Ok(out)
}

fn decode(data: &[u8], encoding: &str, errors: &str) -> Result<String> {
    let Some(c) = codec(encoding) else {
        return Err(Error::unsupported(format!(
            "The encoding {}",
            pyrepr::str_repr(encoding)
        )));
    };
    match c {
        "latin-1" => Ok(data.iter().map(|b| char::from(*b)).collect()),
        "ascii" => {
            let mut out = String::new();
            for (i, b) in data.iter().enumerate() {
                if *b < 0x80 {
                    out.push(char::from(*b));
                } else {
                    match errors {
                        "ignore" => {}
                        "replace" => out.push('\u{fffd}'),
                        _ => {
                            return Err(Error::new(
                                "UnicodeDecodeError",
                                format!(
                                    "'ascii' codec can't decode byte 0x{b:02x} in position {i}: ordinal not in range(128)"
                                ),
                            ));
                        }
                    }
                }
            }
            Ok(out)
        }
        _ => match std::str::from_utf8(data) {
            Ok(s) => Ok(s.to_string()),
            Err(e) => match errors {
                "replace" => Ok(String::from_utf8_lossy(data).into_owned()),
                "ignore" => Ok(String::from_utf8_lossy(data).replace('\u{fffd}', "")),
                _ => Err(Error::new(
                    "UnicodeDecodeError",
                    format!(
                        "'utf-8' codec can't decode byte 0x{:02x} in position {}: invalid start byte",
                        data.get(e.valid_up_to()).copied().unwrap_or(0),
                        e.valid_up_to()
                    ),
                )),
            },
        },
    }
}

/// Calls `recv.name(*args, **kwargs)`.
pub fn call_method(recv: &Value, name: &str, args: Vec<Value>, kwargs: Kwargs) -> Result<Value> {
    if let Value::Object(o) = recv {
        if let Some(r) = o.call_method(recv, name, args.clone(), kwargs.clone()) {
            return r;
        }
        if let Some(c) = recv.downcast::<objects::Cycler>() {
            return objects::cycler_method(c, name, &args, &kwargs);
        }
        if let Some(g) = recv.downcast::<objects::Generator>() {
            return match name {
                "close" => {
                    crate::callargs::positional("close", &args, &kwargs, 0, 0)?;
                    objects::generator_close(g);
                    Ok(Value::None)
                }
                _ => Err(Error::unsupported(format!("generator.{name}"))),
            };
        }
        if o.type_name() == "range" {
            return seq_count_index(recv, "range", name, args, kwargs);
        }
        if o.type_name() == "_GroupTuple" {
            return seq_count_index(recv, "tuple", name, args, kwargs);
        }
        if let Some(b) = recv.downcast::<Bytes>() {
            if name == "decode" {
                check_arity(
                    "bytes",
                    "decode",
                    args.len(),
                    &kwargs,
                    &["encoding", "errors"],
                )?;
                let enc = arg(&args, &kwargs, 0, "encoding").unwrap_or(Value::str("utf-8"));
                let err = arg(&args, &kwargs, 1, "errors").unwrap_or(Value::str("strict"));
                let enc = need_str(&enc, |v| {
                    format!(
                        "decode() argument 'encoding' must be str, not {}",
                        v.type_name()
                    )
                })?;
                let err = need_str(&err, |v| {
                    format!(
                        "decode() argument 'errors' must be str, not {}",
                        v.type_name()
                    )
                })?;
                return decode(&b.data, enc, err).map(Value::str);
            }
        }
        if let Some(v) = recv.downcast::<DictView>() {
            if name == "isdisjoint" {
                crate::callargs::positional("isdisjoint", &args, &kwargs, 1, 1)?;
                let mine: Vec<Value> = ops::iterate(&Value::Object(o.clone()))?;
                let _ = v;
                let mut it = ops::py_iter(&args[0])?;
                while let Some(x) = it.next()? {
                    for m in &mine {
                        if ops::eq(m, &x)? {
                            return Ok(Value::Bool(false));
                        }
                    }
                }
                return Ok(Value::Bool(true));
            }
        }
        return Err(Error::unsupported(format!("{}.{name}()", recv.type_name())));
    }
    let Some(ty) = type_key(recv) else {
        return Err(Error::unsupported(format!("{}.{name}()", recv.type_name())));
    };
    match ty {
        "str" | "Markup" => str_method(recv, ty, name, args, kwargs),
        "list" => list_method(recv, name, args, kwargs),
        "dict" => dict_method(recv, name, args, kwargs),
        "tuple" => seq_count_index(recv, "tuple", name, args, kwargs),
        "int" => int_method(recv, name, args, kwargs),
        "float" => float_method(recv, name, args, kwargs),
        _ => Err(Error::unsupported(format!("{}.{name}()", recv.type_name()))),
    }
}

fn seq_count_index(
    recv: &Value,
    ty: &str,
    name: &str,
    args: Vec<Value>,
    kwargs: Kwargs,
) -> Result<Value> {
    check_arity(ty, name, args.len(), &kwargs, &[])?;
    let items = ops::iterate(recv)?;
    match name {
        "count" => {
            let mut n = 0;
            for x in &items {
                if ops::same_object(x, &args[0]) || ops::eq(x, &args[0])? {
                    n += 1;
                }
            }
            Ok(Value::int(n))
        }
        "index" => {
            let len = items.len();
            let start = slice_index(args.get(1), 0)?;
            let stop = slice_index(args.get(2), isize::MAX)?;
            let (start, stop) = adjust(start, stop, len);
            let (from, to) = (start.max(0) as usize, (stop.max(0) as usize).min(len));
            for (i, item) in items.iter().enumerate().take(to).skip(from) {
                if ops::same_object(item, &args[0]) || ops::eq(item, &args[0])? {
                    return Ok(Value::int(i as i64));
                }
            }
            Err(Error::value_error(match ty {
                "tuple" => "tuple.index(x): x not in tuple".to_string(),
                "range" => format!("{} is not in range", pyrepr::repr(&args[0])?),
                _ => format!("{} is not in list", pyrepr::repr(&args[0])?),
            }))
        }
        _ => Err(Error::unsupported(format!("{ty}.{name}()"))),
    }
}

fn str_method(
    recv: &Value,
    ty: &str,
    name: &str,
    args: Vec<Value>,
    kwargs: Kwargs,
) -> Result<Value> {
    let markup = ty == "Markup";
    let s = recv.as_str().unwrap_or_default();
    let accepted: &[&str] = match name {
        "split" | "rsplit" => &["sep", "maxsplit"],
        "splitlines" => &["keepends"],
        "expandtabs" => &["tabsize"],
        "encode" => &["encoding", "errors"],
        "format" | "format_map" => &[],
        _ => &[],
    };
    if !matches!(name, "format" | "format_map") {
        check_arity(ty, name, args.len(), &kwargs, accepted)?;
    }
    let plain = |out: String| Value::str(out);
    let kind = |out: String| same_kind(recv, out);
    Ok(match name {
        "upper" => kind(unicode::upper(s)),
        "lower" => kind(unicode::lower(s)),
        "title" => kind(unicode::title(s)),
        "capitalize" => kind(unicode::capitalize(s)),
        "swapcase" => kind(unicode::swapcase(s)),
        "casefold" => kind(unicode::casefold(s)),
        "isalnum" => Value::Bool(!s.is_empty() && s.chars().all(unicode::is_alnum)),
        "isalpha" => Value::Bool(!s.is_empty() && s.chars().all(unicode::is_alpha)),
        "isascii" => Value::Bool(s.is_ascii()),
        "isdecimal" => Value::Bool(!s.is_empty() && s.chars().all(unicode::is_decimal)),
        "isdigit" => Value::Bool(!s.is_empty() && s.chars().all(unicode::is_digit)),
        "isnumeric" => Value::Bool(!s.is_empty() && s.chars().all(unicode::is_numeric)),
        "isidentifier" => Value::Bool(unicode::is_identifier(s)),
        "islower" => Value::Bool(unicode::str_islower(s)),
        "isupper" => Value::Bool(unicode::str_isupper(s)),
        "istitle" => Value::Bool(unicode::str_istitle(s)),
        "isspace" => Value::Bool(!s.is_empty() && s.chars().all(unicode::is_space)),
        "isprintable" => Value::Bool(s.chars().all(unicode::is_printable)),
        "strip" | "lstrip" | "rstrip" => {
            let (l, r) = match name {
                "strip" => (true, true),
                "lstrip" => (true, false),
                _ => (false, true),
            };
            kind(strip_with(s, args.first(), name, l, r)?)
        }
        "center" | "ljust" | "rjust" => {
            let width = width_of(&args[0])?;
            let fill = fill_char(args.get(1).cloned(), markup)?;
            let len = s.chars().count();
            if width <= len {
                kind(s.to_string())
            } else {
                let marg = width - len;
                let (l, r) = match name {
                    "center" => {
                        let left = marg / 2 + (marg & width & 1);
                        (left, marg - left)
                    }
                    "ljust" => (0, marg),
                    _ => (marg, 0),
                };
                kind(pad(s, l, r, fill))
            }
        }
        "zfill" => {
            let width = width_of(&args[0])?;
            let c = chars(s);
            if width <= c.len() {
                kind(s.to_string())
            } else {
                let fill = width - c.len();
                let mut out: String = std::iter::repeat_n('0', fill).collect::<String>() + s;
                if matches!(c.first(), Some('+' | '-')) {
                    let sign = c[0];
                    out = format!(
                        "{sign}{}{}",
                        "0".repeat(fill),
                        c[1..].iter().collect::<String>()
                    );
                }
                kind(out)
            }
        }
        "count" | "find" | "rfind" | "index" | "rindex" => {
            let sub = need_str(&args[0], |v| format!("must be str, not {}", v.type_name()))?;
            let c = chars(s);
            let sc = chars(sub);
            let start = slice_index(args.get(1), 0)?;
            let end = slice_index(args.get(2), isize::MAX)?;
            let (start, end) = adjust(start, end, c.len());
            if name == "count" {
                if end - start < sc.len() as isize {
                    return Ok(Value::int(0));
                }
                let (start, end) = (start as usize, end as usize);
                if sc.is_empty() {
                    return Ok(Value::int((end - start + 1) as i64));
                }
                let mut n = 0;
                let mut i = start;
                while i + sc.len() <= end {
                    if c[i..i + sc.len()] == *sc {
                        n += 1;
                        i += sc.len();
                    } else {
                        i += 1;
                    }
                }
                return Ok(Value::int(n));
            }
            let found = if end - start < sc.len() as isize || start as usize > c.len() {
                None
            } else if name.starts_with('r') {
                rfind_in(&c, &sc, start as usize, end as usize)
            } else {
                find_in(&c, &sc, start as usize, end as usize)
            };
            match (found, name) {
                (Some(i), _) => Value::int(i as i64),
                (None, "find" | "rfind") => Value::int(-1),
                (None, _) => return Err(Error::value_error("substring not found")),
            }
        }
        "startswith" => starts_or_ends(s, "startswith", &args, false)?,
        "endswith" => starts_or_ends(s, "endswith", &args, true)?,
        "split" | "rsplit" => {
            let sep = arg(&args, &kwargs, 0, "sep").unwrap_or(Value::None);
            let maxsplit = arg(&args, &kwargs, 1, "maxsplit").unwrap_or(Value::int(-1));
            let sep_s = match &sep {
                Value::None => None,
                v => Some(need_str(v, |v| {
                    format!("must be str or None, not {}", v.type_name())
                })?),
            };
            let max = index_isize(&maxsplit)?;
            let parts = split(s, sep_s, max, name == "rsplit")?;
            ops::check_size(parts.len())?;
            Value::list(
                parts
                    .into_iter()
                    .map(|p| {
                        if markup {
                            Value::markup(p)
                        } else {
                            Value::str(p)
                        }
                    })
                    .collect(),
            )
        }
        "splitlines" => {
            let keep = match arg(&args, &kwargs, 0, "keepends") {
                Some(v) => !index_value(&v)?.is_zero(),
                None => false,
            };
            Value::list(
                unicode::splitlines(s, keep)
                    .into_iter()
                    .map(|p| {
                        if markup {
                            Value::markup(p)
                        } else {
                            Value::str(p)
                        }
                    })
                    .collect(),
            )
        }
        "partition" | "rpartition" => {
            let sep = if markup {
                crate::markup::escape_value(&args[0])?
            } else {
                need_str(&args[0], |v| format!("must be str, not {}", v.type_name()))?.to_string()
            };
            if sep.is_empty() {
                return Err(Error::value_error("empty separator"));
            }
            let parts = if name == "partition" {
                match s.find(&sep) {
                    Some(i) => (
                        s[..i].to_string(),
                        sep.clone(),
                        s[i + sep.len()..].to_string(),
                    ),
                    None => (s.to_string(), String::new(), String::new()),
                }
            } else {
                match s.rfind(&sep) {
                    Some(i) => (
                        s[..i].to_string(),
                        sep.clone(),
                        s[i + sep.len()..].to_string(),
                    ),
                    None => (String::new(), String::new(), s.to_string()),
                }
            };
            Value::tuple(vec![kind(parts.0), kind(parts.1), kind(parts.2)])
        }
        "replace" => {
            let old = need_str(&args[0], |v| {
                format!("replace() argument 1 must be str, not {}", v.type_name())
            })?
            .to_string();
            let new = if markup {
                crate::markup::escape_value(&args[1])?
            } else {
                need_str(&args[1], |v| {
                    format!("replace() argument 2 must be str, not {}", v.type_name())
                })?
                .to_string()
            };
            let count = match args.get(2) {
                Some(c) => index_isize(c)?,
                None => -1,
            };
            kind(py_replace(s, &old, &new, count)?)
        }
        "removeprefix" | "removesuffix" => {
            let x = need_str(&args[0], |v| {
                format!("{name}() argument must be str, not {}", v.type_name())
            })?;
            let out = if name == "removeprefix" {
                s.strip_prefix(x).unwrap_or(s)
            } else {
                s.strip_suffix(x).unwrap_or(s)
            };
            kind(out.to_string())
        }
        "expandtabs" => {
            let tabsize = match arg(&args, &kwargs, 0, "tabsize") {
                Some(v) => index_isize(&v)?,
                None => 8,
            };
            let mut out = String::new();
            let mut col: isize = 0;
            for ch in s.chars() {
                match ch {
                    '\t' => {
                        if tabsize > 0 {
                            let n = tabsize - col % tabsize;
                            ops::check_size(out.len() + n as usize)?;
                            out.extend(std::iter::repeat_n(' ', n as usize));
                            col += n;
                        }
                    }
                    '\n' | '\r' => {
                        out.push(ch);
                        col = 0;
                    }
                    c => {
                        out.push(c);
                        col += 1;
                    }
                }
            }
            kind(out)
        }
        "join" => {
            let mut it = match ops::py_iter(&args[0]) {
                Ok(it) => it,
                Err(e) if e.kind == "TypeError" => {
                    return Err(Error::type_error("can only join an iterable"));
                }
                Err(e) => return Err(e),
            };
            let mut parts = Vec::new();
            let mut i = 0;
            while let Some(item) = it.next()? {
                if markup {
                    parts.push(crate::markup::escape_value(&item)?);
                } else {
                    match item.as_str() {
                        Some(x) => parts.push(x.to_string()),
                        None => {
                            return Err(Error::type_error(format!(
                                "sequence item {i}: expected str instance, {} found",
                                item.type_name()
                            )));
                        }
                    }
                }
                i += 1;
            }
            let out = parts.join(s);
            ops::check_size(out.len())?;
            kind(out)
        }
        "encode" => {
            let enc = arg(&args, &kwargs, 0, "encoding").unwrap_or(Value::str("utf-8"));
            let err = arg(&args, &kwargs, 1, "errors").unwrap_or(Value::str("strict"));
            let enc = need_str(&enc, |v| {
                format!(
                    "encode() argument 'encoding' must be str, not {}",
                    v.type_name()
                )
            })?;
            let err = need_str(&err, |v| {
                format!(
                    "encode() argument 'errors' must be str, not {}",
                    v.type_name()
                )
            })?;
            Value::object(Bytes {
                data: encode(s, enc, err)?,
            })
        }
        "format" => crate::attrs::str_format(recv, args, kwargs)?,
        "format_map" => {
            if !kwargs.is_empty() {
                return Err(Error::type_error("format_map() takes no keyword arguments"));
            }
            if args.len() != 1 {
                return Err(Error::type_error(format!(
                    "format_map() takes exactly one argument ({} given)",
                    args.len()
                )));
            }
            crate::attrs::str_format_map(recv, args[0].clone())?
        }
        "unescape" if markup => plain(crate::markup::unescape(s)),
        "striptags" if markup => plain(crate::markup::striptags(s)),
        "escape" if markup => crate::markup::escape(&args[0])?,
        "__html__" if markup => recv.clone(),
        other => return Err(Error::unsupported(format!("str.{other}()"))),
    })
}

/// `str.replace(old, new, count)`.
pub fn py_replace(s: &str, old: &str, new: &str, count: isize) -> Result<String> {
    let max = if count < 0 {
        usize::MAX
    } else {
        count as usize
    };
    if old.is_empty() {
        // Inserts `new` before every character and at the end.
        let c = chars(s);
        let mut out = String::new();
        let mut n = 0;
        for (i, ch) in c.iter().enumerate() {
            if n < max {
                out.push_str(new);
                n += 1;
            }
            out.push(*ch);
            let _ = i;
            ops::check_size(out.len())?;
        }
        if n < max {
            out.push_str(new);
        }
        return Ok(out);
    }
    let occurrences = s.matches(old).count().min(max);
    ops::check_size(s.len() + occurrences.saturating_mul(new.len()))?;
    Ok(if max == usize::MAX {
        s.replace(old, new)
    } else {
        s.replacen(old, new, max)
    })
}

fn list_method(recv: &Value, name: &str, args: Vec<Value>, kwargs: Kwargs) -> Result<Value> {
    let Value::List(list) = recv else {
        return Err(Error::unsupported(format!("{}.{name}()", recv.type_name())));
    };
    let accepted: &[&str] = if name == "sort" {
        &["key", "reverse"]
    } else {
        &[]
    };
    check_arity("list", name, args.len(), &kwargs, accepted)?;
    Ok(match name {
        "append" => {
            let mut l = list.borrow_mut();
            ops::check_size(l.len() + 1)?;
            l.push(args[0].clone());
            Value::None
        }
        "clear" => {
            list.borrow_mut().clear();
            Value::None
        }
        "copy" => Value::list(list.borrow().clone()),
        "count" | "index" => return seq_count_index(recv, "list", name, args, kwargs),
        "extend" => {
            let items = ops::iterate(&args[0])?;
            let mut l = list.borrow_mut();
            ops::check_size(l.len() + items.len())?;
            l.extend(items);
            Value::None
        }
        "insert" => {
            let i = index_isize(&args[0])?;
            let mut l = list.borrow_mut();
            let n = l.len() as isize;
            let at = if i < 0 { (i + n).max(0) } else { i.min(n) } as usize;
            ops::check_size(l.len() + 1)?;
            l.insert(at, args[1].clone());
            Value::None
        }
        "pop" => {
            let mut l = list.borrow_mut();
            if l.is_empty() {
                return Err(Error::index("pop from empty list"));
            }
            let n = l.len() as isize;
            let i = match args.first() {
                Some(v) => index_exact(v)?,
                None => -1,
            };
            let i = if i < 0 { i + n } else { i };
            if i < 0 || i >= n {
                return Err(Error::index("pop index out of range"));
            }
            l.remove(i as usize)
        }
        "remove" => {
            let items = list.borrow().clone();
            for (i, x) in items.iter().enumerate() {
                if ops::same_object(x, &args[0]) || ops::eq(x, &args[0])? {
                    list.borrow_mut().remove(i);
                    return Ok(Value::None);
                }
            }
            return Err(Error::value_error("list.remove(x): x not in list"));
        }
        "reverse" => {
            list.borrow_mut().reverse();
            Value::None
        }
        "sort" => {
            let key = arg(&[], &kwargs, 0, "key").unwrap_or(Value::None);
            let reverse = match arg(&[], &kwargs, 0, "reverse") {
                Some(v) => !index_value(&v)?.is_zero(),
                None => false,
            };
            let items = std::mem::take(&mut *list.borrow_mut());
            let keys = if matches!(key, Value::None) {
                items.clone()
            } else {
                let mut keys = Vec::with_capacity(items.len());
                for it in &items {
                    keys.push(crate::attrs::call(&key, vec![it.clone()], Vec::new())?);
                }
                keys
            };
            let sorted = ops::sort_by_keys(items, keys, reverse)?;
            *list.borrow_mut() = sorted;
            Value::None
        }
        other => return Err(Error::unsupported(format!("list.{other}()"))),
    })
}

/// `dict.update(other, **kwargs)` / `dict(other, **kwargs)`.
pub fn dict_update(d: &mut Dict, other: Option<&Value>, kwargs: Kwargs) -> Result<()> {
    if let Some(other) = other {
        match other {
            Value::Dict(o) => {
                let entries = o.borrow().entries.clone();
                for (k, v) in entries {
                    d.set(k, v)?;
                }
            }
            v if v.downcast::<crate::notify::EventObject>().is_some() => {
                return Err(Error::unsupported(
                    "Updating a dict from a NotificationEvent",
                ));
            }
            v => {
                let mut it = ops::py_iter(v)?;
                let mut i = 0;
                while let Some(item) = it.next()? {
                    let pair = match ops::py_iter(&item) {
                        Ok(p) => p.collect()?,
                        Err(e) if e.kind == "TypeError" => {
                            return Err(Error::type_error(format!(
                                "cannot convert dictionary update sequence element #{i} to a sequence"
                            )));
                        }
                        Err(e) => return Err(e),
                    };
                    if pair.len() != 2 {
                        return Err(Error::value_error(format!(
                            "dictionary update sequence element #{i} has length {}; 2 is required",
                            pair.len()
                        )));
                    }
                    d.set(pair[0].clone(), pair[1].clone())?;
                    i += 1;
                }
            }
        }
    }
    for (k, v) in kwargs {
        d.set(Value::str(&*k), v)?;
    }
    Ok(())
}

fn dict_method(recv: &Value, name: &str, args: Vec<Value>, kwargs: Kwargs) -> Result<Value> {
    let Value::Dict(dict) = recv else {
        return Err(Error::unsupported(format!("{}.{name}()", recv.type_name())));
    };
    let accepted: &[&str] = &[];
    if name != "update" {
        check_arity("dict", name, args.len(), &kwargs, accepted)?;
    } else if args.len() > 1 {
        return Err(Error::type_error(format!(
            "update expected at most 1 argument, got {}",
            args.len()
        )));
    }
    let view = |kind| {
        Value::object(DictView {
            kind,
            dict: dict.clone(),
        })
    };
    Ok(match name {
        "get" => match dict.borrow().get(&args[0])? {
            Some(v) => v,
            None => args.get(1).cloned().unwrap_or(Value::None),
        },
        "keys" => view(ViewKind::Keys),
        "values" => view(ViewKind::Values),
        "items" => view(ViewKind::Items),
        "copy" => {
            let d = dict.borrow().clone();
            Value::from_dict(d)
        }
        "clear" => {
            dict.borrow_mut().entries.clear();
            Value::None
        }
        "update" => {
            let mut d = dict.borrow().clone();
            dict_update(&mut d, args.first(), kwargs)?;
            *dict.borrow_mut() = d;
            Value::None
        }
        "pop" => {
            let pos = dict.borrow().position(&args[0])?;
            match pos {
                Some(i) => dict.borrow_mut().entries.remove(i).1,
                None => match args.get(1) {
                    Some(d) => d.clone(),
                    None => return Err(Error::key(pyrepr::repr(&args[0])?)),
                },
            }
        }
        "popitem" => match dict.borrow_mut().entries.pop() {
            Some((k, v)) => Value::tuple(vec![k, v]),
            None => return Err(Error::key("'popitem(): dictionary is empty'")),
        },
        "setdefault" => {
            let existing = dict.borrow().get(&args[0])?;
            match existing {
                Some(v) => v,
                None => {
                    let v = args.get(1).cloned().unwrap_or(Value::None);
                    dict.borrow_mut().set(args[0].clone(), v.clone())?;
                    v
                }
            }
        }
        "fromkeys" => {
            let mut d = Dict::default();
            let value = args.get(1).cloned().unwrap_or(Value::None);
            for k in ops::iterate(&args[0])? {
                d.set(k, value.clone())?;
            }
            Value::from_dict(d)
        }
        other => return Err(Error::unsupported(format!("dict.{other}()"))),
    })
}

fn int_method(recv: &Value, name: &str, args: Vec<Value>, kwargs: Kwargs) -> Result<Value> {
    check_arity("int", name, args.len(), &kwargs, &[])?;
    let i = ops::as_int(recv).unwrap_or_default();
    Ok(match name {
        "bit_length" => Value::int(i.bits() as i64),
        "bit_count" => Value::int(i.abs().to_str_radix(2).matches('1').count() as i64),
        "conjugate" => Value::Int(i),
        "as_integer_ratio" => Value::tuple(vec![Value::Int(i), Value::int(1)]),
        other => return Err(Error::unsupported(format!("int.{other}()"))),
    })
}

fn float_method(recv: &Value, name: &str, args: Vec<Value>, kwargs: Kwargs) -> Result<Value> {
    check_arity("float", name, args.len(), &kwargs, &[])?;
    let Value::Float(f) = recv else {
        return Err(Error::unsupported(format!("float.{name}()")));
    };
    Ok(match name {
        "is_integer" => Value::Bool(f.is_finite() && f.fract() == 0.0),
        "conjugate" => Value::Float(*f),
        other => return Err(Error::unsupported(format!("float.{other}()"))),
    })
}

/// The public attributes of a built-in value that are not methods.
pub fn value_attribute(recv: &Value, name: &str) -> Option<Value> {
    match (recv, name) {
        (Value::Int(_) | Value::Bool(_), "real" | "numerator") => ops::as_int(recv).map(Value::Int),
        (Value::Int(_) | Value::Bool(_), "imag") => Some(Value::int(0)),
        (Value::Int(_) | Value::Bool(_), "denominator") => Some(Value::int(1)),
        (Value::Float(f), "real") => Some(Value::Float(*f)),
        (Value::Float(_), "imag") => Some(Value::Float(0.0)),
        (Value::StrEnum(e), "name") => Some(Value::str(&e.name)),
        (Value::StrEnum(e), "value") => Some(Value::str(&e.value)),
        (Value::StrEnum(e), member) => {
            e.members.iter().find(|(n, _)| *n == member).map(|(n, v)| {
                Value::StrEnum(Rc::new(crate::value::StrEnum {
                    class: e.class,
                    module: e.module,
                    name: (*n).to_string(),
                    value: (*v).to_string(),
                    members: e.members,
                }))
            })
        }
        (Value::Dict(d), "default_factory") if d.borrow().default_str => {
            Some(objects::Builtin::value(objects::BuiltinKind::Str))
        }
        _ => None,
    }
}

/// `getattr(value, name)` for a built-in value: a bound method, a property,
/// or `None` when the type has no such public attribute.
pub fn builtin_getattr(recv: &Value, name: &str) -> Option<Result<Value>> {
    if let Some(v) = value_attribute(recv, name) {
        return Some(Ok(v));
    }
    let ty = type_key(recv)?;
    let ty = if matches!(recv, Value::StrEnum(_)) {
        "str"
    } else {
        ty
    };
    let has = tables::ARITY
        .binary_search_by(|(t, m, _, _)| (*t, *m).cmp(&(ty, name)))
        .is_ok()
        || (ty == "Markup" && matches!(name, "unescape" | "striptags" | "escape"));
    if has {
        return Some(Ok(Method::value(recv, name)));
    }
    let _ = PyIter::Done;
    None
}
