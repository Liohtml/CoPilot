//! Binding call arguments to a Python signature, with CPython 3.11's
//! `TypeError` messages.

use std::rc::Rc;

use crate::error::{Error, Result};
use crate::pyrepr::str_repr;
use crate::value::Value;

/// A Python function's signature.
#[derive(Debug, Clone, Default)]
pub struct Sig<'a> {
    /// The qualified name used in messages (`do_truncate`, `Joiner.__init__`).
    pub name: &'a str,
    /// Positional-or-keyword parameters, in order.
    pub params: &'a [&'a str],
    /// How many of `params` are positional-only.
    pub posonly: usize,
    /// Defaults of the last `params`.
    pub defaults: Vec<Value>,
    /// `*args`.
    pub varargs: bool,
    /// Keyword-only parameters and their defaults.
    pub kwonly: Vec<(&'a str, Option<Value>)>,
    /// `**kwargs`.
    pub varkw: bool,
}

/// Arguments bound to a signature.
#[derive(Debug, Clone, Default)]
pub struct Bound {
    /// One value per positional parameter.
    pub args: Vec<Value>,
    /// Extra positional arguments (`*args`).
    pub varargs: Vec<Value>,
    /// Extra keyword arguments (`**kwargs`).
    pub varkw: Vec<(Rc<str>, Value)>,
}

fn names_list(names: &[&str]) -> String {
    let quoted: Vec<String> = names.iter().map(|n| str_repr(n)).collect();
    match quoted.len() {
        1 => quoted[0].clone(),
        2 => format!("{} and {}", quoted[0], quoted[1]),
        n => format!(
            "{}, {}, and {}",
            quoted[..n - 2].join(", "),
            quoted[n - 2],
            quoted[n - 1]
        ),
    }
}

/// CPython's `initialize_locals`.
pub fn bind_sig(sig: &Sig<'_>, args: Vec<Value>, kwargs: Vec<(Rc<str>, Value)>) -> Result<Bound> {
    let argcount = sig.params.len();
    let given = args.len();
    let mut slots: Vec<Option<Value>> = vec![None; argcount];
    let mut kwslots: Vec<Option<Value>> = vec![None; sig.kwonly.len()];
    let mut extra_pos = Vec::new();
    for (i, a) in args.into_iter().enumerate() {
        if i < argcount {
            slots[i] = Some(a);
        } else if sig.varargs {
            extra_pos.push(a);
        }
    }
    let mut varkw = Vec::new();
    for (key, value) in kwargs {
        if let Some(j) = sig
            .params
            .iter()
            .position(|p| *p == &*key)
            .filter(|j| *j >= sig.posonly)
        {
            if slots[j].is_some() {
                return Err(Error::type_error(format!(
                    "{}() got multiple values for argument {}",
                    sig.name,
                    str_repr(&key)
                )));
            }
            slots[j] = Some(value);
            continue;
        }
        if let Some(j) = sig.kwonly.iter().position(|(p, _)| *p == &*key) {
            if kwslots[j].is_some() {
                return Err(Error::type_error(format!(
                    "{}() got multiple values for argument {}",
                    sig.name,
                    str_repr(&key)
                )));
            }
            kwslots[j] = Some(value);
            continue;
        }
        if sig.varkw {
            varkw.push((key, value));
            continue;
        }
        let posonly_named: Vec<&str> = sig.params[..sig.posonly]
            .iter()
            .copied()
            .filter(|p| *p == &*key)
            .collect();
        if !posonly_named.is_empty() {
            return Err(Error::type_error(format!(
                "{}() got some positional-only arguments passed as keyword arguments: '{}'",
                sig.name,
                posonly_named.join(", ")
            )));
        }
        return Err(Error::type_error(format!(
            "{}() got an unexpected keyword argument {}",
            sig.name,
            str_repr(&key)
        )));
    }
    if given > argcount && !sig.varargs {
        let defcount = sig.defaults.len();
        let kwonly_given = kwslots.iter().filter(|s| s.is_some()).count();
        let (sig_text, plural) = if defcount > 0 {
            (
                format!("from {} to {}", argcount - defcount, argcount),
                true,
            )
        } else {
            (argcount.to_string(), argcount != 1)
        };
        let kwonly_text = if kwonly_given > 0 {
            format!(
                " positional argument{} (and {} keyword-only argument{})",
                if given != 1 { "s" } else { "" },
                kwonly_given,
                if kwonly_given != 1 { "s" } else { "" }
            )
        } else {
            String::new()
        };
        return Err(Error::type_error(format!(
            "{}() takes {} positional argument{} but {}{} {} given",
            sig.name,
            sig_text,
            if plural { "s" } else { "" },
            given,
            kwonly_text,
            if given == 1 && kwonly_given == 0 {
                "was"
            } else {
                "were"
            }
        )));
    }
    let first_default = argcount - sig.defaults.len().min(argcount);
    let missing: Vec<&str> = (0..first_default)
        .filter(|i| slots[*i].is_none())
        .map(|i| sig.params[i])
        .collect();
    if !missing.is_empty() {
        return Err(Error::type_error(format!(
            "{}() missing {} required positional argument{}: {}",
            sig.name,
            missing.len(),
            if missing.len() == 1 { "" } else { "s" },
            names_list(&missing)
        )));
    }
    let mut out_args = Vec::with_capacity(argcount);
    for (i, slot) in slots.into_iter().enumerate() {
        out_args.push(match slot {
            Some(v) => v,
            None => sig.defaults[i - first_default].clone(),
        });
    }
    let missing_kw: Vec<&str> = sig
        .kwonly
        .iter()
        .zip(&kwslots)
        .filter(|((_, d), s)| s.is_none() && d.is_none())
        .map(|((n, _), _)| *n)
        .collect();
    if !missing_kw.is_empty() {
        return Err(Error::type_error(format!(
            "{}() missing {} required keyword-only argument{}: {}",
            sig.name,
            missing_kw.len(),
            if missing_kw.len() == 1 { "" } else { "s" },
            names_list(&missing_kw)
        )));
    }
    Ok(Bound {
        args: out_args,
        varargs: extra_pos,
        varkw,
    })
}

/// Binds `args` (the receiver included) to `params` with `defaults`.
pub fn bind_values(
    name: &str,
    params: &[&str],
    defaults: &[Value],
    args: Vec<Value>,
    kwargs: Vec<(Rc<str>, Value)>,
) -> Result<Vec<Value>> {
    let sig = Sig {
        name,
        params,
        defaults: defaults.to_vec(),
        ..Sig::default()
    };
    Ok(bind_sig(&sig, args, kwargs)?.args)
}

/// Checks only the shape of a call with `nargs` positional arguments.
pub fn bind(
    name: &str,
    params: &[&str],
    defaults: &[Value],
    nargs: usize,
    kwargs: &[(Rc<str>, Value)],
) -> Result<()> {
    bind_values(
        name,
        params,
        defaults,
        vec![Value::None; nargs],
        kwargs.to_vec(),
    )
    .map(|_| ())
}

/// A C function taking exactly one argument (`METH_O`).
pub fn exactly_one(name: &str, mut args: Vec<Value>, kwargs: &[(Rc<str>, Value)]) -> Result<Value> {
    if !kwargs.is_empty() {
        return Err(Error::type_error(format!(
            "{name}() takes no keyword arguments"
        )));
    }
    if args.len() != 1 {
        return Err(Error::type_error(format!(
            "{name}() takes exactly one argument ({} given)",
            args.len()
        )));
    }
    Ok(args.remove(0))
}

/// A C method without keyword arguments taking `min..=max` positional ones.
pub fn positional(
    name: &str,
    args: &[Value],
    kwargs: &[(Rc<str>, Value)],
    min: usize,
    max: usize,
) -> Result<()> {
    if !kwargs.is_empty() {
        return Err(Error::type_error(format!(
            "{name}() takes no keyword arguments"
        )));
    }
    let n = args.len();
    if n < min || n > max {
        let msg = if min == max {
            if min == 0 {
                format!("{name}() takes no arguments ({n} given)")
            } else if min == 1 {
                format!("{name}() takes exactly one argument ({n} given)")
            } else {
                format!("{name} expected {min} arguments, got {n}")
            }
        } else if n < min {
            format!(
                "{name} expected at least {min} argument{}, got {n}",
                if min == 1 { "" } else { "s" }
            )
        } else {
            format!(
                "{name} expected at most {max} argument{}, got {n}",
                if max == 1 { "" } else { "s" }
            )
        };
        return Err(Error::type_error(msg));
    }
    Ok(())
}
