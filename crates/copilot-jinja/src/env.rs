//! Environments with a loader, for the report renderers: a
//! `FileSystemLoader` over a known set of files (or a `ChoiceLoader` of
//! several), `autoescape` fixed or `select_autoescape(["html", "htm",
//! "xml"], default=True)`, and Jinja's default `Undefined` or
//! `StrictUndefined`.
//!
//! `extends`, `block`/`super()`/`self`, `import`, `from … import … [with
//! context]` and `include` behave as the code Jinja2 3.1.6 generates for
//! them: the parent's root renders with the child's context after the
//! child's body, a module is the imported template's root rendered in a
//! context of its own (sharing the importer's variables `with context`),
//! and a missing name is the loader's `TemplateNotFound` with its message.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use crate::compiler::{self, Template};
use crate::datetime::{Moment, PyMoment};
use crate::error::{Error, Result};
use crate::notify::Input;
use crate::pyrepr::str_repr;
use crate::value::{UndefinedMode, Value};
use crate::{arena, vm};

/// A value handed to a report template: [`Input`]'s kinds, plus tuples and
/// the `datetime` values of the ORM's rows.
#[derive(Debug, Clone, PartialEq)]
pub enum Data {
    /// `None`.
    None,
    /// `bool`.
    Bool(bool),
    /// `int`.
    Int(i128),
    /// `float`.
    Float(f64),
    /// `str`.
    Str(String),
    /// `markupsafe.Markup`.
    Markup(String),
    /// `list`.
    List(Vec<Data>),
    /// `tuple`.
    Tuple(Vec<Data>),
    /// `dict` with string keys, in insertion order.
    Dict(Vec<(String, Data)>),
    /// `datetime.datetime` (naive).
    DateTime(chrono::NaiveDateTime),
    /// `datetime.date`.
    Date(chrono::NaiveDate),
}

impl From<&Input> for Data {
    fn from(i: &Input) -> Self {
        match i {
            Input::None => Data::None,
            Input::Bool(b) => Data::Bool(*b),
            Input::Int(n) => Data::Int(*n),
            Input::Float(f) => Data::Float(*f),
            Input::Str(s) => Data::Str(s.clone()),
            Input::Markup(s) => Data::Markup(s.clone()),
            Input::List(items) => Data::List(items.iter().map(Data::from).collect()),
            Input::Dict(pairs) => Data::Dict(
                pairs
                    .iter()
                    .map(|(k, v)| (k.clone(), Data::from(v)))
                    .collect(),
            ),
        }
    }
}

impl From<&str> for Data {
    fn from(s: &str) -> Self {
        Data::Str(s.to_string())
    }
}

impl From<String> for Data {
    fn from(s: String) -> Self {
        Data::Str(s)
    }
}

impl From<Option<String>> for Data {
    fn from(s: Option<String>) -> Self {
        s.map_or(Data::None, Data::Str)
    }
}

/// The template value of a [`Data`].
pub(crate) fn data_value(d: &Data) -> Value {
    match d {
        Data::None => Value::None,
        Data::Bool(b) => Value::Bool(*b),
        Data::Int(n) => Value::Int(num_bigint_dig::BigInt::from(*n)),
        Data::Float(f) => Value::Float(*f),
        Data::Str(s) => Value::str(s),
        Data::Markup(s) => Value::markup(s),
        Data::List(items) => Value::list(items.iter().map(data_value).collect()),
        Data::Tuple(items) => Value::tuple(items.iter().map(data_value).collect()),
        Data::Dict(pairs) => Value::str_dict(
            pairs
                .iter()
                .map(|(k, v)| (k.as_str(), data_value(v)))
                .collect(),
        ),
        Data::DateTime(d) => PyMoment::value(Moment::DateTime(*d)),
        Data::Date(d) => PyMoment::value(Moment::Date(*d)),
    }
}

/// The environment's `autoescape`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Autoescape {
    /// `autoescape=False` (Jinja's default).
    Off,
    /// `autoescape=True`.
    On,
    /// `select_autoescape(["html", "htm", "xml"], default=True)`: every
    /// template, string templates included.
    SelectHtml,
}

impl Autoescape {
    /// The decision for a template loaded under `name` (`None`: a string).
    pub fn for_template(self, name: Option<&str>) -> bool {
        match self {
            Autoescape::Off => false,
            Autoescape::On => true,
            // `.html`/`.htm`/`.xml` escape, and so does every other name
            // (`default=True`) and every string (`default_for_string=True`).
            Autoescape::SelectHtml => {
                let _ = name;
                true
            }
        }
    }
}

/// One `FileSystemLoader` directory: its path (for the not-found message)
/// and its files, by path relative to it.
#[derive(Debug, Clone)]
pub struct Directory {
    /// `searchpath`, as the message prints it.
    pub path: String,
    /// `(relative path, source)`.
    pub files: Vec<(String, String)>,
}

/// An environment: its loader (none, one directory, or a `ChoiceLoader`
/// of directories), `autoescape` and its undefined class.
#[derive(Debug, Clone)]
pub struct Environment {
    directories: Arc<Vec<Directory>>,
    autoescape: Autoescape,
    strict_undefined: bool,
}

impl Environment {
    /// `SandboxedEnvironment(autoescape=…)` with Jinja's default `Undefined`
    /// and no loader.
    pub fn new(autoescape: Autoescape) -> Self {
        Self {
            directories: Arc::new(Vec::new()),
            autoescape,
            strict_undefined: false,
        }
    }

    /// `undefined=StrictUndefined`.
    pub fn strict(mut self) -> Self {
        self.strict_undefined = true;
        self
    }

    /// `FileSystemLoader(path)` (a second call makes it a `ChoiceLoader`).
    pub fn with_directory(mut self, dir: Directory) -> Self {
        Arc::make_mut(&mut self.directories).push(dir);
        self
    }

    /// `env.get_template(name).render(**vars)`.
    pub fn render(&self, name: &str, vars: &[(String, Data)]) -> Result<String> {
        let env = self.clone();
        let name = name.to_string();
        let vars = vars.to_vec();
        on_large_stack(move || {
            let _guard = arena::RenderGuard::new();
            let _mode = UndefinedMode::set(env.strict_undefined);
            let loaded = Rc::new(Loaded::new(env));
            let t = loaded.get_template(&name)?;
            render(loaded, &t, &vars)
        })
    }

    /// `env.from_string(source).render(**vars)`.
    pub fn render_string(&self, source: &str, vars: &[(String, Data)]) -> Result<String> {
        let env = self.clone();
        let source = source.to_string();
        let vars = vars.to_vec();
        on_large_stack(move || {
            let _guard = arena::RenderGuard::new();
            let _mode = UndefinedMode::set(env.strict_undefined);
            let autoescape = env.autoescape.for_template(None);
            let t = Rc::new(compiler::compile(&source, autoescape)?);
            let loaded = Rc::new(Loaded::new(env));
            render(loaded, &t, &vars)
        })
    }
}

fn render(loaded: Rc<Loaded>, t: &Rc<Template>, vars: &[(String, Data)]) -> Result<String> {
    let vars: Vec<(Rc<str>, Value)> = vars
        .iter()
        .map(|(k, v)| (Rc::from(k.as_str()), data_value(v)))
        .collect();
    let has_loader = !loaded.env.directories.is_empty();
    let rendered = vm::render_in(has_loader.then_some(loaded), t, vars, usize::MAX)?;
    Ok(rendered.text)
}

/// A render's view of its environment: the loader and the templates it
/// compiled (`Environment.cache`).
pub(crate) struct Loaded {
    env: Environment,
    cache: RefCell<HashMap<String, Rc<Template>>>,
}

impl Loaded {
    fn new(env: Environment) -> Self {
        Self {
            env,
            cache: RefCell::new(HashMap::new()),
        }
    }

    /// `environment.get_template(name)`.
    pub(crate) fn get_template(&self, name: &str) -> Result<Rc<Template>> {
        if let Some(t) = self.cache.borrow().get(name) {
            return Ok(t.clone());
        }
        let source = self.get_source(name)?;
        let autoescape = self.env.autoescape.for_template(Some(name));
        let t = Rc::new(compiler::compile_named(&source, autoescape, name)?);
        self.cache.borrow_mut().insert(name.to_string(), t.clone());
        Ok(t)
    }

    /// The loader's `get_source`: `FileSystemLoader`'s, through a
    /// `ChoiceLoader` when there are several directories.
    fn get_source(&self, name: &str) -> Result<String> {
        let not_found = |message: String| Error::new("TemplateNotFound", message);
        // `split_template_path`.
        let mut pieces: Vec<&str> = Vec::new();
        for piece in name.split('/') {
            if piece == ".." {
                return Err(not_found(name.to_string()));
            }
            if !piece.is_empty() && piece != "." {
                pieces.push(piece);
            }
        }
        let relative = pieces.join("/");
        for dir in self.env.directories.iter() {
            if let Some((_, source)) = dir.files.iter().find(|(p, _)| *p == relative) {
                return Ok(source.clone());
            }
        }
        let dirs = &self.env.directories;
        if dirs.len() == 1 {
            return Err(not_found(format!(
                "{} not found in search path: {}",
                str_repr(name),
                str_repr(&dirs[0].path)
            )));
        }
        Err(not_found(name.to_string()))
    }
}

/// The stack a render runs on: deep macro recursion is Python's limit to
/// reach, not the thread's.
const STACK_SIZE: usize = 256 << 20;

fn on_large_stack<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    let handle = std::thread::Builder::new()
        .name("copilot-jinja".into())
        .stack_size(STACK_SIZE)
        .spawn(f)
        .map_err(|e| {
            Error::new(
                "RuntimeError",
                format!("could not start the template engine: {e}"),
            )
        })?;
    handle
        .join()
        .unwrap_or_else(|_| Err(Error::new("RuntimeError", "the template engine failed")))
}
