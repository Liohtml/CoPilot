//! The case-template library — `app/incidents/services/template_library.py`:
//! the investigation playbooks of `socfortress/CoPilot-Case-Templates`
//! (YAML on GitHub), fetched, parsed, normalised and cached in this process
//! for 30 minutes, as the Python process caches its own copy.
//!
//! A refresh reads the repository tree (`GET /repos/…/git/trees/main?
//! recursive=1`), keeps the blobs ending in `.yaml`/`.yml` under `sysmon/`,
//! fetches each raw file concurrently (`asyncio.gather`), parses it with
//! PyYAML's `safe_load` (`copilot-yaml`) and normalises it
//! (`_normalize_entry`); a file that fails anywhere is listed in
//! `invalid_paths`, a duplicate key too. Every call is httpx 0.28's
//! (`copilot_threat_intel::httpx`, one `AsyncClient(timeout=30.0, headers=
//! {"Accept": "application/vnd.github+json"})` per refresh; `GITHUB_TOKEN` is
//! not sent, as in Python). A failure of the tree request (or of Python's
//! operations on its JSON) fails the refresh and leaves the cache as it was.
//!
//! The response models (`CaseTemplateLibraryEntry`, `CaseTemplateLibraryTask`)
//! and the import's `CaseTemplateCreate` / `CaseTemplateTaskCreate` are
//! Pydantic's lax validation over the YAML values (`copilot_searches::pyd`),
//! with their `ValidationError` texts.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::NaiveDateTime;
use num_bigint_dig::BigInt;

use copilot_searches::py::{self, s};
use copilot_searches::pyd::{Default as D, Field, Invalid, Model, Ty, validate};
use copilot_threat_intel::httpx::{self, HttpxError};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_yaml::Value;

/// `GITHUB_REPO`.
pub const GITHUB_REPO: &str = "socfortress/CoPilot-Case-Templates";
/// `GITHUB_BRANCH`.
pub const GITHUB_BRANCH: &str = "main";
/// `LIBRARY_PATH_PREFIXES`.
pub const LIBRARY_PATH_PREFIXES: &[&str] = &["sysmon/"];
/// `CACHE_TTL_MINUTES`.
pub const CACHE_TTL_MINUTES: i64 = 30;
/// The client's `timeout=30.0`.
const TIMEOUT: Duration = Duration::from_secs(30);

/// A normalised task (`_normalize_entry`'s `normalised_tasks` item).
#[derive(Debug, Clone)]
pub struct Task {
    /// `title.strip()`.
    pub title: String,
    /// `raw.get("description") or None`.
    pub description: Value,
    /// `raw.get("guidelines") or None`.
    pub guidelines: Value,
    /// `bool(raw.get("mandatory", False))`.
    pub mandatory: bool,
    /// An `int` (a `bool` is one) not below 0.
    pub order_index: Value,
}

/// A normalised library entry.
#[derive(Debug, Clone)]
pub struct Entry {
    /// `key.strip()`.
    pub key: String,
    /// `name.strip()`.
    pub name: String,
    /// `data.get("description") or None`.
    pub description: Value,
    /// `data.get("source") or None`.
    pub source: Value,
    /// The `match:` block's field, stripped.
    pub match_field: Option<String>,
    /// `str()` of the `match:` block's value.
    pub match_value: Option<String>,
    /// The `tags:` mapping (`{}` when it is not one).
    pub tags: Value,
    /// The tasks, by `order_index`.
    pub tasks: Vec<Task>,
    /// `_file_path`: where the entry was read.
    pub file_path: String,
}

/// The cache's state.
#[derive(Debug, Default)]
struct Snapshot {
    /// In load order (Python's dict).
    entries: Vec<Entry>,
    invalid: Vec<String>,
    last_refresh: Option<NaiveDateTime>,
}

/// `TemplateLibraryCache`: this process's copy of the library.
#[derive(Debug)]
pub struct Library {
    api: String,
    raw: String,
    snapshot: RwLock<Snapshot>,
    /// `self._lock`: one refresh at a time.
    refresh_lock: tokio::sync::Mutex<()>,
}

/// `datetime.utcnow()`.
fn utcnow() -> NaiveDateTime {
    chrono::Utc::now().naive_utc()
}

impl Library {
    /// The library at `GITHUB_API_BASE` / `GITHUB_RAW_BASE` (overridable for
    /// the parity harness: `COPILOT_GITHUB_{API,RAW}_URL`).
    pub fn new(api: impl Into<String>, raw: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            api: api.into(),
            raw: raw.into(),
            snapshot: RwLock::new(Snapshot::default()),
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    fn read<T>(&self, f: impl FnOnce(&Snapshot) -> T) -> T {
        match self.snapshot.read() {
            Ok(guard) => f(&guard),
            Err(poisoned) => f(&poisoned.into_inner()),
        }
    }

    /// `is_stale`.
    pub fn is_stale(&self) -> bool {
        self.read(|s| match s.last_refresh {
            None => true,
            Some(at) => utcnow() - at > chrono::Duration::minutes(CACHE_TTL_MINUTES),
        })
    }

    /// `ensure_loaded`.
    pub async fn ensure_loaded(&self) -> PyResult<()> {
        if self.is_stale() {
            self.refresh().await?;
        }
        Ok(())
    }

    /// `last_refresh`.
    pub fn last_refresh(&self) -> Option<NaiveDateTime> {
        self.read(|s| s.last_refresh)
    }

    /// `invalid_paths`.
    pub fn invalid_paths(&self) -> Vec<String> {
        self.read(|s| s.invalid.clone())
    }

    /// `list_library_entries`' sort: by `key`.
    pub fn sorted_entries(&self) -> Vec<Entry> {
        let mut entries = self.read(|s| s.entries.clone());
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        entries
    }

    /// `get_entry(key)`.
    pub fn entry(&self, key: &str) -> Option<Entry> {
        self.read(|s| s.entries.iter().find(|e| e.key == key).cloned())
    }

    /// `refresh()`: the number of valid entries loaded.
    pub async fn refresh(&self) -> PyResult<usize> {
        let _guard = self.refresh_lock.lock().await;
        tracing::info!(
            "Refreshing case-template library from github.com/{GITHUB_REPO}@{GITHUB_BRANCH}"
        );
        let client = httpx::Client::new(TIMEOUT).map_err(HttpxError::into_py)?;
        let tree_url = format!(
            "{}/repos/{GITHUB_REPO}/git/trees/{GITHUB_BRANCH}?recursive=1",
            self.api
        );
        let response = httpx::send_on(&client, github_get(tree_url))
            .await
            .map_err(HttpxError::into_py)?;
        response.raise_for_status().map_err(HttpxError::into_py)?;
        let tree = py::from_py(&response.json()?);
        let paths = yaml_paths(&tree)?;
        tracing::info!("Library tree has {} YAML file(s) to parse", paths.len());
        let results =
            futures::future::join_all(paths.iter().map(|p| self.fetch_and_parse(&client, p))).await;
        let mut entries: Vec<Entry> = Vec::new();
        let mut invalid: Vec<String> = Vec::new();
        for (path, result) in paths.iter().zip(results) {
            let Some(mut entry) = result else {
                invalid.push(path.clone());
                continue;
            };
            if entries.iter().any(|e| e.key == entry.key) {
                tracing::warn!("Library: duplicate key '{}' in {path}, skipping", entry.key);
                invalid.push(path.clone());
                continue;
            }
            entry.file_path = path.clone();
            entries.push(entry);
        }
        let loaded = entries.len();
        tracing::info!(
            "Library loaded: {loaded} valid entr(ies), {} skipped",
            invalid.len()
        );
        let mut guard = match self.snapshot.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Snapshot {
            entries,
            invalid,
            last_refresh: Some(utcnow()),
        };
        Ok(loaded)
    }

    /// `_fetch_and_parse`: `None` for whatever `gather` would have caught or
    /// the function returned `None` for.
    async fn fetch_and_parse(&self, client: &httpx::Client, path: &str) -> Option<Entry> {
        let url = format!("{}/{GITHUB_REPO}/{GITHUB_BRANCH}/{path}", self.raw);
        let response = match httpx::send_on(client, github_get(url)).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Library: failed to fetch/parse {path}: {}", e.message);
                return None;
            }
        };
        if let Err(e) = response.raise_for_status() {
            tracing::warn!("Library: failed to fetch/parse {path}: {}", e.message);
            return None;
        }
        // A `YAMLError` is `None`; anything else `safe_load` raises reaches
        // `gather`: invalid either way.
        let data = copilot_yaml::safe_load(&response.text()).ok()?;
        if !data.is_dict() {
            tracing::warn!("Library: {path} top-level is not a mapping, skipping");
            return None;
        }
        normalize(&data)
    }
}

fn github_get(url: String) -> httpx::Request {
    httpx::Request::new(http::Method::GET, url)
        .header("Accept", Some("application/vnd.github+json"))
        .timeout(TIMEOUT)
}

/// The tree's YAML paths, with Python's operations (and their exceptions) on
/// whatever JSON came back.
fn yaml_paths(tree: &Value) -> PyResult<Vec<String>> {
    let items = py::get(tree, "tree", Value::List(Arc::new(Vec::new())))?;
    let mut out = Vec::new();
    for item in py::iterate(&items)? {
        let kind = py::get(&item, "type", Value::None)?;
        if !kind.py_eq(&s("blob")) {
            continue;
        }
        let path = py::get(&item, "path", s(""))?;
        let Value::Str(text) = &path else {
            return Err(py::no_attr(&path, "endswith"));
        };
        if !(text.ends_with(".yaml") || text.ends_with(".yml")) {
            continue;
        }
        if LIBRARY_PATH_PREFIXES.iter().any(|p| text.starts_with(p)) {
            out.push(text.clone());
        }
    }
    Ok(out)
}

/// `isinstance(v, str) and v.strip()`: the stripped text.
fn nonblank(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::Str(t)) if !py::py_strip(t).is_empty() => Some(py::py_strip(t).to_string()),
        _ => None,
    }
}

/// `value or None`.
fn or_none(v: Option<&Value>) -> Value {
    match v {
        Some(v) if v.truthy() => v.clone(),
        _ => Value::None,
    }
}

/// An `int` (or a `bool`, an `int` in Python) as a number.
fn as_int(v: &Value) -> Option<BigInt> {
    match v {
        Value::Int(i) => Some(i.clone()),
        Value::Bool(b) => Some(BigInt::from(u8::from(*b))),
        _ => None,
    }
}

/// `_normalize_entry(data)`.
pub fn normalize(data: &Value) -> Option<Entry> {
    let key = nonblank(data.get("key"))?;
    let name = nonblank(data.get("name"))?;
    let raw_tasks = match data.get("tasks") {
        Some(v) if v.truthy() => match v {
            Value::List(items) => items.to_vec(),
            _ => return None,
        },
        _ => Vec::new(),
    };
    let mut tasks: Vec<(BigInt, Task)> = Vec::new();
    for raw in &raw_tasks {
        if !raw.is_dict() {
            continue;
        }
        let Some(title) = nonblank(raw.get("title")) else {
            continue;
        };
        let Some(order_index) = raw.get("order_index") else {
            continue;
        };
        let Some(order) = as_int(order_index) else {
            continue;
        };
        if order < BigInt::from(0) {
            continue;
        }
        tasks.push((
            order,
            Task {
                title,
                description: or_none(raw.get("description")),
                guidelines: or_none(raw.get("guidelines")),
                mandatory: raw.get("mandatory").is_some_and(Value::truthy),
                order_index: order_index.clone(),
            },
        ));
    }
    tasks.sort_by(|a, b| a.0.cmp(&b.0));
    let tags = match data.get("tags") {
        Some(t) if t.is_dict() => t.clone(),
        _ => Value::Dict(Arc::new(Vec::new())),
    };
    let (mut match_field, mut match_value) = (None, None);
    if let Some(block) = data.get("match").filter(|b| b.is_dict()) {
        if let (Some(field), Some(value)) = (nonblank(block.get("field")), block.get("value")) {
            if !matches!(value, Value::None) {
                match_field = Some(field);
                match_value = Some(value.py_str());
            }
        }
    }
    Some(Entry {
        key,
        name,
        description: or_none(data.get("description")),
        source: or_none(data.get("source")),
        match_field,
        match_value,
        tags,
        tasks: tasks.into_iter().map(|(_, t)| t).collect(),
        file_path: String::new(),
    })
}

// --- the models -------------------------------------------------------------------------

const OPT_STR: Ty = Ty::Opt(&Ty::Str);

/// `CaseTemplateLibraryTask`.
pub static LIBRARY_TASK: Model = Model {
    title: "CaseTemplateLibraryTask",
    fields: &[
        Field::req("title", Ty::Str).max_len(500),
        Field::def("description", OPT_STR, D::None),
        Field::def("guidelines", OPT_STR, D::None),
        Field::def("mandatory", Ty::Bool, D::Bool(false)),
        Field::req("order_index", Ty::Int).range(Some(0), None),
    ],
    after: None,
};

/// `CaseTemplateLibraryEntry` (its `tasks` are the task models already built).
pub static LIBRARY_ENTRY: Model = Model {
    title: "CaseTemplateLibraryEntry",
    fields: &[
        Field::req("key", Ty::Str),
        Field::req("name", Ty::Str).max_len(255),
        Field::def("description", OPT_STR, D::None),
        Field::def("source", OPT_STR, D::None).max_len(50),
        Field::def("match_field", OPT_STR, D::None).max_len(255),
        Field::def("match_value", OPT_STR, D::None),
        Field::def("tags", Ty::DictOf(&Ty::Str, &Ty::Any), D::EmptyDict),
        Field::def("tasks", Ty::List(&Ty::Any), D::EmptyList),
        Field::def("file_path", OPT_STR, D::None),
    ],
    after: None,
};

/// `CaseTemplateTaskCreate`.
pub static TASK_CREATE: Model = Model {
    title: "CaseTemplateTaskCreate",
    fields: &[
        Field::req("title", Ty::Str).max_len(500),
        Field::def("description", OPT_STR, D::None),
        Field::def("guidelines", OPT_STR, D::None),
        Field::def("mandatory", Ty::Bool, D::Bool(false)),
        Field::def("order_index", Ty::Int, D::Int(0)).range(Some(0), None),
    ],
    after: None,
};

/// `CaseTemplateCreate` (its `tasks` are the task models already built).
pub static TEMPLATE_CREATE: Model = Model {
    title: "CaseTemplateCreate",
    fields: &[
        Field::req("name", Ty::Str).max_len(255),
        Field::def("description", OPT_STR, D::None),
        Field::def("customer_code", OPT_STR, D::None).max_len(50),
        Field::def("source", OPT_STR, D::None).max_len(50),
        Field::def("is_default", Ty::Bool, D::Bool(false)),
        Field::def("match_field", OPT_STR, D::None).max_len(255),
        Field::def("match_value", OPT_STR, D::None),
        Field::def("tasks", Ty::List(&Ty::Any), D::EmptyList),
    ],
    after: None,
};

fn dict(items: Vec<(&str, Value)>) -> Value {
    py::dict(items)
}

fn opt(v: &Option<String>) -> Value {
    v.as_ref().map_or(Value::None, |t| s(t.clone()))
}

fn task_kwargs(t: &Task) -> Value {
    dict(vec![
        ("title", s(t.title.clone())),
        ("description", t.description.clone()),
        ("guidelines", t.guidelines.clone()),
        ("mandatory", Value::Bool(t.mandatory)),
        ("order_index", t.order_index.clone()),
    ])
}

/// `_library_entry_to_response(entry)`: the model's dump, or the first
/// `ValidationError` (a task's, built first, then the entry's).
pub fn entry_response(e: &Entry) -> Result<Value, Invalid> {
    let tasks = e
        .tasks
        .iter()
        .map(|t| validate(&LIBRARY_TASK, &task_kwargs(t)))
        .collect::<Result<Vec<_>, _>>()?;
    validate(
        &LIBRARY_ENTRY,
        &dict(vec![
            ("key", s(e.key.clone())),
            ("name", s(e.name.clone())),
            ("description", e.description.clone()),
            ("source", e.source.clone()),
            ("match_field", opt(&e.match_field)),
            ("match_value", opt(&e.match_value)),
            ("tags", e.tags.clone()),
            ("tasks", Value::List(Arc::new(tasks))),
            ("file_path", s(e.file_path.clone())),
        ]),
    )
}

/// The import's `CaseTemplateCreate(...)`: a global, non-default template.
pub fn import_payload(
    e: &Entry,
) -> Result<copilot_incidents::case_templates::TemplateCreate, Invalid> {
    use copilot_incidents::case_templates::{TaskCreate, TemplateCreate};
    let tasks = e
        .tasks
        .iter()
        .map(|t| validate(&TASK_CREATE, &task_kwargs(t)))
        .collect::<Result<Vec<_>, _>>()?;
    let dump = validate(
        &TEMPLATE_CREATE,
        &dict(vec![
            ("name", s(e.name.clone())),
            ("description", e.description.clone()),
            ("customer_code", Value::None),
            ("source", e.source.clone()),
            ("is_default", Value::Bool(false)),
            ("match_field", opt(&e.match_field)),
            ("match_value", opt(&e.match_value)),
            ("tasks", Value::List(Arc::new(tasks.clone()))),
        ]),
    )?;
    let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    Ok(TemplateCreate {
        name: text(&dump, "name").unwrap_or_default(),
        description: text(&dump, "description"),
        customer_code: None,
        source: text(&dump, "source"),
        is_default: false,
        match_field: text(&dump, "match_field"),
        match_value: text(&dump, "match_value"),
        tasks: tasks
            .iter()
            .map(|t| TaskCreate {
                title: text(t, "title").unwrap_or_default(),
                description: text(t, "description"),
                guidelines: text(t, "guidelines"),
                mandatory: matches!(t.get("mandatory"), Some(Value::Bool(true))),
                order_index: t
                    .get("order_index")
                    .and_then(Value::as_i64)
                    .unwrap_or(i64::MAX),
            })
            .collect(),
    })
}

/// A refresh failure as the routes put it in their messages (`str(e)`).
pub fn failure_text(e: &PyExc) -> String {
    e.display()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vectors {
        entries: Vec<EntryCase>,
    }

    #[derive(Deserialize)]
    struct EntryCase {
        yaml: String,
        normalized: bool,
        response: Option<serde_json::Value>,
        response_error: Option<String>,
        import: Option<serde_json::Value>,
        import_error: Option<String>,
    }

    fn dump_json(v: &Value) -> serde_json::Value {
        serde_json::from_str(&v.to_pydantic_json().unwrap()).unwrap()
    }

    #[test]
    fn entries_are_normalised_and_validated_as_python_does() {
        let vectors: Vectors =
            serde_json::from_str(include_str!("case_templates_vectors.json")).unwrap();
        for case in vectors.entries {
            let data = copilot_yaml::safe_load(&case.yaml).unwrap();
            let entry = if data.is_dict() {
                normalize(&data)
            } else {
                None
            };
            assert_eq!(entry.is_some(), case.normalized, "{:?}", case.yaml);
            let Some(mut entry) = entry else { continue };
            entry.file_path = "sysmon/x.yaml".into();
            match entry_response(&entry) {
                Ok(dump) => assert_eq!(Some(dump_json(&dump)), case.response, "{:?}", case.yaml),
                Err(e) => assert_eq!(Some(e.text()), case.response_error, "{:?}", case.yaml),
            }
            match import_payload(&entry) {
                Ok(req) => {
                    let expected = case.import.unwrap();
                    assert_eq!(
                        expected["name"],
                        serde_json::json!(req.name),
                        "{:?}",
                        case.yaml
                    );
                    assert_eq!(expected["description"], serde_json::json!(req.description));
                    assert_eq!(expected["source"], serde_json::json!(req.source));
                    assert_eq!(expected["match_field"], serde_json::json!(req.match_field));
                    assert_eq!(expected["match_value"], serde_json::json!(req.match_value));
                    let tasks = expected["tasks"].as_array().unwrap();
                    assert_eq!(tasks.len(), req.tasks.len());
                    for (want, got) in tasks.iter().zip(&req.tasks) {
                        assert_eq!(want["title"], serde_json::json!(got.title));
                        assert_eq!(want["description"], serde_json::json!(got.description));
                        assert_eq!(want["guidelines"], serde_json::json!(got.guidelines));
                        assert_eq!(want["mandatory"], serde_json::json!(got.mandatory));
                        assert_eq!(want["order_index"], serde_json::json!(got.order_index));
                    }
                }
                Err(e) => assert_eq!(Some(e.text()), case.import_error, "{:?}", case.yaml),
            }
        }
    }
}
