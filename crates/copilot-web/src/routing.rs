//! Starlette's routing, reproduced once for the whole service.
//!
//! uvicorn hands Starlette `scope["path"]`, the request path percent-decoded
//! (`urllib.parse.unquote`: UTF-8, undecodable bytes replaced), and
//! Starlette's `Router.app` walks the app's routes in declaration order:
//! the first route whose path *and* method match answers; else the first
//! whose path matches answers 405 with that route's `Allow`; else — with
//! `redirect_slashes=False` — the 404. A path's `{x}` is `[^/]+`, `{x:path}`
//! `.*`, and its `$` also matches before a final newline (Python `re`).
//!
//! axum routes the raw path with its own priorities (a static segment beats
//! a parameter, whatever the declaration order), so the decision is taken
//! here, on the decoded path, against the Python app's own route table
//! ([`RouteTable`], built from what `scripts/gen-standalone-vectors.py`
//! records), and axum is then handed a path that leads it to the same
//! route: the decoded path quoted again ([`RouteTable::routing_path`]),
//! with every parameter's characters percent-encoded when a more specific
//! template would otherwise take it — no static segment can match an
//! encoded one, and axum decodes a parameter once, so the handler sees
//! Starlette's value. An encoded `/` is thereby just a `/`, as in Starlette.

use std::sync::OnceLock;

use regex::Regex;

/// What kind of route a table entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// A FastAPI `APIRoute` (its methods exactly as declared; FastAPI adds
    /// no `HEAD`).
    Api,
    /// A plain Starlette `Route` (FastAPI's documentation routes: `GET` and
    /// the `HEAD` Starlette adds).
    Route,
    /// A `Mount` (any method; the mounted app decides).
    Mount,
}

/// A parameter's convertor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Convertor {
    /// `str`: `[^/]+`.
    Str,
    /// `path`: `.*`.
    Path,
    /// `int`: `[0-9]+`.
    Int,
    /// `float`: `[0-9]+(\.[0-9]+)?`.
    Float,
    /// `uuid`.
    Uuid,
}

impl Convertor {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "str" => Some(Self::Str),
            "path" => Some(Self::Path),
            "int" => Some(Self::Int),
            "float" => Some(Self::Float),
            "uuid" => Some(Self::Uuid),
            _ => None,
        }
    }

    fn regex(self) -> &'static str {
        match self {
            Self::Str => "[^/]+",
            Self::Path => ".*",
            Self::Int => "[0-9]+",
            Self::Float => r"[0-9]+(?:\.[0-9]+)?",
            Self::Uuid => {
                "[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}"
            }
        }
    }
}

/// One piece of a compiled path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    /// Text matched literally.
    Static(String),
    /// A parameter (its index among the route's parameters).
    Param(usize),
}

/// One route of the Python app.
#[derive(Debug, Clone)]
pub struct PyRoute {
    /// Its kind.
    pub kind: RouteKind,
    /// The path as declared (a mount's prefix, without `/{path:path}`).
    pub path: String,
    /// Its methods in `set` order (empty for a mount: any method).
    pub methods: Vec<String>,
    regex: Regex,
    /// The text before the first parameter: every path the route matches
    /// starts with it (checked before the regex).
    literal: String,
    params: Vec<(String, Convertor)>,
    pieces: Vec<Piece>,
    /// Per `/`-separated segment: 0 static, 1 parameter, 2 catch-all (the
    /// order axum's router prefers them in).
    shape: Vec<u8>,
}

impl PyRoute {
    /// Whether a request with `method` matches fully (the path is assumed to
    /// match).
    pub fn allows(&self, method: &str) -> bool {
        self.methods.is_empty() || self.methods.iter().any(|m| m == method)
    }

    /// `", ".join(route.methods)`: the `Allow` header of its 405.
    pub fn allow_header(&self) -> String {
        self.methods.join(", ")
    }

    /// The parameter names, in the path's order.
    pub fn param_names(&self) -> impl Iterator<Item = &str> {
        self.params.iter().map(|(n, _)| n.as_str())
    }
}

/// Starlette's decision for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The first route matching path and method; its path parameters, as
    /// strings, in the path's order.
    Full {
        /// The route's index in the table.
        index: usize,
        /// `(name, value)` per parameter.
        params: Vec<(String, String)>,
    },
    /// No full match: the first route whose path matched (a 405).
    Partial {
        /// The route's index in the table.
        index: usize,
    },
    /// No route's path matched (a 404).
    None,
}

/// The Python app's routes, in Starlette's order.
#[derive(Debug, Clone)]
pub struct RouteTable {
    routes: Vec<PyRoute>,
    /// The prefixes Python's routers are mounted at (`/api/<module>`, `/docs`,
    /// …): a path under one belongs to the Python app's routing.
    prefixes: Vec<String>,
}

/// Starlette's `PARAM_REGEX` (`None` only if the constant failed to
/// compile, which a test rules out).
fn param_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{([a-zA-Z_][a-zA-Z0-9_]*)(:[a-zA-Z_][a-zA-Z0-9_]*)?\}").ok())
        .as_ref()
}

/// `compile_path(path)`: the regex (`$` as Python reads it), the pieces and
/// the parameters.
#[allow(clippy::type_complexity)]
fn compile_path(path: &str) -> Result<(Regex, Vec<Piece>, Vec<(String, Convertor)>), String> {
    let mut re = String::from(r"\A");
    let mut pieces = Vec::new();
    let mut params: Vec<(String, Convertor)> = Vec::new();
    let mut idx = 0;
    let params_re = param_regex().ok_or("PARAM_REGEX does not compile")?;
    for caps in params_re.captures_iter(path) {
        let Some(whole) = caps.get(0) else { continue };
        let name = caps.get(1).map_or("", |m| m.as_str());
        let conv_name = caps
            .get(2)
            .map_or("str", |m| m.as_str().trim_start_matches(':'));
        let conv = Convertor::from_name(conv_name)
            .ok_or_else(|| format!("Unknown path convertor '{conv_name}'"))?;
        let text = &path[idx..whole.start()];
        re.push_str(&regex::escape(text));
        if !text.is_empty() {
            pieces.push(Piece::Static(text.to_string()));
        }
        re.push('(');
        re.push_str(conv.regex());
        re.push(')');
        if params.iter().any(|(n, _)| n == name) {
            return Err(format!("Duplicated param name {name} at path {path}"));
        }
        pieces.push(Piece::Param(params.len()));
        params.push((name.to_string(), conv));
        idx = whole.end();
    }
    let rest = &path[idx..];
    re.push_str(&regex::escape(rest));
    if !rest.is_empty() {
        pieces.push(Piece::Static(rest.to_string()));
    }
    // Python's `$` (no MULTILINE): the end, or just before a final newline.
    re.push_str(r"\n?\z");
    let regex = Regex::new(&re).map_err(|e| e.to_string())?;
    Ok((regex, pieces, params))
}

fn shape_of(path: &str) -> Vec<u8> {
    path.split('/')
        .map(|seg| {
            if seg.contains(":path}") {
                2
            } else if seg.contains('{') {
                1
            } else {
                0
            }
        })
        .collect()
}

/// The prefix a route claims for the Python app: `/api/<module>` for an API
/// path, else its first segment.
fn prefix_of(path: &str) -> Option<String> {
    let segs: Vec<&str> = path.split('/').collect();
    // ["", "api", "module", …] / ["", "docs", …]
    let take = if segs.get(1) == Some(&"api") { 3 } else { 2 };
    if segs.len() < take {
        return None;
    }
    let prefix = segs[..take].join("/");
    if prefix.contains('{') || prefix.len() <= 1 {
        return None;
    }
    Some(prefix)
}

impl RouteTable {
    /// The table from `(kind, path, methods)` in Starlette's order.
    pub fn new(
        entries: impl IntoIterator<Item = (RouteKind, String, Vec<String>)>,
    ) -> Result<Self, String> {
        let mut routes = Vec::new();
        let mut prefixes: Vec<String> = Vec::new();
        for (kind, path, methods) in entries {
            let compiled = match kind {
                RouteKind::Mount => format!("{}/{{path:path}}", path.trim_end_matches('/')),
                _ => path.clone(),
            };
            let (regex, pieces, params) = compile_path(&compiled)?;
            if let Some(p) = prefix_of(&compiled) {
                if !prefixes.contains(&p) {
                    prefixes.push(p);
                }
            }
            let literal = match pieces.first() {
                Some(Piece::Static(text)) => text.clone(),
                _ => String::new(),
            };
            routes.push(PyRoute {
                kind,
                literal,
                path,
                methods: if kind == RouteKind::Mount {
                    Vec::new()
                } else {
                    methods
                },
                regex,
                params,
                pieces,
                shape: shape_of(&compiled),
            });
        }
        Ok(Self { routes, prefixes })
    }

    /// Every route, in order.
    pub fn routes(&self) -> &[PyRoute] {
        &self.routes
    }

    /// The route at `index`.
    pub fn route(&self, index: usize) -> Option<&PyRoute> {
        self.routes.get(index)
    }

    /// `Router.app`'s decision for `method` on the decoded `path`.
    pub fn decide(&self, method: &str, path: &str) -> Decision {
        let mut partial = None;
        for (index, route) in self.routes.iter().enumerate() {
            if !path.starts_with(&route.literal) {
                continue;
            }
            let Some(caps) = route.regex.captures(path) else {
                continue;
            };
            if route.allows(method) {
                let params = route
                    .params
                    .iter()
                    .enumerate()
                    .map(|(i, (name, _))| {
                        let value = caps.get(i + 1).map_or("", |m| m.as_str());
                        (name.clone(), value.to_string())
                    })
                    .collect();
                return Decision::Full { index, params };
            }
            if partial.is_none() {
                partial = Some(index);
            }
        }
        match partial {
            Some(index) => Decision::Partial { index },
            None => Decision::None,
        }
    }

    /// Whether `path` (decoded) lies in the Python app's routing: under one
    /// of its routers' prefixes, or the root.
    pub fn owns(&self, path: &str) -> bool {
        path == "/"
            || self.prefixes.iter().any(|p| {
                path == p
                    || path
                        .strip_prefix(p.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            })
    }

    /// The most specific route axum's router would prefer for `path` among
    /// the table's (static segments before parameters before catch-alls),
    /// whatever its method.
    fn axum_preference(&self, path: &str) -> Option<usize> {
        self.routes
            .iter()
            .enumerate()
            .filter(|(_, r)| path.starts_with(&r.literal) && r.regex.is_match(path))
            .min_by(|(ia, a), (ib, b)| a.shape.cmp(&b.shape).then(ia.cmp(ib)))
            .map(|(i, _)| i)
    }

    /// The path axum is handed for a full match on route `index` with
    /// `params`: the route's text with each value quoted, every character of
    /// a value encoded when axum would otherwise prefer a more specific
    /// template (one with a static segment where this one has a parameter).
    /// A newline Starlette's `$` let through after the route's text is left
    /// out (the route matched without it).
    pub fn routing_path(&self, index: usize, params: &[(String, String)], decoded: &str) -> String {
        let Some(route) = self.routes.get(index) else {
            return quote_decoded(decoded);
        };
        if route.kind == RouteKind::Mount {
            return quote_decoded(decoded.strip_suffix('\n').unwrap_or(decoded));
        }
        let force = self
            .axum_preference(decoded)
            .and_then(|i| self.routes.get(i))
            .is_some_and(|preferred| preferred.shape != route.shape);
        let mut out = String::new();
        for piece in &route.pieces {
            match piece {
                Piece::Static(text) => out.push_str(&quote_decoded(text)),
                Piece::Param(i) => {
                    let value = params.get(*i).map_or("", |(_, v)| v.as_str());
                    let is_path = route.params.get(*i).map(|(_, c)| *c) == Some(Convertor::Path);
                    out.push_str(&quote_param(value, force, is_path));
                }
            }
        }
        out
    }
}

/// `scope["path"]`: the raw path percent-decoded as `urllib.parse.unquote`
/// decodes it (each `%XX`, then UTF-8 with undecodable bytes replaced).
pub fn scope_path(raw: &str) -> String {
    if !raw.contains('%') {
        return raw.to_string();
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| char::from(b).to_digit(16);
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(u8::try_from(h * 16 + l).unwrap_or(0));
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Characters written as they are in a path axum is handed (RFC 3986's
/// unreserved characters and the sub-delimiters a path may hold).
fn path_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

fn push_encoded(out: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push('%');
    out.push(char::from(HEX[usize::from(b >> 4)]));
    out.push(char::from(HEX[usize::from(b & 0xF)]));
}

/// A decoded path quoted again for axum (`/` kept, `%` and every other
/// character a path does not hold as such encoded): what axum routes and
/// decodes back to `decoded`.
pub fn quote_decoded(decoded: &str) -> String {
    let mut out = String::with_capacity(decoded.len());
    for &b in decoded.as_bytes() {
        if b == b'/' || path_safe(b) {
            out.push(char::from(b));
        } else {
            push_encoded(&mut out, b);
        }
    }
    out
}

/// A parameter's value quoted for axum; with `force`, every byte encoded
/// (a `path` parameter keeps its `/`s, which separate its segments).
fn quote_param(value: &str, force: bool, is_path: bool) -> String {
    if !force {
        if is_path {
            return quote_decoded(value);
        }
        let mut out = String::with_capacity(value.len());
        for &b in value.as_bytes() {
            if path_safe(b) {
                out.push(char::from(b));
            } else {
                push_encoded(&mut out, b);
            }
        }
        return out;
    }
    let mut out = String::with_capacity(value.len() * 3);
    for &b in value.as_bytes() {
        if is_path && b == b'/' {
            out.push('/');
        } else {
            push_encoded(&mut out, b);
        }
    }
    out
}

/// Request extension: the request target as the client sent it (Starlette's
/// `scope["raw_path"]` and query string), before the path was decoded.
#[derive(Debug, Clone)]
pub struct RawUri(pub http::Uri);

/// Request extension: `scope["path"]`, the decoded path Starlette routed and
/// `str(request.url)` names.
#[derive(Debug, Clone)]
pub struct ScopePath(pub String);

/// Request extension: Starlette's decision for the request.
#[derive(Debug, Clone)]
pub struct Routed {
    /// The decision.
    pub decision: Decision,
    /// The template of the route that decided (a full or partial match of a
    /// route that is not a mount): what Python's request timer records.
    pub template: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> RouteTable {
        RouteTable::new([
            (
                RouteKind::Route,
                "/docs".into(),
                vec!["HEAD".into(), "GET".into()],
            ),
            (
                RouteKind::Api,
                "/api/agents/{agent_id}".into(),
                vec!["GET".into()],
            ),
            (
                RouteKind::Api,
                "/api/agents/sync".into(),
                vec!["POST".into()],
            ),
            (
                RouteKind::Api,
                "/api/agents/{agent_id}/delete".into(),
                vec!["DELETE".into()],
            ),
            (
                RouteKind::Api,
                "/api/agents/bulk/delete".into(),
                vec!["POST".into()],
            ),
            (
                RouteKind::Api,
                "/api/x/name/{n:path}".into(),
                vec!["GET".into()],
            ),
            (RouteKind::Mount, "/scoutsuite-report".into(), vec![]),
            (RouteKind::Api, "/".into(), vec!["GET".into()]),
        ])
        .unwrap()
    }

    #[test]
    fn decides_as_starlette() {
        let t = table();
        assert_eq!(
            t.decide("GET", "/api/agents/sync"),
            Decision::Full {
                index: 1,
                params: vec![("agent_id".into(), "sync".into())]
            }
        );
        assert_eq!(
            t.decide("PUT", "/api/agents/sync"),
            Decision::Partial { index: 1 }
        );
        assert_eq!(
            t.decide("HEAD", "/api/agents/x"),
            Decision::Partial { index: 1 }
        );
        assert!(matches!(
            t.decide("HEAD", "/docs"),
            Decision::Full { index: 0, .. }
        ));
        assert_eq!(t.decide("GET", "/api/agents/"), Decision::None);
        assert_eq!(t.decide("GET", "/api/agents/a/b"), Decision::None);
        // `$` before a final newline; `[^/]+` takes the newline.
        assert!(matches!(
            t.decide("GET", "/docs\n"),
            Decision::Full { index: 0, .. }
        ));
        assert_eq!(
            t.decide("GET", "/api/agents/x\n"),
            Decision::Full {
                index: 1,
                params: vec![("agent_id".into(), "x\n".into())]
            }
        );
        assert_eq!(t.decide("GET", "/docs\n\n"), Decision::None);
        assert!(matches!(
            t.decide("DELETE", "/scoutsuite-report/a/b"),
            Decision::Full { index: 6, .. }
        ));
        assert_eq!(t.decide("GET", "/scoutsuite-report"), Decision::None);
        assert_eq!(t.decide("POST", "/"), Decision::Partial { index: 7 });
    }

    #[test]
    fn routing_paths_lead_axum_to_starlettes_route() {
        let t = table();
        // `GET /api/agents/sync` is the `{agent_id}` route in Starlette; axum
        // would prefer the static `sync`: the value is encoded.
        let Decision::Full { index, params } = t.decide("GET", "/api/agents/sync") else {
            panic!()
        };
        assert_eq!(
            t.routing_path(index, &params, "/api/agents/sync"),
            "/api/agents/%73%79%6E%63"
        );
        let Decision::Full { index, params } = t.decide("GET", "/api/agents/a b") else {
            panic!()
        };
        assert_eq!(
            t.routing_path(index, &params, "/api/agents/a b"),
            "/api/agents/a%20b"
        );
        let Decision::Full { index, params } = t.decide("DELETE", "/api/agents/bulk/delete") else {
            panic!()
        };
        assert_eq!(
            t.routing_path(index, &params, "/api/agents/bulk/delete"),
            "/api/agents/%62%75%6C%6B/delete"
        );
        let Decision::Full { index, params } = t.decide("GET", "/api/x/name/a/b%") else {
            panic!()
        };
        assert_eq!(
            t.routing_path(index, &params, "/api/x/name/a/b%"),
            "/api/x/name/a/b%25"
        );
        let Decision::Full { index, params } = t.decide("GET", "/docs\n") else {
            panic!()
        };
        assert_eq!(t.routing_path(index, &params, "/docs\n"), "/docs");
    }

    #[test]
    fn decodes_as_unquote() {
        assert_eq!(scope_path("/a%2Fb"), "/a/b");
        assert_eq!(scope_path("/a%2fb%20c"), "/a/b c");
        assert_eq!(scope_path("/%C3%A4%FF%zz%"), "/ä\u{fffd}%zz%");
        assert_eq!(scope_path("/a%2"), "/a%2");
        assert_eq!(scope_path("/%41"), "/A");
    }

    #[test]
    fn owns_the_routers_prefixes() {
        let t = table();
        assert!(t.owns("/api/agents/a/b") && t.owns("/api/agents") && t.owns("/docs/x"));
        assert!(t.owns("/") && t.owns("/scoutsuite-report"));
        assert!(!t.owns("/api/agentsx") && !t.owns("/api/legacy-only/x") && !t.owns("/x"));
    }
}
