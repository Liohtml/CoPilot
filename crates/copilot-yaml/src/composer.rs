//! `yaml/composer.py`, `yaml/nodes.py` and `yaml/resolver.py` (the
//! implicit resolvers of `yaml.resolver.Resolver`; `SafeLoader` registers no
//! path resolvers): events into a graph of nodes, aliases pointing at the
//! anchored node itself.

use std::sync::OnceLock;

use regex::Regex;

use crate::error::{LoadError, Mark, MarkedError, MarkedKind, PyException};
use crate::parser::{E, EventKind, Parser};
use crate::repr::str_repr;

pub(crate) const STR_TAG: &str = "tag:yaml.org,2002:str";
pub(crate) const SEQ_TAG: &str = "tag:yaml.org,2002:seq";
pub(crate) const MAP_TAG: &str = "tag:yaml.org,2002:map";

/// Python's recursion limit, as composition meets it: two frames per level of
/// nesting (`compose_node` and `compose_*_node`) out of CPython's 1000, less
/// the frames of the caller. The exact depth depends on how deep the caller's
/// stack already is; this is where a plain `yaml.safe_load` gives up.
pub const MAX_DEPTH: usize = 490;

#[derive(Debug, Clone)]
pub(crate) enum NodeValue {
    Scalar(String),
    Sequence(Vec<usize>),
    Mapping(Vec<(usize, usize)>),
}

#[derive(Debug, Clone)]
pub(crate) struct Node {
    pub(crate) tag: String,
    pub(crate) value: NodeValue,
    pub(crate) start_mark: Mark,
}

impl Node {
    /// `node.id`.
    pub(crate) fn id(&self) -> &'static str {
        match self.value {
            NodeValue::Scalar(_) => "scalar",
            NodeValue::Sequence(_) => "sequence",
            NodeValue::Mapping(_) => "mapping",
        }
    }
}

fn composer_error(
    context: Option<&str>,
    context_mark: Option<Mark>,
    problem: impl Into<String>,
    problem_mark: Mark,
) -> LoadError {
    MarkedError::new(
        MarkedKind::Composer,
        context,
        context_mark,
        problem,
        Some(problem_mark),
    )
    .into()
}

// --- the resolver ---------------------------------------------------------------

struct Resolvers {
    bool_: Regex,
    float: Regex,
    int: Regex,
    merge: Regex,
    null: Regex,
    timestamp: Regex,
    value: Regex,
    yaml: Regex,
}

/// Python's `re.match(r'^(?:…)$', s)`: `$` also matches before a final
/// newline.
fn anchored(body: &str) -> Regex {
    #[allow(clippy::expect_used)]
    Regex::new(&format!(r"\A(?:{body})\n?\z")).expect("resolver pattern")
}

fn resolvers() -> &'static Resolvers {
    static R: OnceLock<Resolvers> = OnceLock::new();
    R.get_or_init(|| Resolvers {
        bool_: anchored(
            "yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF",
        ),
        float: anchored(
            r"[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)",
        ),
        int: anchored(
            r"[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+",
        ),
        merge: anchored("<<"),
        null: anchored("~|null|Null|NULL|"),
        timestamp: anchored(
            r"[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?",
        ),
        value: anchored("="),
        yaml: anchored(r"!|&|\*"),
    })
}

/// `Resolver.resolve(ScalarNode, value, implicit)`.
pub(crate) fn resolve_scalar(value: &str, implicit_plain: bool) -> &'static str {
    if implicit_plain {
        let r = resolvers();
        let candidates: &[(&'static str, &Regex)] = match value.chars().next() {
            None => &[("tag:yaml.org,2002:null", &r.null)],
            Some('y' | 'Y' | 't' | 'T' | 'f' | 'F' | 'o' | 'O') => {
                &[("tag:yaml.org,2002:bool", &r.bool_)]
            }
            Some('n' | 'N') => &[
                ("tag:yaml.org,2002:bool", &r.bool_),
                ("tag:yaml.org,2002:null", &r.null),
            ],
            Some('-' | '+') => &[
                ("tag:yaml.org,2002:float", &r.float),
                ("tag:yaml.org,2002:int", &r.int),
            ],
            Some('0'..='9') => &[
                ("tag:yaml.org,2002:float", &r.float),
                ("tag:yaml.org,2002:int", &r.int),
                ("tag:yaml.org,2002:timestamp", &r.timestamp),
            ],
            Some('.') => &[("tag:yaml.org,2002:float", &r.float)],
            Some('<') => &[("tag:yaml.org,2002:merge", &r.merge)],
            Some('~') => &[("tag:yaml.org,2002:null", &r.null)],
            Some('=') => &[("tag:yaml.org,2002:value", &r.value)],
            Some('!' | '&' | '*') => &[("tag:yaml.org,2002:yaml", &r.yaml)],
            Some(_) => &[],
        };
        for (tag, re) in candidates {
            if re.is_match(value) {
                return tag;
            }
        }
    }
    STR_TAG
}

/// The timestamp pattern `construct_yaml_timestamp` reads its groups with.
pub(crate) fn timestamp_groups(value: &str) -> Option<regex::Captures<'_>> {
    static R: OnceLock<Regex> = OnceLock::new();
    #[allow(clippy::expect_used)]
    let re = R.get_or_init(|| {
        Regex::new(
            r"\A(?P<year>[0-9][0-9][0-9][0-9])-(?P<month>[0-9][0-9]?)-(?P<day>[0-9][0-9]?)(?:(?:[Tt]|[ \t]+)(?P<hour>[0-9][0-9]?):(?P<minute>[0-9][0-9]):(?P<second>[0-9][0-9])(?:\.(?P<fraction>[0-9]*))?(?:[ \t]*(?P<tz>Z|(?P<tz_sign>[-+])(?P<tz_hour>[0-9][0-9]?)(?::(?P<tz_minute>[0-9][0-9]))?))?)?\n?\z",
        )
        .expect("timestamp pattern")
    });
    re.captures(value)
}

// --- the composer -----------------------------------------------------------------

pub(crate) struct Composer {
    pub(crate) parser: Parser,
    pub(crate) nodes: Vec<Node>,
    anchors: Vec<(String, usize)>,
    depth: usize,
}

impl Composer {
    pub(crate) fn new(parser: Parser) -> Self {
        Self {
            parser,
            nodes: Vec::new(),
            anchors: Vec::new(),
            depth: 0,
        }
    }

    /// `get_single_node()`.
    pub(crate) fn get_single_node(&mut self) -> Result<Option<usize>, LoadError> {
        self.parser.get_event()?;
        let mut document = None;
        if !self.parser.check_event(&[E::StreamEnd])? {
            document = Some(self.compose_document()?);
        }
        if !self.parser.check_event(&[E::StreamEnd])? {
            let event = self
                .parser
                .get_event()?
                .ok_or_else(|| LoadError::internal("no event"))?;
            let doc_mark = document.map(|d| self.nodes[d].start_mark.clone());
            return Err(composer_error(
                Some("expected a single document in the stream"),
                doc_mark,
                "but found another document",
                event.start_mark,
            ));
        }
        self.parser.get_event()?;
        Ok(document)
    }

    fn compose_document(&mut self) -> Result<usize, LoadError> {
        self.parser.get_event()?;
        let node = self.compose_node()?;
        self.parser.get_event()?;
        self.anchors.clear();
        Ok(node)
    }

    fn anchor_of(&self, name: &str) -> Option<usize> {
        self.anchors
            .iter()
            .find(|(a, _)| a == name)
            .map(|(_, n)| *n)
    }

    fn set_anchor(&mut self, name: String, node: usize) {
        match self.anchors.iter_mut().find(|(a, _)| *a == name) {
            Some(slot) => slot.1 = node,
            None => self.anchors.push((name, node)),
        }
    }

    fn compose_node(&mut self) -> Result<usize, LoadError> {
        if self.parser.check_event(&[E::Alias])? {
            let event = self
                .parser
                .get_event()?
                .ok_or_else(|| LoadError::internal("no event"))?;
            let EventKind::Alias { anchor } = &event.kind else {
                return Err(LoadError::internal("alias event"));
            };
            return self.anchor_of(anchor).ok_or_else(|| {
                composer_error(
                    None,
                    None,
                    format!("found undefined alias {}", str_repr(anchor)),
                    event.start_mark.clone(),
                )
            });
        }
        let event = self
            .parser
            .peek_event()?
            .ok_or_else(|| LoadError::internal("no event"))?
            .clone();
        let anchor = match &event.kind {
            EventKind::Scalar { anchor, .. }
            | EventKind::SequenceStart { anchor, .. }
            | EventKind::MappingStart { anchor, .. } => anchor.clone(),
            _ => None,
        };
        if let Some(a) = &anchor {
            if let Some(first) = self.anchor_of(a) {
                return Err(composer_error(
                    Some(&format!(
                        "found duplicate anchor {}; first occurrence",
                        str_repr(a)
                    )),
                    Some(self.nodes[first].start_mark.clone()),
                    "second occurrence",
                    event.start_mark,
                ));
            }
        }
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(PyException::new(
                "RecursionError",
                "maximum recursion depth exceeded while calling a Python object",
            )
            .into());
        }
        let node = if self.parser.check_event(&[E::Scalar])? {
            self.compose_scalar_node(anchor)?
        } else if self.parser.check_event(&[E::SequenceStart])? {
            self.compose_sequence_node(anchor)?
        } else if self.parser.check_event(&[E::MappingStart])? {
            self.compose_mapping_node(anchor)?
        } else {
            return Err(LoadError::internal("node event"));
        };
        self.depth -= 1;
        Ok(node)
    }

    fn add(&mut self, node: Node) -> usize {
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    fn compose_scalar_node(&mut self, anchor: Option<String>) -> Result<usize, LoadError> {
        let event = self
            .parser
            .get_event()?
            .ok_or_else(|| LoadError::internal("no event"))?;
        let EventKind::Scalar {
            tag,
            implicit,
            value,
            ..
        } = event.kind
        else {
            return Err(LoadError::internal("scalar event"));
        };
        let tag = match tag {
            Some(t) if t != "!" => t,
            _ => resolve_scalar(&value, implicit.0).to_string(),
        };
        let id = self.add(Node {
            tag,
            value: NodeValue::Scalar(value),
            start_mark: event.start_mark,
        });
        if let Some(a) = anchor {
            self.set_anchor(a, id);
        }
        Ok(id)
    }

    fn compose_sequence_node(&mut self, anchor: Option<String>) -> Result<usize, LoadError> {
        let event = self
            .parser
            .get_event()?
            .ok_or_else(|| LoadError::internal("no event"))?;
        let EventKind::SequenceStart { tag, .. } = event.kind else {
            return Err(LoadError::internal("sequence event"));
        };
        let tag = match tag {
            Some(t) if t != "!" => t,
            _ => SEQ_TAG.to_string(),
        };
        let id = self.add(Node {
            tag,
            value: NodeValue::Sequence(Vec::new()),
            start_mark: event.start_mark,
        });
        if let Some(a) = anchor {
            self.set_anchor(a, id);
        }
        while !self.parser.check_event(&[E::SequenceEnd])? {
            let child = self.compose_node()?;
            if let NodeValue::Sequence(items) = &mut self.nodes[id].value {
                items.push(child);
            }
        }
        self.parser.get_event()?;
        Ok(id)
    }

    fn compose_mapping_node(&mut self, anchor: Option<String>) -> Result<usize, LoadError> {
        let event = self
            .parser
            .get_event()?
            .ok_or_else(|| LoadError::internal("no event"))?;
        let EventKind::MappingStart { tag, .. } = event.kind else {
            return Err(LoadError::internal("mapping event"));
        };
        let tag = match tag {
            Some(t) if t != "!" => t,
            _ => MAP_TAG.to_string(),
        };
        let id = self.add(Node {
            tag,
            value: NodeValue::Mapping(Vec::new()),
            start_mark: event.start_mark,
        });
        if let Some(a) = anchor {
            self.set_anchor(a, id);
        }
        while !self.parser.check_event(&[E::MappingEnd])? {
            let key = self.compose_node()?;
            let value = self.compose_node()?;
            if let NodeValue::Mapping(items) = &mut self.nodes[id].value {
                items.push((key, value));
            }
        }
        self.parser.get_event()?;
        Ok(id)
    }
}
