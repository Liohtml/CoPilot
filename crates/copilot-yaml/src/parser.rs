//! `yaml/parser.py` and `yaml/events.py`: the state machine that turns
//! tokens into events, asking the scanner for each token only when it needs
//! it.

use crate::error::{LoadError, Mark, MarkedError, MarkedKind};
use crate::repr::str_repr;
use crate::scanner::{DirectiveValue, Scanner, T, Token, TokenKind};

#[derive(Debug, Clone)]
pub(crate) enum EventKind {
    StreamStart,
    StreamEnd,
    DocumentStart,
    DocumentEnd,
    Alias {
        anchor: String,
    },
    Scalar {
        anchor: Option<String>,
        tag: Option<String>,
        implicit: (bool, bool),
        value: String,
    },
    SequenceStart {
        anchor: Option<String>,
        tag: Option<String>,
    },
    SequenceEnd,
    MappingStart {
        anchor: Option<String>,
        tag: Option<String>,
    },
    MappingEnd,
}

#[derive(Debug, Clone)]
pub(crate) struct Event {
    pub(crate) kind: EventKind,
    pub(crate) start_mark: Mark,
}

/// The event classes `check_event` compares against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum E {
    StreamEnd,
    Alias,
    Scalar,
    SequenceStart,
    SequenceEnd,
    MappingStart,
    MappingEnd,
}

impl EventKind {
    fn is(&self, e: E) -> bool {
        matches!(
            (self, e),
            (EventKind::StreamEnd, E::StreamEnd)
                | (EventKind::Alias { .. }, E::Alias)
                | (EventKind::Scalar { .. }, E::Scalar)
                | (EventKind::SequenceStart { .. }, E::SequenceStart)
                | (EventKind::SequenceEnd, E::SequenceEnd)
                | (EventKind::MappingStart { .. }, E::MappingStart)
                | (EventKind::MappingEnd, E::MappingEnd)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    StreamStart,
    ImplicitDocumentStart,
    DocumentStart,
    DocumentEnd,
    DocumentContent,
    BlockNode,
    BlockSequenceFirstEntry,
    BlockSequenceEntry,
    IndentlessSequenceEntry,
    BlockMappingFirstKey,
    BlockMappingKey,
    BlockMappingValue,
    FlowSequenceFirstEntry,
    FlowSequenceEntry,
    FlowSequenceEntryMappingKey,
    FlowSequenceEntryMappingValue,
    FlowSequenceEntryMappingEnd,
    FlowMappingFirstKey,
    FlowMappingKey,
    FlowMappingValue,
    FlowMappingEmptyValue,
}

type PResult<T> = Result<T, LoadError>;

fn parser_error(
    context: Option<&str>,
    context_mark: Option<Mark>,
    problem: impl Into<String>,
    problem_mark: Mark,
) -> LoadError {
    MarkedError::new(
        MarkedKind::Parser,
        context,
        context_mark,
        problem,
        Some(problem_mark),
    )
    .into()
}

const DEFAULT_TAGS: [(&str, &str); 2] = [("!", "!"), ("!!", "tag:yaml.org,2002:")];

/// `yaml.parser.Parser`.
pub(crate) struct Parser {
    pub(crate) scanner: Scanner,
    current_event: Option<Event>,
    tag_handles: Vec<(String, String)>,
    states: Vec<State>,
    marks: Vec<Mark>,
    state: Option<State>,
}

impl Parser {
    pub(crate) fn new(scanner: Scanner) -> Self {
        Self {
            scanner,
            current_event: None,
            tag_handles: Vec::new(),
            states: Vec::new(),
            marks: Vec::new(),
            state: Some(State::StreamStart),
        }
    }

    fn fill(&mut self) -> PResult<()> {
        if self.current_event.is_none() {
            if let Some(state) = self.state {
                self.current_event = Some(self.run(state)?);
            }
        }
        Ok(())
    }

    pub(crate) fn check_event(&mut self, choices: &[E]) -> PResult<bool> {
        self.fill()?;
        Ok(match &self.current_event {
            Some(e) => choices.is_empty() || choices.iter().any(|c| e.kind.is(*c)),
            None => false,
        })
    }

    pub(crate) fn peek_event(&mut self) -> PResult<Option<&Event>> {
        self.fill()?;
        Ok(self.current_event.as_ref())
    }

    pub(crate) fn get_event(&mut self) -> PResult<Option<Event>> {
        self.fill()?;
        Ok(self.current_event.take())
    }

    fn run(&mut self, state: State) -> PResult<Event> {
        match state {
            State::StreamStart => self.parse_stream_start(),
            State::ImplicitDocumentStart => self.parse_implicit_document_start(),
            State::DocumentStart => self.parse_document_start(),
            State::DocumentEnd => self.parse_document_end(),
            State::DocumentContent => self.parse_document_content(),
            State::BlockNode => self.parse_node(true, false),
            State::BlockSequenceFirstEntry => self.parse_block_sequence_first_entry(),
            State::BlockSequenceEntry => self.parse_block_sequence_entry(),
            State::IndentlessSequenceEntry => self.parse_indentless_sequence_entry(),
            State::BlockMappingFirstKey => self.parse_block_mapping_first_key(),
            State::BlockMappingKey => self.parse_block_mapping_key(),
            State::BlockMappingValue => self.parse_block_mapping_value(),
            State::FlowSequenceFirstEntry => self.parse_flow_sequence_first_entry(),
            State::FlowSequenceEntry => self.parse_flow_sequence_entry(false),
            State::FlowSequenceEntryMappingKey => self.parse_flow_sequence_entry_mapping_key(),
            State::FlowSequenceEntryMappingValue => self.parse_flow_sequence_entry_mapping_value(),
            State::FlowSequenceEntryMappingEnd => self.parse_flow_sequence_entry_mapping_end(),
            State::FlowMappingFirstKey => self.parse_flow_mapping_first_key(),
            State::FlowMappingKey => self.parse_flow_mapping_key(false),
            State::FlowMappingValue => self.parse_flow_mapping_value(),
            State::FlowMappingEmptyValue => self.parse_flow_mapping_empty_value(),
        }
    }

    // --- token helpers --------------------------------------------------------

    fn check_token(&mut self, choices: &[T]) -> PResult<bool> {
        self.scanner.check_token(choices)
    }

    fn peek_token(&mut self) -> PResult<Token> {
        self.scanner
            .peek_token()?
            .cloned()
            .ok_or_else(|| LoadError::internal("no token"))
    }

    fn get_token(&mut self) -> PResult<Token> {
        self.scanner
            .get_token()?
            .ok_or_else(|| LoadError::internal("no token"))
    }

    fn pop_state(&mut self) -> PResult<()> {
        self.state = Some(
            self.states
                .pop()
                .ok_or_else(|| LoadError::internal("pop from empty list"))?,
        );
        Ok(())
    }

    /// An event (its end mark is unused by the composer).
    fn event(kind: EventKind, start_mark: Mark, _end_mark: Mark) -> Event {
        Event { kind, start_mark }
    }

    // --- stream and documents -------------------------------------------------

    fn parse_stream_start(&mut self) -> PResult<Event> {
        let token = self.get_token()?;
        self.state = Some(State::ImplicitDocumentStart);
        Ok(Self::event(
            EventKind::StreamStart,
            token.start_mark,
            token.end_mark,
        ))
    }

    fn parse_implicit_document_start(&mut self) -> PResult<Event> {
        if !self.check_token(&[T::Directive, T::DocumentStart, T::StreamEnd])? {
            self.tag_handles = DEFAULT_TAGS
                .iter()
                .map(|(h, p)| ((*h).to_string(), (*p).to_string()))
                .collect();
            let token = self.peek_token()?;
            let mark = token.start_mark;
            self.states.push(State::DocumentEnd);
            self.state = Some(State::BlockNode);
            Ok(Self::event(EventKind::DocumentStart, mark.clone(), mark))
        } else {
            self.parse_document_start()
        }
    }

    fn parse_document_start(&mut self) -> PResult<Event> {
        while self.check_token(&[T::DocumentEnd])? {
            self.get_token()?;
        }
        if !self.check_token(&[T::StreamEnd])? {
            let token = self.peek_token()?;
            let start_mark = token.start_mark;
            self.process_directives()?;
            if !self.check_token(&[T::DocumentStart])? {
                let token = self.peek_token()?;
                return Err(parser_error(
                    None,
                    None,
                    format!(
                        "expected '<document start>', but found {}",
                        str_repr(token.kind.id())
                    ),
                    token.start_mark,
                ));
            }
            let token = self.get_token()?;
            self.states.push(State::DocumentEnd);
            self.state = Some(State::DocumentContent);
            Ok(Self::event(
                EventKind::DocumentStart,
                start_mark,
                token.end_mark,
            ))
        } else {
            let token = self.get_token()?;
            self.state = None;
            Ok(Self::event(
                EventKind::StreamEnd,
                token.start_mark,
                token.end_mark,
            ))
        }
    }

    fn parse_document_end(&mut self) -> PResult<Event> {
        let token = self.peek_token()?;
        let start_mark = token.start_mark.clone();
        let mut end_mark = token.start_mark;
        if self.check_token(&[T::DocumentEnd])? {
            let token = self.get_token()?;
            end_mark = token.end_mark;
        }
        self.state = Some(State::DocumentStart);
        Ok(Self::event(EventKind::DocumentEnd, start_mark, end_mark))
    }

    fn parse_document_content(&mut self) -> PResult<Event> {
        if self.check_token(&[T::Directive, T::DocumentStart, T::DocumentEnd, T::StreamEnd])? {
            let mark = self.peek_token()?.start_mark;
            let event = Self::empty_scalar(mark);
            self.pop_state()?;
            Ok(event)
        } else {
            self.parse_node(true, false)
        }
    }

    fn process_directives(&mut self) -> PResult<()> {
        let mut yaml_version_seen = false;
        self.tag_handles = Vec::new();
        while self.check_token(&[T::Directive])? {
            let token = self.get_token()?;
            if let TokenKind::Directive { name, value } = &token.kind {
                if name == "YAML" {
                    if yaml_version_seen {
                        return Err(parser_error(
                            None,
                            None,
                            "found duplicate YAML directive",
                            token.start_mark,
                        ));
                    }
                    if let DirectiveValue::Yaml(major, _) = value {
                        if major != "1" {
                            return Err(parser_error(
                                None,
                                None,
                                "found incompatible YAML document (version 1.* is required)",
                                token.start_mark,
                            ));
                        }
                    }
                    yaml_version_seen = true;
                } else if name == "TAG" {
                    if let DirectiveValue::Tag(handle, prefix) = value {
                        if self.tag_handles.iter().any(|(h, _)| h == handle) {
                            return Err(parser_error(
                                None,
                                None,
                                format!("duplicate tag handle {}", str_repr(handle)),
                                token.start_mark,
                            ));
                        }
                        self.tag_handles.push((handle.clone(), prefix.clone()));
                    }
                }
            }
        }
        for (h, p) in DEFAULT_TAGS {
            if !self.tag_handles.iter().any(|(k, _)| k == h) {
                self.tag_handles.push((h.to_string(), p.to_string()));
            }
        }
        Ok(())
    }

    // --- nodes ------------------------------------------------------------------

    fn parse_node(&mut self, block: bool, indentless_sequence: bool) -> PResult<Event> {
        if self.check_token(&[T::Alias])? {
            let token = self.get_token()?;
            let TokenKind::Alias(anchor) = token.kind else {
                return Err(LoadError::internal("alias token"));
            };
            self.pop_state()?;
            return Ok(Self::event(
                EventKind::Alias { anchor },
                token.start_mark,
                token.end_mark,
            ));
        }
        let mut anchor: Option<String> = None;
        let mut tag_pair: Option<(Option<String>, String)> = None;
        let mut start_mark: Option<Mark> = None;
        let mut end_mark: Option<Mark> = None;
        let mut tag_mark: Option<Mark> = None;
        if self.check_token(&[T::Anchor])? {
            let token = self.get_token()?;
            start_mark = Some(token.start_mark.clone());
            end_mark = Some(token.end_mark.clone());
            if let TokenKind::Anchor(a) = token.kind {
                anchor = Some(a);
            }
            if self.check_token(&[T::Tag])? {
                let token = self.get_token()?;
                tag_mark = Some(token.start_mark.clone());
                end_mark = Some(token.end_mark.clone());
                if let TokenKind::Tag(h, s) = token.kind {
                    tag_pair = Some((h, s));
                }
            }
        } else if self.check_token(&[T::Tag])? {
            let token = self.get_token()?;
            start_mark = Some(token.start_mark.clone());
            tag_mark = Some(token.start_mark.clone());
            end_mark = Some(token.end_mark.clone());
            if let TokenKind::Tag(h, s) = token.kind {
                tag_pair = Some((h, s));
            }
            if self.check_token(&[T::Anchor])? {
                let token = self.get_token()?;
                end_mark = Some(token.end_mark.clone());
                if let TokenKind::Anchor(a) = token.kind {
                    anchor = Some(a);
                }
            }
        }
        let mut tag: Option<String> = None;
        if let Some((handle, suffix)) = tag_pair {
            match handle {
                Some(handle) => {
                    let Some((_, prefix)) = self.tag_handles.iter().find(|(h, _)| *h == handle)
                    else {
                        return Err(MarkedError::new(
                            MarkedKind::Parser,
                            Some("while parsing a node"),
                            start_mark,
                            format!("found undefined tag handle {}", str_repr(&handle)),
                            tag_mark,
                        )
                        .into());
                    };
                    tag = Some(format!("{prefix}{suffix}"));
                }
                None => tag = Some(suffix),
            }
        }
        let (start_mark, mut end_mark) = match start_mark {
            Some(s) => {
                let e = end_mark.unwrap_or_else(|| s.clone());
                (s, e)
            }
            None => {
                let m = self.peek_token()?.start_mark;
                (m.clone(), m)
            }
        };
        let implicit = tag.is_none() || tag.as_deref() == Some("!");
        if indentless_sequence && self.check_token(&[T::BlockEntry])? {
            end_mark = self.peek_token()?.end_mark;
            self.state = Some(State::IndentlessSequenceEntry);
            return Ok(Self::event(
                EventKind::SequenceStart { anchor, tag },
                start_mark,
                end_mark,
            ));
        }
        if self.check_token(&[T::Scalar])? {
            let token = self.get_token()?;
            end_mark = token.end_mark;
            let TokenKind::Scalar { value, plain, .. } = token.kind else {
                return Err(LoadError::internal("scalar token"));
            };
            let implicit = if (plain && tag.is_none()) || tag.as_deref() == Some("!") {
                (true, false)
            } else if tag.is_none() {
                (false, true)
            } else {
                (false, false)
            };
            self.pop_state()?;
            return Ok(Self::event(
                EventKind::Scalar {
                    anchor,
                    tag,
                    implicit,
                    value,
                },
                start_mark,
                end_mark,
            ));
        }
        if self.check_token(&[T::FlowSequenceStart])? {
            end_mark = self.peek_token()?.end_mark;
            self.state = Some(State::FlowSequenceFirstEntry);
            return Ok(Self::event(
                EventKind::SequenceStart { anchor, tag },
                start_mark,
                end_mark,
            ));
        }
        if self.check_token(&[T::FlowMappingStart])? {
            end_mark = self.peek_token()?.end_mark;
            self.state = Some(State::FlowMappingFirstKey);
            return Ok(Self::event(
                EventKind::MappingStart { anchor, tag },
                start_mark,
                end_mark,
            ));
        }
        if block && self.check_token(&[T::BlockSequenceStart])? {
            end_mark = self.peek_token()?.start_mark;
            self.state = Some(State::BlockSequenceFirstEntry);
            return Ok(Self::event(
                EventKind::SequenceStart { anchor, tag },
                start_mark,
                end_mark,
            ));
        }
        if block && self.check_token(&[T::BlockMappingStart])? {
            end_mark = self.peek_token()?.start_mark;
            self.state = Some(State::BlockMappingFirstKey);
            return Ok(Self::event(
                EventKind::MappingStart { anchor, tag },
                start_mark,
                end_mark,
            ));
        }
        if anchor.is_some() || tag.is_some() {
            self.pop_state()?;
            return Ok(Self::event(
                EventKind::Scalar {
                    anchor,
                    tag,
                    implicit: (implicit, false),
                    value: String::new(),
                },
                start_mark,
                end_mark,
            ));
        }
        let node = if block { "block" } else { "flow" };
        let token = self.peek_token()?;
        Err(parser_error(
            Some(&format!("while parsing a {node} node")),
            Some(start_mark),
            format!(
                "expected the node content, but found {}",
                str_repr(token.kind.id())
            ),
            token.start_mark,
        ))
    }

    // --- block collections -------------------------------------------------------

    fn last_mark(&self) -> Option<Mark> {
        self.marks.last().cloned()
    }

    fn pop_mark(&mut self) {
        self.marks.pop();
    }

    fn parse_block_sequence_first_entry(&mut self) -> PResult<Event> {
        let token = self.get_token()?;
        self.marks.push(token.start_mark);
        self.parse_block_sequence_entry()
    }

    fn parse_block_sequence_entry(&mut self) -> PResult<Event> {
        if self.check_token(&[T::BlockEntry])? {
            let token = self.get_token()?;
            if !self.check_token(&[T::BlockEntry, T::BlockEnd])? {
                self.states.push(State::BlockSequenceEntry);
                return self.parse_node(true, false);
            }
            self.state = Some(State::BlockSequenceEntry);
            return Ok(Self::empty_scalar(token.end_mark));
        }
        if !self.check_token(&[T::BlockEnd])? {
            let token = self.peek_token()?;
            return Err(parser_error(
                Some("while parsing a block collection"),
                self.last_mark(),
                format!(
                    "expected <block end>, but found {}",
                    str_repr(token.kind.id())
                ),
                token.start_mark,
            ));
        }
        let token = self.get_token()?;
        self.pop_state()?;
        self.pop_mark();
        Ok(Self::event(
            EventKind::SequenceEnd,
            token.start_mark,
            token.end_mark,
        ))
    }

    fn parse_indentless_sequence_entry(&mut self) -> PResult<Event> {
        if self.check_token(&[T::BlockEntry])? {
            let token = self.get_token()?;
            if !self.check_token(&[T::BlockEntry, T::Key, T::Value, T::BlockEnd])? {
                self.states.push(State::IndentlessSequenceEntry);
                return self.parse_node(true, false);
            }
            self.state = Some(State::IndentlessSequenceEntry);
            return Ok(Self::empty_scalar(token.end_mark));
        }
        let token = self.peek_token()?;
        self.pop_state()?;
        Ok(Self::event(
            EventKind::SequenceEnd,
            token.start_mark.clone(),
            token.start_mark,
        ))
    }

    fn parse_block_mapping_first_key(&mut self) -> PResult<Event> {
        let token = self.get_token()?;
        self.marks.push(token.start_mark);
        self.parse_block_mapping_key()
    }

    fn parse_block_mapping_key(&mut self) -> PResult<Event> {
        if self.check_token(&[T::Key])? {
            let token = self.get_token()?;
            if !self.check_token(&[T::Key, T::Value, T::BlockEnd])? {
                self.states.push(State::BlockMappingValue);
                return self.parse_node(true, true);
            }
            self.state = Some(State::BlockMappingValue);
            return Ok(Self::empty_scalar(token.end_mark));
        }
        if !self.check_token(&[T::BlockEnd])? {
            let token = self.peek_token()?;
            return Err(parser_error(
                Some("while parsing a block mapping"),
                self.last_mark(),
                format!(
                    "expected <block end>, but found {}",
                    str_repr(token.kind.id())
                ),
                token.start_mark,
            ));
        }
        let token = self.get_token()?;
        self.pop_state()?;
        self.pop_mark();
        Ok(Self::event(
            EventKind::MappingEnd,
            token.start_mark,
            token.end_mark,
        ))
    }

    fn parse_block_mapping_value(&mut self) -> PResult<Event> {
        if self.check_token(&[T::Value])? {
            let token = self.get_token()?;
            if !self.check_token(&[T::Key, T::Value, T::BlockEnd])? {
                self.states.push(State::BlockMappingKey);
                return self.parse_node(true, true);
            }
            self.state = Some(State::BlockMappingKey);
            return Ok(Self::empty_scalar(token.end_mark));
        }
        self.state = Some(State::BlockMappingKey);
        let token = self.peek_token()?;
        Ok(Self::empty_scalar(token.start_mark))
    }

    // --- flow collections ---------------------------------------------------------

    fn parse_flow_sequence_first_entry(&mut self) -> PResult<Event> {
        let token = self.get_token()?;
        self.marks.push(token.start_mark);
        self.parse_flow_sequence_entry(true)
    }

    fn parse_flow_sequence_entry(&mut self, first: bool) -> PResult<Event> {
        if !self.check_token(&[T::FlowSequenceEnd])? {
            if !first {
                if self.check_token(&[T::FlowEntry])? {
                    self.get_token()?;
                } else {
                    let token = self.peek_token()?;
                    return Err(parser_error(
                        Some("while parsing a flow sequence"),
                        self.last_mark(),
                        format!("expected ',' or ']', but got {}", str_repr(token.kind.id())),
                        token.start_mark,
                    ));
                }
            }
            if self.check_token(&[T::Key])? {
                let token = self.peek_token()?;
                self.state = Some(State::FlowSequenceEntryMappingKey);
                return Ok(Self::event(
                    EventKind::MappingStart {
                        anchor: None,
                        tag: None,
                    },
                    token.start_mark,
                    token.end_mark,
                ));
            } else if !self.check_token(&[T::FlowSequenceEnd])? {
                self.states.push(State::FlowSequenceEntry);
                return self.parse_node(false, false);
            }
        }
        let token = self.get_token()?;
        self.pop_state()?;
        self.pop_mark();
        Ok(Self::event(
            EventKind::SequenceEnd,
            token.start_mark,
            token.end_mark,
        ))
    }

    fn parse_flow_sequence_entry_mapping_key(&mut self) -> PResult<Event> {
        let token = self.get_token()?;
        if !self.check_token(&[T::Value, T::FlowEntry, T::FlowSequenceEnd])? {
            self.states.push(State::FlowSequenceEntryMappingValue);
            return self.parse_node(false, false);
        }
        self.state = Some(State::FlowSequenceEntryMappingValue);
        Ok(Self::empty_scalar(token.end_mark))
    }

    fn parse_flow_sequence_entry_mapping_value(&mut self) -> PResult<Event> {
        if self.check_token(&[T::Value])? {
            let token = self.get_token()?;
            if !self.check_token(&[T::FlowEntry, T::FlowSequenceEnd])? {
                self.states.push(State::FlowSequenceEntryMappingEnd);
                return self.parse_node(false, false);
            }
            self.state = Some(State::FlowSequenceEntryMappingEnd);
            return Ok(Self::empty_scalar(token.end_mark));
        }
        self.state = Some(State::FlowSequenceEntryMappingEnd);
        let token = self.peek_token()?;
        Ok(Self::empty_scalar(token.start_mark))
    }

    fn parse_flow_sequence_entry_mapping_end(&mut self) -> PResult<Event> {
        self.state = Some(State::FlowSequenceEntry);
        let token = self.peek_token()?;
        Ok(Self::event(
            EventKind::MappingEnd,
            token.start_mark.clone(),
            token.start_mark,
        ))
    }

    fn parse_flow_mapping_first_key(&mut self) -> PResult<Event> {
        let token = self.get_token()?;
        self.marks.push(token.start_mark);
        self.parse_flow_mapping_key(true)
    }

    fn parse_flow_mapping_key(&mut self, first: bool) -> PResult<Event> {
        if !self.check_token(&[T::FlowMappingEnd])? {
            if !first {
                if self.check_token(&[T::FlowEntry])? {
                    self.get_token()?;
                } else {
                    let token = self.peek_token()?;
                    return Err(parser_error(
                        Some("while parsing a flow mapping"),
                        self.last_mark(),
                        format!(
                            "expected ',' or '}}', but got {}",
                            str_repr(token.kind.id())
                        ),
                        token.start_mark,
                    ));
                }
            }
            if self.check_token(&[T::Key])? {
                let token = self.get_token()?;
                if !self.check_token(&[T::Value, T::FlowEntry, T::FlowMappingEnd])? {
                    self.states.push(State::FlowMappingValue);
                    return self.parse_node(false, false);
                }
                self.state = Some(State::FlowMappingValue);
                return Ok(Self::empty_scalar(token.end_mark));
            } else if !self.check_token(&[T::FlowMappingEnd])? {
                self.states.push(State::FlowMappingEmptyValue);
                return self.parse_node(false, false);
            }
        }
        let token = self.get_token()?;
        self.pop_state()?;
        self.pop_mark();
        Ok(Self::event(
            EventKind::MappingEnd,
            token.start_mark,
            token.end_mark,
        ))
    }

    fn parse_flow_mapping_value(&mut self) -> PResult<Event> {
        if self.check_token(&[T::Value])? {
            let token = self.get_token()?;
            if !self.check_token(&[T::FlowEntry, T::FlowMappingEnd])? {
                self.states.push(State::FlowMappingKey);
                return self.parse_node(false, false);
            }
            self.state = Some(State::FlowMappingKey);
            return Ok(Self::empty_scalar(token.end_mark));
        }
        self.state = Some(State::FlowMappingKey);
        let token = self.peek_token()?;
        Ok(Self::empty_scalar(token.start_mark))
    }

    fn parse_flow_mapping_empty_value(&mut self) -> PResult<Event> {
        self.state = Some(State::FlowMappingKey);
        let mark = self.peek_token()?.start_mark;
        Ok(Self::empty_scalar(mark))
    }

    fn empty_scalar(mark: Mark) -> Event {
        Event {
            kind: EventKind::Scalar {
                anchor: None,
                tag: None,
                implicit: (true, false),
                value: String::new(),
            },
            start_mark: mark,
        }
    }
}
