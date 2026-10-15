//! `markdown_it.token.Token`, with the fields the renderer reads.

/// One token of the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    /// `type`.
    pub ty: &'static str,
    /// `tag`.
    pub tag: &'static str,
    /// `nesting`: 1 opens, 0 is self-contained, -1 closes.
    pub nesting: i8,
    /// `attrs`, in insertion order.
    pub attrs: Vec<(&'static str, String)>,
    /// `level`.
    pub level: i32,
    /// `children` (inline tokens, image alt tokens).
    pub children: Option<Vec<Token>>,
    /// `content`.
    pub content: String,
    /// `markup`.
    pub markup: String,
    /// `info`.
    pub info: String,
    /// `block`.
    pub block: bool,
    /// `hidden`.
    pub hidden: bool,
}

impl Token {
    /// `Token(type, tag, nesting)`.
    pub fn new(ty: &'static str, tag: &'static str, nesting: i8) -> Self {
        Self {
            ty,
            tag,
            nesting,
            attrs: Vec::new(),
            level: 0,
            children: None,
            content: String::new(),
            markup: String::new(),
            info: String::new(),
            block: false,
            hidden: false,
        }
    }

    /// `attrSet`.
    pub fn attr_set(&mut self, name: &'static str, value: impl Into<String>) {
        let value = value.into();
        match self.attrs.iter_mut().find(|(k, _)| *k == name) {
            Some((_, v)) => *v = value,
            None => self.attrs.push((name, value)),
        }
    }

    /// `attrGet`.
    pub fn attr_get(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }
}
