//! `yaml/reader.py` for a `str` input: the printable-character check, the
//! buffer with its trailing `'\0'`, and the position counters.

use std::rc::Rc;

use crate::error::{Mark, ReaderError};

/// `Reader.NON_PRINTABLE`'s complement: the characters a stream may hold.
fn printable(c: char) -> bool {
    matches!(c as u32,
        0x09 | 0x0A | 0x0D | 0x20..=0x7E | 0x85 | 0xA0..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

pub(crate) struct Reader {
    pub(crate) buffer: Rc<Vec<char>>,
    pub(crate) pointer: usize,
    pub(crate) index: usize,
    pub(crate) line: usize,
    pub(crate) column: usize,
}

impl Reader {
    /// `Reader(stream)` with `stream` a `str`.
    pub(crate) fn new(stream: &str) -> Result<Self, ReaderError> {
        let mut buffer: Vec<char> = Vec::with_capacity(stream.len() + 1);
        for (i, c) in stream.chars().enumerate() {
            if !printable(c) {
                return Err(ReaderError {
                    position: i,
                    character: c as u32,
                });
            }
            buffer.push(c);
        }
        buffer.push('\0');
        Ok(Self {
            buffer: Rc::new(buffer),
            pointer: 0,
            index: 0,
            line: 0,
            column: 0,
        })
    }

    /// `peek(index)`: the stream never reads past its `'\0'`.
    pub(crate) fn peek(&self, index: usize) -> char {
        self.buffer
            .get(self.pointer + index)
            .copied()
            .unwrap_or('\0')
    }

    /// `prefix(length)`.
    pub(crate) fn prefix(&self, length: usize) -> String {
        let end = (self.pointer + length).min(self.buffer.len());
        self.buffer[self.pointer.min(end)..end].iter().collect()
    }

    /// `forward(length)`.
    pub(crate) fn forward(&mut self, length: usize) {
        for _ in 0..length {
            let Some(&ch) = self.buffer.get(self.pointer) else {
                return;
            };
            self.pointer += 1;
            self.index += 1;
            let next = self.buffer.get(self.pointer).copied().unwrap_or('\0');
            if matches!(ch, '\n' | '\u{85}' | '\u{2028}' | '\u{2029}')
                || (ch == '\r' && next != '\n')
            {
                self.line += 1;
                self.column = 0;
            } else if ch != '\u{FEFF}' {
                self.column += 1;
            }
        }
    }

    /// `get_mark()`.
    pub(crate) fn mark(&self) -> Mark {
        Mark {
            name: "<unicode string>",
            index: self.index,
            line: self.line,
            column: self.column,
            buffer: Rc::clone(&self.buffer),
            pointer: self.pointer,
        }
    }
}
