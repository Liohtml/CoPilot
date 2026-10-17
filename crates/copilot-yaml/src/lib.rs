//! # copilot-yaml — `yaml.safe_load` as PyYAML 6.0.3 runs it
//!
//! CoPilot Searches reads every detection rule with `yaml.safe_load`, the
//! pure-Python `SafeLoader` (not libyaml), and its editor routes show what
//! that loader says about a rule the analyst typed. This crate is that loader,
//! module by module:
//!
//! - `reader`: the `str` reader (the printable-character check, the
//!   positions in code points);
//! - `scanner`, `parser`: tokens and events, produced lazily as PyYAML
//!   produces them, so the first error found is PyYAML's first error;
//! - `composer`: the node graph with anchors and aliases, and the YAML 1.1
//!   implicit resolver (`yes`/`no`/`on`/`off`, `0o`/`0x`/`0b`/old-octal and
//!   sexagesimal ints and floats, `.inf`/`.nan`, `~`, timestamps, `<<`, `=`;
//!   `$` matching before a final newline, as Python's `re` does);
//! - `constructor`: `SafeConstructor` — merge keys, duplicate keys
//!   (the last value wins, at the first key's place, under Python's `==`),
//!   `!!binary`, `!!omap`, `!!pairs`, `!!set`, timestamps into `date` and
//!   `datetime`, and the Python exceptions it lets escape (`int()`'s and
//!   `datetime`'s `ValueError`, the bool table's `KeyError`, `IndexError`);
//! - [`value`]: the result, with `repr()`, `str()`, Python's `==` and the
//!   JSON pydantic writes for it;
//! - [`error`]: `YAMLError` and its `str()` (`while parsing …\n  in
//!   "<unicode string>", line N, column M:` and the snippet).
//!
//! `yaml_vectors.json` (`scripts/gen-yaml-vectors.py`) pins it against PyYAML:
//! every resolver tag, the rule files of `crates/copilot-searches/tests/
//! fixtures` and mutations of them, and malformed inputs for each error.
//!
//! Known differences, none reachable from a rule file: a lone surrogate
//! (`"\ud800"`) becomes U+FFFD (a Rust string cannot hold one), a `!!set`
//! keeps insertion order (Python's follows string hashes), and nesting deeper
//! than [`MAX_DEPTH`] levels is Python's `RecursionError` at a fixed depth
//! (Python's depends on how deep its caller's stack already is).

#![warn(missing_docs)]

mod composer;
mod constructor;
pub mod error;
mod parser;
pub mod pyint;
mod reader;
mod repr;
mod scanner;
pub mod value;

pub use composer::MAX_DEPTH;
pub use error::{LoadError, Mark, MarkedError, MarkedKind, PyException, ReaderError, YamlError};
pub use repr::{bytes_repr, float_repr, str_repr};
pub use value::{Date, DateTime, JsonError, Value};

/// `yaml.safe_load(text)` for a `str`.
pub fn safe_load(text: &str) -> Result<Value, LoadError> {
    let reader = reader::Reader::new(text).map_err(|e| LoadError::Yaml(YamlError::Reader(e)))?;
    let scanner = scanner::Scanner::new(reader);
    let parser = parser::Parser::new(scanner);
    let mut composer = composer::Composer::new(parser);
    let Some(root) = composer.get_single_node()? else {
        return Ok(Value::None);
    };
    let mut nodes = std::mem::take(&mut composer.nodes);
    let mut constructor = constructor::Constructor::new(&mut nodes);
    let data = constructor.construct_document(root)?;
    Ok(value::export(&constructor.objs, data))
}

#[cfg(test)]
mod vectors;
