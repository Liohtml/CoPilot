//! `packaging.version.Version` — enough of PEP 440 to compare release tags
//! the way the Python version check does (`Version(current) < Version(latest)`).
//!
//! Parsing follows packaging's `VERSION_PATTERN` (case-insensitive, optional
//! `v`, surrounding whitespace allowed) and ordering its `_cmpkey`: epoch,
//! release without trailing zeros, pre, post, dev, local.
//! `pep440_vectors.json` (generated from packaging) pins both.

use std::cmp::Ordering;
use std::sync::OnceLock;

use regex::Regex;

/// A parsed version.
#[derive(Debug, Clone)]
pub struct Version {
    epoch: u64,
    release: Vec<u64>,
    pre: Option<(PreLabel, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
    local: Option<Vec<LocalPart>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PreLabel {
    A,
    B,
    Rc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalPart {
    Num(u64),
    Text(String),
}

impl Ord for LocalPart {
    /// Numbers sort above strings; strings compare as strings.
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (LocalPart::Num(a), LocalPart::Num(b)) => a.cmp(b),
            (LocalPart::Text(a), LocalPart::Text(b)) => a.cmp(b),
            (LocalPart::Num(_), LocalPart::Text(_)) => Ordering::Greater,
            (LocalPart::Text(_), LocalPart::Num(_)) => Ordering::Less,
        }
    }
}

impl PartialOrd for LocalPart {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        Regex::new(
            r"(?ix)^\s*
            v?
            (?:(?P<epoch>[0-9]+)!)?
            (?P<release>[0-9]+(?:\.[0-9]+)*)
            (?P<pre>[-_\.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_\.]?(?P<pre_n>[0-9]+)?)?
            (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_\.]?(?P<post_l>post|rev|r)[-_\.]?(?P<post_n2>[0-9]+)?))?
            (?P<dev>[-_\.]?(?P<dev_l>dev)[-_\.]?(?P<dev_n>[0-9]+)?)?
            (?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?
            \s*$",
        )
        .expect("static PEP 440 pattern")
    })
}

fn num(s: Option<regex::Match<'_>>) -> Option<u64> {
    s.and_then(|m| m.as_str().parse().ok())
}

impl Version {
    /// `Version(s)`; `None` is packaging's `InvalidVersion`.
    pub fn parse(s: &str) -> Option<Self> {
        let c = pattern().captures(s)?;
        let release = c
            .name("release")?
            .as_str()
            .split('.')
            .map(|p| p.parse::<u64>().ok())
            .collect::<Option<Vec<_>>>()?;
        let pre = match c.name("pre_l") {
            None => None,
            Some(l) => {
                let label = match l.as_str().to_ascii_lowercase().as_str() {
                    "alpha" | "a" => PreLabel::A,
                    "beta" | "b" => PreLabel::B,
                    _ => PreLabel::Rc,
                };
                Some((label, num(c.name("pre_n")).unwrap_or(0)))
            }
        };
        let post = if c.name("post").is_some() {
            Some(
                num(c.name("post_n1"))
                    .or_else(|| num(c.name("post_n2")))
                    .unwrap_or(0),
            )
        } else {
            None
        };
        let dev = c.name("dev").map(|_| num(c.name("dev_n")).unwrap_or(0));
        let local = c.name("local").map(|l| {
            l.as_str()
                .to_ascii_lowercase()
                .split(['-', '_', '.'])
                .map(|p| match p.parse::<u64>() {
                    Ok(n) if p.bytes().all(|b| b.is_ascii_digit()) => LocalPart::Num(n),
                    _ => LocalPart::Text(p.to_string()),
                })
                .collect()
        });
        Some(Self {
            epoch: num(c.name("epoch")).unwrap_or(0),
            release,
            pre,
            post,
            dev,
            local,
        })
    }

    /// `_cmpkey`, as a tuple of orderable parts.
    #[allow(clippy::type_complexity)]
    fn key(
        &self,
    ) -> (
        u64,
        Vec<u64>,
        (u8, Option<(PreLabel, u64)>),
        (u8, u64),
        (u8, u64),
        (u8, Vec<LocalPart>),
    ) {
        let mut release = self.release.clone();
        while release.len() > 1 && release.last() == Some(&0) {
            release.pop();
        }
        if release == [0] {
            release.clear();
        }
        // No pre-release: below everything when only a dev release follows
        // (`1.0.dev0 < 1.0a0`), above every pre-release otherwise.
        let pre = match (self.pre, self.post, self.dev) {
            (None, None, Some(_)) => (0, None),
            (None, _, _) => (2, None),
            (Some(p), _, _) => (1, Some(p)),
        };
        let post = match self.post {
            None => (0, 0),
            Some(n) => (1, n),
        };
        let dev = match self.dev {
            None => (1, 0),
            Some(n) => (0, n),
        };
        let local = match &self.local {
            None => (0, Vec::new()),
            Some(parts) => (1, parts.clone()),
        };
        (self.epoch, release, pre, post, dev, local)
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

impl Eq for Version {}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn matches_packaging() {
        let doc: Value = serde_json::from_str(include_str!("pep440_vectors.json")).unwrap();
        let sorted = doc["sorted"].as_array().unwrap();
        let parsed: Vec<(Version, i64, &str)> = sorted
            .iter()
            .map(|v| {
                let raw = v["input"].as_str().unwrap();
                let parsed = Version::parse(raw).unwrap_or_else(|| panic!("{raw:?} is valid"));
                (parsed, v["rank"].as_i64().unwrap(), raw)
            })
            .collect();
        for (a, ra, sa) in &parsed {
            for (b, rb, sb) in &parsed {
                assert_eq!(a.cmp(b), ra.cmp(rb), "{sa:?} vs {sb:?}");
            }
        }
        for bad in doc["invalid"].as_array().unwrap() {
            let bad = bad.as_str().unwrap();
            assert!(Version::parse(bad).is_none(), "{bad:?} is invalid");
        }
    }
}
