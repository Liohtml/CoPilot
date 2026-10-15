//! `difflib.SequenceMatcher(None, a, b).ratio()` — a faithful port.
//!
//! The palace consolidation flags near-duplicate lessons at a ratio of 0.70,
//! and the ratio is shown to reviewers, so it must be Python's number, not a
//! similar one. That includes the *autojunk* heuristic: when `b` has at least
//! 200 elements, every element occurring more than `len(b) // 100 + 1` times
//! is dropped from the index (not from the extension pass), which changes
//! results drastically for long, repetitive text. Elements are Unicode code
//! points, like Python `str`.

use std::collections::HashMap;

/// Longest matching block of `a[alo..ahi]` and `b[blo..bhi]`
/// (`find_longest_match`, no junk function).
fn find_longest_match(
    a: &[char],
    b: &[char],
    b2j: &HashMap<char, Vec<usize>>,
    (alo, ahi, blo, bhi): (usize, usize, usize, usize),
) -> (usize, usize, usize) {
    let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0usize);
    let mut j2len: HashMap<usize, usize> = HashMap::new();
    for (i, ch) in a.iter().enumerate().take(ahi).skip(alo) {
        let mut newj2len: HashMap<usize, usize> = HashMap::new();
        if let Some(js) = b2j.get(ch) {
            for &j in js {
                if j < blo {
                    continue;
                }
                if j >= bhi {
                    break;
                }
                let k = j
                    .checked_sub(1)
                    .and_then(|p| j2len.get(&p))
                    .copied()
                    .unwrap_or(0)
                    + 1;
                newj2len.insert(j, k);
                if k > bestsize {
                    besti = i + 1 - k;
                    bestj = j + 1 - k;
                    bestsize = k;
                }
            }
        }
        j2len = newj2len;
    }
    // Extend by equal elements on both sides (there is no junk set, so
    // Python's two junk-extension passes never fire).
    while besti > alo && bestj > blo && a[besti - 1] == b[bestj - 1] {
        besti -= 1;
        bestj -= 1;
        bestsize += 1;
    }
    while besti + bestsize < ahi
        && bestj + bestsize < bhi
        && a[besti + bestsize] == b[bestj + bestsize]
    {
        bestsize += 1;
    }
    (besti, bestj, bestsize)
}

/// Total size of the matching blocks (`get_matching_blocks`).
fn matched(a: &[char], b: &[char]) -> usize {
    let mut b2j: HashMap<char, Vec<usize>> = HashMap::new();
    for (j, ch) in b.iter().enumerate() {
        b2j.entry(*ch).or_default().push(j);
    }
    let n = b.len();
    if n >= 200 {
        let ntest = n / 100 + 1;
        b2j.retain(|_, idxs| idxs.len() <= ntest);
    }
    let mut total = 0;
    let mut queue = vec![(0, a.len(), 0, b.len())];
    while let Some((alo, ahi, blo, bhi)) = queue.pop() {
        let (i, j, k) = find_longest_match(a, b, &b2j, (alo, ahi, blo, bhi));
        if k > 0 {
            total += k;
            if alo < i && blo < j {
                queue.push((alo, i, blo, j));
            }
            if i + k < ahi && j + k < bhi {
                queue.push((i + k, ahi, j + k, bhi));
            }
        }
    }
    total
}

/// `SequenceMatcher(None, a, b).ratio()`: `2 * M / (len(a) + len(b))`, or
/// `1.0` for two empty strings.
pub fn ratio(a: &str, b: &str) -> f64 {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let length = a.len() + b.len();
    if length == 0 {
        return 1.0;
    }
    2.0 * matched(&a, &b) as f64 / length as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `[a, b, SequenceMatcher(None, a, b).ratio()]` computed by CPython 3.11.
    const VECTORS: &str = include_str!("difflib_vectors.json");

    #[test]
    fn matches_cpython() {
        let cases: Vec<(String, String, f64)> = serde_json::from_str(VECTORS).unwrap();
        assert!(cases.len() >= 10);
        for (a, b, expected) in cases {
            let got = ratio(&a, &b);
            assert!(
                (got - expected).abs() < 1e-12,
                "ratio({a:?}, {b:?}) = {got}, CPython says {expected}"
            );
        }
    }
}
