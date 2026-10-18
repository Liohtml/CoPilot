//! Link URLs: `mdurl` (parse, format, encode, decode), CPython's punycode
//! codec and markdown-it-py's `normalize_url.py` (`normalizeLink`,
//! `normalizeLinkText`, `validateLink`).

use crate::pystr::py_strip;

/// `mdurl.URL`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Url {
    protocol: Option<String>,
    slashes: bool,
    auth: Option<String>,
    port: Option<String>,
    hostname: Option<String>,
    hash: Option<String>,
    search: Option<String>,
    pathname: Option<String>,
}

fn find(chars: &[char], c: char) -> Option<usize> {
    chars.iter().position(|&x| x == c)
}

fn collect(chars: &[char]) -> String {
    chars.iter().collect()
}

/// `^([a-z0-9.+-]+:)` with `re.IGNORECASE` (which also admits `İ ı ſ K`).
fn protocol_len(rest: &[char]) -> Option<usize> {
    let n = rest
        .iter()
        .take_while(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '.' | '+' | '-' | '\u{130}' | '\u{131}' | '\u{17f}' | '\u{212a}'
                )
        })
        .count();
    (n > 0 && rest.get(n) == Some(&':')).then_some(n + 1)
}

fn hostless(proto: &str) -> bool {
    matches!(proto, "javascript" | "javascript:")
}

fn slashed(proto: &str) -> bool {
    matches!(
        proto,
        "http"
            | "https"
            | "ftp"
            | "gopher"
            | "file"
            | "http:"
            | "https:"
            | "ftp:"
            | "gopher:"
            | "file:"
    )
}

const NON_HOST_CHARS: [char; 19] = [
    '%', '/', '?', ';', '#', '\'', '{', '}', '|', '\\', '^', '`', '<', '>', '"', ' ', '\r', '\n',
    '\t',
];

fn is_host_part_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '_' | '-')
}

/// `HOSTNAME_PART_PATTERN`: `^[+a-z0-9A-Z_-]{0,63}$`.
fn host_part_ok(part: &[char]) -> bool {
    part.len() <= 63 && part.iter().all(|&c| is_host_part_char(c))
}

/// `mdurl.parse(url, slashes_denote_host=True)`.
fn parse(url: &str) -> Url {
    let mut u = Url::default();
    let mut rest: Vec<char> = py_strip(url).chars().collect();
    let mut proto = String::new();
    let mut lower_proto = String::new();
    if let Some(n) = protocol_len(&rest) {
        proto = collect(&rest[..n]);
        lower_proto = proto.to_lowercase();
        u.protocol = Some(proto.clone());
        rest.drain(..n);
    }
    let slashes = rest.starts_with(&['/', '/']);
    if slashes && !(!proto.is_empty() && hostless(&proto)) {
        rest.drain(..2);
        u.slashes = true;
    }
    if !hostless(&proto) && (slashes || (!proto.is_empty() && !slashed(&proto))) {
        let host_end = ['/', '?', '#'].iter().filter_map(|&c| find(&rest, c)).min();
        let at_sign = match host_end {
            None => rest.iter().rposition(|&c| c == '@'),
            Some(end) => rest[..(end + 1).min(rest.len())]
                .iter()
                .rposition(|&c| c == '@'),
        };
        if let Some(at) = at_sign {
            u.auth = Some(collect(&rest[..at]));
            rest.drain(..=at);
        }
        let mut host_end = NON_HOST_CHARS
            .iter()
            .filter_map(|&c| find(&rest, c))
            .min()
            .unwrap_or(rest.len());
        if host_end > 0 && rest[host_end - 1] == ':' {
            host_end -= 1;
        }
        let host: Vec<char> = rest.drain(..host_end).collect();
        parse_host(&mut u, &host);
        let mut hostname: Vec<char> = u.hostname.take().unwrap_or_default().chars().collect();
        let ipv6 = hostname.first() == Some(&'[') && hostname.last() == Some(&']');
        if !ipv6 {
            let parts: Vec<Vec<char>> = hostname
                .split(|&c| c == '.')
                .map(<[char]>::to_vec)
                .collect();
            for (i, part) in parts.iter().enumerate() {
                if part.is_empty() || host_part_ok(part) {
                    continue;
                }
                let ascii: Vec<char> = part
                    .iter()
                    .map(|&c| if (c as u32) > 127 { 'x' } else { c })
                    .collect();
                if host_part_ok(&ascii) {
                    continue;
                }
                let mut valid: Vec<Vec<char>> = parts[..i].to_vec();
                let mut not_host: Vec<Vec<char>> = parts[i + 1..].to_vec();
                // HOSTNAME_PART_START: `^([+a-z0-9A-Z_-]{0,63})(.*)$`
                let head = part
                    .iter()
                    .take(63)
                    .take_while(|&&c| is_host_part_char(c))
                    .count();
                valid.push(part[..head].to_vec());
                not_host.insert(0, part[head..].to_vec());
                let joined = not_host.join(&'.');
                let mut new_rest = joined;
                new_rest.extend_from_slice(&rest);
                rest = new_rest;
                hostname = valid.join(&'.');
                break;
            }
        }
        if hostname.len() > 255 {
            hostname.clear();
        }
        if ipv6 {
            hostname = if hostname.len() >= 2 {
                hostname[1..hostname.len() - 1].to_vec()
            } else {
                Vec::new()
            };
        }
        u.hostname = Some(collect(&hostname));
    }
    if let Some(h) = find(&rest, '#') {
        u.hash = Some(collect(&rest[h..]));
        rest.truncate(h);
    }
    if let Some(q) = find(&rest, '?') {
        u.search = Some(collect(&rest[q..]));
        rest.truncate(q);
    }
    if !rest.is_empty() {
        u.pathname = Some(collect(&rest));
    }
    if slashed(&lower_proto)
        && u.hostname.as_deref().is_some_and(|h| !h.is_empty())
        && u.pathname.as_deref().is_none_or(str::is_empty)
    {
        u.pathname = Some(String::new());
    }
    u
}

/// `parse_host`: `PORT_PATTERN` (`:[0-9]*$`) splits off the port.
fn parse_host(u: &mut Url, host: &[char]) {
    let mut host = host;
    let port_start =
        (0..host.len()).find(|&i| host[i] == ':' && host[i + 1..].iter().all(char::is_ascii_digit));
    if let Some(i) = port_start {
        let port = &host[i..];
        if port.len() > 1 {
            u.port = Some(collect(&port[1..]));
        }
        host = &host[..i];
    }
    if !host.is_empty() {
        u.hostname = Some(collect(host));
    }
}

/// `mdurl.format`.
fn format(u: &Url) -> String {
    let mut out = String::new();
    out.push_str(u.protocol.as_deref().unwrap_or(""));
    if u.slashes {
        out.push_str("//");
    }
    if let Some(auth) = u.auth.as_deref().filter(|a| !a.is_empty()) {
        out.push_str(auth);
        out.push('@');
    }
    match u.hostname.as_deref() {
        Some(h) if h.contains(':') => {
            out.push('[');
            out.push_str(h);
            out.push(']');
        }
        Some(h) => out.push_str(h),
        None => {}
    }
    if let Some(port) = u.port.as_deref().filter(|p| !p.is_empty()) {
        out.push(':');
        out.push_str(port);
    }
    out.push_str(u.pathname.as_deref().unwrap_or(""));
    out.push_str(u.search.as_deref().unwrap_or(""));
    out.push_str(u.hash.as_deref().unwrap_or(""));
    out
}

/// `mdurl.encode(s)` with the default exclusions and `keep_escaped`.
fn encode(s: &str) -> String {
    const EXCLUDE: &str = ";/?:@&=+$,-_.!~*'()#";
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '%'
            && i + 2 < chars.len()
            && chars[i + 1].is_ascii_hexdigit()
            && chars[i + 2].is_ascii_hexdigit()
        {
            out.extend(&chars[i..i + 3]);
            i += 3;
            continue;
        }
        if c.is_ascii() {
            if c.is_ascii_alphanumeric() || EXCLUDE.contains(c) {
                out.push(c);
            } else {
                out.push_str(&format!("%{:02X}", c as u32));
            }
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        i += 1;
    }
    out
}

/// `mdurl.decode(s, exclude)`: runs of `%XX` are decoded as UTF-8; an
/// excluded ASCII character stays escaped (in upper case).
fn decode(s: &str, exclude: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let is_seq = |i: usize| {
        chars.get(i) == Some(&'%')
            && chars.get(i + 1).is_some_and(char::is_ascii_hexdigit)
            && chars.get(i + 2).is_some_and(char::is_ascii_hexdigit)
    };
    while i < chars.len() {
        if !is_seq(i) {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let start = i;
        while is_seq(i) {
            i += 3;
        }
        let seq = &chars[start..i];
        out.push_str(&decode_run(seq, exclude));
    }
    out
}

fn hex_at(seq: &[char], i: usize) -> u8 {
    let s: String = seq[i..i + 2].iter().collect();
    u8::from_str_radix(&s, 16).unwrap_or(0)
}

/// `repl_func_with_cache`.
fn decode_run(seq: &[char], exclude: &str) -> String {
    let l = seq.len();
    let mut out = String::new();
    let mut i = 0;
    let utf8 = |bytes: &[u8], out: &mut String| match std::str::from_utf8(bytes) {
        Ok(s) => out.push_str(s),
        Err(_) => out.extend(std::iter::repeat_n('\u{fffd}', bytes.len())),
    };
    while i < l {
        let b1 = hex_at(seq, i + 1);
        if b1 < 0x80 {
            let c = b1 as char;
            if exclude.contains(c) {
                out.push_str(&format!("%{b1:02X}"));
            } else {
                out.push(c);
            }
            i += 3;
            continue;
        }
        if (b1 & 0xE0) == 0xC0 && i + 3 < l {
            let b2 = hex_at(seq, i + 4);
            if (b2 & 0xC0) == 0x80 {
                utf8(&[b1, b2], &mut out);
                i += 6;
                continue;
            }
        }
        if (b1 & 0xF0) == 0xE0 && i + 6 < l {
            let b2 = hex_at(seq, i + 4);
            let b3 = hex_at(seq, i + 7);
            if (b2 & 0xC0) == 0x80 && (b3 & 0xC0) == 0x80 {
                utf8(&[b1, b2, b3], &mut out);
                i += 9;
                continue;
            }
        }
        if (b1 & 0xF8) == 0xF0 && i + 9 < l {
            let b2 = hex_at(seq, i + 4);
            let b3 = hex_at(seq, i + 7);
            let b4 = hex_at(seq, i + 10);
            if (b2 & 0xC0) == 0x80 && (b3 & 0xC0) == 0x80 && (b4 & 0xC0) == 0x80 {
                utf8(&[b1, b2, b3, b4], &mut out);
                i += 12;
                continue;
            }
        }
        out.push('\u{fffd}');
        i += 3;
    }
    out
}

// ---------------------------------------------------------------------------
// Punycode (CPython `encodings/punycode.py`)
// ---------------------------------------------------------------------------

fn threshold(j: i128, bias: i128) -> i128 {
    (36 * (j + 1) - bias).clamp(1, 26)
}

fn adapt(delta: i128, first: bool, numchars: i128) -> i128 {
    let mut delta = if first { delta / 700 } else { delta / 2 };
    delta += delta / numchars;
    let mut divisions = 0;
    while delta > 455 {
        delta /= 35;
        divisions += 36;
    }
    divisions + (36 * delta / (delta + 38))
}

const DIGITS: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

fn punycode_encode(text: &[char]) -> String {
    let base: String = text.iter().filter(|c| (**c as u32) < 128).collect();
    let mut extended: Vec<char> = text
        .iter()
        .copied()
        .filter(|c| (*c as u32) >= 128)
        .collect();
    extended.sort_unstable();
    extended.dedup();
    // insertion_unsort
    let mut deltas: Vec<i128> = Vec::new();
    let mut oldchar: i128 = 0x80;
    let mut oldindex: i128 = -1;
    for &c in &extended {
        let char_code = c as i128;
        let curlen = text.iter().filter(|x| (**x as i128) < char_code).count() as i128;
        let mut delta = (curlen + 1) * (char_code - oldchar);
        let (mut index, mut pos): (i128, i128) = (-1, -1);
        loop {
            // selective_find
            let mut found = None;
            loop {
                pos += 1;
                if pos as usize == text.len() {
                    break;
                }
                let x = text[pos as usize];
                if x == c {
                    index += 1;
                    found = Some(index);
                    break;
                } else if x < c {
                    index += 1;
                }
            }
            let Some(idx) = found else { break };
            delta += idx - oldindex;
            deltas.push(delta - 1);
            oldindex = idx;
            delta = 0;
        }
        oldchar = char_code;
    }
    // generate_integers
    let mut out = String::new();
    let mut bias: i128 = 72;
    let baselen = base.chars().count() as i128;
    for (points, &delta) in deltas.iter().enumerate() {
        let mut n = delta;
        let mut j = 0;
        loop {
            let t = threshold(j, bias);
            if n < t {
                out.push(DIGITS[n as usize] as char);
                break;
            }
            out.push(DIGITS[(t + ((n - t) % (36 - t))) as usize] as char);
            n = (n - t) / (36 - t);
            j += 1;
        }
        bias = adapt(delta, points == 0, baselen + points as i128 + 1);
    }
    if base.is_empty() {
        out
    } else {
        format!("{base}-{out}")
    }
}

fn punycode_decode(text: &str) -> Option<String> {
    if !text.is_ascii() {
        return None;
    }
    let (base, extended) = match text.rfind('-') {
        None => (String::new(), text.to_ascii_uppercase()),
        Some(p) => (text[..p].to_string(), text[p + 1..].to_ascii_uppercase()),
    };
    let ext = extended.as_bytes();
    let mut out: Vec<char> = base.chars().collect();
    let mut ch: i128 = 0x80;
    let mut pos: i128 = -1;
    let mut bias: i128 = 72;
    let mut extpos = 0usize;
    while extpos < ext.len() {
        // decode_generalized_number
        let mut result: i128 = 0;
        let mut w: i128 = 1;
        let mut j = 0;
        let mut p = extpos;
        let delta = loop {
            let c = *ext.get(p)?;
            p += 1;
            let digit = match c {
                b'A'..=b'Z' => i128::from(c - b'A'),
                b'0'..=b'9' => i128::from(c) - 22,
                _ => return None,
            };
            let t = threshold(j, bias);
            result = result.checked_add(digit.checked_mul(w)?)?;
            if digit < t {
                break result;
            }
            w = w.checked_mul(36 - t)?;
            j += 1;
        };
        pos = pos.checked_add(delta + 1)?;
        let len = out.len() as i128 + 1;
        ch = ch.checked_add(pos / len)?;
        if ch > 0x10FFFF {
            return None;
        }
        pos %= len;
        // A lone surrogate is a valid Python character but not a Rust one.
        let c = char::from_u32(u32::try_from(ch).ok()?)?;
        out.insert(pos as usize, c);
        bias = adapt(delta, extpos == 0, out.len() as i128);
        extpos = p;
    }
    Some(out.into_iter().collect())
}

fn is_label_separator(c: char) -> bool {
    matches!(c, '.' | '\u{3002}' | '\u{ff0e}' | '\u{ff61}')
}

/// `map_domain`: only the part after the first `@` is mapped (and anything
/// after a second `@` is dropped, as in Python).
fn map_domain(s: &str, f: impl Fn(&str) -> Option<String>) -> Option<String> {
    let parts: Vec<&str> = s.split('@').collect();
    let (prefix, domain) = if parts.len() > 1 {
        (format!("{}@", parts[0]), parts[1])
    } else {
        (String::new(), s)
    };
    let labels = domain
        .split(is_label_separator)
        .map(&f)
        .collect::<Option<Vec<_>>>()?;
    Some(prefix + &labels.join("."))
}

fn to_ascii(s: &str) -> Option<String> {
    map_domain(s, |label| {
        if label.chars().any(|c| (c as u32) > 0x7E) {
            Some(format!(
                "xn--{}",
                punycode_encode(&label.chars().collect::<Vec<_>>())
            ))
        } else {
            Some(label.to_string())
        }
    })
}

fn to_unicode(s: &str) -> Option<String> {
    map_domain(s, |label| match label.strip_prefix("xn--") {
        Some(rest) => punycode_decode(&rest.to_lowercase()),
        None => Some(label.to_string()),
    })
}

const RECODE_HOSTNAME_FOR: [&str; 3] = ["http:", "https:", "mailto:"];

fn recodes(u: &Url) -> bool {
    u.hostname.as_deref().is_some_and(|h| !h.is_empty())
        && u.protocol
            .as_deref()
            .is_none_or(|p| p.is_empty() || RECODE_HOSTNAME_FOR.contains(&p))
}

/// `normalizeLink`.
pub(crate) fn normalize_link(url: &str) -> String {
    let mut parsed = parse(url);
    if recodes(&parsed) {
        if let Some(h) = parsed.hostname.as_deref().and_then(to_ascii) {
            parsed.hostname = Some(h);
        }
    }
    encode(&format(&parsed))
}

/// `normalizeLinkText`.
pub(crate) fn normalize_link_text(url: &str) -> String {
    let mut parsed = parse(url);
    if recodes(&parsed) {
        if let Some(h) = parsed.hostname.as_deref().and_then(to_unicode) {
            parsed.hostname = Some(h);
        }
    }
    decode(&format(&parsed), ";/?:@&=+$,#%")
}

/// `validateLink`: no `vbscript:`, `javascript:`, `file:` or `data:` other
/// than `data:image/(gif|png|jpeg|webp);`.
pub(crate) fn validate_link(url: &str) -> bool {
    let url = py_strip(url).to_lowercase();
    let bad = ["vbscript:", "javascript:", "file:", "data:"]
        .iter()
        .any(|p| url.starts_with(p));
    if !bad {
        return true;
    }
    ["gif", "png", "jpeg", "webp"]
        .iter()
        .any(|t| url.starts_with(&format!("data:image/{t};")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdurl_and_punycode() {
        assert_eq!(
            normalize_link("http://example.com/a b"),
            "http://example.com/a%20b"
        );
        assert_eq!(
            normalize_link("http://münchen.de/ä"),
            "http://xn--mnchen-3ya.de/%C3%A4"
        );
        assert_eq!(
            normalize_link_text("http://xn--mnchen-3ya.de/%C3%A4%2F"),
            "http://münchen.de/ä%2F"
        );
        assert_eq!(
            punycode_encode(&"bücher".chars().collect::<Vec<_>>()),
            "bcher-kva"
        );
        assert_eq!(punycode_decode("bcher-kva").as_deref(), Some("bücher"));
        assert!(!validate_link(" JavaScript:alert(1)"));
        assert!(validate_link("data:image/png;base64,xx"));
        assert_eq!(normalize_link("foo%20bar%zz"), "foo%20bar%25zz");
    }
}
