//! CPython 3.11's `ipaddress`, as far as the WAF blocks use it:
//! `ip_network(text, strict=False)`, `str()` of a network and of its address,
//! `subnet_of`, network equality and the address classification properties
//! (`is_private`, `is_loopback`, …) with the 3.11 tables.
//!
//! The parse rules are the module's own, not the RFCs': IPv4 octets are one to
//! three ASCII digits without a leading zero; an IPv4 mask is a prefix length
//! or a dotted netmask / hostmask; an IPv6 address may end in a dotted IPv4
//! quad and carry a `%zone`, which `str()` prints back. An IPv4-mapped IPv6
//! address prints as `::ffff:1.2.3.4` and is classified by its IPv4 address.
//! `waf_vectors.json` pins every probe against the Python module.

/// One parsed network (`IPv4Network` / `IPv6Network`).
#[derive(Debug, Clone)]
pub struct Network {
    /// `version == 6`.
    pub v6: bool,
    /// `int(network_address)`.
    pub addr: u128,
    /// `prefixlen`.
    pub prefix: u8,
    /// The network address's `%zone` (IPv6 only; kept only when the address
    /// had no host bits to clear, as `ip_network(…, strict=False)` keeps it).
    pub scope: Option<String>,
}

impl PartialEq for Network {
    /// `_BaseNetwork.__eq__`: version, network address (with its zone) and
    /// netmask.
    fn eq(&self, other: &Self) -> bool {
        self.v6 == other.v6
            && self.addr == other.addr
            && self.scope == other.scope
            && self.prefix == other.prefix
    }
}

fn max_prefix(v6: bool) -> u8 {
    if v6 { 128 } else { 32 }
}

fn all_ones(v6: bool) -> u128 {
    if v6 { u128::MAX } else { u128::from(u32::MAX) }
}

fn netmask(v6: bool, prefix: u8) -> u128 {
    let max = u32::from(max_prefix(v6));
    let prefix = u32::from(prefix);
    if prefix == 0 {
        0
    } else {
        all_ones(v6) ^ ((1u128 << (max - prefix)) - 1)
    }
}

impl Network {
    /// `prefixlen`.
    pub fn prefixlen(&self) -> u8 {
        self.prefix
    }

    /// `max_prefixlen`.
    pub fn max_prefixlen(&self) -> u8 {
        max_prefix(self.v6)
    }

    /// `version`.
    pub fn version(&self) -> u8 {
        if self.v6 { 6 } else { 4 }
    }

    /// `int(broadcast_address)`.
    pub fn broadcast(&self) -> u128 {
        self.addr | (all_ones(self.v6) ^ netmask(self.v6, self.prefix))
    }

    /// `str(network_address)`.
    pub fn address_str(&self) -> String {
        let base = if self.v6 {
            v6_str(self.addr)
        } else {
            v4_str(self.addr)
        };
        match &self.scope {
            Some(s) if !s.is_empty() => format!("{base}%{s}"),
            _ => base,
        }
    }

    /// `subnet_of(other)` for networks of one version (the caller checks it).
    /// The network addresses compare with `total_ordering`'s `<=` (`<`, else
    /// `==`, which includes the zone); the broadcast addresses have none.
    pub fn subnet_of(&self, other: &Network) -> bool {
        let le = other.addr < self.addr || (other.addr == self.addr && other.scope == self.scope);
        le && other.broadcast() >= self.broadcast()
    }

    /// The network address as an address object, for the `is_*` properties.
    pub fn address(&self) -> Address {
        Address {
            v6: self.v6,
            ip: self.addr,
        }
    }
}

impl std::fmt::Display for Network {
    /// `str(network)`: `address/prefixlen`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address_str(), self.prefix)
    }
}

/// An address, for the classification properties.
#[derive(Debug, Clone, Copy)]
pub struct Address {
    v6: bool,
    ip: u128,
}

/// `(network, prefix)` in a constants table.
type Block = (u128, u8);

const fn v4(a: u8, b: u8, c: u8, d: u8) -> u128 {
    ((a as u128) << 24) | ((b as u128) << 16) | ((c as u128) << 8) | (d as u128)
}

const fn v6h(h: [u16; 8]) -> u128 {
    let mut out = 0u128;
    let mut i = 0;
    while i < 8 {
        out = (out << 16) | (h[i] as u128);
        i += 1;
    }
    out
}

const V4_PRIVATE: &[Block] = &[
    (v4(0, 0, 0, 0), 8),
    (v4(10, 0, 0, 0), 8),
    (v4(127, 0, 0, 0), 8),
    (v4(169, 254, 0, 0), 16),
    (v4(172, 16, 0, 0), 12),
    (v4(192, 0, 0, 0), 24),
    (v4(192, 0, 0, 170), 31),
    (v4(192, 0, 2, 0), 24),
    (v4(192, 168, 0, 0), 16),
    (v4(198, 18, 0, 0), 15),
    (v4(198, 51, 100, 0), 24),
    (v4(203, 0, 113, 0), 24),
    (v4(240, 0, 0, 0), 4),
    (v4(255, 255, 255, 255), 32),
];
const V4_PRIVATE_EXCEPTIONS: &[Block] = &[(v4(192, 0, 0, 9), 32), (v4(192, 0, 0, 10), 32)];
const V4_LOOPBACK: Block = (v4(127, 0, 0, 0), 8);
const V4_LINK_LOCAL: Block = (v4(169, 254, 0, 0), 16);
const V4_MULTICAST: Block = (v4(224, 0, 0, 0), 4);
const V4_RESERVED: Block = (v4(240, 0, 0, 0), 4);

const V6_PRIVATE: &[Block] = &[
    (v6h([0, 0, 0, 0, 0, 0, 0, 1]), 128),
    (0, 128),
    (v6h([0, 0, 0, 0, 0, 0xffff, 0, 0]), 96),
    (v6h([0x64, 0xff9b, 1, 0, 0, 0, 0, 0]), 48),
    (v6h([0x100, 0, 0, 0, 0, 0, 0, 0]), 64),
    (v6h([0x2001, 0, 0, 0, 0, 0, 0, 0]), 23),
    (v6h([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]), 32),
    (v6h([0x2002, 0, 0, 0, 0, 0, 0, 0]), 16),
    (v6h([0x3fff, 0, 0, 0, 0, 0, 0, 0]), 20),
    (v6h([0xfc00, 0, 0, 0, 0, 0, 0, 0]), 7),
    (v6h([0xfe80, 0, 0, 0, 0, 0, 0, 0]), 10),
];
const V6_PRIVATE_EXCEPTIONS: &[Block] = &[
    (v6h([0x2001, 1, 0, 0, 0, 0, 0, 1]), 128),
    (v6h([0x2001, 1, 0, 0, 0, 0, 0, 2]), 128),
    (v6h([0x2001, 3, 0, 0, 0, 0, 0, 0]), 32),
    (v6h([0x2001, 4, 0x112, 0, 0, 0, 0, 0]), 48),
    (v6h([0x2001, 0x20, 0, 0, 0, 0, 0, 0]), 28),
    (v6h([0x2001, 0x30, 0, 0, 0, 0, 0, 0]), 28),
];
const V6_RESERVED: &[Block] = &[
    (0, 8),
    (v6h([0x100, 0, 0, 0, 0, 0, 0, 0]), 8),
    (v6h([0x200, 0, 0, 0, 0, 0, 0, 0]), 7),
    (v6h([0x400, 0, 0, 0, 0, 0, 0, 0]), 6),
    (v6h([0x800, 0, 0, 0, 0, 0, 0, 0]), 5),
    (v6h([0x1000, 0, 0, 0, 0, 0, 0, 0]), 4),
    (v6h([0x4000, 0, 0, 0, 0, 0, 0, 0]), 3),
    (v6h([0x6000, 0, 0, 0, 0, 0, 0, 0]), 3),
    (v6h([0x8000, 0, 0, 0, 0, 0, 0, 0]), 3),
    (v6h([0xa000, 0, 0, 0, 0, 0, 0, 0]), 3),
    (v6h([0xc000, 0, 0, 0, 0, 0, 0, 0]), 3),
    (v6h([0xe000, 0, 0, 0, 0, 0, 0, 0]), 4),
    (v6h([0xf000, 0, 0, 0, 0, 0, 0, 0]), 5),
    (v6h([0xf800, 0, 0, 0, 0, 0, 0, 0]), 6),
    (v6h([0xfe00, 0, 0, 0, 0, 0, 0, 0]), 9),
];
const V6_LINK_LOCAL: Block = (v6h([0xfe80, 0, 0, 0, 0, 0, 0, 0]), 10);
const V6_MULTICAST: Block = (v6h([0xff00, 0, 0, 0, 0, 0, 0, 0]), 8);

impl Address {
    fn within(&self, (net, prefix): Block) -> bool {
        self.ip & netmask(self.v6, prefix) == net
    }

    /// `ipv4_mapped`.
    fn mapped(&self) -> Option<Address> {
        (self.v6 && (self.ip >> 32) == 0xffff).then_some(Address {
            v6: false,
            ip: self.ip & 0xffff_ffff,
        })
    }

    /// `is_private`.
    pub fn is_private(&self) -> bool {
        if let Some(m) = self.mapped() {
            return m.is_private();
        }
        let (private, exceptions) = if self.v6 {
            (V6_PRIVATE, V6_PRIVATE_EXCEPTIONS)
        } else {
            (V4_PRIVATE, V4_PRIVATE_EXCEPTIONS)
        };
        private.iter().any(|b| self.within(*b)) && !exceptions.iter().any(|b| self.within(*b))
    }

    /// `is_loopback`.
    pub fn is_loopback(&self) -> bool {
        match self.mapped() {
            Some(m) => m.is_loopback(),
            None if self.v6 => self.ip == 1,
            None => self.within(V4_LOOPBACK),
        }
    }

    /// `is_unspecified`.
    pub fn is_unspecified(&self) -> bool {
        match self.mapped() {
            Some(m) => m.is_unspecified(),
            None => self.ip == 0,
        }
    }

    /// `is_link_local`.
    pub fn is_link_local(&self) -> bool {
        match self.mapped() {
            Some(m) => m.is_link_local(),
            None if self.v6 => self.within(V6_LINK_LOCAL),
            None => self.within(V4_LINK_LOCAL),
        }
    }

    /// `is_reserved`.
    pub fn is_reserved(&self) -> bool {
        match self.mapped() {
            Some(m) => m.is_reserved(),
            None if self.v6 => V6_RESERVED.iter().any(|b| self.within(*b)),
            None => self.within(V4_RESERVED),
        }
    }

    /// `is_multicast`.
    pub fn is_multicast(&self) -> bool {
        match self.mapped() {
            Some(m) => m.is_multicast(),
            None if self.v6 => self.within(V6_MULTICAST),
            None => self.within(V4_MULTICAST),
        }
    }
}

fn v4_str(ip: u128) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 8) & 0xff,
        ip & 0xff
    )
}

/// `_string_from_ip_int` (`_compress_hextets` on lower-case hextets).
fn compressed(ip: u128) -> String {
    let hextets: Vec<String> = (0..8)
        .map(|i| format!("{:x}", (ip >> (112 - 16 * i)) & 0xffff))
        .collect();
    let (mut best_start, mut best_len, mut start, mut len) = (0usize, 0usize, 0usize, 0usize);
    for (i, h) in hextets.iter().enumerate() {
        if h == "0" {
            if len == 0 {
                start = i;
            }
            len += 1;
            if len > best_len {
                best_len = len;
                best_start = start;
            }
        } else {
            len = 0;
        }
    }
    if best_len > 1 {
        let end = best_start + best_len;
        let mut out: Vec<String> = hextets[..best_start].to_vec();
        if best_start == 0 {
            out.push(String::new());
        }
        out.push(String::new());
        out.extend_from_slice(&hextets[end..]);
        if end == 8 {
            out.push(String::new());
        }
        out.join(":")
    } else {
        hextets.join(":")
    }
}

fn v6_str(ip: u128) -> String {
    if (ip >> 32) == 0xffff {
        format!("{}:{}", compressed(ip >> 32), v4_str(ip & 0xffff_ffff))
    } else {
        compressed(ip)
    }
}

/// `_BaseV4._parse_octet`.
fn parse_octet(s: &str) -> Option<u128> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || s.len() > 3 {
        return None;
    }
    if s != "0" && s.starts_with('0') {
        return None;
    }
    let n: u128 = s.parse().ok()?;
    (n <= 255).then_some(n)
}

/// `_BaseV4._ip_int_from_string`.
fn parse_v4(s: &str) -> Option<u128> {
    if s.is_empty() {
        return None;
    }
    let octets: Vec<&str> = s.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut out = 0u128;
    for o in octets {
        out = (out << 8) | parse_octet(o)?;
    }
    Some(out)
}

/// `_BaseV6._parse_hextet`.
fn parse_hextet(s: &str) -> Option<u128> {
    if !s.chars().all(|c| c.is_ascii_hexdigit()) || s.chars().count() > 4 || s.is_empty() {
        return None;
    }
    u128::from_str_radix(s, 16).ok()
}

/// `_BaseV6._ip_int_from_string`.
fn parse_v6(s: &str) -> Option<u128> {
    if s.is_empty() || s.chars().count() > 45 {
        return None;
    }
    // `split(':', maxsplit=9)`.
    let mut parts: Vec<String> = s.splitn(10, ':').map(str::to_string).collect();
    if parts.len() < 3 {
        return None;
    }
    if parts.last().is_some_and(|p| p.contains('.')) {
        let tail = parts.pop()?;
        if tail.contains('/') {
            return None;
        }
        let v4 = parse_v4(&tail)?;
        parts.push(format!("{:x}", (v4 >> 16) & 0xffff));
        parts.push(format!("{:x}", v4 & 0xffff));
    }
    if parts.len() > 9 {
        return None;
    }
    let mut skip = None;
    for (i, p) in parts.iter().enumerate().take(parts.len() - 1).skip(1) {
        if p.is_empty() {
            if skip.is_some() {
                return None;
            }
            skip = Some(i);
        }
    }
    let n = parts.len();
    let (hi, lo, skipped) = match skip {
        Some(i) => {
            let mut hi = i;
            let mut lo = n - i - 1;
            if parts[0].is_empty() {
                hi -= 1;
                if hi != 0 {
                    return None;
                }
            }
            if parts[n - 1].is_empty() {
                lo -= 1;
                if lo != 0 {
                    return None;
                }
            }
            let used = hi + lo;
            if used >= 8 {
                return None;
            }
            (hi, lo, 8 - used)
        }
        None => {
            if n != 8 || parts[0].is_empty() || parts[n - 1].is_empty() {
                return None;
            }
            (n, 0, 0)
        }
    };
    let mut ip = 0u128;
    for p in &parts[..hi] {
        ip = (ip << 16) | parse_hextet(p)?;
    }
    for _ in 0..skipped {
        ip <<= 16;
    }
    for p in &parts[n - lo..] {
        ip = (ip << 16) | parse_hextet(p)?;
    }
    Some(ip)
}

/// `_prefix_from_prefix_string`.
fn prefix_from_str(s: &str, v6: bool) -> Option<u8> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let trimmed = s.trim_start_matches('0');
    if trimmed.len() > 3 {
        return None;
    }
    let n: u32 = if trimmed.is_empty() {
        0
    } else {
        trimmed.parse().ok()?
    };
    (n <= u32::from(max_prefix(v6))).then_some(n as u8)
}

/// `_prefix_from_ip_int` for IPv4: the length of a `1*0*` mask.
fn prefix_from_mask(mask: u128) -> Option<u8> {
    let mask = mask as u32;
    let ones = mask.leading_ones();
    let rest = mask.checked_shl(ones).unwrap_or(0);
    (rest == 0).then_some(ones as u8)
}

/// IPv4's `_make_netmask` for a string: a prefix length, else a dotted
/// netmask, else a dotted hostmask.
fn v4_mask(s: &str) -> Option<u8> {
    if let Some(p) = prefix_from_str(s, false) {
        return Some(p);
    }
    let ip = parse_v4(s)?;
    prefix_from_mask(ip).or_else(|| prefix_from_mask(ip ^ all_ones(false)))
}

/// `ip_network(text, strict=False)`; `None` is its `ValueError`.
pub fn ip_network(text: &str) -> Option<Network> {
    // `_split_optional_netmask`.
    let parts: Vec<&str> = text.split('/').collect();
    if parts.len() > 2 {
        return None;
    }
    let (addr, mask) = (parts[0], parts.get(1).copied());
    // IPv4Network.
    if let Some(ip) = parse_v4(addr) {
        let prefix = match mask {
            None => Some(32),
            Some(m) => v4_mask(m),
        };
        if let Some(prefix) = prefix {
            return Some(Network {
                v6: false,
                addr: ip & netmask(false, prefix),
                prefix,
                scope: None,
            });
        }
    }
    // IPv6Network: `IPv6Address(addr)` splits off a `%zone` first.
    let (bare, scope) = match addr.split_once('%') {
        None => (addr, None),
        Some((a, z)) if !z.is_empty() && !z.contains('%') => (a, Some(z.to_string())),
        Some(_) => return None,
    };
    let ip = parse_v6(bare)?;
    let prefix = match mask {
        None => 128,
        Some(m) => prefix_from_str(m, true)?,
    };
    let masked = ip & netmask(true, prefix);
    Some(Network {
        v6: true,
        addr: masked,
        prefix,
        // `IPv6Address(packed & netmask)` when host bits were set: no zone.
        scope: if masked == ip { scope } else { None },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_like_python() {
        let n = ip_network("2001:DB8::abcd").unwrap();
        assert_eq!(n.to_string(), "2001:db8::abcd/128");
        assert_eq!(
            ip_network("1:0:0:2:0:0:0:3").unwrap().address_str(),
            "1:0:0:2::3"
        );
        assert_eq!(ip_network("::").unwrap().address_str(), "::");
        assert_eq!(
            ip_network("::ffff:0:0/96").unwrap().to_string(),
            "::ffff:0.0.0.0/96"
        );
        assert_eq!(
            ip_network("fe80::1%eth0/64").unwrap().to_string(),
            "fe80::/64"
        );
        assert_eq!(
            ip_network("fe80::1%eth0").unwrap().to_string(),
            "fe80::1%eth0/128"
        );
        assert!(ip_network("1.2.3.4/255.0.255.0").is_none());
        assert_eq!(
            ip_network("1.2.3.4/0.0.255.255").unwrap().to_string(),
            "1.2.0.0/16"
        );
    }
}
