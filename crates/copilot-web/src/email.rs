//! `EmailStr` — pydantic's `validate_email` over email-validator 2.3
//! (`check_deliverability=False`, every other option at its default).
//!
//! The result is the *normalized* address the Python model stores: the
//! domain lowercased (UTS #46), RFC 2142 role mailboxes (`INFO@`,
//! `postmaster@`, …) lowercased, the local part NFC-normalized, a
//! `Name <addr>` wrapper and surrounding whitespace removed. Failures carry
//! email-validator's sentence; the caller reports it as pydantic does
//! (`value_error`, "value is not a valid email address: …").
//!
//! ASCII addresses — every address CoPilot has seen — follow the Python code
//! step for step, pinned by `email_vectors.json`. Internationalized domains
//! go through the `idna` crate (UTS #46, as the Python `idna` package): valid
//! ones normalize the same; *why* an invalid one is refused can be worded
//! differently. Unicode properties come from current Unicode data, Python's
//! from Unicode 14, so characters assigned since then classify differently.

use std::sync::OnceLock;

use icu_properties::CodePointMapData;
use icu_properties::props::GeneralCategory;
use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};
use regex::Regex;
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::decompose_compatible;

/// pydantic's `MAX_EMAIL_LENGTH`.
const MAX_EMAIL_LENGTH: usize = 2048;
/// RFC 5321 limits as email-validator applies them.
const EMAIL_MAX_LENGTH: usize = 254;
const DOMAIN_MAX_LENGTH: usize = 253;
const DNS_LABEL_LENGTH_LIMIT: usize = 63;

/// RFC 2142 mailbox names, compared case-insensitively.
const CASE_INSENSITIVE_MAILBOX_NAMES: &[&str] = &[
    "info",
    "marketing",
    "sales",
    "support",
    "abuse",
    "noc",
    "security",
    "postmaster",
    "hostmaster",
    "usenet",
    "news",
    "webmaster",
    "www",
    "uucp",
    "ftp",
];

/// IANA special-use domains email-validator refuses.
const SPECIAL_USE_DOMAIN_NAMES: &[&str] =
    &["arpa", "invalid", "local", "localhost", "onion", "test"];

/// `validate_email(value)`: the normalized address, or the full pydantic
/// message (`value is not a valid email address: …`).
pub fn validate_email(value: &str) -> Result<String, String> {
    validate(value).map_err(|reason| format!("value is not a valid email address: {reason}"))
}

type Res<T> = Result<T, String>;

// ---------------------------------------------------------------------------
// Unicode helpers
// ---------------------------------------------------------------------------

/// The two-letter general category (`unicodedata.category`).
fn category(c: char) -> &'static str {
    use GeneralCategory as G;
    match CodePointMapData::<GeneralCategory>::new().get(c) {
        G::Unassigned => "Cn",
        G::UppercaseLetter => "Lu",
        G::LowercaseLetter => "Ll",
        G::TitlecaseLetter => "Lt",
        G::ModifierLetter => "Lm",
        G::OtherLetter => "Lo",
        G::NonspacingMark => "Mn",
        G::SpacingMark => "Mc",
        G::EnclosingMark => "Me",
        G::DecimalNumber => "Nd",
        G::LetterNumber => "Nl",
        G::OtherNumber => "No",
        G::SpaceSeparator => "Zs",
        G::LineSeparator => "Zl",
        G::ParagraphSeparator => "Zp",
        G::Control => "Cc",
        G::Format => "Cf",
        G::PrivateUse => "Co",
        G::Surrogate => "Cs",
        G::DashPunctuation => "Pd",
        G::OpenPunctuation => "Ps",
        G::ClosePunctuation => "Pe",
        G::ConnectorPunctuation => "Pc",
        G::OtherPunctuation => "Po",
        G::InitialPunctuation => "Pi",
        G::FinalPunctuation => "Pf",
        G::MathSymbol => "Sm",
        G::CurrencySymbol => "Sc",
        G::ModifierSymbol => "Sk",
        G::OtherSymbol => "So",
    }
}

/// `unicodedata.name` for the characters email-validator names in its
/// messages (spaces, separators, format and combining characters); others
/// fall back to the `U+XXXX` form Python uses for unnamed characters.
fn char_name(c: char) -> Option<&'static str> {
    Some(match c {
        ' ' => "SPACE",
        '\u{a0}' => "NO-BREAK SPACE",
        '\u{ad}' => "SOFT HYPHEN",
        '\u{300}' => "COMBINING GRAVE ACCENT",
        '\u{301}' => "COMBINING ACUTE ACCENT",
        '\u{302}' => "COMBINING CIRCUMFLEX ACCENT",
        '\u{303}' => "COMBINING TILDE",
        '\u{308}' => "COMBINING DIAERESIS",
        '\u{338}' => "COMBINING LONG SOLIDUS OVERLAY",
        '\u{1680}' => "OGHAM SPACE MARK",
        '\u{2000}' => "EN QUAD",
        '\u{2001}' => "EM QUAD",
        '\u{2002}' => "EN SPACE",
        '\u{2003}' => "EM SPACE",
        '\u{2004}' => "THREE-PER-EM SPACE",
        '\u{2005}' => "FOUR-PER-EM SPACE",
        '\u{2006}' => "SIX-PER-EM SPACE",
        '\u{2007}' => "FIGURE SPACE",
        '\u{2008}' => "PUNCTUATION SPACE",
        '\u{2009}' => "THIN SPACE",
        '\u{200a}' => "HAIR SPACE",
        '\u{200b}' => "ZERO WIDTH SPACE",
        '\u{200c}' => "ZERO WIDTH NON-JOINER",
        '\u{200d}' => "ZERO WIDTH JOINER",
        '\u{200e}' => "LEFT-TO-RIGHT MARK",
        '\u{200f}' => "RIGHT-TO-LEFT MARK",
        '\u{2028}' => "LINE SEPARATOR",
        '\u{2029}' => "PARAGRAPH SEPARATOR",
        '\u{202a}' => "LEFT-TO-RIGHT EMBEDDING",
        '\u{202b}' => "RIGHT-TO-LEFT EMBEDDING",
        '\u{202c}' => "POP DIRECTIONAL FORMATTING",
        '\u{202d}' => "LEFT-TO-RIGHT OVERRIDE",
        '\u{202e}' => "RIGHT-TO-LEFT OVERRIDE",
        '\u{202f}' => "NARROW NO-BREAK SPACE",
        '\u{205f}' => "MEDIUM MATHEMATICAL SPACE",
        '\u{2060}' => "WORD JOINER",
        '\u{2066}' => "LEFT-TO-RIGHT ISOLATE",
        '\u{2067}' => "RIGHT-TO-LEFT ISOLATE",
        '\u{2068}' => "FIRST STRONG ISOLATE",
        '\u{2069}' => "POP DIRECTIONAL ISOLATE",
        '\u{3000}' => "IDEOGRAPHIC SPACE",
        '\u{feff}' => "ZERO WIDTH NO-BREAK SPACE",
        _ => return None,
    })
}

/// `safe_character_display`.
fn display(c: char) -> String {
    if c == '\\' {
        return "\"\\\"".to_string();
    }
    if matches!(category(c).as_bytes()[0], b'L' | b'N' | b'P' | b'S') {
        // repr() of a one-character string.
        return if c == '\'' {
            "\"'\"".to_string()
        } else {
            format!("'{c}'")
        };
    }
    match char_name(c) {
        Some(name) => name.to_string(),
        None if (c as u32) < 0xFFFF => format!("U+{:04X}", c as u32),
        None => format!("U+{:08X}", c as u32),
    }
}

/// `", ".join(sorted({display(c) for c in …}))`.
fn sorted_displays(chars: impl Iterator<Item = char>) -> String {
    let mut shown: Vec<String> = chars.map(display).collect();
    shown.sort();
    shown.dedup();
    shown.join(", ")
}

/// Python's `str.isspace()`.
fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

// ---------------------------------------------------------------------------
// Character classes (email_validator/rfc_constants.py)
// ---------------------------------------------------------------------------

fn is_atext(c: char) -> bool {
    c.is_ascii_alphanumeric() || "_!#$%&'*+-/=?^`{|}~".contains(c)
}

fn is_atext_intl(c: char) -> bool {
    is_atext(c) || c >= '\u{80}'
}

fn is_hostname_intl(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '.' || c >= '\u{80}'
}

/// `[ATEXT]+(?:\.[ATEXT]+)*\Z`.
fn dot_atom(s: &str, atext: fn(char) -> bool) -> bool {
    !s.is_empty()
        && s.split('.')
            .all(|seg| !seg.is_empty() && seg.chars().all(atext))
}

/// `DOT_ATOM_TEXT_HOSTNAME`.
fn dot_atom_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|label| {
            let b = label.as_bytes();
            !b.is_empty()
                && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
                && b[0] != b'-'
                && b[b.len() - 1] != b'-'
        })
}

// ---------------------------------------------------------------------------
// split_email
// ---------------------------------------------------------------------------

/// `split_string_at_unquoted_special`.
fn split_at_special(text: &[char], specials: &[char]) -> Res<(Vec<char>, Vec<char>)> {
    let mut inside_quote = false;
    let mut escaped = false;
    let mut left = Vec::new();
    for (i, &c) in text.iter().enumerate() {
        let combines = text[i..].iter().copied().nfc().next() != Some(c);
        if combines {
            left.push(c);
        } else if inside_quote {
            left.push(c);
            if c == '\\' && !escaped {
                escaped = true;
            } else if c == '"' && !escaped {
                inside_quote = false;
                escaped = false;
            } else {
                escaped = false;
            }
        } else if c == '"' {
            left.push(c);
            inside_quote = true;
        } else if specials.contains(&c) {
            break;
        } else {
            left.push(c);
        }
    }
    if left.len() == text.len() {
        if text.contains(&'＠') {
            return Err("The email address has the \"full-width\" at-sign (@) character instead of a regular at-sign.".into());
        }
        if text.contains(&'﹫') {
            return Err("The email address has the \"small commercial at\" character instead of a regular at-sign.".into());
        }
        return Err("An email address must have an @-sign.".into());
    }
    let right = text[left.len()..].to_vec();
    Ok((left, right))
}

/// `unquote_quoted_string`: the value and whether it was quoted.
fn unquote(text: &[char]) -> Res<(String, bool)> {
    let mut quoted = false;
    let mut escaped = false;
    let mut value = String::new();
    for (i, &c) in text.iter().enumerate() {
        if quoted {
            if escaped {
                value.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                if i != text.len() - 1 {
                    let rest: Vec<String> = text[i + 1..].iter().map(|&c| display(c)).collect();
                    return Err(format!(
                        "Extra character(s) found after close quote: {}",
                        rest.join(", ")
                    ));
                }
                break;
            } else {
                value.push(c);
            }
        } else if i == 0 && c == '"' {
            quoted = true;
        } else {
            value.push(c);
        }
    }
    Ok((value, quoted))
}

struct Split {
    display_name: Option<String>,
    local: String,
    domain: String,
    quoted_local: bool,
}

fn split_email(email: &str) -> Res<Split> {
    let chars: Vec<char> = email.chars().collect();
    let (left, right) = split_at_special(&chars, &['@', '<'])?;
    let (display_name, local, mut domain) = if right.first() == Some(&'<') {
        let mut left = left;
        while left.last().is_some_and(|&c| is_py_space(c)) {
            left.pop();
        }
        let (name, name_quoted) = unquote(&left)?;
        if !name_quoted {
            let bad: Vec<char> = name
                .chars()
                .filter(|&c| (!(is_atext(c) || c == '.') && c != ' ') || c == '.')
                .collect();
            if !bad.is_empty() {
                return Err(format!(
                    "The display name contains invalid characters when not quoted: {}.",
                    sorted_displays(bad.into_iter())
                ));
            }
        }
        check_unsafe_chars(&name, true)?;
        if !right.contains(&'>') {
            return Err("An open angle bracket at the start of the email address has to be followed by a close angle bracket at the end.".into());
        }
        let mut right = right;
        while right.last() == Some(&' ') {
            right.pop();
        }
        if right.last() != Some(&'>') {
            return Err("There can't be anything after the email address.".into());
        }
        let mut spec = right[1..].to_vec();
        while spec.last() == Some(&'>') {
            spec.pop();
        }
        let (local, domain) = split_at_special(&spec, &['@'])?;
        (Some(name), local, domain)
    } else {
        (None, left, right)
    };
    if domain.first() == Some(&'@') {
        domain.remove(0);
    }
    let (local, quoted_local) = unquote(&local)?;
    Ok(Split {
        display_name,
        local,
        domain: domain.into_iter().collect(),
        quoted_local,
    })
}

// ---------------------------------------------------------------------------
// Local part
// ---------------------------------------------------------------------------

/// `check_unsafe_chars`.
fn check_unsafe_chars(s: &str, allow_space: bool) -> Res<()> {
    let mut bad: Vec<char> = Vec::new();
    for (i, c) in s.chars().enumerate() {
        let cat = category(c);
        let unsafe_char = match cat.as_bytes()[0] {
            b'L' | b'N' | b'P' | b'S' => false,
            b'M' => i == 0,
            _ if cat == "Zs" => !allow_space,
            _ => true,
        };
        if unsafe_char {
            bad.push(c);
        }
    }
    if bad.is_empty() {
        return Ok(());
    }
    bad.sort_unstable();
    bad.dedup();
    let shown: Vec<String> = bad.into_iter().map(display).collect();
    Err(format!(
        "The email address contains unsafe characters: {}.",
        shown.join(", ")
    ))
}

/// `check_dot_atom`.
fn check_dot_atom(label: &str, start: &str, end: &str, hostname: bool) -> Res<()> {
    let fill = |template: &str, what: &str| template.replace("{}", what);
    if label.ends_with('.') {
        return Err(fill(end, "period"));
    }
    if label.starts_with('.') {
        return Err(fill(start, "period"));
    }
    if label.contains("..") {
        return Err("An email address cannot have two periods in a row.".into());
    }
    if hostname {
        if label.ends_with('-') {
            return Err(fill(end, "hyphen"));
        }
        if label.starts_with('-') {
            return Err(fill(start, "hyphen"));
        }
        if label.contains(".-") || label.contains("-.") {
            return Err(
                "An email address cannot have a period and a hyphen next to each other.".into(),
            );
        }
    }
    Ok(())
}

struct LocalPart {
    local: String,
    /// The local part when it needs no SMTPUTF8.
    ascii: Option<String>,
}

/// `validate_email_local_part` (UTF-8 allowed, empty refused, not strict).
fn validate_local(local: &str, quoted: bool) -> Res<LocalPart> {
    if local.is_empty() {
        return Err("There must be something before the @-sign.".into());
    }
    if dot_atom(local, is_atext) {
        return Ok(LocalPart {
            local: local.to_string(),
            ascii: Some(local.to_string()),
        });
    }
    let mut valid: Option<&str> = None;
    let mut smtputf8 = false;
    if dot_atom(local, is_atext_intl) {
        valid = Some("dot-atom");
        smtputf8 = true;
    } else if quoted {
        let bad: Vec<char> = local
            .chars()
            .filter(|&c| !(('\u{20}'..='\u{7e}').contains(&c) || c >= '\u{80}'))
            .collect();
        if !bad.is_empty() {
            return Err(format!(
                "The email address contains invalid characters in quotes before the @-sign: {}.",
                sorted_displays(bad.into_iter())
            ));
        }
        smtputf8 = local.chars().any(|c| !('\u{20}'..='\u{7e}').contains(&c));
        valid = Some("quoted");
    }
    if let Some(kind) = valid {
        check_unsafe_chars(local, kind == "quoted")?;
        let local = if kind == "quoted" {
            let mut q = String::from('"');
            for c in local.chars() {
                if c == '"' || c == '\\' {
                    q.push('\\');
                }
                q.push(c);
            }
            q.push('"');
            q
        } else {
            local.to_string()
        };
        return Ok(LocalPart {
            ascii: (!smtputf8).then(|| local.clone()),
            local,
        });
    }
    let bad: Vec<char> = local
        .chars()
        .filter(|&c| !(c == '.' || is_atext_intl(c)))
        .collect();
    if !bad.is_empty() {
        return Err(format!(
            "The email address contains invalid characters before the @-sign: {}.",
            sorted_displays(bad.into_iter())
        ));
    }
    check_dot_atom(
        local,
        "An email address cannot start with a {}.",
        "An email address cannot have a {} immediately before the @-sign.",
        false,
    )?;
    Err("The email address contains invalid characters before the @-sign.".into())
}

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

/// `uts46_valid_char`.
fn uts46_valid_char(c: char) -> bool {
    let u = c as u32;
    if (0x80..=0x9f).contains(&u) {
        return false;
    }
    if ((0x2010..=0x2060).contains(&u)
        && !(0x2024..=0x2026).contains(&u)
        && !(0x2028..=0x202E).contains(&u))
        || matches!(u, 0x00AD | 0x2064 | 0xFF0E)
        || (0x200B..=0x200D).contains(&u)
        || (0x1BCA0..=0x1BCA3).contains(&u)
    {
        return true;
    }
    if matches!(category(c), "Cf" | "Cn" | "Co" | "Cs" | "Zs" | "Zl" | "Zp") {
        return false;
    }
    let mut has_dot = false;
    decompose_compatible(c, |d| has_dot |= d == '.' && c != '.');
    !has_dot
}

fn uts46() -> &'static Uts46 {
    static U: OnceLock<Uts46> = OnceLock::new();
    U.get_or_init(Uts46::new)
}

/// `get_length_reason`.
fn length_reason(len: usize, limit: usize) -> String {
    let diff = len - limit;
    let s = if diff > 1 { "s" } else { "" };
    format!("({diff} character{s} too many)")
}

/// `idna.decode` for an ASCII domain whose labels are not Punycode: the
/// labels lowercased (all of them are valid IDNA 2008 by now).
fn ascii_to_unicode(ascii: &str) -> Res<String> {
    if !ascii
        .split('.')
        .any(|l| l.to_ascii_lowercase().starts_with("xn--"))
    {
        return Ok(ascii.to_ascii_lowercase());
    }
    let (unicode, result) =
        uts46().to_unicode(ascii.as_bytes(), AsciiDenyList::EMPTY, Hyphens::Allow);
    match result {
        Ok(()) if !unicode.contains('\u{fffd}') => Ok(unicode.into_owned()),
        _ => Err(format!(
            "The part after the @-sign is not valid IDNA (Invalid A-label in '{ascii}')."
        )),
    }
}

struct Domain {
    ascii: String,
    unicode: String,
}

/// `validate_email_domain_name` (globally deliverable, not a test
/// environment).
fn validate_domain(domain: &str) -> Res<Domain> {
    let bad: Vec<char> = domain.chars().filter(|&c| !is_hostname_intl(c)).collect();
    if !bad.is_empty() {
        return Err(format!(
            "The part after the @-sign contains invalid characters: {}.",
            sorted_displays(bad.into_iter())
        ));
    }
    check_unsafe_chars(domain, false)?;
    let bad: Vec<char> = domain.chars().filter(|&c| !uts46_valid_char(c)).collect();
    if !bad.is_empty() {
        return Err(format!(
            "The part after the @-sign contains invalid characters: {}.",
            sorted_displays(bad.into_iter())
        ));
    }
    let original = domain;
    // uts46_remap: ASCII is only lowercased; anything else goes through UTS #46.
    let remapped = if domain.is_ascii() {
        domain.to_ascii_lowercase()
    } else {
        let (mapped, result) =
            uts46().to_unicode(domain.as_bytes(), AsciiDenyList::EMPTY, Hyphens::Allow);
        if result.is_err() {
            return Err(format!(
                "The part after the @-sign contains invalid characters (Codepoint not allowed in {domain:?})."
            ));
        }
        mapped.into_owned()
    };
    let bad: Vec<char> = remapped.chars().filter(|&c| !is_hostname_intl(c)).collect();
    if !bad.is_empty() {
        return Err(format!(
            "The part after the @-sign contains invalid characters after Unicode normalization: {}.",
            sorted_displays(bad.into_iter())
        ));
    }
    check_dot_atom(
        &remapped,
        "An email address cannot have a {} immediately after the @-sign.",
        "An email address cannot end with a {}.",
        true,
    )?;
    for label in remapped.split('.') {
        let chars: Vec<char> = label.chars().collect();
        let starts_xn = chars.len() >= 2
            && chars[..2]
                .iter()
                .collect::<String>()
                .eq_ignore_ascii_case("xn");
        if chars.len() >= 4 && chars[2] == '-' && chars[3] == '-' && !starts_xn {
            return Err("An email address cannot have two letters followed by two dashes immediately after the @-sign or after a period, except Punycode.".into());
        }
    }
    let ascii = if dot_atom_hostname(&remapped) {
        remapped.clone()
    } else {
        let ascii = uts46()
            .to_ascii(
                remapped.as_bytes(),
                AsciiDenyList::EMPTY,
                Hyphens::Allow,
                DnsLength::Ignore,
            )
            .map_err(|_| {
                format!(
                    "The part after the @-sign is invalid (Codepoint not allowed in {remapped:?})."
                )
            })?
            .into_owned();
        if !dot_atom_hostname(&ascii) {
            return Err("The email address contains invalid characters after the @-sign after IDNA encoding.".into());
        }
        ascii
    };
    if ascii.len() > DOMAIN_MAX_LENGTH {
        if ascii == original {
            return Err(format!(
                "The email address is too long after the @-sign {}.",
                length_reason(ascii.len(), DOMAIN_MAX_LENGTH)
            ));
        }
        let diff = ascii.len() - DOMAIN_MAX_LENGTH;
        let s = if diff == 1 { "" } else { "s" };
        return Err(format!(
            "The email address is too long after the @-sign ({diff} byte{s} too many after IDNA encoding)."
        ));
    }
    for label in ascii.split('.') {
        if label.len() > DNS_LABEL_LENGTH_LIMIT {
            return Err(format!(
                "After the @-sign, periods cannot be separated by so many characters {}.",
                length_reason(label.len(), DNS_LABEL_LENGTH_LIMIT)
            ));
        }
    }
    if !ascii.contains('.') {
        return Err("The part after the @-sign is not valid. It should have a period.".into());
    }
    if !ascii
        .chars()
        .last()
        .is_some_and(|c| c.is_ascii_alphabetic())
    {
        return Err(
            "The part after the @-sign is not valid. It is not within a valid top-level domain."
                .into(),
        );
    }
    for d in SPECIAL_USE_DOMAIN_NAMES {
        if ascii == *d || ascii.ends_with(&format!(".{d}")) {
            return Err("The part after the @-sign is a special-use or reserved name that cannot be used with email.".into());
        }
    }
    let unicode = ascii_to_unicode(&ascii)?;
    let bad: Vec<char> = unicode.chars().filter(|&c| !is_hostname_intl(c)).collect();
    if !bad.is_empty() {
        return Err(format!(
            "The part after the @-sign contains invalid characters: {}.",
            sorted_displays(bad.into_iter())
        ));
    }
    check_unsafe_chars(&unicode, false)?;
    Ok(Domain { ascii, unicode })
}

/// `validate_email_domain_literal` — every outcome is a refusal here
/// (domain literals are not allowed), but with the right reason.
fn domain_literal(literal: &str) -> String {
    if !literal.is_empty() && literal.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return match ipv4_error(literal) {
            Some(e) => format!(
                "The address in brackets after the @-sign is not valid: It is not an IPv4 address ({e}) or is missing an address literal tag."
            ),
            None => "A bracketed IP address after the @-sign is not allowed here.".into(),
        };
    }
    if let Some(v6) = literal.strip_prefix("IPv6:") {
        return match v6.parse::<std::net::Ipv6Addr>() {
            Ok(_) => "A bracketed IP address after the @-sign is not allowed here.".into(),
            Err(_) => format!(
                "The IPv6 address in brackets after the @-sign is not valid ({v6:?} does not appear to be an IPv6 address)."
            ),
        };
    }
    if !literal.contains(':') {
        return "The part after the @-sign in brackets is not an IPv4 address and has no address literal tag.".into();
    }
    let bad: Vec<char> = literal
        .chars()
        .filter(|&c| !('\u{21}'..='\u{fa}').contains(&c))
        .collect();
    if !bad.is_empty() {
        return format!(
            "The part after the @-sign contains invalid characters in brackets: {}.",
            sorted_displays(bad.into_iter())
        );
    }
    "The part after the @-sign contains an invalid address literal tag in brackets.".into()
}

/// Python's `repr()` of an ASCII string.
fn ascii_repr(s: &str) -> String {
    format!("'{s}'")
}

/// `ipaddress.IPv4Address(text)`'s error, if any.
fn ipv4_error(text: &str) -> Option<String> {
    let octets: Vec<&str> = text.split('.').collect();
    if octets.len() != 4 {
        return Some(format!("Expected 4 octets in {}", ascii_repr(text)));
    }
    for octet in octets {
        let why = if octet.is_empty() {
            Some("Empty octet not permitted".to_string())
        } else if octet.len() > 3 {
            Some(format!(
                "At most 3 characters permitted in {}",
                ascii_repr(octet)
            ))
        } else if octet != "0" && octet.starts_with('0') {
            Some(format!(
                "Leading zeros are not permitted in {}",
                ascii_repr(octet)
            ))
        } else {
            let n: u32 = octet.parse().unwrap_or(0);
            (n > 255).then(|| format!("Octet {n} (> 255) not permitted"))
        };
        if let Some(why) = why {
            return Some(format!("{why} in {}", ascii_repr(text)));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// The whole address
// ---------------------------------------------------------------------------

fn pretty_email() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let name = r"[\p{L}\p{N}_!#$%&'*+\-/=?^`{|}~]";
        let ws = r"[\s\x1c-\x1f]";
        #[allow(clippy::expect_used)]
        Regex::new(&format!(
            r#"^{ws}*(?:((?:{name}+{ws}+)*{name}+)|"((?:[^"]|")+)")?{ws}*<(.+)>{ws}*$"#
        ))
        .expect("static pretty-email pattern")
    })
}

/// `validate_email_length`.
fn check_length(original: &str, normalized: &str, ascii_form: &str) -> Res<()> {
    let forms: [(&str, Option<&str>); 3] = [
        (original, None),
        (normalized, Some("after normalization")),
        (
            ascii_form,
            Some("when the part after the @-sign is converted to IDNA ASCII"),
        ),
    ];
    for (addr, reason) in forms {
        let chars = addr.chars().count();
        let bytes = addr.len();
        if bytes <= EMAIL_MAX_LENGTH {
            continue;
        }
        let diff = bytes - EMAIL_MAX_LENGTH;
        let s = if diff > 1 { "s" } else { "" };
        let reason = match reason {
            None if chars == bytes => length_reason(chars, EMAIL_MAX_LENGTH),
            None => {
                let mbpc = addr.chars().map(char::len_utf8).max().unwrap_or(1);
                let mchars = (diff / mbpc).max(1);
                if mchars == diff {
                    format!("({diff} character{s} too many)")
                } else {
                    format!("({mchars}-{diff} character{s} too many)")
                }
            }
            Some(r) => format!("{r} ({diff} byte{s} too many)"),
        };
        return Err(format!("The email address is too long {reason}."));
    }
    Ok(())
}

fn validate(value: &str) -> Res<String> {
    if value.chars().count() > MAX_EMAIL_LENGTH {
        return Err(format!(
            "Length must not exceed {MAX_EMAIL_LENGTH} characters"
        ));
    }
    let value = match pretty_email().captures(value) {
        Some(c) => c.get(3).map_or(value, |m| m.as_str()),
        None => value,
    };
    let email = value.trim_matches(is_py_space);

    let split = split_email(email)?;
    let original = format!(
        "{}@{}",
        if split.quoted_local {
            format!("\"{}\"", split.local)
        } else {
            split.local.clone()
        },
        split.domain
    );
    let mut local = validate_local(&split.local, split.quoted_local)?;
    let nfc: String = local.local.nfc().collect();
    if nfc != local.local {
        validate_local(&nfc, split.quoted_local)
            .map_err(|e| format!("After Unicode normalization: {e}"))?;
        local.local = nfc;
    }
    if split.quoted_local {
        return Err("Quoting the part before the @-sign is not allowed here.".into());
    }
    if let Some(ascii) = &local.ascii {
        if CASE_INSENSITIVE_MAILBOX_NAMES.contains(&ascii.to_lowercase().as_str()) {
            local.ascii = Some(ascii.to_lowercase());
            local.local = local.local.to_lowercase();
        }
    }
    let domain = &split.domain;
    if domain.is_empty() {
        return Err("There must be something after the @-sign.".into());
    }
    if domain.starts_with('[') && domain.ends_with(']') {
        let inner = if domain.len() >= 2 {
            &domain[1..domain.len() - 1]
        } else {
            ""
        };
        return Err(domain_literal(inner));
    }
    let domain = validate_domain(domain)?;
    let normalized = format!("{}@{}", local.local, domain.unicode);
    let ascii_form = format!(
        "{}@{}",
        local.ascii.as_deref().unwrap_or(&local.local),
        domain.ascii
    );
    check_length(&original, &normalized, &ascii_form)?;
    if split.display_name.is_some() {
        return Err(
            "A display name and angle brackets around the email address are not permitted here."
                .into(),
        );
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Internationalized domains Python refuses: the reason is worded by the
    /// `idna` package, which this port does not reproduce — the prefix is.
    const IDNA_WORDED: &[&str] = &["a@xn--a.com"];

    #[test]
    fn matches_pydantic() {
        let doc: Value = serde_json::from_str(include_str!("email_vectors.json")).unwrap();
        for case in doc["cases"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let got = validate_email(input);
            match (&got, case.get("email"), case.get("error")) {
                (Ok(email), Some(want), _) => {
                    assert_eq!(email, want.as_str().unwrap(), "{input:?}")
                }
                (Err(msg), _, Some(want)) => {
                    let want = want.as_str().unwrap();
                    if IDNA_WORDED.contains(&input) {
                        let prefix = &want[..want.find('(').unwrap()];
                        assert!(msg.starts_with(prefix), "{input:?}: {msg}");
                    } else {
                        assert_eq!(msg, want, "{input:?}");
                    }
                }
                _ => panic!("{input:?}: got {got:?}, want {case}"),
            }
        }
    }
}
