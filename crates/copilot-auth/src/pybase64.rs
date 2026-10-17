//! CPython's lenient base64 (`binascii.a2b_base64(strict_mode=False)`), which
//! py_webauthn's `base64url_to_bytes` and PyJWT's `base64url_decode` both sit
//! on: characters outside the alphabet are skipped, padding may be missing,
//! and decoding stops at the first complete padding sequence. A strict decoder
//! would refuse values Python accepts (a stray `=`, a newline, an `!`).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Why a value did not decode — the `str(e)` Python reports.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Base64Error {
    /// `binascii.Error`: one data character too many.
    #[error(
        "Invalid base64-encoded string: number of data characters ({0}) cannot be 1 more than a multiple of 4"
    )]
    OneTooMany(usize),
    /// `binascii.Error`: a quad was left incomplete without padding.
    #[error("Incorrect padding")]
    IncorrectPadding,
    /// `ValueError` from `_bytes_from_decode_data` for a non-ASCII `str`.
    #[error("string argument should contain only ASCII characters")]
    NonAscii,
    /// Strict mode: `=` as the first character.
    #[error("Leading padding not allowed")]
    LeadingPadding,
    /// Strict mode: anything after a complete padding sequence.
    #[error("Excess data after padding")]
    ExcessDataAfterPadding,
    /// Strict mode: a character outside the alphabet.
    #[error("Only base64 data is allowed")]
    OnlyBase64,
    /// Strict mode: data after a `=` that did not end the quad.
    #[error("Discontinuous padding not allowed")]
    DiscontinuousPadding,
}

fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// `binascii.a2b_base64(data, strict_mode=False)` (CPython 3.11).
pub fn a2b_base64(data: &[u8]) -> Result<Vec<u8>, Base64Error> {
    let mut out = Vec::with_capacity(data.len() / 4 * 3 + 3);
    let mut quad_pos = 0u8;
    let mut pads = 0u8;
    let mut left = 0u8;
    for &byte in data {
        if byte == b'=' {
            if quad_pos >= 2 {
                pads += 1;
                if quad_pos + pads >= 4 {
                    return Ok(out);
                }
            }
            continue;
        }
        let Some(value) = sextet(byte) else {
            continue;
        };
        pads = 0;
        match quad_pos {
            0 => {
                quad_pos = 1;
                left = value;
            }
            1 => {
                quad_pos = 2;
                out.push((left << 2) | (value >> 4));
                left = value & 0x0f;
            }
            2 => {
                quad_pos = 3;
                out.push((left << 4) | (value >> 2));
                left = value & 0x03;
            }
            _ => {
                quad_pos = 0;
                out.push((left << 6) | value);
                left = 0;
            }
        }
    }
    match quad_pos {
        0 => Ok(out),
        1 => Err(Base64Error::OneTooMany(out.len() / 3 * 4 + 1)),
        _ => Err(Base64Error::IncorrectPadding),
    }
}

/// `binascii.a2b_base64(data, strict_mode=True)` (CPython 3.11), which
/// `base64.b64decode(s, validate=True)` calls: no character outside the
/// alphabet, no `=` first, nothing after a complete padding sequence, no data
/// after a `=`. A `=` after a complete quad is skipped, as in CPython, and the
/// unused bits of the last character are not checked.
pub fn a2b_base64_strict(data: &[u8]) -> Result<Vec<u8>, Base64Error> {
    let mut out = Vec::with_capacity(data.len() / 4 * 3 + 3);
    let mut quad_pos = 0u8;
    let mut pads = 0u8;
    let mut left = 0u8;
    let mut padding_started = false;
    for (i, &byte) in data.iter().enumerate() {
        if byte == b'=' {
            padding_started = true;
            if i == 0 {
                return Err(Base64Error::LeadingPadding);
            }
            if quad_pos >= 2 {
                pads += 1;
                if quad_pos + pads >= 4 {
                    if i + 1 < data.len() {
                        return Err(Base64Error::ExcessDataAfterPadding);
                    }
                    return Ok(out);
                }
            }
            continue;
        }
        let Some(value) = sextet(byte) else {
            return Err(Base64Error::OnlyBase64);
        };
        if padding_started {
            return Err(Base64Error::DiscontinuousPadding);
        }
        pads = 0;
        match quad_pos {
            0 => {
                quad_pos = 1;
                left = value;
            }
            1 => {
                quad_pos = 2;
                out.push((left << 2) | (value >> 4));
                left = value & 0x0f;
            }
            2 => {
                quad_pos = 3;
                out.push((left << 4) | (value >> 2));
                left = value & 0x03;
            }
            _ => {
                quad_pos = 0;
                out.push((left << 6) | value);
                left = 0;
            }
        }
    }
    match quad_pos {
        0 => Ok(out),
        1 => Err(Base64Error::OneTooMany(out.len() / 3 * 4 + 1)),
        _ => Err(Base64Error::IncorrectPadding),
    }
}

/// `base64.b64decode(s, validate=True)` on a `str`: ASCII only, then
/// [`a2b_base64_strict`].
pub fn b64decode_validate(value: &str) -> Result<Vec<u8>, Base64Error> {
    if !value.is_ascii() {
        return Err(Base64Error::NonAscii);
    }
    a2b_base64_strict(value.as_bytes())
}

/// `base64.urlsafe_b64decode(bytes)`: `-`/`_` read as `+`/`/`.
pub fn urlsafe_b64decode(data: &[u8]) -> Result<Vec<u8>, Base64Error> {
    let translated: Vec<u8> = data
        .iter()
        .map(|b| match b {
            b'-' => b'+',
            b'_' => b'/',
            other => *other,
        })
        .collect();
    a2b_base64(&translated)
}

/// py_webauthn's `base64url_to_bytes`: `urlsafe_b64decode(f"{val}===")` on a
/// `str` (which must be ASCII).
pub fn base64url_to_bytes(value: &str) -> Result<Vec<u8>, Base64Error> {
    if !value.is_ascii() {
        return Err(Base64Error::NonAscii);
    }
    let mut padded = Vec::with_capacity(value.len() + 3);
    padded.extend_from_slice(value.as_bytes());
    padded.extend_from_slice(b"===");
    urlsafe_b64decode(&padded)
}

/// PyJWT's `base64url_decode`: the UTF-8 bytes, padded to a multiple of four.
pub fn jwt_base64url_decode(value: &str) -> Result<Vec<u8>, Base64Error> {
    let mut padded = value.as_bytes().to_vec();
    let rem = padded.len() % 4;
    if rem > 0 {
        padded.extend(std::iter::repeat_n(b'=', 4 - rem));
    }
    urlsafe_b64decode(&padded)
}

/// `bytes_to_base64url` / PyJWT's `base64url_encode`: URL-safe, unpadded.
pub fn bytes_to_base64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lenient_rules() {
        assert_eq!(base64url_to_bytes("QQ").unwrap(), b"A");
        assert_eq!(base64url_to_bytes("Q=Q").unwrap(), b"A");
        assert_eq!(base64url_to_bytes("a!b").unwrap(), [0x69]);
        assert_eq!(base64url_to_bytes("QQ=QQQQ=QQ").unwrap().len(), 6);
        assert_eq!(
            base64url_to_bytes("A").unwrap_err().to_string(),
            "Invalid base64-encoded string: number of data characters (1) cannot be 1 more than a multiple of 4"
        );
        assert_eq!(base64url_to_bytes("ä").unwrap_err(), Base64Error::NonAscii);
        assert_eq!(
            a2b_base64(b"QQ").unwrap_err(),
            Base64Error::IncorrectPadding
        );
        assert_eq!(jwt_base64url_decode("eyJ").unwrap(), b"{\"");
        assert_eq!(bytes_to_base64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn strict_rules() {
        let text = |s: &str| match b64decode_validate(s) {
            Ok(b) => b.iter().map(|x| format!("{x:02x}")).collect::<String>(),
            Err(e) => e.to_string(),
        };
        assert_eq!(text("QQ=="), "41");
        assert_eq!(text("QR=="), "41", "unused bits are not checked");
        assert_eq!(text("QUJD="), "414243");
        assert_eq!(text("QUJD=="), "414243");
        assert_eq!(text("="), "Leading padding not allowed");
        assert_eq!(text("QQ==\n"), "Excess data after padding");
        assert_eq!(text("QUJD\n"), "Only base64 data is allowed");
        assert_eq!(text("Q=Q="), "Discontinuous padding not allowed");
        assert_eq!(text("QUJDRA="), "Incorrect padding");
        assert_eq!(
            text("QUJDR"),
            "Invalid base64-encoded string: number of data characters (5) cannot be 1 more than a multiple of 4"
        );
        assert_eq!(text("Q==="), text("Q"));
        assert_eq!(
            text("é"),
            "string argument should contain only ASCII characters"
        );
    }
}
