//! TOTP 2FA — pyotp 2.9's `TOTP` with CoPilot's settings (SHA-1, 6 digits,
//! 30 s, `verify(code, valid_window=1)`), the enrolment secret and URI, and
//! the backup codes of `app/auth/services/totp.py`.
//!
//! - A code is compared the way `pyotp.utils.strings_equal` does: both sides
//!   NFKC-normalised (full-width digits match), then constant-time.
//! - The replay guard is the caller's: a code is accepted only when the
//!   current counter (`now // 30`) is past `user_totp.last_used_at`.
//! - Backup codes are 8 × 10 characters of `A-Z0-9`, stored as bcrypt hashes
//!   and checked as `code.upper().strip()`.
//!
//! `auth_vectors.json` pins codes, verification and URIs against pyotp.

use hmac::{Hmac, Mac};
use rand::Rng;
use rand::rngs::OsRng;
use sha1::Sha1;
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// `TOTP.interval`.
pub const INTERVAL_SECS: u64 = 30;
/// Number of backup codes issued at once.
pub const BACKUP_CODE_COUNT: usize = 8;
/// Length of a backup code.
pub const BACKUP_CODE_LENGTH: usize = 10;
/// The otpauth issuer.
pub const ISSUER: &str = "CoPilot";

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BACKUP_ALPHABET: &[u8; 36] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// `pyotp.random_base32()`: 32 characters from the system RNG.
pub fn random_base32() -> String {
    (0..32)
        .map(|_| char::from(BASE32[OsRng.gen_range(0..BASE32.len())]))
        .collect()
}

/// `base64.b32decode(secret, casefold=True)` after pyotp's padding.
fn b32decode(secret: &str) -> Option<Vec<u8>> {
    let mut bits: u64 = 0;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    let trimmed = secret.trim_end_matches('=');
    for c in trimmed.bytes() {
        let v = BASE32.iter().position(|&b| b == c.to_ascii_uppercase())? as u64;
        bits = (bits << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
            bits &= (1 << nbits) - 1;
        }
    }
    Some(out)
}

/// A TOTP generator for one secret.
#[derive(Clone)]
pub struct Totp {
    key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp").finish_non_exhaustive()
    }
}

/// `int(time.time()) // 30`.
pub fn counter_at(unix_secs: u64) -> u64 {
    unix_secs / INTERVAL_SECS
}

fn nfkc(s: &str) -> String {
    s.nfkc().collect()
}

impl Totp {
    /// `pyotp.TOTP(secret)`; `None` when the secret is not base32.
    pub fn new(secret: &str) -> Option<Self> {
        Some(Self {
            key: Zeroizing::new(b32decode(secret)?),
        })
    }

    /// `generate_otp(counter)`: the 6-digit code for a time step.
    pub fn code(&self, counter: u64) -> String {
        #[allow(clippy::expect_used)]
        let mut mac = Hmac::<Sha1>::new_from_slice(&self.key).expect("HMAC takes any key length");
        mac.update(&counter.to_be_bytes());
        let hash = mac.finalize().into_bytes();
        let offset = usize::from(hash[hash.len() - 1] & 0x0f);
        let code = (u32::from(hash[offset]) & 0x7f) << 24
            | u32::from(hash[offset + 1]) << 16
            | u32::from(hash[offset + 2]) << 8
            | u32::from(hash[offset + 3]);
        format!("{:06}", code % 1_000_000)
    }

    /// `verify(code, valid_window=1)` at `unix_secs`.
    pub fn verify(&self, code: &str, unix_secs: u64) -> bool {
        let given = nfkc(code);
        let counter = counter_at(unix_secs);
        let mut ok = false;
        for c in [
            counter.checked_sub(1),
            Some(counter),
            counter.checked_add(1),
        ]
        .into_iter()
        .flatten()
        {
            let expected = self.code(c);
            ok |= bool::from(given.as_bytes().ct_eq(expected.as_bytes()));
        }
        ok
    }
}

/// `urllib.parse.quote(s)` (safe `/`).
fn quote(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"_.-~/".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `TOTP(secret).provisioning_uri(name=username, issuer_name="CoPilot")`.
pub fn provisioning_uri(secret: &str, username: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={secret}&issuer={ISSUER}",
        quote(ISSUER),
        quote(username)
    )
}

/// Fresh backup codes (plaintext; the caller hashes them).
pub fn generate_backup_codes() -> Vec<String> {
    (0..BACKUP_CODE_COUNT)
        .map(|_| {
            (0..BACKUP_CODE_LENGTH)
                .map(|_| char::from(BACKUP_ALPHABET[OsRng.gen_range(0..BACKUP_ALPHABET.len())]))
                .collect()
        })
        .collect()
}

/// `backup_code.upper().strip()`.
pub fn normalize_backup_code(code: &str) -> String {
    let upper = code.to_uppercase();
    upper
        .trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("auth_vectors.json")).unwrap()
    }

    #[test]
    fn codes_match_pyotp() {
        let v = vectors();
        for c in v["totp"]["codes"].as_array().unwrap() {
            let totp = Totp::new(c["secret"].as_str().unwrap()).unwrap();
            assert_eq!(
                totp.code(c["counter"].as_u64().unwrap()),
                c["code"].as_str().unwrap(),
                "{c}"
            );
        }
    }

    #[test]
    fn verify_matches_pyotp() {
        let v = vectors();
        let totp = Totp::new(v["totp"]["verify_secret"].as_str().unwrap()).unwrap();
        let now = v["totp"]["verify_now"].as_u64().unwrap();
        for c in v["totp"]["verify"].as_array().unwrap() {
            let code = c["code"].as_str().unwrap();
            assert_eq!(
                totp.verify(code, now),
                c["valid"].as_bool().unwrap(),
                "{code:?}"
            );
        }
    }

    #[test]
    fn uris_match_pyotp() {
        let v = vectors();
        let secret = v["totp"]["verify_secret"].as_str().unwrap();
        for u in v["totp"]["uris"].as_array().unwrap() {
            assert_eq!(
                provisioning_uri(secret, u["name"].as_str().unwrap()),
                u["uri"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn backup_codes() {
        for c in vectors()["backup_codes"].as_array().unwrap() {
            assert_eq!(
                normalize_backup_code(c["input"].as_str().unwrap()),
                c["normalized"].as_str().unwrap()
            );
        }
        let codes = generate_backup_codes();
        assert_eq!(codes.len(), 8);
        assert!(codes.iter().all(|c| {
            c.len() == 10
                && c.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        }));
        let secret = random_base32();
        assert_eq!(secret.len(), 32);
        assert!(Totp::new(&secret).is_some());
        assert!(Totp::new("not base32!").is_none());
    }
}
