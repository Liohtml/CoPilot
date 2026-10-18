//! Fernet — `cryptography.fernet.Fernet`, which encrypts the TOTP secrets
//! stored in `user_totp.secret_enc` (`app/auth/services/totp.py`).
//!
//! Token: `0x80 | timestamp (u64 BE) | IV (16) | AES-128-CBC/PKCS7 | HMAC-SHA256`,
//! url-safe base64 with padding. The key is 32 url-safe-base64 bytes: the
//! first half signs, the second encrypts. CoPilot never sets a TTL, so the
//! timestamp is written but not checked.
//!
//! The key is `TOTP_ENCRYPTION_KEY` when set (Python refuses to start when it
//! is malformed, and so does the Rust binary), else derived from
//! `JWT_SECRET`: `urlsafe_b64encode(sha256(JWT_SECRET))`. `auth_vectors.json`
//! holds tokens made by `cryptography` that must decrypt — and that the Rust
//! encryption must reproduce byte for byte.

use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes128;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use copilot_core::config::Secret;

type HmacSha256 = Hmac<Sha256>;

/// The message Python raises for a malformed key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Fernet key must be 32 url-safe base64-encoded bytes.")]
pub struct FernetKeyError;

/// A Fernet key.
#[derive(Clone)]
pub struct Fernet {
    signing: Zeroizing<[u8; 16]>,
    encryption: Zeroizing<[u8; 16]>,
}

impl std::fmt::Debug for Fernet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fernet").finish_non_exhaustive()
    }
}

/// `base64.urlsafe_b64decode`: characters outside the alphabet are
/// discarded first (`binascii` in non-strict mode); the padding must be right.
fn urlsafe_b64decode(s: &str) -> Option<Vec<u8>> {
    let kept: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '=' | '+' | '/'))
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    URL_SAFE.decode(kept).ok()
}

impl Fernet {
    fn from_bytes(key: &[u8]) -> Result<Self, FernetKeyError> {
        if key.len() != 32 {
            return Err(FernetKeyError);
        }
        let mut signing = Zeroizing::new([0u8; 16]);
        let mut encryption = Zeroizing::new([0u8; 16]);
        signing.copy_from_slice(&key[..16]);
        encryption.copy_from_slice(&key[16..]);
        Ok(Self {
            signing,
            encryption,
        })
    }

    /// `Fernet(key)` for a url-safe base64 key (`TOTP_ENCRYPTION_KEY`,
    /// already stripped of surrounding whitespace).
    pub fn new(key: &str) -> Result<Self, FernetKeyError> {
        let raw = Zeroizing::new(urlsafe_b64decode(key).ok_or(FernetKeyError)?);
        Self::from_bytes(&raw)
    }

    /// The key derived from `JWT_SECRET` when no `TOTP_ENCRYPTION_KEY` is set.
    pub fn derived_from_jwt_secret(secret: &Secret) -> Self {
        let digest: Zeroizing<[u8; 32]> =
            Zeroizing::new(Sha256::digest(secret.expose().as_bytes()).into());
        let mut signing = Zeroizing::new([0u8; 16]);
        let mut encryption = Zeroizing::new([0u8; 16]);
        signing.copy_from_slice(&digest[..16]);
        encryption.copy_from_slice(&digest[16..]);
        Self {
            signing,
            encryption,
        }
    }

    /// `TOTP_ENCRYPTION_KEY` when set (trimmed), else the `JWT_SECRET`
    /// derivation — `totp.py`'s choice.
    pub fn for_totp(
        encryption_key: Option<&Secret>,
        jwt_secret: &Secret,
    ) -> Result<Self, FernetKeyError> {
        match encryption_key.filter(|k| k.is_set()) {
            Some(key) => Self::new(key.expose().trim()),
            None => Ok(Self::derived_from_jwt_secret(jwt_secret)),
        }
    }

    fn mac(&self) -> HmacSha256 {
        #[allow(clippy::expect_used)]
        HmacSha256::new_from_slice(&self.signing[..]).expect("HMAC takes any key length")
    }

    /// `Fernet.encrypt`: now, with a random IV.
    pub fn encrypt(&self, data: &[u8]) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut iv = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut iv);
        self.encrypt_at(data, now, iv)
    }

    /// `Fernet._encrypt_from_parts`.
    pub fn encrypt_at(&self, data: &[u8], time: u64, iv: [u8; 16]) -> String {
        let ciphertext = cbc::Encryptor::<Aes128>::new((&*self.encryption).into(), (&iv).into())
            .encrypt_padded_vec_mut::<Pkcs7>(data);
        let mut token = Vec::with_capacity(1 + 8 + 16 + ciphertext.len() + 32);
        token.push(0x80);
        token.extend_from_slice(&time.to_be_bytes());
        token.extend_from_slice(&iv);
        token.extend_from_slice(&ciphertext);
        let mut mac = self.mac();
        mac.update(&token);
        token.extend_from_slice(&mac.finalize().into_bytes());
        URL_SAFE.encode(token)
    }

    /// `Fernet.decrypt` (no TTL): `None` is `InvalidToken`.
    pub fn decrypt(&self, token: &str) -> Option<Vec<u8>> {
        let data = urlsafe_b64decode(token)?;
        if data.first() != Some(&0x80) || data.len() < 1 + 8 + 16 + 32 {
            return None;
        }
        let (signed, signature) = data.split_at(data.len() - 32);
        let mut mac = self.mac();
        mac.update(signed);
        mac.verify_slice(signature).ok()?;
        let iv: [u8; 16] = signed[9..25].try_into().ok()?;
        cbc::Decryptor::<Aes128>::new((&*self.encryption).into(), (&iv).into())
            .decrypt_padded_vec_mut::<Pkcs7>(&signed[25..])
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str::<Value>(include_str!("auth_vectors.json")).unwrap()["fernet"].clone()
    }

    fn iv(hex_iv: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, chunk) in hex_iv.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        out
    }

    #[test]
    fn matches_cryptography() {
        let v = vectors();
        let f = Fernet::new(v["key"].as_str().unwrap()).unwrap();
        for t in v["tokens"].as_array().unwrap() {
            let token = t["token"].as_str().unwrap();
            let plaintext = t["plaintext"].as_str().unwrap();
            assert_eq!(f.decrypt(token).unwrap(), plaintext.as_bytes());
            let ours = f.encrypt_at(
                plaintext.as_bytes(),
                t["time"].as_u64().unwrap(),
                iv(t["iv"].as_str().unwrap()),
            );
            assert_eq!(ours, token);
        }
        for bad in v["invalid"].as_array().unwrap() {
            assert_eq!(f.decrypt(bad.as_str().unwrap()), None, "{bad}");
        }
        let round = f.encrypt(b"JBSWY3DPEHPK3PXP");
        assert_eq!(f.decrypt(&round).unwrap(), b"JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn derived_key_matches_totp_py() {
        let v = vectors();
        let secret = Secret::new(v["jwt_secret"].as_str().unwrap());
        let derived = Fernet::for_totp(None, &secret).unwrap();
        assert_eq!(
            derived
                .decrypt(v["derived_token"].as_str().unwrap())
                .unwrap(),
            b"SECRET"
        );
        let explicit = Secret::new(format!(" {}\n", v["derived_key"].as_str().unwrap()));
        let same = Fernet::for_totp(Some(&explicit), &Secret::new("other")).unwrap();
        assert_eq!(
            same.decrypt(v["derived_token"].as_str().unwrap()).unwrap(),
            b"SECRET"
        );
        assert_eq!(Fernet::new("too-short").unwrap_err(), FernetKeyError);
        // 43 characters: the padding is missing, Python's "Incorrect padding".
        let key = v["key"].as_str().unwrap();
        assert!(Fernet::new(&key[..key.len() - 1]).is_err());
    }
}
