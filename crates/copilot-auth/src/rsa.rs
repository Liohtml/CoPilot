//! RSA signature verification as `cryptography` (OpenSSL 3) performs it —
//! for passkeys (`RS*`/`PS*` credentials) and SSO ID tokens (`RS256`).
//!
//! Only the public operation is needed, so it is done directly on
//! `num-bigint-dig` rather than through a key type with its own limits:
//! - key checks are `RSAPublicNumbers.public_key()`'s, with its messages
//!   (`n must be >= 3.`, `e must be >= 3 and < n.`, `e must be odd.`);
//! - OpenSSL's verify-time limits apply as failed verifications: a modulus
//!   over 16384 bits, or an exponent over 64 bits on a modulus over 3072;
//! - PKCS#1 v1.5 requires a signature of exactly the modulus length and the
//!   exact `DigestInfo`; PSS (MGF1 with the message hash) recovers the salt
//!   length from the signature, which is what `PSS.MAX_LENGTH` means when
//!   verifying.

use num_bigint_dig::BigUint;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// The hash a signature is computed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-1 (`RS1`, legacy).
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlg {
    /// `hash(data)`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha1 => Sha1::digest(data).to_vec(),
            HashAlg::Sha256 => Sha256::digest(data).to_vec(),
            HashAlg::Sha384 => Sha384::digest(data).to_vec(),
            HashAlg::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    fn len(self) -> usize {
        match self {
            HashAlg::Sha1 => 20,
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    /// DER `DigestInfo` prefix (AlgorithmIdentifier with NULL parameters).
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            HashAlg::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ],
            HashAlg::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            HashAlg::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            HashAlg::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

/// Why `RSAPublicNumbers(e, n).public_key()` refused the numbers; the
/// `Display` strings are cryptography's `ValueError` texts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RsaKeyError {
    /// `n < 3`.
    #[error("n must be >= 3.")]
    ModulusTooSmall,
    /// `e < 3` or `e >= n`.
    #[error("e must be >= 3 and < n.")]
    ExponentOutOfRange,
    /// `e` even.
    #[error("e must be odd.")]
    ExponentEven,
}

/// An RSA public key.
#[derive(Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    n: BigUint,
    e: BigUint,
}

impl std::fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaPublicKey({} bits)", self.n.bits())
    }
}

/// OpenSSL's `OPENSSL_RSA_MAX_MODULUS_BITS`.
const MAX_MODULUS_BITS: usize = 16384;
/// `OPENSSL_RSA_SMALL_MODULUS_BITS` / `OPENSSL_RSA_MAX_PUBEXP_BITS`.
const SMALL_MODULUS_BITS: usize = 3072;
const MAX_PUBEXP_BITS: usize = 64;

impl RsaPublicKey {
    /// From big-endian magnitudes, with cryptography's checks.
    pub fn from_be_bytes(n: &[u8], e: &[u8]) -> Result<Self, RsaKeyError> {
        let n = BigUint::from_bytes_be(n);
        let e = BigUint::from_bytes_be(e);
        let three = BigUint::from(3u8);
        if n < three {
            return Err(RsaKeyError::ModulusTooSmall);
        }
        if e < three || e >= n {
            return Err(RsaKeyError::ExponentOutOfRange);
        }
        if e.to_bytes_be().last().is_none_or(|b| b & 1 == 0) {
            return Err(RsaKeyError::ExponentEven);
        }
        Ok(Self { n, e })
    }

    /// Modulus size in bytes (`RSA_size`).
    pub fn size(&self) -> usize {
        self.n.bits().div_ceil(8)
    }

    /// `s^e mod n` as `RSA_size` bytes, or `None` where OpenSSL refuses.
    fn public_op(&self, signature: &[u8]) -> Option<Vec<u8>> {
        let bits = self.n.bits();
        if bits > MAX_MODULUS_BITS || (bits > SMALL_MODULUS_BITS && self.e.bits() > MAX_PUBEXP_BITS)
        {
            return None;
        }
        let k = self.size();
        if signature.len() > k {
            return None;
        }
        let s = BigUint::from_bytes_be(signature);
        if s >= self.n {
            return None;
        }
        let m = s.modpow(&self.e, &self.n).to_bytes_be();
        let mut em = vec![0u8; k - m.len().min(k)];
        em.extend_from_slice(&m);
        Some(em)
    }

    /// RSASSA-PKCS1-v1_5.
    pub fn verify_pkcs1v15(&self, hash: HashAlg, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != self.size() {
            return false;
        }
        let Some(em) = self.public_op(signature) else {
            return false;
        };
        let mut t = hash.digest_info_prefix().to_vec();
        t.extend_from_slice(&hash.digest(message));
        let k = em.len();
        if k < t.len() + 11 {
            return false;
        }
        let ps_len = k - t.len() - 3;
        em[0] == 0x00
            && em[1] == 0x01
            && em[2..2 + ps_len].iter().all(|b| *b == 0xff)
            && em[2 + ps_len] == 0x00
            && em[3 + ps_len..] == t[..]
    }

    /// RSASSA-PSS with MGF1(`hash`) and the salt length taken from the
    /// signature (`RSA_PSS_SALTLEN_AUTO`).
    pub fn verify_pss(&self, hash: HashAlg, message: &[u8], signature: &[u8]) -> bool {
        let Some(em) = self.public_op(signature) else {
            return false;
        };
        let h_len = hash.len();
        let ms_bits = (self.n.bits() - 1) & 7;
        let mut em: &[u8] = &em;
        if em.first().is_none_or(|b| b & (0xffu8 << ms_bits) != 0) {
            return false;
        }
        if ms_bits == 0 {
            em = &em[1..];
        }
        let em_len = em.len();
        if em_len < h_len + 2 || em[em_len - 1] != 0xbc {
            return false;
        }
        let masked_len = em_len - h_len - 1;
        let h = &em[masked_len..em_len - 1];
        let mut db = mgf1(hash, h, masked_len);
        for (d, m) in db.iter_mut().zip(&em[..masked_len]) {
            *d ^= m;
        }
        if ms_bits != 0 {
            db[0] &= 0xff >> (8 - ms_bits);
        }
        let mut i = 0;
        while i < masked_len - 1 && db[i] == 0 {
            i += 1;
        }
        if db[i] != 0x01 {
            return false;
        }
        let salt = &db[i + 1..];
        let mut m_prime = vec![0u8; 8];
        m_prime.extend_from_slice(&hash.digest(message));
        m_prime.extend_from_slice(salt);
        hash.digest(&m_prime) == h
    }
}

fn mgf1(hash: HashAlg, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + hash.len());
    let mut counter: u32 = 0;
    while out.len() < len {
        let mut block = seed.to_vec();
        block.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&hash.digest(&block));
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_checks_in_cryptography_order() {
        assert_eq!(
            RsaPublicKey::from_be_bytes(&[1], &[3]).unwrap_err(),
            RsaKeyError::ModulusTooSmall
        );
        assert_eq!(
            RsaPublicKey::from_be_bytes(&[15], &[17]).unwrap_err(),
            RsaKeyError::ExponentOutOfRange
        );
        assert_eq!(
            RsaPublicKey::from_be_bytes(&[0xff, 0xff, 0xff], &[1, 0, 0]).unwrap_err(),
            RsaKeyError::ExponentEven
        );
        assert!(RsaPublicKey::from_be_bytes(&[0xff, 0xfe], &[3]).is_ok());
    }
}
