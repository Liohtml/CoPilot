//! Credential public keys: COSE decoding (`decode_credential_public_key`),
//! conversion to a usable key (`decoded_public_key_to_cryptography`),
//! signature checks (`verify_signature`) and the key of an attestation
//! certificate.
//!
//! The COSE values are not type-checked by py_webauthn, so they are kept as
//! [`Cbor`] and compared with Python's `==` (`-7.0` is ES256, `True` is
//! key type 1). Python's failures map as CoPilot reports them: a `ValueError`
//! (an off-curve point, an even RSA exponent) is a [`Failure::Rejected`]
//! with cryptography's text, anything else a [`Failure::Internal`].

use ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256, Sha512};
use x509_cert::der::Decode;
use x509_cert::der::asn1::ObjectIdentifier;

use copilot_auth::rsa::{HashAlg, RsaPublicKey};

use crate::Failure;
use crate::cbor::{self, Cbor};

/// A decoded COSE key (`DecodedOKPPublicKey` / `DecodedEC2PublicKey` /
/// `DecodedRSAPublicKey`).
#[derive(Debug, Clone)]
pub enum DecodedKey {
    /// `kty` 1.
    Okp {
        /// `alg` (3).
        alg: Cbor,
        /// `crv` (-1).
        crv: Cbor,
        /// `x` (-2).
        x: Cbor,
    },
    /// `kty` 2, or a raw `0x04 ‖ x ‖ y` U2F key.
    Ec2 {
        /// `alg` (3).
        alg: Cbor,
        /// `crv` (-1).
        crv: Cbor,
        /// `x` (-2).
        x: Cbor,
        /// `y` (-3).
        y: Cbor,
    },
    /// `kty` 3.
    Rsa {
        /// `alg` (3).
        alg: Cbor,
        /// `n` (-1).
        n: Cbor,
        /// `e` (-2).
        e: Cbor,
    },
}

impl DecodedKey {
    /// The key's `alg`.
    pub fn alg(&self) -> &Cbor {
        match self {
            DecodedKey::Okp { alg, .. }
            | DecodedKey::Ec2 { alg, .. }
            | DecodedKey::Rsa { alg, .. } => alg,
        }
    }
}

fn get(key: &Cbor, index: i64) -> Result<Cbor, Failure> {
    key.get_index(index).map_err(Failure::Internal)
}

fn required(value: Cbor) -> Result<Cbor, Failure> {
    if value.truthy() {
        Ok(value)
    } else {
        Err(Failure::Internal("InvalidPublicKeyStructure"))
    }
}

/// `decode_credential_public_key(key)`.
pub fn decode_credential_public_key(key: &[u8]) -> Result<DecodedKey, Failure> {
    let first = *key.first().ok_or(Failure::Internal("IndexError"))?;
    if first == 0x04 {
        let slice = |a: usize, b: usize| key.get(a.min(key.len())..b.min(key.len())).unwrap_or(&[]);
        return Ok(DecodedKey::Ec2 {
            alg: Cbor::int(-7),
            crv: Cbor::int(1),
            x: Cbor::Bytes(slice(1, 33).to_vec()),
            y: Cbor::Bytes(slice(33, 65).to_vec()),
        });
    }
    let decoded = cbor::decode(key).map_err(|_| Failure::Internal("InvalidCBORData"))?;
    let kty = get(&decoded, 1)?;
    let alg = get(&decoded, 3)?;
    let kty = required(kty)?;
    let alg = required(alg)?;
    if kty.py_eq(&Cbor::int(1)) {
        let crv = get(&decoded, -1)?;
        let x = get(&decoded, -2)?;
        Ok(DecodedKey::Okp {
            alg,
            crv: required(crv)?,
            x: required(x)?,
        })
    } else if kty.py_eq(&Cbor::int(2)) {
        let crv = get(&decoded, -1)?;
        let x = get(&decoded, -2)?;
        let y = get(&decoded, -3)?;
        Ok(DecodedKey::Ec2 {
            alg,
            crv: required(crv)?,
            x: required(x)?,
            y: required(y)?,
        })
    } else if kty.py_eq(&Cbor::int(3)) {
        let n = get(&decoded, -1)?;
        let e = get(&decoded, -2)?;
        Ok(DecodedKey::Rsa {
            alg,
            n: required(n)?,
            e: required(e)?,
        })
    } else {
        Err(Failure::Internal("UnsupportedPublicKeyType"))
    }
}

/// An elliptic-curve verifying key.
#[derive(Clone)]
pub enum EcKey {
    /// P-256.
    P256(p256::ecdsa::VerifyingKey),
    /// P-384.
    P384(p384::ecdsa::VerifyingKey),
    /// P-521.
    P521(p521::ecdsa::VerifyingKey),
}

impl std::fmt::Debug for EcKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            EcKey::P256(_) => "EcKey::P256",
            EcKey::P384(_) => "EcKey::P384",
            EcKey::P521(_) => "EcKey::P521",
        })
    }
}

/// A key signatures can be checked with.
#[derive(Debug, Clone)]
pub enum PublicKey {
    /// ECDSA.
    Ec(EcKey),
    /// RSA.
    Rsa(RsaPublicKey),
    /// Ed25519. `None`: 32 bytes that are not a curve point — cryptography
    /// loads such a key, and every signature then fails.
    Ed25519(Option<ed25519_dalek::VerifyingKey>),
}

/// `int(codecs.encode(value, "hex"), 16)`, as big-endian bytes.
fn hex_int(value: &Cbor) -> Result<Vec<u8>, Failure> {
    match value {
        Cbor::Bytes(b) if b.is_empty() => Err(Failure::Rejected(
            "invalid literal for int() with base 16: b''".into(),
        )),
        Cbor::Bytes(b) => Ok(b.clone()),
        _ => Err(Failure::Internal("TypeError")),
    }
}

const OFF_CURVE: &str = "Invalid EC key. Point is not on the curve specified.";

fn sec1_point(x: &[u8], y: &[u8], size: usize) -> Option<Vec<u8>> {
    let trim = |v: &[u8]| -> Option<Vec<u8>> {
        let start = v.iter().take_while(|b| **b == 0).count();
        let v = &v[start..];
        if v.len() > size {
            return None;
        }
        let mut out = vec![0u8; size - v.len()];
        out.extend_from_slice(v);
        Some(out)
    };
    let mut point = vec![0x04];
    point.extend(trim(x)?);
    point.extend(trim(y)?);
    Some(point)
}

/// `EllipticCurvePublicNumbers(x, y, curve).public_key()`.
fn ec_key(curve: &Cbor, x: &[u8], y: &[u8]) -> Result<EcKey, Failure> {
    let rejected = || Failure::Rejected(OFF_CURVE.into());
    if curve.py_eq(&Cbor::int(1)) {
        let point = sec1_point(x, y, 32).ok_or_else(rejected)?;
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
            .map(EcKey::P256)
            .map_err(|_| rejected())
    } else if curve.py_eq(&Cbor::int(2)) {
        let point = sec1_point(x, y, 48).ok_or_else(rejected)?;
        p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
            .map(EcKey::P384)
            .map_err(|_| rejected())
    } else if curve.py_eq(&Cbor::int(3)) {
        let point = sec1_point(x, y, 66).ok_or_else(rejected)?;
        p521::ecdsa::VerifyingKey::from_sec1_bytes(&point)
            .map(EcKey::P521)
            .map_err(|_| rejected())
    } else {
        Err(Failure::Internal("UnsupportedEC2Curve"))
    }
}

fn ed25519_key(x: &Cbor) -> Result<PublicKey, Failure> {
    let Cbor::Bytes(raw) = x else {
        return Err(Failure::Internal("TypeError"));
    };
    let raw: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| Failure::Rejected("An Ed25519 public key is 32 bytes long".into()))?;
    Ok(PublicKey::Ed25519(
        ed25519_dalek::VerifyingKey::from_bytes(&raw).ok(),
    ))
}

/// `decoded_public_key_to_cryptography(key)`.
pub fn to_public_key(key: &DecodedKey) -> Result<PublicKey, Failure> {
    match key {
        DecodedKey::Ec2 { crv, x, y, .. } => {
            let x = hex_int(x)?;
            let y = hex_int(y)?;
            ec_key(crv, &x, &y).map(PublicKey::Ec)
        }
        DecodedKey::Rsa { n, e, .. } => {
            let e = hex_int(e)?;
            let n = hex_int(n)?;
            RsaPublicKey::from_be_bytes(&n, &e)
                .map(PublicKey::Rsa)
                .map_err(|err| Failure::Rejected(err.to_string()))
        }
        DecodedKey::Okp { alg, crv, x } => {
            if !alg.py_eq(&Cbor::int(-8)) || !crv.py_eq(&Cbor::int(6)) {
                return Err(Failure::Internal("UnsupportedPublicKey"));
            }
            ed25519_key(x)
        }
    }
}

fn alg_is(alg: &Cbor, ids: &[i64]) -> bool {
    ids.iter().any(|id| alg.py_eq(&Cbor::int(*id)))
}

/// Left-pad a digest shorter than the curve order to its size; ECDSA uses
/// the leftmost bits of a longer one (`bits2field` does that part).
fn prehash(digest: Vec<u8>, size: usize) -> Vec<u8> {
    if digest.len() >= size {
        return digest;
    }
    let mut out = vec![0u8; size - digest.len()];
    out.extend(digest);
    out
}

fn ec_verify(key: &EcKey, digest: Vec<u8>, signature: &[u8]) -> bool {
    match key {
        EcKey::P256(vk) => p256::ecdsa::Signature::from_der(signature)
            .is_ok_and(|s| vk.verify_prehash(&prehash(digest, 32), &s).is_ok()),
        EcKey::P384(vk) => p384::ecdsa::Signature::from_der(signature)
            .is_ok_and(|s| vk.verify_prehash(&prehash(digest, 48), &s).is_ok()),
        EcKey::P521(vk) => p521::ecdsa::Signature::from_der(signature)
            .is_ok_and(|s| vk.verify_prehash(&prehash(digest, 66), &s).is_ok()),
    }
}

/// `verify_signature(public_key, signature_alg, signature, data)`:
/// `Ok(false)` is cryptography's `InvalidSignature`.
pub fn verify_signature(
    key: &PublicKey,
    alg: &Cbor,
    signature: &[u8],
    data: &[u8],
) -> Result<bool, Failure> {
    match key {
        PublicKey::Ec(ec) => {
            let digest = if alg_is(alg, &[-7]) {
                Sha256::digest(data).to_vec()
            } else if alg_is(alg, &[-36]) {
                Sha512::digest(data).to_vec()
            } else {
                return Err(Failure::Internal("UnsupportedAlgorithm"));
            };
            Ok(ec_verify(ec, digest, signature))
        }
        PublicKey::Rsa(rsa) => {
            let pkcs = [
                (-65535, HashAlg::Sha1),
                (-257, HashAlg::Sha256),
                (-258, HashAlg::Sha384),
                (-259, HashAlg::Sha512),
            ];
            let pss = [
                (-37, HashAlg::Sha256),
                (-38, HashAlg::Sha384),
                (-39, HashAlg::Sha512),
            ];
            if let Some((_, hash)) = pkcs.iter().find(|(id, _)| alg_is(alg, &[*id])) {
                Ok(rsa.verify_pkcs1v15(*hash, data, signature))
            } else if let Some((_, hash)) = pss.iter().find(|(id, _)| alg_is(alg, &[*id])) {
                Ok(rsa.verify_pss(*hash, data, signature))
            } else {
                Err(Failure::Internal("UnsupportedAlgorithm"))
            }
        }
        PublicKey::Ed25519(vk) => {
            let Some(vk) = vk else {
                return Ok(false);
            };
            let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
                return Ok(false);
            };
            // OpenSSL's check: canonical `S`, the cofactorless equation;
            // small-order keys are not refused (that would be `verify_strict`).
            Ok(ed25519_dalek::Verifier::verify(vk, data, &signature).is_ok())
        }
    }
}

/// The public key of an attestation certificate (`x5c[0]`).
#[derive(Debug, Clone)]
pub enum CertKey {
    /// An EC key on P-256 / P-384 / P-521.
    Ec(EcKey),
    /// An EC key on any other curve (cryptography loads it; fido-u2f
    /// refuses it by name).
    OtherCurve,
    /// RSA.
    Rsa(RsaPublicKey),
    /// Ed25519.
    Ed25519(Option<ed25519_dalek::VerifyingKey>),
    /// Ed448, DSA, X25519, …: cryptography loads them, py_webauthn cannot
    /// verify with them.
    Unsupported,
}

const OID_EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// `x509.load_der_x509_certificate(der).public_key()`. A certificate that
/// does not parse is a `ValueError` (the text differs from cryptography's).
pub fn certificate_key(der: &[u8]) -> Result<CertKey, Failure> {
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| Failure::Rejected(format!("error parsing asn1 value: {e}")))?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let raw = spki.subject_public_key.raw_bytes();
    let oid = spki.algorithm.oid;
    if oid == OID_EC {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        let invalid = || Failure::Rejected(OFF_CURVE.into());
        return match curve {
            Some(c) if c == OID_P256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(raw)
                .map(|k| CertKey::Ec(EcKey::P256(k)))
                .map_err(|_| invalid()),
            Some(c) if c == OID_P384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(raw)
                .map(|k| CertKey::Ec(EcKey::P384(k)))
                .map_err(|_| invalid()),
            Some(c) if c == OID_P521 => p521::ecdsa::VerifyingKey::from_sec1_bytes(raw)
                .map(|k| CertKey::Ec(EcKey::P521(k)))
                .map_err(|_| invalid()),
            _ => Ok(CertKey::OtherCurve),
        };
    }
    if oid == OID_RSA {
        let key = pkcs1::RsaPublicKey::from_der(raw)
            .map_err(|e| Failure::Rejected(format!("error parsing asn1 value: {e}")))?;
        return RsaPublicKey::from_be_bytes(key.modulus.as_bytes(), key.public_exponent.as_bytes())
            .map(CertKey::Rsa)
            .map_err(|e| Failure::Rejected(e.to_string()));
    }
    if oid == OID_ED25519 {
        let raw: [u8; 32] = raw
            .try_into()
            .map_err(|_| Failure::Rejected("An Ed25519 public key is 32 bytes long".into()))?;
        return Ok(CertKey::Ed25519(
            ed25519_dalek::VerifyingKey::from_bytes(&raw).ok(),
        ));
    }
    Ok(CertKey::Unsupported)
}

/// `verify_signature` with a certificate's key.
pub fn verify_with_certificate(
    key: &CertKey,
    alg: &Cbor,
    signature: &[u8],
    data: &[u8],
) -> Result<bool, Failure> {
    let key = match key {
        CertKey::Ec(ec) => PublicKey::Ec(ec.clone()),
        CertKey::Rsa(rsa) => PublicKey::Rsa(rsa.clone()),
        CertKey::Ed25519(vk) => PublicKey::Ed25519(*vk),
        CertKey::OtherCurve | CertKey::Unsupported => {
            return Err(Failure::Internal("UnsupportedPublicKey"));
        }
    };
    verify_signature(&key, alg, signature, data)
}
