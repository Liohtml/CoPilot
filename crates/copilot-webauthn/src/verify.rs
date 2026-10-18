//! `verify_registration_response` and `verify_authentication_response`,
//! with the arguments CoPilot passes (one expected origin, user presence
//! required, user verification not required, the default algorithms, no
//! attestation root certificates).
//!
//! Attestation formats: `none`, `packed` (self attestation and `x5c`) and
//! `fido-u2f` — what browsers send when the options ask for attestation
//! `"none"`, as CoPilot's do. The vendor formats (`tpm`, `android-key`,
//! `android-safetynet`, `apple`) only arrive when an RP asks for direct
//! attestation; they are refused here rather than verified (py_webauthn
//! checks them against bundled vendor roots). Like py_webauthn without root
//! certificates, an `x5c` chain is not validated: only the leaf signs.

use sha2::{Digest, Sha256};

use copilot_auth::pybase64::bytes_to_base64url;
use copilot_auth::pyvalue::PyValue;

use crate::Failure;
use crate::cbor::Cbor;
use crate::keys::{
    CertKey, DecodedKey, EcKey, certificate_key, decode_credential_public_key, to_public_key,
    verify_signature, verify_with_certificate,
};
use crate::parse::{self, AttestationStatement, AuthenticatorData};

/// `default_supported_pub_key_algs`, in order.
pub const SUPPORTED_ALGS: [i64; 9] = [-7, -8, -36, -37, -38, -39, -257, -258, -259];

fn reject(message: impl Into<String>) -> Failure {
    Failure::Rejected(message.into())
}

/// `repr(default_supported_pub_key_algs)`.
fn supported_algs_repr() -> String {
    let names = [
        ("ECDSA_SHA_256", -7),
        ("EDDSA", -8),
        ("ECDSA_SHA_512", -36),
        ("RSASSA_PSS_SHA_256", -37),
        ("RSASSA_PSS_SHA_384", -38),
        ("RSASSA_PSS_SHA_512", -39),
        ("RSASSA_PKCS1_v1_5_SHA_256", -257),
        ("RSASSA_PKCS1_v1_5_SHA_384", -258),
        ("RSASSA_PKCS1_v1_5_SHA_512", -259),
    ];
    let items: Vec<String> = names
        .iter()
        .map(|(name, id)| format!("<COSEAlgorithmIdentifier.{name}: {id}>"))
        .collect();
    format!("[{}]", items.join(", "))
}

/// The client-data checks both ceremonies share.
fn check_client_data(
    client_data_json: &[u8],
    expected_type: &str,
    enum_name: &str,
    expected_challenge: &[u8],
    expected_origin: &str,
) -> Result<(), Failure> {
    let data = parse::client_data(client_data_json)
        .ok_or_else(|| reject("clientDataJSON was malformed. See __cause__ for more info"))?;
    if data.type_.as_str() != Some(expected_type) {
        return Err(reject(format!(
            "Unexpected client data type \"{}\", expected \"ClientDataType.{enum_name}\"",
            data.type_.py_str()
        )));
    }
    if data.challenge != expected_challenge {
        return Err(reject("Client data challenge was not expected challenge"));
    }
    if data.origin.as_str() != Some(expected_origin) {
        return Err(reject(format!(
            "Unexpected client data origin \"{}\", expected \"{expected_origin}\"",
            data.origin.py_str()
        )));
    }
    if let Some(status) = data.token_binding_status {
        if !matches!(&status, PyValue::Str(s) if s == "supported" || s == "present") {
            return Err(reject(format!(
                "Unexpected token_binding status of \"{}\", expected one of \"supported,present\"",
                status.py_str()
            )));
        }
    }
    Ok(())
}

fn backup_flags(auth_data: &AuthenticatorData) -> Result<(), Failure> {
    if !auth_data.flags.be() && auth_data.flags.bs() {
        return Err(Failure::Internal("InvalidBackupFlags"));
    }
    Ok(())
}

/// A verified registration (`VerifiedRegistration`, the fields CoPilot stores).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// `credential_id`.
    pub credential_id: Vec<u8>,
    /// `credential_public_key`: the re-encoded COSE key.
    pub public_key: Vec<u8>,
    /// `sign_count`.
    pub sign_count: u32,
}

/// `verify_registration_response(credential=…, expected_challenge=…,
/// expected_rp_id=…, expected_origin=…, require_user_verification=False)`.
pub fn verify_registration(
    credential: &serde_json::Value,
    expected_challenge: &[u8],
    expected_rp_id: &str,
    expected_origin: &str,
) -> Result<Registration, Failure> {
    let cred = parse::registration_credential(credential)?;
    if bytes_to_base64url(&cred.raw_id) != cred.id {
        return Err(reject("id and raw_id were not equivalent"));
    }
    check_client_data(
        &cred.client_data_json,
        "webauthn.create",
        "WEBAUTHN_CREATE",
        expected_challenge,
        expected_origin,
    )?;
    let att = parse::attestation_object(&cred.attestation_object)
        .ok_or_else(|| reject("attestationObject was malformed. See __cause__ for more info"))?;
    let auth_data = &att.auth_data;
    if auth_data.rp_id_hash != Sha256::digest(expected_rp_id.as_bytes()).as_slice() {
        return Err(reject("Unexpected RP ID hash"));
    }
    if !auth_data.flags.up() {
        return Err(reject(
            "User presence was required, but was not present during attestation",
        ));
    }
    let attested = auth_data
        .attested
        .as_ref()
        .ok_or_else(|| reject("Authenticator did not provide attested credential data"))?;
    if attested.credential_id.is_empty() {
        return Err(reject("Authenticator did not provide a credential ID"));
    }
    if attested.public_key.is_empty() {
        return Err(reject(
            "Authenticator did not provide a credential public key",
        ));
    }
    if attested.aaguid.is_empty() {
        return Err(reject("Authenticator did not provide an AAGUID"));
    }
    let decoded = decode_credential_public_key(&attested.public_key)?;
    if !SUPPORTED_ALGS
        .iter()
        .any(|id| decoded.alg().py_eq(&Cbor::int(*id)))
    {
        return Err(reject(format!(
            "Unsupported credential public key alg \"{}\", expected one of: {}",
            decoded.alg().py_str(),
            supported_algs_repr()
        )));
    }
    let fmt = |name: &str| att.fmt.py_eq(&Cbor::Text(name.into()));
    let client_data_hash = Sha256::digest(&cred.client_data_json);
    if fmt("none") {
        if att.statement.any_set {
            return Err(reject(
                "None attestation had unexpected attestation statement",
            ));
        }
    } else if fmt("packed") {
        verify_packed(
            &att.statement,
            &att.raw_auth_data,
            &client_data_hash,
            &decoded,
        )?;
    } else if fmt("fido-u2f") {
        verify_fido_u2f(
            &att.statement,
            &client_data_hash,
            &auth_data.rp_id_hash,
            &attested.credential_id,
            &attested.public_key,
            &attested.aaguid,
        )?;
    } else {
        return Err(reject(format!(
            "Unsupported attestation type \"{}\"",
            att.fmt.py_str()
        )));
    }
    backup_flags(auth_data)?;
    Ok(Registration {
        credential_id: attested.credential_id.clone(),
        public_key: attested.public_key.clone(),
        sign_count: auth_data.sign_count,
    })
}

fn truthy(value: &Option<Cbor>) -> bool {
    value.as_ref().is_some_and(Cbor::truthy)
}

fn sig_bytes(sig: &Option<Cbor>) -> Result<Vec<u8>, Failure> {
    match sig {
        Some(Cbor::Bytes(b)) => Ok(b.clone()),
        _ => Err(Failure::Internal("TypeError")),
    }
}

/// `x5c[0]` as a DER certificate.
fn first_certificate(x5c: &Cbor) -> Result<Vec<u8>, Failure> {
    match x5c.get_index(0).map_err(Failure::Internal)? {
        Cbor::Bytes(der) => Ok(der),
        _ => Err(Failure::Internal("TypeError")),
    }
}

fn verify_packed(
    stmt: &AttestationStatement,
    raw_auth_data: &Cbor,
    client_data_hash: &[u8],
    decoded: &DecodedKey,
) -> Result<(), Failure> {
    if !truthy(&stmt.sig) {
        return Err(reject(
            "Attestation statement was missing signature (Packed)",
        ));
    }
    if !truthy(&stmt.alg) {
        return Err(reject(
            "Attestation statement was missing algorithm (Packed)",
        ));
    }
    let alg = stmt.alg.clone().unwrap_or(Cbor::Null);
    let Cbor::Bytes(auth_data) = raw_auth_data else {
        return Err(Failure::Internal("TypeError"));
    };
    let mut data = auth_data.clone();
    data.extend_from_slice(client_data_hash);
    if let Some(x5c) = stmt.x5c.as_ref().filter(|x| x.truthy()) {
        let key = certificate_key(&first_certificate(x5c)?)?;
        let sig = sig_bytes(&stmt.sig)?;
        if !verify_with_certificate(&key, &alg, &sig, &data)? {
            return Err(reject(
                "Could not verify attestation statement signature (Packed)",
            ));
        }
        return Ok(());
    }
    if !decoded.alg().py_eq(&alg) {
        return Err(reject(format!(
            "Credential public key alg {} did not equal attestation statement alg {}",
            decoded.alg().py_str(),
            alg.py_str()
        )));
    }
    let key = to_public_key(decoded)?;
    let sig = sig_bytes(&stmt.sig)?;
    if !verify_signature(&key, &alg, &sig, &data)? {
        return Err(reject(
            "Could not verify attestation statement signature (Packed|Self)",
        ));
    }
    Ok(())
}

fn aaguid_string(aaguid: &[u8]) -> String {
    let hex: String = aaguid.iter().map(|b| format!("{b:02x}")).collect();
    let part = |a: usize, b: usize| hex.get(a.min(hex.len())..b.min(hex.len())).unwrap_or("");
    format!(
        "{}-{}-{}-{}-{}",
        part(0, 8),
        part(8, 12),
        part(12, 16),
        part(16, 20),
        part(20, 32)
    )
}

fn verify_fido_u2f(
    stmt: &AttestationStatement,
    client_data_hash: &[u8],
    rp_id_hash: &[u8],
    credential_id: &[u8],
    public_key: &[u8],
    aaguid: &[u8],
) -> Result<(), Failure> {
    if !truthy(&stmt.sig) {
        return Err(reject(
            "Attestation statement was missing signature (FIDO-U2F)",
        ));
    }
    let x5c = stmt
        .x5c
        .as_ref()
        .filter(|x| x.truthy())
        .ok_or_else(|| reject("Attestation statement was missing certificate (FIDO-U2F)"))?;
    if x5c.py_len().ok_or(Failure::Internal("TypeError"))? > 1 {
        return Err(reject(
            "Attestation statement contained too many certificates (FIDO-U2F)",
        ));
    }
    let actual = aaguid_string(aaguid);
    let expected = "00000000-0000-0000-0000-000000000000";
    if actual != expected {
        return Err(reject(format!(
            "AAGUID {actual} was not expected {expected} (FIDO-U2F)"
        )));
    }
    let leaf = certificate_key(&first_certificate(x5c)?)?;
    let ec = match leaf {
        CertKey::Ec(EcKey::P256(key)) => key,
        CertKey::Ec(_) | CertKey::OtherCurve => {
            return Err(reject("Leaf cert did not use P-256 curve (FIDO-U2F)"));
        }
        _ => return Err(reject("Leaf cert was not an EC2 certificate (FIDO-U2F)")),
    };
    let DecodedKey::Ec2 { x, y, .. } = decode_credential_public_key(public_key)? else {
        return Err(reject("Credential public key was not EC2 (FIDO-U2F)"));
    };
    let (Cbor::Bytes(x), Cbor::Bytes(y)) = (x, y) else {
        return Err(Failure::Internal("TypeError"));
    };
    let mut data = vec![0x00];
    data.extend_from_slice(rp_id_hash);
    data.extend_from_slice(client_data_hash);
    data.extend_from_slice(credential_id);
    data.push(0x04);
    data.extend_from_slice(&x);
    data.extend_from_slice(&y);
    let sig = sig_bytes(&stmt.sig)?;
    let key = crate::keys::PublicKey::Ec(EcKey::P256(ec));
    if !verify_signature(&key, &Cbor::int(-7), &sig, &data)? {
        return Err(reject(
            "Could not verify attestation statement signature (FIDO-U2F)",
        ));
    }
    Ok(())
}

/// `verify_authentication_response(credential=…, expected_challenge=…,
/// expected_rp_id=…, expected_origin=…, credential_public_key=…,
/// credential_current_sign_count=…, require_user_verification=False)`;
/// returns `new_sign_count`.
pub fn verify_authentication(
    credential: &serde_json::Value,
    expected_challenge: &[u8],
    expected_rp_id: &str,
    expected_origin: &str,
    public_key: &[u8],
    current_sign_count: u32,
) -> Result<u32, Failure> {
    let cred = parse::authentication_credential(credential)?;
    if bytes_to_base64url(&cred.raw_id) != cred.id {
        return Err(reject("id and raw_id were not equivalent"));
    }
    check_client_data(
        &cred.client_data_json,
        "webauthn.get",
        "WEBAUTHN_GET",
        expected_challenge,
        expected_origin,
    )?;
    let auth_data = parse::authenticator_data(&cred.authenticator_data)
        .ok_or_else(|| reject("authenticatorData was malformed. See __cause__ for more info"))?;
    if auth_data.rp_id_hash != Sha256::digest(expected_rp_id.as_bytes()).as_slice() {
        return Err(reject("Unexpected RP ID hash"));
    }
    if !auth_data.flags.up() {
        return Err(reject("User was not present during authentication"));
    }
    if (auth_data.sign_count > 0 || current_sign_count > 0)
        && auth_data.sign_count <= current_sign_count
    {
        return Err(reject(format!(
            "Response sign count of {} was not greater than current count of {current_sign_count}",
            auth_data.sign_count
        )));
    }
    let mut data = cred.authenticator_data.clone();
    data.extend_from_slice(&Sha256::digest(&cred.client_data_json));
    let decoded = decode_credential_public_key(public_key)?;
    let key = to_public_key(&decoded)?;
    if !verify_signature(&key, decoded.alg(), &cred.signature, &data)? {
        return Err(reject("Could not verify authentication signature"));
    }
    backup_flags(&auth_data)?;
    Ok(auth_data.sign_count)
}
