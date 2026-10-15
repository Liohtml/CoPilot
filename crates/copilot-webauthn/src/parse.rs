//! The pieces of a credential, parsed as py_webauthn parses them:
//! `parse_registration_credential_json` / `parse_authentication_credential_json`
//! (the dict FastAPI hands the route), `parse_client_data_json`,
//! `parse_authenticator_data`, `parse_attestation_object` and
//! `parse_attestation_statement`.

use serde_json::Value;

use copilot_auth::pybase64::{Base64Error, base64url_to_bytes};
use copilot_auth::pyvalue::{PyValue, loads_bytes};

use crate::Failure;
use crate::cbor::{self, Cbor};

/// `InvalidJSONStructure`, which CoPilot does not catch: a 500.
const JSON_STRUCTURE: Failure = Failure::Internal("InvalidJSONStructure");

fn str_field<'a>(obj: &'a serde_json::Map<String, Value>, key: &str) -> Result<&'a str, Failure> {
    obj.get(key).and_then(Value::as_str).ok_or(JSON_STRUCTURE)
}

fn check_type_and_attachment(obj: &serde_json::Map<String, Value>) -> Result<(), Failure> {
    if obj.get("type").and_then(Value::as_str) != Some("public-key") {
        return Err(JSON_STRUCTURE);
    }
    if let Some(Value::String(a)) = obj.get("authenticatorAttachment") {
        if a != "platform" && a != "cross-platform" {
            return Err(JSON_STRUCTURE);
        }
    }
    Ok(())
}

/// A registration credential (`RegistrationCredential`).
#[derive(Debug, Clone)]
pub struct RegistrationCredential {
    /// `id`.
    pub id: String,
    /// `rawId`, decoded.
    pub raw_id: Vec<u8>,
    /// `response.clientDataJSON`, decoded.
    pub client_data_json: Vec<u8>,
    /// `response.attestationObject`, decoded.
    pub attestation_object: Vec<u8>,
}

/// `parse_registration_credential_json(dict)`.
pub fn registration_credential(value: &Value) -> Result<RegistrationCredential, Failure> {
    let obj = value.as_object().ok_or(JSON_STRUCTURE)?;
    let id = str_field(obj, "id")?;
    let raw_id = str_field(obj, "rawId")?;
    let response = obj
        .get("response")
        .and_then(Value::as_object)
        .ok_or(JSON_STRUCTURE)?;
    let client_data_json = str_field(response, "clientDataJSON")?;
    let attestation_object = str_field(response, "attestationObject")?;
    check_type_and_attachment(obj)?;
    let parse = |v: &str| {
        base64url_to_bytes(v).map_err(|_| {
            Failure::Rejected(
                "Could not parse registration credential from JSON data. See __cause__ for more info"
                    .into(),
            )
        })
    };
    Ok(RegistrationCredential {
        id: id.to_string(),
        raw_id: parse(raw_id)?,
        client_data_json: parse(client_data_json)?,
        attestation_object: parse(attestation_object)?,
    })
}

/// An authentication credential (`AuthenticationCredential`).
#[derive(Debug, Clone)]
pub struct AuthenticationCredential {
    /// `id`.
    pub id: String,
    /// `rawId`, decoded.
    pub raw_id: Vec<u8>,
    /// `response.clientDataJSON`, decoded.
    pub client_data_json: Vec<u8>,
    /// `response.authenticatorData`, decoded.
    pub authenticator_data: Vec<u8>,
    /// `response.signature`, decoded.
    pub signature: Vec<u8>,
}

fn base64_failure(e: Base64Error) -> Failure {
    Failure::Rejected(e.to_string())
}

/// `parse_authentication_credential_json(dict)`.
pub fn authentication_credential(value: &Value) -> Result<AuthenticationCredential, Failure> {
    let obj = value.as_object().ok_or(JSON_STRUCTURE)?;
    let id = str_field(obj, "id")?;
    let raw_id = str_field(obj, "rawId")?;
    let response = obj
        .get("response")
        .and_then(Value::as_object)
        .ok_or(JSON_STRUCTURE)?;
    let client_data_json = str_field(response, "clientDataJSON")?;
    let authenticator_data = str_field(response, "authenticatorData")?;
    let signature = str_field(response, "signature")?;
    if obj.get("type").and_then(Value::as_str) != Some("public-key") {
        return Err(JSON_STRUCTURE);
    }
    match response.get("userHandle") {
        // Decoded outside py_webauthn's try: a `binascii.Error` reaches the
        // route as a `ValueError`.
        Some(Value::String(handle)) => {
            base64url_to_bytes(handle).map_err(base64_failure)?;
        }
        None | Some(Value::Null) => {}
        Some(_) => return Err(JSON_STRUCTURE),
    }
    check_type_and_attachment(obj)?;
    let parse = |v: &str| {
        base64url_to_bytes(v).map_err(|_| {
            Failure::Rejected(
                "Could not parse authentication credential from JSON data. See __cause__ for more info"
                    .into(),
            )
        })
    };
    Ok(AuthenticationCredential {
        id: id.to_string(),
        raw_id: parse(raw_id)?,
        client_data_json: parse(client_data_json)?,
        authenticator_data: parse(authenticator_data)?,
        signature: parse(signature)?,
    })
}

/// `CollectedClientData`.
#[derive(Debug, Clone)]
pub struct ClientData {
    /// `type`, any JSON value.
    pub type_: PyValue,
    /// `challenge`, decoded.
    pub challenge: Vec<u8>,
    /// `origin`, any JSON value.
    pub origin: PyValue,
    /// `tokenBinding.status` when `tokenBinding` is an object.
    pub token_binding_status: Option<PyValue>,
}

/// `parse_client_data_json(bytes)`; `None` where py_webauthn raises (every
/// such failure reads "clientDataJSON was malformed").
pub fn client_data(bytes: &[u8]) -> Option<ClientData> {
    let doc = loads_bytes(bytes).ok()?;
    let PyValue::Dict(_) = doc else {
        return None;
    };
    let type_ = doc.get("type")?.clone();
    let challenge = doc.get("challenge")?;
    let origin = doc.get("origin")?.clone();
    let challenge = base64url_to_bytes(&challenge.py_str()).ok()?;
    let token_binding_status = match doc.get("tokenBinding") {
        Some(tb @ PyValue::Dict(_)) => Some(tb.get("status")?.clone()),
        _ => None,
    };
    Some(ClientData {
        type_,
        challenge,
        origin,
        token_binding_status,
    })
}

/// The flags byte.
#[derive(Debug, Clone, Copy)]
pub struct Flags(pub u8);

impl Flags {
    /// User present.
    pub fn up(self) -> bool {
        self.0 & 0x01 != 0
    }
    /// User verified.
    pub fn uv(self) -> bool {
        self.0 & 0x04 != 0
    }
    /// Backup eligible.
    pub fn be(self) -> bool {
        self.0 & 0x08 != 0
    }
    /// Backup state.
    pub fn bs(self) -> bool {
        self.0 & 0x10 != 0
    }
    fn at(self) -> bool {
        self.0 & 0x40 != 0
    }
    fn ed(self) -> bool {
        self.0 & 0x80 != 0
    }
}

/// `AttestedCredentialData`.
#[derive(Debug, Clone)]
pub struct AttestedCredential {
    /// `aaguid` (possibly short on truncated data, as Python slices).
    pub aaguid: Vec<u8>,
    /// `credential_id`.
    pub credential_id: Vec<u8>,
    /// The re-encoded COSE key.
    pub public_key: Vec<u8>,
}

/// `AuthenticatorData`.
#[derive(Debug, Clone)]
pub struct AuthenticatorData {
    /// `rp_id_hash`.
    pub rp_id_hash: Vec<u8>,
    /// Flags.
    pub flags: Flags,
    /// `sign_count`.
    pub sign_count: u32,
    /// Attested credential data, when the AT flag is set.
    pub attested: Option<AttestedCredential>,
}

fn slice(data: &[u8], start: usize, end: usize) -> &[u8] {
    let len = data.len();
    &data[start.min(len)..end.min(len)]
}

const BAD_EDDSA_CBOR: [u8; 17] = [
    0xa3, 0x01, 0x63, 0x4f, 0x4b, 0x50, 0x03, 0x27, 0x20, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31,
    0x39,
];

/// `parse_authenticator_data(bytes)`; `None` where it raises.
pub fn authenticator_data(data: &[u8]) -> Option<AuthenticatorData> {
    if data.len() < 37 {
        return None;
    }
    let mut data = data.to_vec();
    let flags = Flags(data[32]);
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    let mut pointer = 37usize;
    let mut attested = None;
    if flags.at() {
        let aaguid = slice(&data, pointer, pointer + 16).to_vec();
        pointer += 16;
        let len_bytes = slice(&data, pointer, pointer + 2);
        let cred_len = len_bytes
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        pointer += 2;
        let credential_id = slice(&data, pointer, pointer + cred_len).to_vec();
        pointer += cred_len;
        // Some authenticators write a map of 3 for a 4-entry EdDSA key.
        if slice(&data, pointer, pointer + BAD_EDDSA_CBOR.len()) == BAD_EDDSA_CBOR {
            data[pointer] = 0xa4;
        }
        let key = cbor::decode(slice(&data, pointer, usize::MAX)).ok()?;
        let public_key = cbor::encode(&key).ok()?;
        pointer += public_key.len();
        attested = Some(AttestedCredential {
            aaguid,
            credential_id,
            public_key,
        });
    }
    if flags.ed() {
        let ext = cbor::decode(slice(&data, pointer, usize::MAX)).ok()?;
        pointer += cbor::encode(&ext).ok()?.len();
    }
    if data.len() > pointer {
        return None;
    }
    Some(AuthenticatorData {
        rp_id_hash: data[..32].to_vec(),
        flags,
        sign_count,
        attested,
    })
}

/// `AttestationStatement`: the fields py_webauthn reads, raw.
#[derive(Debug, Clone, Default)]
pub struct AttestationStatement {
    /// `sig`.
    pub sig: Option<Cbor>,
    /// `x5c`.
    pub x5c: Option<Cbor>,
    /// `alg`.
    pub alg: Option<Cbor>,
    /// Whether any field Python's dataclass holds is set to something other
    /// than `None` (the check a `none` attestation must pass).
    pub any_set: bool,
}

const STATEMENT_FIELDS: [&str; 7] = [
    "sig", "x5c", "response", "alg", "ver", "certInfo", "pubArea",
];

/// `parse_attestation_statement(val)`; `None` where Python raises.
fn attestation_statement(value: &Cbor) -> Option<AttestationStatement> {
    match value {
        Cbor::Map(_) => {
            let field = |name: &str| value.get_text(name).cloned();
            let any_set = STATEMENT_FIELDS
                .iter()
                .any(|f| field(f).is_some_and(|v| !matches!(v, Cbor::Null)));
            Some(AttestationStatement {
                sig: field("sig"),
                x5c: field("x5c"),
                alg: field("alg"),
                any_set,
            })
        }
        // `"sig" in val` works on these, and `val["sig"]` then raises.
        Cbor::Array(items) => STATEMENT_FIELDS
            .iter()
            .all(|f| !items.iter().any(|i| matches!(i, Cbor::Text(t) if t == f)))
            .then(AttestationStatement::default),
        Cbor::Text(t) => STATEMENT_FIELDS
            .iter()
            .all(|f| !t.contains(f))
            .then(AttestationStatement::default),
        _ => None,
    }
}

/// `AttestationObject`.
#[derive(Debug, Clone)]
pub struct AttestationObject {
    /// `fmt`, any CBOR value.
    pub fmt: Cbor,
    /// `authData`, parsed.
    pub auth_data: AuthenticatorData,
    /// `authData` as stored (packed signs over it).
    pub raw_auth_data: Cbor,
    /// `attStmt`.
    pub statement: AttestationStatement,
}

/// `parse_attestation_object(bytes)`; `None` where it raises (every such
/// failure reads "attestationObject was malformed").
pub fn attestation_object(bytes: &[u8]) -> Option<AttestationObject> {
    let doc = cbor::decode(bytes).ok()?;
    let Cbor::Map(_) = doc else {
        return None;
    };
    let fmt = doc.get_text("fmt")?.clone();
    let raw_auth_data = doc.get_text("authData")?.clone();
    let auth_data = authenticator_data(&raw_auth_data.py_bytes()?)?;
    let statement = match doc.get_text("attStmt") {
        Some(stmt) => attestation_statement(stmt)?,
        None => AttestationStatement::default(),
    };
    Some(AttestationObject {
        fmt,
        auth_data,
        raw_auth_data,
        statement,
    })
}
