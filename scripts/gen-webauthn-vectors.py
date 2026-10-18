"""Generate WebAuthn vectors for copilot-webauthn's port of py_webauthn, as CoPilot uses it.

    backend/.venv/bin/python -I scripts/gen-webauthn-vectors.py \
        > crates/copilot-webauthn/src/webauthn_vectors.json

Run from the repository root: the origin cases import CoPilot's own
`app/auth/services/passkey.py`. Every key, challenge and signature is fixed (ECDSA is
RFC 6979, PSS uses a fixed salt), so the file only changes when a library does.

- `base64url`: `base64url_to_bytes` (CPython's lenient `a2b_base64` after `"==="`).
- `cbor`: what `cbor2.loads` + `cbor2.dumps` make of a byte string (py_webauthn re-encodes
  the credential public key, and its length moves the authenticator-data pointer).
- `registration` / `authentication`: credentials run through `verify_registration_response`
  / `verify_authentication_response` with CoPilot's arguments, mapped the way CoPilot's
  service and route map them: `ok`, `rejected` (the 400/401 detail: an
  `InvalidRegistrationResponse`/`InvalidAuthenticationResponse` or any `ValueError`) or
  `internal` (anything else — an unhandled 500). `message_differs` marks the few cases whose
  detail is a third-party parser's text that the Rust port does not reproduce.
- `origins`: `resolve_request_origin`, `_get_rp_id_for_origin`, `_ensure_passkey_origin`,
  `is_passkey_configured` and `_get_rp_name` under different `WEBAUTHN_*` environments.
- `options`: `generate_registration_options` / `generate_authentication_options` with
  CoPilot's arguments and a fixed challenge, through `options_to_json`.
- `device_names`: the routes' `(name or "Passkey").strip()[:128] or "Passkey"`.
"""
import datetime
import hashlib
import json
import os
import sys

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "unused")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "unused")
os.environ.setdefault("JWT_SECRET", "vector-generator-secret")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))

import cbor2  # noqa: E402
import cryptography  # noqa: E402
import webauthn  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import (  # noqa: E402
    decode_dss_signature,
)
from cryptography.hazmat.primitives.asymmetric.utils import (  # noqa: E402
    encode_dss_signature,
)
from cryptography.x509.oid import NameOID  # noqa: E402
from webauthn import generate_authentication_options  # noqa: E402
from webauthn import generate_registration_options  # noqa: E402
from webauthn import options_to_json  # noqa: E402
from webauthn import verify_authentication_response  # noqa: E402
from webauthn import verify_registration_response  # noqa: E402
from webauthn.helpers import base64url_to_bytes  # noqa: E402
from webauthn.helpers import bytes_to_base64url  # noqa: E402
from webauthn.helpers.exceptions import InvalidAuthenticationResponse  # noqa: E402
from webauthn.helpers.exceptions import InvalidRegistrationResponse  # noqa: E402
from webauthn.helpers.structs import AuthenticatorSelectionCriteria  # noqa: E402
from webauthn.helpers.structs import ResidentKeyRequirement  # noqa: E402
from webauthn.helpers.structs import UserVerificationRequirement  # noqa: E402

from app.auth.services import passkey as copilot_passkey  # noqa: E402

RSA_PEM = b"""-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLZ2YbzrV6tRSN
3krQwGDkidmY+/eDkY+xWU0IOUV0PVs0EA1lXlZ9AH4hrg2Bd7VnIYpG7wYS8ewm
/bU3goquDsyzo0gArTh5e8O6380f+4Z6BqBOhSigQImS1FqZ5bSmGxOZ43b29EZG
sI7LI03UQLpukeX/6gTgCLXYnYt6f/+vkY+1U8FljLrowzyJHO7QCu8N7a9msslq
/zxWnyGFvKFEbyfwL52y30FPG1k4xL/6cBjGjFANiUrvBE1yRSmGBX/Ug6UGFuVb
lSj65zUI4G4lXRwN3x288pjPFV+hsyQmIK+tor272MGvrKaaMpuLZ5IatNl/mLzS
QJZ6+r1xAgMBAAECggEAAofko2qP06E4inAaUVT+c6ODNIoIjS+YyIuwV56KTqEj
jw8W0pTBGdyxZRMCxiJOnJQUUdAALOjLj9vi5wgZ2IL0wTSyNPdyyyCrCZqGpWvq
Uz79PELgA7fv2kbIAo+TDwjJ1nWoBZg6Hl+spCqKGa6tPypTsLqpQT4cgJ+rtExJ
GqWMBbmdb2h+zob9IlJEtHtshGQ1k4m+J+jH/qKc8BGxIvGeBDUkMJvCkMN+xQ7X
QkW7Ag818NBPhknkmaFY4biLbsmBcM9u9fCDsr/Ro7gAZFvQvevrRfIDRvbhZk9d
lqHCoHfLATk8rBI/18ZXW3xTyd3PLPet4J0kNEwfoQKBgQDxiUPYoyLymkY+GHlx
ocKLlzJnJEe7e9QITr1bTNP0yRD5Bk8xmUCB9Uxbi+H+k+ughJcT43y+qevXdJdf
yUhjeGOMJuJbu+0Mk1E9t98TbDakIoGjO/a9AHn7pp8TJSFTdcrlI/OGkfUKvJyG
Gc3rrA2C533F5TxAI4q/oRy2EQKBgQDXlZF0Mcv7bOYUQ4yroMQyhYtmR+ChfSo8
V/wit7QJseWc7/jFcHN8l3cZKcQRERWJJQzeaqJ5HB1Gtdhj6SpyzEwFWd26IZEv
m4RK7mtGE4ZCX4/g5VJUuzQ99lvGLWmGcT22h+eJkXQkGr4O37wPCBYudHb4XC/+
xzsqKbixYQKBgQDCrNYISASk8P9okSVhFvXMuMKhKza9v+J4B67LZbL4ew65CALQ
gSrjFCjFKIuwOt0RdYynNRWYPzCdaZWQWJWFxsTFc5nCQkefeSVjz013RCMOS9md
DXmjgDzRPcy9C5I+yJQN99oSPpX4X2jxFN9J8lS5i4dt94OGVp9AMMUJYQKBgQCu
ZKCoZQwElKA+bjJiOAfecqdEkwqEuDKtY+Nj1kU+vnjnDjyowwG5HPHMGjwwLijE
q4MQfSR3YiXQqJOmptyexuMMRRkXU8YVw/EtiFag9nRaRuGl5PxH7LQjF6I/20aM
6hgpCyFi6JYSCswKTjTb2AfRhoci+7gbmuEih2OPoQKBgF+UWCnFnVaqMeKUhHMZ
B1YgfGR5vvDgamT6hN+sR6AWZY+89p7ZXhqQzwwRPjO9+lMAyjks7X5HolUpLPW7
7AEI59GhttcWes3q1txltBFvxMyN2E/Z3+oClujAB9wzhj6b5aHlDA45HLC/bJQ+
oLsnhujk1rhMu5PtZKm3DeO8
-----END PRIVATE KEY-----
"""

RP_ID = "localhost"
ORIGIN = "http://localhost:5173"
CHALLENGE = bytes(range(64))
OTHER_CHALLENGE = bytes(range(1, 65))
AAGUID = bytes.fromhex("adce000235bcc60a648b0b25f1f05503")
ZERO_AAGUID = bytes(16)
CRED_ID = bytes(range(100, 132))
PSS_SALT = bytes(range(32))

P256 = ec.derive_private_key(0x1F2E3D4C5B6A7980, ec.SECP256R1())
P384 = ec.derive_private_key(0x2F2E3D4C5B6A7981, ec.SECP384R1())
P521 = ec.derive_private_key(0x3F2E3D4C5B6A7982, ec.SECP521R1())
ED = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
RSA = serialization.load_pem_private_key(RSA_PEM, password=None)
HASHES = {
    -7: hashes.SHA256(),
    -36: hashes.SHA512(),
    -37: hashes.SHA256(),
    -38: hashes.SHA384(),
    -39: hashes.SHA512(),
    -257: hashes.SHA256(),
    -258: hashes.SHA384(),
    -259: hashes.SHA512(),
    -65535: hashes.SHA1(),
}
HASHLIB = {"SHA256": hashlib.sha256, "SHA384": hashlib.sha384, "SHA512": hashlib.sha512, "SHA1": hashlib.sha1}


def b64u(data: bytes) -> str:
    return bytes_to_base64url(data)


def int_bytes(value: int, size: int) -> bytes:
    return value.to_bytes(size, "big")


def mgf1(seed: bytes, length: int, hash_fn) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hash_fn(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def pss_sign(message: bytes, hash_fn, salt: bytes) -> bytes:
    """EMSA-PSS-ENCODE with a fixed salt, then the raw RSA private operation."""
    numbers = RSA.private_numbers()
    n, d = numbers.public_numbers.n, numbers.d
    mod_bits = n.bit_length()
    em_bits = mod_bits - 1
    em_len = (em_bits + 7) // 8
    m_hash = hash_fn(message).digest()
    h = hash_fn(b"\x00" * 8 + m_hash + salt).digest()
    ps = b"\x00" * (em_len - len(salt) - len(h) - 2)
    db = ps + b"\x01" + salt
    masked = bytes(a ^ b for a, b in zip(db, mgf1(h, len(db), hash_fn)))
    masked = bytes([masked[0] & (0xFF >> (8 * em_len - em_bits))]) + masked[1:]
    em = masked + h + b"\xbc"
    k = (mod_bits + 7) // 8
    return int_bytes(pow(int.from_bytes(em, "big"), d, n), k)


class Key:
    """A credential key: its COSE map and how it signs."""

    def __init__(self, kind, alg, private):
        self.kind, self.alg, self.private = kind, alg, private

    def cose(self) -> dict:
        if self.kind == "ec":
            numbers = self.private.public_key().public_numbers()
            size = (self.private.curve.key_size + 7) // 8
            crv = {"secp256r1": 1, "secp384r1": 2, "secp521r1": 3}[self.private.curve.name]
            return {1: 2, 3: self.alg, -1: crv, -2: int_bytes(numbers.x, size), -3: int_bytes(numbers.y, size)}
        if self.kind == "ed":
            raw = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            return {1: 1, 3: self.alg, -1: 6, -2: raw}
        numbers = self.private.public_key().public_numbers()
        return {1: 3, 3: self.alg, -1: int_bytes(numbers.n, 256), -2: int_bytes(numbers.e, 3)}

    def sign(self, data: bytes) -> bytes:
        if self.kind == "ec":
            return self.private.sign(data, ec.ECDSA(HASHES[self.alg], deterministic_signing=True))
        if self.kind == "ed":
            return self.private.sign(data)
        if self.alg in (-37, -38, -39):
            return pss_sign(data, HASHLIB[HASHES[self.alg].name.upper()], PSS_SALT)
        return self.private.sign(data, padding.PKCS1v15(), HASHES[self.alg])


ES256 = Key("ec", -7, P256)
KEYS = {
    "ES256": ES256,
    "ES256_P384": Key("ec", -7, P384),
    "ES512_P521": Key("ec", -36, P521),
    "ES512_P256": Key("ec", -36, P256),
    "EdDSA": Key("ed", -8, ED),
    "RS256": Key("rsa", -257, RSA),
    "RS384": Key("rsa", -258, RSA),
    "RS512": Key("rsa", -259, RSA),
    "PS256": Key("rsa", -37, RSA),
    "PS384": Key("rsa", -38, RSA),
    "PS512": Key("rsa", -39, RSA),
    "RS1": Key("rsa", -65535, RSA),
}


def cert(private, subject_cn="CoPilot vector", issuer_key=None):
    issuer_key = issuer_key or private
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private.public_key())
        .serial_number(4242)
        .not_valid_before(datetime.datetime(2024, 1, 1))
        .not_valid_after(datetime.datetime(2044, 1, 1))
    )
    if isinstance(issuer_key, ec.EllipticCurvePrivateKey):
        signed = builder.sign(issuer_key, hashes.SHA256(), ecdsa_deterministic=True)
    elif isinstance(issuer_key, ed25519.Ed25519PrivateKey):
        signed = builder.sign(issuer_key, None)
    else:
        signed = builder.sign(issuer_key, hashes.SHA256())
    return signed.public_bytes(serialization.Encoding.DER)


def auth_data(
    *,
    rp_id=RP_ID,
    flags=0x45,
    sign_count=0,
    aaguid=AAGUID,
    cred_id=CRED_ID,
    cose=None,
    cose_bytes=None,
    extensions=None,
    attested=True,
) -> bytes:
    out = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + sign_count.to_bytes(4, "big")
    if attested:
        key = cose_bytes if cose_bytes is not None else cbor2.dumps(cose if cose is not None else ES256.cose())
        out += aaguid + len(cred_id).to_bytes(2, "big") + cred_id + key
    if extensions is not None:
        out += extensions
    return out


def client_data(type_="webauthn.create", challenge=CHALLENGE, origin=ORIGIN, **extra) -> bytes:
    doc = {"type": type_, "challenge": b64u(challenge) if isinstance(challenge, bytes) else challenge, "origin": origin}
    doc.update(extra)
    return json.dumps(doc, separators=(",", ":")).encode()


def registration(att_obj: bytes, cdj: bytes, *, cred_id=CRED_ID, **overrides) -> dict:
    cred = {
        "id": b64u(cred_id),
        "rawId": b64u(cred_id),
        "response": {"clientDataJSON": b64u(cdj), "attestationObject": b64u(att_obj), "transports": ["internal", "hybrid"]},
        "type": "public-key",
        "clientExtensionResults": {},
        "authenticatorAttachment": "platform",
    }
    for key, value in overrides.items():
        if key.startswith("response_"):
            cred["response"][key[len("response_") :]] = value
        elif value is DROP:
            cred.pop(key, None)
        else:
            cred[key] = value
    return cred


DROP = object()


def attestation(fmt="none", att_stmt=None, ad=None, *, raw=None) -> bytes:
    if raw is not None:
        return raw
    doc = {"fmt": fmt, "attStmt": {} if att_stmt is None else att_stmt, "authData": ad if ad is not None else auth_data()}
    return cbor2.dumps(doc)


def packed(key: Key, ad: bytes, cdj: bytes, *, x5c=None, alg=None, sig=None) -> bytes:
    stmt = {"alg": key.alg if alg is None else alg}
    data = ad + hashlib.sha256(cdj).digest()
    stmt["sig"] = key.sign(data) if sig is None else sig
    if x5c is not None:
        stmt["x5c"] = x5c
    return attestation("packed", stmt, ad)


def u2f(key_priv, ad: bytes, cdj: bytes, *, cert_der=None, cred_cose=None, x5c=None, sig=None) -> bytes:
    cose = cred_cose or ES256.cose()
    data = b"\x00" + hashlib.sha256(RP_ID.encode()).digest() + hashlib.sha256(cdj).digest() + CRED_ID + b"\x04" + cose[-2] + cose[-3]
    signature = key_priv.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)) if sig is None else sig
    stmt = {"sig": signature, "x5c": x5c if x5c is not None else [cert_der or cert(key_priv)]}
    return attestation("fido-u2f", stmt, ad)


def run_registration(cred, challenge=CHALLENGE):
    try:
        verified = verify_registration_response(
            credential=cred,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=False,
        )
    except InvalidRegistrationResponse as e:
        return {"rejected": str(e)}
    except ValueError as e:
        return {"rejected": str(e)}
    except Exception as e:  # noqa: BLE001 - CoPilot lets these through: a 500
        return {"internal": type(e).__name__}
    try:
        # services/passkey.py:verify_registration, after the verification.
        transports = list(cred.get("response", {}).get("transports") or [])
    except Exception as e:  # noqa: BLE001
        return {"internal": type(e).__name__}
    return {
        "ok": {
            "credential_id": b64u(verified.credential_id),
            "public_key": b64u(verified.credential_public_key),
            "sign_count": verified.sign_count,
            "transports": transports,
        },
    }


def run_authentication(cred, public_key: bytes, sign_count: int, challenge=CHALLENGE):
    try:
        verified = verify_authentication_response(
            credential=cred,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=False,
        )
    except InvalidAuthenticationResponse as e:
        return {"rejected": str(e)}
    except ValueError as e:
        return {"rejected": str(e)}
    except Exception as e:  # noqa: BLE001
        return {"internal": type(e).__name__}
    return {"ok": {"new_sign_count": verified.new_sign_count}}


REG = []


def reg(name, cred, challenge=CHALLENGE, message_differs=False):
    case = {"name": name, "credential": cred, "challenge": b64u(challenge), "outcome": run_registration(cred, challenge)}
    if message_differs:
        case["message_differs"] = True
    REG.append(case)


def registrations():
    cdj = client_data()
    for name, key in KEYS.items():
        reg(f"none {name}", registration(attestation(ad=auth_data(cose=key.cose())), cdj))
    reg("none ES384 unsupported", registration(attestation(ad=auth_data(cose={**ES256.cose(), 3: -35})), cdj))
    reg("none alg as text", registration(attestation(ad=auth_data(cose={**ES256.cose(), 3: "ES256"})), cdj))
    reg("none alg float", registration(attestation(ad=auth_data(cose={**ES256.cose(), 3: -7.0})), cdj))
    reg("none attStmt missing", registration(cbor2.dumps({"fmt": "none", "authData": auth_data()}), cdj))
    reg("none attStmt sig null", registration(attestation("none", {"sig": None}), cdj))
    reg("none attStmt with sig", registration(attestation("none", {"sig": b"x"}), cdj))
    reg("none attStmt with alg", registration(attestation("none", {"alg": -7}), cdj))
    reg("none attStmt unknown field", registration(attestation("none", {"foo": 1}), cdj))
    reg("unknown fmt", registration(attestation("foo"), cdj))
    reg("fmt bytes", registration(attestation(b"none"), cdj))
    reg("fmt int", registration(attestation(5), cdj))
    reg("fmt compound", registration(attestation("compound", {"x": 1}), cdj))
    for fmt in ("tpm", "android-key", "android-safetynet", "apple"):
        reg(
            f"vendor fmt {fmt}",
            registration(attestation(fmt, {"sig": b"x", "alg": -7, "x5c": [b"x"], "ver": "2.0"}), cdj),
            message_differs=True,
        )

    # packed
    ad = auth_data()
    reg("packed self ES256", registration(packed(ES256, ad, cdj), cdj))
    for name in ("EdDSA", "RS256", "PS256", "ES512_P521", "ES256_P384"):
        key = KEYS[name]
        key_ad = auth_data(cose=key.cose())
        reg(f"packed self {name}", registration(packed(key, key_ad, cdj), cdj))
    reg("packed self bad sig", registration(packed(ES256, ad, cdj, sig=b"\x30\x06\x02\x01\x01\x02\x01\x01"), cdj))
    reg("packed self garbage sig", registration(packed(ES256, ad, cdj, sig=b"garbage"), cdj))
    reg("packed self alg mismatch", registration(packed(ES256, ad, cdj, alg=-257), cdj))
    reg("packed missing sig", registration(attestation("packed", {"alg": -7}, ad), cdj))
    reg("packed empty sig", registration(attestation("packed", {"alg": -7, "sig": b""}, ad), cdj))
    reg("packed missing alg", registration(attestation("packed", {"sig": b"x"}, ad), cdj))
    reg("packed self signed by other key", registration(packed(KEYS["ES256_P384"], ad, cdj, alg=-7), cdj))
    off_curve = {**ES256.cose(), -3: bytes(32)}
    off_ad = auth_data(cose=off_curve)
    reg("packed self off-curve key", registration(attestation("packed", {"alg": -7, "sig": b"x"}, off_ad), cdj))
    p256_cert = cert(P256)
    reg("packed x5c ES256", registration(packed(ES256, ad, cdj, x5c=[p256_cert]), cdj))
    reg("packed x5c chain of two", registration(packed(ES256, ad, cdj, x5c=[p256_cert, cert(P384)]), cdj))
    rsa_cert = cert(RSA)
    reg("packed x5c RS256", registration(packed(KEYS["RS256"], ad, cdj, x5c=[rsa_cert]), cdj))
    reg("packed x5c PS256", registration(packed(KEYS["PS256"], ad, cdj, x5c=[rsa_cert]), cdj))
    reg("packed x5c ES512 on P-256 cert", registration(packed(KEYS["ES512_P256"], ad, cdj, x5c=[p256_cert]), cdj))
    reg("packed x5c Ed25519 cert", registration(packed(KEYS["EdDSA"], ad, cdj, x5c=[cert(ED)]), cdj))
    reg("packed x5c bad sig", registration(packed(ES256, ad, cdj, x5c=[p256_cert], sig=b"\x30\x06\x02\x01\x01\x02\x01\x01"), cdj))
    reg("packed x5c wrong cert", registration(packed(ES256, ad, cdj, x5c=[cert(P384)]), cdj))
    reg("packed x5c EC cert RSA alg", registration(packed(ES256, ad, cdj, x5c=[p256_cert], alg=-257), cdj))
    reg("packed x5c RSA cert EC alg", registration(packed(KEYS["RS256"], ad, cdj, x5c=[rsa_cert], alg=-7), cdj))
    reg("packed x5c garbage cert", registration(packed(ES256, ad, cdj, x5c=[b"not a certificate"]), cdj), message_differs=True)
    reg("packed x5c text entry", registration(packed(ES256, ad, cdj, x5c=["abc"]), cdj))

    # fido-u2f
    zero_ad = auth_data(aaguid=ZERO_AAGUID)
    reg("fido-u2f", registration(u2f(P256, zero_ad, cdj), cdj))
    reg("fido-u2f nonzero aaguid", registration(u2f(P256, ad, cdj), cdj))
    reg("fido-u2f two certs", registration(u2f(P256, zero_ad, cdj, x5c=[p256_cert, p256_cert]), cdj))
    reg("fido-u2f missing x5c", registration(attestation("fido-u2f", {"sig": b"x"}, zero_ad), cdj))
    reg("fido-u2f missing sig", registration(attestation("fido-u2f", {"x5c": [p256_cert]}, zero_ad), cdj))
    reg("fido-u2f rsa cert", registration(attestation("fido-u2f", {"sig": b"x", "x5c": [rsa_cert]}, zero_ad), cdj))
    reg("fido-u2f p384 cert", registration(attestation("fido-u2f", {"sig": b"x", "x5c": [cert(P384)]}, zero_ad), cdj))
    rsa_cred_ad = auth_data(aaguid=ZERO_AAGUID, cose=KEYS["RS256"].cose())
    reg("fido-u2f rsa credential", registration(attestation("fido-u2f", {"sig": b"x", "x5c": [p256_cert]}, rsa_cred_ad), cdj))
    reg("fido-u2f bad sig", registration(u2f(P256, zero_ad, cdj, sig=b"\x30\x06\x02\x01\x01\x02\x01\x01"), cdj))
    reg("fido-u2f garbage cert", registration(attestation("fido-u2f", {"sig": b"x", "x5c": [b"junk"]}, zero_ad), cdj), message_differs=True)

    # client data
    reg("wrong type", registration(attestation(), client_data("webauthn.get")))
    reg("type number", registration(attestation(), client_data(5)))
    reg("type null", registration(attestation(), client_data(None)))
    reg("wrong challenge", registration(attestation(), client_data(challenge=OTHER_CHALLENGE)))
    reg("challenge number", registration(attestation(), client_data(challenge=1234)))
    reg("challenge bad base64", registration(attestation(), client_data(challenge="A")))
    reg("challenge padded", registration(attestation(), client_data(challenge=b64u(CHALLENGE) + "==")))
    reg("challenge with junk", registration(attestation(), client_data(challenge="!" + b64u(CHALLENGE))))
    reg("wrong origin", registration(attestation(), client_data(origin="https://evil.example")))
    reg("origin number", registration(attestation(), client_data(origin=5)))
    reg("origin list", registration(attestation(), client_data(origin=["a", 1, None, True, 1.5])))
    reg("origin dict", registration(attestation(), client_data(origin={"a": "b'c"})))
    reg("origin trailing slash", registration(attestation(), client_data(origin=ORIGIN + "/")))
    reg("token binding present", registration(attestation(), client_data(tokenBinding={"status": "present", "id": "x"})))
    reg("token binding bad status", registration(attestation(), client_data(tokenBinding={"status": "not-supported"})))
    reg("token binding status number", registration(attestation(), client_data(tokenBinding={"status": 3})))
    reg("token binding no status", registration(attestation(), client_data(tokenBinding={"id": "x"})))
    reg("token binding string", registration(attestation(), client_data(tokenBinding="present")))
    reg("cross origin", registration(attestation(), client_data(crossOrigin=True)))
    reg("client data not json", registration(attestation(), b"{not json"))
    reg("client data array", registration(attestation(), b"[1,2]"))
    reg("client data missing type", registration(attestation(), b'{"challenge":"' + b64u(CHALLENGE).encode() + b'","origin":"x"}'))
    reg(
        "client data missing origin",
        registration(attestation(), b'{"type":"webauthn.create","challenge":"' + b64u(CHALLENGE).encode() + b'"}'),
    )
    reg("client data utf8 bom", registration(attestation(), b"\xef\xbb\xbf" + cdj))
    reg("client data utf16", registration(attestation(), cdj.decode().encode("utf-16-le")))
    reg("client data duplicate key", registration(attestation(), cdj[:-1] + b',"type":"webauthn.get"}'))
    reg("client data NaN", registration(attestation(), cdj[:-1] + b',"x":NaN}'))

    # credential structure
    good_att = attestation()
    reg("missing id", registration(good_att, cdj, id=DROP))
    reg("id mismatch", registration(good_att, cdj, id=b64u(b"other")))
    reg("id padded", registration(good_att, cdj, id=b64u(CRED_ID) + "=", rawId=b64u(CRED_ID) + "="))
    reg("rawId with junk", registration(good_att, cdj, rawId="*" + b64u(CRED_ID)))
    reg("rawId bad base64", registration(good_att, cdj, rawId="A", id="A"))
    reg("missing rawId", registration(good_att, cdj, rawId=DROP))
    reg("id number", registration(good_att, cdj, id=5))
    reg("wrong type field", registration(good_att, cdj, type="password"))
    reg("missing type field", registration(good_att, cdj, type=DROP))
    reg("bad attachment", registration(good_att, cdj, authenticatorAttachment="usb"))
    reg("attachment number", registration(good_att, cdj, authenticatorAttachment=5))
    reg("cross-platform attachment", registration(good_att, cdj, authenticatorAttachment="cross-platform"))
    reg("response not object", registration(good_att, cdj, response="x"))
    reg("missing clientDataJSON", registration(good_att, cdj, response_clientDataJSON=None))
    reg("attestationObject bad base64", registration(good_att, cdj, response_attestationObject="A"))
    reg("attestationObject non-ascii", registration(good_att, cdj, response_attestationObject="ä"))
    reg("clientDataJSON bad base64", registration(good_att, cdj, response_clientDataJSON="A"))
    reg("transports string", registration(good_att, cdj, response_transports="usb"))
    reg("transports object", registration(good_att, cdj, response_transports={"usb": 1, "nfc": 2}))
    reg("transports null", registration(good_att, cdj, response_transports=None))
    reg("transports unknown", registration(good_att, cdj, response_transports=["usb", "carrier-pigeon", 7]))
    reg("transports number", registration(good_att, cdj, response_transports=5))
    reg("transports true", registration(good_att, cdj, response_transports=True))
    reg("transports zero", registration(good_att, cdj, response_transports=0))

    # attestation object and authenticator data
    reg("attestation not cbor", registration(b"\xff", cdj))
    reg("attestation empty", registration(b"", cdj))
    reg("attestation array", registration(cbor2.dumps([1, 2]), cdj))
    reg("attestation missing fmt", registration(cbor2.dumps({"attStmt": {}, "authData": auth_data()}), cdj))
    reg("attestation missing authData", registration(cbor2.dumps({"fmt": "none", "attStmt": {}}), cdj))
    reg("attestation trailing bytes", registration(good_att + b"\x00\x01", cdj))
    reg("authData text", registration(cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": "x" * 40}), cdj))
    reg("authData int", registration(cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": 40}), cdj))
    reg("authData list", registration(cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": list(auth_data())}), cdj))
    reg("authData short", registration(attestation(ad=auth_data()[:36]), cdj))
    reg("rp id hash", registration(attestation(ad=auth_data(rp_id="evil.example")), cdj))
    reg("user not present", registration(attestation(ad=auth_data(flags=0x44)), cdj))
    reg("user verified", registration(attestation(ad=auth_data(flags=0x45 | 0x04)), cdj))
    reg("no attested data", registration(attestation(ad=auth_data(flags=0x01, attested=False)), cdj))
    reg("attested flag without data", registration(attestation(ad=auth_data(attested=False)), cdj))
    reg("empty credential id", registration(attestation(ad=auth_data(cred_id=b"")), cdj, cred_id=b""))
    reg("short aaguid", registration(attestation(ad=auth_data()[:37] + b"\x01\x02"), cdj))
    reg("leftover bytes", registration(attestation(ad=auth_data() + b"\x00"), cdj))
    ext = cbor2.dumps({"credProtect": 2})
    reg("extensions", registration(attestation(ad=auth_data(flags=0xC5, extensions=ext)), cdj))
    reg("extensions flag without data", registration(attestation(ad=auth_data(flags=0xC5)), cdj))
    reg("backup eligible and state", registration(attestation(ad=auth_data(flags=0x45 | 0x18)), cdj))
    reg("backup state without eligible", registration(attestation(ad=auth_data(flags=0x45 | 0x10)), cdj))
    reg("sign count", registration(attestation(ad=auth_data(sign_count=7)), cdj))
    cose_bad_eddsa = bytes.fromhex("a301634f4b500327206745643235353139") + bytes.fromhex("21") + cbor2.dumps(bytes(32))
    reg("eddsa map-of-three quirk", registration(attestation(ad=auth_data(cose_bytes=cose_bad_eddsa)), cdj))
    reg("cose key int 4", registration(attestation(ad=auth_data(cose_bytes=b"\x04")), cdj))
    reg("cose key array", registration(attestation(ad=auth_data(cose_bytes=cbor2.dumps([1, 2, 3, 4]))), cdj))
    reg("cose missing kty", registration(attestation(ad=auth_data(cose={3: -7, -1: 1, -2: b"x", -3: b"y"})), cdj))
    reg("cose kty zero", registration(attestation(ad=auth_data(cose={1: 0, 3: -7})), cdj))
    reg("cose missing alg", registration(attestation(ad=auth_data(cose={1: 2, -1: 1})), cdj))
    reg("cose kty 4", registration(attestation(ad=auth_data(cose={1: 4, 3: -7})), cdj))
    reg("cose ec missing y", registration(attestation(ad=auth_data(cose={1: 2, 3: -7, -1: 1, -2: b"x"})), cdj))
    reg("cose ec empty x", registration(attestation(ad=auth_data(cose={1: 2, 3: -7, -1: 1, -2: b"", -3: b"y"})), cdj))
    reg("cose okp missing x", registration(attestation(ad=auth_data(cose={1: 1, 3: -8, -1: 6})), cdj))
    reg("cose rsa missing e", registration(attestation(ad=auth_data(cose={1: 3, 3: -257, -1: b"n"})), cdj))
    reg("cose kty true", registration(attestation(ad=auth_data(cose={1: True, 3: -8, -1: 6, -2: bytes(32)})), cdj))
    reg("cose text kty", registration(attestation(ad=auth_data(cose={1: "EC2", 3: -7})), cdj))
    reg(
        "cose duplicate key",
        registration(
            attestation(
                ad=auth_data(
                    cose_bytes=bytes.fromhex("a6010203260102")
                    + cbor2.dumps(-1)
                    + b"\x01"
                    + b"\x21"
                    + cbor2.dumps(b"x" * 32)
                    + b"\x22"
                    + cbor2.dumps(b"y" * 32),
                ),
            ),
            cdj,
        ),
    )
    reg(
        "cose non-shortest int",
        registration(
            attestation(
                ad=auth_data(
                    cose_bytes=bytes.fromhex("a50102033806200121")
                    + cbor2.dumps(ES256.cose()[-2])
                    + b"\x22"
                    + cbor2.dumps(ES256.cose()[-3]),
                ),
            ),
            cdj,
        ),
    )
    reg(
        "cose half float value",
        registration(
            attestation(ad=auth_data(cose_bytes=bytes([0xA6]) + cbor2.dumps(ES256.cose())[1:] + bytes.fromhex("1863f93c00"))),
            cdj,
        ),
    )
    reg(
        "cose bignum alg",
        registration(
            attestation(
                ad=auth_data(
                    cose_bytes=bytes.fromhex("a50102")
                    + bytes.fromhex("03c34106")
                    + bytes.fromhex("2001")
                    + b"\x21"
                    + cbor2.dumps(ES256.cose()[-2])
                    + b"\x22"
                    + cbor2.dumps(ES256.cose()[-3]),
                ),
            ),
            cdj,
        ),
    )
    reg(
        "cose indefinite map",
        registration(attestation(ad=auth_data(cose_bytes=bytes([0xBF]) + cbor2.dumps(ES256.cose())[1:] + b"\xff")), cdj),
    )
    reg(
        "cose undefined value",
        registration(attestation(ad=auth_data(cose_bytes=bytes([0xA6]) + cbor2.dumps(ES256.cose())[1:] + bytes.fromhex("1863f7"))), cdj),
    )
    reg(
        "cose tag value",
        registration(
            attestation(ad=auth_data(cose_bytes=bytes([0xA6]) + cbor2.dumps(ES256.cose())[1:] + bytes.fromhex("1863c64101"))),
            cdj,
        ),
    )
    reg("cose truncated", registration(attestation(ad=auth_data(cose_bytes=cbor2.dumps(ES256.cose())[:20])), cdj))
    reg(
        "cose invalid utf8 key",
        registration(attestation(ad=auth_data(cose_bytes=bytes([0xA6]) + cbor2.dumps(ES256.cose())[1:] + bytes.fromhex("62c32801"))), cdj),
    )
    reg("challenge mismatch with packed", registration(packed(ES256, ad, cdj), cdj), challenge=OTHER_CHALLENGE)


def assertion(key: Key, *, ad=None, cdj=None, cred_id=CRED_ID, sig=None, **overrides) -> dict:
    ad = auth_data(flags=0x05, sign_count=1, attested=False) if ad is None else ad
    cdj = client_data("webauthn.get") if cdj is None else cdj
    signature = key.sign(ad + hashlib.sha256(cdj).digest()) if sig is None else sig
    cred = {
        "id": b64u(cred_id),
        "rawId": b64u(cred_id),
        "response": {
            "clientDataJSON": b64u(cdj),
            "authenticatorData": b64u(ad),
            "signature": b64u(signature),
            "userHandle": b64u(b"7"),
        },
        "type": "public-key",
        "clientExtensionResults": {},
        "authenticatorAttachment": "platform",
    }
    for k, value in overrides.items():
        if k.startswith("response_"):
            if value is DROP:
                cred["response"].pop(k[len("response_") :], None)
            else:
                cred["response"][k[len("response_") :]] = value
        elif value is DROP:
            cred.pop(k, None)
        else:
            cred[k] = value
    return cred


AUTH = []


def auth(name, cred, public_key: bytes, sign_count=0, challenge=CHALLENGE, message_differs=False):
    case = {
        "name": name,
        "credential": cred,
        "public_key": b64u(public_key),
        "sign_count": sign_count,
        "challenge": b64u(challenge),
        "outcome": run_authentication(cred, public_key, sign_count, challenge),
    }
    if message_differs:
        case["message_differs"] = True
    AUTH.append(case)


def authentications():
    for name, key in KEYS.items():
        pk = cbor2.dumps(key.cose())
        auth(f"{name}", assertion(key), pk)
        auth(f"{name} bad signature", assertion(key, sig=key.sign(b"something else")), pk)
    es = cbor2.dumps(ES256.cose())
    auth("ES256 malformed der", assertion(ES256, sig=b"\x30\x00"), es)
    auth("ES256 raw r||s", assertion(ES256, sig=b"\x01" * 64), es)
    good = ES256.sign(auth_data(flags=0x05, sign_count=1, attested=False) + hashlib.sha256(client_data("webauthn.get")).digest())
    r, s = decode_dss_signature(good)
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    auth("ES256 high S", assertion(ES256, sig=encode_dss_signature(r, n - s)), es)
    auth("ES256 trailing byte", assertion(ES256, sig=good + b"\x00"), es)
    auth("Ed25519 short signature", assertion(KEYS["EdDSA"], sig=b"\x00" * 63), cbor2.dumps(KEYS["EdDSA"].cose()))
    auth("RS256 short signature", assertion(KEYS["RS256"], sig=b"\x01" * 255), cbor2.dumps(KEYS["RS256"].cose()))
    auth(
        "PS256 digest-length salt",
        assertion(
            KEYS["PS256"],
            sig=pss_sign(
                auth_data(flags=0x05, sign_count=1, attested=False) + hashlib.sha256(client_data("webauthn.get")).digest(),
                hashlib.sha256,
                bytes(range(32)),
            ),
        ),
        cbor2.dumps(KEYS["PS256"].cose()),
    )
    auth(
        "PS256 empty salt",
        assertion(
            KEYS["PS256"],
            sig=pss_sign(
                auth_data(flags=0x05, sign_count=1, attested=False) + hashlib.sha256(client_data("webauthn.get")).digest(),
                hashlib.sha256,
                b"",
            ),
        ),
        cbor2.dumps(KEYS["PS256"].cose()),
    )

    # sign counts
    auth("sign count zero both", assertion(ES256, ad=auth_data(flags=0x05, sign_count=0, attested=False)), es, 0)
    auth("sign count equal", assertion(ES256, ad=auth_data(flags=0x05, sign_count=5, attested=False)), es, 5)
    auth("sign count lower", assertion(ES256, ad=auth_data(flags=0x05, sign_count=2, attested=False)), es, 5)
    auth("sign count reset to zero", assertion(ES256, ad=auth_data(flags=0x05, sign_count=0, attested=False)), es, 3)
    auth("sign count higher", assertion(ES256, ad=auth_data(flags=0x05, sign_count=9, attested=False)), es, 5)

    # flags / rp / client data
    auth("user not present", assertion(ES256, ad=auth_data(flags=0x04, sign_count=1, attested=False)), es)
    auth("backup state without eligible", assertion(ES256, ad=auth_data(flags=0x15, sign_count=1, attested=False)), es)
    auth("backup eligible and state", assertion(ES256, ad=auth_data(flags=0x1D, sign_count=1, attested=False)), es)
    auth("rp id hash", assertion(ES256, ad=auth_data(rp_id="evil.example", flags=0x05, sign_count=1, attested=False)), es)
    auth("authData short", assertion(ES256, ad=auth_data(flags=0x05, sign_count=1, attested=False)[:30]), es)
    auth("authData leftover", assertion(ES256, ad=auth_data(flags=0x05, sign_count=1, attested=False) + b"\x00"), es)
    auth("authData with attested data", assertion(ES256, ad=auth_data(flags=0x45, sign_count=1)), es)
    auth(
        "authData extensions",
        assertion(ES256, ad=auth_data(flags=0x85, sign_count=1, attested=False, extensions=cbor2.dumps({"x": 1}))),
        es,
    )
    auth("wrong type", assertion(ES256, cdj=client_data("webauthn.create")), es)
    auth("wrong challenge", assertion(ES256, cdj=client_data("webauthn.get", challenge=OTHER_CHALLENGE)), es)
    auth("wrong origin", assertion(ES256, cdj=client_data("webauthn.get", origin="https://evil.example")), es)
    auth("token binding bad status", assertion(ES256, cdj=client_data("webauthn.get", tokenBinding={"status": "x"})), es)
    auth("client data malformed", assertion(ES256, cdj=b"nope"), es)

    # credential structure
    auth("missing signature", assertion(ES256, response_signature=DROP), es)
    auth("missing authenticatorData", assertion(ES256, response_authenticatorData=DROP), es)
    auth("id mismatch", assertion(ES256, id="other"), es)
    auth("userHandle absent", assertion(ES256, response_userHandle=DROP), es)
    auth("userHandle null", assertion(ES256, response_userHandle=None), es)
    auth("userHandle bad base64", assertion(ES256, response_userHandle="A"), es)
    auth("userHandle non-ascii", assertion(ES256, response_userHandle="ü"), es)
    auth("userHandle number", assertion(ES256, response_userHandle=5), es)
    auth("signature bad base64", assertion(ES256, response_signature="A"), es)
    auth("wrong type field", assertion(ES256, type="nope"), es)
    auth("bad attachment", assertion(ES256, authenticatorAttachment="nope"), es)

    # stored keys
    auth("stored key off curve", assertion(ES256), cbor2.dumps({**ES256.cose(), -3: bytes(32)}))
    auth("stored key coordinate too long", assertion(ES256), cbor2.dumps({**ES256.cose(), -2: b"\x00" + ES256.cose()[-2]}))
    auth("stored key unknown curve", assertion(ES256), cbor2.dumps({**ES256.cose(), -1: 9}))
    auth("stored key rsa alg on ec", assertion(ES256), cbor2.dumps({**ES256.cose(), 3: -257}))
    auth("stored key ec alg -35", assertion(ES256), cbor2.dumps({**ES256.cose(), 3: -35}))
    auth("stored key int 4", assertion(ES256), b"\x04")
    rsa_cose = KEYS["RS256"].cose()
    auth("stored rsa e even", assertion(KEYS["RS256"]), cbor2.dumps({**rsa_cose, -2: b"\x01\x00\x00"}))
    auth("stored rsa e one", assertion(KEYS["RS256"]), cbor2.dumps({**rsa_cose, -2: b"\x01"}))
    auth("stored rsa n tiny", assertion(KEYS["RS256"]), cbor2.dumps({**rsa_cose, -1: b"\x01"}))
    auth("stored rsa ec alg", assertion(KEYS["RS256"]), cbor2.dumps({**rsa_cose, 3: -7}))
    ed_cose = KEYS["EdDSA"].cose()
    auth("stored ed25519 short", assertion(KEYS["EdDSA"]), cbor2.dumps({**ed_cose, -2: bytes(31)}))
    auth("stored ed25519 bad point", assertion(KEYS["EdDSA"]), cbor2.dumps({**ed_cose, -2: b"\xff" * 32}))
    auth("stored ed25519 crv text", assertion(KEYS["EdDSA"]), cbor2.dumps({**ed_cose, -1: "Ed25519"}))
    auth("stored ed25519 alg -7", assertion(KEYS["EdDSA"]), cbor2.dumps({**ed_cose, 3: -7}))
    auth("stored ec x text", assertion(ES256), cbor2.dumps({**ES256.cose(), -2: "abc"}))
    auth("stored key missing kty", assertion(ES256), cbor2.dumps({3: -7}))


def base64_cases():
    out = []
    for value in [
        "",
        "A",
        "AA",
        "AAA",
        "AAAA",
        "AAAAA",
        "AB=C",
        "QQ===xyz",
        "a!b",
        "a b",
        "QUJD",
        "QUJD=",
        "QQ==",
        "-_-_",
        "+/+/",
        "ä",
        "Zm9v\nYmFy",
        "=QQ",
        "Q=Q",
        "QQ=Q",
        "QUJDRA",
        "QQ=QQQQ=QQ",
        "QQ=QQQQ=QQQ",
    ]:
        try:
            out.append({"input": value, "bytes": base64url_to_bytes(value).hex()})
        except Exception as e:  # noqa: BLE001
            out.append({"input": value, "error": str(e), "kind": type(e).__name__})
    return out


def cbor_cases():
    out = []
    for hexed in [
        "01",
        "0102",
        "17",
        "1818",
        "1801",
        "190001",
        "1a00000001",
        "1b0000000000000001",
        "1bffffffffffffffff",
        "20",
        "3bffffffffffffffff",
        "3806",
        "1c",
        "1f",
        "40",
        "4401020304",
        "5f4101ff",
        "5f41014102ff",
        "5f01ff",
        "60",
        "6161",
        "62c328",
        "7f6161ff",
        "80",
        "820102",
        "9f0102ff",
        "a0",
        "a10102",
        "a201020103",
        "a2010201f5",
        "a20102f503",
        "a182010203",
        "a1a1010203",
        "bf0102ff",
        "c24101",
        "c249010000000000000000",
        "c2420001",
        "c34100",
        "c349010000000000000000",
        "c26161",
        "d9d9f701",
        "c601",
        "f4",
        "f5",
        "f6",
        "f7",
        "e0",
        "f0",
        "f818",
        "f820",
        "f93c00",
        "fa3fc00000",
        "fb3ff0000000000000",
        "f97c00",
        "ff",
        "",
        "1a0000",
        "a1",
        "9f01",
        "a301634f4b500327206745643235353139",
    ]:
        data = bytes.fromhex(hexed)
        try:
            value = cbor2.loads(data)
        except Exception as e:  # noqa: BLE001
            out.append({"input": hexed, "decode_error": type(e).__name__})
            continue
        try:
            out.append({"input": hexed, "encoded": cbor2.dumps(value).hex()})
        except Exception as e:  # noqa: BLE001
            out.append({"input": hexed, "encode_error": type(e).__name__})
    return out


ORIGIN_ENVS = [
    {"WEBAUTHN_ORIGINS": "https://copilot.example.com", "WEBAUTHN_RP_ID": "copilot.example.com"},
    {"WEBAUTHN_ORIGINS": "https://copilot.example.com/, https://soc.example.com:8443 ,,", "WEBAUTHN_RP_ID": " example.com "},
    {"WEBAUTHN_ORIGINS": "http://localhost:5173", "WEBAUTHN_RP_ID": "localhost"},
    {"WEBAUTHN_ORIGINS": "http://127.0.0.1:5173"},
    {"WEBAUTHN_ORIGINS": "http://localhost:5173,https://a.example"},
    {"WEBAUTHN_ORIGIN": "https://legacy.example.com"},
    {"WEBAUTHN_ORIGINS": "", "WEBAUTHN_ORIGIN": "https://legacy.example.com"},
    {},
    {"WEBAUTHN_ORIGINS": "https://copilot.example.com", "WEBAUTHN_RP_ID": "other.example"},
    {"WEBAUTHN_ORIGINS": "https://copilot.example.com", "WEBAUTHN_RP_NAME": "  ", "WEBAUTHN_RP_ID": ""},
    {"WEBAUTHN_ORIGINS": "https://[::1]:8443,http://LOCALHOST:5173", "WEBAUTHN_RP_NAME": " Acme SOC "},
]
REQUEST_ORIGINS = [
    None,
    "",
    "https://copilot.example.com",
    "https://copilot.example.com/",
    "https://copilot.example.com//",
    "https://soc.example.com:8443",
    "https://evil.example",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://localhost",
    "http://127.0.0.1",
    "http://localhost:abc",
    "http://127.0.0.1:99999",
    "https://a.example",
    "https://[::1]:8443",
    "http://LOCALHOST:5173",
    "http://user@localhost:5173",
    "null",
]


def origin_cases():
    out = []
    keys = ("WEBAUTHN_ORIGINS", "WEBAUTHN_ORIGIN", "WEBAUTHN_RP_ID", "WEBAUTHN_RP_NAME")
    saved = {k: os.environ.get(k) for k in keys}
    for env in ORIGIN_ENVS:
        for k in keys:
            os.environ.pop(k, None)
        os.environ.update(env)
        results = []
        for request_origin in REQUEST_ORIGINS:
            row = {"request": request_origin}
            try:
                resolved = copilot_passkey.resolve_request_origin(request_origin)
            except ValueError as e:
                row["error"] = str(e)
                results.append(row)
                continue
            row["resolved"] = resolved
            row["rp_id"] = copilot_passkey._get_rp_id_for_origin(resolved)
            try:
                copilot_passkey._ensure_passkey_origin(resolved)
                row["ensure"] = None
            except ValueError as e:
                row["ensure"] = str(e)
            results.append(row)
        out.append(
            {
                "env": env,
                "configured": copilot_passkey.is_passkey_configured(),
                "rp_name": copilot_passkey._get_rp_name(),
                "requests": results,
            },
        )
    for k, v in saved.items():
        os.environ.pop(k, None)
        if v is not None:
            os.environ[k] = v
    return out


def options_cases():
    stored = [
        (b64u(CRED_ID), ["internal", "hybrid"]),
        (b64u(bytes([1, 2, 3])), []),
        (b64u(bytes([4, 5])), ["usb", "carrier-pigeon", 7, None]),
        (b64u(bytes([9])), None),
    ]
    descriptors = [copilot_passkey._credential_descriptor(cid, transports) for cid, transports in stored]
    registration_options = generate_registration_options(
        rp_id=RP_ID,
        rp_name="SOCFortress CoPilot",
        user_id=str(7).encode(),
        user_name="alice",
        user_display_name="alice",
        exclude_credentials=descriptors,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        challenge=CHALLENGE,
    )
    empty_registration = generate_registration_options(
        rp_id="example.com",
        rp_name="Acme",
        user_id=str(12).encode(),
        user_name="bob",
        user_display_name="bob",
        exclude_credentials=[],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        challenge=CHALLENGE,
    )
    authentication_options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=descriptors,
        user_verification=UserVerificationRequirement.PREFERRED,
        challenge=CHALLENGE,
    )
    usernameless = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=None,
        user_verification=UserVerificationRequirement.PREFERRED,
        challenge=CHALLENGE,
    )
    return {
        "challenge": b64u(CHALLENGE),
        "stored": [{"credential_id": cid, "transports": transports} for cid, transports in stored],
        "registration": json.loads(options_to_json(registration_options)),
        "registration_empty": json.loads(options_to_json(empty_registration)),
        "authentication": json.loads(options_to_json(authentication_options)),
        "authentication_usernameless": json.loads(options_to_json(usernameless)),
    }


def device_names():
    out = []
    for name in [None, "", "  ", " YubiKey 5 ", "x" * 200, "ä" * 130, "　Laptop　", "\x1cTab\x1f", " " + "y" * 128 + " "]:
        out.append({"input": name, "output": (name or "Passkey").strip()[:128] or "Passkey"})
    return out


def main():
    registrations()
    authentications()
    doc = {
        "webauthn": webauthn.__version__,
        "cbor2": cbor2.__version__ if hasattr(cbor2, "__version__") else "5.9.0",
        "cryptography": cryptography.__version__,
        "rp_id": RP_ID,
        "origin": ORIGIN,
        "base64url": base64_cases(),
        "cbor": cbor_cases(),
        "registration": REG,
        "authentication": AUTH,
        "origins": origin_cases(),
        "options": options_cases(),
        "device_names": device_names(),
    }
    json.dump(doc, sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write("\n")


main()
