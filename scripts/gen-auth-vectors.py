"""Generate 2FA vectors for copilot-auth's Fernet and TOTP ports.

    backend/.venv/bin/python -I scripts/gen-auth-vectors.py \
        > crates/copilot-auth/src/auth_vectors.json

- `fernet`: tokens made by `cryptography.fernet.Fernet` (fixed time and IV so the
  Rust encryption must produce them byte for byte), the key derived from a
  `JWT_SECRET` the way `app/auth/services/totp.py` derives it, and tokens that
  must not decrypt.
- `totp`: `pyotp.TOTP(secret).at(t)` codes, `verify(code, valid_window=1)`
  outcomes (NFKC-normalised comparison included) and provisioning URIs.
- `backup_codes`: `backup_code.upper().strip()`, what a backup code is checked as.
"""
import base64
import hashlib
import json
import sys

import cryptography
import pyotp
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken

KEY = base64.urlsafe_b64encode(bytes(range(32))).decode()
JWT_SECRET = "unit-test-secret"
DERIVED = base64.urlsafe_b64encode(hashlib.sha256(JWT_SECRET.encode()).digest()).decode()

fernet = Fernet(KEY)
tokens = []
for i, plaintext in enumerate(["JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "", "x" * 16, "ä€"]):
    iv = bytes([i] * 16)
    token = fernet._encrypt_from_parts(plaintext.encode(), 1_700_000_000 + i, iv).decode()
    tokens.append({"plaintext": plaintext, "time": 1_700_000_000 + i, "iv": iv.hex(), "token": token})

derived_token = Fernet(DERIVED)._encrypt_from_parts(b"SECRET", 1_700_000_000, bytes(16)).decode()

good = tokens[0]["token"]
raw = bytearray(base64.urlsafe_b64decode(good))
tampered_mac = raw[:]
tampered_mac[-1] ^= 1
tampered_body = raw[:]
tampered_body[30] ^= 1
bad_version = raw[:]
bad_version[0] = 0x81
invalid = [
    base64.urlsafe_b64encode(bytes(tampered_mac)).decode(),
    base64.urlsafe_b64encode(bytes(tampered_body)).decode(),
    base64.urlsafe_b64encode(bytes(bad_version)).decode(),
    good[:-4],
    "",
    "not a token",
    Fernet(DERIVED)._encrypt_from_parts(b"other key", 1_700_000_000, bytes(16)).decode(),
]
for token in invalid:
    try:
        fernet.decrypt(token)
        raise SystemExit(f"expected InvalidToken for {token!r}")
    except InvalidToken:
        pass

SECRETS = ["JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "jbswy3dpehpk3pxp", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"]
TIMES = [59, 1_111_111_109, 1_234_567_890, 2_000_000_000, 20_000_000_000]
codes = []
for secret in SECRETS:
    totp = pyotp.TOTP(secret)
    for t in TIMES:
        codes.append({"secret": secret, "counter": t // 30, "code": totp.generate_otp(t // 30)})

secret = SECRETS[0]
totp = pyotp.TOTP(secret)
now = 1_700_000_015
counter = now // 30
current = totp.generate_otp(counter)
fullwidth = "".join(chr(ord(c) - ord("0") + 0xFF10) for c in current)
verify = []
for code in [
    current,
    totp.generate_otp(counter - 1),
    totp.generate_otp(counter + 1),
    totp.generate_otp(counter - 2),
    totp.generate_otp(counter + 2),
    fullwidth,
    " " + current,
    current[:-1],
    current + "0",
    "",
    "abcdef",
]:
    import datetime

    for_time = datetime.datetime.fromtimestamp(now)
    verify.append({"code": code, "valid": totp.verify(code, for_time=for_time, valid_window=1)})

uris = []
for name in ["alice", "a b", "ä@x.com", "x/y", "a:b", "a+b&c=d", "~_.-", "O'Brien#1"]:
    uris.append({"name": name, "uri": pyotp.TOTP(secret).provisioning_uri(name=name, issuer_name="CoPilot")})

backup = []
for code in ["abcd123456", "  ABcd ", "straße", "\x1cX\x1f", "ﬁx", " q　", "ǆ"]:
    backup.append({"input": code, "normalized": code.upper().strip()})

doc = {
    "cryptography": cryptography.__version__,
    "pyotp": pyotp.__version__ if hasattr(pyotp, "__version__") else "2.9.0",
    "fernet": {
        "key": KEY,
        "tokens": tokens,
        "jwt_secret": JWT_SECRET,
        "derived_key": DERIVED,
        "derived_token": derived_token,
        "invalid": invalid,
    },
    "totp": {"codes": codes, "verify_secret": secret, "verify_now": now, "verify": verify, "uris": uris},
    "backup_codes": backup,
}
json.dump(doc, sys.stdout, indent=1, ensure_ascii=False)
sys.stdout.write("\n")
