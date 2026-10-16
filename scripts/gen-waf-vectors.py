"""Regenerate the vectors that pin the pure parts of the customer WAF port (`copilot-waf`) to the
Python module it ports (`app/customer_waf/`).

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-waf-vectors.py

Writes `crates/copilot-waf/src/waf_vectors.json`:

* `targets` — `blocks.normalize_target` on probe inputs (CPython's `ipaddress.ip_network(...,
  strict=False)` underneath): the canonical network, `display()`, the prefix check, and
  `target_warnings()`, or the `BlockTargetError` text;
* `rules` — `rule_networks()`, `is_copilot_rule()` and `to_block()` on WAF custom rules, and the
  `_covers` / `_exact` matrix of every rule against every accepted target;
* `rule_texts`, `descriptions` — the SecLang a block creates and the rule description;
* `roles` — `capabilities_for_roles()` and `summarize_roles()`;
* `api_urls`, `tokens`, `keys` — `normalize_api_url()`, `normalize_token()` /
  `display_prefix()`, and which `WAF_TOKEN_ENCRYPTION_KEY` values are usable;
* `times` — `_utc_iso()` of a value FastAPI parsed as a `datetime` query parameter;
* `port_ranges` — `forwarding.port_range()` for `WAF_SYSLOG_PORT_RANGE` values;
* `pems` — `services.customer_waf._clean_ca_cert()` (`ssl.create_default_context(cadata=…)`) on
  CA uploads: a certificate made here, cut, repeated, wrapped in text, followed by junk.

Re-run after a Python upgrade (the `ipaddress` tables) or a change to these functions.
"""

import json
import os
import pathlib
from datetime import datetime

from pydantic import TypeAdapter

from app.customer_waf.services import blocks
from app.customer_waf.services import crypto
from app.customer_waf.services import forwarding
from app.customer_waf.services.customer_waf import _utc_iso
from app.customer_waf.services.customer_waf import capabilities_for_roles
from app.customer_waf.services.customer_waf import summarize_roles
from app.customer_waf.utils.universal import normalize_api_url

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-waf" / "src" / "waf_vectors.json"

TARGETS = [
    "203.0.113.7",
    " 203.0.113.7 ",
    "203.0.113.7/32",
    "203.0.113.0/24",
    "203.0.113.7/24",
    "203.0.113.7/255.255.255.0",
    "203.0.113.7/0.0.0.255",
    "203.0.113.7/024",
    "198.51.100.0/16",
    "198.51.100.0/15",
    "10.0.0.0/8",
    "10.1.2.3",
    "127.0.0.1",
    "0.0.0.0",
    "0.0.0.0/16",
    "169.254.1.1",
    "224.0.0.1",
    "240.0.0.1",
    "255.255.255.255",
    "100.64.0.1",
    "192.0.0.9",
    "192.0.0.10",
    "192.0.0.11",
    "8.8.8.8",
    "01.2.3.4",
    "1.2.3",
    "1.2.3.4.5",
    "256.1.1.1",
    "1.2.3.4/33",
    "1.2.3.4/",
    "1.2.3.4/a",
    "1.2.3.4/255.0.255.0",
    "1.2.3.4/1/2",
    "１.2.3.4",
    "",
    "   ",
    "not-an-ip",
    "2001:db8::1",
    "2001:db8::/48",
    "2001:db8::/47",
    "2001:db8:0:0:0:0:0:1",
    "2001:DB8::abcd",
    "2001:db8::1/64",
    "::1",
    "::",
    "::/48",
    "fe80::1",
    "ff02::1",
    "fc00::1",
    "2606:4700::1111",
    "::ffff:1.2.3.4",
    "::ffff:10.0.0.1",
    "::ffff:127.0.0.1",
    "::ffff:0.0.0.0",
    "::ffff:8.8.8.8",
    "::ffff:0:0/96",
    "64:ff9b::8.8.8.8",
    "1:0:0:2:0:0:0:3",
    "1:0:0:2:0:0:3:4",
    "0:0:1:0:0:0:0:0",
    "1::2::3",
    ":1:2:3:4:5:6:7",
    "1:2:3:4:5:6:7:",
    "1:2:3:4:5:6:7:8:9",
    "12345::1",
    "g::1",
    "2001:db8::1/129",
    "2001:db8::1/ 64",
    "2001:db8::1/255.255.255.0",
    "1:2:3:4:5:6:1.2.3.4",
    "1:2:3:4:5:6:7:1.2.3.4",
    "::1.2.3.4",
    "2001:0db8:0000:0000:0000:0000:0000:0001/128",
    "2001:db8::1%eth0",
    "fe80::1%eth0/64",
]

RULES = [
    {
        "id": "u1",
        "rule_id": 1001,
        "name": "CoPilot block: 203.0.113.7",
        "description": "x",
        "is_enabled": True,
        "field": "REMOTE_ADDR",
        "operator": "@ipMatch",
        "value": "203.0.113.7",
        "conf_text": "SecRule REMOTE_ADDR \"@ipMatch 203.0.113.7\" \"id:1001,phase:1,deny,status:403,log,msg:'CoPilot block: 203.0.113.7',tag:'copilot-block'\"",
        "created_at": "2026-01-02T03:04:05Z",
    },
    {
        "id": "u2",
        "rule_id": 1002,
        "name": "TI block",
        "description": None,
        "is_enabled": True,
        "field": "remote_addr",
        "operator": "@ipMatch",
        "value": "198.51.100.0/24, 192.0.2.5 2001:db8::/48",
        "conf_text": 'SecRule REMOTE_ADDR "@ipMatch 198.51.100.0/24,192.0.2.5" "id:1002,phase:1,deny,status:403"',
    },
    {
        "id": "u3",
        "rule_id": 1003,
        "name": "bypass",
        "is_enabled": True,
        "field": "REMOTE_ADDR",
        "operator": "@ipMatch",
        "value": "10.0.0.1",
        "action": "deny,status:403",
        "conf_text": 'SecRule REMOTE_ADDR "@ipMatch 10.0.0.1" "id:1003,phase:1,pass,ctl:ruleEngine=Off"',
    },
    {
        "id": "u4",
        "rule_id": "1004",
        "name": "chained",
        "is_enabled": True,
        "field": "REMOTE_ADDR",
        "operator": "@ipMatch",
        "value": "10.0.0.2",
        "conf_text": 'SecRule REMOTE_ADDR "@ipMatch 10.0.0.2" "id:1004,phase:1,deny,chain"',
    },
    {
        "id": "u5",
        "rule_id": 1005,
        "name": "CoPilot block: 203.0.113.0/24",
        "is_enabled": False,
        "field": "REMOTE_ADDR",
        "operator": "@ipMatch",
        "value": "203.0.113.0/24",
        "conf_text": 'SecRule REMOTE_ADDR "@ipMatch 203.0.113.0/24" "id:1005,deny"',
    },
    {
        "id": 6,
        "rule_id": 1006,
        "name": None,
        "is_enabled": 1,
        "field": "REMOTE_ADDR",
        "operator": "@ipMatch",
        "value": ",,bogus  fe80::1%eth0 2001:db8:1::/48",
        "conf_text": "deny",
    },
    {
        "id": "u7",
        "rule_id": 1007,
        "name": "other",
        "is_enabled": True,
        "field": "ARGS",
        "operator": "@rx",
        "value": "x",
        "conf_text": 'SecRule ARGS "@rx x" "deny"',
    },
    {
        "id": "u8",
        "rule_id": 1008,
        "name": "tagged",
        "is_enabled": True,
        "field": "REMOTE_ADDR",
        "operator": "@ipMatch",
        "value": "",
        "conf_text": 'SecRule REMOTE_ADDR "@ipMatch " "deny,tag:\'copilot-block\'"',
    },
    {"id": "u9", "rule_id": 1009, "is_enabled": True, "field": None, "operator": None, "value": None, "conf_text": None},
    {
        "id": "u10",
        "rule_id": 1010,
        "name": "big",
        "is_enabled": True,
        "field": "REMOTE_ADDR",
        "operator": "@ipMatch",
        "value": "203.0.0.0/16 198.51.100.7 ::ffff:1.2.3.4",
        "conf_text": "deny",
    },
]

DESCRIPTIONS = [
    ("  brute force\n from  scanner ", "alice", None, None),
    ("x", "bob", 12, None),
    ("x", "bob", None, 7),
    ("multi\tline reason", "carol", 0, 0),
]

ROLE_SETS = [
    [],
    ["viewer"],
    ["operator"],
    ["admin"],
    ["viewer", "operator"],
    ["unknown"],
    ["admin", "operator", "viewer", "auditor-with-a-very-long-role-name-that-goes-on"],
    ["b", "a"],
]

API_URLS = [
    "https://waf.example.com:8080",
    "https://waf.example.com:8080/",
    "https://waf.example.com:8080/api/v1",
    "https://waf.example.com:8080/api/v1/",
    "https://waf.example.com/prefix/api/v1/api/v1",
    "  http://WAF.example.com  ",
    "HTTPS://Waf.Example.com",
    "ftp://waf.example.com",
    "waf.example.com",
    "https://",
    "https:///path",
    "",
    "https://[::1]:8443",
    "https://[::1",
    "https://[1.2.3.4]/",
    "https://user:pw@waf:8080",
    "https://waf:99999",
    "\thttps://waf\n.example.com",
]

TOKENS = ["wafst_abcdefghijklmnop", "  wafst_x  ", "wafst_", "waf_abc", "eyJhbGciOi", "", "WAFST_abc", "wafst_éééééééé"]

KEYS = [
    None,
    "",
    "   ",
    "REPLACE_ME",
    " REPLACE_ME ",
    "x" * 44,
    "q83vEjmO2YW-bQjzAZp8kYC0Wf7zZcGq2hD2bGy9Xf4=",
    "  q83vEjmO2YW-bQjzAZp8kYC0Wf7zZcGq2hD2bGy9Xf4=  ",
    "q83vEjmO2YW-bQjzAZp8kYC0Wf7zZcGq2hD2bGy9Xf4",
    "q83vEjmO2YW+bQjzAZp8kYC0Wf7zZcGq2hD2bGy9Xf4=",
    "q83vEjmO2YW-bQjzAZp8k!YC0Wf7zZcGq2hD2bGy9Xf4=",
    "c2hvcnQ=",
]

TIMES = [
    "2026-01-02T03:04:05",
    "2026-01-02T03:04:05Z",
    "2026-01-02T03:04:05.123456+02:00",
    "2026-01-02T03:04:05-05:30",
    "2026-01-02",
    "1700000000",
    "1700000000123",
    "2026-01-02 03:04:05.5",
]

PORT_RANGES = [
    None,
    "",
    "5600-5699",
    " 6000-6000 ",
    "6000",
    "a-b",
    "1000-2000",
    "2000-1000",
    "5600-65536",
    "5600 - 5700",
    "5600-5700-5800",
    "+5600-5700",
]


def target_vector(raw):
    try:
        net = blocks.normalize_target(raw)
    except blocks.BlockTargetError as e:
        return {"input": raw, "error": str(e)}
    return {
        "input": raw,
        "network": str(net),
        "display": blocks.display(net),
        "version": net.version,
        "prefixlen": net.prefixlen,
        "warnings": blocks.target_warnings(net),
        "rule_text": blocks.build_rule_text(net),
    }


def rule_vector(rule):
    out = {"rule": rule, "networks": [str(n) for n in blocks.rule_networks(rule)], "is_copilot": blocks.is_copilot_rule(rule)}
    try:
        out["block"] = json.loads(blocks.to_block(rule).model_dump_json())
    except Exception as e:  # noqa: BLE001 - recorded
        out["block_error"] = f"{type(e).__name__}: {e}"
    return out


def key_vector(value):
    if value is None:
        os.environ.pop(crypto.KEY_ENV_VAR, None)
    else:
        os.environ[crypto.KEY_ENV_VAR] = value
    try:
        crypto._fernet()
        return {"value": value, "configured": True}
    except crypto.WafTokenCryptoError as e:
        return {"value": value, "configured": False, "error": type(e).__name__, "message": str(e)}


def pem_vectors():
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from fastapi import HTTPException

    from app.customer_waf.services.customer_waf import _clean_ca_cert

    key = ec.derive_private_key(12345, ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vectors")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(dt.datetime(2020, 1, 1))
        .not_valid_after(dt.datetime(2040, 1, 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    lines = pem.splitlines()
    bad_block = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    cases = {
        "good": pem,
        "padded": "  \n" + pem + "\n  ",
        "two": pem + pem,
        "text before": "issuer: test\n" + pem,
        "text after": pem + "trailing\n",
        "crlf": pem.replace("\n", "\r\n"),
        "no final newline": pem.rstrip("\n"),
        "indented": "\n".join("  " + line for line in lines),
        "truncated": "\n".join(lines[:-3] + lines[-1:]),
        "no end": "\n".join(lines[:-1]),
        "good then bad": pem + bad_block,
        "bad then good": bad_block + pem,
        "bad": bad_block,
        "text": "not a certificate",
        "private key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        "x509 label": pem.replace("BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE").replace("END CERTIFICATE", "END X509 CERTIFICATE"),
        "base64 junk": "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        "not ascii": "\u00e9",
        "blank": "  \n ",
    }
    out = []
    for label, text in cases.items():
        try:
            got = _clean_ca_cert(text)
            out.append({"label": label, "pem": text, "ok": got})
        except HTTPException as e:
            out.append({"label": label, "pem": text, "error": e.detail})
        except Exception as e:  # noqa: BLE001 - recorded
            out.append({"label": label, "pem": text, "raises": type(e).__name__})
    return out


def main():
    targets = [target_vector(t) for t in TARGETS]
    accepted = [blocks.normalize_target(t["input"]) for t in targets if "network" in t]
    rules = [rule_vector(r) for r in RULES]
    matrix = []
    for rule in RULES:
        for net in accepted:
            matrix.append(
                {"rule_id": rule["rule_id"], "target": str(net), "covers": blocks._covers(rule, net), "exact": blocks._exact(rule, net)},
            )
    split = blocks.ip_block_rules(RULES)
    api_urls = []
    for url in API_URLS:
        try:
            api_urls.append({"input": url, "ok": normalize_api_url(url)})
        except ValueError as e:
            api_urls.append({"input": url, "error": str(e)})
    tokens = []
    for t in TOKENS:
        try:
            ok = crypto.normalize_token(t)
            tokens.append({"input": t, "ok": ok, "prefix": crypto.display_prefix(ok)})
        except crypto.WafTokenCryptoError as e:
            tokens.append({"input": t, "error": str(e)})
    saved = os.environ.get(crypto.KEY_ENV_VAR)
    keys = [key_vector(k) for k in KEYS]
    if saved is None:
        os.environ.pop(crypto.KEY_ENV_VAR, None)
    else:
        os.environ[crypto.KEY_ENV_VAR] = saved
    adapter = TypeAdapter(datetime)
    times = [{"input": t, "utc_iso": _utc_iso(adapter.validate_python(t))} for t in TIMES]
    ports = []
    for raw in PORT_RANGES:
        if raw is None:
            os.environ.pop("WAF_SYSLOG_PORT_RANGE", None)
        else:
            os.environ["WAF_SYSLOG_PORT_RANGE"] = raw
        try:
            ports.append({"value": raw, "range": list(forwarding.port_range())})
        except forwarding.ForwardingError as e:
            ports.append({"value": raw, "error": e.detail, "status": e.status_code})
    os.environ.pop("WAF_SYSLOG_PORT_RANGE", None)
    data = {
        "targets": targets,
        "rules": rules,
        "matrix": matrix,
        "split": {"copilot": [r["rule_id"] for r in split[0]], "other": [r["rule_id"] for r in split[1]]},
        "descriptions": [
            {"reason": r, "username": u, "alert_id": a, "case_id": c, "out": blocks.build_description(r, u, a, c)}
            for r, u, a, c in DESCRIPTIONS
        ],
        "roles": [
            {"roles": roles, "capabilities": capabilities_for_roles(roles).model_dump(), "summary": summarize_roles(roles)}
            for roles in ROLE_SETS
        ],
        "api_urls": api_urls,
        "tokens": tokens,
        "keys": keys,
        "times": times,
        "port_ranges": ports,
        "pems": pem_vectors(),
    }
    OUT.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
