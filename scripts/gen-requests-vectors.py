"""Generate `requests` URL-preparation vectors for copilot-wazuh's manager client.

    backend/.venv/bin/python -I scripts/gen-requests-vectors.py \
        > crates/copilot-wazuh/src/requests_vectors.json

Each case is a connector URL plus an endpoint (as the Wazuh manager helpers build
`f"{connector_url}{endpoint}"`, the endpoint carrying already-decoded path parameters)
and the `params` dict's `(name, str(value))` pairs; `prepared` is
`requests.Request(...).prepare().url` after the adapter lookup, absent when requests
raises.
"""
import json
import sys

import requests
import urllib3

bases = [
    "https://wazuh-manager:55000",
    "https://Wazuh-Manager.EXAMPLE.com:55000",
    "HTTPS://10.0.0.5:55000",
    "http://127.0.0.1:5591",
    "https://wazuh:55000/",
    "https://wazuh:55000/api",
    "https://wazuh:0",
    "https://wazuh:00055000",
    "https://[::1]:55000",
    "https://[FE80::1%25eth0]:55000",
    "https://user:p%40ss@wazuh:55000",
    "https://us er@wazuh:55000",
    "  https://wazuh:55000",
    "https://wazuh",
    "https://bücher.example:55000",
    "https://wazuh:99999",
    "https://wazuh:port",
    "wazuh:55000",
    "wazuh-manager",
    "ftp://wazuh:21",
    "https://",
    "https://*.wazuh:55000",
    "httpx://wazuh:55000",
]
endpoints = [
    "/security/user/authenticate",
    "/rules",
    "/rules/files/local_rules.xml",
    "/rules/files/a b.xml",
    "/rules/files/ä€.xml",
    "/rules/files/x?y=1",
    "/rules/files/x#frag",
    "/rules/files/100%",
    "/rules/files/%41%2f%7e%2E",
    "/rules/files/..",
    "/rules/files/./x/../y",
    '/groups/g[1]/files/{c}|^`"<>',
    "/groups/g;x=1/files/a@b:c!$&'()*+,=",
    "rules",
    "",
]
param_sets = [
    [],
    [("pretty", "False"), ("wait_for_complete", "False"), ("offset", "0"), ("limit", "500"), ("distinct", "False")],
    [("search", "a b&c=d/e~f+g%h"), ("q", "level>5;groups=sysmon"), ("select", "id,level")],
    [("raw", "True")],
    [("filename", "ä,€"), ("relative_dirname", "etc/rules")],
]

cases = []
for base in bases:
    for endpoint in endpoints:
        for params in param_sets if endpoint in ("/rules", "/rules/files/x?y=1", "/rules/files/a b.xml") else [[]]:
            url = f"{base}{endpoint}"
            case = {"url": url, "params": [list(p) for p in params]}
            try:
                prepared = requests.Request("GET", url, params=dict(params)).prepare()
                requests.Session().get_adapter(prepared.url)
                case["prepared"] = prepared.url
            except Exception as e:  # noqa: BLE001 - every refusal ends the call alike
                case["error"] = f"{type(e).__name__}: {e}"
            cases.append(case)

json.dump(
    {
        "generated_with": {"requests": requests.__version__, "urllib3": urllib3.__version__, "python": sys.version.split()[0]},
        "prepare_url": cases,
    },
    sys.stdout,
    indent=1,
    ensure_ascii=False,
)
sys.stdout.write("\n")
