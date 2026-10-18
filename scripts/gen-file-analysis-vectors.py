"""Regenerate the vectors that pin the File Analysis port (`copilot-file-analysis`) to the
Python module it ports (`app/file_analysis/`).

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-file-analysis-vectors.py

Writes `crates/copilot-file-analysis/src/file_analysis_vectors.json`. Every input is stored
as the JSON text `json.loads` reads (NaN and big ints included), every outcome as the value
(as the JSON text `json.dumps(…, ensure_ascii=False)` writes) or the exception (class and
`str()`):

* `signature_names` — `is_noise_signature` / `is_low_confidence_signature` on every name of
  both sets and on odd values (the two sets are pinned through them);
* `sandboxes` — per synthetic CAPE summary (noise only, low-confidence only, a config
  family, C2, a meaningful signature at severity 4, odd types): `meaningful_signatures`,
  `noise_stats`, `dynamic_evidence`, `dynamic_verdict_from_report`;
* `merge_verdict`, `verdict_from_reputation` (threshold 5), the orchestrator's
  `_merge_verdict` and `explain_verdict` over static verdicts, the sandboxes, reputations and
  inspector answers (`analysis_incomplete` included), as rows of input indexes (a sandbox
  index of -1 is `None`);
* `summarize` — `cape.summarize(report).to_dict()` over synthetic reports;
* `parse_report` — `_parse_report(FileReportResponse(data=…))` and `extract_intel` —
  `_extract_intel(attrs, behaviour)`;
* `history_item`, `should_escalate`, `report_file_name`;
* `report` — `build_context(result, generated_at, screenshots)` and the HTML
  `render_html_template` writes for it (the sandboxed, autoescaping Jinja2 environment);
* `mimetypes` — `mimetypes.MimeTypes().guess_type(name)[0]` (the module's built-in table, no
  host file), what httpx's multipart encoder puts in a file part's `Content-Type`.

Re-run after a change to the module or a Pydantic, Jinja2 or Python upgrade.
"""

import json
import mimetypes
import os
import pathlib

from jinja2 import FileSystemLoader
from jinja2 import select_autoescape
from jinja2.sandbox import SandboxedEnvironment

from app.file_analysis.services import orchestrator
from app.file_analysis.services import report_pdf
from app.file_analysis.services import reputation
from app.file_analysis.services import state_store
from app.file_analysis.services import verdict
from app.file_analysis.services.sandbox import cape
from app.threat_intel.schema.virustotal import FileReportResponse

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "crates" / "copilot-file-analysis" / "src" / "file_analysis_vectors.json"
TEMPLATE = ROOT / "backend" / "app" / "file_analysis" / "templates" / "report.html"


def text(value):
    return json.dumps(value, ensure_ascii=False)


def outcome(fn, *args):
    try:
        return {"ok": text(fn(*args))}
    except Exception as e:  # noqa: BLE001 - the exception is the vector
        return {"error": {"class": type(e).__name__, "text": str(e)}}


ODD_NAMES = [None, "", 5, 1.5, True, ["x"], {"a": 1}, "Process injection", "deletes_shadow_copies"]

NAMES = sorted(verdict.ENVIRONMENTAL_NOISE_SIGNATURES) + sorted(verdict.LOW_CONFIDENCE_SIGNATURES) + ODD_NAMES

NOISE = sorted(verdict.ENVIRONMENTAL_NOISE_SIGNATURES)
LOW = sorted(verdict.LOW_CONFIDENCE_SIGNATURES)

SANDBOXES = [
    {},
    {"malscore": 10.0, "signatures": [{"name": n, "severity": 3} for n in NOISE[:6]]},
    {"malscore": 8, "signatures": [{"name": n, "severity": 2} for n in LOW[:5]] + [{"name": NOISE[0], "severity": 1}]},
    {"malscore": 9.4, "family": "RedLine", "c2_ips": ["45.10.20.30"], "c2_domains": ["evil.example.com"], "signatures": []},
    {"malscore": 0, "c2_domains": ["evil.example.com"]},
    {"malscore": 3.5, "signatures": [{"name": "deletes_shadow_copies", "severity": 4}]},
    {"malscore": 3.5, "signatures": [{"name": NOISE[1], "severity": 5}, {"name": LOW[1], "severity": 6}]},
    {"malscore": "2.5", "signatures": [{"name": "powershell_command_suspicious", "severity": 2}, {"name": NOISE[2]}]},
    {"malscore": "abc", "signatures": "abc"},
    {"malscore": None, "signatures": [{"name": "a", "severity": "5"}, {"name": "b", "severity": "x"}]},
    {"malscore": 1e100, "signatures": [{"name": "a", "severity": 4.7}, {"name": "b", "severity": True}, {"name": "c", "severity": None}]},
    {"malscore": [1], "signatures": [{"name": "a", "severity": []}, {"name": "b", "severity": [1]}, "not a dict", 5]},
    {"malfamily": "Emotet", "c2_ips": "1.2.3.4"},
    {"family": "", "malfamily": "", "c2_ips": [], "c2_domains": None, "signatures": [{"severity": 9}]},
    {"signatures": [{"name": None, "severity": 4}, {"name": 5, "severity": 4}]},
    {"signatures": [{"name": ["x"], "severity": 1}]},
    {"malscore": float("nan"), "signatures": [{"name": "x", "severity": 1}]},
    {"malscore": float("inf"), "signatures": [{"name": NOISE[3], "severity": 1}]},
    {"malscore": 123456789.0, "signatures": [{"name": LOW[2], "severity": 1}]},
    {"malscore": 0.000012345, "signatures": [{"name": NOISE[4], "severity": 1}]},
    {"malscore": 12345678901234567890, "signatures": [{"name": "real", "severity": 3}]},
    {"malscore": -2, "signatures": [{"name": NOISE[0]}]},
    ["not", "a", "dict"],
]

REPUTATIONS = [
    None,
    {},
    {"found": True, "malicious": 10, "suspicious": 0, "total": 70},
    {"found": True, "malicious": 0, "suspicious": 0, "total": 72},
    {"found": True, "malicious": 2, "suspicious": 0, "total": 0},
    {"found": True, "malicious": 0, "suspicious": 3},
    {"found": True, "malicious": "7", "total": "70"},
    {"found": True, "malicious": None, "total": None},
    {"found": True, "malicious": 4.9},
    {"found": True, "malicious": "x"},
    {"found": False, "submitted": True},
    {"found": 0, "submitted": 0},
    {"found": True, "malicious": True, "suspicious": False, "total": 1},
    ["odd"],
]

INSPECTORS = [
    None,
    {},
    {"analysis_incomplete": True, "error": "inspector unreachable: All connection attempts failed."},
    {"analysis_incomplete": True, "error": None},
    {"analysis_incomplete": True, "error": "  padded..  "},
    {"analysis_incomplete": False, "error": "ignored"},
    {"analysis_incomplete": 1, "error": 5},
]

STATICS = ["clean", "suspicious", "malicious", "", "bogus", None]


def merge_all(static, sandbox, rep):
    return orchestrator._merge_verdict(static, sandbox, rep)


REPORTS = [
    {},
    {
        "info": {"id": 42, "duration": 267, "package": "ps1", "machine": {"name": "capewin", "platform": "windows"}},
        "malscore": 9.4,
        "CAPE": {
            "configs": [
                {"RedLine": {"c2": ["45.10.20.30:443", "http://evil.example.com/gate.php"], "cnc": "1.2.3.4", "address": [None, 5, "x.y"]}},
                "not a dict",
            ],
            "payloads": [{"name": "p.bin", "sha256": "ab" * 32, "cape_type": "RedLine Payload"}, {"name": "q", "type": "raw"}, "skip"],
        },
        "signatures": [
            {"name": "Process injection", "severity": 3, "description": "Injects", "ttp": [{"attack_id": "T1055"}, "T1056"]},
            {"name": "Registry Run key persistence", "mitre": ["T1547.001"]},
            {"name": NOISE[0], "severity": 2},
            {"name": LOW[0], "severity": 2},
        ],
        "network": {
            "hosts": [{"ip": "45.10.20.30"}, "8.8.8.8", {"ip": ""}, {"ip": "45.10.20.30"}, None],
            "domains": [{"domain": "evil.example.com"}, "telemetry.microsoft.com", {"domain": None}],
            "dns": [
                {"request": "evil.example.com", "type": "A", "answers": [{"data": "45.10.20.30"}, "1.1.1.1"]},
                "skip",
                {"answers": None},
            ],
            "http": [{"method": "POST", "host": "evil.example.com", "uri": "/gate.php"}, {"path": "/p"}, 5],
            "tcp": [{"dst": "45.10.20.30", "dport": 443}, {"dst": ""}, {"dport": 1}],
            "udp": [{"dst": "8.8.8.8", "dport": 53}, "x"],
            "dead_hosts": [["10.0.0.1", 80], ["10.0.0.2"], [], "10.0.0.3:22", None, 0, ("a", "b", "c")],
        },
        "behavior": {
            "processes": [
                {"process_name": "powershell.exe", "process_id": 100, "parent_id": 4, "command_line": "powershell -c x"},
                {"name": "cmd.exe", "pid": 7, "ppid": 100, "environ": {"CommandLine": "cmd /c y"}},
                {"process_id": None, "pid": 9, "parent_id": 0, "environ": "not a dict"},
                "skip",
            ],
            "summary": {
                "files": ["C:\\a.txt", 5, None],
                "keys": ["HKLM\\Software\\x"],
                "mutexes": [],
                "executed_commands": ["cmd /c y"],
                "resolved_apis": ["kernel32.dll.CreateFileW"] * 3,
            },
            "enhanced": [{"event": "write", "object": "file", "data": {"file": "C:\\a.txt"}}, "skip", {"event": "load"}],
        },
        "ttps": [{"ttp": "T1055", "signature": "injection"}, {"id": "T1059", "name": "cmd"}, {"signature": "none"}, "skip"],
        "dropped": [{"sha256": "cd" * 32, "name": "drop.exe", "type": "PE32"}, {}],
        "screenshots": [{"path": "shots/0001.jpg"}, "shots/0002.jpg"],
        "debug": {"errors": ["Monitor injection attempted but failed for process 1", "", None, 5]},
    },
    {
        "info": {"id": "7", "score": "3.5", "machine": "not a dict", "duration": "12"},
        "malfamily": "Emotet",
        "CAPE": [],
        "signatures": None,
        "network": None,
        "behavior": None,
    },
    {
        "info": None,
        "malscore": "abc",
        "CAPE": {"configs": [{"Fam": "not a dict"}, {"Other": {"c2_list": ["2.2.2.2"]}}]},
        "signatures": [{"name": "x", "ttp": None, "mitre": None}],
    },
    {
        "info": {"machine": {"label": "cape1", "platform": ""}, "package": None},
        "malscore": 0,
        "signatures": [{"name": LOW[3], "severity": 1}],
    },
    {"info": {"id": 1}, "malscore": None, "network": {"hosts": "abc"}, "behavior": {"summary": {"read_files": "xyz"}}},
    {"info": {"id": 1, "duration": None}, "network": {"dns": [{"request": "a", "answers": "abc"}]}},
    {"info": {"machine": {"name": "m"}, "duration": 1.9}, "signatures": [{"name": "s", "severity": 5, "ttp": [{"no_id": 1}]}]},
    {"malscore": True, "dropped": "x"},
    {"malscore": 5, "signatures": ["not a dict"]},
    {"info": {"duration": "x"}},
    {"behavior": {"summary": {"files": [str(i) for i in range(2005)]}, "enhanced": [{"event": str(i)} for i in range(3)]}},
]


def summarize(report):
    return cape.summarize(report).to_dict()


VT_ANSWERS = [
    {
        "data": {
            "id": "a" * 64,
            "type": "file",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 10,
                    "suspicious": 1,
                    "undetected": 55,
                    "harmless": 0,
                    "timeout": 2,
                    "type-unsupported": 3,
                    "failure": 0,
                },
                "popular_threat_classification": {"suggested_threat_label": "trojan.redline/stealer"},
                "meaningful_name": "evil.exe",
            },
        },
    },
    {"data": {"id": "b" * 64, "type": "file", "attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 70}}}},
    {"data": {"id": "c" * 64, "type": "file", "attributes": {}}},
    {
        "data": {
            "id": "d" * 64,
            "type": "file",
            "attributes": {"last_analysis_stats": {"malicious": None}, "popular_threat_classification": "x"},
        },
    },
]


def parse_report(answer):
    model = FileReportResponse(data=answer["data"], success=True, message="File report retrieved successfully")
    return reputation._parse_report(model, "f" * 64)


INTEL_CASES = [
    ({}, {}),
    (None, None),
    (
        {
            "type_description": "Win32 EXE",
            "type_tag": "peexe",
            "size": 12345,
            "names": ["a.exe", "b.exe", "a.exe", "", None],
            "tags": ["peexe", "signed"],
            "first_submission_date": 1700000000,
            "last_analysis_date": "1700000100",
            "times_submitted": 3,
            "reputation": -5,
            "signature_info": {"product": "Prod", "signers": "X; Y", "verified": "Signed"},
            "popular_threat_classification": {
                "suggested_threat_label": "trojan.redline/stealer",
                "popular_threat_category": [{"value": "trojan", "count": 20}, {"value": "stealer", "count": 5}, "skip"],
                "popular_threat_name": [{"value": "redline", "count": 30}],
            },
            "last_analysis_results": {
                "EngineB": {"category": "malicious", "result": "Trojan.X", "engine_name": "EngineB"},
                "engineA": {"category": "malicious", "result": "Trojan.Y"},
                "EngineC": {"category": "suspicious", "result": "Heur"},
                "EngineD": {"category": "undetected", "result": None},
                "EngineE": "not a dict",
            },
            "crowdsourced_yara_results": [
                {"rule_name": "RULE_A", "ruleset_name": "set", "author": "me", "description": "d", "source": "s"},
                "skip",
            ],
            "sigma_analysis_results": [{"rule_title": "Sigma A", "rule_level": "high", "rule_description": "x", "rule_source": "src"}],
            "crowdsourced_ids_results": [{"rule_msg": "ET TROJAN", "alert_severity": "high", "rule_category": "trojan"}],
            "sandbox_verdicts": {
                "Zenbox": {
                    "category": "malicious",
                    "malware_classification": ["MALWARE"],
                    "malware_names": ["Redline"],
                    "sandbox_name": "Zenbox",
                },
            },
        },
        {
            "mitre_attack_techniques": [
                {"id": "T1055", "signature_description": "inject", "severity": "IMPACT_SEVERITY_HIGH"},
                {"id": "T1055"},
                "skip",
            ],
            "ip_traffic": [{"destination_ip": "1.2.3.4", "destination_port": 443, "transport_layer_protocol": "TCP"}],
            "dns_lookups": [{"hostname": "evil.example.com", "resolved_ips": ["1.2.3.4"]}, "plain.example"],
            "http_conversations": [{"url": "http://evil.example.com/gate.php", "request_method": "POST"}],
            "files_dropped": [{"path": "C:\\a.exe", "sha256": "e" * 64}],
            "processes_created": ["cmd.exe /c y", {"name": "x"}],
            "command_executions": ["cmd /c y", "cmd /c y"],
            "registry_keys_set": [{"key": "HKLM\\x", "value": "1"}],
            "mutexes_created": ["m1"],
            "tags": ["DETECT_DEBUG_ENVIRONMENT"],
            "verdicts": ["MALWARE"],
        },
    ),
    (
        {"names": "abc", "tags": None, "last_analysis_results": [], "first_submission_date": "x"},
        {"mitre_attack_techniques": "x", "dns_lookups": None},
    ),
    (
        {"popular_threat_classification": "x", "signature_info": "y", "sandbox_verdicts": ["z"]},
        {"ip_traffic": [None, 5, {"destination_ip": None}]},
    ),
]


def extract_intel(attrs, behaviour):
    return reputation._extract_intel(attrs, behaviour)


RESULTS = [
    {
        "job": {
            "job_id": "0123456789abcdef0123456789abcdef",
            "filename": "evil.ps1",
            "sha256": "a" * 64,
            "customer_code": "00001",
            "source": "upload",
            "status": "done",
            "verdict": "malicious",
            "hardened": False,
            "sandbox_enabled": True,
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:01:00.123456+00:00",
        },
        "inspector": {
            "filename": "evil.ps1",
            "filetype": "script",
            "sha256": "a" * 64,
            "size": 1234,
            "verdict_hint": "malicious",
            "hashes": {"md5": "m" * 32, "sha1": "s" * 40, "sha256": "a" * 64},
            "flags": ["FLAG_MALICIOUS_BEHAVIOR", "<script>"],
            "iocs": {"urls": ["http://evil.example.com/<x>"], "ips": ["1.2.3.4"], "domains": ["evil.example.com"]},
            "content": {
                "behaviors": [
                    {
                        "attack_id": "T1490",
                        "technique": "Inhibit System Recovery",
                        "severity": "malicious",
                        "evidence": "vssadmin delete shadows",
                    },
                ],
                "deobfuscated": ["layer 1 & <b>", "x" * 7000],
                "strings": ["s" + str(i) for i in range(130)],
            },
            "metadata": {"entropy": 4.5, "lines": 10},
        },
        "sandbox": {
            "task_id": 6,
            "malscore": 9.4,
            "family": "RedLine",
            "machine": "capewin (windows)",
            "duration": 267,
            "verdict": "malicious",
            "signatures": [
                {
                    "name": "deletes_shadow_copies",
                    "severity": 4,
                    "description": "d",
                    "noise": False,
                    "low_confidence": False,
                    "mitre": ["T1490"],
                },
                {"name": NOISE[0], "severity": 2, "noise": True, "low_confidence": False},
                {"name": LOW[0], "severity": 1, "noise": False, "low_confidence": True},
                {"name": "x"},
            ],
            "processes": [{"name": "powershell.exe", "pid": 100, "ppid": 4, "command_line": "powershell -c x"}],
            "connections": [
                {"proto": "TCP", "dst": "1.2.3.4", "dport": 443},
                {"proto": "tcp", "dst": "1.2.3.4", "dport": 443},
                {"proto": None, "dst": None, "dport": None},
            ],
            "hosts": ["1.2.3.4"],
            "domains": ["evil.example.com"],
            "dns": [{"request": "evil.example.com", "type": "A", "answers": ["1.2.3.4"]}],
            "http": [{"method": "POST", "host": "evil.example.com", "uri": "/gate.php"}],
            "ttps": [{"id": "T1055", "signature": "injection"}],
            "c2_ips": ["45.10.20.30"],
            "c2_domains": [],
            "dropped": [{"sha256": "c" * 64, "name": "drop.exe", "type": "PE32"}],
            "payloads": [],
            "errors": ["boom"],
            "behavior": {"files": ["C:\\a.txt"]},
            "dead_hosts": ["10.0.0.1:80"],
        },
        "reputation": {
            "source": "virustotal",
            "found": True,
            "malicious": 10,
            "suspicious": 1,
            "total": 70,
            "family": "trojan.redline",
            "permalink": "https://www.virustotal.com/gui/file/" + "a" * 64,
            "intel": {
                "threat_label": "trojan.redline",
                "detections": [{"engine": "A", "result": "Trojan"}],
                "yara": [],
                "sigma": [{"title": "S"}],
            },
        },
        "preview_urls": [],
        "engine_version": 15,
        "verdict_reason": "static inspection: malicious; sandbox: malware config extracted (RedLine)",
    },
    {
        "job": {"job_id": "j2", "customer_code": "00002", "sha256": "b" * 64, "verdict": None},
        "inspector": {"verdict_hint": "suspicious", "analysis_incomplete": True, "error": "down"},
    },
    {
        "job": {"job_id": "j3", "customer_code": "00002"},
        "inspector": {},
        "sandbox": None,
        "reputation": {"found": False, "submitted": True, "note": "pending"},
    },
    {"job": None, "inspector": None},
    {
        "job": {"job_id": "j4", "customer_code": "00001"},
        "sandbox": {"signatures": [{"name": "x", "severity": "3"}, {"name": "y", "severity": 1}]},
    },
    {"job": {"verdict": "bogus"}, "inspector": {"sha256": "short", "hashes": None, "iocs": "x"}},
]

SCREENSHOTS = [[], [b"\xff\xd8\xff\xe0jpeg-bytes", b"", b"second"], None]


def build_context(result, shots):
    return report_pdf.build_context(result, generated_at="2026-01-02 03:04:05 UTC", screenshots=shots)


def render(context):
    env = SandboxedEnvironment(
        loader=FileSystemLoader(str(TEMPLATE.parent)),
        autoescape=select_autoescape(["html", "htm", "xml"], default=True),
    )
    return env.get_template(TEMPLATE.name).render(context)


def file_name(result):
    sha = (result.get("inspector") or {}).get("sha256") or (result.get("job") or {}).get("sha256") or "report"
    return f"file-analysis-{sha[:12]}.pdf"


ESCALATE = [
    {},
    {"filetype": "pe"},
    {"filetype": "script"},
    {"filetype": "image"},
    {"filetype": "text", "flags": ["FLAG_MALICIOUS_BEHAVIOR"]},
    {"filetype": "text", "flags": ["nothing"]},
    {"filetype": "image", "verdict_hint": "suspicious"},
    {"filetype": "image", "verdict_hint": "malicious"},
    {"filetype": None, "flags": None},
    {"filetype": "office", "analysis_incomplete": True},
    {"filetype": ["x"]},
    {"flags": "FLAG_HTML_SMUGGLING"},
]

MIME_NAMES = [
    "sample",
    "evil.ps1",
    "a.EXE",
    "doc.docx",
    "x.pdf",
    "x.tar.gz",
    "x.tgz",
    "x.svgz",
    "photo.JPG",
    "a.b.c.js",
    "noext.",
    ".bashrc",
    "dir/file.html",
    "C:\\Users\\x\\a.txt",
    "a.bat",
    "a.vbs",
    "x.zip",
    "x.7z",
    "x.msi",
    "x.lnk",
    "x.hta",
    "data:text/plain,hello",
    "data:,x",
    "http://example.com/a.png",
    "x.json",
    "x.xml",
    "x.csv",
    "x.mp4",
    "Ünï.txt",
    "x.bz2",
    "x.tar.xz",
]


def main():
    builtin = mimetypes.MimeTypes()
    vectors = {
        "engine_version": state_store.ENGINE_VERSION,
        "signature_names": [
            {"name": text(n), "noise": outcome(verdict.is_noise_signature, n), "low": outcome(verdict.is_low_confidence_signature, n)}
            for n in NAMES
        ],
        "sandboxes": [
            {
                "sandbox": text(s),
                "meaningful": outcome(verdict.meaningful_signatures, s),
                "stats": outcome(verdict.noise_stats, s),
                "evidence": outcome(verdict.dynamic_evidence, s),
                "verdict": outcome(verdict.dynamic_verdict_from_report, s),
            }
            for s in SANDBOXES
        ],
        "merge_verdict": [{"a": text(a), "b": text(b), "out": outcome(verdict.merge_verdict, a, b)} for a in STATICS for b in STATICS],
        "verdict_from_reputation": [{"rep": text(r), "out": outcome(reputation.verdict_from_reputation, r)} for r in REPUTATIONS],
        # The two cross products refer to the inputs by index.
        "statics": [text(st) for st in STATICS],
        "reputations": [text(r) for r in REPUTATIONS],
        "inspectors": [text(i) for i in INSPECTORS],
        "merge_all": [
            [i, j, k, outcome(merge_all, STATICS[i], SANDBOXES[j], REPUTATIONS[k])]
            for i in range(3)
            for j in range(i, len(SANDBOXES), 3)
            for k in range(len(REPUTATIONS))
        ],
        "explain": [
            [i, j, k, m, outcome(verdict.explain_verdict, STATICS[i], SANDBOXES[j] if j >= 0 else None, REPUTATIONS[k], INSPECTORS[m])]
            for i, j, k, m in [(i, -1, 0, m) for i in range(len(STATICS)) for m in range(len(INSPECTORS))]
            + [
                ((j + k) % len(STATICS), j, k, (3 * j + k) % len(INSPECTORS))
                for j in range(len(SANDBOXES))
                for k in range(len(REPUTATIONS))
            ]
        ],
        "summarize": [{"report": text(r), "out": outcome(summarize, r)} for r in REPORTS],
        "parse_report": [{"answer": text(a), "out": outcome(parse_report, a)} for a in VT_ANSWERS],
        "extract_intel": [{"attrs": text(a), "behaviour": text(b), "out": outcome(extract_intel, a, b)} for a, b in INTEL_CASES],
        "history_item": [{"result": text(r), "out": outcome(state_store._history_item, r)} for r in RESULTS],
        "should_escalate": [{"inspector": text(i), "out": outcome(orchestrator._should_escalate, i, "upload")} for i in ESCALATE],
        "report_file_name": [{"result": text(r), "out": outcome(file_name, r)} for r in RESULTS],
        "report": [],
        "mimetypes": [{"name": n, "type": builtin.guess_type(n)[0]} for n in MIME_NAMES],
    }
    for n, r in enumerate(RESULTS):
        for shots in SCREENSHOTS if n == 0 else [None]:
            ctx = outcome(build_context, r, shots)
            entry = {"result": text(r), "screenshots": [s.hex() for s in shots] if shots is not None else None, "context": ctx}
            if "ok" in ctx:
                entry["html"] = outcome(render, build_context(r, shots))
            vectors["report"].append(entry)
    OUT.write_text(json.dumps(vectors, ensure_ascii=False, indent=1) + "\n")
    print(f"wrote {OUT} ({os.path.getsize(OUT)} bytes)")


if __name__ == "__main__":
    main()
