"""Regenerate `crates/copilot-case-templates/src/case_templates_vectors.json`.

Pins what `copilot-case-templates` reproduces of the case-template library and the
template suggestions (`app/incidents/services/template_library.py`,
`template_suggestions.py`, the library routes of `routes/case_templates.py`):

* `text`: `_tokenize`, `_extract_mitre_ids`, `_contains_phrase`, `_as_string_list`,
  `_flatten_values`, `_usage_points`;
* `entries`: a YAML document → `_normalize_entry` (after `yaml.safe_load`), the
  library route's `_library_entry_to_response` dump (or its `ValidationError`
  text), and the import's `CaseTemplateCreate` dump (or the first
  `ValidationError` the route raises);
* `scores`: templates scored against signals (`score_template`, `_in_scope`).

Re-run after a change to those modules or a Pydantic / PyYAML / Python upgrade:

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x MYSQL_ROOT_PASSWORD=x \\
        JWT_SECRET=gen-secret-xyz python ../scripts/gen-case-templates-vectors.py
"""

import json
import pathlib

import yaml

from app.incidents.models import CaseTemplate
from app.incidents.models import CaseTemplateTask
from app.incidents.routes.case_templates import _library_entry_to_response
from app.incidents.schema.case_templates import CaseTemplateCreate
from app.incidents.schema.case_templates import CaseTemplateTaskCreate
from app.incidents.services import template_suggestions as ts
from app.incidents.services.template_library import _normalize_entry

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "crates" / "copilot-case-templates" / "src" / "case_templates_vectors.json"

TEXTS = [
    "",
    "Ransomware — host containment",
    "T1059.001 and t1486; T10599 T1059.0011 xT1003 T1003_x (T1566) T1059.0 T١٢٣٤",
    "Kelvin K and İstanbul ÉCOLE straße",
    "foo-bar_baz qux1 2fa",
    "lateral-movement, LateralMovement; lateral_movement|x",
]
PHRASES = [
    ("check the lateral movement of a host", "lateral-movement"),
    ("check the lateral movement of a host", "lateral_movement"),
    ("check the lateralmovement", "LateralMovement"),
    ("ransomware_behaviour detected", "ransomware_behaviour"),
    ("ransomware detected", "ransomware_behaviour"),
    ("a web server", "web"),
    ("an ad host", "ad"),
    ("x lateral   —  movement y", "lateral movement"),
    ("xlateral movement", "lateral movement"),
    ("lateral movementx", "lateral movement"),
    ("lateral é movement", "lateral movement"),
    ("lateral_movement", "lateral movement"),
    ("café lateral movement", "lateral movement"),
    ("ébrute force", "brute force"),
    ("brute force", "brute-force attack"),
    ("t1059 powershell", "T1059"),
]
VALUES = [
    None,
    "a,b;c|d",
    " a , ,;|  ",
    ["x", ["y,z"], None, 3],
    5,
    2.5,
    True,
    {"k": "v"},
    [{"a": 1}, [1.0, False]],
    "",
]


def text_vectors():
    out = []
    for t in TEXTS:
        out.append({"text": t, "tokens": ts._tokenize(t), "mitre": sorted(ts._extract_mitre_ids(t))})
    phrases = []
    for corpus, phrase in PHRASES:
        text = corpus.lower()
        phrases.append({"corpus": corpus, "phrase": phrase, "matches": ts._contains_phrase(set(ts._tokenize(text)), text, phrase)})
    values = []
    for v in VALUES:
        flat = []
        ts._flatten_values(v, flat)
        values.append({"value": v, "strings": ts._as_string_list(v), "flat": flat})
    return {
        "texts": out,
        "phrases": phrases,
        "values": values,
        "usage": [ts._usage_points(n) for n in range(0, 70)],
    }


DOCS = [
    "key: a\nname: A\ntasks: []\n",
    "key: '  spaced  '\nname: '  N  '\ndescription: d\nsource: wazuh\ntags: {mitre: [T1003], 1: x}\n"
    "match: {field: ' data_win_system_eventID ', value: 11}\n"
    "tasks:\n  - {title: ' b ', order_index: 2, mandatory: yes}\n  - {title: a, order_index: 1, description: '', guidelines: g}\n"
    "  - {title: c, order_index: true}\n  - {title: '  ', order_index: 0}\n  - {title: d, order_index: -1}\n  - {title: e, order_index: 1.0}\n"
    "  - not a dict\n  - {title: f}\n",
    "key: k\nname: n\ntags: {when: 2024-01-02, at: 2024-01-02 03:04:05, b: !!binary aGk=, f: .inf}\ntasks:\n  - {title: t, order_index: 0}\n",
    "key: k\nname: n\nmatch: {field: f}\n",
    "key: k\nname: n\nmatch: {field: f, value: null}\n",
    "key: k\nname: n\nmatch: {field: f, value: [1, 'a']}\n",
    "key: k\nname: n\nmatch: {field: f, value: {a: 1.5}}\n",
    "key: k\nname: n\nmatch: {field: f, value: true}\n",
    "key: k\nname: n\nmatch: {field: '', value: x}\n",
    "key: k\nname: n\nmatch: [field, value]\n",
    "key: 1\nname: n\n",
    "key: ''\nname: n\n",
    "key: k\nname: 2\n",
    "key: k\n",
    "key: k\nname: n\ntasks: {a: 1}\n",
    "key: k\nname: n\ntasks: x\n",
    "key: k\nname: n\ntasks: ''\n",
    "key: k\nname: n\ndescription: 5\n",
    "key: k\nname: n\ndescription: [a]\nsource: 7\n",
    "key: k\nname: " + "N" * 256 + "\n",
    "key: k\nname: n\nsource: " + "s" * 51 + "\n",
    "key: k\nname: n\nmatch: {field: " + "f" * 256 + ", value: v}\n",
    "key: k\nname: n\ntasks:\n  - {title: " + "t" * 501 + ", order_index: 0}\n",
    "key: k\nname: n\ntasks:\n  - {title: t, order_index: 0, description: 5, guidelines: [1]}\n  - {title: u, order_index: 1, description: 6}\n",
    "key: k\nname: n\ndescription: 0\nsource: ''\ntags: [a]\n",
    "key: k\nname: n\ntags: {a: {b: [1, 2]}, c: null}\n",
    "key: k\nname: n\ndescription: !!binary aGk=\n",
    "- a\n- b\n",
    "just text\n",
]


def entry_vectors():
    out = []
    for doc in DOCS:
        data = yaml.safe_load(doc)
        normalized = _normalize_entry(data) if isinstance(data, dict) else None
        record = {"yaml": doc, "normalized": normalized is not None}
        if normalized is not None:
            normalized["_file_path"] = "sysmon/x.yaml"
            try:
                record["response"] = _library_entry_to_response(normalized).model_dump(mode="json")
            except Exception as e:  # noqa: BLE001 - the route's own catch
                record["response_error"] = str(e)
            try:
                payload = CaseTemplateCreate(
                    name=normalized["name"],
                    description=normalized.get("description"),
                    customer_code=None,
                    source=normalized.get("source"),
                    is_default=False,
                    match_field=normalized.get("match_field"),
                    match_value=normalized.get("match_value"),
                    tasks=[
                        CaseTemplateTaskCreate(
                            title=t["title"],
                            description=t.get("description"),
                            guidelines=t.get("guidelines"),
                            mandatory=t.get("mandatory", False),
                            order_index=t["order_index"],
                        )
                        for t in normalized.get("tasks", [])
                    ],
                )
                record["import"] = payload.model_dump(mode="json")
            except Exception as e:  # noqa: BLE001 - the ValueError handler's 400
                record["import_error"] = str(e)
        out.append(record)
    return out


def template(tid, name, description=None, customer_code=None, source=None, is_default=False, match=None, tasks=()):
    t = CaseTemplate(
        id=tid,
        name=name,
        description=description,
        customer_code=customer_code,
        source=source,
        is_default=is_default,
        match_field=match[0] if match else None,
        match_value=match[1] if match else None,
        created_by="gen",
    )
    t.tasks = [
        CaseTemplateTask(id=tid * 10 + i, template_id=tid, title=title, description=desc, guidelines=guide, mandatory=False, order_index=i)
        for i, (title, desc, guide) in enumerate(tasks)
    ]
    return t


TEMPLATES = [
    template(
        1,
        "Ransomware — host containment",
        "Isolate the host; see T1486.",
        tasks=[("Isolate", "Cut network T1486", None), ("Backups", None, "check vss")],
    ),
    template(
        2,
        "Endpoint triage",
        None,
        customer_code="ACME",
        source="wazuh",
        is_default=True,
        tasks=[("Collect", "PowerShell T1059", None)],
    ),
    template(
        3,
        "Sysmon process create",
        None,
        source="wazuh",
        match=("data_win_system_eventID", "1"),
        tasks=[("Review", "process tree", None)],
    ),
    template(4, "Phishing", "Email phishing with lateral movement and brute force", tasks=[("Check", "T1566.001 attachment", "web proxy")]),
    template(5, "Other customer", None, customer_code="OTHER"),
    template(6, "Half condition", None, match=("field", "")),
    template(7, "Credential dumping", "Mimikatz lsass T1003", tasks=[("Dump", "Command and Scripting Interpreter", None)]),
]

SIGNALS = [
    {"customer_code": "ACME", "source": "wazuh"},
    {"customer_code": None, "source": None},
    {"customer_code": "", "source": ""},
    {
        "customer_code": "ACME",
        "source": "wazuh",
        "alert_name": "Possible ransomware PowerShell lsass dump detected on host",
        "tags": ["lateral-movement", "T1486", "web", "brute force", "t1003.001"],
        "mitre_ids": ["T1059.001", "T1003", "T1566.002", "T1486"],
        "mitre_names": ["Command and Scripting Interpreter", "Phishing"],
        "rule_groups": ["windows", "syslog", "ransomware_behaviour", "lateral movement", "web"],
        "document": {"data_win_system_eventID": 1},
        "document_available": True,
    },
    {"customer_code": "ACME", "source": "wazuh", "document": {"data_win_system_eventID": "2"}, "document_available": True},
    {"customer_code": "OTHER", "source": "office365", "document": {}, "document_available": False},
]


def score_vectors():
    out = []
    for raw in SIGNALS:
        signals = ts.AlertSignals(
            customer_code=raw.get("customer_code"),
            source=raw.get("source"),
            alert_name=raw.get("alert_name"),
            tags=list(raw.get("tags", [])),
            mitre_ids=set(raw.get("mitre_ids", [])),
            mitre_names=list(raw.get("mitre_names", [])),
            rule_groups=list(raw.get("rule_groups", [])),
            keywords=[
                tok
                for tok in dict.fromkeys(ts._tokenize(raw.get("alert_name") or ""))
                if len(tok) >= ts._MIN_TOKEN_LENGTH and tok not in ts._KEYWORD_STOPWORDS
            ],
            document=dict(raw.get("document", {})),
            document_available=raw.get("document_available", False),
        )
        usage = {1: 3, 2: 40, 4: 1}
        results = []
        for t in TEMPLATES:
            score, reasons, cond = ts.score_template(t, signals, usage)
            results.append(
                {
                    "template": t.id,
                    "in_scope": ts._in_scope(t, signals),
                    "score": score,
                    "confidence": ts._confidence_for(score),
                    "condition": cond,
                    "reasons": [r.model_dump() for r in sorted(reasons, key=lambda r: r.points, reverse=True)],
                },
            )
        out.append({"signals": raw, "keywords": signals.keywords, "results": results})
    return {
        "templates": [
            {
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "customer_code": t.customer_code,
                "source": t.source,
                "is_default": t.is_default,
                "match_field": t.match_field,
                "match_value": t.match_value,
                "tasks": [{"title": k.title, "description": k.description, "guidelines": k.guidelines} for k in t.tasks],
            }
            for t in TEMPLATES
        ],
        "usage": {"1": 3, "2": 40, "4": 1},
        "cases": out,
    }


def main():
    vectors = {"text": text_vectors(), "entries": entry_vectors(), "scores": score_vectors()}
    OUT.write_text(json.dumps(vectors, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
