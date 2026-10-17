"""Regenerate the vectors that pin `copilot-wazuh-rules` to the Python services it ports.

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-wazuh-rules-vectors.py

Writes `crates/copilot-wazuh-rules/src/wazuh_rules_vectors.json`:

* `levels` — `set_rule_level(file_content, rule_id, new_level)` then `convert_to_xml(...)`
  (`app/connectors/wazuh_manager/services/rules.py`, xmltodict's `unparse(pretty=True)`):
  the rule file as the Wazuh API answers it (JSON), the rule id and level, and what came out —
  `previous_level` and the XML text, or the `HTTPException` detail (`{"http": detail}`) or the
  exception that escaped (`{"raised": class, "text": str(e)}`);
* `index` — `AtomicRedTeamService._parse_atomic_index_markdown(text)`'s techniques and test
  count (Python's `re` on the index markdown);
* `exclude` — `RuleExcludeRequest(**body)`: the model's dump, the `HTTPException` its validators
  raise, or the `ValidationError`'s errors.

Re-run after an xmltodict, Pydantic or Python upgrade, or a change to those services.
"""

import asyncio
import json
import pathlib

from fastapi import HTTPException
from pydantic import ValidationError

from app.connectors.wazuh_manager.schema.rules import RuleExcludeRequest
from app.connectors.wazuh_manager.services.mitre import AtomicRedTeamService
from app.connectors.wazuh_manager.services.rules import convert_to_xml
from app.connectors.wazuh_manager.services.rules import set_rule_level

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-wazuh-rules" / "src" / "wazuh_rules_vectors.json"


def rule(rule_id, level, **extra):
    out = {"@id": rule_id, "@level": level}
    out.update(extra)
    return out


GROUP = {
    "@name": "syslog,sshd,",
    "rule": [
        rule("5700", "0", decoded_as="sshd", description="SSHD messages grouped."),
        rule(
            "5701",
            "8",
            if_sid="5700",
            match="Bad protocol version identification",
            description="sshd: Possible attack.",
            mitre={"id": "T1190"},
        ),
        rule(
            "5702",
            "5",
            if_sid="5700",
            match={"@type": "pcre2", "#text": "^reverse mapping .* failed"},
            description="x",
            group="gdpr_IV_35.7.d,",
        ),
    ],
}

LEVELS = [
    # The shapes the Wazuh API answers with.
    (GROUP, "5701", "1"),
    (GROUP, "5700", "1"),
    (GROUP, "9999", "1"),
    ([GROUP, {"@name": "second,", "rule": rule("5701", "3", description="again")}], "5701", "1"),
    ({"@name": "one,", "rule": rule("100", "12", description="only")}, "100", "12"),
    ({"@name": "empty,"}, "100", "1"),
    ({"@name": "norule,", "rule": None}, "100", "1"),
    ({"@name": "norule,", "rule": []}, "100", "1"),
    ([], "100", "1"),
    # Odd shapes: Python's failures.
    ({"@name": "x", "rule": [{"@level": "3"}]}, "100", "1"),
    ({"@name": "x", "rule": "text"}, "100", "1"),
    ({"@name": "x", "rule": 5}, "100", "1"),
    ({"@name": "x", "rule": [rule(100, "3")]}, "100", "1"),
    ({"@name": "x", "rule": [rule("100", 3)]}, "100", "1"),
    (["not a group"], "100", "1"),
    ("text", "100", "1"),
    (5, "100", "1"),
    (None, "100", "1"),
    ([GROUP, GROUP], "5701", "1"),
    ([[GROUP]], "5701", "1"),
    # xmltodict's rendering: attributes, text, lists, scalars, None, escaping, quoting.
    (
        {"@name": "a&b<c>", "@x": 'say "hi"', "@y": "it's", "@z": "both ' and \"", "rule": rule("1", "2", description="a & b < c > d")},
        "1",
        "1",
    ),
    ({"@name": "ws", "@n": "line\nbreak\ttab\rcr", "rule": rule("1", "2", field="  spaced  ")}, "1", "1"),
    (
        {
            "@name": "types",
            "@int": 5,
            "@float": 1.5,
            "@true": True,
            "@false": False,
            "@none": None,
            "@list": ["a", 1],
            "@dict": {"k": "v"},
            "rule": rule("1", "2"),
        },
        "1",
        "1",
    ),
    (
        {
            "@name": "kids",
            "rule": rule(
                "1",
                "2",
                n=5,
                f=2.0,
                t=True,
                f2=False,
                none=None,
                empty="",
                lst=["a", "b"],
                emptylist=[],
                nested=[["x"], {"a": "b"}],
                obj={"@k": "v", "#text": "t", "c": "d"},
            ),
        },
        "1",
        "1",
    ),
    (
        {
            "@name": "text",
            "#text": "group text",
            "rule": rule("1", "2", description={"#text": 5}, info={"#text": None}, x={"#text": ["l"]}),
        },
        "1",
        "1",
    ),
    ({"@name": "unicode é ☃", "rule": rule("1", "2", description="naïve — ünïcödé 日本")}, "1", "1"),
    ({"@name": "xmlns", "@xmlns": {"": "urn:a", "b": "urn:b", "c": None}, "rule": rule("1", "2")}, "1", "1"),
    ({"@name": "decl", "rule": rule("1", "2", description='<?xml version="1.0" encoding="utf-8"?>')}, "1", "1"),
    ({"@name": "comment", "#comment": "a note", "rule": rule("1", "2", **{"#comment": ["one", "", None, 7]})}, "1", "1"),
    ({"@name": "badcomment", "rule": rule("1", "2", **{"#comment": "a--b"})}, "1", "1"),
    ({"@name": "badcomment2", "rule": rule("1", "2", **{"#comment": "ends-"})}, "1", "1"),
    ({"@name": "names", "rule": rule("1", "2", **{"bad name": "x"})}, "1", "1"),
    ({"@name": "names", "rule": rule("1", "2", **{"a/b": "x"})}, "1", "1"),
    ({"@name": "names", "rule": rule("1", "2", **{"?pi": "x"})}, "1", "1"),
    ({"@name": "names", "rule": rule("1", "2", **{"a=b": "x"})}, "1", "1"),
    ({"@name": "names", "rule": rule("1", "2", **{"q'": "x"})}, "1", "1"),
    ({"@name": "names", "rule": rule("1", "2", **{"x\u001cy": "x"})}, "1", "1"),
    ({"@name": "names", "@a b": "x", "rule": rule("1", "2")}, "1", "1"),
    ({"@name": "names", "@": "empty attr", "rule": rule("1", "2")}, "1", "1"),
    ({"@name": "names", "@xmlns": {"b c": "urn"}, "rule": rule("1", "2")}, "1", "1"),
    ({"@name": "big", "@n": 12345678901234567890, "rule": rule("1", "2", x=-0.0, y=1e100, z=3.14159)}, "1", "1"),
    ({"@name": "ctrl", "rule": rule("1", "2", description="a\u0001b\u007fc")}, "1", "1"),
    ({"@name": "  lead", "rule": rule("1", "2")}, "1", "1"),
    ({"@name": "trailing ws doc\n", "rule": rule("1", "2")}, "1", " \n"),
]

INDEX = [
    "| [OS Credential Dumping](../../T1003/T1003.md) | T1003 | 12 |\n| [LSASS Memory](../../T1003.001/T1003.001.md) | T1003.001 | 7 |\n",
    "# Index\n\n| Technique | ID | Tests |\n|---|---|---|\n| [A](x) | T1 | 1 |\n|[B]( y )|T2.002|  3  |\n| [C] (z) | T3 | 4 |\n",
    "| [Bad](x) | T9 | x |\n| [Unicode](x) | T5 | ٣ |\n| [Brackets [inner]](x) | T6 | 2 |\n",
    "",
    "| [Name|pipe](x) | T7 | 1 |",
]

EXCLUDE = [
    {"integration": "wazuh-rule-exclusion", "prompt": {"rule_group1": "windows", "x": 1}},
    {"integration": "other", "prompt": {"rule_group1": "windows"}},
    {"integration": 5, "prompt": {"rule_group1": "windows"}},
    {"integration": 5, "prompt": {"rule_group1": "linux"}},
    {"integration": "wazuh-rule-exclusion", "prompt": {}},
    {"integration": "wazuh-rule-exclusion", "prompt": {"rule_group1": "linux"}},
    {"integration": "wazuh-rule-exclusion", "prompt": {"rule_group3": "windows"}},
    {"integration": "wazuh-rule-exclusion", "prompt": {"rule_group3": "linux"}},
    {"integration": "wazuh-rule-exclusion", "prompt": {"rule_group3": "linux", "rule_group1": "linux"}},
    {"integration": "wazuh-rule-exclusion", "prompt": {"rule_group3": "linux", "rule_group1": "windows"}},
    {"integration": "wazuh-rule-exclusion", "prompt": "text"},
    {"integration": "wazuh-rule-exclusion"},
    {},
    {"integration": None, "prompt": None},
]


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def level_vector(content, rule_id, new_level):
    probe = {"content": content, "rule_id": rule_id, "new_level": new_level}
    copy = json.loads(json.dumps(content))
    try:
        previous, updated = run(set_rule_level(copy, rule_id, new_level))
        probe["previous_level"] = previous
        probe["xml"] = run(convert_to_xml(updated))
    except HTTPException as e:
        probe["http"] = e.detail
    except Exception as e:  # noqa: BLE001 - what escaped is the point
        probe["raised"] = type(e).__name__
        probe["text"] = str(e)
    return probe


def exclude_vector(body):
    probe = {"body": body}
    try:
        probe["dump"] = RuleExcludeRequest(**body).model_dump()
    except HTTPException as e:
        probe["http"] = [e.status_code, e.detail]
    except ValidationError as e:
        probe["errors"] = [{"type": err["type"], "loc": list(err["loc"]), "msg": err["msg"]} for err in e.errors()]
    return probe


def main():
    out = {
        "levels": [level_vector(*probe) for probe in LEVELS],
        "index": [{"text": text, "parsed": run(AtomicRedTeamService._parse_atomic_index_markdown(text))} for text in INDEX],
        "exclude": [exclude_vector(body) for body in EXCLUDE],
    }
    for entry in out["index"]:
        entry["parsed"].pop("last_updated")
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(out['levels'])} levels, {len(out['index'])} index texts, {len(out['exclude'])} bodies)")


if __name__ == "__main__":
    main()
