"""Generate the PyYAML vectors copilot-yaml is pinned to.

    backend/.venv/bin/python -I scripts/gen-yaml-vectors.py \
        > crates/copilot-yaml/src/yaml_vectors.json

Regenerate after a PyYAML, pydantic or Python upgrade. Every case is what
`yaml.safe_load(text)` (the pure-Python `SafeLoader`, PyYAML 6.0.3, which
CoPilot Searches uses for the rule files, `/validate`, `/backtest` and
`/publish`) does with `text`:

* `value`: the constructed value as a tagged tree (`{"t": "int", "v": "12"}`, …),
  with `repr` and `json` — `TypeAdapter(Any).dump_json(value)`, how FastAPI
  writes a `dict` field holding it, or the serializer's error — both only when
  it holds no set (a set's order follows string hashes); an input over
  2000 characters (the rule files) keeps only `json`, which is exact for what
  they hold (strings, integers, booleans, `None`, lists, mappings), and a mutated
  file only the SHA-256 of that JSON (`json_sha256`);
* `yaml_error`: a `yaml.YAMLError` — its class, `str()`, `problem` and the
  1-based line of `problem_mark` (what the rule linter reads);
* `exception`: anything else the loader raised (`ValueError` from `int()` or
  `datetime`, `KeyError` from the bool table, …) — its class and `str()`.

The inputs are hand-written cases for every resolver tag, style, escape and
error the scanner, parser, composer and constructor raise, the real rule files
under `crates/copilot-searches/tests/fixtures/rules` (from
socfortress/CoPilot-Search-Queries), and deterministic truncations and
mutations of those files (`derive`: `{"from": <the file's label>, "edit":
[position, deleted, inserted]}`, positions in code points).
"""

import datetime
import hashlib
import json
import os
import random
import sys

import yaml
from pydantic import TypeAdapter

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "..", "crates", "copilot-searches", "tests", "fixtures", "rules")

ANY = TypeAdapter(object)


def has_set(v, seen=None):
    seen = seen or set()
    if id(v) in seen:
        return False
    if isinstance(v, (set, frozenset)):
        return True
    if isinstance(v, (list, tuple)):
        seen.add(id(v))
        return any(has_set(x, seen) for x in v)
    if isinstance(v, dict):
        seen.add(id(v))
        return any(has_set(k, seen) or has_set(x, seen) for k, x in v.items())
    return False


def has_surrogate(text):
    return any(0xD800 <= ord(c) <= 0xDFFF for c in text)


def tag(v, stack=()):
    if any(v is s for s in stack):
        return {"t": "rec"}
    if v is None:
        return {"t": "none"}
    if isinstance(v, bool):
        return {"t": "bool", "v": v}
    if isinstance(v, int):
        return {"t": "int", "v": str(v)}
    if isinstance(v, float):
        return {"t": "float", "v": repr(v)}
    if isinstance(v, str):
        return {"t": "str", "v": v}
    if isinstance(v, bytes):
        return {"t": "bytes", "v": v.hex()}
    if isinstance(v, datetime.datetime):
        off = v.utcoffset()
        return {
            "t": "datetime",
            "v": [v.year, v.month, v.day, v.hour, v.minute, v.second, v.microsecond],
            "offset": None if off is None else int(off.total_seconds()),
        }
    if isinstance(v, datetime.date):
        return {"t": "date", "v": [v.year, v.month, v.day]}
    inner = stack + (v,)
    if isinstance(v, list):
        return {"t": "list", "v": [tag(x, inner) for x in v]}
    if isinstance(v, tuple):
        return {"t": "tuple", "v": [tag(x, inner) for x in v]}
    if isinstance(v, set):
        return {"t": "set", "v": sorted((tag(x, inner) for x in v), key=lambda e: json.dumps(e, sort_keys=True))}
    if isinstance(v, dict):
        return {"t": "dict", "v": [[tag(k, inner), tag(x, inner)] for k, x in v.items()]}
    raise TypeError(type(v))


def case(text, label, derive=None):
    out = {"label": label}
    if derive is None:
        out["input"] = text
    else:
        out["derive"] = derive
    big = len(text) > 2000
    try:
        value = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        out["yaml_error"] = {
            "class": type(exc).__name__,
            "str": str(exc),
            "problem": getattr(exc, "problem", None),
            "problem_line": None if mark is None else mark.line + 1,
        }
        return out
    except Exception as exc:  # noqa: BLE001 - recorded, not handled
        out["exception"] = {"class": type(exc).__name__, "str": str(exc)}
        return out
    if not big:
        out["value"] = tag(value)
    if not big and not has_set(value):
        try:
            out["repr"] = repr(value)
        except RecursionError:
            out["repr"] = None
    if has_set(value):
        return out
    try:
        dumped = ANY.dump_json(value).decode()
        if derive is None:
            out["json"] = dumped
        else:
            out["json_sha256"] = hashlib.sha256(dumped.encode()).hexdigest()
    except Exception as exc:  # noqa: BLE001
        out["json_error"] = {"class": type(exc).__name__, "str": str(exc)}
    return out


SCALARS = [
    # null
    "~", "null", "Null", "NULL", "nULL", "", "nul", "None",
    # bool
    "yes", "Yes", "YES", "yEs", "no", "No", "NO", "true", "True", "TRUE", "tRUE", "false", "False", "FALSE",
    "on", "On", "ON", "off", "Off", "OFF", "y", "Y", "n", "N", "t", "f",
    # int
    "0", "-0", "+0", "12", "-12", "+12", "1_000", "1__0", "_1", "1_", "012", "0o17", "0_", "00", "08", "09",
    "0b101", "-0b101", "0b1_0", "0b", "0b2", "0x1F", "-0x1f", "0x_1", "0xg", "0X1F", "190:20:30", "-1:30",
    "1:60", "1:5", "1:05", "0:30", "09:30", "123456789012345678901234567890", "-99999999999999999999",
    "0x" + "f" * 40, "1e3", "1E3", "+1", "--1",
    # float
    "1.0", "-1.0", "+1.5", "1.", "-.5", ".5", "._5", "1_0.5", "1.5e+3", "1.5e3", "1.5E-3", "1.5e-03",
    "0.1", "1e+3", ".inf", "-.inf", "+.inf", ".Inf", ".INF", ".nan", ".NaN", ".NAN", "-.nan", ".nAn", "inf",
    "nan", "1:30.5", "-1:30.5", "190:20:30.15", "1.7976931348623157e+308", "1.0e+400", "5e-324",
    "0.000001", "123456789.123456789", "1_000.000_1", "1.e+3", "6.02e+23",
    # timestamp
    "2001-12-14", "2001-12-14t21:59:43.10-05:00", "2001-12-14 21:59:43.10 -5", "2001-12-15 2:59:43.10",
    "2001-12-15T02:59:43.1Z", "2002-12-14", "2001-1-1 1:00:00", "2001-01-01T00:00:00+05:30",
    "2001-01-01T00:00:00.1234567", "2001-01-01 00:00:00 Z", "2001-01-01T00:00:00-00:00",
    "2026-08-26", "2026-02-30", "2026-13-01", "0000-01-01", "2026-1-1", "2001-12-14T25:00:00",
    "2001-12-14T23:60:00", "2001-12-14T23:59:60", "2001-12-14T23:59:59+24:00", "2001-12-14T23:59:59-99:99",
    "2001-12-14T23:59:59+23:59", "2001-12-14 21:59:43", "2001-12-14\t21:59:43", "2001-12-14T21:59:43.",
    "1999-12-31T23:59:59.999999999Z",
    # merge, value, yaml
    "<<", "=", "==", "<",
    # strings
    "hello", "hello world", "a:b", "a: b", "-a", "?a", ":a", "a#b", "a #b", "é", "ünïcödé", "日本",
    "${INDEX_PATTERN}", "@x", "`x", "%x", "!x", "&x", "*x", "|x", ">x", "'x'", '"x"', "x'", "{x}", "[x]",
    "a,b", "a?b", "now-24h",
]


def scalar_docs():
    out = []
    for s in SCALARS:
        out.append((s, f"scalar {s!r}"))
        out.append((f"k: {s}\n", f"mapping value {s!r}"))
        out.append((f"- {s}\n", f"sequence item {s!r}"))
        out.append((f"[{s}]", f"flow item {s!r}"))
        out.append((f"{{k: {s}}}", f"flow value {s!r}"))
        out.append((f"'{s}'", f"single-quoted {s!r}"))
        out.append((f"! {s}", f"non-specific tag {s!r}"))
    return out


HAND = [
    # documents and directives
    ("", "empty"), ("   \n\n", "blank lines"), ("# comment only\n", "comment"), ("---\n", "explicit empty"),
    ("--- a\n", "explicit scalar"), ("---\n...\n", "end marker"), ("a\n...\n", "implicit end"),
    ("a\n---\nb\n", "two documents"), ("---\na: 1\n---\nb: 2\n", "two explicit documents"),
    ("--- >\n  folded\n  text\n", "folded root"), ("%YAML 1.1\n---\na: 1\n", "yaml directive"),
    ("%YAML 1.2\n--- a\n", "yaml 1.2"), ("%YAML 2.0\n--- a\n", "yaml 2.0"), ("%YAML 1.1\n%YAML 1.1\n--- a\n", "duplicate yaml"),
    ("%YAML 1\n--- a\n", "directive no dot"), ("%YAML a.1\n--- a\n", "directive letter"), ("%YAML 1.1x\n--- a\n", "directive junk"),
    ("%TAG !e! tag:example.com,2000:\n--- !e!foo bar\n", "tag directive"),
    ("%TAG !e! tag:a,2000:\n%TAG !e! tag:b,2000:\n--- x\n", "duplicate tag"),
    ("%FOO bar baz\n--- x\n", "unknown directive"), ("%\n--- x\n", "directive without name"),
    ("%YAML 1.1 # c\n--- x\n", "directive comment"), ("%YAML 1.1 x\n--- x\n", "directive extra"),
    ("%TAG !e!x tag:a\n--- x\n", "tag handle junk"), ("%TAG !e! \n--- x\n", "tag no prefix"),
    ("%YAML 1.1\na: 1\n", "directive without document start"), ("\ufeffa: 1\n", "bom"),
    ("a: 1\n\ufeffb: 2\n", "bom inside"),
    # block mappings and sequences
    ("a: 1\nb: 2\n", "mapping"), ("a:\n  b:\n    c: 1\n", "nested mapping"),
    ("a:\n- 1\n- 2\n", "indentless sequence"), ("a:\n  - 1\n  - 2\n", "indented sequence"),
    ("- a\n- b:\n  - c\n", "sequence of mapping"), ("- - a\n  - b\n- c\n", "nested sequences"),
    ("-\n- \n-   \n", "empty entries"), ("a:\nb:\n", "empty values"), ("? a\n: b\n", "complex key"),
    ("? a\n", "complex key alone"), ("? - a\n  - b\n: c\n", "sequence key"), ("? [a, b]\n: c\n", "flow sequence key"),
    ("? {a: b}\n: c\n", "flow mapping key"), (": a\n", "value without key"), ("a: 1\na: 2\n", "duplicate keys"),
    ("1: a\n1.0: b\ntrue: c\n", "equal number keys"), ("null: a\n~: b\n", "null keys"),
    ("2001-01-01: a\n2001-01-01 00:00:00: b\n", "date keys"),
    ("2001-01-01T10:00:00+01:00: a\n2001-01-01T09:00:00Z: b\n", "same instant keys"),
    ("2001-01-01T10:00:00: a\n2001-01-01T10:00:00Z: b\n", "naive and aware keys"),
    ("1.5: a\n-0.0: b\n1.0e+16: c\n0.0000001: d\n.inf: e\n", "float keys"),
    ("? !!binary YWI=\n: a\nyes: b\n12345678901234567890: c\n", "bytes bool and big keys"),
    (".nan: a\n.nan: b\n", "shared nan keys"), ("!!float nan: a\n!!float nan: b\n", "distinct nan keys"),
    ("a: 1\n b: 2\n", "bad indentation"), ("a: 1\n  - b\n", "sequence after scalar"), ("a:\n  b: 1\n c: 2\n", "dedent mismatch"),
    ("- a\nb: 1\n", "mapping after sequence"), ("a: b: c\n", "mapping values not allowed"), ("a: - b\n", "sequence not allowed"),
    ("key: value\n- item\n", "block entry in mapping"), ("a:\n\t- b\n", "tab indent"), ("a:\tb\n", "tab after colon"),
    ("a: b\t\n", "trailing tab"), ("\ta: b\n", "leading tab"), ("a: [b,\tc]\n", "tab in flow"),
    ("a\nb: c\n", "plain then mapping"), ("a: 'b'c\n", "quoted then plain"), ("'a' b: c\n", "quoted key junk"),
    ("a: 1\n# c\nb: 2 # trailing\n", "comments"), ("a: b # c: d\n", "comment colon"), ("a: b#c\n", "hash without space"),
    ("a: |\n  x\n  y\n", "literal"), ("a: |-\n  x\n  y\n", "literal strip"), ("a: |+\n  x\n  y\n\n\n", "literal keep"),
    ("a: |\n  x\n\n  y\n", "literal blank line"), ("a: >\n  x\n  y\n\n  z\n", "folded"), ("a: >-\n  x\n   y\n  z\n", "folded more indented"),
    ("a: >\n  x\n\n\n  y\n", "folded two blanks"), ("a: |2\n   x\n", "literal indent indicator"), ("a: |0\n  x\n", "indent zero"),
    ("a: |-2\n   x\n", "chomp then indent"), ("a: |2-\n   x\n", "indent then chomp"), ("a: |x\n  y\n", "block junk"),
    ("a: | # c\n  x\n", "block comment"), ("a: | c\n  x\n", "block header junk"), ("a: >\n\n  x\n", "folded leading blank"),
    ("a: |\n", "empty literal"), ("a: >\nb: c\n", "empty folded"), ("- |\n  x\n- y\n", "literal in sequence"),
    ("a: |\n   x\n  y\n", "literal dedent"), ("a: >\n  x\r\n  y\r\n", "folded crlf"), ("a: |\n  x\ry\n", "literal cr"),
    ("a: >\n  x\u2028  y\n", "folded line separator"), ("a: >\n  x\x85  y\n", "folded nel"),
    ("description: >\n  Detects a thing\n  across lines.\n\n  Second paragraph.\n", "rule-style folded"),
    # flow collections
    ("[a, b, c]", "flow sequence"), ("[a, [b, c], {d: e}]", "nested flow"), ("{a: 1, b: [2, 3]}", "flow mapping"),
    ("[a, b,]", "trailing comma"), ("[,]", "leading comma"), ("[a b]", "flow missing comma"), ("[a, b", "unclosed sequence"),
    ("{a: b", "unclosed mapping"), ("{a: b,}", "mapping trailing comma"), ("{a b}", "flow plain key"), ("{a, b}", "flow keys only"),
    ("[a: b, c: d]", "flow pairs"), ("[? a : b]", "flow complex pair"), ("{? a : b}", "flow complex key"), ("{a: [b}", "mismatched"),
    ("]", "stray close"), ("}", "stray brace"), ("[a]]", "extra close"), ("{a: b}}", "extra brace"), ("[a, - b]", "block entry in flow"),
    ("[\n a,\n b\n]", "multiline flow"), ("{\n a: 1\n}\n", "multiline flow map"), ("a: {b: 1,\nc: 2}\n", "flow across lines"),
    ("[a:b, c]", "colon in flow plain"), ("{a:b}", "flow map no space"), ("[http://x.y]", "url in flow"), ("{a: b:c}", "colon value"),
    ("[{a: 1}, {b: 2}]", "mappings in flow"), ("{a: , b: }", "empty flow values"), ("{: a}", "empty flow key"), ("[a, ? b]", "flow key entry"),
    ("[a,b,c]", "no spaces"), ("{\"a\":1,\"b\":[true,null]}", "json"), ("[1, 2.5, -3, .inf, ~, yes]", "typed flow"),
    # quoting and escapes
    ("'it''s'", "single escape"), ("'a\\nb'", "single backslash"), ('"a\\nb\\tc\\\\d\\"e\\/f"', "double escapes"),
    ('"\\0\\a\\b\\v\\f\\r\\e\\ \\N\\_\\L\\P"', "special escapes"), ('"\\x41\\u00e9\\U0001F600"', "hex escapes"),
    ('"\\x4"', "short hex"), ('"\\xZZ"', "bad hex"), ('"\\q"', "unknown escape"), ('"\\U00110000"', "escape out of range"),
    ('"\\ud800"', "surrogate escape"), ('"a\nb"', "double multiline"), ('"a\n\nb"', "double blank line"), ("'a\n  b'", "single multiline"),
    ('"a\\\n  b"', "escaped line break"), ('"a', "unterminated double"), ("'a", "unterminated single"), ('"a\n---\nb"', "separator in quote"),
    ('"a\n...\nb"', "end marker in quote"), ("'a' 'b'", "two quoted"), ('"a"b', "quoted junk"), ('"\t"', "tab in quotes"),
    ('"a\\\tb"', "escaped tab"), ("' a '", "spaces kept"), ('"  "', "only spaces"), ("''", "empty single"), ('""', "empty double"),
    ('k: "v"\n', "quoted value"), ("\"k\": v\n", "quoted key"), ("'k': 'v'\n", "single quoted pair"), ('"a\r\nb"', "quoted crlf"),
    # anchors, aliases, tags
    ("a: &x 1\nb: *x\n", "alias scalar"), ("a: &x [1, 2]\nb: *x\n", "alias sequence"), ("a: &x {k: v}\nb: *x\n", "alias mapping"),
    ("a: *x\n", "undefined alias"), ("a: &x 1\nb: &x 2\n", "duplicate anchor"), ("&x a: 1\n", "anchored key"), ("a: &x\n", "empty anchor"),
    ("a: &\n", "anchor no name"), ("a: &x! 1\n", "anchor bad char"), ("a: *x!\n", "alias bad char"), ("&a [*a]", "recursive sequence"),
    ("&a {k: *a}", "recursive mapping"), ("&a {*a: 1}", "recursive key"), ("a: &x 1\n*x : 2\n", "alias as key"),
    ("- &a x\n- *a\n- &a y\n- *a\n", "anchor reuse across"), ("a: !!str 12\n", "str tag"), ("a: !!int '12'\n", "int tag"),
    ("a: !!int ''\n", "empty int"), ("a: !!int 'abc'\n", "bad int"), ("a: !!int '0x0x10'\n", "double prefix"), ("a: !!int '0o17'\n", "octal prefix"),
    ("a: !!int ' 12 '\n", "int spaces"), ("a: !!int '1:x'\n", "bad sexagesimal"), ("a: !!int '0b'\n", "empty binary"), ("a: !!int '-09'\n", "bad octal"),
    ("a: !!float '1'\n", "float tag"), ("a: !!float ''\n", "empty float"), ("a: !!float abc\n", "bad float"), ("a: !!float ' 1.5 '\n", "float spaces"),
    ("a: !!float 'nan'\n", "float nan"), ("a: !!float '-inf'\n", "float inf"), ("a: !!float 'infinity'\n", "float infinity"), ("a: !!float '1:x'\n", "bad float sexagesimal"),
    ("a: !!bool 'YES'\n", "bool tag"), ("a: !!bool maybe\n", "bad bool"), ("a: !!null x\n", "null tag"), ("a: !!timestamp '2001-01-01'\n", "timestamp tag"),
    ("a: !!timestamp 'yesterday'\n", "bad timestamp"), ("a: !!binary aGVsbG8=\n", "binary"), ("a: !!binary |\n  aGVs\n  bG8=\n", "binary block"),
    ("a: !!binary 'a'\n", "binary bad length"), ("a: !!binary 'aGVsbG8'\n", "binary padding"), ("a: !!binary 'é'\n", "binary non ascii"),
    ("a: !!binary '//79'\n", "binary not utf8"), ("a: !!binary ''\n", "binary empty"), ("a: !!binary 'a$$b'\n", "binary junk chars"),
    ("a: !!omap [b: 1, c: 2]\n", "omap"), ("a: !!omap {b: 1}\n", "omap not sequence"), ("a: !!omap [b, c]\n", "omap not mapping"),
    ("a: !!omap [{b: 1, c: 2}]\n", "omap two items"), ("a: !!pairs [b: 1, b: 2]\n", "pairs"), ("a: !!pairs b\n", "pairs scalar"),
    ("a: !!set {b, c}\n", "set"), ("a: !!set [b]\n", "set from sequence"), ("a: !!seq {b: 1}\n", "seq tag on mapping"), ("a: !!map [b]\n", "map tag on sequence"),
    ("a: !!str [b]\n", "str tag on sequence"), ("a: !!int [1]\n", "int tag on sequence"), ("a: !!python/name:os.system\n", "python tag"),
    ("a: !foo bar\n", "local tag"), ("a: !<tag:yaml.org,2002:str> 12\n", "verbatim tag"), ("a: !<x\n", "unclosed verbatim"),
    ("a: !e!x y\n", "undefined handle"), ("a: ! 12\n", "non-specific number"), ("a: ! '12'\n", "non-specific quoted"), ("! a: b\n", "non-specific key"),
    ("a: !!str\n", "tag empty"), ("a: !!str &x b\nc: *x\n", "tag then anchor"), ("a: &x !!int '3'\nc: *x\n", "anchor then tag"),
    ("a: !!%21x y\n", "tag escape"), ("a: !!%zz y\n", "bad tag escape"), ("a: !!%ff y\n", "tag escape not utf8"), ("a: !%C3%A9 y\n", "tag escape utf8"),
    ("a: !! y\n", "empty suffix"), ("a: !x!y z\n", "handle undefined"), ("a: !<> z\n", "empty verbatim"), ("? !!set\n", "tagged complex key"),
    ("a: !!value =\n", "value tag"), ("a: =\n", "plain equals"), ("=: a\n", "equals key"), ("a:\n  =: b\n  c: d\n", "value key in mapping"),
    # merge keys
    ("a: &a {x: 1, y: 2}\nb:\n  <<: *a\n  y: 3\n", "merge"), ("a: &a {x: 1}\nb: &b {y: 2}\nc:\n  <<: [*a, *b]\n", "merge list"),
    ("a: &a {x: 1}\nb: &b {x: 2}\nc:\n  <<: [*a, *b]\n", "merge list order"), ("a:\n  <<: 1\n", "merge scalar"), ("a:\n  <<: [1]\n", "merge list scalar"),
    ("a:\n  <<: {x: 1}\n  <<: {y: 2}\n", "two merges"), ("a:\n  z: 0\n  <<: {z: 1, w: 2}\n", "merge after key"), ("<<: {a: 1}\n", "root merge"),
    ("a: &a {<<: {x: 1}}\nb: {<<: *a}\n", "nested merge"), ("a: !!merge x\n", "merge tag value"), ("a:\n  '<<': {x: 1}\n", "quoted merge key"),
    # reader
    ("a: \x07\n", "bell"), ("a: \x00\n", "nul"), ("a: \ufffe\n", "nonchar"), ("a: \x1b\n", "escape char"), ("\x7f", "del"),
    ("a: \x85b\n", "nel inside"), ("a\u2028b: c\n", "line separator"), ("a\rb: c\n", "lone cr"), ("a: b\r\nc: d\r\n", "crlf"),
    # misc scanner
    ("@a", "at sign"), ("`a", "backtick"), ("a: %b\n", "percent value"), ("-a: b\n", "dash plain"), ("- - - x\n", "triple sequence"),
    ("a: -\n", "dash value"), ("a: ?\n", "question value"), ("?\n", "lone question"), (":\n", "lone colon"), ("-\n", "lone dash"),
    ("a: b\n  c\n", "plain continuation"), ("a: b\n\n  c\n", "plain blank continuation"), ("a: b\n#c\n  d\n", "comment breaks plain"),
    ("a: b\n---\n", "separator after plain"), ("a: 'b\n  c'\n", "quoted continuation"), ("x" * 1100 + ": y\n", "long simple key"),
    ("[" + "x" * 1100 + ": y]", "long flow key"), ("a: b\nc\n", "dangling plain"), ("a:\n  b\n  c: d\n", "plain then key"),
    ("'a\n': b\n", "multiline key"), ("a: [b\n  c]\n", "flow multiline plain"), ("{a: 1}: b\n", "flow key with value"),
    ("[a, b]: c\n", "flow sequence simple key"), ("- a: 1\n  b: 2\n- c: 3\n", "list of maps"), ("a: !!seq\n- b\n", "tag before indentless"),
    ("a:\n  - b\n -c\n", "bad sequence indentation"), ("a: >1\n x\n", "folded indicator 1"), ("a: 'b' # c\n", "quoted comment"),
    ("a: \"b\" c\n", "double then plain"), ("a: [b, 'c' d]\n", "flow quoted junk"), ("a: {b: 'c' d}\n", "flow map quoted junk"),
    ("&x\n", "anchor only"), ("!!str\n", "tag only"), ("*x\n", "alias only"), ("&x *y\n", "anchor alias"), ("[&x a, *x]\n", "flow alias"),
    ("{&x a: *x}\n", "flow anchored key"), ("? &x a\n: *x\n", "anchored complex key"), ("a: 1 # c\n# d\n", "trailing comments"),
]


def fixture_files():
    out = []
    for root, _dirs, files in os.walk(FIXTURES):
        for name in sorted(files):
            if name.endswith((".yaml", ".yml")):
                path = os.path.join(root, name)
                with open(path, encoding="utf-8") as fh:
                    out.append((os.path.relpath(path, FIXTURES), fh.read()))
    return sorted(out)


def mutations(name, text, rnd):
    """`(label, [position, deleted, inserted])` edits of a rule file (positions in code points)."""
    out = []
    starts = [0] + [i + 1 for i, c in enumerate(text) if c == "\n" and i + 1 < len(text)]
    for _ in range(6):
        cut = rnd.randrange(1, len(text))
        out.append((f"{name}: cut at {cut}", [cut, len(text) - cut, ""]))
    for _ in range(4):
        i = rnd.randrange(len(starts))
        out.append((f"{name}: tab on line {i + 1}", [starts[i], 0, "\t"]))
    for _ in range(4):
        i = rnd.randrange(len(starts))
        out.append((f"{name}: indent shifted on line {i + 1}", [starts[i], 0, text[starts[i] : starts[i] + 1]]))
    for ch in ('"', "'", "[", "{", "]", ": x: ", "&", "*", "!", "\x01", "- "):
        i = rnd.randrange(len(text))
        out.append((f"{name}: {ch!r} inserted at {i}", [i, 0, ch]))
    return out


def apply_edit(text, edit):
    pos, deleted, inserted = edit
    return text[:pos] + inserted + text[pos + deleted :]


def main():
    rnd = random.Random(1072)
    cases = []
    for text, label in HAND + scalar_docs():
        if not has_surrogate(text):
            cases.append(case(text, label))
    for name, text in fixture_files():
        base = f"rule file {name}"
        cases.append(case(text, base))
        for label, edit in mutations(name, text, rnd):
            cases.append(case(apply_edit(text, edit), label, {"from": base, "edit": edit}))
    cases = [c for c in cases if not has_surrogate(json.dumps(c, ensure_ascii=False))]
    json.dump({"pyyaml": yaml.__version__, "cases": cases}, sys.stdout, ensure_ascii=False, indent=0)
    sys.stdout.write("\n")


main()
