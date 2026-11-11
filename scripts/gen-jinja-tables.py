"""Generate the Python data copilot-jinja reproduces: character classes, case
mappings, HTML entities and the attributes each value type has.

    backend/.venv/bin/python -I scripts/gen-jinja-tables.py \
        > crates/copilot-jinja/src/tables.rs

Run from the repository root with the backend's Python (3.11): the tables are what
*that* interpreter answers, so `str.isalpha()`, `str.title()`, the `\\w` of Jinja's
name pattern and `html.unescape` behave in Rust exactly as in the renderer they
replace. Regenerate after a Python or Jinja2 upgrade.
"""
import os
import re
import sys
import unicodedata
import warnings
from collections import defaultdict
from html import _invalid_charrefs  # noqa: PLC2701 — the table html.unescape uses
from html import _invalid_codepoints  # noqa: PLC2701
from html.entities import html5

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "unused")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "unused")
os.environ.setdefault("JWT_SECRET", "table-generator-secret")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))

import markupsafe  # noqa: E402
from jinja2 import runtime  # noqa: E402
from jinja2 import utils  # noqa: E402
from jinja2._identifier import pattern as name_re  # noqa: E402
from jinja2.filters import _GroupTuple  # noqa: E402

from app.notifications.schema.events import NotificationEvent  # noqa: E402
from app.notifications.schema.notifications import NotificationSeverity  # noqa: E402

CODE_POINTS = [c for c in range(0x110000) if not 0xD800 <= c <= 0xDFFF]


def ranges(pred):
    out = []
    start = None
    prev = None
    for c in CODE_POINTS:
        if pred(c):
            if start is None:
                start = c
            elif c != prev + 1:
                out.append((start, prev))
                start = c
            prev = c
        elif start is not None:
            out.append((start, prev))
            start = None
    if start is not None:
        out.append((start, prev))
    return out


def cased(c):
    ch = chr(c)
    return ch.islower() or ch.isupper() or unicodedata.category(ch) == "Lt"


def case_ignorable(c):
    # Python does not expose Case_Ignorable; its final-sigma rule reveals it.
    ch = chr(c)
    if cased(c):
        return ("AΣ" + ch).lower()[1] == "ς"
    return ("A" + ch + "Σ").lower()[-1] == "ς"


def emit_ranges(name, doc, rs):
    print(f"/// {doc}")
    print(f"pub const {name}: &[(u32, u32)] = &[")
    line = "   "
    for a, b in rs:
        item = f" (0x{a:x}, 0x{b:x}),"
        if len(line) + len(item) > 99:
            print(line)
            line = "   "
        line += item
    if line.strip():
        print(line)
    print("];")
    print()


def rust_str(s):
    out = []
    for ch in s:
        n = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif 0x20 <= n < 0x7F:
            out.append(ch)
        else:
            out.append(f"\\u{{{n:x}}}")
    return '"' + "".join(out) + '"'


def emit_map(name, doc, pairs):
    print(f"/// {doc}")
    print(f"pub const {name}: &[(u32, &str)] = &[")
    for c, s in pairs:
        print(f"    (0x{c:x}, {rust_str(s)}),")
    print("];")
    print()


CANDIDATES = {
    "__class__",
    "__dict__",
    "__doc__",
    "__module__",
    "__name__",
    "__qualname__",
    "__self__",
    "__func__",
    "__code__",
    "__globals__",
    "__closure__",
    "__defaults__",
    "__kwdefaults__",
    "__annotations__",
    "__wrapped__",
    "__mro__",
    "__bases__",
    "__base__",
    "__subclasses__",
    "mro",
    "__weakref__",
    "__slots__",
    "__init__",
    "__new__",
    "__call__",
    "__getattr__",
    "__getattribute__",
    "__reduce__",
    "gi_frame",
    "gi_code",
    "gi_running",
    "gi_yieldfrom",
    "gi_suspended",
}


def attrs(obj):
    names = set(dir(type(obj))) | set(dir(obj)) | CANDIDATES
    return sorted(n for n in names if hasattr(obj, n))


def sample_generator():
    yield 1


SAMPLES = [
    ("STR", "str", "abc"),
    ("INT", "int", 1),
    ("FLOAT", "float", 1.5),
    ("BOOL", "bool", True),
    ("NONE", "NoneType", None),
    ("LIST", "list", [1]),
    ("TUPLE", "tuple", (1,)),
    ("DICT", "dict", {"a": 1}),
    ("DEFAULTDICT", "defaultdict", defaultdict(str)),
    ("MARKUP", "Markup", markupsafe.Markup("x")),
    ("BYTES", "bytes", b"x"),
    ("RANGE", "range", range(3)),
    ("SEVERITY", "a member of NotificationSeverity", NotificationSeverity.HIGH),
    (
        "EVENT",
        "NotificationEvent",
        NotificationEvent(trigger="investigation_complete", severity="High", subject="s", summary="s", entity_id=1, dedupe_key="k"),
    ),
    ("LOOP", "LoopContext", runtime.LoopContext([1], runtime.StrictUndefined)),
    ("CYCLER", "Cycler", utils.Cycler(1)),
    ("JOINER", "Joiner", utils.Joiner()),
    ("NAMESPACE", "Namespace", utils.Namespace(a=1)),
    ("MACRO", "Macro", runtime.Macro(None, lambda: "", "m", [], False, False, False, False)),
    ("GENERATOR", "generator", sample_generator()),
    ("GROUP_TUPLE", "_GroupTuple", _GroupTuple(1, [1])),
    ("DICT_KEYS", "dict_keys", {}.keys()),
    ("DICT_VALUES", "dict_values", {}.values()),
    ("DICT_ITEMS", "dict_items", {}.items()),
    ("LIST_REVERSEITERATOR", "list_reverseiterator", reversed([1])),
    ("FUNCTION", "a Python function", utils.generate_lorem_ipsum),
    ("BUILTIN_METHOD", "a built-in method", "x".upper),
    ("METHOD", "a bound Python method", utils.Cycler(1).reset),
    ("TYPE", "a class", dict),
]


class _Sentinel:
    pass


ARITY_RE = re.compile(
    r"(takes (no|exactly|at least|at most|from|\d+) .*argument|expected (at least |at most )?\d+ arguments?, got|missing \d+ required)",
)

METHOD_SAMPLES = [
    ("str", lambda: "abc"),
    ("Markup", lambda: markupsafe.Markup("abc")),
    ("list", lambda: [1, 2]),
    ("dict", lambda: {"a": 1}),
    ("tuple", lambda: (1, 2)),
    ("int", lambda: 5),
    ("float", lambda: 1.5),
    ("bytes", lambda: b"ab"),
]


def arity_table():
    """For each method: the TypeError a call with 0 to 5 arguments raises when
    the count is wrong, and the one an unknown keyword raises."""
    sentinel = _Sentinel()
    rows = []
    for tname, make in METHOD_SAMPLES:
        for name in sorted(n for n in dir(make()) if not n.startswith("_")):
            if not callable(getattr(make(), name)):
                continue
            counts = []
            for n in range(6):
                try:
                    getattr(make(), name)(*([sentinel] * n))
                except TypeError as e:
                    if ARITY_RE.search(str(e)):
                        counts.append((n, str(e)))
                except Exception:  # noqa: BLE001 — only arity errors matter
                    pass
            try:
                getattr(make(), name)(__bogus__=1)
                kw = ""
            except TypeError as e:
                kw = str(e).replace("__bogus__", "{kw}")
            except Exception:  # noqa: BLE001
                kw = ""
            rows.append((tname, name, counts, kw))
    return sorted(rows)


def main():
    warnings.simplefilter("ignore")
    print("//! Python 3.11 data, generated by `scripts/gen-jinja-tables.py`: do not edit.")
    print()
    print("#![allow(missing_docs)]")
    print()
    emit_ranges(
        "NAME_CHARS",
        "Characters of Jinja's name pattern (`\\w` and the identifier extras).",
        ranges(lambda c: name_re.fullmatch(chr(c)) is not None),
    )
    emit_ranges("SPACE", "`str.isspace()` (also `\\s` and `str.split()`).", ranges(lambda c: chr(c).isspace()))
    emit_ranges("ALPHA", "`str.isalpha()`.", ranges(lambda c: chr(c).isalpha()))
    emit_ranges("DECIMAL", "`str.isdecimal()` (also `\\d`).", ranges(lambda c: chr(c).isdecimal()))
    print("/// The zero of every run of decimal digits.")
    print("pub const DECIMAL_ZEROS: &[u32] = &[")
    zeros = [c for c in CODE_POINTS if chr(c).isdecimal() and unicodedata.decimal(chr(c)) == 0]
    for i in range(0, len(zeros), 8):
        print("   " + "".join(f" 0x{c:x}," for c in zeros[i : i + 8]))
    print("];")
    print()
    emit_ranges("DIGIT", "`str.isdigit()`.", ranges(lambda c: chr(c).isdigit()))
    emit_ranges("NUMERIC", "`str.isnumeric()`.", ranges(lambda c: chr(c).isnumeric()))
    emit_ranges("LOWER", "Characters `str.islower()` counts as lowercase.", ranges(lambda c: chr(c).islower()))
    emit_ranges("UPPER", "Characters `str.isupper()` counts as uppercase.", ranges(lambda c: chr(c).isupper()))
    emit_ranges("TITLECASE", "General category Lt.", ranges(lambda c: unicodedata.category(chr(c)) == "Lt"))
    emit_ranges("CASED", "Cased characters.", ranges(cased))
    emit_ranges("CASE_IGNORABLE", "Case-ignorable characters (the final-sigma rule).", ranges(case_ignorable))
    emit_ranges("PRINTABLE", "`str.isprintable()`.", ranges(lambda c: chr(c).isprintable()))
    emit_ranges("XID_START", "Characters `str.isidentifier()` accepts first.", ranges(lambda c: chr(c).isidentifier()))
    emit_ranges("XID_CONTINUE", "Characters `str.isidentifier()` accepts after the first.", ranges(lambda c: ("a" + chr(c)).isidentifier()))
    emit_ranges("LINEBREAK", "Line boundaries of `str.splitlines()`.", ranges(lambda c: len(("a" + chr(c) + "b").splitlines()) == 2))
    emit_map(
        "UPPER_MAP",
        "`str.upper()` of every character it changes.",
        [(c, chr(c).upper()) for c in CODE_POINTS if chr(c).upper() != chr(c)],
    )
    emit_map(
        "LOWER_MAP",
        "`str.lower()` of every character it changes (sigma's final form aside).",
        [(c, chr(c).lower()) for c in CODE_POINTS if chr(c).lower() != chr(c)],
    )
    emit_map(
        "TITLE_MAP",
        "The title case of every character whose title case is not its upper case.",
        [(c, chr(c).title()) for c in CODE_POINTS if chr(c).title() != chr(c).upper()],
    )
    emit_map(
        "FOLD_MAP",
        "`str.casefold()` of every character it maps unlike `str.lower()`.",
        [(c, chr(c).casefold()) for c in CODE_POINTS if chr(c).casefold() != chr(c).lower()],
    )
    print("/// `html.entities.html5`, sorted by name.")
    print("pub const HTML5_ENTITIES: &[(&str, &str)] = &[")
    for name in sorted(html5):
        print(f"    ({rust_str(name)}, {rust_str(html5[name])}),")
    print("];")
    print()
    emit_map("INVALID_CHARREFS", "`html._invalid_charrefs`.", sorted(_invalid_charrefs.items()))
    print("/// `html._invalid_codepoints`.")
    print("pub const INVALID_CODEPOINTS: &[u32] = &[")
    print("   " + "".join(f" 0x{c:x}," for c in sorted(_invalid_codepoints)))
    print("];")
    print()
    print("/// One `ARITY` row.")
    print("pub type Arity = (&'static str, &'static str, &'static [(u8, &'static str)], &'static str);")
    print()
    print("/// Wrong-arity `TypeError`s of the built-in methods: (type, method,")
    print("/// [(argument count, message)], message for an unknown keyword with `{kw}`).")
    print("pub const ARITY: &[Arity] = &[")
    for tname, name, counts, kw in arity_table():
        items = ", ".join(f"({n}, {rust_str(m)})" for n, m in counts)
        print(f"    ({rust_str(tname)}, {rust_str(name)}, &[{items}], {rust_str(kw)}),")
    print("];")
    for const, what, obj in SAMPLES:
        names = attrs(obj)
        print()
        print(f"/// The attributes `hasattr` finds on {what}.")
        print(f"pub const ATTRS_{const}: &[&str] = &[")
        for n in names:
            print(f"    {rust_str(n)},")
        print("];")


main()
