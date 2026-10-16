"""Generate the Python built-in vectors copilot-ingest's `py.rs` is pinned to.

    backend/.venv/bin/python -I scripts/gen-ingest-vectors.py \
        > crates/copilot-ingest/src/py_vectors.json

Regenerate after a Python upgrade. Every case is what CPython 3.11 answers:

* `fromisoformat`: `datetime.fromisoformat(s)` as `isoformat()` plus the offset in
  microseconds (`null` for a naive value), or the `ValueError`'s text;
* `day_range`: `calculate_day_range`'s two `%Y-%m-%d %H:%M:%S.%f`[:-3] strings;
* `capitalize`, `splitlines`, `split`: the `str` methods;
* `ip_address`: whether `ipaddress.ip_address(s)` accepts it;
* `basename`: `os.path.basename` (POSIX);
* `dumps_indent2`: `json.dumps(json.loads(s), indent=2)`;
* `timedelta_repr`: `repr(timedelta(microseconds=n))`.
"""
import ipaddress
import json
import posixpath
import sys
from datetime import datetime
from datetime import timedelta

ISO = [
    "2026-03-01",
    "2026-03-01T10:00:00",
    "2026-03-01T10:00:00Z",
    "2026-03-01T10:00:00.250Z",
    "2026-03-01T10:00:00.250000+00:00",
    "2026-03-01 10:00:00.987654+02:00",
    "2026-03-01T10:00:00,5-05:30",
    "2026-03-01T10:00:00.1234567",
    "2026-03-01T10:00",
    "2026-03-01T10",
    "2026-03-01T1000",
    "2026-03-01T100000",
    "20260301T100000",
    "20260301",
    "2026-W09-7",
    "2026W097",
    "2026-W53-1",
    "2020-W53-1",
    "2026-060",
    "2026-03-01T10:00:00+0530",
    "2026-03-01T10:00:00+05",
    "2026-03-01T10:00:00+24:00",
    "2026-03-01T10:00:00-23:59:59.999999",
    "2026-03-01T24:00:00",
    "2026-02-30T00:00:00",
    "2026-13-01",
    "0000-01-01",
    "9999-12-31T23:59:59.999999",
    "2026-03-01T10:00:00Zjunk",
    "2026-03-01X10:00:00",
    "2026-03-01T10:61:00",
    "2026-03-01T10:00:60",
    "2026-3-1",
    "not a date",
    "",
    "2026-03",
    "2026-03-01T",
    "2026-03-01T10:00:00.",
    "２０２６-03-01",
    "2026-03-01T10:00:00+05:30:15.5",
    "2026-03-01 10:00:00 ",
]

STRINGS = [
    "hOST application",
    "ßa",
    "ǅungla",
    "ﬁre",
    "",
    "1abc",
    "\u0130stanbul",
    "a\r\nb\rc\n\nd\u0085e\u2028f\x1c",
    "x\n",
    "  Host \x1c Application\t ",
    "\u00a0lead",
    "one\x0btwo\x0cthree\x1d\x1e\x1f",
]

IPS = [
    "1.2.3.4",
    "01.2.3.4",
    "1.2.3",
    "255.255.255.255",
    "256.1.1.1",
    "::1",
    "fe80::1%eth0",
    "fe80::1%",
    "::ffff:1.2.3.4",
    "1::",
    "1:2:3:4:5:6:7:8",
    "1:2:3:4:5:6:7:8:9",
    "1:2",
    ":::",
    "g::1",
    "2001:db8::1",
    " 1.2.3.4",
    "1.2.3.4 ",
    "::1.2.3",
    "1::2::3",
    "0:0:0:0:0:0:0:0",
    "12345::",
    "١.٢.٣.٤",
]

PATHS = ["/usr/bin/ls", "C:\\x\\y.exe", "dir/", "", "/", "a/b/c.txt", "noslash"]

JSONS = [
    '{"a": [1, 2.5, {"b": "é"}], "c": {}, "d": []}',
    "[1e16, 0.000025, -0.0, 1e-7, 123456789012345678901234567890]",
    '{"s": "tab\\tquote\\"slash\\\\ \\u2028 \\ud83d\\ude00", "n": null, "t": true}',
    "[]",
    '"plain"',
]

TIMEDELTAS = [0, 1, -1, 90_000_000_000, -90_000_000_001, 86_400_000_000, 1_000_000]


def iso_case(s):
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as e:
        return {"input": s, "error": str(e)}
    offset = dt.utcoffset()
    out = {
        "input": s,
        "wall": dt.replace(tzinfo=None).isoformat(),
        "offset_us": None if offset is None else (offset // timedelta(microseconds=1)),
    }
    start = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    try:
        end = start + timedelta(days=1)
        out["day_range"] = [start.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], end.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]]
    except OverflowError as e:
        out["day_range_error"] = str(e)
    return out


def ip_ok(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


json.dump(
    {
        "fromisoformat": [iso_case(s) for s in ISO],
        "strings": [{"input": s, "capitalize": s.capitalize(), "splitlines": s.splitlines(), "split": s.split()} for s in STRINGS],
        "ip_address": [{"input": s, "ok": ip_ok(s)} for s in IPS],
        "basename": [{"input": s, "out": posixpath.basename(s)} for s in PATHS],
        "dumps_indent2": [{"input": s, "out": json.dumps(json.loads(s), indent=2)} for s in JSONS],
        "timedelta_repr": [{"us": n, "out": repr(timedelta(microseconds=n))} for n in TIMEDELTAS],
    },
    sys.stdout,
    ensure_ascii=False,
    indent=1,
)
sys.stdout.write("\n")
