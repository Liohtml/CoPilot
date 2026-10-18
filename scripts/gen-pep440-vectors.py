"""Generate `packaging.version.Version` vectors for copilot-platform's PEP 440 compare.

    backend/.venv/bin/python -I scripts/gen-pep440-vectors.py \
        > crates/copilot-platform/src/pep440_vectors.json

`sorted` is a list of valid versions in ascending order (equal versions share a rank);
`invalid` are strings `Version()` rejects.
"""
import json
import sys

import packaging
from packaging.version import InvalidVersion
from packaging.version import Version

candidates = [
    "0.1.98",
    "0.1.99",
    "v0.1.99",
    "0.1.98.0",
    "0.1.100",
    "0.2",
    "0.2.0",
    "1.0",
    "1.0.0",
    "1!0.1",
    "1.0a1",
    "1.0a",
    "1.0.alpha2",
    "1.0b1",
    "1.0-beta.3",
    "1.0rc1",
    "1.0c2",
    "1.0pre3",
    "1.0preview4",
    "1.0.post1",
    "1.0-1",
    "1.0post",
    "1.0.rev2",
    "1.0r3",
    "1.0.dev1",
    "1.0dev",
    "1.0a1.dev2",
    "1.0.post1.dev3",
    "1.0+local",
    "1.0+abc.5",
    "1.0+5",
    "1.0+abc.def",
    "1.0+ABC",
    " 1.0 ",
    "V1.0",
    "1.0RC1",
    "2026.10.15",
    "0.1.98rc1",
    "0.1.98.post0",
    "0",
    "0.0.0",
    "1.0_rc_1",
]
invalid = ["", "abc", "1.0.", "1..0", "1.0-", "1.0+", "1.0+a..b", "1.0 beta", "v", "1.0-dev-1x", "latest", "1.0.0-alpha.1+x y"]
valid = []
for c in candidates:
    try:
        valid.append((Version(c), c))
    except InvalidVersion:
        invalid.append(c)
valid.sort(key=lambda p: p[0])
ranks, rank, prev = [], -1, None
for v, raw in valid:
    if prev is None or v != prev:
        rank += 1
    ranks.append({"input": raw, "rank": rank})
    prev = v
for bad in invalid:
    try:
        Version(bad)
        raise SystemExit(f"{bad!r} is valid")
    except InvalidVersion:
        pass
json.dump({"packaging": packaging.__version__, "sorted": ranks, "invalid": sorted(set(invalid))}, sys.stdout, indent=1)
