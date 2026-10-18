"""Regenerate the vectors that pin the Mimecast SIEM collection's file handling
(`crates/copilot-integration-modules/src/mimecast/`) to CPython 3.11, the library behaviour
`app/integrations/mimecast/services/mimecast.py` relies on past its `HttpUrl + str` crash.

    python scripts/gen-mimecast-vectors.py

Writes `crates/copilot-integration-modules/src/mimecast_vectors.json`:

* `zips` — `zipfile.ZipFile(io.BytesIO(data)).extractall(dir)` (`write_log_file`): the archive
  (hex) and either the files it left under `dir` (relative path → hex; a directory ends in `/`)
  or `"error"` with what was extracted before the failure;
* `decode` — `bytes.decode("utf-8")`: the text, or the `UnicodeDecodeError`'s `str()`;
* `lines` — `for line in open(path, encoding="utf-8")` over the bytes (the 8192-byte chunks the
  text layer decodes): the lines read before a `UnicodeDecodeError`, and its text;
* `convert` — `convert_to_json(line)`: the pairs in the dict's order.

Re-run after a Python upgrade or a change to those functions.
"""

import io
import json
import os
import pathlib
import tempfile
import zipfile

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates/copilot-integration-modules/src/mimecast_vectors.json"


def convert_to_json(log_line: str) -> dict:
    # `app/integrations/mimecast/services/mimecast.py:convert_to_json`, verbatim.
    log_dict = {}
    for pair in log_line.split("|"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            log_dict[key.strip()] = value.strip()
    return log_dict


def archive(members, compression=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as z:
        for name, data in members:
            info = zipfile.ZipInfo(name)
            info.compress_type = compression
            z.writestr(info, data)
    return buf.getvalue()


def tree(root):
    out = {}
    for base, dirs, files in os.walk(root):
        rel = os.path.relpath(base, root)
        for d in dirs:
            out[os.path.normpath(os.path.join(rel, d)) + "/"] = None
        for f in files:
            with open(os.path.join(base, f), "rb") as fh:
                out[os.path.normpath(os.path.join(rel, f))] = fh.read().hex()
    return dict(sorted(out.items()))


def zip_case(label, data):
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "page.zip")
        try:
            zipfile.ZipFile(io.BytesIO(data)).extractall(target)
            outcome = "ok"
        except Exception:  # noqa: BLE001 - every failure is one answer in `write_log_file`
            outcome = "error"
        return {"label": label, "data": data.hex(), "outcome": outcome, "files": tree(target) if os.path.exists(target) else {}}


def zips():
    good = archive([("a.log", b"x=1|y=2\n"), ("b.log", b"plain")])
    corrupt_crc = bytearray(archive([("a.log", b"hello world")], zipfile.ZIP_STORED))
    corrupt_crc[30 + len("a.log")] ^= 0x01
    second_bad = bytearray(archive([("a.log", b"first"), ("b.log", b"second")], zipfile.ZIP_STORED))
    second_bad[second_bad.index(b"second")] ^= 0x01
    prefixed = b"junk in front" + archive([("a.log", b"after junk")], zipfile.ZIP_STORED)
    commented = bytearray(archive([("a.log", b"c")], zipfile.ZIP_STORED))
    commented[-2:] = (5).to_bytes(2, "little")
    commented += b"hello"
    cp437 = bytearray(archive([("café.log", b"x")], zipfile.ZIP_STORED))
    return [
        zip_case("two deflated files", good),
        zip_case("stored", archive([("s.log", b"stored")], zipfile.ZIP_STORED)),
        zip_case("dot segments and absolute names", archive([("../../up.log", b"u"), ("/abs/x.log", b"a"), ("./d/./e.log", b"e")])),
        zip_case("directories", archive([("dir/", b""), ("dir/f.log", b"f"), ("other/sub/g.log", b"g")])),
        zip_case("the same name twice", archive([("dup.log", b"one"), ("dup.log", b"two")], zipfile.ZIP_STORED)),
        zip_case("a name of only dots", archive([("..", b"x")], zipfile.ZIP_STORED)),
        zip_case("a UTF-8 name", archive([("über.log", b"u")])),
        zip_case("a cp437 name", bytes(cp437)),
        zip_case("empty archive", archive([])),
        zip_case("a bad CRC", bytes(corrupt_crc)),
        zip_case("the second member broken", bytes(second_bad)),
        zip_case("data in front", prefixed),
        zip_case("an archive comment", bytes(commented)),
        zip_case("not a zip", b"definitely not a zip file at all"),
        zip_case("too short", b"PK"),
        zip_case("truncated", good[: len(good) // 2]),
    ]


def decode():
    out = []
    for raw in (
        b"plain",
        b"caf\xc3\xa9",
        b"ab\xff",
        b"\x80",
        b"\xc0\xaf",
        b"\xe2\x28\xa1",
        b"x\xe2\x82",
        b"x\xe2",
        b"\xed\xa0\x80",
        b"\xf4\x90\x80\x80",
        b"\xf0\x9f\x98",
        b"ok\xf5ok",
    ):
        try:
            out.append({"bytes": raw.hex(), "text": raw.decode("utf-8")})
        except UnicodeDecodeError as e:
            out.append({"bytes": raw.hex(), "error": str(e)})
    return out


def lines():
    out = []
    for label, raw in (
        ("plain", b"a=1\nb=2\r\nc=3\rd=4"),
        ("a bad byte early", b"a=1\nb=\xff\nc=3\n"),
        ("a bad byte in the second chunk", b"x" * 9000 + b"\n" + b"line=1\n" * 10 + b"\xff\n"),
        ("a bad byte past a full chunk of lines", (b"k=v|" * 30 + b"\n") * 200 + b"bad=\xfe\n"),
        ("crlf", b"a=1\r\n\r\nb=2\r\n"),
    ):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(raw)
            path = fh.name
        got, error = [], None
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    got.append(line)
        except UnicodeDecodeError as e:
            error = str(e)
        finally:
            os.unlink(path)
        out.append({"label": label, "bytes": raw.hex(), "lines": got, "error": error})
    return out


def convert():
    out = []
    for line in (
        "datetime=2026-10-17T10:00:00+0000|aCode=a1|acc=C0A0\n",
        " a = 1 | b=2=3|junk| a=4\n",
        "\n",
        "=x|y=\n",
        "k = v |\x1ck2=v2\x1f\n",
        "Subject=café | x =  y ",
    ):
        out.append({"line": line, "pairs": list(convert_to_json(line).items())})
    return out


def main():
    data = {"zips": zips(), "decode": decode(), "lines": lines(), "convert": convert()}
    OUT.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
