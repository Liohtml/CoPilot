"""Generate request-body vectors for copilot-web's FastAPI/Starlette body reading.

    backend/.venv/bin/python -I scripts/gen-form-vectors.py \
        > crates/copilot-web/src/form_vectors.json

- `options`: python-multipart's `parse_options_header` (Content-Type and
  Content-Disposition values), keys and values as latin-1 text.
- `forms`: what `Request.form()` makes of a body (Starlette + python-multipart),
  mapped the way FastAPI's request handler maps failures: a `MultiPartException`
  is its message, anything else "There was an error parsing the body". Bodies
  are latin-1 text so that every byte value round-trips through JSON.
- `json_errors`: `json.loads(body)` failures as FastAPI reports them (`e.pos`).
- `json_content_types`: which Content-Type values FastAPI parses as JSON.
"""
import asyncio
import email.message
import json
import sys

import python_multipart
import starlette
from python_multipart.multipart import parse_options_header
from starlette.exceptions import HTTPException
from starlette.requests import Request

OPTION_HEADERS = [
    "",
    "multipart/form-data; boundary=abc",
    "Multipart/Form-Data; Boundary=abc",
    'multipart/form-data; boundary="a b"',
    "application/x-www-form-urlencoded",
    " Application/X-WWW-Form-Urlencoded ",
    "application/x-www-form-urlencoded; charset=UTF-8",
    'form-data; name="username"',
    'form-data; name="file"; filename="C:\\dir\\a.txt"',
    'form-data; name="file"; filename="\\\\server\\share\\b.txt"',
    'form-data; name=user; filename=""',
    'form-data; name="a;b"',
    'form-data;name="x"',
    'form-data; NAME="x"',
    'form-data; name="x\\"y"',
    'form-data; name="x\\\\y"',
    "form-data; name=<x>",
    "form-data; name",
    "form-data; name=",
    "form-data; ; name=x",
    'form-data; name = "spaced" ',
    "form-data; name*=UTF-8''%C3%A4",
    "text/plain",
    "text/plain;",
]

B = "XyZ"


def mp(*parts: str, end: str = f"--{B}--\r\n") -> str:
    return "".join(f"--{B}\r\n{p}\r\n" for p in parts) + end


def field(name: str, value: str, extra: str = "") -> str:
    return f'Content-Disposition: form-data; name="{name}"\r\n{extra}\r\n{value}'


MULTIPART = f"multipart/form-data; boundary={B}"
URLENC = "application/x-www-form-urlencoded"

FORMS = [
    (URLENC, "username=alice&password=secret"),
    (URLENC, "username=alice;password=x"),
    (URLENC, "a=1;b=2&c=3"),
    (URLENC, "username=al%69ce&password=p%C3%A4ss+word"),
    (URLENC, "username=%E4"),
    (URLENC, "username=\xc3\xa4&password=\xe4"),
    (URLENC, "username"),
    (URLENC, "username&password=x"),
    (URLENC, "&&username=a&&"),
    (URLENC, ";;a=1;;"),
    (URLENC, "=x"),
    (URLENC, "a=1&a=2"),
    (URLENC, "a=%zz%4&b=%"),
    (URLENC, "a=%C3%28%F0%9F%98%80%ED%A0%80x"),
    (URLENC, ""),
    (URLENC, "username=a=b"),
    (URLENC, "user+name=a+b%2Bc"),
    ("Application/X-WWW-Form-Urlencoded", "username=a"),
    ("application/x-www-form-urlencoded; charset=latin-1", "username=a"),
    ("APPLICATION/X-WWW-FORM-URLENCODED; charset=utf-8", "username=a"),
    (None, "username=a"),
    ("text/plain", "username=a"),
    ("application/json", '{"username": "a"}'),
    (MULTIPART, mp(field("username", "alice"), field("password", "s3cret"))),
    (MULTIPART, "\r\n" + mp(field("username", "alice"))),
    (MULTIPART, "\r\njunk\r\n" + mp(field("username", "alice"))),
    (MULTIPART, "junk" + mp(field("username", "alice"))),
    (MULTIPART, mp(field("username", "\xe4\xf6"))),
    (f"multipart/form-data; charset=latin-1; boundary={B}", mp(field("username", "\xe4"))),
    (f"multipart/form-data; charset=utf-8; boundary={B}", mp(field("username", "\xc3\xa4"))),
    (f"multipart/form-data; charset=nonsense; boundary={B}", mp(field("username", "\xc3\xa4"))),
    (MULTIPART, mp('Content-Disposition: form-data; name="f"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\nbody')),
    (MULTIPART, mp('Content-Disposition: form-data; filename="a.txt"\r\n\r\nx')),
    (MULTIPART, mp("Content-Type: text/plain\r\n\r\nx")),
    ("multipart/form-data", mp(field("username", "a"))),
    ("multipart/form-data; charset=utf-8", mp(field("username", "a"))),
    (MULTIPART, f"--{B}\r\n" + field("username", "never closed")),
    (MULTIPART, mp(field("a", "1")) + "epilogue\r\nmore"),
    (MULTIPART, f"--{B}--\r\n"),
    (MULTIPART, f"--{B}--"),
    (MULTIPART, f"--{B}-x"),
    (MULTIPART, mp(field("a", "x", extra="Content-Type: text/plain\r\nX-Other: 1\r\n"))),
    (MULTIPART, mp('Content-Disposition: form-data; name="a"\r\nBad Header: x\r\n\r\nv')),
    (MULTIPART, mp('Content-Disposition: form-data; name="a"\r\n: x\r\n\r\nv')),
    (MULTIPART, mp('Content-Disposition: form-data; name="a"\r\n' + "".join(f"X-H{i}: v\r\n" for i in range(8)) + "\r\nv")),
    (MULTIPART, mp('Content-Disposition: form-data; name="a"\r\n' + "".join(f"X-H{i}: v\r\n" for i in range(7)) + "\r\nv")),
    (MULTIPART, mp(field("a", f"line\r\n--{B}X still data\r\n--{B}-not"))),
    (MULTIPART, mp(field("a", f"--{B}"))),
    (MULTIPART, mp(field("a", ""), field("b", "2"))),
    (MULTIPART, f'--{B}\nContent-Disposition: form-data; name="a"\n\nv\n--{B}--\n'),
    (MULTIPART, f'--{B}\r\nContent-Disposition: form-data; name="a"\rX'),
    (MULTIPART, f'--{B}\r\nContent-Disposition: form-data; name="a"\r\n\rX'),
    (MULTIPART, f"--{B}x\r\n"),
    (MULTIPART, f"--{B}\rx"),
    (MULTIPART, ""),
    (MULTIPART, mp(field("a", "1"), end=f"--{B}--")),
    (MULTIPART, mp(field("a", "1"), end=f"--{B}\r\n")),
    (MULTIPART, mp('Content-Disposition:form-data; name="a"\r\n\r\nv')),
    (MULTIPART, mp('content-disposition: form-data; name="a"\r\n\r\nv')),
    (MULTIPART, mp('Content-Disposition:    form-data; name="a"\r\n\r\nv')),
    (MULTIPART, mp('Content-Disposition: form-data; name="a"\r\nContent-Disposition: form-data; name="b"\r\n\r\nv')),
    (MULTIPART, mp(field("a", "1"), field("a", "2"))),
    ('multipart/form-data; boundary="quoted b"', "--quoted b\r\n" + field("a", "1") + "\r\n--quoted b--\r\n"),
]

JSON_DOCS = [
    "  ",
    "\n\n  \t",
    "{",
    '{"a": 1',
    "{bad",
    "[1,2",
    '{"a":}',
    '{"a": 1,}',
    "nul",
    "tru",
    '"abc',
    '{"a" 1}',
    "1 2",
    "[1,]",
    '{"\xe4": x}',
    '{"a":\n x}',
    '{\n  "a": 1,\n  "b": [1, 2,\n}',
    "NaN",
    '"\\x"',
    "[1e]",
    '{"a": "b\nc"}',
    "\ufeff{}",
    "{}",
    "[]",
    "x",
    '{"a": 1}}',
    "-",
    "01",
]

JSON_CONTENT_TYPES = [
    "application/json",
    "application/json; charset=utf-8",
    "Application/JSON",
    "application/vnd.api+json",
    "application/ld+json; x=y",
    "application/jsonx",
    "text/json",
    "application",
    "application/json/x",
    " application/json ",
    "*/*",
    "application/x-www-form-urlencoded",
    "APPLICATION/JSON;",
    "application/merge-patch+json",
]


async def read_form(content_type, body: bytes):
    headers = [] if content_type is None else [(b"content-type", content_type.encode("latin-1"))]
    scope = {"type": "http", "method": "POST", "path": "/", "headers": headers, "app": object(), "query_string": b""}
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    try:
        form = await Request(scope, receive).form()
    except HTTPException as e:
        return {"error": e.detail}
    except Exception:
        return {"error": "There was an error parsing the body"}
    items = []
    for key, value in form.multi_items():
        items.append([key, value if isinstance(value, str) else {"filename": value.filename}])
    return {"items": items}


def json_content_type(value: str) -> bool:
    message = email.message.Message()
    message["content-type"] = value
    if message.get_content_maintype() != "application":
        return False
    subtype = message.get_content_subtype()
    return subtype == "json" or subtype.endswith("+json")


async def main():
    options = []
    for value in OPTION_HEADERS:
        ctype, opts = parse_options_header(value)
        options.append(
            {
                "input": value,
                "value": ctype.decode("latin-1"),
                "options": [[k.decode("latin-1"), v.decode("latin-1")] for k, v in opts.items()],
            },
        )
    forms = []
    for content_type, body in FORMS:
        result = await read_form(content_type, body.encode("latin-1"))
        forms.append({"content_type": content_type, "body": body, **result})
    json_errors = []
    for doc in JSON_DOCS:
        try:
            json.loads(doc.encode("utf-8"))
            json_errors.append({"doc": doc, "pos": None})
        except json.JSONDecodeError as e:
            json_errors.append({"doc": doc, "pos": e.pos})
    content_types = [{"input": v, "json": json_content_type(v)} for v in JSON_CONTENT_TYPES]
    doc = {
        "starlette": starlette.__version__,
        "python_multipart": python_multipart.__version__,
        "options": options,
        "forms": forms,
        "json_errors": json_errors,
        "json_content_types": content_types,
    }
    json.dump(doc, sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write("\n")


asyncio.run(main())
