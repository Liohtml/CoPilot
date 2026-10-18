"""Regenerate what pins the Rust service's own routing and pages (`copilot-standalone`) to the Python
app it replaces (`backend/copilot.py`).

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-standalone-vectors.py

`copilot.py` is imported from a scratch working directory (it creates `scoutsuite-report` where it
runs). Writes, under `crates/copilot-standalone/src/python/`:

* `app.json` — the Python app's routes in Starlette's order (`app.routes`: FastAPI's four
  documentation routes, every `APIRoute`, the `/scoutsuite-report` mount, `GET /`), each with its
  path template, its methods (as this process's `set` iterates them: only the four documentation
  routes have two, `GET` and `HEAD`) and its kind; the Swagger UI, OAuth2-redirect and ReDoc pages
  FastAPI serves (`get_swagger_ui_html`, `get_swagger_ui_oauth2_redirect_html`, `get_redoc_html` as
  `FastAPI.setup` calls them, the bodies of their `HTMLResponse`s);
* `openapi.json` — `GET /openapi.json`'s body (`JSONResponse(app.openapi())`), with the one value
  Python computes at import time (`LogRetrieveModel.timestamp`'s example, `datetime.now()`)
  replaced by `"__COPILOT_IMPORT_TIME__"`;
* `standalone_vectors.json` — the decisions the Rust front reproduces:
  - `routing`: a request target and a method → uvicorn's `scope["path"]`
    (`urllib.parse.unquote` of the raw path) and Starlette's `Router.app` decision on it: the
    first route that matches fully (its index and path parameters), else the first partial
    match (a 405 naming that route's methods), else none (`redirect_slashes=False`: a 404);
  - `cors`: `CORSMiddleware(allow_origins=["*"], allow_credentials=True, allow_methods=["*"],
    allow_headers=["*"])` inside `GZipMiddleware(minimum_size=1000)`, as `copilot.py` nests them,
    around an app answering a small 404 or a JSON body big enough to be compressed: the status,
    every header in order and the body for requests with and without an `Origin`, preflights
    (methods, headers, private network);
  - `parsedate`: `email.utils.parsedate(text)[:6]` (what `StaticFiles` compares
    `If-Modified-Since` by);
  - `static`: the `/scoutsuite-report` mount (`StaticFiles(directory="scoutsuite-report")`) over a
    directory of files with fixed modification times, through the app's `GZipMiddleware`: the
    status, the headers (the timing pair removed, a gzipped `content-length` masked) and the body
    (decompressed) of plain, conditional, ranged and refused requests.

`backend/tests/test_rust_standalone_snapshot.py` regenerates the two Python-app files and fails when
they differ from the committed ones. Re-run after a route, a schema or a FastAPI/Starlette upgrade.
"""

import asyncio
import gzip
import importlib
import json
import os
import pathlib
import re
import sys
import tempfile
import urllib.parse

REPO = pathlib.Path(__file__).resolve().parent.parent
OUT = REPO / "crates" / "copilot-standalone" / "src" / "python"
IMPORT_TIME_MARKER = "__COPILOT_IMPORT_TIME__"
# Fixed modification times for the static files: whole seconds and a fraction (the etag hashes
# `str(st_mtime)`, so both of `float.__repr__`'s shapes are pinned).
MTIME_WHOLE = 1_700_000_000
MTIME_FRACTION = 1_700_000_123.25

_APP = None


def load_app():
    """`copilot.app`, imported once from a scratch working directory."""
    global _APP
    if _APP is None:
        backend = REPO / "backend"
        if str(backend) not in sys.path:
            sys.path.insert(0, str(backend))
        cwd = os.getcwd()
        scratch = tempfile.mkdtemp(prefix="gen-standalone-")
        os.chdir(scratch)
        try:
            _APP = importlib.import_module("copilot").app
        finally:
            os.chdir(cwd)
    return _APP


def route_entries(app):
    from fastapi.routing import APIRoute
    from starlette.routing import Mount
    from starlette.routing import Route

    out = []
    for r in app.routes:
        if isinstance(r, APIRoute):
            out.append({"kind": "api", "path": r.path, "methods": list(r.methods)})
        elif isinstance(r, Route):
            out.append({"kind": "route", "path": r.path, "methods": list(r.methods)})
        elif isinstance(r, Mount):
            out.append({"kind": "mount", "path": r.path, "methods": None})
        else:  # pragma: no cover - the app has no other kind
            raise TypeError(type(r).__name__)
    return out


def pages(app):
    from fastapi.openapi.docs import get_redoc_html
    from fastapi.openapi.docs import get_swagger_ui_html
    from fastapi.openapi.docs import get_swagger_ui_oauth2_redirect_html

    swagger = get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} - Swagger UI",
        oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        init_oauth=app.swagger_ui_init_oauth,
        swagger_ui_parameters=app.swagger_ui_parameters,
    )
    redirect = get_swagger_ui_oauth2_redirect_html()
    redoc = get_redoc_html(openapi_url=app.openapi_url, title=f"{app.title} - ReDoc")
    return {
        "docs_url": app.docs_url,
        "redoc_url": app.redoc_url,
        "openapi_url": app.openapi_url,
        "oauth2_redirect_url": app.swagger_ui_oauth2_redirect_url,
        "swagger_ui": swagger.body.decode("utf-8"),
        "oauth2_redirect": redirect.body.decode("utf-8"),
        "redoc": redoc.body.decode("utf-8"),
    }


def openapi_body(app):
    """`GET /openapi.json`'s body, the import-time example replaced by the marker."""
    from fastapi.responses import JSONResponse

    import app.utils as utils

    schema = app.openapi()
    body = JSONResponse(schema).body.decode("utf-8")
    examples = utils.LogRetrieveModel.model_fields["timestamp"].examples
    stamp = json.dumps(examples[0].isoformat())
    if body.count(stamp) != 1:
        raise SystemExit(f"the import-time example {stamp} is not in the document exactly once")
    return body.replace(stamp, json.dumps(IMPORT_TIME_MARKER))


def app_json(app):
    return {"routes": route_entries(app), "pages": pages(app), "import_time_marker": IMPORT_TIME_MARKER}


# ---------------------------------------------------------------------------- routing ----


def fill(template, value="x", path_value="x/y"):
    def sub(m):
        return path_value if m.group(2) == ":path" else value

    return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)(:[a-zA-Z_][a-zA-Z0-9_]*)?\}", sub, template)


def segments(template):
    return template.split("/")


def is_param(seg):
    return seg.startswith("{") and seg.endswith("}")


def routing_inputs(routes):
    methods_all = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    inputs = []
    seen = set()

    def add(raw, method):
        if (raw, method) not in seen:
            seen.add((raw, method))
            inputs.append((raw, method))

    templates = [r["path"] if r["kind"] != "mount" else r["path"] + "/{path:path}" for r in routes]
    for r, t in zip(routes, templates):
        own = r["methods"] or ["GET"]
        s0 = fill(t)
        for m in methods_all:
            add(s0, m)
        segs = segments(t)
        params = [i for i, s in enumerate(segs) if is_param(s)]
        for m in own:
            # An encoded slash inside a parameter, and one in place of the last separator.
            if params:
                i = params[0]
                v = list(segs)
                v[i] = "a%2Fb"
                add(fill("/".join(v)), m)
                add(fill("/".join(v)).replace("a%2Fb", "a%2fb"), m)
            if s0.count("/") >= 2:
                cut = s0.rfind("/")
                add(s0[:cut] + "%2F" + s0[cut + 1 :], m)
            add(s0 + "/", m)
            add(s0 + "%0A", m)
            add(s0 + "%0A/x", m)
            add("/" + s0, m)
            add(s0 + "%20", m)
        # Starlette tries the routes in order; axum prefers a static segment. Each parameter
        # filled with the static segments other routes have in that place.
        for i in params:
            prefix = segs[:i]
            for other in templates:
                os_ = segments(other)
                if len(os_) > i and os_[:i] == prefix and not is_param(os_[i]) and os_[i]:
                    v = list(segs)
                    v[i] = os_[i]
                    for m in methods_all[:5]:
                        add(fill("/".join(v)), m)
    for raw in [
        "/",
        "",
        "/api",
        "/api/",
        "/nothing-here",
        "/api/nothing-here",
        "/docs/",
        "/scoutsuite-report",
        "/scoutsuite-report/",
        "/scoutsuite-report/a/../b.html",
        "/scoutsuite-report%2Fa",
        "/api/customers/%zz",
        "/api/customers/%C3%A4",
        "/api/customers/%FF",
        "/api/customers/%E2%82",
        "/api/customers/%2525",
        "/api/customers/%25",
        "/api/customers/a%",
        "/api/customers/a%2",
        "/api/customers/%00",
        "/api/customers/%0A",
        "/api/customers/%0A%0A",
        "/api/copilot_searches/name/a%0Ab",
        "/api/copilot_searches/name/a%0A",
        "/api/copilot_searches/name/",
        "/api/copilot_searches/catalog/compliance/pci/a%2Fb%2Fc",
        "/api%2Fcustomers",
        "/API/customers",
    ]:
        for m in ["GET", "POST", "DELETE", "HEAD"]:
            add(raw, m)
    return inputs


def decide(app, raw, method):
    from starlette.routing import Match

    decoded = urllib.parse.unquote(raw) if "%" in raw else raw
    scope = {"type": "http", "path": decoded, "root_path": "", "method": method, "headers": []}
    partial = None
    for i, route in enumerate(app.routes):
        match, child = route.matches(scope)
        if match == Match.FULL:
            params = dict(child.get("path_params", {}))
            return decoded, ["full", i, [[k, str(v)] for k, v in params.items()]]
        if match == Match.PARTIAL and partial is None:
            partial = i
    if partial is not None:
        return decoded, ["partial", partial]
    return decoded, ["none"]


def routing_vectors(app, routes):
    return [[raw, method, *decide(app, raw, method)] for raw, method in routing_inputs(routes)]


# ------------------------------------------------------------------------------- ASGI ----


async def asgi_call(app, method, raw_path, headers, body=b""):
    """One request through an ASGI app; the response start and the joined body."""
    path = urllib.parse.unquote(raw_path)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": raw_path.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers],
        "client": ("127.0.0.1", 40000),
        "server": ("testserver", 80),
        "app": app,
    }
    sent = False

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        await asyncio.sleep(3600)

    start = {}
    chunks = []

    async def send(message):
        if message["type"] == "http.response.start":
            start["status"] = message["status"]
            start["headers"] = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in message.get("headers", [])]
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    await app(scope, receive, send)
    return start["status"], start["headers"], b"".join(chunks)


CORS_REQUESTS = [
    ("GET", []),
    ("GET", [("Origin", "http://localhost:5173")]),
    ("POST", [("Origin", "https://soc.example.com"), ("Cookie", "a=b")]),
    ("GET", [("Origin", "null")]),
    ("OPTIONS", [("Origin", "http://localhost:5173")]),
    ("OPTIONS", [("Origin", "http://localhost:5173"), ("Access-Control-Request-Method", "PUT")]),
    (
        "OPTIONS",
        [
            ("Origin", "http://a"),
            ("Access-Control-Request-Method", "DELETE"),
            ("Access-Control-Request-Headers", "Authorization, Content-Type"),
        ],
    ),
    ("OPTIONS", [("Origin", "http://a"), ("Access-Control-Request-Method", "get")]),
    ("OPTIONS", [("Origin", "http://a"), ("Access-Control-Request-Method", "PROPFIND")]),
    ("OPTIONS", [("Origin", "http://a"), ("Access-Control-Request-Method", "GET"), ("Access-Control-Request-Private-Network", "true")]),
    ("OPTIONS", [("Origin", "http://a"), ("Access-Control-Request-Method", "")]),
    ("OPTIONS", [("Access-Control-Request-Method", "GET")]),
    ("OPTIONS", [("Origin", "http://a"), ("Access-Control-Request-Method", "PATCH"), ("Access-Control-Request-Headers", "")]),
    ("GET", [("Origin", "http://a"), ("X-Answer-Size", "big")]),
    ("GET", [("Origin", "http://a"), ("X-Answer-Size", "big"), ("Accept-Encoding", "gzip")]),
    ("GET", [("X-Answer-Size", "big"), ("Accept-Encoding", "gzip")]),
    ("PUT", [("Origin", "http://\xe4.example")]),
]


def cors_vectors():
    """`copilot.py`'s nesting: `GZipMiddleware(CORSMiddleware(app))` around an app answering a
    small 404, or a JSON body big enough to be gzipped."""
    from starlette.middleware.cors import CORSMiddleware
    from starlette.middleware.gzip import GZipMiddleware
    from starlette.responses import JSONResponse

    async def inner(scope, receive, send):
        request_headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
        if request_headers.get("x-answer-size") == "big":
            response = JSONResponse({"items": ["x" * 40] * 50})
        else:
            response = JSONResponse({"detail": "Not Found"}, status_code=404)
        await response(scope, receive, send)

    app = GZipMiddleware(
        CORSMiddleware(inner, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]),
        minimum_size=1000,
    )
    out = []
    for method, headers in CORS_REQUESTS:
        status, resp_headers, body = asyncio.run(asgi_call(app, method, "/x", headers))
        if any(k == "content-encoding" and v == "gzip" for k, v in resp_headers):
            body = gzip.decompress(body)
            resp_headers = [(k, "*" if k == "content-length" else v) for k, v in resp_headers]
        out.append(
            {"method": method, "headers": headers, "status": status, "response_headers": resp_headers, "body": body.decode("latin-1")},
        )
    return out


PARSEDATE = [
    "Tue, 15 Nov 1994 08:12:31 GMT",
    "Tuesday, 15-Nov-94 08:12:31 GMT",
    "Tue Nov 15 08:12:31 1994",
    "15 Nov 1994 08:12:31 +0100",
    "15 Nov 1994 08:12 -0500",
    "Tue, 15 Nov 69 08:12:31 GMT",
    "Tue, 15 Nov 68 08:12:31 GMT",
    "Tue, 15 november 1994 08.12.31",
    "Tue, 15 Nov 1994 08.12 GMT",
    "Tue,15 Nov 1994 08:12:31 GMT",
    "Nov 15 1994 08:12:31",
    "15 Nov 1994, 08:12:31,",
    "Tue, 32 Nov 1994 08:12:31 GMT",
    "Tue, 15 Nov 1994 25:12:31 GMT",
    "Tue, 15 Foo 1994 08:12:31 GMT",
    "Tue, 15 Nov 1994",
    "Tue, 15 Nov 1994 08:12:31:00 GMT",
    "Tue, 15 Nov 1_994 08:12:31 GMT",
    "Tue, 15 Nov +1994 08:12:31 GMT",
    "  ",
    "",
    "garbage",
    "Thu, 01 Jan 2099 00:00:00 GMT",
    "Tue, 14 Nov 2023 22:15:23 GMT",
]


def parsedate_vectors():
    from email.utils import parsedate

    out = []
    for text in PARSEDATE:
        t = parsedate(text)
        out.append([text, None if t is None else list(t[:6])])
    return out


# ----------------------------------------------------------------------------- static ----

STATIC_FILES = {
    "index.html": ("<!doctype html><title>ScoutSuite</title>\n" * 40, MTIME_WHOLE),
    "small.html": ("<p>ok</p>\n", MTIME_FRACTION),
    "report.js": ("var scout = 1;\n", MTIME_WHOLE),
    "style.css": ("body{}\n", MTIME_WHOLE),
    "data.json": ('{"a": 1}\n', MTIME_WHOLE),
    "image.png": ("\x89PNG\r\n\x1a\n" + "x" * 2000, MTIME_WHOLE),
    "notes": ("plain\n", MTIME_WHOLE),
    "archive.tar.gz": ("not really\n", MTIME_WHOLE),
    "with space.txt": ("spaced\n", MTIME_WHOLE),
    "ünï.txt": ("unicode name\n", MTIME_WHOLE),
    "big.txt": ("0123456789abcdef" * 5000, MTIME_FRACTION),
    "scoutsuite-results/scoutsuite_results_aws-x.js": ("scoutsuite_results = {};\n", MTIME_WHOLE),
    "sub/index.html": ("<p>sub</p>\n", MTIME_WHOLE),
}

STATIC_REQUESTS = [
    ("GET", "/scoutsuite-report/index.html", []),
    ("GET", "/scoutsuite-report/index.html", [("Accept-Encoding", "gzip, deflate")]),
    ("HEAD", "/scoutsuite-report/index.html", []),
    ("HEAD", "/scoutsuite-report/index.html", [("Accept-Encoding", "gzip")]),
    ("GET", "/scoutsuite-report/small.html", [("Accept-Encoding", "gzip")]),
    ("GET", "/scoutsuite-report/report.js", []),
    ("GET", "/scoutsuite-report/style.css", []),
    ("GET", "/scoutsuite-report/data.json", []),
    ("GET", "/scoutsuite-report/image.png", [("Accept-Encoding", "gzip")]),
    ("GET", "/scoutsuite-report/notes", []),
    ("GET", "/scoutsuite-report/archive.tar.gz", []),
    ("GET", "/scoutsuite-report/with%20space.txt", []),
    ("GET", "/scoutsuite-report/%C3%BCn%C3%AF.txt", []),
    ("GET", "/scoutsuite-report/big.txt", []),
    ("GET", "/scoutsuite-report/big.txt", [("Accept-Encoding", "gzip")]),
    ("GET", "/scoutsuite-report/scoutsuite-results/scoutsuite_results_aws-x.js", []),
    ("GET", "/scoutsuite-report/scoutsuite-results%2Fscoutsuite_results_aws-x.js", []),
    ("GET", "/scoutsuite-report/sub/index.html", []),
    ("GET", "/scoutsuite-report/sub", []),
    ("GET", "/scoutsuite-report/sub/", []),
    ("GET", "/scoutsuite-report/", []),
    ("GET", "/scoutsuite-report/missing.html", []),
    ("GET", "/scoutsuite-report/../etc/passwd", []),
    ("GET", "/scoutsuite-report/sub/../index.html", []),
    ("GET", "/scoutsuite-report/./small.html", []),
    ("GET", "/scoutsuite-report//small.html", []),
    ("GET", "/scoutsuite-report/small.html%00", []),
    ("GET", "/scoutsuite-report/" + "a" * 300, []),
    ("GET", "/scoutsuite-report/outside-link", []),
    ("GET", "/scoutsuite-report/small.html", [("If-None-Match", "ETAG")]),
    ("GET", "/scoutsuite-report/small.html", [("If-None-Match", 'W/ETAG, "other"')]),
    ("GET", "/scoutsuite-report/small.html", [("If-None-Match", '"other"')]),
    ("GET", "/scoutsuite-report/small.html", [("If-Modified-Since", "LASTMOD")]),
    ("GET", "/scoutsuite-report/small.html", [("If-Modified-Since", "Tue, 15 Nov 1994 08:12:31 GMT")]),
    ("GET", "/scoutsuite-report/small.html", [("If-Modified-Since", "Thu, 01 Jan 2099 00:00:00 GMT")]),
    ("GET", "/scoutsuite-report/small.html", [("If-Modified-Since", "garbage")]),
    ("GET", "/scoutsuite-report/big.txt", [("Range", "bytes=0-9")]),
    ("GET", "/scoutsuite-report/big.txt", [("Range", "bytes=-5")]),
    ("GET", "/scoutsuite-report/big.txt", [("Range", "bytes=79990-")]),
    ("GET", "/scoutsuite-report/big.txt", [("Range", "bytes=90000-")]),
    ("GET", "/scoutsuite-report/big.txt", [("Range", "items=0-1")]),
    ("GET", "/scoutsuite-report/big.txt", [("Range", "bytes=5-1")]),
    ("GET", "/scoutsuite-report/big.txt", [("Range", "bytes=0-1"), ("If-Range", '"nope"')]),
    ("GET", "/scoutsuite-report/big.txt", [("Range", "bytes=0-1"), ("If-Range", "ETAG")]),
    ("HEAD", "/scoutsuite-report/big.txt", [("Range", "bytes=0-1")]),
    ("POST", "/scoutsuite-report/index.html", []),
    ("DELETE", "/scoutsuite-report/missing", []),
    ("OPTIONS", "/scoutsuite-report/index.html", []),
]


def static_tree(root):
    """The files of the vectors under `root/scoutsuite-report`, with their modification times."""
    base = os.path.join(root, "scoutsuite-report")
    os.makedirs(base, exist_ok=True)
    for name, (content, mtime) in STATIC_FILES.items():
        path = os.path.join(base, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(content.encode("latin-1") if name == "image.png" else content.encode("utf-8"))
        os.utime(path, (mtime, mtime))
    outside = os.path.join(root, "outside.txt")
    with open(outside, "w") as f:
        f.write("outside\n")
    link = os.path.join(base, "outside-link")
    if not os.path.lexists(link):
        os.symlink(outside, link)
    return base


def static_vectors(app):
    import hashlib
    from email.utils import formatdate

    root = tempfile.mkdtemp(prefix="gen-standalone-static-")
    static_tree(root)
    small = os.stat(os.path.join(root, "scoutsuite-report", "small.html"))
    big = os.stat(os.path.join(root, "scoutsuite-report", "big.txt"))

    def etag(st):
        return '"' + hashlib.md5((str(st.st_mtime) + "-" + str(st.st_size)).encode(), usedforsecurity=False).hexdigest() + '"'

    subst = {
        "ETAG": etag(small),
        "LASTMOD": formatdate(small.st_mtime, usegmt=True),
    }
    out = []
    cwd = os.getcwd()
    os.chdir(root)
    try:
        for method, path, headers in STATIC_REQUESTS:
            hdrs = []
            for k, v in headers:
                for key, value in subst.items():
                    v = v.replace(key, subst[key] if not (path.endswith("big.txt") and key == "ETAG") else etag(big))
                hdrs.append((k, v))
            status, resp_headers, body = asyncio.run(asgi_call(app, method, path, hdrs))
            resp_headers = [(k, v) for k, v in resp_headers if k not in ("x-process-time-ms", "x-request-id")]
            gz = any(k == "content-encoding" and v == "gzip" for k, v in resp_headers)
            if gz:
                body = gzip.decompress(body)
                resp_headers = [(k, "*" if k == "content-length" else v) for k, v in resp_headers]
            ctype = dict(resp_headers).get("content-type", "")
            if ctype.startswith("multipart/byteranges"):
                boundary = ctype.split("boundary=", 1)[1]
                body = body.replace(boundary.encode(), b"BOUNDARY")
                resp_headers = [(k, v.replace(boundary, "BOUNDARY")) for k, v in resp_headers]
            out.append(
                {
                    "method": method,
                    "path": path,
                    "headers": hdrs,
                    "status": status,
                    "response_headers": resp_headers,
                    "body": body.decode("latin-1"),
                },
            )
    finally:
        os.chdir(cwd)
    return {"files": {k: [v[0], v[1]] for k, v in STATIC_FILES.items()}, "requests": out}


def build():
    """Every generated file, by its path under `OUT`."""
    app = load_app()
    data = app_json(app)
    vectors = {
        "routing": routing_vectors(app, data["routes"]),
        "cors": cors_vectors(),
        "parsedate": parsedate_vectors(),
        "static": static_vectors(app),
    }
    return {
        "app.json": json.dumps(data, indent=1, ensure_ascii=False) + "\n",
        "openapi.json": openapi_body(app),
        "standalone_vectors.json": json.dumps(vectors, indent=None, ensure_ascii=False, separators=(",", ":")) + "\n",
    }


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in build().items():
        (OUT / name).write_text(text, encoding="utf-8")
        print(f"wrote {OUT / name} ({len(text.encode())} bytes)")


if __name__ == "__main__":
    main()
