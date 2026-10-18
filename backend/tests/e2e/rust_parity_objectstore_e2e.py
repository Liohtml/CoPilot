"""Parity of the Rust MinIO routes (`crates/copilot-objectstore`, `copilot-incidents`' datastore
module) with this backend — NOT collected by pytest (needs a live MySQL and the Rust binary; run by
scripts/rust-parity.sh).

The real FastAPI routers (in-process) and a Rust instance this suite starts (no legacy backend)
answer the same requests on one database. MinIO is a local stand-in (`S3StandIn`): in-memory buckets,
the S3 calls miniopy-async makes (bucket location, head/create bucket, put/head/get/delete object,
multipart uploads, ListObjectsV2 with `encoding-type=url`), MinIO's XML errors and its rule of
ignoring a `Range` it cannot parse, plus injected faults (5xx answers, non-XML errors). It verifies
every request's SigV4 signature with the shared secret and records it.

For each check the suite compares the status, the response bytes (and, for downloads, the
`Content-Type`, `Content-Disposition`, `Content-Length`, `Content-Encoding` headers and the
`Accept-Encoding` of `Vary`;
the Python app carries copilot.py's `GZipMiddleware`, which gzips every streamed download a
browser asks for, and a gzipped body is compared decoded, as its header holds the time), the
stand-in's contents
afterwards, and every request each backend sent to it: method, path, query, the headers
(`Authorization` reduced to its scope region and signed-header list, `x-amz-date` dropped), the
payload hash, the body's hash and whether the signature verified. Signatures themselves carry the
request time, so they are verified, not compared. Python's download `Range` names the address of an
aiohttp session (`bytes=<aiohttp.client.ClientSession object at 0x…>-`); the address is masked.
The multipart parts go out three at a time, so their order is not compared.

Python dials `MINIO_URL:9000` whatever the environment; this suite points its `create_session()`
at the stand-in (in-process, the one change it makes to Python) and the Rust instance through
`COPILOT_MINIO_ENDPOINT` (tests only). A second Rust instance points at a closed port for the
unreachable-MinIO checks.

Writes run on twin rows (a case, a file, a report for each backend: ids and the keys built from them
are normalised) or on one row restored between the two backends. Ids are explicit, seven digits or
more, in disjoint ranges. Deliberate differences: none (RUST_MIGRATION.md §4 lists the cases the
stand-in cannot provoke).

    PARITY_SUITES=tests/e2e/rust_parity_objectstore_e2e.py scripts/rust-parity.sh
"""

import asyncio
import base64
import datetime
import hashlib
import hmac
import io
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qsl
from urllib.parse import quote
from urllib.parse import unquote

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "e2epass")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "e2eroot")
os.environ.setdefault("JWT_SECRET", "e2e-test-secret-not-the-default")

import httpx  # noqa: E402
import jwt  # noqa: E402
from fastapi import APIRouter  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from fastapi.middleware.gzip import GZipMiddleware  # noqa: E402
from miniopy_async import Minio  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.db_session import sync_engine  # noqa: E402

SFX = uuid.uuid4().hex[:6]
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
# Ports: the Rust instances and the stand-in (5775-5778; nothing listens on S3_CLOSED_PORT).
RS_PORT = int(os.environ.get("OBJECTSTORE_PARITY_RUST_PORT", "5775"))
S3_PORT = int(os.environ.get("S3_STUB_PORT", "5776"))
RS_DOWN_PORT = int(os.environ.get("OBJECTSTORE_PARITY_RUST_DOWN_PORT", "5777"))
S3_CLOSED_PORT = int(os.environ.get("S3_CLOSED_PORT", "5778"))
S3_USER, S3_SECRET = "minio-parity", "minio-parity-secret"
CUST_A, CUST_B = f"OBJ_A{SFX}", f"OBJ_B{SFX}"
ADMIN, ANALYST, PORTAL = f"obj_admin{SFX}", f"obj_analyst{SFX}", f"obj_portal{SFX}"
NOBODY, ANALYST_B = f"obj_nobody{SFX}", f"obj_analyst_b{SFX}"
P = "/api/incidents/db_operations"
CR = "/api/incidents/customer_reports"
DS = "/api/agent_data_store"
results = []


def check(name, passed, detail=""):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not passed else ""))


def token(username, scopes, **extra):
    now = datetime.datetime.utcnow()
    claims = {"exp": now + datetime.timedelta(hours=1), "iat": now, "sub": username, "scopes": scopes, **extra}
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")


def sql(statement, **params):
    with sync_engine.begin() as conn:
        return conn.execute(text(statement), params)


def rows(statement, **params):
    with sync_engine.connect() as conn:
        return [dict(r._mapping) for r in conn.execute(text(statement), params)]


# --- The MinIO stand-in -----------------------------------------------------------------------------

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
REQUEST_ID = "18A2F7C3D4E5F601"
HOST_ID = "dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8"
MESSAGES = {
    "NoSuchBucket": "The specified bucket does not exist",
    "NoSuchKey": "The specified key does not exist.",
    "NoSuchUpload": "The specified multipart upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
    "BucketAlreadyOwnedByYou": "Your previous request to create the named bucket succeeded and you already own it.",
    "SignatureDoesNotMatch": "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
    "InternalError": "We encountered an internal error, please try again.",
}


def go_xml_escape(s):
    """encoding/xml's EscapeText, as MinIO writes text."""
    table = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&#34;", "'": "&#39;", "\t": "&#x9;", "\n": "&#xA;", "\r": "&#xD;"}
    return "".join(table.get(ch, ch) for ch in s)


def s3_url_encode(s):
    """MinIO's s3URLEncode (encoding-type=url): space as `+`, `-_./*` and alphanumerics kept."""
    out = []
    for b in s.encode("utf-8"):
        c = chr(b)
        if c.isascii() and (c.isalnum() or c in "-_./*"):
            out.append(c)
        elif c == " ":
            out.append("+")
        else:
            out.append("%%%02X" % b)
    return "".join(out)


class Obj:
    def __init__(self, data, content_type, etag=None):
        self.data = data
        self.content_type = content_type
        self.etag = etag or hashlib.md5(data).hexdigest()


class S3StandIn:
    def __init__(self, access_key, secret_key):
        self.access_key, self.secret_key = access_key, secret_key
        self.lock = threading.Lock()
        self.buckets, self.regions, self.uploads, self.requests, self.faults = {}, {}, {}, [], []
        self.page_size = None

    # state
    def snapshot(self):
        with self.lock:
            return (
                {b: {k: (o.data, o.content_type, o.etag) for k, o in objs.items()} for b, objs in self.buckets.items()},
                dict(self.regions),
            )

    def restore(self, snap):
        buckets, regions = snap
        with self.lock:
            self.buckets = {b: {k: Obj(d, ct, e) for k, (d, ct, e) in objs.items()} for b, objs in buckets.items()}
            self.regions, self.uploads, self.faults = dict(regions), {}, []

    def put(self, bucket, key, data, content_type="application/octet-stream"):
        with self.lock:
            self.buckets.setdefault(bucket, {})[key] = Obj(data, content_type)

    def drop(self, bucket, key=None):
        with self.lock:
            if key is None:
                self.buckets.pop(bucket, None)
            else:
                self.buckets.get(bucket, {}).pop(key, None)

    def make_bucket(self, bucket, region=""):
        with self.lock:
            self.buckets.setdefault(bucket, {})
            self.regions[bucket] = region

    def fault(self, predicate, response, count=1):
        with self.lock:
            self.faults.append([predicate, count, response])

    def take(self):
        with self.lock:
            out, self.requests = self.requests, []
        return out

    # signature
    def verify(self, method, raw_path, raw_query, headers):
        auth = headers.get("authorization")
        if auth is None:
            return "anonymous"
        m = re.fullmatch(
            r"AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([^/]+)/s3/aws4_request, SignedHeaders=([^,]+), Signature=([0-9a-f]{64})",
            auth,
        )
        if not m:
            return "malformed"
        access, date, region, signed, signature = m.groups()
        if access != self.access_key:
            return "unknown access key"
        pairs = sorted(p.split("=") for p in raw_query.split("&")) if raw_query else [[""]]
        canonical_query = "&".join("=".join(p) for p in pairs)
        lines = []
        for name in signed.split(";"):
            value = headers.get(name)
            if value is None:
                return f"signed header {name} not sent"
            lines.append(f"{name}:{re.sub(' +', ' ', value).strip()}")
        payload = headers.get("x-amz-content-sha256", "")
        canonical = f"{method}\n{raw_path or '/'}\n{canonical_query}\n" + "\n".join(lines) + f"\n\n{signed}\n{payload}"
        amz_date = headers.get("x-amz-date", "")
        if not amz_date.startswith(date):
            return "date mismatch"
        scope = f"{date}/{region}/s3/aws4_request"
        to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
        key = ("AWS4" + self.secret_key).encode()
        for part in (date, region, "s3", "aws4_request"):
            key = hmac.new(key, part.encode(), hashlib.sha256).digest()
        expected = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
        return "ok" if hmac.compare_digest(expected, signature) else "bad signature"

    # dispatch
    def error(self, status, code, resource, bucket=None, key=None, head=False):
        if head:
            return status, {}, b""
        parts = [f"<Code>{code}</Code><Message>{go_xml_escape(MESSAGES.get(code, code))}</Message>"]
        if key:
            parts.append(f"<Key>{go_xml_escape(key)}</Key>")
        if bucket:
            parts.append(f"<BucketName>{go_xml_escape(bucket)}</BucketName>")
        parts.append(f"<Resource>{go_xml_escape(resource)}</Resource><RequestId>{REQUEST_ID}</RequestId><HostId>{HOST_ID}</HostId>")
        body = ('<?xml version="1.0" encoding="UTF-8"?>\n<Error>' + "".join(parts) + "</Error>").encode()
        return status, {"Content-Type": "application/xml"}, body

    def handle(self, method, raw_path, raw_query, headers, body):
        record = {
            "method": method,
            "path": raw_path,
            "query": raw_query,
            "headers": headers,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "signature": self.verify(method, raw_path, raw_query, headers),
        }
        with self.lock:
            self.requests.append(record)
            for f in self.faults:
                predicate, count, response = f
                if count > 0 and predicate(method, raw_path, raw_query):
                    f[1] -= 1
                    return response
        if record["signature"] not in ("ok", "anonymous"):
            return self.error(403, "SignatureDoesNotMatch", unquote(raw_path), head=method == "HEAD")
        sent = headers.get("x-amz-content-sha256")
        if sent and sent != "UNSIGNED-PAYLOAD" and sent != record["body_sha256"]:
            return self.error(400, "XAmzContentSHA256Mismatch", unquote(raw_path), head=method == "HEAD")
        with self.lock:
            return self.dispatch(method, raw_path, raw_query, headers, body)

    def dispatch(self, method, raw_path, raw_query, headers, body):
        path = unquote(raw_path)
        query = dict(parse_qsl(raw_query, keep_blank_values=True))
        head = method == "HEAD"
        bucket, _, key = path[1:].partition("/")
        base = {"x-amz-request-id": REQUEST_ID, "x-amz-id-2": HOST_ID, "Server": "MinIO"}

        def answer(status, hdrs, data):
            return status, {**base, **hdrs}, data

        objs = self.buckets.get(bucket)
        if not key:
            if method == "PUT" and not query:
                if objs is not None:
                    return answer(*self.error(409, "BucketAlreadyOwnedByYou", path, bucket=bucket))
                self.buckets[bucket], self.regions[bucket] = {}, ""
                return answer(200, {"Location": "/" + bucket}, b"")
            if objs is None:
                return answer(*self.error(404, "NoSuchBucket", path, bucket=bucket, head=head))
            if method == "GET" and "location" in query:
                xml = f'<?xml version="1.0" encoding="UTF-8"?>\n<LocationConstraint xmlns="{NS}">{self.regions.get(bucket, "")}</LocationConstraint>'
                return answer(200, {"Content-Type": "application/xml"}, xml.encode())
            if head:
                return answer(200, {}, b"")
            if method == "GET" and query.get("list-type") == "2":
                return answer(200, {"Content-Type": "application/xml"}, self.list_v2(bucket, objs, query))
            return answer(*self.error(501, "NotImplemented", path, bucket=bucket))
        if objs is None:
            return answer(*self.error(404, "NoSuchBucket", path, bucket=bucket, head=head))
        if method == "POST" and "uploads" in query:
            upload_id = uuid.uuid4().hex
            self.uploads[upload_id] = {"key": key, "content_type": headers.get("content-type"), "parts": {}}
            xml = (
                f'<?xml version="1.0" encoding="UTF-8"?>\n<InitiateMultipartUploadResult xmlns="{NS}"><Bucket>{go_xml_escape(bucket)}</Bucket>'
                f"<Key>{go_xml_escape(key)}</Key><UploadId>{upload_id}</UploadId></InitiateMultipartUploadResult>"
            )
            return answer(200, {"Content-Type": "application/xml"}, xml.encode())
        if "uploadId" in query:
            up = self.uploads.get(query["uploadId"])
            if up is None:
                return answer(*self.error(404, "NoSuchUpload", path, bucket=bucket, key=key))
            if method == "PUT":
                up["parts"][int(query["partNumber"])] = body
                return answer(200, {"ETag": '"' + hashlib.md5(body).hexdigest() + '"'}, b"")
            if method == "DELETE":
                del self.uploads[query["uploadId"]]
                return answer(204, {}, b"")
            numbers = [int(n) for n in re.findall(rb"<PartNumber>(\d+)</PartNumber>", body)]
            data = b"".join(up["parts"][n] for n in numbers)
            etag = hashlib.md5(b"".join(hashlib.md5(up["parts"][n]).digest() for n in numbers)).hexdigest() + f"-{len(numbers)}"
            objs[key] = Obj(data, up["content_type"] or "application/octet-stream", etag)
            del self.uploads[query["uploadId"]]
            xml = (
                f'<?xml version="1.0" encoding="UTF-8"?>\n<CompleteMultipartUploadResult xmlns="{NS}"><Location>http://{headers.get("host")}'
                f"/{go_xml_escape(bucket)}/{go_xml_escape(key)}</Location><Bucket>{go_xml_escape(bucket)}</Bucket><Key>{go_xml_escape(key)}</Key>"
                f"<ETag>&#34;{etag}&#34;</ETag></CompleteMultipartUploadResult>"
            )
            return answer(200, {"Content-Type": "application/xml"}, xml.encode())
        if method == "PUT":
            objs[key] = Obj(body, headers.get("content-type") or "binary/octet-stream")
            return answer(200, {"ETag": '"' + objs[key].etag + '"'}, b"")
        if method == "DELETE":
            objs.pop(key, None)
            return answer(204, {}, b"")
        obj = objs.get(key)
        if obj is None:
            return answer(*self.error(404, "NoSuchKey", path, bucket=bucket, key=key, head=head))
        meta = {"Content-Type": obj.content_type, "ETag": '"' + obj.etag + '"', "Last-Modified": formatdate(1767323045, usegmt=True)}
        if head:
            return answer(200, {**meta, "Content-Length": str(len(obj.data))}, b"")
        rng = self.parse_range(headers.get("range"), len(obj.data))
        if rng is None:
            return answer(200, meta, obj.data)
        start, end = rng
        return answer(206, {**meta, "Content-Range": f"bytes {start}-{end}/{len(obj.data)}"}, obj.data[start : end + 1])

    @staticmethod
    def parse_range(value, size):
        """MinIO's parseRequestRangeSpec: what does not parse is ignored (a plain GET)."""
        if not value or not value.startswith("bytes="):
            return None
        first, sep, last = value[6:].partition("-")
        if not sep or not (first.isdigit() or first == "") or not (last.isdigit() or last == "") or (first == last == ""):
            return None
        if first == "":
            return (max(size - int(last), 0), size - 1)
        return (int(first), min(int(last) if last else size - 1, size - 1))

    def list_v2(self, bucket, objs, query):
        prefix, delimiter = query.get("prefix", ""), query.get("delimiter", "")
        max_keys = int(query.get("max-keys", "1000"))
        page = min(max_keys, self.page_size or max_keys)
        token = query.get("continuation-token")
        start = base64.b64decode(token).decode() if token else query.get("start-after", "")
        entries, prefixes = [], set()
        for k in sorted(objs):
            if not k.startswith(prefix) or k <= start:
                continue
            rest = k[len(prefix) :]
            if delimiter and delimiter in rest:
                cp = prefix + rest[: rest.index(delimiter) + len(delimiter)]
                if cp not in prefixes and cp > start:
                    prefixes.add(cp)
                    entries.append(("prefix", cp))
            else:
                entries.append(("key", k))
        truncated = len(entries) > page
        entries = entries[:page]
        enc = s3_url_encode if query.get("encoding-type") == "url" else (lambda s: s)
        parts = [
            f'<?xml version="1.0" encoding="UTF-8"?>\n<ListBucketResult xmlns="{NS}"><Name>{go_xml_escape(bucket)}</Name>'
            f"<Prefix>{go_xml_escape(enc(prefix))}</Prefix><KeyCount>{len(entries)}</KeyCount><MaxKeys>{max_keys}</MaxKeys>",
        ]
        if delimiter:
            parts.append(f"<Delimiter>{go_xml_escape(enc(delimiter))}</Delimiter>")
        if query.get("encoding-type") == "url":
            parts.append("<EncodingType>url</EncodingType>")
        parts.append(f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>")
        if token:
            parts.append(f"<ContinuationToken>{token}</ContinuationToken>")
        if truncated:
            parts.append(f"<NextContinuationToken>{base64.b64encode(entries[-1][1].encode()).decode()}</NextContinuationToken>")
        for kind, name in entries:
            if kind == "key":
                o = objs[name]
                parts.append(
                    f"<Contents><Key>{go_xml_escape(enc(name))}</Key><LastModified>2026-01-02T03:04:05.000Z</LastModified>"
                    f"<ETag>&#34;{o.etag}&#34;</ETag><Size>{len(o.data)}</Size><StorageClass>STANDARD</StorageClass></Contents>",
                )
        for kind, name in entries:
            if kind == "prefix":
                parts.append(f"<CommonPrefixes><Prefix>{go_xml_escape(enc(name))}</Prefix></CommonPrefixes>")
        parts.append("</ListBucketResult>")
        return "".join(parts).encode()

    def serve(self, port):
        standin = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _any(self):
                raw_path, _, raw_query = self.path.partition("?")
                headers = {k.lower(): v for k, v in self.headers.items()}
                if "chunked" in headers.get("transfer-encoding", ""):
                    body = b""
                    while True:
                        size = int(self.rfile.readline().strip(), 16)
                        if size == 0:
                            self.rfile.readline()
                            break
                        body += self.rfile.read(size)
                        self.rfile.readline()
                else:
                    body = self.rfile.read(int(headers.get("content-length") or 0))
                response = standin.handle(self.command, raw_path, raw_query, headers, body)
                status, hdrs, data = response
                self.send_response(status)
                for k, v in hdrs.items():
                    if k.lower() != "content-length":
                        self.send_header(k, v)
                if self.command == "HEAD":
                    if "Content-Length" in hdrs:
                        self.send_header("Content-Length", hdrs["Content-Length"])
                elif status not in (204, 304):
                    self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if self.command != "HEAD" and status not in (204, 304):
                    self.wfile.write(data)

            do_GET = do_PUT = do_POST = do_DELETE = do_HEAD = _any

        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server


S3 = S3StandIn(S3_USER, S3_SECRET)
# Where Python's `create_session()` dials (the stand-in, or the closed port).
PY_TARGET = {"port": S3_PORT}


def patch_python_minio():
    from app.data_store import data_store_operations
    from app.data_store import data_store_session

    async def create_session():
        return Minio(f"127.0.0.1:{PY_TARGET['port']}", access_key=S3_USER, secret_key=S3_SECRET, secure=False)

    data_store_operations.create_session = create_session
    # The Sysmon upload's existence check imports it from here at call time.
    data_store_session.create_session = create_session


# --- Normalisation ----------------------------------------------------------------------------------

ADDRESS = re.compile(r"object at 0x[0-9a-f]+")
CREDENTIAL = re.compile(r"Credential=[^/]+/\d{8}/([^/]+)/s3/aws4_request, SignedHeaders=([^,]+), Signature=[0-9a-f]{64}")


def substitute(value, subst):
    for old, new in subst:
        value = value.replace(old, new)
    return value


def outbound(records, subst=()):
    """The stand-in's records, comparable across the two backends."""
    out = []
    for r in records:
        headers = dict(r["headers"])
        auth = headers.pop("authorization", None)
        headers.pop("x-amz-date", None)
        if "range" in headers:
            headers["range"] = ADDRESS.sub("object at 0x…", headers["range"])
        signed = None
        if auth is not None:
            m = CREDENTIAL.search(auth)
            signed = m.groups() if m else ("unparsed", auth)
        query = re.sub(r"uploadId=[0-9a-f]+", "uploadId=<id>", r["query"])
        headers = tuple(sorted((k, substitute(v, subst)) for k, v in headers.items()))
        out.append(
            (r["method"], substitute(r["path"], subst), substitute(query, subst), headers, signed, r["body_sha256"], r["signature"]),
        )
    # The parts of a multipart upload go out three at a time.
    parts = sorted(i for i, o in enumerate(out) if "partNumber=" in o[2])
    if parts:
        block = sorted((out[i] for i in parts), key=lambda o: o[2])
        for i, o in zip(parts, block):
            out[i] = o
    return out


def changes(start, end, subst=()):
    """What a run changed in the stand-in: buckets created or removed, objects written or deleted."""
    (b0, _), (b1, r1) = start, end
    out = set()
    for bucket in set(b0) | set(b1):
        if bucket not in b0:
            out.add(("bucket created", bucket, r1.get(bucket)))
        if bucket not in b1:
            out.add(("bucket removed", bucket))
        before, after = b0.get(bucket, {}), b1.get(bucket, {})
        for key in set(before) | set(after):
            if key not in after:
                out.add(("deleted", bucket, substitute(key, subst)))
            elif before.get(key) != after[key]:
                data, ctype, _ = after[key]
                out.add(("written", bucket, substitute(key, subst), hashlib.sha256(data).hexdigest(), ctype))
    return sorted(out, key=repr)


VOLATILE = {"id", "upload_time"}


def mask(value, subst=()):
    if isinstance(value, dict):
        return {k: ("<v>" if k in VOLATILE and v is not None else mask(v, subst)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask(v, subst) for v in value]
    if isinstance(value, str):
        return substitute(value, subst)
    if isinstance(value, int) and not isinstance(value, bool):
        return next((new for old, new in subst if old == str(value)), value)
    return value


def body_of(r):
    try:
        return r.json()
    except ValueError:
        return r.content


DOWNLOAD_HEADERS = ("content-type", "content-disposition", "content-length", "content-encoding", "vary")


def download_headers(r):
    """The download headers; of `Vary` its `Accept-Encoding` (the Rust CORS layer adds `Origin, …` to
    every response, for every route: not this module's)."""
    out = {k: r.headers.get(k) for k in DOWNLOAD_HEADERS}
    out["vary"] = [v.strip() for v in (out["vary"] or "").split(",") if v.strip().lower() == "accept-encoding"]
    return out


# What a browser sends: Starlette gzips every streamed download it asks for.
BROWSER = {"headers": {"Accept-Encoding": "gzip, deflate, br"}}


# --- The two backends -------------------------------------------------------------------------------


def build_python_app():
    from app.middleware.exception_handlers import custom_http_exception_handler
    from app.middleware.exception_handlers import validation_exception_handler
    from app.middleware.exception_handlers import value_error_handler
    from app.routers import active_response
    from app.routers import data_store
    from app.routers import incidents

    api = APIRouter(prefix="/api")
    api.include_router(incidents.router)
    api.include_router(data_store.router)
    api.include_router(active_response.router)
    app = FastAPI(redirect_slashes=False)
    app.include_router(api)
    # As in copilot.py: it decides how a download is encoded.
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_exception_handler(HTTPException, custom_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    return app


def start_rust(port, s3_port):
    binary = os.environ.get("COPILOT_BIN", os.path.join(REPO, "target", "debug", "copilot"))
    user, password, host = os.environ["MYSQL_USER"], os.environ["MYSQL_PASSWORD"], os.environ["MYSQL_URL"]
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/tmp"),
        "COPILOT_DATABASE_URL": f"mysql://{user}:{password}@{host}/copilot",
        "JWT_SECRET": os.environ["JWT_SECRET"],
        "COPILOT_BIND": "127.0.0.1",
        # The catalog caches load on demand, as this Python side never warms them.
        "COPILOT_CATALOG_REFRESH": "false",
        "COPILOT_PORT": str(port),
        "MINIO_ROOT_USER": S3_USER,
        "MINIO_ROOT_PASSWORD": S3_SECRET,
        "COPILOT_MINIO_ENDPOINT": f"127.0.0.1:{s3_port}",
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
    }
    proc = subprocess.Popen([binary, "--root", "/nonexistent", "serve"], env=env)
    for _ in range(100):
        try:
            if httpx.get(f"http://127.0.0.1:{port}/_copilot/health", timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError("the Rust instance did not start")


class Pair:
    def __init__(self):
        self.py = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_python_app(), raise_app_exceptions=False),
            base_url="http://py",
            timeout=120,
        )
        self.rs = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_PORT}", timeout=120)
        self.rs_down = httpx.AsyncClient(base_url=f"http://127.0.0.1:{RS_DOWN_PORT}", timeout=120)

    async def call(self, client, method, path, tok, **kw):
        headers = {"Accept-Encoding": "identity", **dict(kw.pop("headers", {}))}
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        S3.take()
        try:
            r = await client.request(method, path, headers=headers, **kw)
        except httpx.ConnectError:
            # Name what happened to the instance rather than a bare connection error.
            codes = [proc.poll() for proc in PROCS]
            raise RuntimeError(f"a Rust instance is gone (exit codes {codes}; a negative code is the signal)")
        await asyncio.sleep(0.05)
        return r, S3.take()

    async def same(
        self,
        name,
        method,
        path,
        tok=None,
        rs_path=None,
        before=None,
        between=None,
        subst=((), ()),
        masked=False,
        state=True,
        down=False,
        db=None,
        **kw,
    ):
        """Python, then Rust: `before` prepares both runs, `between` undoes Python's writes, `subst`
        names (old, marker) pairs per side for twin rows, `db` reads the rows a write leaves."""
        S3.faults = []
        if before:
            before()
        start = S3.snapshot()
        PY_TARGET["port"] = S3_CLOSED_PORT if down else S3_PORT
        r1, out1 = await self.call(self.py, method, path, tok, **kw)
        PY_TARGET["port"] = S3_PORT
        end1 = S3.snapshot()
        rows1 = db("p") if db else None
        if between:
            between()
        S3.restore(start)
        if before:
            before()
        client = self.rs_down if down else self.rs
        r2, out2 = await self.call(client, method, rs_path or path, tok, **kw)
        end2 = S3.snapshot()
        rows2 = db("r") if db else None
        sp, sr = subst
        b1, b2 = body_of(r1), body_of(r2)
        if isinstance(b1, (dict, list)):
            b1 = mask(b1, sp) if masked else json.loads(substitute(json.dumps(b1), sp))
        if isinstance(b2, (dict, list)):
            b2 = mask(b2, sr) if masked else json.loads(substitute(json.dumps(b2), sr))
        if isinstance(b1, bytes) and isinstance(b2, bytes):
            b1, b2 = substitute(b1.decode("latin-1"), sp), substitute(b2.decode("latin-1"), sr)
        ok = r1.status_code == r2.status_code and b1 == b2
        detail = f"python {r1.status_code} {str(b1)[:700]}\n        rust   {r2.status_code} {str(b2)[:700]}"
        if r1.status_code == 200 and r1.headers.get("content-type") != "application/json":
            h1, h2 = download_headers(r1), download_headers(r2)
            if h1 != h2:
                ok = False
                detail += f"\n        headers python {h1}\n        headers rust   {h2}"
        o1, o2 = outbound(out1, sp), outbound(out2, sr)
        if o1 != o2:
            ok = False
            first = next((i for i, (x, y) in enumerate(zip(o1, o2)) if x != y), min(len(o1), len(o2)))
            detail += f"\n        outbound #{first} of {len(o1)}/{len(o2)}\n        python {o1[first:first + 2]}\n        rust   {o2[first:first + 2]}"
        if not down and state and changes(start, end1, sp) != changes(start, end2, sr):
            ok = False
            detail += f"\n        minio python {changes(start, end1, sp)}\n        minio rust   {changes(start, end2, sr)}"
        if db and mask(rows1, sp) != mask(rows2, sr):
            ok = False
            detail += f"\n        rows python {mask(rows1, sp)}\n        rows rust   {mask(rows2, sr)}"
        if any(o[-1] not in ("ok",) for o in o1 + o2):
            ok = False
            detail += f"\n        signatures python {[o[-1] for o in o1]} rust {[o[-1] for o in o2]}"
        check(f"{name} [{r1.status_code}]", ok, detail)
        if os.environ.get("PARITY_VERBOSE"):
            print(f"        {str(b1)[:300]}\n        outbound {[(o[0], o[1], o[2]) for o in o1]}")
        return r1, r2

    async def close(self):
        await self.py.aclose()
        await self.rs.aclose()
        await self.rs_down.aclose()


# --- Seed -------------------------------------------------------------------------------------------

IDS = {}
USERS = {}
PROCS = []


def multipart(fields=(), files=(), boundary="parityboundary"):
    """A multipart body: `fields` (name, value), `files` (name, filename, content type or None, data)."""
    out = b""
    for name, value in fields:
        out += f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode() + value.encode() + b"\r\n"
    for name, filename, ctype, data in files:
        out += f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode("utf-8")
        if ctype:
            out += f"Content-Type: {ctype}\r\n".encode()
        out += b"\r\n" + data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return {"content": out, "headers": {"Content-Type": f"multipart/form-data; boundary={boundary}"}}


def docx_bytes(marker):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", f"<w:document>{marker}</w:document>")
    return buf.getvalue()


def seed():
    top = 0
    for table in (
        "incident_management_case",
        "incident_management_case_datastore",
        "incident_management_case_report_template_datastore",
        "incident_management_customer_reports",
        "agent_datastore",
        "incident_management_alert",
    ):
        top = max(top, rows(f"SELECT COALESCE(MAX(id), 0) AS n FROM {table}")[0]["n"])
    base = max(top + 100, 1_000_000)
    # Disjoint ranges: cases base+1000.., files base+2000.., reports base+3000.., artifacts base+4000.., alerts base+5000...
    IDS.update({"case": base + 1000, "file": base + 2000, "report": base + 3000, "artifact": base + 4000, "alert": base + 5000})
    for c in (CUST_A, CUST_B):
        sql("INSERT INTO customers (customer_code, customer_name, created_at) VALUES (:c, :c, UTC_TIMESTAMP())", c=c)
    for name, role in ((ADMIN, 1), (ANALYST, 2), (PORTAL, 4), (NOBODY, 2), (ANALYST_B, 2)):
        sql(
            "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (:n, 'x', 'o@example.com', UTC_TIMESTAMP(), :r)",
            n=name,
            r=role,
        )
        USERS[name] = rows("SELECT id FROM `user` WHERE username = :n", n=name)[0]["id"]
    for name, code in ((ANALYST, CUST_A), (PORTAL, CUST_A), (ANALYST_B, CUST_B)):
        sql("INSERT INTO user_customer_access (user_id, customer_code, created_at) VALUES (:u, :c, UTC_TIMESTAMP())", u=USERS[name], c=code)
    for c in (CUST_A, CUST_B):
        for i in range(2):
            sql(
                "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, velociraptor_id, "
                "wazuh_agent_version, wazuh_agent_status, customer_code, quarantined) VALUES (:a, '10.0.0.1', 'linux', :h, 'l', 0, "
                "UTC_TIMESTAMP(), 'C.1', 'v4', 'active', :c, 0)",
                a=f"{c}-ag{i}",
                h=f"{c}-host{i}",
                c=c,
            )


def new_id(kind):
    IDS[kind] += 1
    return IDS[kind]


def add_case(customer, name="case"):
    cid = new_id("case")
    sql(
        "INSERT INTO incident_management_case (id, case_name, case_description, case_creation_time, case_status, customer_code, "
        "notification_invoked_number, escalated) VALUES (:i, :n, 'd', '2026-01-02 03:04:05', 'OPEN', :c, 0, 0)",
        i=cid,
        n=f"{name}{SFX}",
        c=customer,
    )
    return cid


def add_file(case_id, file_name, content_type="text/plain", bucket="copilot-cases", key=None, data=b"file body"):
    # The uploads insert rows here too, so these ids are MySQL's (none of them appears in a text).
    key = key or f"{case_id}/{file_name}"
    return sql(
        "INSERT INTO incident_management_case_datastore (case_id, bucket_name, object_key, file_name, content_type, file_size, "
        "upload_time, file_hash) VALUES (:c, :b, :k, :f, :t, :s, '2026-01-02 03:04:05', :h)",
        c=case_id,
        b=bucket,
        k=key,
        f=file_name,
        t=content_type,
        s=len(data),
        h=hashlib.sha256(data).hexdigest(),
    ).lastrowid


def case_rows(side_case):
    def read(side):
        cid = side_case(side)
        return {
            "case": rows("SELECT customer_code FROM incident_management_case WHERE id = :i", i=cid),
            "files": rows(
                "SELECT case_id, bucket_name, object_key, file_name, content_type, file_size, file_hash FROM "
                "incident_management_case_datastore WHERE case_id = :i ORDER BY id",
                i=cid,
            ),
            "comments": rows("SELECT comment FROM incident_management_case_comment WHERE case_id = :i", i=cid),
            "links": rows("SELECT COUNT(*) AS n FROM incident_management_casealertlink WHERE case_id = :i", i=cid),
            "tasks": rows("SELECT title FROM incident_management_case_task WHERE case_id = :i", i=cid),
            "events": rows("SELECT event_type FROM incident_management_case_event WHERE case_id = :i", i=cid),
            "audit": rows(
                "SELECT action, actor_username, customer_code, entity_type, entity_id, old_value, new_value FROM audit_log "
                "WHERE entity_type = 'case_file' AND JSON_EXTRACT(COALESCE(new_value, old_value), '$.case_id') = :i ORDER BY id",
                i=cid,
            ),
        }

    return read


# --- The checks -------------------------------------------------------------------------------------


async def case_file_checks(p, t):
    print("\n=== case files: download ===")
    ca, cb = add_case(CUST_A, "dl-a"), add_case(CUST_B, "dl-b")
    names = {
        "plain": ("notes.txt", "text/plain"),
        "binary": ("dump.bin", "application/octet-stream"),
        "no type": ("untyped.dat", None),
        "spaces": ("a b+c~(1).txt", "text/plain; charset=latin-1"),
        "latin-1": ("café.txt", "text/plain"),
        "not latin-1": ("€uro.txt", "text/plain"),
        "html": ("page.html", "text/html"),
        "image": ("pic.png", "image/png"),
        "event stream": ("events.txt", "text/event-stream"),
    }
    S3.make_bucket("copilot-cases")
    for label, (fname, ctype) in names.items():
        add_file(ca, fname, ctype, data=f"body of {fname}\nline two\n".encode())
        S3.put("copilot-cases", f"{ca}/{fname}", f"body of {fname}\nline two\n".encode(), ctype or "application/octet-stream")
    add_file(ca, "empty.txt", data=b"")
    S3.put("copilot-cases", f"{ca}/empty.txt", b"", "text/plain")
    add_file(cb, "b.txt")
    S3.put("copilot-cases", f"{cb}/b.txt", b"tenant b")
    add_file(ca, "orphan.txt")  # no object
    add_file(ca, "nobucket.txt", bucket=f"gone-{SFX.lower()}")
    add_file(ca, "badbucket.txt", bucket="Bad_Bucket!")
    for label, (fname, _) in names.items():
        for who in ("admin", "analyst", "portal"):
            if who != "admin" and label not in ("plain", "spaces"):
                continue
            await p.same(f"download {label} ({who})", "GET", f"{P}/case/data-store/download/{ca}/{quote(fname)}", t[who])
        await p.same(f"download {label} (browser: gzip)", "GET", f"{P}/case/data-store/download/{ca}/{quote(fname)}", t["admin"], **BROWSER)
    await p.same("download: empty file", "GET", f"{P}/case/data-store/download/{ca}/empty.txt", t["admin"])
    await p.same("download: empty file (browser: gzip)", "GET", f"{P}/case/data-store/download/{ca}/empty.txt", t["admin"], **BROWSER)
    await p.same(
        "download: gzip;q=0 still gzips (a substring test)",
        "GET",
        f"{P}/case/data-store/download/{ca}/notes.txt",
        t["admin"],
        headers={"Accept-Encoding": "gzip;q=0"},
    )
    await p.same("download: not found (browser: gzip)", "GET", f"{P}/case/data-store/download/{ca}/none.txt", t["admin"], **BROWSER)
    await p.same("download: other tenant's case (analyst)", "GET", f"{P}/case/data-store/download/{cb}/b.txt", t["analyst"])
    await p.same("download: other tenant's case (portal)", "GET", f"{P}/case/data-store/download/{cb}/b.txt", t["portal"])
    await p.same("download: unassigned analyst", "GET", f"{P}/case/data-store/download/{ca}/notes.txt", t["nobody"])
    await p.same("download: no token", "GET", f"{P}/case/data-store/download/{ca}/notes.txt")
    await p.same("download: case not an int", "GET", f"{P}/case/data-store/download/x/notes.txt", t["admin"])
    await p.same("download: case missing", "GET", f"{P}/case/data-store/download/{IDS['case'] + 500}/notes.txt", t["admin"])
    await p.same("download: no such file row", "GET", f"{P}/case/data-store/download/{ca}/none.txt", t["admin"])
    await p.same("download: name matched by collation", "GET", f"{P}/case/data-store/download/{ca}/NOTES.TXT", t["admin"])
    await p.same("download: object missing (listing, 404)", "GET", f"{P}/case/data-store/download/{ca}/orphan.txt", t["admin"])
    await p.same("download: bucket missing (bare 500)", "GET", f"{P}/case/data-store/download/{ca}/nobucket.txt", t["admin"])
    await p.same("download: invalid bucket name (400)", "GET", f"{P}/case/data-store/download/{ca}/badbucket.txt", t["admin"])
    await p.same("download: encoded slash", "GET", f"{P}/case/data-store/download/{ca}/a%2Fb.txt", t["admin"])
    await p.same("download: invalid UTF-8 escape", "GET", f"{P}/case/data-store/download/{ca}/%E9.txt", t["admin"])

    def flaky(n, status=503, code="InternalError"):
        def before():
            body = (
                f'<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>{code}</Code><Message>{MESSAGES.get(code, code)}</Message>'
                f"<Resource>/x</Resource><RequestId>{REQUEST_ID}</RequestId><HostId>{HOST_ID}</HostId></Error>"
            ).encode()
            S3.fault(
                lambda m, path, q: m == "GET" and not q and path.endswith("notes.txt"),
                (status, {"Content-Type": "application/xml"}, body),
                n,
            )

        return before

    await p.same(
        "download: two 503s, then the object (retried)",
        "GET",
        f"{P}/case/data-store/download/{ca}/notes.txt",
        t["admin"],
        before=flaky(2),
    )
    await p.same(
        "download: five 500s (gives up, 404)",
        "GET",
        f"{P}/case/data-store/download/{ca}/notes.txt",
        t["admin"],
        before=flaky(5, 500),
    )
    await p.same(
        "download: non-XML 502 on the location",
        "GET",
        f"{P}/case/data-store/download/{ca}/notes.txt",
        t["admin"],
        before=lambda: S3.fault(lambda m, path, q: q == "location=", (502, {"Content-Type": "text/html"}, b"<html>bad gateway</html>"), 1),
    )
    await p.same(
        "download: a 403 on HEAD",
        "GET",
        f"{P}/case/data-store/download/{ca}/notes.txt",
        t["admin"],
        before=lambda: S3.fault(lambda m, path, q: m == "HEAD", (403, {"x-amz-request-id": "R"}, b""), 1),
    )

    print("\n=== case files: upload ===")
    S3.make_bucket("copilot-cases")
    pair_cases = {}

    def twin(label):
        if label not in pair_cases:
            pair_cases[label] = (add_case(CUST_A, f"up-{label}-p"), add_case(CUST_A, f"up-{label}-r"))
        return pair_cases[label]

    async def upload(label, files, who="admin", existing=None, query=None, before=None, case=None, fields=()):
        cp, cr = case or twin(label)
        if existing:
            for c in (cp, cr):
                add_file(c, existing)
        qp = f"?case_id={cp}" if query is None else query.format(cp)
        qr = f"?case_id={cr}" if query is None else query.format(cr)

        def files_of(side):
            c = cp if side == "p" else cr
            return {
                "files": rows(
                    "SELECT case_id, bucket_name, object_key, file_name, content_type, file_size, file_hash FROM "
                    "incident_management_case_datastore WHERE case_id = :i ORDER BY id",
                    i=c,
                ),
                "audit": rows(
                    "SELECT action, actor_username, customer_code, entity_type, entity_id, old_value, new_value FROM audit_log "
                    "WHERE action = 'datastore.file_create' AND JSON_EXTRACT(new_value, '$.case_id') = :i",
                    i=c,
                ),
            }

        await p.same(
            f"upload {label} ({who})",
            "POST",
            f"{P}/case/data-store/upload{qp}",
            t[who],
            rs_path=f"{P}/case/data-store/upload{qr}",
            subst=(((str(cp), "<case>"),), ((str(cr), "<case>"),)),
            masked=True,
            db=files_of,
            before=before,
            **multipart(fields=fields, files=files),
        )

    await upload("text", [("file", f"report{SFX}.txt", "text/plain", b"hello world")])
    await upload("no content type", [("file", f"raw{SFX}.bin", None, b"\x00\x01\x02")])
    await upload("empty", [("file", f"empty{SFX}.txt", "text/plain", b"")])
    await upload("multipart (5 MiB + 7)", [("file", f"big{SFX}.bin", "application/zip", os.urandom(5 * 1024 * 1024 + 7))])
    await upload("portal user on their case", [("file", f"portal{SFX}.txt", "text/plain", b"from the portal")], who="portal")
    await upload("name taken", [("file", f"dupe{SFX}.txt", "text/plain", b"x")], existing=f"dupe{SFX}.txt")
    await upload("name taken (collation)", [("file", f"DUPE{SFX}.TXT", "text/plain", b"x")], existing=f"dupe{SFX}.txt")
    await upload("name of 256 characters", [("file", "n" * 252 + ".txt", "text/plain", b"x")])
    await upload("content type over 100", [("file", f"ct{SFX}.txt", "text/" + "x" * 100, b"x")])
    await upload("dot-dot segment", [("file", f"../up{SFX}.txt", "text/plain", b"x")])
    await upload("windows path", [("file", f"C:\\\\dir\\\\win{SFX}.txt", "text/plain", b"x")])
    await upload("unicode name", [("file", f"résumé-€{SFX}.txt", "text/plain", b"x")])
    await upload(
        "analyst, other tenant",
        [("file", f"x{SFX}.txt", "text/plain", b"x")],
        who="analyst",
        case=(add_case(CUST_B), add_case(CUST_B)),
    )
    await upload(
        "portal, other tenant",
        [("file", f"x{SFX}.txt", "text/plain", b"x")],
        who="portal",
        case=(add_case(CUST_B), add_case(CUST_B)),
    )
    await upload("case missing", [("file", f"x{SFX}.txt", "text/plain", b"x")], case=(IDS["case"] + 900, IDS["case"] + 901))
    await upload("no case_id", [("file", f"x{SFX}.txt", "text/plain", b"x")], query="")
    await upload("case_id not an int, no file", [], query="?case_id=x{}")
    await upload("file as a text field", [], fields=[("file", "not a file")])
    await upload("bucket missing (bare 500)", [("file", f"nob{SFX}.txt", "text/plain", b"x")], before=lambda: S3.drop("copilot-cases"))
    S3.make_bucket("copilot-cases")
    await p.same("upload: not multipart", "POST", f"{P}/case/data-store/upload?case_id=1", t["admin"], json={"file": "x"})
    await p.same(
        "upload: no boundary (400 before the token)",
        "POST",
        f"{P}/case/data-store/upload?case_id=1",
        None,
        content=b"x",
        headers={"Content-Type": "multipart/form-data"},
    )
    await p.same(
        "upload: no token",
        "POST",
        f"{P}/case/data-store/upload?case_id=1",
        None,
        **multipart(files=[("file", "a.txt", None, b"x")]),
    )
    await p.same("GET /case/data-store/upload", "GET", f"{P}/case/data-store/upload", t["admin"])

    print("\n=== case files: delete ===")

    async def delete(label, who="admin", object_missing=False, row_missing=False, tenant=CUST_A, before=None):
        cp, cr = add_case(tenant, f"del-{label}-p"), add_case(tenant, f"del-{label}-r")
        fname = f"del{SFX}.txt"
        for c in (cp, cr):
            if not row_missing:
                add_file(c, fname)
            if not object_missing:
                S3.put("copilot-cases", f"{c}/{fname}", b"to delete")
        await p.same(
            f"delete file: {label} ({who})",
            "DELETE",
            f"{P}/case/data-store/{cp}/{fname}",
            t[who],
            rs_path=f"{P}/case/data-store/{cr}/{fname}",
            subst=(((str(cp), "<case>"),), ((str(cr), "<case>"),)),
            db=case_rows(lambda side: cp if side == "p" else cr),
            before=before,
        )

    await delete("success")
    await delete("success", who="analyst")
    await delete("object missing", object_missing=True)
    await delete("row missing", row_missing=True)
    await delete("other tenant", who="analyst", tenant=CUST_B)
    await delete("portal user", who="portal")
    await delete("bucket missing", before=lambda: S3.drop("copilot-cases"))
    S3.make_bucket("copilot-cases")
    await p.same("delete file: case not an int", "DELETE", f"{P}/case/data-store/x/a.txt", t["admin"])

    print("\n=== DELETE /case/{case_id} ===")

    def full_case(tenant, label, files, missing=()):
        cid = add_case(tenant, label)
        aid = new_id("alert")
        sql(
            "INSERT INTO incident_management_alert (id, alert_name, alert_description, status, alert_creation_time, customer_code, "
            "source, escalated) VALUES (:i, 'a', 'd', 'OPEN', UTC_TIMESTAMP(), :c, 'wazuh', 0)",
            i=aid,
            c=tenant,
        )
        sql("INSERT INTO incident_management_casealertlink (case_id, alert_id) VALUES (:c, :a)", c=cid, a=aid)
        sql(
            "INSERT INTO incident_management_case_comment (case_id, comment, user_name, created_at) VALUES (:c, 'hi', 'u', UTC_TIMESTAMP())",
            c=cid,
        )
        sql(
            "INSERT INTO incident_management_case_task (case_id, title, mandatory, order_index, status, created_by, created_at, updated_at) "
            "VALUES (:c, 'task', 0, 0, 'TODO', 'u', UTC_TIMESTAMP(), UTC_TIMESTAMP())",
            c=cid,
        )
        sql(
            "INSERT INTO incident_management_case_event (case_id, event_type, actor, timestamp, payload) VALUES (:c, 'case_created', 'u', "
            "UTC_TIMESTAMP(), '{}')",
            c=cid,
        )
        for f in files:
            add_file(cid, f)
            if f not in missing:
                S3.put("copilot-cases", f"{cid}/{f}", b"case file")
        return cid

    async def delete_case(label, who="admin", files=("a.txt", "b.txt"), missing=(), tenant=CUST_A):
        cp, cr = full_case(tenant, f"{label}-p", files, missing), full_case(tenant, f"{label}-r", files, missing)
        await p.same(
            f"delete case: {label} ({who})",
            "DELETE",
            f"{P}/case/{cp}",
            t[who],
            rs_path=f"{P}/case/{cr}",
            subst=(((str(cp), "<case>"),), ((str(cr), "<case>"),)),
            db=case_rows(lambda side: cp if side == "p" else cr),
        )

    await delete_case("no files", files=())
    await delete_case("two files")
    await delete_case("two files", who="analyst")
    await delete_case("second object missing (FK, 500)", missing=("b.txt",))
    await delete_case("first object missing (FK, 500)", missing=("a.txt",))
    await delete_case("other tenant", who="analyst", tenant=CUST_B)
    await delete_case("portal user", who="portal")
    await p.same("delete case: missing", "DELETE", f"{P}/case/{IDS['case'] + 950}", t["admin"])
    await p.same("delete case: not an int", "DELETE", f"{P}/case/abc", t["admin"])
    await p.same("delete case: a static path", "DELETE", f"{P}/case/comment", t["admin"])
    await p.same("delete case: data-store", "DELETE", f"{P}/case/data-store", t["admin"])
    await p.same("delete case: no token", "DELETE", f"{P}/case/1")


async def template_checks(p, t):
    T = f"{P}/case-report-template"
    bucket = "copilot-case-report-templates"
    print("\n=== report templates: list ===")
    S3.make_bucket(bucket)
    for name in (f"t1{SFX}.docx", f"t 2+{SFX}.html", f"folder{SFX}/inner.docx", f"zé{SFX}.docx"):
        S3.put(bucket, name, b"x")
    await p.same("list templates (admin)", "GET", T, t["admin"])
    await p.same("list templates (analyst)", "GET", T, t["analyst"])
    await p.same("list templates (portal)", "GET", T, t["portal"])
    S3.page_size = 2
    await p.same("list templates: pages of two", "GET", T, t["admin"])
    S3.page_size = None
    snap = S3.snapshot()
    await p.same("list templates: bucket missing (bare 500)", "GET", T, t["admin"], before=lambda: S3.drop(bucket))
    S3.restore(snap)
    await p.same(
        "list templates: region eu-central-1",
        "GET",
        T,
        t["admin"],
        before=lambda: S3.make_bucket(bucket, "eu-central-1"),
    )
    S3.make_bucket(bucket, "")

    print("\n=== report templates: download ===")
    tid = new_id("file")
    name = f"tpl{SFX}.docx"
    data = docx_bytes("tpl")
    sql(
        "INSERT INTO incident_management_case_report_template_datastore (id, report_template_name, bucket_name, object_key, file_name, "
        "content_type, file_size, upload_time, file_hash) VALUES (:i, :n, :b, :n, :n, :t, :s, UTC_TIMESTAMP(), 'h')",
        i=tid,
        n=name,
        b=bucket,
        t="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        s=len(data),
    )
    S3.put(bucket, name, data)
    await p.same("download template", "GET", f"{T}/download/{name}", t["admin"])
    await p.same("download template (browser: gzip)", "GET", f"{T}/download/{name}", t["admin"], **BROWSER)
    await p.same("download template (portal)", "GET", f"{T}/download/{name}", t["portal"])
    await p.same("download template: no row", "GET", f"{T}/download/none{SFX}.docx", t["admin"])
    await p.same("download template: object missing", "GET", f"{T}/download/{name}", t["admin"], before=lambda: S3.drop(bucket, name))
    S3.put(bucket, name, data)

    print("\n=== report templates: upload ===")

    def template_rows(fname):
        def read(side):
            return rows(
                "SELECT report_template_name, bucket_name, object_key, file_name, content_type, file_size, file_hash FROM "
                "incident_management_case_report_template_datastore WHERE report_template_name = :n",
                n=fname,
            )

        return read

    async def upload(label, fname, ctype, body, existing=False, who="admin"):
        if existing:
            sql(
                "INSERT INTO incident_management_case_report_template_datastore (report_template_name, bucket_name, object_key, file_name, "
                "file_size, upload_time, file_hash) VALUES (:n, :b, :n, :n, 1, UTC_TIMESTAMP(), 'h')",
                n=fname,
                b=bucket,
            )

        def undo():
            if not existing:
                sql("DELETE FROM incident_management_case_report_template_datastore WHERE report_template_name = :n", n=fname)

        await p.same(
            f"upload template: {label}",
            "POST",
            f"{T}/upload",
            t[who],
            between=undo,
            masked=True,
            db=template_rows(fname),
            **multipart(files=[("file", fname, ctype, body)]),
        )
        undo()

    await upload("docx", f"up{SFX}.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", docx_bytes("u"))
    await upload("html", f"up{SFX}.html", "text/html", "<p>héllo</p>".encode())
    await upload("upper-case extension", f"UP{SFX}.DOCX", None, docx_bytes("u"))
    await upload("docx that is no zip", f"bad{SFX}.docx", None, b"not a zip")
    await upload("html that is a zip", f"zip{SFX}.html", "text/html", docx_bytes("z"))
    await upload("html not UTF-8", f"latin{SFX}.html", "text/html", b"caf\xe9")
    await upload("other extension", f"x{SFX}.txt", "text/plain", b"x")
    await upload("dot file", ".docx", None, docx_bytes("u"))
    await upload("name taken", f"taken{SFX}.docx", None, docx_bytes("u"), existing=True)
    await upload("name of 256 characters", "n" * 251 + ".docx", None, docx_bytes("u"))
    await upload("portal user", f"p{SFX}.docx", None, docx_bytes("u"), who="portal")
    await p.same("upload template: no file", "POST", f"{T}/upload", t["admin"], **multipart(fields=[("other", "x")]))

    print("\n=== report templates: delete ===")

    def restore_template(row):
        def again():
            sql("DELETE FROM incident_management_case_report_template_datastore WHERE id = :i", i=row["id"])
            cols = ", ".join(row)
            sql(
                f"INSERT INTO incident_management_case_report_template_datastore ({cols}) VALUES ({', '.join(':' + c for c in row)})",
                **row,
            )

        return again

    row = rows("SELECT * FROM incident_management_case_report_template_datastore WHERE id = :i", i=tid)[0]
    await p.same("delete template", "DELETE", f"{T}/{name}", t["admin"], between=restore_template(row), db=template_rows(name))
    restore_template(row)()
    S3.put(bucket, name, data)
    await p.same(
        "delete template: object missing",
        "DELETE",
        f"{T}/{name}",
        t["admin"],
        before=lambda: S3.drop(bucket, name),
        between=restore_template(row),
        db=template_rows(name),
    )
    restore_template(row)()
    S3.put(bucket, name, data)
    await p.same("delete template: no row", "DELETE", f"{T}/none{SFX}.docx", t["admin"])
    await p.same("delete template: 'upload'", "DELETE", f"{T}/upload", t["admin"])
    await p.same("delete template: 'do-default-template-exists'", "DELETE", f"{T}/do-default-template-exists", t["admin"])
    await p.same("delete template: portal", "DELETE", f"{T}/{name}", t["portal"])
    await p.same("default-template stays Python (405 here)", "GET", f"{T}/default-template", t["admin"])


async def report_checks(p, t):
    print("\n=== customer reports: download and delete ===")
    bucket = "incident-management-reports"
    S3.make_bucket(bucket)

    def add_report(customer, status="completed", visible=False, role="analyst", by=None, missing=False, name="r"):
        rid = new_id("report")
        key = f"{customer}/{rid}.pdf"
        sql(
            "INSERT INTO incident_management_customer_reports (id, report_name, customer_code, bucket_name, object_key, file_name, file_size, "
            "file_hash, generated_at, generated_by, generated_by_role, date_from, date_to, filters_json, total_alerts, total_cases, "
            "open_cases, closed_cases, status, error_message, visible_to_customer) VALUES (:i, :n, :c, :b, :k, :f, 4, 'h', "
            "'2026-01-02 03:04:05', :g, :role, '2026-01-01 00:00:00', '2026-01-02 00:00:00', '{}', 0, 0, 0, 0, :s, NULL, :v)",
            i=rid,
            n=f"{name}{SFX}",
            c=customer,
            b=bucket,
            k=key,
            f=f"report é {rid}.pdf",
            g=by if by is not None else USERS[ADMIN],
            role=role,
            s=status,
            v=1 if visible else 0,
        )
        if not missing:
            S3.put(bucket, key, b"%PDF-1.4 report")
        return rid

    done = add_report(CUST_A)
    shared = add_report(CUST_A, visible=True)
    own = add_report(CUST_A, role="customer_user", by=USERS[PORTAL])
    pending = add_report(CUST_A, status="pending")
    gone = add_report(CUST_A, missing=True)
    other = add_report(CUST_B)
    for who in ("admin", "analyst"):
        await p.same(f"report download ({who})", "GET", f"{CR}/{done}/download", t[who])
    await p.same("report download (browser: gzip)", "GET", f"{CR}/{done}/download", t["admin"], **BROWSER)
    await p.same("report download: portal, not shared", "GET", f"{CR}/{done}/download", t["portal"])
    await p.same("report download: portal, shared", "GET", f"{CR}/{shared}/download", t["portal"])
    await p.same("report download: portal, their own", "GET", f"{CR}/{own}/download", t["portal"])
    await p.same("report download: pending (409)", "GET", f"{CR}/{pending}/download", t["admin"])
    await p.same("report download: object missing (bare 500)", "GET", f"{CR}/{gone}/download", t["admin"])
    await p.same("report download: other tenant", "GET", f"{CR}/{other}/download", t["analyst"])
    await p.same("report download: missing", "GET", f"{CR}/{IDS['report'] + 900}/download", t["admin"])
    await p.same("report download: not an int", "GET", f"{CR}/x/download", t["admin"])

    def report_rows(rid):
        return lambda side: rows("SELECT id, report_name FROM incident_management_customer_reports WHERE id = :i", i=rid)

    def restore_report(rid):
        row = rows("SELECT * FROM incident_management_customer_reports WHERE id = :i", i=rid)[0]

        def again():
            sql("DELETE FROM incident_management_customer_reports WHERE id = :i", i=rid)
            cols = ", ".join(row)
            sql(f"INSERT INTO incident_management_customer_reports ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)

        return again

    for label, rid, who in (
        ("admin", add_report(CUST_A), "admin"),
        ("creator (analyst)", add_report(CUST_A, by=USERS[ANALYST]), "analyst"),
        ("not the creator (analyst)", add_report(CUST_A), "analyst"),
        ("portal creator", add_report(CUST_A, role="customer_user", by=USERS[PORTAL]), "portal"),
        ("object missing", add_report(CUST_A, missing=True), "admin"),
        ("other tenant", add_report(CUST_B, by=USERS[ANALYST]), "analyst"),
    ):
        await p.same(f"report delete: {label}", "DELETE", f"{CR}/{rid}", t[who], between=restore_report(rid), db=report_rows(rid))
    await p.same("report delete: missing", "DELETE", f"{CR}/{IDS['report'] + 901}", t["admin"])


async def agent_checks(p, t):
    print("\n=== /api/agent_data_store ===")
    bucket = "velociraptor-artifacts"
    S3.make_bucket(bucket)
    agent_a, agent_b = f"{CUST_A}-ag0", f"{CUST_B}-ag0"

    def add_artifact(agent, flow, fname, ctype="application/zip", missing=False, when="2026-01-02 03:04:05", data=b"PK zip"):
        aid = new_id("artifact")
        sql(
            "INSERT INTO agent_datastore (id, agent_id, velociraptor_id, artifact_name, flow_id, collection_time, bucket_name, object_key, "
            "file_name, content_type, file_size, file_hash, uploaded_by, notes, status) VALUES (:i, :a, 'C.1', 'Generic.Collect', :f, :w, "
            ":b, :k, :n, :t, :s, 'h', NULL, 'n', 'completed')",
            i=aid,
            a=agent,
            f=flow,
            w=when,
            b=bucket,
            k=f"{agent}/{flow}/{fname}",
            n=fname,
            t=ctype,
            s=len(data),
        )
        if not missing:
            S3.put(bucket, f"{agent}/{flow}/{fname}", data)
        return aid

    a1 = add_artifact(agent_a, "F.1", "collection.zip")
    a2 = add_artifact(agent_a, "F.2", "second file.zip", when="2026-01-02 03:04:05")
    a3 = add_artifact(agent_a, "F.2", "notes.txt", ctype="text/plain", missing=True)
    b1 = add_artifact(agent_b, "F.9", "b.zip")
    for who in ("admin", "analyst"):
        await p.same(f"artifacts of agent A ({who})", "GET", f"{DS}/agent/{agent_a}/artifacts", t[who])
    await p.same("artifacts: flow filter", "GET", f"{DS}/agent/{agent_a}/artifacts?flow_id=F.2", t["analyst"])
    await p.same("artifacts: empty flow filter", "GET", f"{DS}/agent/{agent_a}/artifacts?flow_id=", t["analyst"])
    await p.same("artifacts: other tenant's agent", "GET", f"{DS}/agent/{agent_b}/artifacts", t["analyst"])
    await p.same("artifacts: unknown agent (analyst)", "GET", f"{DS}/agent/nope{SFX}/artifacts", t["analyst"])
    await p.same("artifacts: unknown agent (admin)", "GET", f"{DS}/agent/nope{SFX}/artifacts", t["admin"])
    await p.same("artifacts: portal", "GET", f"{DS}/agent/{agent_a}/artifacts", t["portal"])
    await p.same("artifact details", "GET", f"{DS}/agent/{agent_a}/artifacts/{a1}", t["analyst"])
    await p.same("artifact details: of another agent", "GET", f"{DS}/agent/{agent_a}/artifacts/{b1}", t["admin"])
    await p.same("artifact details: id not an int", "GET", f"{DS}/agent/{agent_a}/artifacts/x", t["admin"])
    await p.same("artifact details: other tenant before the id", "GET", f"{DS}/agent/{agent_b}/artifacts/x", t["analyst"])
    await p.same("artifact download", "GET", f"{DS}/agent/{agent_a}/artifacts/{a1}/download", t["analyst"])
    await p.same(
        "artifact download (browser: gzip, no Content-Length)",
        "GET",
        f"{DS}/agent/{agent_a}/artifacts/{a1}/download",
        t["analyst"],
        **BROWSER,
    )
    await p.same("artifact download: space in name", "GET", f"{DS}/agent/{agent_a}/artifacts/{a2}/download", t["admin"])
    await p.same("artifact download: object missing", "GET", f"{DS}/agent/{agent_a}/artifacts/{a3}/download", t["admin"])
    await p.same("artifact download: no row", "GET", f"{DS}/agent/{agent_a}/artifacts/{b1}/download", t["admin"])
    await p.same("artifact download: other tenant", "GET", f"{DS}/agent/{agent_b}/artifacts/{b1}/download", t["analyst"])
    await p.same(
        "artifact download: bucket missing",
        "GET",
        f"{DS}/agent/{agent_a}/artifacts/{a1}/download",
        t["admin"],
        before=lambda: S3.drop(bucket),
    )
    S3.make_bucket(bucket)
    S3.put(bucket, f"{agent_a}/F.1/collection.zip", b"PK zip")
    S3.put(bucket, f"{agent_a}/F.2/second file.zip", b"PK zip")

    def artifact_rows(aid):
        return lambda side: rows("SELECT id, file_name FROM agent_datastore WHERE id = :i", i=aid)

    def restore_artifact(aid):
        row = rows("SELECT * FROM agent_datastore WHERE id = :i", i=aid)[0]

        def again():
            sql("DELETE FROM agent_datastore WHERE id = :i", i=aid)
            cols = ", ".join(f"`{c}`" for c in row)
            sql(f"INSERT INTO agent_datastore ({cols}) VALUES ({', '.join(':' + c for c in row)})", **row)

        return again

    d1 = add_artifact(agent_a, "F.3", "del.zip")
    await p.same("artifact delete (analyst: admin only)", "DELETE", f"{DS}/agent/{agent_a}/artifacts/{d1}", t["analyst"])
    await p.same(
        "artifact delete",
        "DELETE",
        f"{DS}/agent/{agent_a}/artifacts/{d1}",
        t["admin"],
        between=restore_artifact(d1),
        db=artifact_rows(d1),
    )
    d2 = add_artifact(agent_a, "F.4", "gone.zip", missing=True)
    await p.same(
        "artifact delete: object missing",
        "DELETE",
        f"{DS}/agent/{agent_a}/artifacts/{d2}",
        t["admin"],
        between=restore_artifact(d2),
        db=artifact_rows(d2),
    )
    await p.same("artifact delete: no row", "DELETE", f"{DS}/agent/{agent_a}/artifacts/{IDS['artifact'] + 900}", t["admin"])

    print("\n=== /api/agent_data_store/upload ===")

    async def upload(label, fields, files, who="admin", before=None):
        await p.same(f"upload: {label} ({who})", "POST", f"{DS}/upload", t[who], before=before, **multipart(fields=fields, files=files))

    new_bucket = f"parity-{SFX.lower()}"
    await upload(
        "into a new bucket",
        [("bucket_name", new_bucket), ("object_name", "dir/a.txt")],
        [("file", "a.txt", "text/plain", b"abc")],
    )
    S3.drop(new_bucket)
    await upload("into an existing bucket", [("bucket_name", bucket), ("object_name", f"up/{SFX}.zip")], [("file", "x.zip", None, b"zip")])
    await upload("empty file name", [("bucket_name", bucket), ("object_name", "o")], [("file", "", "text/plain", b"abc")])
    await upload("invalid bucket name", [("bucket_name", "No_Such!"), ("object_name", "o")], [("file", "a.txt", None, b"x")])
    await upload(
        "uppercase bucket (strict create)",
        [("bucket_name", f"Upper{SFX}"), ("object_name", "o")],
        [("file", "a.txt", None, b"x")],
    )
    await upload("IP-shaped bucket", [("bucket_name", "10.1.2.3"), ("object_name", "o")], [("file", "a.txt", None, b"x")])
    await upload("dot-dot object", [("bucket_name", bucket), ("object_name", "a/../b")], [("file", "a.txt", None, b"x")])
    await upload("blank object", [("bucket_name", bucket), ("object_name", " ")], [("file", "a.txt", None, b"x")])
    await upload(
        "multipart (6 MiB)",
        [("bucket_name", bucket), ("object_name", f"big/{SFX}.bin")],
        [("file", "b.bin", None, os.urandom(6 * 1024 * 1024))],
    )
    await upload("fields missing", [], [])
    await upload("empty fields", [("bucket_name", ""), ("object_name", "")], [("file", "a.txt", None, b"x")])
    await upload("file as text", [("bucket_name", bucket), ("object_name", "o"), ("file", "text")], [])
    await upload("portal", [("bucket_name", bucket), ("object_name", "o")], [("file", "a.txt", None, b"x")], who="portal")
    await upload(
        "a 500 XML error on the PUT",
        [("bucket_name", bucket), ("object_name", f"e/{SFX}")],
        [("file", "a.txt", None, b"x")],
        before=lambda: S3.fault(
            lambda m, path, q: m == "PUT" and "/e/" in path,
            (
                500,
                {"Content-Type": "application/xml"},
                f'<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>InternalError</Code><Message>{MESSAGES["InternalError"]}</Message>'
                f"<Key>e/{SFX}</Key><BucketName>{bucket}</BucketName><Resource>/{bucket}/e/{SFX}</Resource><RequestId>{REQUEST_ID}</RequestId>"
                f"<HostId>{HOST_ID}</HostId></Error>".encode(),
            ),
            5,
        ),
    )
    await upload(
        "a non-XML 502 on the bucket check",
        [("bucket_name", bucket), ("object_name", "o")],
        [("file", "a.txt", None, b"x")],
        before=lambda: S3.fault(lambda m, path, q: m == "HEAD", (502, {"Content-Type": "text/plain"}, b"bad gateway"), 5),
    )
    await upload(
        "a 404 without a body on HEAD bucket",
        [("bucket_name", bucket), ("object_name", "o")],
        [("file", "a.txt", None, b"x")],
        before=lambda: S3.fault(lambda m, path, q: m == "HEAD", (404, {}, b""), 1),
    )
    # A scoped analyst under their customer: its code, or an agent id of theirs, first.
    await upload(
        "under the analyst's customer",
        [("bucket_name", bucket), ("object_name", f"{CUST_A}/a.txt")],
        [("file", "a.txt", None, b"x")],
        who="analyst",
    )
    await upload(
        "under the analyst's agent",
        [("bucket_name", bucket), ("object_name", f"{agent_a}/F.1/a.bin")],
        [("file", "a.bin", None, b"x")],
        who="analyst",
    )

    # §4: anywhere else is refused to a scoped analyst before MinIO is asked (Python wrote any
    # bucket and object for any analyst).
    async def refused(label, obj, who="analyst"):
        S3.faults = []
        start = S3.snapshot()
        form = lambda: multipart(
            fields=[("bucket_name", bucket), ("object_name", obj)],
            files=[("file", "a.txt", None, b"x")],
        )  # noqa: E731
        r1, _ = await p.call(p.py, "POST", f"{DS}/upload", t[who], **form())
        wrote = changes(start, S3.snapshot(), ())
        S3.restore(start)
        r2, out2 = await p.call(p.rs, "POST", f"{DS}/upload", t[who], **form())
        ok = (
            r1.status_code == 200
            and bool(wrote)
            and r2.status_code == 403
            and body_of(r2) == {"message": f"Access denied to object {obj}", "success": False}
            and not out2
            and S3.snapshot() == start
        )
        check(
            f"upload: {label} ({who}) [diff by design (200, 403)]",
            ok,
            f"python {r1.status_code} {r1.text[:200]} wrote {wrote}\n        rust   {r2.status_code} {r2.text[:200]} sent {len(out2)}",
        )

    await refused("under another tenant's customer", f"{CUST_B}/a.txt")
    await refused("under another tenant's agent", f"{agent_b}/F.1/a.bin")
    await refused("under no customer", "dir/a.txt")
    await refused("anywhere, without customers", f"{CUST_A}/nobody.txt", who="nobody")
    # A dot-dot segment further on: miniopy-async refuses it on both backends.
    await upload(
        "a dot-dot segment after the analyst's customer",
        [("bucket_name", bucket), ("object_name", f"{CUST_A}/../{CUST_B}/a.txt")],
        [("file", "a.txt", None, b"x")],
        who="analyst",
    )


async def unreachable_checks(p, t):
    print("\n=== MinIO unreachable ===")
    ca = add_case(CUST_A, "down")
    add_file(ca, "down.txt")
    await p.same("download: connection refused (bare 500)", "GET", f"{P}/case/data-store/download/{ca}/down.txt", t["admin"], down=True)
    await p.same(
        "agent upload: connection refused",
        "POST",
        f"{DS}/upload",
        t["admin"],
        down=True,
        **multipart(fields=[("bucket_name", "b-x"), ("object_name", "o")], files=[("file", "a.txt", None, b"x")]),
    )
    await p.same("template list: connection refused", "GET", f"{P}/case-report-template", t["admin"], down=True)
    cp, cr = add_case(CUST_A, "down-p"), add_case(CUST_A, "down-r")
    for c in (cp, cr):
        add_file(c, "x.txt")
    await p.same(
        "delete file: connection refused (404)",
        "DELETE",
        f"{P}/case/data-store/{cp}/x.txt",
        t["admin"],
        rs_path=f"{P}/case/data-store/{cr}/x.txt",
        subst=(((str(cp), "<case>"),), ((str(cr), "<case>"),)),
        down=True,
    )


async def default_and_sysmon_checks(p, t):
    """`POST /case-report-template/default-template` and `POST /api/sysmon_config/upload`."""
    import pathlib

    print("\n=== default report templates ===")
    T = f"{P}/case-report-template/default-template"
    bucket = "copilot-case-report-templates"
    templates = pathlib.Path(REPO) / "backend" / "app" / "incidents" / "templates"
    names = sorted(f.name for f in templates.iterdir() if f.is_file())
    saved = rows("SELECT * FROM incident_management_case_report_template_datastore WHERE report_template_name IN :n", n=names)

    def wipe():
        sql("DELETE FROM incident_management_case_report_template_datastore WHERE report_template_name IN :n", n=names)

    def template_rows():
        found = rows(
            "SELECT report_template_name, bucket_name, object_key, file_name, content_type, file_size, file_hash "
            "FROM incident_management_case_report_template_datastore WHERE report_template_name IN :n ORDER BY report_template_name",
            n=names,
        )
        return [dict(r) for r in found]

    try:
        wipe()
        await p.same("default templates: portal user", "POST", T, t["portal"])
        await p.same("default templates: no token", "POST", T)
        # Python visits the directory in the order the filesystem lists it, Rust in name order
        # (RUST_MIGRATION.md §4): the answers' lists and the uploads are compared as sets.
        S3.make_bucket(bucket)
        start = S3.snapshot()
        r1, out1 = await p.call(p.py, "POST", T, t["analyst"])
        end1, rows1 = S3.snapshot(), template_rows()
        wipe()
        S3.restore(start)
        r2, out2 = await p.call(p.rs, "POST", T, t["analyst"])
        end2, rows2 = S3.snapshot(), template_rows()
        b1, b2 = body_of(r1), body_of(r2)
        listed = lambda b: {**b, "case_report_template_data_store": sorted(b["case_report_template_data_store"])}  # noqa: E731
        o1 = sorted(outbound(out1), key=repr)
        o2 = sorted(outbound(out2), key=repr)
        check(
            f"default templates: every file stored [{r1.status_code}]",
            r1.status_code == r2.status_code == 200
            and listed(b1) == listed(b2)
            and sorted(b1["case_report_template_data_store"]) == names
            and o1 == o2
            and all(o[-1] == "ok" for o in o1 + o2)
            and changes(start, end1) == changes(start, end2)
            and rows1 == rows2
            and all(r["content_type"] is None for r in rows2),
            f"python {r1.status_code} {b1}\n        rust   {r2.status_code} {b2}\n        outbound equal {o1 == o2}"
            f"\n        minio python {changes(start, end1)}\n        minio rust   {changes(start, end2)}\n        rows {rows1 == rows2}",
        )
        await p.same("default templates: they exist already", "POST", T, t["admin"])
    finally:
        wipe()
        for r in saved:
            cols = list(r.keys())
            sql(
                f"INSERT INTO incident_management_case_report_template_datastore ({', '.join(cols)}) "
                f"VALUES ({', '.join(':' + c for c in cols)})",
                **r,
            )

    print("\n=== sysmon config upload ===")
    U = "/api/sysmon_config/upload"
    config = b"<Sysmon schemaversion='4.90'>\n  <EventFiltering>\n    <RuleGroup groupRelation='or'/>\n  </EventFiltering>\n</Sysmon>"

    def form(code=CUST_A, name="config.xml", data=config, ctype="text/xml"):
        fields = [("customer_code", code)] if code is not None else []
        files = [("file", name, ctype, data)] if name is not None else []
        return multipart(fields, files)

    await p.same("sysmon upload: no token", "POST", U, **form())
    await p.same("sysmon upload: analyst", "POST", U, t["analyst"], **form())
    await p.same("sysmon upload: no file", "POST", U, t["admin"], **form(name=None))
    await p.same("sysmon upload: no customer", "POST", U, t["admin"], **form(code=None))
    await p.same("sysmon upload: neither", "POST", U, t["admin"], **form(code=None, name=None))
    await p.same("sysmon upload: not .xml", "POST", U, t["admin"], **form(name="config.txt"))
    await p.same("sysmon upload: not UTF-8", "POST", U, t["admin"], **form(data=b"<Sysmon>\xff</Sysmon>"))
    for label, doc in (
        ("empty", b""),
        ("text", b"not xml"),
        ("mismatched tag", b"<Sysmon>\n  <EventFiltering>\n</Sysmon>"),
        ("invalid token", b"<Sysmon>\n  <EventFiltering a=b/>\n</Sysmon>"),
        ("unclosed", b"<Sysmon><EventFiltering"),
        ("undefined entity", b"<Sysmon>&nbsp;</Sysmon>"),
        ("duplicate attribute", b"<Sysmon a='1' a='2'/>"),
        ("junk after the root", b"<Sysmon/>\n<Other/>"),
        ("BOM, CRLF and a declaration", "﻿<?xml version='1.0' encoding='utf-8'?>\r\n<Sysmon>\r\n<EventFiltering>\r\n</Sysmon>".encode()),
        ("another root", b"<sysmon><EventFiltering><RuleGroup groupRelation='or'/></EventFiltering></sysmon>"),
        ("no EventFiltering", b"<Sysmon><Other/></Sysmon>"),
        ("text in EventFiltering", b"<Sysmon><EventFiltering>x<RuleGroup groupRelation='or'/></EventFiltering></Sysmon>"),
        ("no RuleGroup", b"<Sysmon><EventFiltering/></Sysmon>"),
        (
            "a RuleGroup without groupRelation",
            b"<Sysmon><EventFiltering><RuleGroup groupRelation='or'/><RuleGroup/></EventFiltering></Sysmon>",
        ),
    ):
        await p.same(f"sysmon upload: {label}", "POST", U, t["admin"], **form(data=doc))
    S3.drop("sysmon-configs")
    await p.same("sysmon upload: the bucket missing (created, uploaded)", "POST", U, t["admin"], **form())
    S3.make_bucket("sysmon-configs")
    await p.same("sysmon upload: a first config", "POST", U, t["admin"], **form(code=CUST_B))
    S3.put("sysmon-configs", f"{CUST_A}/sysmon_config.xml", b"<old/>", "application/xml")
    await p.same("sysmon upload: replacing one", "POST", U, t["admin"], **form())
    await p.same(
        "sysmon upload: MinIO fails the existence check",
        "POST",
        U,
        t["admin"],
        before=lambda: S3.fault(
            lambda m, path, q: m == "HEAD" and path == "/sysmon-configs",
            S3.error(500, "InternalError", "/sysmon-configs", head=True),
            count=10,
        ),
        **form(),
    )
    await p.same(
        "sysmon upload: MinIO fails the upload",
        "POST",
        U,
        t["admin"],
        before=lambda: S3.fault(
            lambda m, path, q: m == "PUT" and path.endswith("/sysmon_config.xml"),
            S3.error(500, "InternalError", "/x"),
            count=10,
        ),
        **form(),
    )
    await p.same("sysmon upload: MinIO down", "POST", U, t["admin"], down=True, **form())


async def main():
    server = S3.serve(S3_PORT)
    patch_python_minio()
    seed()
    procs = [start_rust(RS_PORT, S3_PORT), start_rust(RS_DOWN_PORT, S3_CLOSED_PORT)]
    PROCS.extend(procs)
    p = Pair()
    t = {
        "admin": token(ADMIN, ["admin"]),
        "analyst": token(ANALYST, ["analyst"]),
        "portal": token(PORTAL, ["customer_user"], customer_codes=[CUST_A]),
        "nobody": token(NOBODY, ["analyst"]),
    }
    try:
        sections = os.environ.get("OBJECTSTORE_PARITY_SECTIONS", "cases,templates,defaults,reports,agents,down").split(",")
        if "cases" in sections:
            await case_file_checks(p, t)
        if "templates" in sections:
            await template_checks(p, t)
        if "defaults" in sections:
            await default_and_sysmon_checks(p, t)
        if "reports" in sections:
            await report_checks(p, t)
        if "agents" in sections:
            await agent_checks(p, t)
        if "down" in sections:
            await unreachable_checks(p, t)
    finally:
        await p.close()
        for proc in procs:
            proc.terminate()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
        cleanup()
        server.shutdown()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


def cleanup():
    base = IDS.get("case", 0) - 1000
    if base <= 0:
        return
    case_range = {"lo": base + 1000, "hi": base + 1999}
    for table in (
        "incident_management_case_comment",
        "incident_management_casealertlink",
        "incident_management_case_task",
        "incident_management_case_event",
    ):
        sql(f"DELETE FROM {table} WHERE case_id BETWEEN :lo AND :hi", **case_range)
    sql("DELETE FROM incident_management_case_datastore WHERE case_id BETWEEN :lo AND :hi", **case_range)
    sql("DELETE FROM incident_management_case WHERE id BETWEEN :lo AND :hi", **case_range)
    sql("DELETE FROM incident_management_alert WHERE id BETWEEN :lo AND :hi", lo=base + 5000, hi=base + 5999)
    sql("DELETE FROM incident_management_case_report_template_datastore WHERE report_template_name LIKE :p", p=f"%{SFX}%")
    sql("DELETE FROM incident_management_case_report_template_datastore WHERE id BETWEEN :lo AND :hi", lo=base + 2000, hi=base + 2999)
    sql(
        "DELETE FROM incident_management_case_report_template_datastore WHERE report_template_name LIKE 'nnnn%' OR report_template_name = '.docx'",
    )
    sql("DELETE FROM incident_management_customer_reports WHERE customer_code IN (:a, :b)", a=CUST_A, b=CUST_B)
    sql("DELETE FROM agent_datastore WHERE agent_id LIKE :p", p=f"OBJ_%{SFX}%")
    sql("DELETE FROM agents WHERE customer_code IN (:a, :b)", a=CUST_A, b=CUST_B)
    sql("DELETE FROM audit_log WHERE actor_username LIKE :p", p=f"obj_%{SFX}")
    for name in USERS:
        sql("DELETE FROM log_entries WHERE user_id = :u", u=USERS[name])
        sql("DELETE FROM user_customer_access WHERE user_id = :u", u=USERS[name])
        sql("DELETE FROM `user` WHERE id = :u", u=USERS[name])
    for c in (CUST_A, CUST_B):
        sql("DELETE FROM soc_sla_case_tracking WHERE case_id IN (SELECT id FROM incident_management_case WHERE customer_code = :c)", c=c)
        sql("DELETE FROM customers WHERE customer_code = :c", c=c)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
