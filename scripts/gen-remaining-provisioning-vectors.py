"""Regenerate the vectors that pin the Rust port of the remaining provisioning (Office 365, AWS,
CrowdStrike, Defender for Endpoint, Bitdefender, customer provisioning and the Portainer Wazuh stack)
to CPython and the backend's own code.

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-remaining-provisioning-vectors.py

Writes:

* `crates/copilot-integrations/src/etree_expat_vectors.json` — what expat (through
  `ET.XMLParser`) makes of each probe document: the parsed root re-serialised, or the
  `ParseError` text with its line and column; the comment-keeping parse (`TreeBuilder(
  insert_comments=True)`) serialised as `unicode` and as `us-ascii`, and after
  `ET.indent(root, "  ", 1)`; and which document pairs `ET.canonicalize(…, strip_text=True)` makes
  equal, with and without comments.
* `crates/copilot-cloud-provisioning/src/cloud_provisioning_vectors.json` — the Office 365
  `ossec.conf` edits (the first tenant's `<office365>` block, a further tenant's `<api_auth>`
  block, every error text), the AWS `aws-s3` wodle reconcile (`reconcile_aws_buckets`,
  `verify_only_instance_changed`), `ProvisionAwsAuthKeys` and `parse_services`, and the pipeline
  rule sources.

Re-run after a Python upgrade (expat and ElementTree ship with CPython) or a change to the modules
these pin.
"""

import json
import pathlib
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent
ETREE_OUT = ROOT / "crates" / "copilot-integrations" / "src" / "etree_expat_vectors.json"


# --- ElementTree / expat ---------------------------------------------------------------------------

PARSE_PROBES = [
    "<a/><b/>",
    "<a/>\n<b/>",
    "<!-- c -->\n<ossec_config>\n  <x>1</x>\n</ossec_config>\n\n<ossec_config>\n</ossec_config>\n",
    "<a>x&y</a>",
    "<a>x&amp</a>",
    "<a><b></a>",
    "<a><b></c></a>",
    "<a>",
    "",
    "   ",
    "<a b=c/>",
    "<a b='1' b='2'/>",
    "<a>&foo;</a>",
    "<a>\x01</a>",
    "<a>é\x01</a>",
    "<a>\n é\x02</a>",
    "x<a/>",
    "<a></a>x",
    "<a></a><!-- ok -->",
    "<a>]]></a>",
    "<a><!-- -- --></a>",
    "<?xml version='1.0'?><a/>",
    " <?xml version='1.0'?><a/>",
    "<a><?xml version='1.0'?></a>",
    "<a>&#0;</a>",
    "<a>&#x110000;</a>",
    "<a b='<'/>",
    "<p:a/>",
    "<a></a ",
    "<a",
    "<a b",
    "<a b=",
    "<a b='",
    "<!DOCTYPE a><a/>",
    "<a></b>",
    "<ossec_config>\r\n<x/>\r\n</ossec_config>\r\n<ossec_config/>",
    "abc<a/>",
    "x\n<a/>",
    " x <a/>",
    "<a/>x",
    "<a/> x",
    "<a/>\n\n  junk",
    "<a/><?pi x?>",
    "<a/><?pi x?><b/>",
    "<a/>&amp;",
    "<a/><!DOCTYPE a>",
    "<a></a>]",
    "<a>a&b c</a>",
    "<a>&</a>",
    "<a>& </a>",
    "<a>&#;</a>",
    "<a>&#x;</a>",
    "<a>&#12a;</a>",
    "<a>&lt</a>",
    "<a><b>x</b></c>",
    "<a>\n<b>\n</a>",
    "<a b='1'c='2'/>",
    "<a b = '1' />",
    "<a b>",
    "<a b='x'",
    "<a 1='x'/>",
    "<1a/>",
    "<a><1b/></a>",
    "< a/>",
    "<a></ a>",
    "<a></a b>",
    "<a>x</a",
    "<a>x<",
    "<a><!--",
    "<a><!-- x",
    "<a><![CDATA[x",
    "<a><?pi",
    "<a><?pi x",
    "<a><!DOCTYPE b></a>",
    "<a><!x></a>",
    "<!-- x --><!-- y",
    "<?xml version='1.0'?>\n<?xml version='1.0'?><a/>",
    "<?xml version='2'?><a/>",
    "<?xml?><a/>",
    "<?xml version='1.0' encoding='utf-8' standalone='maybe'?><a/>",
    "<a>\t\x0b</a>",
    "<a b='\x01'/>",
    "<a\x01/>",
    "<a><b\x01/></a>",
    "<a>é&é;</a>",
    "<ossec_config>\n  <a>&</a>\n</ossec_config>",
    "<ossec_config>\n  <a>x</b>\n</ossec_config>",
    "<ossec_config>\n  <a>\n</ossec_config>",
    "<a xmlns:p='u'><p:b/></a>",
    "<a><q:b/></a>",
    "<a q:x='1'/>",
    "<a xmlns:p=''/>",
    "<a xmlns:xml='x'/>",
    "<a>￾</a>",
    "<a>￿</a>",
    "﻿<a/>",
    "<a/>﻿",
    "<a><![CDATA[xyz",
    "<a><![CDATA[",
    "<a>&",
    "<a>&a",
    "<a>&#",
    "<a>&#1",
    "<a/></b>",
    "<a/>x<b/>",
    "<a/>1",
    "<a/>'x'",
    "<a/>'x",
    "<a/>[",
    "1<a/>",
    "&<a/>",
    "'x'<a/>",
    "<a/ >",
    "<a b='1'/ >",
    "<a/><?xml version='1.0'?>",
    "<a></a\x01>",
    "<a></a\n>",
    "<?xml version='1.0' ?><a/>",
    "<?xml version = '1.0'?><a/>",
    "<?xml version='1.0'encoding='utf-8'?><a/>",
    "<?xml version='1.0' bogus='1'?><a/>",
    "<?xmlx?><a/>",
    "<?xml-stylesheet x?><a/>",
    "<a><?xml-x y?></a>",
    "<a><?p?></a>",
    "<a><?p:q x?></a>",
    "<a><!--x--y--></a>",
    "<a><!---></a>",
    "<a><!----></a>",
    "<a b='&amp;&#10;&lt;'/>",
    "<a b='&x;'/>",
    "<a b='&'/>",
    "<a\n b='1'\n b='2'/>",
    "<a\tb='1'/>",
    "<a\nb='1'/>",
    "<a>\r</a>",
    "<a>\r\n\r\nx\x01</a>",
    "<a>x\ry\x01</a>",
    "<a/>  \r\n  <b/>",
    # ossec.conf as the manager serves it.
    "<!-- Wazuh - Manager - Default configuration for ubuntu 22.04\n  More info at: https://documentation.wazuh.com\n -->\n\n"
    "<ossec_config>\n  <global>\n    <jsonout_output>yes</jsonout_output>\n  </global>\n</ossec_config>\n",
    "<ossec_config>\n  <global>\n    <email_to>a@b</email_to>\n  </global>\n</ossec_config>\n\n<ossec_config>\n  <remote/>\n</ossec_config>\n",
    "<ossec_config>\n  <x>é ü — 😀</x>\n</ossec_config>\n<ossec_config/>",
]

COMMENT_PROBES = [
    "<ossec_config>\n  <!-- one -->\n  <global>yes</global><!--two--> tail\n</ossec_config>",
    "<w><!-- c --><bucket type='cloudtrail'><name>b</name></bucket></w>",
    "<w>\n<a>é<b>ü</b></a>\n<!--ç--></w>",
    "<w><a x='1&#10;2' y='&quot;'>t</a><b/><c>  </c></w>",
    "<w>text<a/>between<b><c/></b>tail</w>",
    "<w>\n    <wodle name='aws-s3'>\n      <disabled>no</disabled>\n      <bucket type='guardduty'><name>x</name></bucket>\n    </wodle>\n  </w>",
]

CANONICAL_PAIRS = [
    ("<a><b>x</b></a>", "<a>\n  <b> x </b>\n</a>"),
    ("<a><b>x</b></a>", "<a><b>y</b></a>"),
    ("<a x='1' y='2'/>", "<a y='2' x='1'></a>"),
    ("<a>t<!--c-->u</a>", "<a>tu</a>"),
    ("<a>t <!--c--> u</a>", "<a>t  u</a>"),
    ("<a><!--c--><b/></a>", "<a><b/></a>"),
    ("<a><!--c--><b/></a>", "<a><!--d--><b/></a>"),
    ("<a xml:space='preserve'> x </a>", "<a xml:space='preserve'>x</a>"),
    ("<a>&amp;</a>", "<a>&#38;</a>"),
    ("<a> x</a>", "<a>x</a>"),
    ("<a><b/>\n<c/></a>", "<a><b/><c/></a>"),
    ("<a><b/>x<c/></a>", "<a><b/><c/>x</a>"),
]


def etree_vectors():
    parse = []
    for doc in PARSE_PROBES:
        try:
            root = ET.fromstring(doc)
            result = "OK " + ET.tostring(root, encoding="utf-8").decode("utf-8")
        except ET.ParseError as e:
            result = str(e)
        parse.append({"doc": doc, "result": result})
    comments = []
    for doc in COMMENT_PROBES:
        parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
        parser.feed(doc)
        root = parser.close()
        unicode = ET.tostring(root, encoding="unicode")
        ascii_ = ET.tostring(root).decode("ascii")
        ET.indent(root, space="  ", level=1)
        comments.append({"doc": doc, "unicode": unicode, "ascii": ascii_, "indent": ET.tostring(root, encoding="unicode")})
    canonical = []
    for a, b in CANONICAL_PAIRS:

        def canon(doc, with_comments):
            parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
            parser.feed(doc)
            root = parser.close()
            return ET.canonicalize(ET.tostring(root, encoding="unicode"), strip_text=True, with_comments=with_comments)

        canonical.append(
            {
                "a": a,
                "b": b,
                "equal": canon(a, False) == canon(b, False),
                "equal_with_comments": canon(a, True) == canon(b, True),
            },
        )
    return {"parse": parse, "comments": comments, "canonical": canonical}


# --- Office 365: the ossec.conf edits ---------------------------------------------------------------

CLOUD_OUT = ROOT / "crates" / "copilot-cloud-provisioning" / "src" / "cloud_provisioning_vectors.json"

O365_GLOBAL = "<ossec_config>\n  <global>\n    <jsonout_output>yes</jsonout_output>\n  </global>\n"
O365_BLOCK = (
    "  <office365>\n    <enabled>yes</enabled>\n    <interval>1m</interval>\n    <api_auth>\n"
    "      <tenant_id>t-old</tenant_id>\n      <client_id>c</client_id>\n    </api_auth>\n"
    "    <subscriptions>\n      <subscription>Audit.General</subscription>\n    </subscriptions>\n  </office365>\n"
)
O365_CONFIGS = [
    O365_GLOBAL + "</ossec_config>\n",
    "<!-- Wazuh - Manager - Default configuration -->\n" + O365_GLOBAL + "  <!-- a comment -->\n</ossec_config>\n",
    '<?xml version="1.0" encoding="UTF-8"?>\r\n' + O365_GLOBAL.replace("\n", "\r\n") + "</ossec_config>",
    O365_GLOBAL + '  <x attr="a&amp;b" y=\'q"\'>é &lt; ü — 😀</x>\n</ossec_config>',
    O365_GLOBAL + "</ossec_config>\n\n<ossec_config>\n  <remote/>\n</ossec_config>\n",
    O365_GLOBAL + O365_BLOCK + "</ossec_config>\n",
    O365_GLOBAL + O365_BLOCK.replace("t-old", "t-ü") + "  <!-- c -->\n</ossec_config>\n",
    O365_GLOBAL + O365_BLOCK + "</ossec_config>\n<ossec_config/>\n",
    O365_GLOBAL + "  <office365><enabled>no</enabled></office365>\n</ossec_config>\n",
    O365_GLOBAL + "  <wodle name='office365'><office365/></wodle>\n</ossec_config>\n",
    O365_GLOBAL + "  <!-- office365 is mentioned here only -->\n</ossec_config>\n",
    O365_GLOBAL + "  <office365><subscriptions/><subscriptions/></office365>\n</ossec_config>\r\n",
    "<ossec_config><x>a\rb</x><y>&#13;</y></ossec_config>",
    "not xml at all",
    "",
]
O365_KEYS = [
    {"TENANT_ID": "t-new", "CLIENT_ID": "c-1", "CLIENT_SECRET": "s3cr3t", "API_TYPE": "commercial"},
    {"TENANT_ID": "tén&<ant>", "CLIENT_ID": " c\n2 ", "CLIENT_SECRET": "ü\"'s", "API_TYPE": "gcc-high"},
    {"TENANT_ID": "t-new", "CLIENT_ID": "", "CLIENT_SECRET": "x\ry", "API_TYPE": ""},
    {"TENANT_ID": "t-new", "CLIENT_ID": "c\x01", "CLIENT_SECRET": "s", "API_TYPE": "a"},
    {"TENANT_ID": "t-new", "CLIENT_ID": "c", "CLIENT_SECRET": "\ufffe", "API_TYPE": "a"},
    {"TENANT_ID": "t-new", "CLIENT_ID": "😀", "CLIENT_SECRET": "]]>", "API_TYPE": "<api_type>"},
]


def office365_vectors():
    """What `provision_office365` PUTs for each configuration and set of keys (the text the second
    `aiofiles.open(..., "r")` reads back from wazuh_config.xml), or the exception its first steps
    raise."""
    import asyncio
    import tempfile

    from fastapi import HTTPException

    from app.integrations.office365.schema.provision import ProvisionOffice365AuthKeys
    from app.integrations.office365.services import provision as o365

    out = []
    with tempfile.TemporaryDirectory() as tmp:
        saved = o365.__file__
        o365.__file__ = str(pathlib.Path(tmp) / "provision.py")
        path = pathlib.Path(tmp) / "wazuh_config.xml"
        try:
            for config in O365_CONFIGS:
                for raw_keys in O365_KEYS:
                    keys = ProvisionOffice365AuthKeys(**raw_keys)
                    case = {"config": config, "keys": raw_keys}
                    with open(path, "w") as f:
                        f.write(config)
                    try:
                        if "office365" in config:
                            asyncio.run(o365.add_api_auth_to_office365_block("c", keys))
                        else:
                            asyncio.run(o365.office365_template_with_api_type("c", keys))
                        with open(path, "r") as f:
                            case["put"] = f.read()
                    except HTTPException as e:
                        case["error"] = {"status": e.status_code, "text": e.detail}
                    except Exception as e:  # noqa: BLE001
                        case["error"] = {"status": 500, "text": str(e)}
                    out.append(case)
        finally:
            o365.__file__ = saved
    return out


def pipeline_rule_sources():
    from app.integrations.office365.services import provision as o365

    return {"office365_utc": o365.office365_utc_rule_source("Office365 Timestamp - UTC")}


# --- AWS ---------------------------------------------------------------------------------------------

AWS_OUT = ROOT / "crates" / "copilot-cloud-provisioning" / "src" / "aws_vectors.json"
AWS_FIXED_NOW = (2026, 10, 17, 12, 0, 0)
AWS_FIXED_ID = "00000000-0000-4000-8000-000000000000"
AWS_ENDPOINT = "http://aws.test:8080"
AWS_KEY_ID = "AKIAEXAMPLE000000000"
AWS_SECRET = "secret/key+x"


class _AwsRaw:
    def __init__(self, b):
        self.b = b

    def stream(self, **kw):
        yield self.b

    def close(self):
        pass

    def read(self, *a):
        return self.b


def _aws_patch():
    import datetime as dt
    import time
    import uuid

    import botocore.auth
    import botocore.endpoint

    saved = (botocore.auth.get_current_datetime, botocore.endpoint.uuid.uuid4, time.sleep)
    botocore.auth.get_current_datetime = lambda: dt.datetime(*AWS_FIXED_NOW)
    botocore.endpoint.uuid.uuid4 = lambda: uuid.UUID(AWS_FIXED_ID)
    time.sleep = lambda s: None
    return saved


def _aws_unpatch(saved):
    import time

    import botocore.auth
    import botocore.endpoint

    botocore.auth.get_current_datetime, botocore.endpoint.uuid.uuid4, time.sleep = saved


def _aws_request(r):
    headers = []
    for k, v in r.headers.items():
        if k == "User-Agent":
            continue
        headers.append([k, v.decode() if isinstance(v, bytes) else str(v)])
    body = r.body
    if isinstance(body, bytes):
        body = body.decode()
    return {"method": r.method, "url": r.url, "headers": headers, "body": body or ""}


def _aws_answer(a):
    if isinstance(a, Exception):
        return {"raise": type(a).__name__}
    status, headers, body = a
    return {"status": status, "headers": headers, "body": body.decode()}


class _AwsScript:
    """Answers each request from a list consumed in order, or from a function of (method, url);
    records the requests and the answers given."""

    def __init__(self, answers):
        self.answers = answers if callable(answers) else list(answers)
        self.seen = []
        self.given = []

    def __call__(self, request, **kw):
        from botocore.awsrequest import AWSResponse

        self.seen.append(_aws_request(request))
        if callable(self.answers):
            a = self.answers(request.method, request.url)
        else:
            a = self.answers.pop(0) if self.answers else (200, {}, b"")
        self.given.append(_aws_answer(a))
        if isinstance(a, Exception):
            raise a
        status, headers, body = a
        resp = AWSResponse(request.url, status, headers, _AwsRaw(body))
        resp._content = body
        return resp


def _aws_config():
    from botocore.config import Config

    return Config(connect_timeout=5, read_timeout=15, retries={"max_attempts": 2, "mode": "standard"})


def _aws_set_endpoint(override):
    import os

    if override:
        os.environ["AWS_ENDPOINT_URL"] = override
    else:
        os.environ.pop("AWS_ENDPOINT_URL", None)


def _aws_jsonable(v):
    import datetime as dt

    if isinstance(v, dict):
        return {k: _aws_jsonable(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_aws_jsonable(x) for x in v]
    if isinstance(v, dt.datetime):
        return v.isoformat()
    return v


def _aws_outcome(fn):
    from botocore.exceptions import ClientError

    try:
        out = fn()
        out = {k: v for k, v in out.items() if k != "Body"}
        meta = out.pop("ResponseMetadata", {})
        return {"ok": _aws_jsonable(out), "headers": meta.get("HTTPHeaders"), "retries": meta.get("RetryAttempts")}
    except ClientError as e:
        error = e.response.get("Error", {})
        return {
            "client_error": {
                "error": _aws_jsonable(error) if isinstance(error, dict) else {"__text__": error},
                "headers": e.response.get("ResponseMetadata", {}).get("HTTPHeaders"),
            },
        }
    except Exception as e:  # noqa: BLE001
        return {"exception": [type(e).__name__, str(e)]}


def _sts_ok(account="123456789012"):
    return (
        200,
        {"Content-Type": "text/xml"},
        (
            '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">\n  <GetCallerIdentityResult>\n'
            "    <Arn>arn:aws:iam::" + account + ":user/x</Arn>\n    <UserId>AIDA</UserId>\n    <Account>" + account + "</Account>\n"
            "  </GetCallerIdentityResult>\n  <ResponseMetadata><RequestId>r-1</RequestId></ResponseMetadata>\n</GetCallerIdentityResponse>\n"
        ).encode(),
    )


def _s3_error(status, code, message, extra=b""):
    return (
        status,
        {"Content-Type": "application/xml", "x-amz-request-id": "rq"},
        b'<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>'
        + code
        + b"</Code><Message>"
        + message
        + b"</Message>"
        + extra
        + b"<RequestId>rq</RequestId><HostId>h</HostId></Error>",
    )


def _list_body(contents=(), prefixes=(), encoding=True):
    items = "".join(
        "<Contents><Key>"
        + key
        + "</Key><LastModified>2026-10-16T01:02:03.000Z</LastModified><ETag>&quot;e&quot;</ETag><Size>"
        + str(size)
        + "</Size>"
        + (f"<StorageClass>{storage}</StorageClass>" if storage else "")
        + "</Contents>"
        for key, size, storage in contents
    )
    common = "".join(f"<CommonPrefixes><Prefix>{p}</Prefix></CommonPrefixes>" for p in prefixes)
    enc = "<EncodingType>url</EncodingType>" if encoding else ""
    return (
        200,
        {"Content-Type": "application/xml"},
        (
            '<?xml version="1.0" encoding="UTF-8"?>\n<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            f"<Name>my-bucket</Name><KeyCount>{len(contents)}</KeyCount><MaxKeys>25</MaxKeys>{enc}<IsTruncated>false</IsTruncated>"
            + items
            + common
            + "</ListBucketResult>"
        ).encode(),
    )


def aws_call_vectors():
    """One call each, scripted answers: the requests sent (retries and redirects included) and what
    the caller sees."""
    import boto3
    from botocore.exceptions import ConnectTimeoutError
    from botocore.exceptions import EndpointConnectionError
    from botocore.exceptions import ReadTimeoutError

    sts_err = (
        403,
        {"Content-Type": "text/xml"},
        b'<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">\n  <Error>\n    <Type>Sender</Type>\n    <Code>InvalidClientTokenId</Code>\n'
        b"    <Message>The security token included in the request is invalid.</Message>\n  </Error>\n  <RequestId>r-2</RequestId>\n</ErrorResponse>\n",
    )
    list_body = (
        200,
        {"Content-Type": "application/xml"},
        b'<?xml version="1.0" encoding="UTF-8"?>\n<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>my-bucket</Name><Prefix>A%2F</Prefix>'
        b"<KeyCount>4</KeyCount><MaxKeys>25</MaxKeys><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated><Contents><Key>A/</Key>"
        b"<LastModified>2026-10-16T01:02:03.000Z</LastModified><ETag>&quot;e&quot;</ETag><Size>0</Size><StorageClass>STANDARD</StorageClass></Contents>"
        b"<Contents><Key>A/a+b%20c%2Bd.json.gz</Key><LastModified>2026-10-16T01:02:03.000Z</LastModified><ETag>&quot;e&quot;</ETag>"
        b"<ChecksumAlgorithm>CRC64NVME</ChecksumAlgorithm><ChecksumType>FULL_OBJECT</ChecksumType><Size>1234</Size><StorageClass>GLACIER</StorageClass>"
        b"</Contents><Contents><Key>A/%C3%A9.gz</Key><Size>5</Size></Contents><CommonPrefixes><Prefix>A/eu-west-1/</Prefix></CommonPrefixes>"
        b"<CommonPrefixes><Prefix>A/us%20east/</Prefix></CommonPrefixes></ListBucketResult>",
    )
    E = AWS_ENDPOINT
    cases = [
        ("sts ok", "sts", "us-east-1", None, "get_caller_identity", {}, [_sts_ok()]),
        ("sts ok over the override", "sts", "us-east-1", E, "get_caller_identity", {}, [_sts_ok()]),
        ("sts bad key", "sts", "us-east-1", E, "get_caller_identity", {}, [sts_err]),
        ("sts 500 thrice", "sts", "us-east-1", E, "get_caller_identity", {}, [(500, {}, b"")] * 3),
        ("sts 503 html then ok", "sts", "us-east-1", E, "get_caller_identity", {}, [(503, {}, b"<html>busy</html>"), _sts_ok()]),
        (
            "sts throttled then ok",
            "sts",
            "us-east-1",
            E,
            "get_caller_identity",
            {},
            [
                (400, {}, b"<ErrorResponse><Error><Code>Throttling</Code><Message>Rate exceeded</Message></Error></ErrorResponse>"),
                _sts_ok(),
            ],
        ),
        ("sts 400 empty", "sts", "us-east-1", E, "get_caller_identity", {}, [(400, {}, b"")]),
        (
            "sts 503 with a date, then ok",
            "sts",
            "us-east-1",
            E,
            "get_caller_identity",
            {},
            [(503, {"Date": "Sat, 17 Oct 2026 12:00:05 GMT"}, b""), _sts_ok()],
        ),
        (
            "sts 503 with a date, refused, then ok",
            "sts",
            "us-east-1",
            E,
            "get_caller_identity",
            {},
            [(503, {"Date": "Sat, 17 Oct 2026 11:59:00 UTC"}, b""), EndpointConnectionError(endpoint_url=E + "/"), _sts_ok()],
        ),
        ("sts 503 with a date that does not parse", "sts", "us-east-1", E, "get_caller_identity", {}, [(503, {"Date": "yesterday"}, b""), _sts_ok()]),
        ("sts 403 not xml", "sts", "us-east-1", E, "get_caller_identity", {}, [(403, {}, b"nope")]),
        (
            "sts 400 error as text",
            "sts",
            "us-east-1",
            E,
            "get_caller_identity",
            {},
            [(400, {}, b"<ErrorResponse><Error>oops</Error></ErrorResponse>")],
        ),
        (
            "sts 400 empty message",
            "sts",
            "us-east-1",
            E,
            "get_caller_identity",
            {},
            [(400, {}, b"<ErrorResponse><Error><Code>X</Code><Message/></Error></ErrorResponse>")],
        ),
        ("sts 200 not xml", "sts", "us-east-1", E, "get_caller_identity", {}, [(200, {}, b"nope")]),
        (
            "sts 200 no account",
            "sts",
            "us-east-1",
            E,
            "get_caller_identity",
            {},
            [
                (
                    200,
                    {},
                    b"<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>a</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>",
                ),
            ],
        ),
        (
            "sts 200 no result",
            "sts",
            "us-east-1",
            E,
            "get_caller_identity",
            {},
            [(200, {}, b"<GetCallerIdentityResponse></GetCallerIdentityResponse>")],
        ),
        ("sts refused", "sts", "us-east-1", E, "get_caller_identity", {}, [EndpointConnectionError(endpoint_url=E + "/")] * 3),
        (
            "sts connect timeout then ok",
            "sts",
            "us-east-1",
            E,
            "get_caller_identity",
            {},
            [ConnectTimeoutError(endpoint_url=E + "/"), _sts_ok()],
        ),
        (
            "sts read timeout",
            "sts",
            "us-east-1",
            None,
            "get_caller_identity",
            {},
            [ReadTimeoutError(endpoint_url="https://sts.us-east-1.amazonaws.com/")] * 3,
        ),
        ("sts in eu-central-1", "sts", "eu-central-1", None, "get_caller_identity", {}, [_sts_ok()]),
        (
            "head ok",
            "s3",
            "us-east-1",
            None,
            "head_bucket",
            {"Bucket": "my-bucket"},
            [(200, {"x-amz-bucket-region": "eu-west-1", "x-amz-request-id": "rq"}, b"")],
        ),
        ("head ok, dotted", "s3", "us-east-1", None, "head_bucket", {"Bucket": "my.bucket"}, [(200, {}, b"")]),
        ("head ok, eu-west-1", "s3", "eu-west-1", None, "head_bucket", {"Bucket": "my-bucket"}, [(200, {}, b"")]),
        ("head 404", "s3", "us-east-1", E, "head_bucket", {"Bucket": "my-bucket"}, [(404, {"x-amz-request-id": "rq"}, b"")]),
        ("head 403", "s3", "us-east-1", E, "head_bucket", {"Bucket": "my-bucket"}, [(403, {"x-amz-bucket-region": "eu-west-1"}, b"")]),
        (
            "head 301 redirected",
            "s3",
            "us-east-1",
            None,
            "head_bucket",
            {"Bucket": "my-bucket"},
            [(301, {"x-amz-bucket-region": "eu-west-1"}, b""), (200, {"x-amz-bucket-region": "eu-west-1"}, b"")],
        ),
        (
            "head 301 redirected over the override",
            "s3",
            "us-east-1",
            E,
            "head_bucket",
            {"Bucket": "my-bucket"},
            [(301, {"x-amz-bucket-region": "eu-west-1"}, b""), (200, {"x-amz-bucket-region": "eu-west-1"}, b"")],
        ),
        (
            "head 301 twice",
            "s3",
            "us-east-1",
            None,
            "head_bucket",
            {"Bucket": "my.bucket"},
            [(301, {"x-amz-bucket-region": "ap-south-1"}, b"")] * 2,
        ),
        (
            "head 301 with a date",
            "s3",
            "us-east-1",
            E,
            "head_bucket",
            {"Bucket": "my-bucket"},
            [(301, {"x-amz-bucket-region": "eu-west-1", "Date": "Sat, 17 Oct 2026 12:01:00 GMT"}, b""), (200, {}, b"")],
        ),
        (
            "head 400 with region",
            "s3",
            "us-east-1",
            E,
            "head_bucket",
            {"Bucket": "my-bucket"},
            [(400, {"x-amz-bucket-region": "eu-central-1"}, b""), (400, {"x-amz-bucket-region": "eu-central-1"}, b"")],
        ),
        ("head 400 without region", "s3", "us-east-1", E, "head_bucket", {"Bucket": "my-bucket"}, [(400, {}, b"")]),
        (
            "head 301 without region (a second HEAD)",
            "s3",
            "us-east-1",
            E,
            "head_bucket",
            {"Bucket": "my-bucket"},
            [(301, {}, b""), (301, {}, b"")],
        ),
        ("head 500 thrice", "s3", "us-east-1", E, "head_bucket", {"Bucket": "my-bucket"}, [(500, {}, b"")] * 3),
        ("head 503 slow down then ok", "s3", "us-east-1", E, "head_bucket", {"Bucket": "my-bucket"}, [(503, {}, b""), (200, {}, b"")]),
        (
            "head 307 with an invalid region",
            "s3",
            "us-east-1",
            E,
            "head_bucket",
            {"Bucket": "my-bucket"},
            [(307, {"x-amz-bucket-region": "bad region!"}, b"")],
        ),
        ("list ok", "s3", "eu-west-1", None, "list_objects_v2", {"Bucket": "my-bucket", "Prefix": "A/", "MaxKeys": 25}, [list_body]),
        (
            "list ok, dotted",
            "s3",
            "eu-west-1",
            None,
            "list_objects_v2",
            {"Bucket": "my.bucket", "Prefix": "A/", "MaxKeys": 25},
            [list_body],
        ),
        (
            "list ok over the override",
            "s3",
            "eu-west-1",
            E,
            "list_objects_v2",
            {"Bucket": "my-bucket", "Prefix": "A/(x) y~é+&=", "Delimiter": "/"},
            [list_body],
        ),
        (
            "list access denied",
            "s3",
            "eu-west-1",
            E,
            "list_objects_v2",
            {"Bucket": "my-bucket", "Prefix": "A/", "MaxKeys": 25},
            [_s3_error(403, b"AccessDenied", b"Access Denied")],
        ),
        (
            "list permanent redirect with region",
            "s3",
            "us-east-1",
            None,
            "list_objects_v2",
            {"Bucket": "my-bucket", "Prefix": "A/", "Delimiter": "/"},
            [
                _s3_error(
                    301,
                    b"PermanentRedirect",
                    b"The bucket you are attempting to access must be addressed using the specified endpoint.",
                    b"<Endpoint>my-bucket.s3.eu-west-1.amazonaws.com</Endpoint><Bucket>my-bucket</Bucket>",
                ),
                (200, {"x-amz-bucket-region": "eu-west-1"}, b""),
                list_body,
            ],
        ),
        (
            "list authorization header malformed",
            "s3",
            "us-east-1",
            E,
            "list_objects_v2",
            {"Bucket": "my-bucket", "Prefix": "A/", "MaxKeys": 25},
            [
                _s3_error(
                    400,
                    b"AuthorizationHeaderMalformed",
                    b"The authorization header is malformed; the region 'us-east-1' is wrong; expecting 'eu-west-2'",
                    b"<Region>eu-west-2</Region>",
                ),
                list_body,
            ],
        ),
        (
            "list internal error thrice",
            "s3",
            "eu-west-1",
            E,
            "list_objects_v2",
            {"Bucket": "my-bucket", "Prefix": "A/", "MaxKeys": 25},
            [_s3_error(500, b"InternalError", b"We encountered an internal error. Please try again.")] * 3,
        ),
        (
            "list 200 not xml",
            "s3",
            "eu-west-1",
            E,
            "list_objects_v2",
            {"Bucket": "my-bucket", "Prefix": "A/", "MaxKeys": 25},
            [(200, {}, b"<ListBucketResult><Contents>")],
        ),
        (
            "list 200 error",
            "s3",
            "eu-west-1",
            E,
            "list_objects_v2",
            {"Bucket": "my-bucket", "Prefix": "A/", "MaxKeys": 25},
            [_s3_error(200, b"InternalError", b"x")] * 3,
        ),
        (
            "list 403 not xml",
            "s3",
            "eu-west-1",
            E,
            "list_objects_v2",
            {"Bucket": "my-bucket", "Prefix": "A/", "MaxKeys": 25},
            [(403, {}, b"<html>denied</html>")],
        ),
        (
            "list bad size",
            "s3",
            "eu-west-1",
            E,
            "list_objects_v2",
            {"Bucket": "my-bucket", "Prefix": "A/", "MaxKeys": 25},
            [
                (
                    200,
                    {},
                    b"<ListBucketResult><EncodingType>url</EncodingType><Contents><Key>k</Key><Size>big</Size></Contents></ListBucketResult>",
                ),
            ],
        ),
        (
            "list no key",
            "s3",
            "eu-west-1",
            E,
            "list_objects_v2",
            {"Bucket": "my-bucket", "Prefix": "A/", "MaxKeys": 25},
            [(200, {}, b"<ListBucketResult><Contents><Size>3</Size></Contents></ListBucketResult>")],
        ),
        (
            "list no key, url encoded",
            "s3",
            "eu-west-1",
            E,
            "list_objects_v2",
            {"Bucket": "my-bucket", "Prefix": "A/", "MaxKeys": 25},
            [(200, {}, b"<ListBucketResult><EncodingType>url</EncodingType><Contents><Size>3</Size></Contents></ListBucketResult>")],
        ),
        (
            "list without encoding type",
            "s3",
            "eu-west-1",
            E,
            "list_objects_v2",
            {"Bucket": "my-bucket", "Prefix": "A/", "MaxKeys": 25},
            [(200, {}, b"<ListBucketResult><Contents><Key>a%20b</Key><Size>3</Size></Contents></ListBucketResult>")],
        ),
        (
            "list empty prefix",
            "s3",
            "eu-west-1",
            E,
            "list_objects_v2",
            {"Bucket": "my-bucket", "Prefix": "A/", "Delimiter": "/"},
            [(200, {}, b"<ListBucketResult><EncodingType>url</EncodingType><CommonPrefixes></CommonPrefixes></ListBucketResult>")],
        ),
        (
            "get ok",
            "s3",
            "eu-west-1",
            None,
            "get_object",
            {"Bucket": "my-bucket", "Key": "A/a b+c(1)~!*'=&%/é", "Range": "bytes=0-0"},
            [(206, {"Content-Range": "bytes 0-0/9"}, b"x")],
        ),
        (
            "get kms denied",
            "s3",
            "eu-west-1",
            E,
            "get_object",
            {"Bucket": "my-bucket", "Key": "k", "Range": "bytes=0-0"},
            [_s3_error(403, b"AccessDenied", b"User: arn:aws:iam::1:user/x is not authorized to perform: kms:Decrypt")],
        ),
        (
            "get invalid object state",
            "s3",
            "eu-west-1",
            E,
            "get_object",
            {"Bucket": "my-bucket", "Key": "k", "Range": "bytes=0-0"},
            [_s3_error(403, b"InvalidObjectState", b"The operation is not valid for the object's storage class")],
        ),
        (
            "get KMS code",
            "s3",
            "eu-west-1",
            E,
            "get_object",
            {"Bucket": "my-bucket", "Key": "k", "Range": "bytes=0-0"},
            [_s3_error(400, b"KMS.DisabledException", b"")],
        ),
        (
            "get no message",
            "s3",
            "eu-west-1",
            E,
            "get_object",
            {"Bucket": "my-bucket", "Key": "k", "Range": "bytes=0-0"},
            [(404, {}, b"<Error><Code>NoSuchKey</Code></Error>")],
        ),
        (
            "get 200 error body",
            "s3",
            "eu-west-1",
            E,
            "get_object",
            {"Bucket": "my-bucket", "Key": "k", "Range": "bytes=0-0"},
            [(200, {}, b"<Error><Code>X</Code></Error>")],
        ),
    ]
    out = []
    for name, service, region, override, op, params, answers in cases:
        _aws_set_endpoint(override)
        session = boto3.Session(aws_access_key_id=AWS_KEY_ID, aws_secret_access_key=AWS_SECRET)
        client = session.client(service, region_name=region, config=_aws_config())
        script = _AwsScript(answers)
        client.meta.events.register("before-send", script)
        result = _aws_outcome(lambda: getattr(client, op)(**params))
        out.append(
            {
                "name": name,
                "service": service,
                "region": region,
                "endpoint": override,
                "op": op,
                "params": params,
                "answers": script.given,
                "requests": script.seen,
                "result": result,
            },
        )
    _aws_set_endpoint(None)
    return out


AWS_VALIDATE_KEYS = {
    "ACCESS_KEY_ID": AWS_KEY_ID,
    "SECRET_ACCESS_KEY": AWS_SECRET,
    "AWS_ACCOUNT_ID": "123456789012",
    "BUCKET_NAME": "my-bucket",
    "SERVICES": "cloudtrail",
}


def _router(rules):
    """An answering function: the first rule whose test matches (method, url) answers; the last
    rule's answer repeats."""

    def answer(method, url):
        for test, reply in rules:
            if test(method, url):
                return reply(method, url) if callable(reply) else reply
        return (200, {}, b"")

    return answer


def _is(method, needle=""):
    return lambda m, u: m == method and needle in u


def aws_validate_vectors():
    """`_validate` end to end over scripted answers: the requests (headers and all) and the
    result, the `AwsValidationError` text, or whatever escapes."""
    import boto3
    from botocore.exceptions import ConnectTimeoutError
    from botocore.exceptions import EndpointConnectionError

    from app.integrations.aws.schema.provision import ProvisionAwsAuthKeys
    from app.integrations.aws.services import validate as v

    class FixedDateTime(v.datetime):
        @classmethod
        def now(cls, tz=None):
            return v.datetime(2026, 10, 17, 12, 0, 0, tzinfo=tz)

    prefix = "AWSLogs/123456789012/CloudTrail/"
    region_prefix = prefix + "eu-west-1/"
    day = region_prefix + "2026/10/17/"
    key = day + "123456789012_CloudTrail_eu-west-1_x.json.gz"
    head_ok = (200, {"x-amz-bucket-region": "eu-west-1"}, b"")
    get_ok = (206, {"Content-Range": "bytes 0-0/9"}, b"x")
    delim = "delimiter=%2F"
    regions = _list_body(prefixes=[region_prefix])
    listing_ok = [
        (_is("GET", delim), regions),
        (_is("GET", "prefix=" + "AWSLogs%2F123456789012%2FCloudTrail%2Feu-west-1%2F2026%2F10%2F17%2F"), _list_body([(key, 9, "STANDARD")])),
        (_is("GET", "list-type"), _list_body()),
        (_is("GET"), get_ok),
    ]
    base = [(_is("POST"), _sts_ok()), (_is("HEAD"), head_ok)]
    E = AWS_ENDPOINT
    cases = [
        ("ok", None, AWS_VALIDATE_KEYS, base + listing_ok),
        ("ok over the override", E, AWS_VALIDATE_KEYS, base + listing_ok),
        ("wrong account", E, AWS_VALIDATE_KEYS, [(_is("POST"), _sts_ok("111111111111"))]),
        (
            "no account",
            E,
            AWS_VALIDATE_KEYS,
            [
                (
                    _is("POST"),
                    (
                        200,
                        {},
                        b"<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>a</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>",
                    ),
                ),
            ],
        ),
        (
            "bad key",
            E,
            AWS_VALIDATE_KEYS,
            [
                (
                    _is("POST"),
                    (403, {}, b"<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>no</Message></Error></ErrorResponse>"),
                ),
            ],
        ),
        (
            "sts refused otherwise",
            E,
            AWS_VALIDATE_KEYS,
            [
                (
                    _is("POST"),
                    (403, {}, b"<ErrorResponse><Error><Code>AccessDenied</Code><Message>not allowed</Message></Error></ErrorResponse>"),
                ),
            ],
        ),
        (
            "sts refused without a message",
            E,
            AWS_VALIDATE_KEYS,
            [(_is("POST"), (403, {}, b"<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>"))],
        ),
        ("sts error as text", E, AWS_VALIDATE_KEYS, [(_is("POST"), (403, {}, b"<ErrorResponse><Error>oops</Error></ErrorResponse>"))]),
        ("sts not xml", E, AWS_VALIDATE_KEYS, [(_is("POST"), (200, {}, b"nope"))]),
        ("unreachable", E, AWS_VALIDATE_KEYS, [(_is("POST"), lambda m, u: EndpointConnectionError(endpoint_url=u))]),
        ("no bucket", E, AWS_VALIDATE_KEYS, [(_is("POST"), _sts_ok()), (_is("HEAD"), (404, {}, b""))]),
        ("bucket denied", E, AWS_VALIDATE_KEYS, [(_is("POST"), _sts_ok()), (_is("HEAD"), (403, {}, b""))]),
        (
            "bucket in another region (400)",
            E,
            AWS_VALIDATE_KEYS,
            [(_is("POST"), _sts_ok()), (_is("HEAD"), (400, {"x-amz-bucket-region": "eu-central-1"}, b""))] + listing_ok,
        ),
        ("bucket 400 without region", E, AWS_VALIDATE_KEYS, [(_is("POST"), _sts_ok()), (_is("HEAD"), (400, {}, b""))]),
        ("bucket 500", E, AWS_VALIDATE_KEYS, [(_is("POST"), _sts_ok()), (_is("HEAD"), (500, {}, b""))]),
        (
            "bucket invalid region",
            E,
            AWS_VALIDATE_KEYS,
            [(_is("POST"), _sts_ok()), (_is("HEAD"), (307, {"x-amz-bucket-region": "bad region!"}, b""))],
        ),
        (
            "bucket answered with an invalid region",
            E,
            AWS_VALIDATE_KEYS,
            [(_is("POST"), _sts_ok()), (_is("HEAD"), (200, {"x-amz-bucket-region": "bad region!"}, b""))],
        ),
        ("bucket without region header", None, AWS_VALIDATE_KEYS, [(_is("POST"), _sts_ok()), (_is("HEAD"), (200, {}, b""))] + listing_ok),
        ("list denied", E, AWS_VALIDATE_KEYS, base + [(_is("GET"), _s3_error(403, b"AccessDenied", b"Access Denied"))]),
        (
            "list failed",
            E,
            AWS_VALIDATE_KEYS,
            base + [(_is("GET"), _s3_error(404, b"NoSuchBucket", b"The specified bucket does not exist"))],
        ),
        ("list unreachable", E, AWS_VALIDATE_KEYS, base + [(_is("GET"), lambda m, u: ConnectTimeoutError(endpoint_url=u))]),
        ("no logs", E, AWS_VALIDATE_KEYS, base + [(_is("GET"), _list_body())]),
        (
            "archived only",
            E,
            AWS_VALIDATE_KEYS,
            base
            + [
                (_is("GET", delim), regions),
                (_is("GET", "max-keys=25&encoding-type=url"), _list_body([(prefix + "old.gz", 5, "GLACIER")])),
            ],
        ),
        (
            "archived only, the day lists answer the archive too",
            E,
            AWS_VALIDATE_KEYS,
            base
            + [(_is("GET", delim), regions), (_is("GET"), _list_body([(prefix + "d/", 0, None), (prefix + "old.gz", 5, "DEEP_ARCHIVE")]))],
        ),
        (
            "fallback finds a readable object",
            E,
            AWS_VALIDATE_KEYS,
            base
            + [
                (_is("GET", delim), _list_body()),
                (
                    _is("GET", "list-type"),
                    _list_body([(prefix + "x/", 0, None), (prefix + "empty.gz", 0, None), (prefix + "k.gz", 3, None)]),
                ),
                (_is("GET"), get_ok),
            ],
        ),
        (
            "kms denied",
            E,
            AWS_VALIDATE_KEYS,
            base + listing_ok[:3] + [(_is("GET"), _s3_error(403, b"AccessDenied", b"no kms:Decrypt for you"))],
        ),
        ("get denied", E, AWS_VALIDATE_KEYS, base + listing_ok[:3] + [(_is("GET"), _s3_error(403, b"AccessDenied", b"Access Denied"))]),
        ("get failed", E, AWS_VALIDATE_KEYS, base + listing_ok[:3] + [(_is("GET"), _s3_error(403, b"InvalidObjectState", b"archived"))]),
        ("get KMS code", E, AWS_VALIDATE_KEYS, base + listing_ok[:3] + [(_is("GET"), _s3_error(400, b"KMS.NotFoundException", b""))]),
        (
            "bad size",
            E,
            AWS_VALIDATE_KEYS,
            base
            + [
                (_is("GET", delim), regions),
                (_is("GET"), (200, {}, b"<ListBucketResult><Contents><Key>k</Key><Size>big</Size></Contents></ListBucketResult>")),
            ],
        ),
        (
            "no key",
            E,
            AWS_VALIDATE_KEYS,
            base
            + [
                (_is("GET", delim), regions),
                (_is("GET"), (200, {}, b"<ListBucketResult><Contents><Size>3</Size></Contents></ListBucketResult>")),
            ],
        ),
        (
            "prefix without Prefix",
            E,
            AWS_VALIDATE_KEYS,
            base + [(_is("GET"), (200, {}, b"<ListBucketResult><CommonPrefixes></CommonPrefixes></ListBucketResult>"))],
        ),
        (
            "two services, an organization and a prefix",
            E,
            {**AWS_VALIDATE_KEYS, "SERVICES": "cloudtrail:org-trail,guardduty:gd/", "AWS_ORGANIZATION_ID": "o-a1b2c3d4e5"},
            base
            + [
                (_is("GET", delim), _list_body()),
                (_is("GET", "list-type"), lambda m, u: _list_body([("some/where/x.gz", 7, "STANDARD_IA")])),
                (_is("GET"), get_ok),
            ],
        ),
        (
            "guardduty archived",
            E,
            {**AWS_VALIDATE_KEYS, "SERVICES": "guardduty"},
            base + [(_is("GET", delim), _list_body()), (_is("GET", "list-type"), _list_body([("x.gz", 7, "GLACIER")]))],
        ),
    ]
    out = []
    saved_dt = v.datetime
    saved_client = boto3.Session.client
    v.datetime = FixedDateTime
    try:
        for name, override, raw_keys, rules in cases:
            _aws_set_endpoint(override)
            script = _AwsScript(_router(rules))

            def client(self, *a, **kw):
                c = saved_client(self, *a, **kw)
                c.meta.events.register("before-send", script)
                return c

            boto3.Session.client = client
            keys = ProvisionAwsAuthKeys(**raw_keys)
            try:
                r = v._validate(keys, keys.service_configs())
                result = {"ok": {"validated": r.validated, "bucket_region": r.bucket_region, "warnings": r.warnings}}
            except v.AwsValidationError as e:
                result = {"invalid": str(e)}
            except Exception as e:  # noqa: BLE001
                result = {"exception": [type(e).__name__, str(e)]}
            out.append(
                {"name": name, "endpoint": override, "keys": raw_keys, "answers": script.given, "requests": script.seen, "result": result},
            )
    finally:
        v.datetime = saved_dt
        boto3.Session.client = saved_client
        _aws_set_endpoint(None)
    return out


AWS_OSSEC_HEAD = """<!-- Wazuh - Manager - Default configuration -->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
  </global>
"""
AWS_OSSEC_TAIL = """</ossec_config>

<ossec_config>
  <!-- the second block -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/x</location>
  </localfile>
</ossec_config>
"""


def _bucket(kind, name, account, extra="", start="2026-JAN-01", key="AKIAOTHER0000000000"):
    account_xml = f"\n      <aws_account_id>{account}</aws_account_id>" if account is not None else ""
    return (
        f'    <bucket type="{kind}">\n      <name>{name}</name>{extra}\n      <access_key>{key}</access_key>\n'
        f"      <secret_key>s</secret_key>{account_xml}\n      <only_logs_after>{start}</only_logs_after>\n    </bucket>\n"
    )


def _wodle(buckets, disabled="no", extra=""):
    return (
        '  <wodle name="aws-s3">\n'
        f"    <disabled>{disabled}</disabled>\n    <interval>10m</interval>\n    <run_on_start>yes</run_on_start>\n    <skip_on_error>yes</skip_on_error>\n"
        + extra
        + "".join(buckets)
        + "  </wodle>\n"
    )


MINE = "123456789012"
OTHER_BUCKET = _bucket("cloudtrail", "other-bucket", "999999999999")
OWN_TRAIL = _bucket("cloudtrail", "my-bucket", MINE, start="2026-FEB-02", key=AWS_KEY_ID)
OWN_GUARD = _bucket("guardduty", "my-bucket", MINE, start="2026-FEB-02", key=AWS_KEY_ID)
AWS_CONFIGS = {
    "no wodle": AWS_OSSEC_HEAD + AWS_OSSEC_TAIL,
    "no wodle, one block": AWS_OSSEC_HEAD + "</ossec_config>\n",
    "no wodle, an empty block": "<ossec_config></ossec_config>",
    "another customer": AWS_OSSEC_HEAD + "\n  <!-- aws -->\n" + _wodle([OTHER_BUCKET]) + AWS_OSSEC_TAIL,
    "owned": AWS_OSSEC_HEAD + _wodle([OTHER_BUCKET, OWN_TRAIL, OWN_GUARD]) + AWS_OSSEC_TAIL,
    "owned, rotated key": AWS_OSSEC_HEAD + _wodle([OWN_TRAIL.replace(AWS_KEY_ID, "AKIAOLDKEY0000000000"), OTHER_BUCKET]) + AWS_OSSEC_TAIL,
    "owned twice": AWS_OSSEC_HEAD + _wodle([OWN_TRAIL, OTHER_BUCKET, OWN_TRAIL]) + AWS_OSSEC_TAIL,
    "only ours": AWS_OSSEC_HEAD + "  <!-- before -->\n" + _wodle([OWN_TRAIL]) + "  <!-- after -->\n" + AWS_OSSEC_TAIL,
    "only ours, first child": "<ossec_config>" + _wodle([OWN_TRAIL]).lstrip() + "</ossec_config>",
    "ours with a service": AWS_OSSEC_HEAD
    + _wodle([OWN_TRAIL], extra='    <service type="inspector">\n      <regions>us-east-1</regions>\n    </service>\n')
    + AWS_OSSEC_TAIL,
    "hand-made": AWS_OSSEC_HEAD + _wodle([_bucket("cloudtrail", "my-bucket", MINE)]) + AWS_OSSEC_TAIL,
    "no account": AWS_OSSEC_HEAD + _wodle([_bucket("cloudtrail", "my-bucket", None)]) + AWS_OSSEC_TAIL,
    "several accounts": AWS_OSSEC_HEAD + _wodle([_bucket("cloudtrail", "my-bucket", f"{MINE}, 999999999999")]) + AWS_OSSEC_TAIL,
    "other path": AWS_OSSEC_HEAD
    + _wodle([_bucket("cloudtrail", "my-bucket", "999999999999", extra="\n      <path>/org-trail/</path>")])
    + AWS_OSSEC_TAIL,
    "disabled": AWS_OSSEC_HEAD + _wodle([OTHER_BUCKET], disabled="YES") + AWS_OSSEC_TAIL,
    "two wodles": AWS_OSSEC_HEAD + _wodle([OTHER_BUCKET]) + "</ossec_config>\n<ossec_config>\n" + _wodle([OWN_TRAIL]) + "</ossec_config>\n",
    "declaration": "<?xml version='1.0' encoding='UTF-8'?>\n" + AWS_OSSEC_HEAD + AWS_OSSEC_TAIL,
    "masked": AWS_OSSEC_HEAD + "  <auth><key>*****</key></auth>\n" + AWS_OSSEC_TAIL,
    "dtd": '<!DOCTYPE x [<!ENTITY a "b">]>\n' + AWS_OSSEC_HEAD + AWS_OSSEC_TAIL,
    "doctype lower": "<!doctype x>" + AWS_OSSEC_HEAD + AWS_OSSEC_TAIL,
    "empty": "  \n ",
    "no block": "<foo/>",
    "broken": "<ossec_config><x></ossec_config>",
    "text at the root": "junk " + AWS_OSSEC_HEAD + AWS_OSSEC_TAIL,
    "wodle named with spaces": AWS_OSSEC_HEAD + _wodle([OWN_TRAIL]).replace('name="aws-s3"', 'name=" aws-s3 "') + AWS_OSSEC_TAIL,
}
AWS_RECONCILE_CASES = [
    # (config, SERVICES, ONLY_LOGS_AFTER, adopt_existing, keep_only_logs_after, extra keys)
    ("no wodle", "cloudtrail,guardduty", "2026-OCT-01", False, True, {}),
    ("no wodle, one block", "cloudtrail", "2026-OCT-01", False, True, {}),
    ("no wodle, an empty block", "cloudtrail", "2026-OCT-01", False, True, {}),
    (
        "another customer",
        "cloudtrail:org-trail/,guardduty",
        "2026-OCT-01",
        False,
        True,
        {"AWS_ACCOUNT_ALIAS": "prod", "AWS_ORGANIZATION_ID": "o-a1b2c3d4e5"},
    ),
    ("owned", "cloudtrail,guardduty", "2026-OCT-01", True, True, {}),
    ("owned", "cloudtrail,guardduty", "2026-OCT-01", True, False, {}),
    ("owned", "cloudtrail", "2026-OCT-01", True, True, {}),
    ("owned", "guardduty:gd", "2026-OCT-01", True, True, {}),
    ("owned", "", None, True, False, {}),
    ("owned", "cloudtrail", "2026-OCT-01", False, True, {}),
    ("owned, rotated key", "cloudtrail", "2026-OCT-01", True, True, {}),
    ("owned twice", "cloudtrail", "2026-OCT-01", True, True, {}),
    ("only ours", "", None, True, False, {}),
    ("only ours, first child", "", None, True, False, {}),
    ("ours with a service", "", None, True, False, {}),
    ("hand-made", "cloudtrail", "2026-OCT-01", False, True, {}),
    ("hand-made", "cloudtrail", "2026-OCT-01", True, True, {}),
    ("no account", "cloudtrail,guardduty", "2026-OCT-01", False, True, {}),
    ("several accounts", "cloudtrail", "2026-OCT-01", False, True, {}),
    ("other path", "cloudtrail:org-trail", "2026-OCT-01", False, True, {}),
    ("other path", "cloudtrail", "2026-OCT-01", False, True, {}),
    ("disabled", "guardduty", "2026-OCT-01", False, True, {}),
    ("two wodles", "cloudtrail,guardduty", "2026-OCT-01", True, True, {}),
    ("two wodles", "", None, True, False, {}),
    ("declaration", "cloudtrail", "2026-OCT-01", False, True, {}),
    ("masked", "cloudtrail", "2026-OCT-01", False, True, {}),
    ("dtd", "cloudtrail", "2026-OCT-01", False, True, {}),
    ("doctype lower", "cloudtrail", "2026-OCT-01", False, True, {}),
    ("empty", "cloudtrail", "2026-OCT-01", False, True, {}),
    ("no block", "cloudtrail", "2026-OCT-01", False, True, {}),
    ("broken", "cloudtrail", "2026-OCT-01", False, True, {}),
    ("text at the root", "cloudtrail", "2026-OCT-01", False, True, {}),
    ("wodle named with spaces", "cloudtrail", "2026-OCT-01", True, True, {}),
    ("another customer", "", None, True, False, {}),
]


def aws_reconcile_vectors():
    import xml.etree.ElementTree as ET

    from app.integrations.aws.schema.provision import ProvisionAwsAuthKeys
    from app.integrations.aws.services.wazuh_config import AwsWazuhConfigError
    from app.integrations.aws.services.wazuh_config import desired_buckets
    from app.integrations.aws.services.wazuh_config import reconcile_aws_buckets

    out = []
    for config_name, services, start, adopt, keep, extra in AWS_RECONCILE_CASES:
        raw_keys = {**AWS_VALIDATE_KEYS, "SERVICES": services or "cloudtrail", **extra}
        if start:
            raw_keys["ONLY_LOGS_AFTER"] = start
        keys = ProvisionAwsAuthKeys(**raw_keys)
        desired = desired_buckets(keys) if services else []
        case = {
            "config": AWS_CONFIGS[config_name],
            "name": config_name,
            "keys": raw_keys,
            "desired": bool(services),
            "adopt": adopt,
            "keep": keep,
        }
        try:
            r = reconcile_aws_buckets(
                AWS_CONFIGS[config_name],
                desired,
                keys.BUCKET_NAME,
                keys.AWS_ACCOUNT_ID,
                adopt_existing=adopt,
                keep_only_logs_after=keep,
            )
            case["result"] = {
                "config": r.config,
                "changed": r.changed,
                "added": r.added,
                "updated": r.updated,
                "removed": r.removed,
                "wodle_created": r.wodle_created,
                "wodle_removed": r.wodle_removed,
                "wodle_disabled": r.wodle_disabled,
                "previous": [ET.tostring(b, encoding="unicode") for b in r.previous],
            }
        except AwsWazuhConfigError as e:
            case["error"] = {"class": "AwsWazuhConfigError", "text": str(e)}
        except Exception as e:  # noqa: BLE001
            case["error"] = {"class": type(e).__name__, "text": str(e)}
        out.append(case)
    return out


AWS_AUTH_KEY_CASES = [
    AWS_VALIDATE_KEYS,
    {**AWS_VALIDATE_KEYS, "AWS_ACCOUNT_ALIAS": " prod ", "AWS_ORGANIZATION_ID": "o-a1b2c3d4e5", "ONLY_LOGS_AFTER": " 2026-oct-08 "},
    {**AWS_VALIDATE_KEYS, "AWS_ACCOUNT_ALIAS": "", "AWS_ORGANIZATION_ID": "  ", "ONLY_LOGS_AFTER": ""},
    {},
    {"ACCESS_KEY_ID": "", "SECRET_ACCESS_KEY": " ", "AWS_ACCOUNT_ID": "\t", "BUCKET_NAME": "", "SERVICES": ""},
    {**AWS_VALIDATE_KEYS, "ACCESS_KEY_ID": "akia0000000000000"},
    {**AWS_VALIDATE_KEYS, "ACCESS_KEY_ID": "AKIA"},
    {**AWS_VALIDATE_KEYS, "ACCESS_KEY_ID": "A" * 129},
    {**AWS_VALIDATE_KEYS, "AWS_ACCOUNT_ID": "12345678901"},
    {**AWS_VALIDATE_KEYS, "AWS_ACCOUNT_ID": "١٢٣٤٥٦٧٨٩٠١٢"},
    {**AWS_VALIDATE_KEYS, "AWS_ACCOUNT_ID": "12345678901a"},
    {**AWS_VALIDATE_KEYS, "AWS_ORGANIZATION_ID": "o-ABCDEFGHIJ"},
    {**AWS_VALIDATE_KEYS, "AWS_ORGANIZATION_ID": "o-abc"},
    {**AWS_VALIDATE_KEYS, "AWS_ACCOUNT_ALIAS": "pro d"},
    {**AWS_VALIDATE_KEYS, "AWS_ACCOUNT_ALIAS": "a" * 64},
    {**AWS_VALIDATE_KEYS, "BUCKET_NAME": "My-Bucket"},
    {**AWS_VALIDATE_KEYS, "BUCKET_NAME": "ab"},
    {**AWS_VALIDATE_KEYS, "BUCKET_NAME": "-ab"},
    {**AWS_VALIDATE_KEYS, "BUCKET_NAME": "a.b-c"},
    {**AWS_VALIDATE_KEYS, "BUCKET_NAME": "a" * 64},
    {**AWS_VALIDATE_KEYS, "SERVICES": "vpcflow"},
    {**AWS_VALIDATE_KEYS, "SERVICES": "cloudtrail,CloudTrail"},
    {**AWS_VALIDATE_KEYS, "SERVICES": "nope"},
    {**AWS_VALIDATE_KEYS, "SERVICES": " , "},
    {**AWS_VALIDATE_KEYS, "SERVICES": "cloudtrail:a b"},
    {**AWS_VALIDATE_KEYS, "SERVICES": "cloudtrail:/x/y/, guardduty : g "},
    {**AWS_VALIDATE_KEYS, "ONLY_LOGS_AFTER": "2026-10-08"},
    {**AWS_VALIDATE_KEYS, "ONLY_LOGS_AFTER": "2026-FEB-30"},
    {**AWS_VALIDATE_KEYS, "ONLY_LOGS_AFTER": "0000-JAN-01"},
    {**AWS_VALIDATE_KEYS, "ONLY_LOGS_AFTER": "٢٠٢٦-JAN-01"},
    {**AWS_VALIDATE_KEYS, "EXTRA": "ignored", "SECRET_ACCESS_KEY": "  sp ace  "},
    {
        "ACCESS_KEY_ID": "bad",
        "AWS_ACCOUNT_ID": "x",
        "BUCKET_NAME": "B",
        "SERVICES": "x",
        "ONLY_LOGS_AFTER": "y",
        "AWS_ACCOUNT_ALIAS": "!",
        "AWS_ORGANIZATION_ID": "z",
    },
]


def aws_auth_key_vectors():
    from fastapi import HTTPException

    from app.integrations.aws.routes.provision import parse_aws_auth_keys

    out = []
    for raw in AWS_AUTH_KEY_CASES:
        try:
            k = parse_aws_auth_keys(dict(raw))
            out.append(
                {
                    "keys": raw,
                    "ok": {
                        "ACCESS_KEY_ID": k.ACCESS_KEY_ID,
                        "SECRET_ACCESS_KEY": k.SECRET_ACCESS_KEY.get_secret_value(),
                        "AWS_ACCOUNT_ID": k.AWS_ACCOUNT_ID,
                        "AWS_ACCOUNT_ALIAS": k.AWS_ACCOUNT_ALIAS,
                        "AWS_ORGANIZATION_ID": k.AWS_ORGANIZATION_ID,
                        "BUCKET_NAME": k.BUCKET_NAME,
                        "SERVICES": k.SERVICES,
                        "ONLY_LOGS_AFTER": k.ONLY_LOGS_AFTER,
                    },
                },
            )
        except HTTPException as e:
            out.append({"keys": raw, "error": e.detail})
    return out


def aws_misc_vectors():
    import datetime as dt

    from app.integrations.aws.services import provision as p
    from app.integrations.aws.services import wazuh_manager as m
    from app.integrations.aws.utils import services as u

    def attempt(fn):
        try:
            return {"ok": fn()}
        except Exception as e:  # noqa: BLE001
            return {"exception": [type(e).__name__, str(e)]}

    prefixes = []
    for services in ("cloudtrail", "cloudtrail:org/,guardduty:/gd/x/", "guardduty"):
        for org in (None, "o-a1b2c3d4e5"):
            for config in u.parse_services(services):
                prefixes.append(
                    {"services": services, "org": org, "key": config.key, "prefix": u.s3_log_prefix(config, "123456789012", org)},
                )
    stamps = [
        "2026-10-17T10:00:00Z",
        "2026-10-17T09:00:00+00:00",
        "2026-10-17 10:00:00",
        "2026-10-17T12:00:00+02:00",
        "nope",
        "zzz",
        "",
        None,
        5,
        "2026-10-17",
    ]
    is_after = []
    for t in stamps:
        for mk in stamps:
            is_after.append({"timestamp": t, "marker": mk, "result": attempt(lambda: m._is_after(t, mk))})
    return {
        "rules": dict(p.aws_rule_sources()),
        "pipeline": p.aws_pipeline_source(),
        "same_source": [[a, b, p._same_source(a, b)] for a, b in [(None, ""), ("a  b\n c", "a b c"), ("a b", "a b"), ("ab", "a b")]],
        "notice": [
            {"detected": d, "region": r, "dump": m.aws_config_notice(d, r).model_dump()}
            for d, r in [(False, None), (True, "eu-west-1"), (False, "")]
        ],
        "prefixes": prefixes,
        "decode": [
            [v, u.decode_service_ids(v)] for v in [None, "", "cloudtrail:a,guardduty:b", " x:1 , y: , :z, w:2:3, x:4", "cloudtrail"]
        ],
        "encode": [[d, u.encode_service_ids(d)] for d in [{}, {"guardduty": "b", "cloudtrail": "a"}, {"x": "", "y": "1"}]],
        "wazuh_date": [[f"{y}-{mo}-{d}", u.wazuh_date(dt.date(y, mo, d))] for y, mo, d in [(2026, 1, 1), (2026, 12, 31), (5, 6, 7)]],
        "is_after": is_after,
    }


def write(path, value):
    path.write_text(json.dumps(value, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {path.relative_to(ROOT)}")


def main():
    write(ETREE_OUT, etree_vectors())
    write(CLOUD_OUT, {"office365": office365_vectors(), "rules": pipeline_rule_sources()})
    saved = _aws_patch()
    try:
        write(
            AWS_OUT,
            {
                "calls": aws_call_vectors(),
                "validate": aws_validate_vectors(),
                "reconcile": aws_reconcile_vectors(),
                "auth_keys": aws_auth_key_vectors(),
                "misc": aws_misc_vectors(),
            },
        )
    finally:
        _aws_unpatch(saved)


if __name__ == "__main__":
    main()
