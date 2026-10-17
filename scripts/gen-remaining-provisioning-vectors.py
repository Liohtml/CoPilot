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


def write(path, value):
    path.write_text(json.dumps(value, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {path.relative_to(ROOT)}")


def main():
    write(ETREE_OUT, etree_vectors())
    write(CLOUD_OUT, {"office365": office365_vectors(), "rules": pipeline_rule_sources()})


if __name__ == "__main__":
    main()
