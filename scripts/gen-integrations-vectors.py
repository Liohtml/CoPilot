"""Regenerate the vectors that pin `copilot-integrations`' ElementTree subset (`etree.rs`) and the
Office365 decommission's `ossec.conf` edit (`office365.rs`) to CPython.

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-integrations-vectors.py

Writes `crates/copilot-integrations/src/etree_vectors.json`, one entry per probe document:

* `doc`, `tenant` — the text `ET.fromstring` is given and the tenant the decommission removes;
* `parsed` — whether expat (through `ET.XMLParser`) accepts the document;
* `tostring` — `ET.tostring(root, encoding="utf-8")` of what it parsed (`null` when refused);
* `removed` — `remove_api_auth_block(doc, tenant)`: the new configuration, `null` when the tenant
  is not configured, or `{"error": status}` when the document is refused.

Re-run after a Python upgrade (expat and ElementTree ship with CPython) or a change to
`app/integrations/office365/services/decommission.py`.
"""

import json
import pathlib
import xml.etree.ElementTree as ET

from fastapi import HTTPException

from app.integrations.office365.services.decommission import remove_api_auth_block

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-integrations" / "src" / "etree_vectors.json"


def block(*tenants, extra=""):
    auths = "".join(f"\n    <api_auth>\n      <tenant_id>{t}</tenant_id>\n      <client_id>c</client_id>\n    </api_auth>" for t in tenants)
    return f"  <office365>\n    <enabled>yes</enabled>{auths}{extra}\n  </office365>\n"


def config(*blocks, head="", tail=""):
    return (
        f"{head}<ossec_config>\n  <global>\n    <jsonout_output>yes</jsonout_output>\n  </global>\n{''.join(blocks)}</ossec_config>{tail}"
    )


PROBES = [
    # The shapes the decommission meets.
    (config(block("t-a", "t-b")), "t-b"),
    (config(block("t-a", "t-b")), "t-a"),
    (config(block("t-a")), "t-a"),
    (config(block("t-a")), "t-x"),
    (config(), "t-a"),
    (config(block("t-a"), block("t-b")), "t-a"),
    (config(block("t-a"), block("t-b")), "t-b"),
    # Once one tenant is gone, a later block without any api_auth goes too.
    (config(block("t-a"), "  <office365>\n    <enabled>no</enabled>\n  </office365>\n"), "t-a"),
    (config("  <office365><enabled>no</enabled></office365>\n", block("t-a")), "t-a"),
    (config(block(" t-a\n ")), "t-a"),
    (config(block("t-a", "t-a", "t-b")), "t-a"),
    (config(block("t-a", extra="\n    <api_auth><client_id>no tenant</client_id></api_auth>")), "t-a"),
    (config("  <wodle name='office365'><office365><api_auth><tenant_id>t-a</tenant_id></api_auth></office365></wodle>\n"), "t-a"),
    # Prolog, epilog, comments, processing instructions.
    (config(block("t-a", "t-b"), head='<?xml version="1.0" encoding="UTF-8"?>\n<!-- Wazuh - Manager -->\n'), "t-b"),
    (config(block("t-a", "t-b"), tail="\n<!-- end -->\n\n"), "t-b"),
    (
        "<ossec_config><!-- one --><office365><!-- two --><api_auth><tenant_id>t-a</tenant_id></api_auth><?pi x?>after</office365>tail</ossec_config>",
        "t-a",
    ),
    (
        "<ossec_config>a<!--c-->b<?p?>c<office365><api_auth><tenant_id>t-a</tenant_id></api_auth></office365>d<!--e-->f</ossec_config>",
        "t-a",
    ),
    ("<?xml version='1.0'?><a/>", "t-a"),
    ('<?xml version="1.0" standalone="yes"?>\n<a>x</a>', "t-a"),
    # Escapes, entities, character references, CDATA, line ends.
    ('<a b="x &amp; &lt;y&gt; &quot;z&quot; &apos;w&apos;">&amp;&lt;&gt;&quot;&apos;</a>', "t"),
    ("<a b='1\t2\n3\r\n4  5'>x\r\ny\rz</a>", "t"),
    ("<a>&#65;&#x42;&#x1F600;&#10;&#13;&#9;</a>", "t"),
    ("<a><![CDATA[<tenant_id>&amp;]]></a>", "t"),
    (
        '<!DOCTYPE a [<!ENTITY t "t-a"><!ENTITY two "&t;-&t;">]><a><office365><api_auth><tenant_id>&t;</tenant_id></api_auth></office365>&two;</a>',
        "t-a",
    ),
    ("<!DOCTYPE ossec_config>\n" + config(block("t-a")), "t-a"),
    ('<a b="&#34;&#60;&#62;&#10;&#13;&#9;"/>', "t"),
    ("<a>é ü 漢字 \U0001f600</a>", "t"),
    ("<a>]]</a>", "t"),
    ("<a>></a>", "t"),
    # Empty elements, attributes, namespaces.
    ('<a><b/><c></c><d x="1" y="2"/><e x="1">t</e></a>', "t"),
    ('<a xmlns="urn:x"><b/></a>', "t"),
    ('<p:a xmlns:p="urn:p" p:x="1"><p:b/><c/></p:a>', "t"),
    ('<a xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="t"><b xml:lang="en"/></a>', "t"),
    ('<a xmlns:q="urn:q" xmlns:p="urn:p"><q:b/><p:c/></a>', "t"),
    # What expat refuses.
    ("", "t"),
    ("not xml", "t"),
    ("<a>", "t"),
    ("<a></b>", "t"),
    ("<a/><b/>", "t"),
    ("<a/>junk", "t"),
    ('<a x="1" x="2"/>', "t"),
    ("<a>&nope;</a>", "t"),
    ("<a>& </a>", "t"),
    ("<a>]]></a>", "t"),
    ("<a><!-- x -- y --></a>", "t"),
    ("<a><?xml version='1.0'?></a>", "t"),
    (" <?xml version='1.0'?><a/>", "t"),
    ("<a>&#0;</a>", "t"),
    ("<a>&#xD800;</a>", "t"),
    ("<a>\x01</a>", "t"),
    ("<p:a/>", "t"),
    ('<a b="<"/>', "t"),
    ("<a b=1/>", "t"),
    ("<1a/>", "t"),
    (config(block("t-a")).replace("</office365>", ""), "t-a"),
]


def entry(doc, tenant):
    try:
        root = ET.fromstring(doc)
        parsed, text = True, ET.tostring(root, encoding="utf-8").decode("utf-8")
    except ET.ParseError:
        parsed, text = False, None
    try:
        removed = remove_api_auth_block(doc, tenant)
    except HTTPException as e:
        removed = {"error": e.status_code}
    return {"doc": doc, "tenant": tenant, "parsed": parsed, "tostring": text, "removed": removed}


def main():
    vectors = [entry(doc, tenant) for doc, tenant in PROBES]
    OUT.write_text(json.dumps(vectors, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(vectors)} vectors to {OUT}")


if __name__ == "__main__":
    main()
