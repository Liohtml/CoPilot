"""Generate the vectors of `copilot_docx::recover` (lxml 6 over libxml2 2.14, `recover=True`).

    /var/lib/copilot-venv/bin/python -I scripts/gen-docx-recover-vectors.py \
        > crates/copilot-docx/src/recover_vectors.json

docxtpl's `fix_tables` parses the rendered body with `etree.fromstring(xml,
etree.XMLParser(recover=True))`. Every case is a `str` parsed that way and the outcome:

- `out`: `etree.tostring(root, encoding="UTF-8")` decoded (the root's serialization);
- `none`: `fromstring` returned `None` (a document without a root element);
- `error`: `"syntax"` (lxml's `XMLSyntaxError`) or `"invalid-utf8"` (the tree holds a
  surrogate libxml2 stores as invalid UTF-8; the Rust port refuses it).

`cases` are written out; `bodies` are a document body (`base`: the bundled
`case_report_jinja_template.docx`'s, serialized as docxtpl's `get_xml` does, and a small
one with tables) with edits `[position, deleted, inserted]` applied in turn (positions in
characters of the text as it is when the edit applies), the outcome kept as the SHA-256 and
length of the serialization. The edits are what a template's rendering does to the XML: a
conditional cutting across elements, stray markup characters, control characters from a
case field, entities, broken attributes, a truncated text.

Regenerate after an lxml or libxml2 upgrade.
"""
import hashlib
import json
import os
import random
import sys

import docx
from lxml import etree

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLED = os.path.join(ROOT, "backend", "app", "incidents", "templates", "case_report_jinja_template.docx")

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def parse(text):
    parser = etree.XMLParser(recover=True)
    try:
        root = etree.fromstring(text, parser=parser)
    except etree.XMLSyntaxError:
        return {"error": "syntax"}
    if root is None:
        return {"none": True}
    raw = etree.tostring(root, encoding="UTF-8")
    try:
        return {"out": raw.decode("utf-8")}
    except UnicodeDecodeError:
        return {"error": "invalid-utf8"}


HAND = [
    "<a>x &amp; y</a>",
    "<a><b></a>x &amp; y",
    "<a><b></c>t &amp; u &#60; v</b></a>",
    "<a>t &foo; u</a>",
    "<a>t & u</a>",
    "<a>t &amp u</a>",
    "<a>t < u</a>",
    "<a b=v>t</a>",
    '<a b="1" b="2"/>',
    "<p:a>t</p:a>",
    '<a p:b="1"/>',
    "<a>\x01x￾y</a>",
    '<a b="\x01x￾"/>',
    "<a><b>",
    "<a></a><b/>",
    "<",
    "",
    "text",
    "   ",
    "\x00<a/>",
    "<a><b/></a>trailing<c/>",
    '<a xmlns:w="u"><w:b></a>',
    '<a><b x="1" y></b></a>',
    "<a></b></a>",
    "<a>x</a  >",
    "<a>x</a x>",
    "<a>x</",
    "<a>abc]]>def</a>",
    "<a>abéc]]>def</a>",
    "<a>&#1;x&#x110000;z&#12a;b&#;c&#x;d</a>",
    "<a>&#xD800;</a>",
    '<a b="&#1;"/>',
    "<a>&#xB;&#x7F;&#x80;&#xFFFE;&#xFFFF;&#13;</a>",
    "<a>x\ry\r\nz</a>",
    '<a b="x\ry\r\nz\tq\nw"/>',
    "<a>x\x00y &amp; z</a>",
    "<a><!-- c -- d --><!-- e -->f &amp; g</a>",
    "<a><!-- a ---> b --> &amp;</a>",
    "<a><!-- é -- x --> &amp;</a>",
    "<a><!-- unterminated",
    "<a><!-- x\x01 --> &amp;</a>",
    "<a><?pi data?><?pi?><?pi ?>&amp;</a>",
    "<a><?xml x?>&amp;</a>",
    "<a><?XML x?>&amp;</a>",
    "<a><?xml-stylesheet x?><?xmlfoo x?>&amp;</a>",
    "<a><?pi\x01?>&amp;</a>",
    "<a><? x?>&amp;</a>",
    "<a><?pi never",
    "<a><![CDATA[x<y]]>z &amp; w</a>",
    "<a><![CDATA[]]>z</a>",
    "<a><![CDATA[x\x01]]>z &amp; w</a>",
    "<a><![CDATA[never",
    '<a xmlns="">t</a>',
    '<a xmlns:p="">t</a>',
    '<a xmlns:p="u" xmlns:p="v">t &amp; x</a>',
    '<a xmlns="u" xmlns="v">t &amp; x</a>',
    '<a xmlns:q="u" xmlns:r="u" q:x="1" r:x="2">t &amp; x</a>',
    '<a xmlns:q="u" xmlns:r="u" q:x="1" r:x="2" q:y="1" r:y="2">t &amp; x</a>',
    '<a b="1" c="2" b="3">t &amp; x</a>',
    "<p:a>t &amp; x</p:a>",
    "<w:p:x>t</w:p:x>",
    "<a:>t</a:>",
    "<:a>t</:a>",
    "<a/><b/>",
    '<a b="x<y">t</a>',
    '<a b="x&y">t</a>',
    '<a b="x&foo;y">t</a>',
    '<a b="x&amp;y">&amp;</a>',
    '<a b="x&#38;y&#32;z">&amp;</a>',
    '<a><b c="1"d="2">x</b></a>',
    "<a><b c='1'/></a>",
    "<a><b/ ></a>",
    "<a><b / ></a>",
    "<a><b\x01></b></a>",
    "<a>x</a\x01>",
    "<a></ >",
    "<a></b c>",
    '<a xmlns:p="u"></p:a>',
    '<a xmlns:p="u"><p:b></b></a>',
    '<a xmlns:p="u"><p:b></p:c></a>',
    '<a xmlns:p="u"><p:b></p:b ></a>',
    '<a xml:space="preserve"> </a>',
    "<a><xml:b/></a>",
    '<a xmlns:xml="http://www.w3.org/XML/1998/namespace" xmlns:x="http://www.w3.org/XML/1998/namespace">t</a>',
    '<a xmlns:xmlns="u" xmlns="http://www.w3.org/2000/xmlns/">t &amp; x</a>',
    "<a>" + "<b>" * 300 + "x",
    "<a>" + "<b>" * 254 + "<c/><d>x</d>",
    "<a>" + "<b>" * 255 + "<c/><d>x</d>",
    "<a>é€\U0001f600 &amp; x</a>",
    "<a b='é€\U0001f600'>ÿ</a>",
    '<élément atté="1">x</élément>',
    "<a><b\r\n/></a>",
    "<a><b \r\nc='1'\r\n/></a>",
    "<a></a\r\n>",
    "<a>&#x41;&#65;&#x0041;&#0000065;&#x00000000000000000000041;&#000000000000000000000000065;</a>",
    "<a>&#xAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;</a>",
    "<a>&amp ;&lt;&gt;&quot;&apos;</a>",
    "<a>&am\x00p; &amp;</a>",
    "<a><b>x<c/>y</b>z</a>",
    "<a>text<!x>more &amp;</a>",
    "<a>text<!DOCTYPE x>more</a>",
]


def mini_body():
    rows = []
    for r in range(3):
        cells = "".join(
            '<w:tc><w:tcPr><w:tcW w:w="2000" w:type="dxa"/></w:tcPr><w:p><w:r><w:t>r%dc%d &amp; {{ x }}</w:t></w:r></w:p></w:tc>' % (r, c)
            for c in range(2)
        )
        rows.append("<w:tr>%s</w:tr>" % cells)
    return (
        '<w:body xmlns:w="%s" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<w:p><w:pPr><w:pStyle w:val="Title"/></w:pPr><w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">Case &lt;1&gt; </w:t></w:r></w:p>'
        '<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/></w:tblPr><w:tblGrid><w:gridCol w:w="2000"/><w:gridCol w:w="2000"/></w:tblGrid>%s</w:tbl>'
        "<w:p><w:r><w:t>After &quot;table&quot; &#8212; done</w:t></w:r></w:p>"
        '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/></w:sectPr></w:body>'
    ) % (W, "".join(rows))


INSERTS = [
    "<",
    "&",
    "&amp",
    "&nbsp;",
    "]]>",
    "\x0b",
    "\x01",
    "\x00",
    "￾",
    "&#1;",
    "&#xFFFE;",
    "<x",
    "</x>",
    "</w:p>",
    "</w:tc>",
    "<w:p>",
    "<w:r><w:t>",
    "<w:b c=1>",
    ' w:val="2"',
    "é",
    "€",
    "\U0001f600",
    "<!--",
    "-->",
    "<![CDATA[",
    "<?pi x?>",
    "\r",
    "\r\n",
    "<y:z>",
]


def random_ops(rng, text):
    ops = []
    cur = text
    for _ in range(rng.randint(1, 3)):
        kind = rng.random()
        n = len(cur)
        if n == 0:
            break
        if kind < 0.35:
            # a span cut out, as a false conditional cuts it
            lts = [i for i, ch in enumerate(cur) if ch == "<"]
            a = rng.choice(lts) if lts and rng.random() < 0.7 else rng.randrange(n)
            b = min(n, a + rng.randint(1, max(1, min(400, n - a))))
            if lts and rng.random() < 0.5:
                later = [i for i in lts if i > a]
                if later:
                    b = rng.choice(later[:40])
            op = [a, b - a, ""]
        elif kind < 0.5:
            # one tag removed
            lts = [i for i, ch in enumerate(cur) if ch == "<"]
            if not lts:
                continue
            a = rng.choice(lts)
            b = cur.find(">", a)
            if b < 0:
                continue
            op = [a, b + 1 - a, ""]
        elif kind < 0.9:
            ins = rng.choice(INSERTS)
            if rng.random() < 0.3:
                ins = ins * rng.randint(2, 3)
            op = [rng.randrange(n + 1), 0, ins]
        else:
            # truncated
            a = rng.randrange(n)
            op = [a, n - a, ""]
        ops.append(op)
        cur = cur[: op[0]] + op[2] + cur[op[0] + op[1] :]
    return ops, cur


def digest(outcome):
    if "out" in outcome:
        b = outcome["out"].encode("utf-8")
        return {"sha256": hashlib.sha256(b).hexdigest(), "len": len(b)}
    return outcome


def main():
    cases = [{"input": t, **parse(t)} for t in HAND]
    bundled = etree.tostring(docx.Document(BUNDLED).element.body, encoding="unicode")
    bodies = []
    for name, base, count, seed in (("mini", mini_body(), 400, 934), ("bundled", bundled, 150, 1165)):
        rng = random.Random(seed)
        entries = [{"ops": [], **digest(parse(base))}]
        for _ in range(count):
            ops, text = random_ops(rng, base)
            entries.append({"ops": ops, **digest(parse(text))})
        bodies.append({"name": name, "base": base, "cases": entries})
    json.dump({"cases": cases, "bodies": bodies}, sys.stdout, ensure_ascii=False, indent=0)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
