"""Regenerate the ElementTree parse vectors and the Sysmon upload's validation vectors.

* `crates/copilot-integrations/src/expat_vectors.json` — `ET.fromstring(text)` on documents
  expat accepts and refuses: `null`, or `str(ParseError)` (expat's message, line and column);
* `crates/copilot-response/src/sysmon/sysmon_vectors.json` — `validate_sysmon_config(text)`
  (`app/active_response/services/sysmon_config.py`): `null`, or the `HTTPException`'s detail.

Re-run after a Python (pyexpat) upgrade or a change to `validate_sysmon_config`:

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x MYSQL_ROOT_PASSWORD=x \\
        JWT_SECRET=gen-secret-xyz python ../scripts/gen-expat-vectors.py
"""

import asyncio
import json
import pathlib
import xml.etree.ElementTree as ET

import pyexpat
from fastapi import HTTPException

from app.active_response.services.sysmon_config import validate_sysmon_config

ROOT = pathlib.Path(__file__).resolve().parent.parent
PARSE_OUT = ROOT / "crates" / "copilot-integrations" / "src" / "expat_vectors.json"
SYSMON_OUT = ROOT / "crates" / "copilot-response" / "src" / "sysmon" / "sysmon_vectors.json"

SYSMON = (
    "<Sysmon schemaversion='4.90'>\n  <EventFiltering>\n    <RuleGroup name='' groupRelation='or'>\n"
    "      <ProcessCreate onmatch='exclude'/>\n    </RuleGroup>\n  </EventFiltering>\n</Sysmon>"
)

DOCUMENTS = [
    # accepted
    "<a/>",
    "<a></a >",
    "<?xml version='1.0' encoding='UTF-8'?>\n<!-- c -->\n<a b=\"x\" c='y'>t<b/>u</a>",
    "<?xml version='1.0' ?><a/>",
    "<?xml version = '1.0'?><a/>",
    "<?xml version='2.0'?><a/>",
    "<?xml version='1.0' encoding='latin-1' standalone='yes'?><a/>",
    "﻿<a/>",
    "<a/><?pi?>",
    "<a/> <!-- c -->",
    "<a/>\n\n\n",
    "<a>&lt;&gt;&amp;&apos;&quot;&#65;&#x42;</a>",
    "<a><![CDATA[x<y]]></a>",
    "<a><?x?><?xml-foo bar?></a>",
    "<é/>",
    "<a·/>",
    "<a xml:lang='en'/>",
    "<a xmlns:xml='http://www.w3.org/XML/1998/namespace'/>",
    "<a xmlns=''/>",
    "<!DOCTYPE a [<!ENTITY e 'x'>]><a>&e;</a>",
    "<a b='x'\n/>",
    SYSMON,
    # refused: the prolog and the document's end
    "",
    "   ",
    "\n\n",
    "abc",
    "\n  x",
    "é",
    "<!-- only -->",
    "<?pi only?>",
    "<a>",
    "<a>text",
    "<a>]]",
    "<a>]",
    "<?xml version='1.0'?>",
    "<?xml version='1.0'?>x",
    " <?xml version='1.0'?><a/>",
    "<!DOCTYPE a><!DOCTYPE a><a/>",
    # refused: tags
    "<a></b>",
    "<a>\n  <b>\n</a>",
    "<a>\r\n</b>",
    "<a>\r</b>",
    "<a><b></a></b>",
    "<a><b><c></b></c></a>",
    "<a>é<b></c></a>",
    "<a>éé</c>",
    "<a>\U0001d538</b>",
    "﻿<a></b>",
    "<?xml version='1.0' encoding='utf-8'?>\n<Sysmon><EventFiltering></Sysmon>",
    "< a/>",
    "<1a/>",
    "</a>",
    "<a></ a>",
    "<a></a x>",
    "<̀a/>",
    "<a\x01/>",
    "<a\r\n<b/>",
    # refused: attributes
    "<a b=c/>",
    "<a b='<'/>",
    "<a b='x' c/>",
    "<a b='x'c='y'/>",
    "<a\n  b='1'\n  c/>",
    "<a b='1' b='2'/>",
    '<a b="x" b="y"/>',
    "<a>\n\n   <b c='1' c='2'/></a>",
    "<a b='1' b='2' c/>",
    "<a b='\x01'/>",
    "<a b='&x;'/>",
    "<a b='&#0;'/>",
    "<a b='&#12'/>",
    "<a b='&am'/>",
    "<a b='&#x110000;'/>",
    "<a b='&#0;' b='1'/>",
    # refused: references and characters
    "<a>&</a>",
    "<a>&foo;</a>",
    "<a>&amp</a>",
    "<a>&#0;</a>",
    "<a>&#x110000;</a>",
    "<a>&#;</a>",
    "<a>&#x;</a>",
    "<a>&#1a;</a>",
    "<a>\x01</a>",
    "<a>￿</a>",
    "<a>]]></a>",
    "<a>é<</a>",
    "<!DOCTYPE a [<!ENTITY e 'x'>]><a>&f;</a>",
    # refused: comments, instructions, CDATA, declarations in content
    "<a><!-- -- --></a>",
    "<a><!--x--y--></a>",
    "<a><!---></a>",
    "<a><!x></a>",
    "<a><!-x></a>",
    "<a><!DOCTYPE b></a>",
    "<a><![CDATA[x</a>",
    "<a><![CDATA[\x01]]></a>",
    "<a><![CDAT[x]]></a>",
    "<a><?></a>",
    "<a><? x?></a>",
    "<a><?XML?></a>",
    "<a><?xml x?></a>",
    # refused: unclosed tokens
    "<a",
    "<a b",
    "<a b=",
    "<a b='x",
    "<a>text<",
    "<a>text</",
    "<a>text</a",
    "<a>&#12",
    "<a>&#x",
    "<a>&am",
    "<a>&",
    "<a><!",
    "<a><!-",
    "<a><![CDA",
    "<a><?pi",
    "<a><?",
    "<a></",
    "<a><!-- x",
    "<a><?pi x",
    "<a/><!-- x",
    "<?xml version='1.0'",
    # refused: after the root
    "<a/><b/>",
    "<a/>x",
    "<a/>\n x",
    "<a></a><a>",
    "<a/>\n\n  </b>",
    "<a/><!x>",
    "<a/><!x y>",
    # refused: the XML declaration
    "<?xml?><a/>",
    "<?xml foo='1'?><a/>",
    "<?xml encoding='x'?><a/>",
    "<?xml version='1.0' encoding='1x'?><a/>",
    "<?xml version='1.0'encoding='u'?><a/>",
    "<?xml version=1.0?><a/>",
    "<?xml version='1.0' version='1.0'?><a/>",
    "<?xml version='1.0' standalone='yes' encoding='u'?><a/>",
    "<?xml version='1.0' standalone='maybe'?><a/>",
    "<?xml version='1 0'?><a/>",
    # refused: namespaces
    "<x:a/>",
    "<a x:y='1'/>",
    "<a xmlns:p='u'><p:b/><q:c/></a>",
    "<a xmlns:p='u' p:x='1' p:x='2'/>",
    "<a xmlns:p='u' xmlns:q='u' p:x='1' q:x='2'/>",
    "<a xmlns:xml='u'/>",
    "<a xmlns:p=''/>",
    "<a xmlns:xmlns='u'/>",
    "<a xmlns:p='http://www.w3.org/2000/xmlns/'/>",
    "<a xmlns='http://www.w3.org/2000/xmlns/'/>",
    "<a xmlns='http://www.w3.org/XML/1998/namespace'/>",
    "<a xmlns:p='http://www.w3.org/XML/1998/namespace'/>",
    "<a xmlns:p='u'><b xmlns:p=''/></a>",
]

SYSMON_DOCUMENTS = [
    SYSMON,
    "<?xml version='1.0' encoding='UTF-8'?>\n<!-- comment -->\n<Sysmon schemaversion='4.90'><HashAlgorithms>md5</HashAlgorithms>"
    "<EventFiltering><RuleGroup groupRelation='and'></RuleGroup></EventFiltering></Sysmon>",
    "<sysmon><EventFiltering><RuleGroup groupRelation='or'/></EventFiltering></sysmon>",
    "<x:Sysmon xmlns:x='u'><EventFiltering><RuleGroup groupRelation='or'/></EventFiltering></x:Sysmon>",
    "<Sysmon/>",
    "<Sysmon><Other><EventFiltering/></Other></Sysmon>",
    "<Sysmon><EventFiltering>text<RuleGroup groupRelation='or'/></EventFiltering></Sysmon>",
    "<Sysmon><EventFiltering>\n  \t<RuleGroup groupRelation='or'/></EventFiltering></Sysmon>",
    "<Sysmon><EventFiltering> <RuleGroup groupRelation='or'/></EventFiltering></Sysmon>",
    "<Sysmon><EventFiltering><!-- x --><RuleGroup groupRelation='or'/></EventFiltering></Sysmon>",
    "<Sysmon><EventFiltering/></Sysmon>",
    "<Sysmon><EventFiltering><Rule/></EventFiltering></Sysmon>",
    "<Sysmon><EventFiltering><RuleGroup/></EventFiltering></Sysmon>",
    "<Sysmon><EventFiltering><RuleGroup groupRelation=''/></EventFiltering></Sysmon>",
    "<Sysmon><EventFiltering><RuleGroup groupRelation='or'/><RuleGroup/></EventFiltering></Sysmon>",
    "<Sysmon><EventFiltering><RuleGroup groupRelation='or'/></EventFiltering><EventFiltering/></Sysmon>",
    "<Sysmon><EventFiltering><RuleGroup groupRelation='or'/></EventFiltering>",
    "<Sysmon><EventFiltering><RuleGroup groupRelation='or'></EventFiltering></Sysmon>",
    "not xml",
    "",
]


def parse(text):
    try:
        ET.fromstring(text)
        return None
    except ET.ParseError as e:
        return str(e)


def sysmon(text):
    try:
        asyncio.run(validate_sysmon_config(text))
        return None
    except HTTPException as e:
        return e.detail


def main():
    parse_vectors = {"expat": pyexpat.EXPAT_VERSION, "documents": [{"text": d, "error": parse(d)} for d in DOCUMENTS]}
    sysmon_vectors = [{"text": d, "detail": sysmon(d)} for d in SYSMON_DOCUMENTS]
    PARSE_OUT.write_text(json.dumps(parse_vectors, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    SYSMON_OUT.write_text(json.dumps(sysmon_vectors, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {PARSE_OUT} ({len(DOCUMENTS)} documents) and {SYSMON_OUT} ({len(SYSMON_DOCUMENTS)} configs)")


if __name__ == "__main__":
    main()
