"""Generate rendering vectors for copilot-jinja's port of the notification template renderer.

    backend/.venv/bin/python -I scripts/gen-jinja-vectors.py \
        > crates/copilot-jinja/src/jinja_vectors.json

Run from the repository root. Every case goes through CoPilot's own
`app/notifications/services/rendering.render` — the sandboxed Jinja2 environment with
`StrictUndefined`, the per-format autoescape, the `context` defaultdict and the
`event` envelope — exactly as the temporary-password email and the notification
dispatch call it.

- `contexts`: the events and extra variables the cases render against, in a form the
  Rust test rebuilds them from.
- `cases`: a template, the context it renders against and whether autoescape is on;
  the outcome is `{"ok": output}` or `{"error": {"type", "message"}}` (`type(e).__name__`
  and `str(e)`, what the Security tab's preview shows).
"""
import json
import os
import sys

os.environ.setdefault("MYSQL_URL", "127.0.0.1:13306")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "unused")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "unused")
os.environ.setdefault("JWT_SECRET", "vector-generator-secret")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))

from app.notifications.schema.events import NotificationEvent  # noqa: E402
from app.notifications.services.rendering import render  # noqa: E402

BRANDING = {
    "logo": None,
    "title": "Acme",
    "footer_brand": "Acme",
    "accent": "#1f2937",
    "accent_strong": "#2563eb",
    "accent_text": "#ffffff",
    "accent_soft": "#e5e7eb",
}

CONTEXTS = {
    "temp": {
        "event": {
            "customer_code": "ACME",
            "trigger": "temp_password_issued",
            "severity": "Informational",
            "subject": "CoPilot — temporary password",
            "summary": "An administrator has issued a temporary password for your CoPilot account. "
            "Sign in with it and change it immediately.",
            "entity_type": "user",
            "entity_id": 7,
            "dedupe_key": "user:7:temp_password_issued",
            "link_url": "https://copilot.example/login",
            "assignee_username": None,
            "actor_username": None,
            "context": {"username": "alice"},
        },
        "extra": {
            "user_name": "alice",
            "user_email": "alice@example.com",
            "temp_password": "Tmp-Pass#1<&>",
            "login_url": "https://copilot.example/login",
            "customer_name": "Acme <Corp> & Co",
            "organization_name": "Acme <Corp> & Co",
            "branding": BRANDING,
        },
    },
    "alert": {
        "event": {
            "customer_code": None,
            "trigger": "investigation_complete",
            "severity": "High",
            "subject": "Mimikatz on dc01",
            "summary": "Credential dumping detected.\nSecond line with 'quotes' & <tags>.",
            "entity_type": "alert",
            "entity_id": 42,
            "dedupe_key": "alert:42:investigation_complete",
            "link_url": None,
            "assignee_username": "bob",
            "actor_username": "carol",
            "context": {
                "alert_name": "Mimikatz",
                "asset_name": "dc01",
                "iocs": [{"type": "ip", "value": "10.0.0.1"}, {"type": "hash", "value": "abc"}],
                "score": 7.5,
                "count": 3,
                "tags": ["b", "a", "c"],
                "nested": {"k": [1, 2], "z": None},
                "flag": True,
                "nothing": None,
                "big": 12345678901234567890,
                "neg": -3,
                "ratio": 0.1,
            },
        },
        "extra": {
            "user_name": "bob",
            "customer_name": "",
            "login_url": "",
            "branding": {**BRANDING, "title": "CoPilot", "logo": "data:image/png;base64,AAAA"},
        },
    },
}

CASES = []


def case(name, source, ctx="temp", ae=(False,)):
    for autoescape in ae:
        CASES.append({"name": name, "source": source, "ctx": ctx, "autoescape": autoescape})


BOTH = (False, True)

# --- Text, whitespace, comments ---------------------------------------------------------
case("plain", "Hello", ae=BOTH)
case("empty", "")
case("variable", "Hello {{ user_name }}", ae=BOTH)
case("trailing newline", "a\n")
case("two trailing newlines", "a\n\n")
case("crlf", "a\r\nb\r\n")
case("ws control", "a  {{- user_name -}}  b\n  {%- if true %} x {% endif -%}  \n y")
case("comment", "a{# c #}b{#- d -#} c")
case("raw", "{% raw %}{{ user_name }}{% endraw %}")
case("unicode", "Grüße {{ customer_name }} — ✓")
case("block newline", "{% if true %}\nyes\n{% endif %}\nend")

# --- str() of values --------------------------------------------------------------------
for expr in (
    "none",
    "None",
    "true",
    "True",
    "false",
    "1 == 1",
    "42",
    "-7",
    "1.5",
    "10/4",
    "10/2",
    "10//3",
    "-7//2",
    "7 % 3",
    "-7 % 3",
    "2**10",
    "2**0.5",
    "2**-1",
    "1e20",
    "1e16",
    "1e15",
    "0.1+0.2",
    "1/3",
    "100.0",
    "3.0 * 2",
    "[1, 'a', none, true]",
    "(1, 2)",
    "(1,)",
    "()",
    "[]",
    "{}",
    "{'a': 1, 'b': [2]}",
    "'it\\'s'",
    '"say \\"hi\\""',
    "'tab\\tnew\\nline'",
    "'ü'",
    "[\"it's\", 'x\"y']",
    "2**64",
    "big",
    "context.big",
    "context.score",
    "context.ratio",
    "context.iocs",
    "context.nested",
    "context.tags",
    "context.flag",
    "context.nothing",
    "branding",
    "branding.logo",
    "severity",
    "trigger",
    "entity_type",
    "entity_id",
    "alert_id",
    "event.severity",
    "event.trigger",
    "event.severity.value",
    "event.trigger.value",
    "event.severity.name",
    "event.entity_id",
    "event.customer_code",
    "event.link_url",
    "event.context",
    "event.alert_id",
    "customer_code",
    "report_url",
    "link_url",
    "assignee",
    "actor",
    "subject",
    "summary",
    "alert_name",
):
    case(f"value {expr}", "{{ " + expr + " }}", ctx="alert" if "context." in expr or expr in ("big",) else "temp")
    case(f"value {expr} (alert)", "{{ " + expr + " }}", ctx="alert")
case("escape values", "{{ summary }}|{{ temp_password }}|{{ customer_name }}|{{ [customer_name] }}", ae=BOTH)
case("escape values alert", "{{ summary }}|{{ context.iocs }}|{{ none }}|{{ 1.5 }}", ctx="alert", ae=BOTH)

# --- Operators ---------------------------------------------------------------------------
for expr in (
    "'a' ~ 1 ~ none ~ true",
    "'a' + 'b'",
    "1 + 2",
    "1 + 2.5",
    "'ab' * 3",
    "3 * 'ab'",
    "[1] + [2]",
    "[1] * 2",
    "'%s-%d' % ('x', 3)",
    "'%s' % user_name",
    "'%05.1f|%x|%r' % (3.14159, 255, 'q')",
    "'%(a)s' % {'a': 1}",
    "10 - 3",
    "-(3)",
    "+3",
    "not true",
    "not none",
    "1 < 2 < 3",
    "1 == 1.0",
    "'a' in 'cat'",
    "1 in [1, 2]",
    "'k' in {'k': 1}",
    "3 not in [1]",
    "'' or 'x'",
    "0 or none",
    "'a' and 'b'",
    "none and 1",
    "customer_name or 'CoPilot'",
    "login_url and 'yes'",
    "'a' if true else 'b'",
    "'a' if false else 'b'",
    "user_name ~ '!' if user_name",
    "2 ** 3 ** 2",
    "7 // 2 * 2",
    "-2 ** 2",
    "(1, 2) == (1, 2)",
    "[1, 2] == (1, 2)",
    "'abc'[1]",
    "'abc'[-1]",
    "'abcdef'[1:4]",
    "'abcdef'[::2]",
    "'abcdef'[::-1]",
    "[1, 2, 3][1:]",
    "{'a': 1}['a']",
    "'abc' < 'abd'",
    "none is none",
    "1 is number",
    "true is boolean",
    "1.0 is integer",
):
    case(f"op {expr}", "{{ " + expr + " }}")

# --- Statements --------------------------------------------------------------------------
case("if elif else", "{% if context.count > 5 %}big{% elif context.count > 1 %}mid{% else %}small{% endif %}", ctx="alert")
case("if defined", "{% if context.asset_name %}on {{ context.asset_name }}{% endif %}", ctx="alert")
case("if missing context key", "{% if context.missing %}x{% else %}none{% endif %}", ctx="alert")
case("missing context key prints empty", "[{{ context.missing }}][{{ context['also'] }}]", ctx="alert")
case("context get", "{{ context.get('asset_name') }}|{{ context.get('missing') }}|{{ context.get('missing', 'dflt') }}", ctx="alert")
case("context after missing lookup", "{{ context.zzz }}{{ context|length }}", ctx="alert")
case(
    "for loop vars",
    "{% for i in context.iocs %}{{ loop.index }}/{{ loop.length }} {{ i.type }}={{ i.value }}"
    "{% if not loop.last %}, {% endif %}{% endfor %}",
    ctx="alert",
)
case(
    "for loop more vars",
    "{% for t in context.tags %}{{ loop.index0 }}{{ loop.first }}{{ loop.last }}{{ loop.revindex }}"
    "{{ loop.revindex0 }}{{ loop.cycle('x', 'y') }};{% endfor %}",
    ctx="alert",
)
case("for else", "{% for x in [] %}{{ x }}{% else %}empty{% endfor %}")
case("for filter", "{% for x in [1, 2, 3, 4] if x is even %}{{ x }}{% endfor %}")
case("for unpack", "{% for k, v in branding.items() %}{{ k }}={{ v }};{% endfor %}")
case("for dict", "{% for k in branding %}{{ k }},{% endfor %}")
case("for string", "{% for c in 'abc' %}{{ c }}-{% endfor %}")
case("for prev next", "{% for x in [1, 2, 3] %}{{ loop.previtem }}<{{ x }}>{{ loop.nextitem }}|{% endfor %}")
case("for previtem undefined", "{% for x in [1] %}{{ loop.previtem }}{% endfor %}")
case("for depth", "{% for x in [1] %}{{ loop.depth }}{{ loop.depth0 }}{% endfor %}")
case("for range", "{% for i in range(3) %}{{ i }}{% endfor %}|{{ range(2, 10, 3)|list }}")
case("nested loops", "{% for a in [1, 2] %}{% for b in 'xy' %}{{ a }}{{ b }}{{ loop.index }} {% endfor %}{% endfor %}")
case("set", "{% set greeting = 'Hi ' ~ user_name %}{{ greeting }}")
case("set block", "{% set body %}Hello {{ user_name }}{% endset %}[{{ body }}]", ae=BOTH)
case("set tuple", "{% set a, b = 1, 2 %}{{ a }}{{ b }}")
case("set in loop scope", "{% set n = 0 %}{% for x in [1, 2] %}{% set n = n + x %}{% endfor %}{{ n }}")
case("namespace", "{% set ns = namespace(n=0) %}{% for x in [1, 2] %}{% set ns.n = ns.n + x %}{% endfor %}{{ ns.n }}")
case("with", "{% with x = 3 %}{{ x }}{% endwith %}")
case("macro", "{% macro b(t, c='x') %}<{{ t }}|{{ c }}>{% endmacro %}{{ b('a') }}{{ b('a', c='y') }}", ae=BOTH)
case("macro caller", "{% macro w() %}[{{ caller() }}]{% endmacro %}{% call w() %}in{% endcall %}")
case("filter block", "{% filter upper %}hello {{ user_name }}{% endfilter %}")
case("autoescape block", "{% autoescape false %}{{ customer_name }}{% endautoescape %}|{{ customer_name }}", ae=BOTH)
case("dict global", "{{ dict(a=1, b=2) }}")
case("joiner", "{% set j = joiner(', ') %}{% for x in [1, 2, 3] %}{{ j() }}{{ x }}{% endfor %}")
case("cycler", "{% set c = cycler('a', 'b') %}{{ c.next() }}{{ c.next() }}{{ c.next() }}")

# --- Filters -----------------------------------------------------------------------------
for expr in (
    "user_name|upper",
    "'HeLLo'|lower",
    "'hello world-foo bar'|title",
    "\"they're o'neil\"|title",
    "'hELLO wORLD'|capitalize",
    "'  x  '|trim",
    "'xxaxx'|trim('x')",
    "'a-b-a'|replace('a', 'z')",
    "'a-b-a'|replace('a', 'z', 1)",
    "context.missing|default('d')",
    "nope|default('d')",
    "nope|d('d')",
    "''|default('d')",
    "''|default('d', true)",
    "none|default('d')",
    "branding.nope|default('#fff')",
    "branding.logo|default('nologo')",
    "[3, 1, 2]|sort",
    "[3, 1, 2]|sort(reverse=true)",
    "['b', 'A', 'c']|sort",
    "['b', 'A', 'c']|sort(case_sensitive=true)",
    "context.iocs|sort(attribute='value')|map(attribute='value')|join(',')",
    "context.iocs|map(attribute='type')|list",
    "context.iocs|selectattr('type', 'equalto', 'ip')|map(attribute='value')|first",
    "context.iocs|rejectattr('type', 'eq', 'ip')|list",
    "[1, 2, 3, 4]|select('odd')|list",
    "[1, 2, 3, 4]|reject('odd')|list",
    "[1, 2, 3]|join",
    "[1, 2, 3]|join('-')",
    "['<a>', 'b']|join('&')",
    "[1, 2, 3]|first",
    "[1, 2, 3]|last",
    "[]|first",
    "'abc'|first",
    "[1, 2, 3]|length",
    "'abc'|count",
    "{'a': 1}|length",
    "[1, 2, 3]|sum",
    "[1.5, 2]|sum",
    "context.iocs|length",
    "[3, 1, 2]|max",
    "['b', 'a']|min",
    "[1, 2, 2, 1]|unique|list",
    "['a', 'A', 'b']|unique|list",
    "[1, 2, 3]|reverse|list",
    "'abc'|reverse",
    "'42'|int",
    "'4.7'|int",
    "'x'|int",
    "'x'|int(5)",
    "'0x1A'|int(0, 16)",
    "'0b11'|int(base=2)",
    "3.9|int",
    "'3.5'|float",
    "'x'|float",
    "3|float",
    "3.14159|round",
    "3.14159|round(2)",
    "2.5|round",
    "3.5|round",
    "2.675|round(2)",
    "3.14159|round(1, 'floor')",
    "3.14159|round(1, 'ceil')",
    "-3.5|abs",
    "-3|abs",
    "'abc'|list",
    "{'a': 1, 'b': 2}|list",
    "branding|dictsort|first",
    "{'b': 1, 'a': 2}|dictsort",
    "{'b': 1, 'a': 2}|dictsort(by='value')",
    "{'b': 1, 'a': 2}|dictsort(reverse=true)",
    "{'b': 1, 'a': 2}|items|list",
    "'%s=%d'|format('x', 3)",
    "'{}'|format(1)",
    "'%.2f'|format(1)",
    "'<b>'|e",
    "'<b>'|escape",
    "'<b>'|safe",
    "'<b>'|forceescape",
    "'a\"b\\'c&d'|e",
    "'<p>a <b>b</b></p>   c'|striptags",
    "'a &amp; b &lt;'|striptags",
    "'hello world foo'|truncate(9)",
    "'hello world foo'|truncate(11)",
    "'hello world foo bar baz'|truncate(9, true)",
    "'hello world foo bar baz'|truncate(12, false, '…')",
    "'short'|truncate(10)",
    "'one two  three'|wordcount",
    "'a b c d e f g'|wordwrap(5)",
    "'x'|center(5)",
    "'line1\\nline2'|indent",
    "'line1\\nline2'|indent(2, true)",
    "'line1\\n\\nline2'|indent(2, blank=true)",
    "1234567|filesizeformat",
    "1234567|filesizeformat(true)",
    "100|filesizeformat",
    "1|filesizeformat",
    "'a b&c'|urlencode",
    "{'a': 'b c', 'd': 1}|urlencode",
    "'/path?q=1'|urlencode",
    "{'a': 1, 'b': [1, 2]}|tojson",
    "'<x>&\\'y'|tojson",
    "context.nested|tojson",
    "context.nested|tojson(indent=2)",
    "{'b': 1, 'a': 2}|tojson",
    "[1, 2, 3, 4, 5]|batch(2)|list",
    "[1, 2, 3, 4, 5]|batch(2, 'x')|list",
    "[1, 2, 3, 4, 5]|slice(2)|list",
    "context.iocs|groupby('type')|map(attribute='grouper')|list",
    "'x'|string",
    "1|string",
    "none|string",
    "[1]|string",
    "{'class': 'a', 'id': 'b<c'}|xmlattr",
    "'see https://example.com/x and www.example.org'|urlize",
    "context.iocs|map('length')|list",
    "['a', 'bb']|map('upper')|list",
    "context|attr('nope')",
    "branding|attr('accent')",
    "context.tags|sort|join(', ')",
    "'abc'|pprint",
    "{'a': [1, 2]}|pprint",
):
    case(f"filter {expr}", "{{ " + expr + " }}", ctx="alert")
case("filter escape in html", "{{ '<b>'|e }}{{ '<b>'|safe }}{{ ('<i>'|safe) ~ '<u>' }}{{ ['<a>']|join }}", ae=BOTH)
case("filter tojson in html", "{{ {'a': '<b>'}|tojson }}", ae=BOTH)

# --- Tests -------------------------------------------------------------------------------
for expr in (
    "nope is defined",
    "nope is undefined",
    "user_name is defined",
    "branding.logo is none",
    "branding.nope is defined",
    "context.missing is defined",
    "1 is odd",
    "4 is even",
    "6 is divisibleby(3)",
    "'a' is string",
    "1 is string",
    "{} is mapping",
    "[] is mapping",
    "[] is sequence",
    "'x' is sequence",
    "1 is iterable",
    "'ABC' is upper",
    "'abc' is lower",
    "1 is eq 1",
    "1 is lt 2",
    "1 is in [1, 2]",
    "true is true",
    "1 is true",
    "1.5 is float",
    "1 is integer",
    "none is sameas none",
    "user_name is callable",
    "'<b>'|e is escaped",
    "'upper' is filter",
    "'odd' is test",
):
    case(f"test {expr}", "{{ " + expr + " }}", ctx="alert")

# --- Python methods ----------------------------------------------------------------------
for expr in (
    "user_name.upper()",
    "user_name.title()",
    "'a,b,,c'.split(',')",
    "'a b  c'.split()",
    "'a,b,c'.split(',', 1)",
    "'a,b,c'.rsplit(',', 1)",
    "'  x  '.strip()",
    "'xxyxx'.strip('x')",
    "'  x'.lstrip()",
    "'x  '.rstrip()",
    "'hello'.replace('l', 'L')",
    "'hello'.startswith('he')",
    "'hello'.endswith(('x', 'lo'))",
    "'{} {}'.format('a', 1)",
    "'{0}-{name}'.format('a', name='b')",
    "'{:>5}|{:.2f}'.format('x', 3.14159)",
    "', '.join(['a', 'b'])",
    "'hello'.count('l')",
    "'hello'.find('l')",
    "'hello'.find('z')",
    "'hello'.index('e')",
    "'123'.isdigit()",
    "'abc'.isalpha()",
    "'ab1'.isalnum()",
    "'  '.isspace()",
    "'Hi'.isupper()",
    "'42'.zfill(5)",
    "'x'.center(5, '*')",
    "'x'.ljust(3, '.')",
    "'x'.rjust(3)",
    "'a\\nb'.splitlines()",
    "'a=b=c'.partition('=')",
    "'a=b=c'.rpartition('=')",
    "'Hello'.swapcase()",
    "'hello world'.capitalize()",
    "'ß'.upper()",
    "'İ'.lower()",
    "'abc'.encode()",
    "branding.get('accent')",
    "branding.get('nope')",
    "branding.get('nope', 'x')",
    "branding.keys()|list",
    "branding.values()|list|length",
    "branding.items()|list|first",
    "[1, 2, 1].count(1)",
    "[1, 2, 3].index(2)",
    "context.iocs[0].get('value')",
):
    case(f"method {expr}", "{{ " + expr + " }}", ctx="alert")
case("list append", "{% set l = [] %}{{ l.append(1) }}{{ l }}")
case("dict update", "{% set d = {} %}{{ d.update({'a': 1}) }}{{ d }}")

# --- Errors ------------------------------------------------------------------------------
for src in (
    "{{ nope }}",
    "{{ nope.attr }}",
    "{{ nope['k'] }}",
    "{{ branding.nope }}",
    "{{ branding['nope'] }}",
    "{{ user_name.nope }}",
    "{{ event.nope }}",
    "{{ none.attr }}",
    "{{ [1][5] }}",
    "{{ (1, 2)[5] }}",
    "{{ 'abc'[10] }}",
    "{{ 1.attr }}",
    "{% if nope %}x{% endif %}",
    "{% for x in nope %}{% endfor %}",
    "{{ nope ~ 'x' }}",
    "{{ nope + 1 }}",
    "{{ nope == 1 }}",
    "{{ nope or 'x' }}",
    "{{ nope() }}",
    "{{ user_name() }}",
    "{{ user_name.nope() }}",
    "{{ 1 / 0 }}",
    "{{ 1 // 0 }}",
    "{{ 1 % 0 }}",
    "{{ 1 + 'a' }}",
    "{{ 'a' - 1 }}",
    "{{ [1] + 'a' }}",
    "{{ 'a' < 1 }}",
    "{{ {} < {} }}",
    "{{ 1|nosuchfilter }}",
    "{{ 1 is nosuchtest }}",
    "{{ 'a' ~ }}",
    "{{ user_name",
    "{% if true %}x",
    "{% if true %}x{% endfor %}",
    "{% nosuchtag %}",
    "{{ }}",
    "{% endif %}",
    "{% for %}{% endfor %}",
    "{{ 'unterminated }}",
    "{{ a b }}",
    "{{ ''.__class__ }}",
    "{{ user_name.__class__.__mro__ }}",
    "{{ event.__dict__ }}",
    "{{ event.model_dump() }}",
    "{{ range(10**7)|list|length }}",
    "{{ 'x' * 70000 }}",
    "{% for i in range(70000) %}x{% endfor %}",
    "{% include 'other.html' %}",
    "{% extends 'base.html' %}",
    "{% import 'macros.html' as m %}",
    "{{ 'a' if false }}",
    "{{ ('a' if false)|default('d') }}",
    "{{ '%d' % 'x' }}",
    "{{ '%s %s' % ('a',) }}",
    "{{ '{}'.format() }}",
    "{{ 'abc'|int(base=99) }}",
    "{{ [1, 'a']|sort }}",
    "{{ 1|join }}",
    "{{ 5|length }}",
    "{{ none|upper }}",
    "{{ 1|upper }}",
    "{{ none|list }}",
    "{{ cycler() }}",
    "{{ namespace(a=1).b }}",
    "{{ loop.index }}",
    "{% for x in [1] %}{{ loop.nope }}{% endfor %}",
):
    case(f"error {src}", src, ctx="alert")
case("too large", "{{ 'x' * 65536 }}")
case("just under the limit", "{{ 'x' * 65535 }}{{ 'é'|length }}")
case("multibyte over the limit", "{{ 'é' * 32768 }}")

# --- Scoping, macros, loops and blocks: the compiler's frames ------------------------------
for src in (
    "{{ m() }}{% macro m() %}x{% endmacro %}",
    "{% macro m() %}{{ x }}{% endmacro %}{% set x = 1 %}{{ m() }}",
    "{% macro m() %}{{ x }}{% endmacro %}{{ m() }}{% set x = 1 %}",
    "{{ user_name }}{% set user_name = 'z' %}",
    "{% set user_name = 'z' %}{{ user_name }}",
    "{% if true %}{% set y = 1 %}{% endif %}{{ y }}",
    "{% if false %}{% set y = 1 %}{% endif %}{{ y }}",
    "{% if false %}{% set user_name = 'q' %}{% endif %}{{ user_name }}",
    "{% if false %}{% elif true %}{% set y = 2 %}{% else %}{% set y = 3 %}{% endif %}{{ y }}",
    "{% for x in [1, 2] %}{% set y = x %}{% endfor %}{{ y is defined }}",
    "{% set x = 1 %}{% for i in [1] %}{% set x = 2 %}{{ x }}{% endfor %}{{ x }}",
    "{% for i in [1, 2] %}{% if loop.first %}{% set z = 'a' %}{% endif %}{{ z }}{% endfor %}",
    "{% for x in [1, 2] %}{% macro m() %}{{ x }}{% endmacro %}{{ m() }}{% endfor %}",
    "{% set ns = namespace(m=none) %}{% for x in [1] %}{% macro m() %}[{{ x }}]{% endmacro %}" "{% set ns.m = m %}{% endfor %}{{ ns.m() }}",
    "{% macro m(a, b=a ~ '!') %}{{ b }}{% endmacro %}{{ m('x') }}",
    "{% macro m(a=b, b=1) %}{{ a }}{% endmacro %}{{ m() }}",
    "{% macro m(a) %}{{ a }}|{{ varargs }}|{{ kwargs }}{% endmacro %}{{ m(1, 2, 3, k=4) }}",
    "{% macro m(a) %}{{ a }}{% endmacro %}{{ m(1, 2) }}",
    "{% macro m(a) %}{{ a }}{% endmacro %}{{ m(b=2) }}",
    "{% macro m(a) %}{{ a }}{% endmacro %}{{ m() }}",
    "{% macro m() %}{{ caller() }}{% endmacro %}{{ m() }}",
    "{% macro m(caller) %}{{ caller() }}{% endmacro %}",
    "{% macro m(caller=none) %}[{{ caller }}]{% endmacro %}{{ m() }}{% call m() %}x{% endcall %}",
    "{% macro m() %}{{ varargs }}{% endmacro %}{{ m(1, 2) }}",
    "{% macro m() %}{% endmacro %}{{ m }}|{{ m.name }}|{{ m.arguments }}|{{ m.caller }}",
    "{% macro items(xs) %}{% for i in xs %}<{{ caller(i) }}>{% endfor %}{% endmacro %}"
    "{% call(x) items([1, 2]) %}{{ x * 2 }}{% endcall %}",
    "{% macro r(n) %}{{ r(n + 1) }}{% endmacro %}{{ r(0) }}",
    "{% macro m() %}m{% endmacro %}{% block b %}{{ m() }}{% endblock %}",
    "{% for x in [1] %}{% macro m() %}{% endmacro %}{% endfor %}{{ m is defined }}",
    "{{ caller }}",
    "{% set a = [1] %}{% set b = a %}{{ b.append(2) }}{{ a }}",
    "{% for i in [1, 2] %}{% set l = [0] %}{{ l.append(i) }}{{ l }}{% endfor %}",
    "{% for i in [1, 2] %}{% set l = [0]|list %}{{ l.append(i) }}{{ l }}{% endfor %}",
    "{% set x = 1 %}{{ x }}{% set x = x + 1 %}{{ x }}",
    "{% for x in [1] %}{{ x }}{% endfor %}{{ x }}",
    "{% with a = 1, b = a %}{{ a }}{{ b }}{% endwith %}",
    "{% with %}x{% endwith %}",
    "{% for x in user_name %}{{ x }}.{% endfor %}",
    "{% for n in [{'v': 1, 'c': [{'v': 2, 'c': []}]}] recursive %}{{ n.v }}"
    "{% if n.c %}[{{ loop(n.c) }}]{% endif %}{{ loop.depth }}{% endfor %}",
    "{% for x in context.iocs recursive %}{{ x.value }};{% endfor %}",
    "{% for x in [1] %}{{ loop(x) }}{% endfor %}",
    "{% for x in [1, 2, 3, 4] if x is even %}{{ loop.index }}/{{ loop.length }}:{{ x }} {% endfor %}",
    "{% for x in [] %}a{% else %}empty{% endfor %}",
    "{% for x in [1] if false %}a{% else %}none{% endfor %}",
    "{% for a, b in [[1, 2], [3, 4]] if a > 1 %}{{ a }}{{ b }}{% endfor %}",
    "{% for a, b in [[1, 2, 3]] %}{% endfor %}",
    "{% for a, b in [1] %}{% endfor %}",
    "{% for x in [1, 1, 2] %}{{ loop.changed(x) }}{% endfor %}",
    "{% for loop in [1] %}{% endfor %}",
    "{% for x in [1] %}{% set loop = 2 %}{% endfor %}",
    "{% for x in [1, 2] %}{{ loop }}{% endfor %}",
    "{% for x in [1, 2] %}{{ loop.revindex }}{{ loop.last }}{{ loop.nextitem is defined }}{% endfor %}",
    "{% for x in [1] if loop %}{% endfor %}",
    "{% for x in 5 if x %}{% endfor %}",
    "{% block b %}in block {{ user_name }}{% endblock %}",
    "{% set x = 1 %}{% block b %}{{ x }}{% endblock %}",
    "{% for i in [1] %}{% block b scoped %}{{ i }}{% endblock %}{% endfor %}",
    "{% for i in [1] %}{% block b %}{{ i }}{% endblock %}{% endfor %}",
    "{% block a %}{% endblock %}{% block a %}{% endblock %}",
    "{% block b %}x{% endblock %}{{ self.b() }}",
    "{% block b %}{{ super() }}{% endblock %}",
    "{{ self }}|{{ self.nope is defined }}",
    "{% block b required %}{% endblock %}",
    "{% set x | length %}abc{% endset %}{{ x + 1 }}",
    "{% set x %}{% endset %}{{ x|length }}",
    "{% set ns.x = 1 %}",
    "{% if true %}{% set x = 1 %}{{ x }}{% endif %}",
    "{{ ({[1]: 2}).x }}",
    "{{ nope }}{{ ({[1]: 2}).x }}",
    "{{ {[1]: 2} }}",
    "{{ x|nosuch if false }}",
    "{% if false %}{{ 1|nosuch }}{% endif %}ok",
    "{% if true %}{{ 1|nosuch }}{% endif %}",
    "{{ 1 if 1 is nosuch else 2 }}",
    "{{ (1|a)|b }}",
    "{% if true %}{% filter nosuch %}x{% endfilter %}{% endif %}",
    "{{ 1e400 }}|{{ [1e400] }}|{{ 'a' ~ 1e400 }}",
    "{{ user_name|default(1e400) }}",
    "{{ 10**5000 }}",
    "{{ user_name ~ (10**5000) }}",
    "{% include [] ignore missing %}ok",
    "{% include [] %}",
    "{% include ['a.html', 'b.html'] %}",
    "{% include user_name %}",
    "{% extends 'a' %}{{ x|nosuchfilter }}",
    "{% if true %}{% extends 'a' %}{% endif %}",
    "{% macro m() %}{% extends 'a' %}{% endmacro %}",
    "{{ range(*[3])|list }}|{{ dict(**{'a': 1}) }}",
    "{{ dict(a=1, **{'a': 2}) }}",
    "{{ range(*1) }}",
    "{{ dict(**1) }}",
    "{{ dict(**{1: 2}) }}",
    "{{ 'x'.format }}",
    "{% set x = 1 %}{% set y = 2 %}{{ x }}{{ y }}",
    "{% set a, (b, c) = 1, [2, 3] %}{{ a }}{{ b }}{{ c }}",
    "{% raw %}{{ x }}{% endraw %}",
    "{# comment #}x",
):
    case(f"frames {src}", src, ctx="alert")
for src in (
    "{% filter upper %}{{ customer_name }}{% endfilter %}",
    "{% set x | upper %}a{{ customer_name }}{% endset %}{{ x }}",
    "{% autoescape customer_name == '' %}{{ customer_name }}|{{ '<x>' }}|{{ '<' ~ customer_name }}{% endautoescape %}",
    "{% autoescape true %}{% macro m() %}<b>{{ customer_name }}</b>{% endmacro %}{% endautoescape %}{{ m() }}",
    "{% macro m() %}{{ customer_name }}{% endmacro %}{% autoescape true %}{{ m() }}{% endautoescape %}",
    "{% autoescape customer_name %}{{ '<' ~ 'b' }}{{ customer_name }}{% endautoescape %}",
    "{% autoescape true %}{% block b %}{{ customer_name }}{% endblock %}{% endautoescape %}",
    "{{ ('<i>'|safe) ~ customer_name }}",
    "{{ event.severity ~ 'x' }}",
    "{% for x in ['<a>'] recursive %}{{ x }}{% endfor %}",
    "{% macro m() %}<{{ caller() }}>{% endmacro %}{% call m() %}{{ customer_name }}{% endcall %}",
):
    case(f"escaping {src}", src, ae=BOTH)


# --- The seeded temporary-password template ----------------------------------------------
SEEDED_SUBJECT = "Your temporary {{ customer_name or 'CoPilot' }} password"
SEEDED_BODY = (
    '<div style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;'
    'max-width:560px;margin:0 auto;padding:24px;color:#374151">'
    "{% if branding.logo %}"
    '<img src="{{ branding.logo }}" alt="{{ branding.title | default("") }}" '
    'style="max-height:48px;margin-bottom:24px">'
    "{% endif %}"
    '<h2 style="color:{{ branding.accent | default("#1f2937") }};margin:0 0 16px">'
    "Your temporary password</h2>"
    "<p>Hello {{ user_name }},</p>"
    "<p>An administrator has issued a temporary password for your "
    "{% if customer_name %}{{ customer_name }} {% endif %}CoPilot account.</p>"
    '<p style="background:{{ branding.accent_soft | default("#e5e7eb") }};padding:16px;'
    "border-radius:6px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:18px;"
    'letter-spacing:0.5px;word-break:break-all">{{ temp_password }}</p>'
    "{% if login_url %}"
    '<p style="margin:24px 0">'
    '<a href="{{ login_url }}" style="background:{{ branding.accent_strong | default("#2563eb") }};'
    'color:{{ branding.accent_text | default("#ffffff") }};padding:10px 20px;border-radius:6px;'
    'text-decoration:none;display:inline-block">Sign in</a></p>'
    "{% endif %}"
    "<p><strong>Please change it immediately after signing in.</strong> "
    "If you did not expect this, contact your security team.</p>"
    '<p style="color:#6b7280;font-size:12px;margin-top:32px">'
    "{{ branding.footer_brand or 'CoPilot' }}</p>"
    "</div>"
)
case("seeded subject", SEEDED_SUBJECT, ae=BOTH)
case("seeded body", SEEDED_BODY, ae=BOTH)


def build_event(spec):
    return NotificationEvent(**spec)


def run(c):
    spec = CONTEXTS[c["ctx"]]
    try:
        out = render(c["source"], build_event(spec["event"]), autoescape=c["autoescape"], extra_context=dict(spec["extra"]))
        return {"ok": out}
    except Exception as e:  # noqa: BLE001 — the error text is the vector
        return {"error": {"type": type(e).__name__, "message": str(e)}}


cases = []
for c in CASES:
    cases.append({**c, "outcome": run(c)})

json.dump({"contexts": CONTEXTS, "cases": cases}, sys.stdout, indent=1, ensure_ascii=False)
sys.stdout.write("\n")
