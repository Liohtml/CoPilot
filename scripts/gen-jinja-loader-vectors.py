"""Generate the template-loading vectors of copilot-jinja's report environments.

    /var/lib/copilot-venv/bin/python -I scripts/gen-jinja-loader-vectors.py \
        > crates/copilot-jinja/src/jinja_loader_vectors.json

Every case renders through Jinja2 3.1's `SandboxedEnvironment` the way the report
renderers configure it: a `FileSystemLoader` (or a `ChoiceLoader` of two) over a set of
files written to a temporary directory, `autoescape` off, on, or
`select_autoescape(["html", "htm", "xml"], default=True)`, and Jinja's default
`Undefined` (`StrictUndefined` for a few cases). They cover `extends` (with `super()`,
`self`, scoped and required blocks, conditional and repeated extends), `import`,
`from … import … with context`, `include`, the default `Undefined` and `datetime`
values.

- `cases[i].env`: `{"autoescape": "off"|"on"|"select", "strict": bool}`;
- `cases[i].dirs`: one dict of `{relative path: source}` per directory (the loader's
  search path, in order);
- `cases[i].render`: a template name, or `cases[i].string`: a `from_string` source;
- `cases[i].vars`: the variables, with `{"$dt": iso}`, `{"$date": iso}`,
  `{"$tuple": [...]}` and `{"$markup": text}` for the values JSON has no type for;
- the outcome is `{"ok": output}` or `{"error": {"type", "message"}}`, where a message
  naming the temporary directory has it replaced by `<dir0>`, `<dir1>`.
"""
import datetime
import json
import os
import tempfile

from jinja2 import ChoiceLoader
from jinja2 import FileSystemLoader
from jinja2 import StrictUndefined
from jinja2 import select_autoescape
from jinja2.sandbox import SandboxedEnvironment
from markupsafe import Markup

BASE = """<html><title>{% block title %}Base{% endblock %}</title>
<body>{% block body %}<p>base body</p>{% endblock %}
<footer>{% block footer required %}{% endblock %}</footer></body></html>"""

CASES = []


def case(render=None, string=None, dirs=(), vars=None, autoescape="select", strict=False):
    CASES.append(
        {
            "env": {"autoescape": autoescape, "strict": strict},
            "dirs": [dict(d) for d in dirs],
            **({"render": render} if render is not None else {"string": string}),
            "vars": vars or {},
        },
    )


# --- extends ------------------------------------------------------------------------------------
case(
    "child.html",
    dirs=[
        {
            "base.html": BASE,
            "child.html": "{# a comment #}\n{% extends 'base.html' %}\nignored text\n"
            "{% block title %}Child — {{ super() }}{% endblock %}"
            "{% block body %}{{ self.title() }}|{{ name }}{% endblock %}"
            "{% block footer %}f{% endblock %}",
        },
    ],
    vars={"name": "<b>"},
)
case(
    "grand.html",
    dirs=[
        {
            "base.html": "A{% block x %}[base {{ v }}]{% endblock %}B",
            "mid.html": "{% extends 'base.html' %}{% block x %}[mid {{ super() }}]{% endblock %}",
            "grand.html": "{% extends 'mid.html' %}{% set v = 3 %}{% block x %}[grand {{ super() }}]{% endblock %}",
        },
    ],
    vars={"v": 1},
)
case(
    "c.html",
    dirs=[{"b.html": "{% block footer required %}{% endblock %}", "c.html": "{% extends 'b.html' %}"}],
)
case(
    "c.html",
    dirs=[
        {
            "b.html": "{% for i in [1,2] %}{% block row scoped %}<{{ i }}>{% endblock %}{% endfor %}",
            "c.html": "{% extends 'b.html' %}{% block row %}({{ i }}){% endblock %}",
        },
    ],
)
case(
    "c.html",
    dirs=[
        {
            "b.html": "B{% block a %}a{% endblock %}",
            "c.html": "pre{% if flag %}{% extends 'b.html' %}{% endif %}post{% block a %}A{% endblock %}",
        },
    ],
    vars={"flag": True},
)
case(
    "c.html",
    dirs=[
        {
            "b.html": "B{% block a %}a{% endblock %}",
            "c.html": "pre{% if flag %}{% extends 'b.html' %}{% endif %}post{% block a %}A{% endblock %}",
        },
    ],
    vars={"flag": False},
)
case("c.html", dirs=[{"b.html": "B", "c.html": "{% extends 'b.html' %}{% extends 'b.html' %}"}])
case("c.html", dirs=[{"c.html": "{% extends 'missing.html' %}"}])
case("c.html", dirs=[{"c.html": "{% extends '../x.html' %}"}])
case(
    "c.html",
    dirs=[
        {
            "b.html": "<{{ self.t() }}>{% block t %}T{% endblock %}",
            "c.html": "{% extends 'b.html' %}{% block t %}{{ super.super }}x{% endblock %}",
        },
    ],
)
case(
    "sub/c.html",
    dirs=[{"sub/b.html": "[{% block a %}{% endblock %}]", "sub/c.html": "{% extends 'sub/b.html' %}{% block a %}ok{% endblock %}"}],
)
case("c.html", dirs=[{"c.html": "{% extends 'b.html' %}"}, {"b.html": "from the second directory"}])
case("nope.html", dirs=[{"a.html": "a"}, {"b.html": "b"}])
case("nope.html", dirs=[{"a.html": "a"}])
case("./c.html", dirs=[{"c.html": "dot {{ 1 }}"}])

# --- import / from import ---------------------------------------------------------------------
MACROS = """{# macros #}
{% macro chip(p) -%}<span>{{ p }}</span>{%- endmacro %}
{% macro row(x, closed=false) %}<tr>{{ chip(x) }}{% if closed %}C{% endif %}{{ period.from }}</tr>{% endmacro %}
{% set exported = 7 %}{% set _hidden = 8 %}
"""
case(
    "page.html",
    dirs=[
        {
            "macros.html": MACROS,
            "page.html": "{% from 'macros.html' import chip, row with context %}{{ chip('<i>') }}{{ row(1, true) }}|{{ exported }}",
        },
    ],
    vars={"period": {"from": "2024-01-01"}},
)
case(
    "page.html",
    dirs=[{"macros.html": MACROS, "page.html": "{% from 'macros.html' import row %}{{ row(1) }}"}],
    vars={"period": {"from": "x"}},
)
case(
    "page.html",
    dirs=[{"macros.html": MACROS, "page.html": "{% from 'macros.html' import row, nothing as n with context %}[{{ n }}]{{ row(2) }}"}],
    vars={"period": {"from": "y"}},
)
case(
    "page.html",
    dirs=[{"macros.html": MACROS, "page.html": "{% from 'macros.html' import nothing %}{{ nothing.attr }}"}],
)
case(
    "page.html",
    dirs=[
        {
            "macros.html": MACROS,
            "page.html": "{% import 'macros.html' as m %}{{ m.chip(1) }}|{{ m.exported }}|{{ m._hidden }}|{{ m.missing }}",
        },
    ],
)
case(
    "page.html",
    dirs=[{"macros.html": MACROS, "page.html": "{% import 'macros.html' as m with context %}{{ m.row(3) }}{{ m.__name__ }}"}],
    vars={"period": {"from": "z"}},
)
case(
    "page.html",
    dirs=[
        {
            "base.html": "<{% block content %}{% endblock %}>",
            "macros.html": MACROS,
            "page.html": "{% extends 'base.html' %}{% from 'macros.html' import row with context %}"
            "{% block content %}{% for c in cases %}{{ row(c, loop.last) }}{% endfor %}{% endblock %}",
        },
    ],
    vars={"period": {"from": "p"}, "cases": [1, 2]},
)
case("page.html", dirs=[{"page.html": "{% from 'macros.html' import x %}"}])
case(
    "page.html",
    dirs=[
        {
            "macros.html": "{% macro m() %}{{ v }}{% endmacro %}",
            "page.html": "{% for v in [1, 2] %}{% from 'macros.html' import m with context %}{{ m() }}{% endfor %}",
        },
    ],
    vars={"v": 0},
)

# --- include ----------------------------------------------------------------------------------
case(
    "page.html",
    dirs=[{"part.html": "[{{ x }}]", "page.html": "{% set x = 2 %}{% include 'part.html' %}{% include 'part.html' without context %}"}],
    vars={"x": 1},
)
case("page.html", dirs=[{"page.html": "a{% include 'missing.html' ignore missing %}b"}])
case("page.html", dirs=[{"part.html": "P", "page.html": "{% include ['nope.html', 'part.html'] %}"}])
case("page.html", dirs=[{"page.html": "{% include ['nope.html', 'neither.html'] %}"}])
case("page.html", dirs=[{"page.html": "{% include 'missing.html' %}"}])
case(
    "page.html",
    dirs=[
        {
            "part.html": "{% for i in items %}{{ i }}{% endfor %}",
            "page.html": "{% for items in [[1], [2, 3]] %}{% include 'part.html' %}{% endfor %}",
        },
    ],
)

# --- the default Undefined --------------------------------------------------------------------
for src in [
    "[{{ missing }}]",
    "[{{ d.missing }}]",
    "[{{ d.missing.x }}]",
    "[{{ missing.x }}]",
    "{% if missing %}y{% else %}n{% endif %}",
    "{{ missing or 'dash' }}",
    "{% for x in missing %}x{% else %}empty{% endfor %}",
    "{{ missing|length }}",
    "[{{ missing|join(',') }}]",
    "{{ missing == none }}|{{ missing is defined }}|{{ missing is none }}",
    "{{ missing + 1 }}",
    "{{ missing() }}",
    "{{ d.missing or '—' }}",
    "{{ d.type_label or (d.type or '—') }}",
    "{{ d.items|length }}",
    "{{ d['nope'] }}|{{ d.k }}",
    "{{ [missing] }}",
    "{{ missing ~ 'x' }}",
    "{{ (missing|default('def')) }}",
    "{{ d }}",
    "{{ d.__class__ }}|{{ ''.__class__ }}",
    "{% set ns = namespace(n=0) %}{% set ns.n = ns.n + 1 %}{{ ns.n }}",
]:
    case(string=src, vars={"d": {"k": "v'<", "type": None}}, autoescape="on")
case(string="[{{ missing }}]", strict=True, autoescape="on")
case(string="[{{ d.missing }}]", vars={"d": {}}, autoescape="off")

# --- datetime values --------------------------------------------------------------------------
for src in [
    "{{ t }}|{{ t2 }}|{{ day }}",
    "{{ [t, t2, day] }}",
    "{{ t.year }}-{{ t.month }}-{{ t.day }} {{ t.hour }}:{{ t.minute }}:{{ t.second }}.{{ t.microsecond }}",
    "{{ t.strftime('%Y-%m-%d %H:%M') }}|{{ t2.strftime('%d/%m/%y %a %b %f') }}",
    "{{ t.isoformat() }}|{{ t2.isoformat() }}|{{ t.isoformat(' ') }}|{{ day.isoformat() }}",
    "{{ t.date() }}|{{ t.time() }}|{{ t.weekday() }}|{{ t.isoweekday() }}",
    "{{ t if t else 'N/A' }}|{{ none_t if none_t else 'N/A' }}",
    "{{ t.tzinfo }}|{{ t.nope }}",
    "{{ t == t }}",
]:
    case(
        string=src,
        vars={
            "t": {"$dt": "2024-03-05T14:07:09"},
            "t2": {"$dt": "2024-03-05T14:07:09.000250"},
            "day": {"$date": "2024-03-05"},
            "none_t": None,
        },
        autoescape="on",
    )

# --- values -----------------------------------------------------------------------------------
case(
    string="{% for a, b in pairs %}{{ a }}={{ b }};{% endfor %}{{ pairs }}|{{ m }}|{{ f }}|{{ r }}",
    vars={"pairs": [{"$tuple": ["x", 1]}, {"$tuple": ["y", 2]}], "m": {"$markup": "<b>ok</b>"}, "f": 33.3, "r": 0.0},
    autoescape="on",
)
case(string="{{ ctx }}", vars={"ctx": {"a": 1, "b": [1.5, None, True], "c": {"d": "e"}}}, autoescape="on")
case(string="{{ ctx }}", vars={"ctx": {"a": 1, "b": [1.5, None, True], "c": {"d": "e"}}}, autoescape="off")
case(string="line\r\nnext\n", autoescape="on")
case(string="{{ x }}\n\n", vars={"x": 1}, autoescape="on")


def decode(v):
    if isinstance(v, dict):
        if "$dt" in v:
            return datetime.datetime.fromisoformat(v["$dt"])
        if "$date" in v:
            return datetime.date.fromisoformat(v["$date"])
        if "$tuple" in v:
            return tuple(decode(x) for x in v["$tuple"])
        if "$markup" in v:
            return Markup(v["$markup"])
        return {k: decode(x) for k, x in v.items()}
    if isinstance(v, list):
        return [decode(x) for x in v]
    return v


def run(c):
    with tempfile.TemporaryDirectory() as root:
        paths = []
        for i, files in enumerate(c["dirs"]):
            d = os.path.join(root, f"d{i}")
            os.makedirs(d)
            for name, source in files.items():
                p = os.path.join(d, name)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(source)
            paths.append(d)
        loader = None
        if len(paths) == 1:
            loader = FileSystemLoader(paths[0])
        elif paths:
            loader = ChoiceLoader([FileSystemLoader(p) for p in paths])
        autoescape = {"off": False, "on": True, "select": select_autoescape(["html", "htm", "xml"], default=True)}[c["env"]["autoescape"]]
        kwargs = {"loader": loader, "autoescape": autoescape}
        if c["env"]["strict"]:
            kwargs["undefined"] = StrictUndefined
        env = SandboxedEnvironment(**kwargs)
        try:
            if "render" in c:
                out = env.get_template(c["render"]).render(decode(c["vars"]))
            else:
                out = env.from_string(c["string"]).render(decode(c["vars"]))
            return {"ok": out}
        except Exception as e:  # noqa: BLE001 - the outcome is the vector
            msg = str(e)
            for i, p in enumerate(paths):
                msg = msg.replace(p, f"<dir{i}>")
            return {"error": {"type": type(e).__name__, "message": msg}}


for c in CASES:
    c["outcome"] = run(c)

print(json.dumps({"cases": CASES}, indent=1, ensure_ascii=False))
