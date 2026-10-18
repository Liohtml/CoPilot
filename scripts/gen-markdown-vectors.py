"""Generate crates/copilot-markdown/src/markdown_vectors.json.

Runs the backend's own `markdown_to_html` (markdown-it-py, gfm-like, html off)
over a hand-written corpus — AI-report-shaped documents, GFM tables with
alignment, fences, lists, blockquotes, links, images, autolinks, entities,
escapes, raw HTML — plus a deterministic fuzz corpus of markdown fragments,
and records each output (or the exception markdown-it-py raised). The Rust
port must reproduce every one. Regenerate after a markdown-it-py, mdurl or
Python upgrade:

    cd backend && /var/lib/copilot-venv/bin/python ../scripts/gen-markdown-vectors.py
"""

from __future__ import annotations

import json
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "backend"))

from app.notifications.utils import markdown_html  # noqa: E402
from app.notifications.utils.markdown_html import _RENDERER  # noqa: E402
from app.notifications.utils.markdown_html import _WRAPPER_STYLE  # noqa: E402
from app.notifications.utils.markdown_html import markdown_to_html  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-markdown" / "src" / "markdown_vectors.json"

AI_REPORT = """# Investigation: Suspicious PowerShell on WKSTN-014

**Verdict:** *Likely malicious* — confidence **high**.

## Timeline

| Time (UTC) | Event | Source |
|:-----------|:-----:|-------:|
| 2026-09-01 04:00 | `powershell.exe -enc SQBFAFgA...` | Sysmon 1 |
| 2026-09-01 04:01 | Outbound to 185.199.108.153:443 | Sysmon 3 |
| 2026-09-01 04:02 | Registry run key \\| persistence | Sysmon 13 |

## IOCs

| Indicator | Type | VirusTotal |
|---|---|---|
| 185.199.108.153 | ip | 3/94 |
| a1b2c3d4e5f6 | hash | *unknown* |

> The parent process was **winword.exe**, which is consistent
> with a malicious document.
>
> - user opened `invoice.docm`
> - macros enabled

### Recommended actions

1. Isolate the host.
2. Reset the user's credentials.
   - including service accounts
3. Block the IP at the perimeter.

```powershell
Get-Process | Where-Object { $_.Name -eq "powershell" }
```

See [MITRE T1059.001](https://attack.mitre.org/techniques/T1059/001/ "PowerShell") and <https://example.com/report?id=42&x=<y>>.

---

~~False positive~~ ruled out. Contact <soc@example.com>.
"""

CORPUS = [
    "",
    " ",
    "plain",
    "a\nb",
    "a  \nb",
    "a\\\nb",
    "a\r\nb\rc",
    "nul \0 char",
    "# h1\n## h2 ##\n###### h6\n####### seven",
    "#no space",
    "Setext\n===\n\nTwo\n---",
    "*em* _em_ **strong** __strong__ ***both*** *a **b** c*",
    "snake_case_word and 2*3*4",
    "**bold**text and *it*'s",
    "~~strike~~ ~single~ ~~~three~~~",
    "`code` ``co`de`` ` spaced ` `unclosed",
    "    indented code\n    line 2\n\n    after blank",
    "```\nfenced\n```",
    "```python title\nx = 1 < 2\n```",
    "~~~\ntilde\n~~~~",
    "```\nunclosed fence",
    "> quote\ncontinued\n> > nested",
    "> - item\n>   more",
    "- a\n- b\n\n- c",
    "- a\n  - nested\n    - deeper\n- b",
    "1. one\n2. two\n3) three",
    "3. starts at three\n4. four",
    "* star\n+ plus\n- dash",
    "- [ ] task\n- [x] done",
    "1. a\n\n   para in item\n2. b",
    "| a | b |\n|---|:-:|\n| 1 | 2 |",
    "a | b\n--|--\nc | d",
    "| x |\n|---|\n| y | extra |\n| short",
    "| a \\| b | c |\n|---|---|\n| `x\\|y` | z |",
    "|a|\n|-|\n\nnot table",
    "| a |\n| --- |\n- list ends table",
    "Term\n| a |\n|---|",
    "***\n---\n___\n* * *",
    "[link](http://example.com)",
    "[link](<http://example.com/with space> 'title')",
    '[link](http://example.com "title") [empty]()',
    "[ref][r] [r] [R][] \n\n[r]: http://ref.example 'Ref Title'",
    "[a]: /url\n[a]: /other\n\n[a]",
    '![alt *text*](img.png "t") ![](x.png)',
    "![nested ![inner](i.png)](o.png)",
    "<http://auto.link/path?q=1> <mailto:me@x.org> <me@example.com>",
    "<javascript:alert(1)> [x](javascript:alert(1)) [y](data:image/png;base64,AA) [z](data:text/html,x)",
    "[u](http://münchen.de/ä) <http://xn--mnchen-3ya.de>",
    "&amp; &copy; &#65; &#x41; &#0; &#xFFFFFF; &nosuch; &AMP",
    "\\* not em \\_ \\` \\\\ \\a",
    "<b>raw html</b> <!-- comment --> <div>\nblock\n</div>",
    "<script>alert(1)</script>",
    "line with trailing spaces   \nnext",
    "tab\tseparated\tvalues",
    "\tindented with tab",
    "> quote\n\n\n> another",
    "1) a\n1) b\n\nparagraph\n2. c",
    "- a\n-\n- c",
    "-\n  foo",
    "*foo**bar**baz*",
    "**foo*bar*baz**",
    "_foo_bar_baz_",
    "*(*foo*)*",
    "a * b * c",
    "[foo [bar]](/url)",
    '[foo](/url "title" junk)',
    "[foo]( /url )",
    "[foo](/url(with)parens)",
    "unicode: café — “quotes” …",
    "emoji 🎉 *🎉* **x🎉**",
    "Ω *ω* ẞ",
    AI_REPORT,
    "> | a |\n> | - |\n>",
    ">   ```\n> ",
    "x\n\n  ",
    "  \n\n  ",
    "\n\n\nlate start",
    "a\n\n\n\nb",
    "| a |\n|:--|\n| *x* **y** |",
    "[a](http://x.com/%zz%41 'q\\'t')",
    "[a](http://user:pw@host:8080/p?q#h)",
    "[a](//host/path) [b](mailto:a@b.c) [c](HTTP://Example.COM)",
    "[a](http://[::1]:80/) [b](http://a..b/) [c](http://a_b.c/)",
    "<HTTP://UPPER.CASE> <a+b://x>",
    "[x]:\n/url\n'title'\n\n[x]",
    "[x]: /url 'unterminated\n\n[x]",
    "[x]: <bad url\n\n[x]",
    "  [x]: /u\n\n[x]",
]

FRAGMENTS = [
    "a",
    "b",
    "word",
    " ",
    "  ",
    "\t",
    "\n",
    "\n\n",
    "*",
    "**",
    "_",
    "__",
    "~",
    "~~",
    "`",
    "``",
    "```",
    "[",
    "]",
    "(",
    ")",
    "![",
    "](",
    "<",
    ">",
    "#",
    "# ",
    "## ",
    "-",
    "- ",
    "+ ",
    "1. ",
    "2) ",
    "> ",
    "|",
    " | ",
    "|---|",
    ":-:",
    "---",
    "===",
    "\\",
    "\\*",
    "&amp;",
    "&#x41;",
    "&#65;",
    "&bogus;",
    "&",
    "http://ex.com",
    "<http://ex.com>",
    "<a@b.co>",
    "'",
    '"',
    "(t)",
    "    ",
    "\u00e9",
    "\u2014",
    "\U0001f389",
    "[r]",
    "[r]: /u",
    "\u00a0",
    "x\u3000y",
    "<b>",
    "</b>",
    "javascript:",
    "%20",
    "%E2%82%AC",
    "![i](p.png)",
    "[l](/u 't')",
    "<x@y.z>",
]


LINE_STARTS = [
    "",
    "",
    "",
    "  ",
    "    ",
    "\t",
    "# ",
    "### ",
    "> ",
    "> > ",
    "- ",
    "  - ",
    "* ",
    "1. ",
    "10) ",
    "| ",
    "|---|---|",
    "| :-- | --: |",
    "---",
    "===",
    "```",
    "~~~",
    "[r]: http://r.example/x ",
    "> - ",
    "-   ",
]


def fuzz(seed: int, count: int) -> list[str]:
    """Inline soup: random fragments run together."""
    rnd = random.Random(seed)
    out = []
    for _ in range(count):
        n = rnd.randint(1, 18)
        out.append("".join(rnd.choice(FRAGMENTS) for _ in range(n)))
    return out


def line_fuzz(seed: int, count: int) -> list[str]:
    """Documents of block constructs: each line a block marker plus a little inline soup."""
    rnd = random.Random(seed)
    out = []
    for _ in range(count):
        lines = []
        for _ in range(rnd.randint(1, 8)):
            body = "".join(rnd.choice(FRAGMENTS) for _ in range(rnd.randint(0, 4)))
            if rnd.random() < 0.3:
                body = " | ".join(rnd.choice(["a", "*b*", "`c`", "", "d\\|e"]) for _ in range(rnd.randint(1, 4)))
            lines.append(rnd.choice(LINE_STARTS) + body)
        out.append("\n".join(lines) + rnd.choice(["", "\n", "\n\n"]))
    return out


def table_fuzz(seed: int, count: int) -> list[str]:
    """GFM tables: alignment rows, ragged bodies, escaped pipes, prefixes."""
    rnd = random.Random(seed)
    cells = ["a", "*b*", "`c|d`", "", " x ", "d\\|e", "[l](/u)", "**s**", "&amp;", "1.5"]
    aligns = ["---", ":--", "--:", ":-:", "-", " --- ", "::", "-x-"]
    out = []
    for _ in range(count):
        n = rnd.randint(1, 4)
        pipe = rnd.random() < 0.7
        prefix = rnd.choice(["", "", "> ", "- ", "  ", "    "])

        def row(k: int) -> str:
            body = " | ".join(rnd.choice(cells) for _ in range(k))
            return f"| {body} |" if pipe else body

        lines = [row(n), ("|" if pipe else "") + "|".join(rnd.choice(aligns) for _ in range(n)) + ("|" if pipe else "")]
        lines += [row(max(0, n + rnd.randint(-1, 1))) for _ in range(rnd.randint(0, 3))]
        if rnd.random() < 0.3:
            lines.append(rnd.choice(["", "after", "> q", "- l", "```"]))
        out.append("\n".join(prefix + line for line in lines))
    return out


#: The inline styles recur in every table cell; the file stores them as
#: these markers and the Rust test expands them (`expand_styles`).
STYLE_MARKERS = {
    "\u00a7T": markdown_html._TABLE_STYLE,
    "\u00a7H": markdown_html._TH_STYLE,
    "\u00a7D": markdown_html._TD_STYLE,
    "\u00a7P": markdown_html._PRE_STYLE,
    "\u00a7C": markdown_html._CODE_STYLE,
    "\u00a7B": markdown_html._BLOCKQUOTE_STYLE,
}


def compact(html: str) -> str:
    assert "\u00a7" not in html
    for marker, style in STYLE_MARKERS.items():
        html = html.replace(f'style="{style}', f'style="{marker}')
    return html


def main() -> None:
    cases = list(dict.fromkeys(CORPUS + fuzz(1048, 700) + line_fuzz(1185, 900) + table_fuzz(1256, 400)))
    vectors = []
    for source in cases:
        # `html` is the renderer's output; the wrapper is checked here once so
        # the file does not carry it thousands of times.
        try:
            inner = _RENDERER.render(source)
        except Exception as e:  # noqa: BLE001 — recorded, the port must raise alike
            vectors.append({"source": source, "html": None, "error": f"{type(e).__name__}: {e}"})
            continue
        wrapped = str(markdown_to_html(source))
        expected = "" if not source.strip() else f'<div style="{_WRAPPER_STYLE}">{inner}</div>'
        assert wrapped == expected, source
        vectors.append({"source": source, "html": compact(inner), "error": None})
    OUT.write_text(json.dumps(vectors, ensure_ascii=False, indent=0) + "\n")
    errors = sum(1 for v in vectors if v["error"])
    print(f"wrote {OUT} ({len(vectors)} cases, {errors} raising)")


if __name__ == "__main__":
    main()
