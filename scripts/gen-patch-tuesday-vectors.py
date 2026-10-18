"""Regenerate the vectors that pin the Microsoft Patch Tuesday port (`copilot-patch-tuesday`)
to the Python module it ports (`app/integrations/microsoft_patch_tuesday/`).

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-patch-tuesday-vectors.py

Writes `crates/copilot-patch-tuesday/src/patch_tuesday_vectors.json`. Every input value is
stored as the JSON text `json.loads` reads (NaN and big ints included), every outcome as the
value or the exception (class and `str()`):

* `normalize_text`, `product_family`, `safe_float`, `extract_cvss`, `extract_severity`,
  `extract_kbs`, `build_product_lookup`, `extract_affected_products` on odd inputs;
* `calculate_priority` (its `:.3f` / `:.1f` reasons), `chunk_by_max_chars`, `second_tuesday`
  and `get_available_cycles` on fixed dates;
* `scenarios` — `get_patch_tuesday`, `get_patch_tuesday_summary` and
  `search_cves_in_patch_tuesday` with `fetch_json` replaced by scripted answers (nothing is
  sent): the calls asked for (URL and params, in order) and the response model's JSON.

Re-run after a change to the module or a Pydantic or Python upgrade.
"""

import asyncio
import datetime as real_dt
import json
import pathlib

from app.integrations.microsoft_patch_tuesday.schema.microsoft_patch_tuesday import (
    PatchTuesdayRequest,
)
from app.integrations.microsoft_patch_tuesday.services import (
    microsoft_patch_tuesday as svc,
)

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-patch-tuesday" / "src" / "patch_tuesday_vectors.json"


def text(value):
    return json.dumps(value, ensure_ascii=False)


def outcome(fn, *args):
    try:
        return {"ok": fn(*args)}
    except Exception as e:  # noqa: BLE001 - the exception is the vector
        return {"error": {"class": type(e).__name__, "text": str(e)}}


ODD_VALUES = [
    None,
    True,
    False,
    0,
    1,
    -7,
    123456789012345678901234567890,
    0.0,
    1.0,
    1.5,
    -2.25,
    1e16,
    1.5e-5,
    float("nan"),
    float("inf"),
    "",
    "  ",
    "plain",
    "  spaced\tout \n text with unicode　space  ",
    "\x1c\x1dctrl\x1e\x1f",
    "Ünïcödé ﬁ ß Σ",
    [],
    ["a", "", " b ", None, 3, ["nested", "list"]],
    [None, ""],
    {},
    {"Value": "the value"},
    {"value": 5},
    {"Description": 1.5, "Value": None},
    {"Text": True},
    {"Title": ["not", "scalar"], "Name": "named"},
    {"other": "x", "nested": {"a": [1, 2.5, None, True]}, "ü": "é"},
    {"Value": {"inner": "dict"}},
    {"x": float("nan"), "y": float("-inf")},
]

PRODUCTS = [
    "Windows Server 2022",
    "windows 11 Version 24H2 for x64-based Systems",
    "Microsoft Office LTSC 2021",
    "Microsoft 365 Apps for Enterprise",
    "Microsoft Exchange Server 2019 Cumulative Update 14",
    "Microsoft SharePoint Server Subscription Edition",
    "Microsoft SQL Server 2022 for x64-based Systems (GDR)",
    "Microsoft Visual Studio 2022 version 17.8",
    ".NET 8.0",
    "Microsoft Edge (Chromium-based)",
    "Azure Connected Machine Agent",
    "Microsoft Dynamics 365 (on-premises) version 9.1",
    "Skype for Business Server 2019",
    "",
    "WINDOWS",
    "Edgeless Sharepoint",
]


def cvss_inputs():
    return [
        {},
        {"CVSSScoreSets": []},
        {"CVSSScoreSets": {"BaseScore": 7.8, "Vector": "CVSS:3.1/AV:L/AC:L"}},
        {"CVSSScoreSets": [{"BaseScore": 5.5, "Vector": "v1"}, {"BaseScore": 8.8, "Vector": "v2"}, {"BaseScore": 8.8, "Vector": "v3"}]},
        {"CvssScoreSets": [{"baseScore": "9.1", "vectorString": " CVSS:3.1 \n /X "}]},
        {"CVSSScoreSets": [{"BaseScore": 0, "Score": "6"}, "junk", None, {"Score": "abc"}, {"BaseScore": True}]},
        {"CVSSScoreSets": [{"BaseScore": " 1_0.5 "}, {"BaseScore": "nan"}, {"BaseScore": "-inf"}]},
        {"CVSSScoreSets": [{"BaseScore": 1e400}]},
        {"CVSSScoreSets": [{"BaseScore": [1]}, {"BaseScore": {"a": 1}}, {"BaseScore": 4.0, "VectorString": {"Value": "VS"}}]},
        {"CVSSScoreSets": "abc"},
        {"CVSSScoreSets": 5},
        {
            "CVSSScoreSets": [
                {
                    "BaseScore": 123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890,
                },
            ],
        },
    ]


def severity_inputs():
    return [
        {},
        {"Threats": [{"Type": 3, "Description": {"Value": "Critical"}}]},
        {"Threats": [{"Type": "Severity", "Description": "important"}]},
        {"Threats": {"type": "severity rating", "description": "  moDERATE\nlevel  "}},
        {
            "Threats": [{"Type": "Impact", "Description": "Remote Code Execution"}, {"Type": "SEVERITY", "Description": ""}],
            "Severity": "low",
        },
        {"Threats": ["x", None, {"Type": "", "Description": "Critical"}], "severity": "ǆemo ǉ ß"},
        {"Threats": "text"},
        {"Threats": 7},
        {"Threats": [{"Type": {"Value": "Severity"}, "Description": ["crit", "ical"]}]},
        {"Severity": 3},
    ]


def kbs_inputs():
    return [
        {},
        {
            "Remediations": [
                {"Description": {"Value": "5034441"}, "URL": "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5034441"},
            ],
        },
        {"Remediations": {"Description": "kb123456 and KB12345678 but not KB123456789 nor xKB123456 nor KB12345"}},
        {"Remediations": [{"Url": "KB1234567_x KB7654321-y", "url": "kb5555555"}, {"description": "KB١٢٣٤٥٦ KB1111111 ſKB2222222"}]},
        {"Remediations": [{"Description": 1234567}, {"URL": ["KB3333333", {"k": "KB4444444"}]}, {"Description": {"Value": "KB6666666"}}]},
        {"Remediations": ["KB7777777", None, 3]},
        {"Remediations": [{"Description": False, "URL": 0}]},
        {"Remediations": "KB8888888"},
        {"Remediations": 4},
    ]


def lookup_docs():
    return [
        {},
        {
            "ProductTree": {
                "FullProductName": [
                    {"ProductID": "1", "Value": "Windows 11"},
                    {"productId": 2, "value": " Office  2021 "},
                    {"ProductId": 3.5, "Name": "Edge"},
                ],
            },
        },
        {"ProductTree": {"FullProductName": {"ProductID": True, "name": {"Value": "Dict name"}}}},
        {
            "ProductTree": {
                "FullProductName": [
                    {"ProductID": "", "Value": "x"},
                    {"ProductID": "4", "Value": ""},
                    "junk",
                    {"ProductID": {"a": 1}, "Value": "dict pid"},
                    {"ProductID": "1", "Value": "dup"},
                ],
            },
        },
        {"ProductTree": {"FullProductName": "chars"}},
        {"ProductTree": {"FullProductName": 5}},
        {"ProductTree": []},
        {"ProductTree": [1]},
        {"ProductTree": "s"},
    ]


def affected_inputs():
    lookup = {"1": "Windows 11", "2": "Office 2021", "3.5": "Edge", "True": "Truthy", "None": "Nothing", "[1]": "List", "{'a': 1}": "Dict"}
    vulns = [
        {},
        {"ProductStatuses": [{"ProductID": ["1", 2, "9"], "Type": 3}]},
        {"ProductStatuses": {"ProductID": [3.5, True, None, [1], {"a": 1}], "Fixed": "2", "Other": 1}},
        {"ProductStatus": [{"x": True, "y": 3.5, "z": None}], "Products": ["1", "2", 7]},
        {"ProductStatuses": ["junk", None], "Products": "1"},
        {"ProductStatuses": 9},
        {"ProductStatuses": "ab"},
        {"Products": [True, None]},
    ]
    return [{"vuln": v, "lookup": lookup} for v in vulns]


def priority_inputs():
    severities = [None, "Critical", "Important", "Moderate", "Low", "", "ǆemo"]
    numbers = [
        None,
        0.0,
        0.0005,
        0.0015,
        0.1,
        0.1235,
        0.2999,
        0.3,
        0.69,
        0.7,
        0.8995,
        0.9,
        0.9995,
        1.0,
        2.675,
        5.99,
        6.0,
        7.25,
        7.35,
        7.45,
        7.99,
        8.0,
        9.8,
        -0.04,
        1e300,
        float("nan"),
        float("inf"),
    ]
    families = ["Windows", "Other", "Azure", "Edge"]
    out = []
    for sev in severities[:5]:
        for cvss in [None, 6.0, 8.0, 9.8]:
            for epss in [None, 0.1, 0.3, 0.7, 0.9]:
                for fam in ["Windows", "Other"]:
                    out.append((sev, cvss, epss, fam, False))
    for n in numbers:
        out.append((None, n, n, "Azure", True))
        out.append(("Critical", n, n, "Edge", False))
        out.append(("Low", n, None, families[0], False))
    return out


def chunk_inputs():
    cves = [f"CVE-2026-{n:05d}" for n in range(1, 260)]
    return [
        ([], 1900),
        (["CVE-1"], 1900),
        (cves, 1900),
        (["aaaa", "bbbb", "cc", "d"], 9),
        (["toolongitem", "x", "yy"], 5),
        (["é" * 5, "ü" * 4], 10),
    ]


DATES = [
    real_dt.date(2026, 1, 1),
    real_dt.date(2026, 1, 13),
    real_dt.date(2026, 1, 14),
    real_dt.date(2026, 3, 31),
    real_dt.date(2026, 12, 8),
    real_dt.date(2026, 12, 9),
    real_dt.date(2026, 12, 31),
    real_dt.date(2024, 2, 29),
    real_dt.date(2025, 7, 15),
]


# --- scenarios --------------------------------------------------------------------------------------

MSRC = svc.MSRC_CVRF_BASE
EPSS = svc.EPSS_BASE
KEV = svc.CISA_KEV_JSON

DOC = {
    "DocumentTitle": {"Value": "January 2026 Security Updates"},
    "ProductTree": {
        "FullProductName": [
            {"ProductID": "11926", "Value": "Windows 11 Version 24H2 for x64-based Systems"},
            {"ProductID": "12001", "Value": "Windows Server 2025"},
            {"ProductID": "11800", "Value": "Microsoft Office LTSC 2021 for 64-bit editions"},
            {"ProductID": "11700", "Value": "Microsoft Exchange Server 2019 Cumulative Update 14"},
            {"ProductID": "11600", "Value": "Microsoft Edge (Chromium-based)"},
            {"ProductID": "11500", "Value": "Azure Connected Machine Agent"},
            {"ProductID": "11400", "Value": "Skype for Business Server 2019"},
        ],
    },
    "Vulnerability": [
        {
            "Title": {"Value": "Windows Kernel Elevation of Privilege Vulnerability"},
            "CVE": "CVE-2026-20001",
            "Threats": [{"Type": 0, "Description": {"Value": "Important"}}, {"Type": 3, "Description": {"Value": "Important"}}],
            "CVSSScoreSets": [{"BaseScore": 7.8, "Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "ProductID": ["11926"]}],
            "ProductStatuses": [{"ProductID": ["11926", "12001"], "Type": 3}],
            "Remediations": [
                {"Description": {"Value": "5034441"}, "URL": "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5034441"},
            ],
        },
        {
            "Title": {"Value": "Microsoft Office Remote Code Execution Vulnerability"},
            "CVE": "cve-2026-20002",
            "Severity": "critical",
            "CVSSScoreSets": [{"BaseScore": 8.4, "Vector": "CVSS:3.1/AV:L"}],
            "ProductStatuses": [{"ProductID": ["11800"], "Type": 3}],
            "Remediations": [{"Description": "KB5002500", "URL": "https://support.microsoft.com/help/5002500"}],
        },
        {
            "Title": "Exchange Server Spoofing",
            "CVE": "CVE-2026-20003",
            "CVSSScoreSets": [{"BaseScore": 6.5}],
            "ProductStatuses": [{"ProductID": ["11700", "99999"]}],
        },
        {"Title": "Edge", "CVE": "CVE-2026-20004", "Threats": [{"Type": "Severity", "Description": "moderate"}], "Products": ["11600"]},
        {
            "Title": "Azure Agent",
            "CVE": "CVE-2026-20005",
            "CVSSScoreSets": [{"BaseScore": 5.0}],
            "ProductStatuses": [{"ProductID": ["11500"]}],
        },
        {"Title": "Unmapped", "CVE": "CVE-2026-20006"},
        {"Title": "Skype", "CVE": "CVE-2026-20007", "Severity": "low", "ProductStatuses": [{"ProductID": "11400"}]},
        {"Title": "Not a CVE", "CVE": "ADV990001"},
        "junk",
    ],
}

EPSS_ANSWER = {
    "status": "OK",
    "data": [
        {"cve": "CVE-2026-20001", "epss": "0.94321", "percentile": "0.99", "date": "2026-01-14"},
        {"cve": "cve-2026-20002", "epss": "0.12345", "percentile": "0.80000", "date": "2026-01-14"},
        {"cve": "CVE-2026-20005", "epss": 0.35, "percentile": None, "date": None},
        {"cve": "", "epss": "1"},
        {"cve": "CVE-2026-20007", "epss": "", "percentile": "x"},
    ],
}

KEV_ANSWER = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-20003",
            "vendorProject": "Microsoft",
            "product": "Exchange Server",
            "vulnerabilityName": "Microsoft Exchange Server Spoofing Vulnerability",
            "dateAdded": "2026-01-13",
            "shortDescription": "  Exchange   contains\na spoofing vulnerability. ",
            "requiredAction": "Apply mitigations per vendor instructions.",
            "dueDate": "2026-02-03",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20003", ""],
        },
        {"cveID": "cve-2026-20007", "vendorProject": {"Value": "MS"}},
        {"cveId": "CVE-2026-29999"},
        {"CVE": "not-a-cve"},
        "junk",
    ],
}


def cves_param(cves):
    return {"cve": ",".join(cves)}


SORTED_CVES = sorted(
    {"CVE-2026-20001", "CVE-2026-20002", "CVE-2026-20003", "CVE-2026-20004", "CVE-2026-20005", "CVE-2026-20006", "CVE-2026-20007"},
)


def scenario_list():
    full = [
        (f"{MSRC}/2026-Jan", None, {"value": DOC}),
        (EPSS, cves_param(SORTED_CVES), {"value": EPSS_ANSWER}),
        (KEV, None, {"value": KEV_ANSWER}),
    ]
    out = []
    out.append({"name": "full", "call": "get", "cycle": "2026-Jan", "epss": True, "kev": True, "answers": full})
    out.append({"name": "summary", "call": "summary", "cycle": "2026-Jan", "epss": True, "kev": True, "top_n": 3, "answers": full})
    out.append({"name": "no enrichment", "call": "get", "cycle": "2026-Jan", "epss": False, "kev": False, "answers": full[:1]})
    out.append({"name": "epss only", "call": "get", "cycle": "2026-Jan", "epss": True, "kev": False, "answers": full[:2]})
    out.append(
        {
            "name": "search",
            "call": "search",
            "cycle": "2026-Jan",
            "cve_ids": ["cve-2026-20001", "CVE-2026-20003", "nope"],
            "product": None,
            "answers": full,
        },
    )
    out.append(
        {
            "name": "search product",
            "call": "search",
            "cycle": "2026-Jan",
            "cve_ids": ["CVE-2026-20001"],
            "product": "Windows Server 2025",
            "answers": full,
        },
    )
    out.append(
        {"name": "search none", "call": "search", "cycle": "2026-Jan", "cve_ids": ["CVE-1999-0001"], "product": None, "answers": full},
    )
    out.append(
        {
            "name": "msrc failure",
            "call": "get",
            "cycle": "2026-Feb",
            "epss": True,
            "kev": True,
            "answers": [(f"{MSRC}/2026-Feb", None, {"raise": "GET x failed: HTTP 404 - nope"})],
        },
    )
    out.append(
        {
            "name": "msrc failure summary",
            "call": "summary",
            "cycle": "2026-Feb",
            "epss": True,
            "kev": True,
            "top_n": 25,
            "answers": [(f"{MSRC}/2026-Feb", None, {"raise": "boom"})],
        },
    )
    out.append(
        {
            "name": "msrc failure search",
            "call": "search",
            "cycle": "2026-Feb",
            "cve_ids": ["x"],
            "product": None,
            "answers": [(f"{MSRC}/2026-Feb", None, {"raise": "boom"})],
        },
    )
    out.append(
        {
            "name": "epss and kev failures",
            "call": "get",
            "cycle": "2026-Jan",
            "epss": True,
            "kev": True,
            "answers": [full[0], (EPSS, cves_param(SORTED_CVES), {"raise": "epss down"}), (KEV, None, {"raise": "kev down"})],
        },
    )
    epss_odd = [
        {"data": [{"cve": "CVE-2026-20001", "epss": "0.5"}, "row", {"cve": "CVE-2026-20002"}]},
        {"data": None},
        {"data": "abc"},
        {"data": 5},
        {"data": [{"cve": 7}]},
        [1, 2],
        "text",
        {"data": {"cve": "x"}},
        {"data": [{"cve": "CVE-2026-20001", "epss": "1e400", "percentile": True, "date": 20260114}]},
        {"data": [{"cve": "CVE-2026-20001", "epss": "NaN", "percentile": [1], "date": {"d": 1}}]},
    ]
    for i, answer in enumerate(epss_odd):
        out.append(
            {
                "name": f"epss odd {i}",
                "call": "get",
                "cycle": "2026-Jan",
                "epss": True,
                "kev": False,
                "answers": [full[0], (EPSS, cves_param(SORTED_CVES), {"value": answer})],
            },
        )
    kev_odd = [
        [1],
        {"vulnerabilities": None},
        {"vulnerabilities": {"cveID": "CVE-2026-20001", "notes": None}},
        {"vulnerabilities": "abc"},
        {"vulnerabilities": 3},
        {"vulnerabilities": [{"cveID": 20260001}, {"cveID": "CVE-2026-20001", "dueDate": 5, "notes": {"Text": 1.0}}]},
    ]
    for i, answer in enumerate(kev_odd):
        out.append(
            {
                "name": f"kev odd {i}",
                "call": "get",
                "cycle": "2026-Jan",
                "epss": False,
                "kev": True,
                "answers": [full[0], (KEV, None, {"value": answer})],
            },
        )
    doc_odd = [
        [],
        "doc",
        {"ProductTree": [1]},
        {"ProductTree": {"FullProductName": 3}},
        {"Vulnerability": 5},
        {"Vulnerability": {"CVE": "CVE-2026-1", "Title": 7}},
        {"Vulnerabilities": [{"cve": "CVE-2026-2", "Threats": 4}]},
        {"Vulnerability": [{"cve": "CVE-2026-3", "Remediations": 4}]},
        {"Vulnerability": [{"cve": "CVE-2026-3", "ProductStatuses": 4}]},
        {"Vulnerability": [{"Cve": ["cve", "2026"]}, {"CVE": {"Value": "CVE-2026-4"}, "CVSSScoreSets": 4}]},
        {"Vulnerability": "cves"},
        {"Vulnerability": []},
    ]
    for i, doc in enumerate(doc_odd):
        cves = []
        if isinstance(doc, dict):
            vulns = doc.get("Vulnerability") or doc.get("Vulnerabilities") or []
            if isinstance(vulns, dict):
                vulns = [vulns]
            if isinstance(vulns, list):
                for v in vulns:
                    if isinstance(v, dict):
                        c = (svc.normalize_text(v.get("CVE") or v.get("Cve") or v.get("cve")) or "").upper()
                        if c.startswith("CVE-"):
                            cves.append(c)
        answers = [(f"{MSRC}/2026-Mar", None, {"value": doc})]
        if cves:
            answers.append((EPSS, cves_param(sorted(set(cves))), {"value": {"data": []}}))
        answers.append((KEV, None, {"value": {"vulnerabilities": []}}))
        out.append({"name": f"doc odd {i}", "call": "get", "cycle": "2026-Mar", "epss": True, "kev": True, "answers": answers})
    # Many CVEs: the EPSS query is split in chunks of at most 1900 characters.
    many = {
        "ProductTree": {"FullProductName": [{"ProductID": "1", "Value": "Windows 10"}]},
        "Vulnerability": [
            {"CVE": f"CVE-2026-{n:05d}", "Products": ["1"], "CVSSScoreSets": [{"BaseScore": (n % 100) / 10}]} for n in range(1, 160)
        ],
    }
    many_cves = sorted({f"CVE-2026-{n:05d}" for n in range(1, 160)})
    chunks = svc.chunk_by_max_chars(many_cves)
    answers = [(f"{MSRC}/2026-Apr", None, {"value": many})]
    for k, chunk in enumerate(chunks):
        rows = [{"cve": c, "epss": str((int(c[-5:]) * 37 % 1000) / 1000), "percentile": "0.5", "date": "2026-04-15"} for c in chunk]
        answers.append((EPSS, cves_param(chunk), {"value": {"data": rows}} if k != 1 else {"raise": "chunk down"}))
    answers.append((KEV, None, {"value": {"vulnerabilities": [{"cveID": "CVE-2026-00042"}]}}))
    out.append({"name": "many cves", "call": "summary", "cycle": "2026-Apr", "epss": True, "kev": True, "top_n": 12, "answers": answers})
    return out


class FrozenDateTime(real_dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return real_dt.datetime(2026, 1, 15, 9, 30, 15, 123456, tzinfo=tz)


class FrozenDate(real_dt.date):
    @classmethod
    def today(cls):
        return real_dt.date(2026, 1, 15)


class DtShim:
    date = FrozenDate
    datetime = FrozenDateTime
    timedelta = real_dt.timedelta
    timezone = real_dt.timezone


async def run_scenario(sc):
    answers = list(sc["answers"])
    calls = []

    async def fake_fetch_json(url, params=None, timeout=60):
        calls.append({"url": url, "params": params})
        if not answers:
            raise AssertionError(f"unexpected call {url} {params}")
        want_url, want_params, answer = answers.pop(0)
        assert (want_url, want_params) == (url, params), (want_url, want_params, url, params)
        if "raise" in answer:
            raise RuntimeError(answer["raise"])
        return json.loads(json.dumps(answer["value"]))

    svc.fetch_json = fake_fetch_json
    if sc["call"] == "get":
        resp = await svc.get_patch_tuesday(PatchTuesdayRequest(cycle=sc["cycle"], include_epss=sc["epss"], include_kev=sc["kev"]))
    elif sc["call"] == "summary":
        resp = await svc.get_patch_tuesday_summary(
            PatchTuesdayRequest(cycle=sc["cycle"], include_epss=sc["epss"], include_kev=sc["kev"]),
            top_n=sc["top_n"],
        )
    else:
        resp = await svc.search_cves_in_patch_tuesday(sc["cve_ids"], sc["cycle"], sc["product"])
    used = sc["answers"][: len(calls)]
    return {
        "name": sc["name"],
        "call": sc["call"],
        "cycle": sc["cycle"],
        "epss": sc.get("epss", True),
        "kev": sc.get("kev", True),
        "top_n": sc.get("top_n"),
        "cve_ids": sc.get("cve_ids"),
        "product": sc.get("product"),
        "answers": [
            {
                "url": u,
                "params": p,
                **({"raise": a["raise"]} if "raise" in a else {"value": text(a["value"])}),
            }
            for (u, p, a) in used
        ],
        "calls": calls,
        "response": resp.model_dump_json(),
    }


def main():
    out = {}
    out["normalize_text"] = [{"input": text(v), "output": outcome(svc.normalize_text, v)} for v in ODD_VALUES]
    out["product_family"] = [{"input": text(v), "output": outcome(svc.product_family, v)} for v in PRODUCTS + ODD_VALUES]
    out["safe_float"] = [
        {"input": text(v), "output": text(svc.safe_float(v))}
        for v in ODD_VALUES + ["1_000", " 3.5 ", "1e3", "inf", "-Infinity", "nan", "abc", "٣.٥"]
    ]
    out["extract_cvss"] = [{"input": text(v), "output": outcome(svc.extract_cvss, v)} for v in cvss_inputs()]
    for case in out["extract_cvss"]:
        if "ok" in case["output"]:
            case["output"]["ok"] = text(list(case["output"]["ok"]))
    out["extract_severity"] = [{"input": text(v), "output": outcome(svc.extract_severity, v)} for v in severity_inputs()]
    out["extract_kbs"] = [{"input": text(v), "output": outcome(svc.extract_kbs, v)} for v in kbs_inputs()]
    out["build_product_lookup"] = [{"input": text(v), "output": outcome(svc.build_product_lookup, v)} for v in lookup_docs()]
    out["extract_affected_products"] = [
        {"input": text(c["vuln"]), "lookup": c["lookup"], "output": outcome(svc.extract_affected_products, c["vuln"], c["lookup"])}
        for c in affected_inputs()
    ]
    out["calculate_priority"] = []
    out["slas"] = []
    for sev, cvss, epss, fam, kev in priority_inputs():
        prio, reasons, sla = svc.calculate_priority(sev, cvss, epss, fam, kev)
        if sla not in out["slas"]:
            out["slas"].append(sla)
        out["calculate_priority"].append(
            {
                "severity": sev,
                "cvss": text(cvss),
                "epss": text(epss),
                "family": fam,
                "in_kev": kev,
                "priority": prio,
                "reasons": reasons,
                "sla": out["slas"].index(sla),
            },
        )
    out["chunk_by_max_chars"] = [{"items": items, "max": m, "chunks": svc.chunk_by_max_chars(items, m)} for items, m in chunk_inputs()]
    out["second_tuesday"] = [
        {"year": y, "month": m, "date": svc.second_tuesday(y, m).isoformat()} for y in (2024, 2025, 2026, 2027) for m in range(1, 13)
    ]
    cycles = []
    for d in DATES:

        class _Date(real_dt.date):
            @classmethod
            def today(cls, _d=d):
                return _d

        class _Shim:
            date = _Date
            datetime = real_dt.datetime
            timedelta = real_dt.timedelta
            timezone = real_dt.timezone

        svc.dt = _Shim
        cycles.append({"today": d.isoformat(), "response": asyncio.run(svc.get_available_cycles()).model_dump_json()})
    out["available_cycles"] = cycles
    svc.dt = DtShim
    out["now"] = FrozenDateTime.now(real_dt.timezone.utc).isoformat()
    out["scenarios"] = [asyncio.run(run_scenario(sc)) for sc in scenario_list()]
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
