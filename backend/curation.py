"""Which records may enter the knowledge graph, and the hard size limits.

Used by the one-off rebuild (``backend/rebuild_graph.py``) and by every later
synchronisation, so a rejected or incomplete record cannot come back with an update.
A rule only looks at the official record itself; nothing is guessed or filled in.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Iterable

# "less than 200,000 nodes / 400,000 relationships at all times"
NODE_LIMIT = 199_000
REL_LIMIT = 399_000
TARGET_CVES = 150_000
MAX_PRODUCTS_PER_CVE = 5
MIN_CVES_PER_PRODUCT = 5
# Famous vulnerabilities people ask for by name: exempt from the age limit, and from the
# CWE requirement (NVD gives EternalBlue, Zerologon, PrintNightmare... no CWE).
PINNED_CVES = frozenset({
    "CVE-2014-0160", "CVE-2014-6271", "CVE-2021-44228", "CVE-2017-0144", "CVE-2019-0708",
    "CVE-2020-1472", "CVE-2021-34527", "CVE-2016-5195", "CVE-2022-0847", "CVE-2022-22965",
    "CVE-2014-3566", "CVE-2020-1350", "CVE-2021-3156", "CVE-2021-26855", "CVE-2020-0796",
    "CVE-2022-30190"})

_WITHDRAWN = re.compile(r"^\W*(rejected|reject\b|do not use)|\*\*\s*(reject|disputed|unsupported)", re.I)
_MODERN_CVSS = {"3.0", "3.1", "4.0"}


def cve_problems(row: dict, cwe_ids: set[str] | None = None) -> list[str]:
    """Every reason this CVE may not be stored ([] = complete and current)."""
    text = row.get("description") or ""
    problems = []
    if row.get("vuln_status") == "Rejected" or _WITHDRAWN.search(text):
        problems.append("rejected, disputed or unsupported")
    if len(text) < 40:
        problems.append("no usable description")
    if row.get("base_score") is None or not row.get("severity") or not row.get("cvss_vector"):
        problems.append("no CVSS score, severity or vector")
    elif str(row.get("cvss_version")) not in _MODERN_CVSS:
        problems.append("obsolete scoring (CVSS v2 only)")
    wanted = row.get("related_cwe_ids") or []
    if row.get("id") not in PINNED_CVES and not (wanted if cwe_ids is None else [i for i in wanted if i in cwe_ids]):
        problems.append("no usable CWE weakness")
    if not row.get("affected_products"):
        problems.append("no affected product")
    if not row.get("reference_urls"):
        problems.append("no reference")
    if not row.get("published"):
        problems.append("no publication date")
    return problems


def record_problems(label: str, row: dict) -> list[str]:
    """The same for the MITRE sources and the reference documents."""
    problems = []
    name = row.get("name") or row.get("term") or row.get("section") or ""
    text = row.get("description") or row.get("definition") or row.get("content") or ""
    if not name.strip() or not text.strip():
        problems.append("no name or description")
    if re.match(r"\W*(deprecated|obsolete)", name, re.I) or row.get("status") in {"Deprecated", "Obsolete"}:
        problems.append("deprecated or obsolete")
    if label == "CWE" and row.get("status") == "Incomplete":
        if row.get("category") == "Category":
            problems.append("incomplete category (a grouping, not a weakness)")
        elif not row.get("mitigations") and not row.get("related_capec_ids"):
            problems.append("incomplete: no mitigation and no attack pattern")
    if label == "CyberDocument" and name.strip() == "Cyber Defense":
        problems.append("title page, no knowledge content")
    return problems


# --------------------------------------------------------------------------- #
# Entities derived from fields of the official records
# --------------------------------------------------------------------------- #
def pretty(token: str) -> str:
    return re.sub(r"[_\\]+", " ", token).strip().title()


def product_row(cpe: str) -> dict | None:
    vendor, _, product = (cpe or "").partition(":")
    if not vendor or not product:
        return None
    v, p = pretty(vendor), pretty(product)
    return {"id": f"product:{cpe}", "name": p if p.lower().startswith(v.lower()) else f"{v} {p}",
            "vendor": v, "vendor_ids": [f"vendor:{vendor}"], "source": "NVD CPE"}


def product_ids(row: dict, known: set[str] | None = None) -> list[str]:
    ids = [f"product:{p}" for p in dict.fromkeys(row.get("affected_products") or [])]
    return [i for i in ids if known is None or i in known][:MAX_PRODUCTS_PER_CVE]


def build_products(cves: Iterable[dict]) -> tuple[list[dict], list[dict]]:
    counts = Counter(p for r in cves for p in set(r.get("affected_products") or []))
    products, vendors = {}, {}
    for cpe, count in counts.items():
        row = product_row(cpe) if count >= MIN_CVES_PER_PRODUCT else None
        if row is None:
            continue
        row["description"] = f"{row['name']}, a product of {row['vendor']} with known vulnerabilities."
        products[row["id"]] = row
        entry = vendors.setdefault(row["vendor_ids"][0], {
            "id": row["vendor_ids"][0], "name": row["vendor"], "source": "NVD CPE", "_p": []})
        entry["_p"].append((count, row["name"]))
    for entry in vendors.values():
        top = [n for _, n in sorted(entry.pop("_p"), reverse=True)[:12]]
        entry["description"] = f"{entry['name']}, vendor of " + ", ".join(top) + "."
    return list(products.values()), list(vendors.values())


_MITIGATION = re.compile(r"^(M\d{4}) ([^:]+?)(?:: (.*))?$", re.S)


def build_attack_entities(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Tactic and Mitigation nodes; also sets tactic_ids / mitigation_ids on ``rows``."""
    tactics: dict[str, list[str]] = {}
    mitigations: dict[str, dict] = {}
    for row in rows:
        row["tactic_ids"] = [f"tactic:{t}" for t in row.get("tactics") or []]
        for tactic in row["tactic_ids"]:
            tactics.setdefault(tactic, []).append(row["name"])
        row["mitigation_ids"] = []
        for text in row.get("mitigations") or []:
            match = _MITIGATION.match(text)
            if not match:
                continue
            row["mitigation_ids"].append(match.group(1))
            entry = mitigations.setdefault(match.group(1), {
                "id": match.group(1), "name": match.group(2).strip(), "_d": [], "_t": [],
                "source": "MITRE ATT&CK",
                "source_url": f"https://attack.mitre.org/mitigations/{match.group(1)}/"})
            entry["_t"].append(row["name"])
            if match.group(3):
                entry["_d"].append(match.group(3).strip())
    for entry in mitigations.values():
        names, details = entry.pop("_t"), entry.pop("_d")
        entry["description"] = (f"{entry['name']} mitigates {len(names)} ATT&CK techniques, such as "
                                + ", ".join(names[:8]) + ". " + " ".join(details[:2]))[:1500]
    tactic_rows = [{"id": i, "name": pretty(i.split(":", 1)[1].replace("-", " ")),
                    "description": f"ATT&CK tactic with {len(names)} techniques, such as "
                                   + ", ".join(names[:15]) + ".",
                    "source": "MITRE ATT&CK"} for i, names in tactics.items()]
    return tactic_rows, list(mitigations.values())
