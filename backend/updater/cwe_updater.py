"""CWE updater - official MITRE CWE XML release.

Source: https://cwe.mitre.org/data/downloads.html  (cwec_latest.xml.zip)

Parses weaknesses and categories, the ChildOf hierarchy and the CWE -> CAPEC
cross references ("Related_Attack_Patterns"), then stores them in Neo4j.
"""
from __future__ import annotations

import logging
import re

from backend.database import LABEL_CWE, REL_CWE_CAPEC, REL_CWE_CHILD
from backend.updater.data_processor import (
    DataValidationError, SnapshotUpdater, dedupe, local_name, normalize_capec_id, normalize_cwe_id, parse_xml,
    xml_child, xml_children, xml_text,
)

log = logging.getLogger(__name__)

SOURCE = "cwe"


def parse_cwe_catalog(data: bytes) -> tuple[list[dict], dict]:
    """Parse the CWE XML catalogue into CWE node rows."""
    root = parse_xml(data)
    if local_name(root.tag) != "Weakness_Catalog":
        raise DataValidationError("Not a CWE catalogue (root element is not Weakness_Catalog)")
    meta = {"catalog": root.get("Name"), "version": root.get("Version"), "date": root.get("Date")}

    # Category membership (informational property on the weakness).
    membership: dict[str, list[str]] = {}
    category_rows = []
    # CWE <= 4.x publishes Categories/Category, CWE 5.x Groupings/Grouping.
    groupings = (xml_children(xml_child(root, "Categories"), "Category")
                 + xml_children(xml_child(root, "Groupings"), "Grouping"))
    for category in groupings:
        cat_id = normalize_cwe_id(category.get("ID"))
        if not cat_id or category.get("Status") == "Deprecated":
            continue
        members = dedupe(
            normalize_cwe_id(m.get("CWE_ID")) or ""
            for m in xml_children(xml_child(category, "Relationships"), "Has_Member"))
        for member in members:
            membership.setdefault(member, []).append(category.get("Name", ""))
        category_rows.append({
            "id": cat_id, "name": category.get("Name", ""),
            "description": xml_text(xml_child(category, "Summary"), 4000),
            "category": "Category", "status": category.get("Status"),
            "child_of_ids": [], "related_capec_ids": [], "member_ids": members,
            "mitigations": [], "source": "MITRE CWE",
            "source_url": f"https://cwe.mitre.org/data/definitions/{cat_id.split('-')[1]}.html",
            "source_version": meta["version"],
        })

    rows = []
    for weakness in xml_children(xml_child(root, "Weaknesses"), "Weakness"):
        cwe_id = normalize_cwe_id(weakness.get("ID"))
        if not cwe_id or weakness.get("Status") == "Deprecated":
            continue
        parents = [normalize_cwe_id(rel.get("CWE_ID")) or ""
                   for rel in xml_children(xml_child(weakness, "Related_Weaknesses"), "Related_Weakness")
                   if rel.get("Nature") == "ChildOf"]
        capecs = [normalize_capec_id(rel.get("CAPEC_ID")) or ""
                  for rel in xml_children(xml_child(weakness, "Related_Attack_Patterns"),
                                          "Related_Attack_Pattern")]
        mitigations = []
        for mitigation in xml_children(xml_child(weakness, "Potential_Mitigations"), "Mitigation"):
            phases = ", ".join(xml_text(p) for p in xml_children(mitigation, "Phase"))
            text = xml_text(xml_child(mitigation, "Description"), 700)
            if text:
                mitigations.append(f"[{phases}] {text}" if phases else text)
        consequences = []
        for consequence in xml_children(xml_child(weakness, "Common_Consequences"), "Consequence"):
            scopes = ", ".join(xml_text(s) for s in xml_children(consequence, "Scope"))
            impacts = ", ".join(xml_text(i) for i in xml_children(consequence, "Impact"))
            if scopes or impacts:
                consequences.append(f"{scopes}: {impacts}".strip(": "))
        alternate_terms = dedupe(
            xml_text(xml_child(term, "Term"), 120)
            for term in xml_children(xml_child(weakness, "Alternate_Terms"), "Alternate_Term"))
        description = xml_text(xml_child(weakness, "Description"), 4000)
        extended = xml_text(xml_child(weakness, "Extended_Description"), 3000)
        rows.append({
            "id": cwe_id, "name": weakness.get("Name", ""), "description": description,
            "extended_description": extended or None,
            "alternate_terms": alternate_terms[:12],
            "category": weakness.get("Abstraction"),          # Pillar/Class/Base/Variant/Compound
            "structure": weakness.get("Structure"), "status": weakness.get("Status"),
            "child_of_ids": dedupe(parents), "related_capec_ids": dedupe(capecs),
            "member_of_categories": dedupe(membership.get(cwe_id, [])),
            "likelihood": xml_text(xml_child(weakness, "Likelihood_Of_Exploit")) or None,
            "consequences": dedupe(consequences)[:10], "mitigations": mitigations[:12],
            "source": "MITRE CWE",
            "source_url": f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html",
            "source_version": meta["version"],
        })
    weakness_ids = {row["id"] for row in rows}
    rows += [row for row in category_rows if row["id"] not in weakness_ids]
    meta.update({"weaknesses": len(weakness_ids), "categories": len(rows) - len(weakness_ids)})
    return rows, meta


class CWEUpdater(SnapshotUpdater):
    source = SOURCE
    label = LABEL_CWE
    rel_types = (REL_CWE_CHILD, REL_CWE_CAPEC)
    id_pattern = re.compile(r"^CWE-\d+$")

    def urls(self) -> list[str]:
        return [self.settings.cwe_xml_url]

    def parse(self, payloads: list[bytes]) -> tuple[list[dict], dict]:
        return parse_cwe_catalog(payloads[0])

    def after_write(self) -> None:
        # CVEs stored before their CWE existed can be linked now.
        self.db.link_cves_to_cwes()
