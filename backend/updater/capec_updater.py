"""CAPEC updater - official MITRE CAPEC XML release.

Source: https://capec.mitre.org/data/downloads.html  (capec_latest.xml)

Parses attack patterns with severity, likelihood and mitigations, their ChildOf /
CanPrecede / CanFollow relationships, related CWEs and the official taxonomy
mappings to MITRE ATT&CK.
"""
from __future__ import annotations

import logging
import re

from backend.database import (
    LABEL_CAPEC, REL_CAN_PRECEDE, REL_CAPEC_ATTACK, REL_CAPEC_CHILD, REL_CWE_CAPEC,
)
from backend.updater.data_processor import (
    DataValidationError, SnapshotUpdater, dedupe, local_name, normalize_attack_id,
    normalize_capec_id, normalize_cwe_id, parse_xml, xml_child, xml_children, xml_text,
)

log = logging.getLogger(__name__)

SOURCE = "capec"


def parse_capec_catalog(data: bytes) -> tuple[list[dict], dict]:
    """Parse the CAPEC XML catalogue into CAPEC node rows."""
    root = parse_xml(data)
    if local_name(root.tag) != "Attack_Pattern_Catalog":
        raise DataValidationError("Not a CAPEC catalogue (root is not Attack_Pattern_Catalog)")
    meta = {"catalog": root.get("Name"), "version": root.get("Version"), "date": root.get("Date")}

    membership: dict[str, list[str]] = {}
    for category in xml_children(xml_child(root, "Categories"), "Category"):
        if category.get("Status") == "Deprecated":
            continue
        for member in xml_children(xml_child(category, "Relationships"), "Has_Member"):
            member_id = normalize_capec_id(member.get("CAPEC_ID"))
            if member_id:
                membership.setdefault(member_id, []).append(category.get("Name", ""))

    rows, deprecated = [], 0
    for pattern in xml_children(xml_child(root, "Attack_Patterns"), "Attack_Pattern"):
        capec_id = normalize_capec_id(pattern.get("ID"))
        if not capec_id:
            continue
        if pattern.get("Status") in {"Deprecated", "Obsolete"}:
            deprecated += 1
            continue
        related: dict[str, list[str]] = {"ChildOf": [], "CanPrecede": [], "CanFollow": [], "PeerOf": []}
        for rel in xml_children(xml_child(pattern, "Related_Attack_Patterns"), "Related_Attack_Pattern"):
            other = normalize_capec_id(rel.get("CAPEC_ID"))
            if other and rel.get("Nature") in related:
                related[rel.get("Nature")].append(other)
        cwes = [normalize_cwe_id(rel.get("CWE_ID")) or ""
                for rel in xml_children(xml_child(pattern, "Related_Weaknesses"), "Related_Weakness")]
        attack_ids = []
        for mapping in xml_children(xml_child(pattern, "Taxonomy_Mappings"), "Taxonomy_Mapping"):
            if mapping.get("Taxonomy_Name") == "ATTACK":
                attack_id = normalize_attack_id(xml_text(xml_child(mapping, "Entry_ID")))
                if attack_id:
                    attack_ids.append(attack_id)
        mitigations = [text for text in (
            xml_text(m, 700) for m in xml_children(xml_child(pattern, "Mitigations"), "Mitigation"))
            if text]
        prerequisites = [text for text in (
            xml_text(p, 400) for p in xml_children(xml_child(pattern, "Prerequisites"), "Prerequisite"))
            if text]
        number = capec_id.split("-")[1]
        rows.append({
            "id": capec_id, "name": pattern.get("Name", ""),
            "description": xml_text(xml_child(pattern, "Description"), 4000),
            "category": pattern.get("Abstraction"),              # Meta / Standard / Detailed
            "status": pattern.get("Status"),
            "childOf": dedupe(related["ChildOf"]),
            "can_precede_ids": dedupe(related["CanPrecede"]),
            "can_follow_ids": dedupe(related["CanFollow"]),
            "peer_of_ids": dedupe(related["PeerOf"]),
            "likelihood": xml_text(xml_child(pattern, "Likelihood_Of_Attack")) or None,
            "severity": xml_text(xml_child(pattern, "Typical_Severity")) or None,
            "mitigations": mitigations[:12], "prerequisites": prerequisites[:8],
            "related_cwe_ids": dedupe(cwes), "attack_ids": dedupe(attack_ids),
            "member_of_categories": dedupe(membership.get(capec_id, [])),
            "source": "MITRE CAPEC",
            "source_url": f"https://capec.mitre.org/data/definitions/{number}.html",
            "source_version": meta["version"],
        })
    meta.update({"attack_patterns": len(rows), "deprecated_skipped": deprecated})
    return rows, meta


class CAPECUpdater(SnapshotUpdater):
    source = SOURCE
    label = LABEL_CAPEC
    rel_types = (REL_CWE_CAPEC, REL_CAPEC_CHILD, REL_CAN_PRECEDE, REL_CAPEC_ATTACK)
    id_pattern = re.compile(r"^CAPEC-\d+$")

    def urls(self) -> list[str]:
        return [self.settings.capec_xml_url]

    def parse(self, payloads: list[bytes]) -> tuple[list[dict], dict]:
        return parse_capec_catalog(payloads[0])
