"""ATT&CK updater - official MITRE ATT&CK STIX 2.1 data.

Source: https://github.com/mitre-attack/attack-stix-data

Only ``attack-pattern`` objects carrying an ATT&CK technique id become ATTACK
nodes; every other STIX object type (groups, software, tactics, data sources,
...) is ignored.  ``relationship`` objects are parsed separately to obtain the
sub-technique hierarchy and the official mitigations, and the CAPEC ids listed
in a technique's external references provide the CAPEC <-> ATT&CK mapping.
"""
from __future__ import annotations

import logging
import re

from backend.database import LABEL_ATTACK, REL_CAPEC_ATTACK, REL_SUBTECHNIQUE_OF
from backend.updater.data_processor import (
    ATTACK_ID_RE, SnapshotUpdater, clean_text, dedupe, load_stix_bundle, normalize_capec_id,
    stix_external_ids,
)

log = logging.getLogger(__name__)

SOURCE = "attack"
_ATTACK_SOURCES = ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack")
_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")


def _inactive(obj: dict) -> bool:
    return bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))


_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\((?:https?://)[^)\s]+\)")
_HTML_TAG_RE = re.compile(r"</?(?:code|br|p|b|i|em|strong|ul|li)\s*/?>", re.I)


def _describe(text) -> str:
    """ATT&CK descriptions use Markdown links, inline HTML and citation markers."""
    value = _CITATION_RE.sub("", str(text or ""))
    value = _HTML_TAG_RE.sub(" ", _MD_LINK_RE.sub(r"\1", value))
    return clean_text(value, 4000)


def parse_attack_bundles(payloads: list[bytes]) -> tuple[list[dict], dict]:
    """Parse one or more ATT&CK STIX bundles (enterprise / mobile / ics)."""
    techniques: dict[str, dict] = {}
    stix_to_attack: dict[str, str] = {}
    mitigations_by_stix: dict[str, dict] = {}
    relationships: list[dict] = []
    skipped = {"revoked_or_deprecated": 0, "other_object_types": 0, "without_technique_id": 0}

    for payload in payloads:
        for obj in load_stix_bundle(payload):
            kind = obj.get("type")
            if kind == "relationship":
                if not _inactive(obj):
                    relationships.append(obj)
            elif kind == "course-of-action":
                ids = stix_external_ids(obj, _ATTACK_SOURCES)
                if ids and not _inactive(obj):
                    mitigations_by_stix[obj["id"]] = {"id": ids[0][0], "name": obj.get("name", "")}
            elif kind == "attack-pattern":
                if _inactive(obj):
                    skipped["revoked_or_deprecated"] += 1
                    continue
                ids = [(i, url) for i, url in stix_external_ids(obj, _ATTACK_SOURCES)
                       if ATTACK_ID_RE.match(i)]
                if not ids:
                    skipped["without_technique_id"] += 1
                    continue
                attack_id, url = ids[0]
                tactics = dedupe(
                    str(phase.get("phase_name"))
                    for phase in obj.get("kill_chain_phases") or []
                    if isinstance(phase, dict) and str(phase.get("kill_chain_name", "")).startswith("mitre"))
                capec_ids = dedupe(normalize_capec_id(i) or "" for i, _ in stix_external_ids(obj, ("capec",)))
                existing = techniques.get(attack_id)
                domains = dedupe((existing or {}).get("domains", []) + list(obj.get("x_mitre_domains") or []))
                stix_to_attack[obj["id"]] = attack_id
                if existing:                       # same technique in a second domain bundle
                    existing["domains"] = domains
                    existing["tactics"] = dedupe(existing["tactics"] + tactics)
                    existing["category"] = ", ".join(existing["tactics"]) or None
                    existing["capec_ids"] = dedupe(existing["capec_ids"] + capec_ids)
                    continue
                techniques[attack_id] = {
                    "id": attack_id, "name": obj.get("name", ""),
                    "description": _describe(obj.get("description")),
                    "type": "sub-technique" if obj.get("x_mitre_is_subtechnique") else "technique",
                    "category": ", ".join(tactics) or None,       # ATT&CK tactic(s)
                    "tactics": tactics,
                    "platforms": [str(p) for p in obj.get("x_mitre_platforms") or []],
                    "domains": domains, "capec_ids": capec_ids, "parent_ids": [],
                    "mitigations": [],
                    "detection": _describe(obj.get("x_mitre_detection"))[:1500] or None,
                    "stix_id": obj["id"], "created": obj.get("created"),
                    "modified": obj.get("modified"),
                    "attack_version": obj.get("x_mitre_version"),
                    "source": "MITRE ATT&CK",
                    "source_url": url or f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/",
                }
            else:
                skipped["other_object_types"] += 1

    for rel in relationships:
        source_ref, target_ref = rel.get("source_ref"), rel.get("target_ref")
        kind = rel.get("relationship_type")
        if kind == "subtechnique-of":
            child, parent = stix_to_attack.get(source_ref), stix_to_attack.get(target_ref)
            if child and parent and parent not in techniques[child]["parent_ids"]:
                techniques[child]["parent_ids"].append(parent)
        elif kind == "mitigates":
            mitigation, technique = mitigations_by_stix.get(source_ref), stix_to_attack.get(target_ref)
            if mitigation and technique:
                detail = _describe(rel.get("description"))[:500]
                entry = f"{mitigation['id']} {mitigation['name']}" + (f": {detail}" if detail else "")
                if entry not in techniques[technique]["mitigations"]:
                    techniques[technique]["mitigations"].append(entry)

    rows = sorted(techniques.values(), key=lambda r: r["id"])
    for row in rows:
        row["mitigations"] = sorted(row["mitigations"])[:12]
    meta = {"techniques": sum(r["type"] == "technique" for r in rows),
            "sub_techniques": sum(r["type"] == "sub-technique" for r in rows),
            "skipped": skipped}
    return rows, meta


class AttackUpdater(SnapshotUpdater):
    source = SOURCE
    label = LABEL_ATTACK
    rel_types = (REL_CAPEC_ATTACK, REL_SUBTECHNIQUE_OF)
    id_pattern = ATTACK_ID_RE

    def urls(self) -> list[str]:
        return list(self.settings.attack_stix_urls)

    def parse(self, payloads: list[bytes]) -> tuple[list[dict], dict]:
        return parse_attack_bundles(payloads)
