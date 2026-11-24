"""Curation rules, size limits, spelling correction and the confidence score."""
from __future__ import annotations

import pytest

from backend.curation import (
    NODE_LIMIT, PINNED_CVES, REL_LIMIT, build_attack_entities, build_products, cve_problems,
    product_ids, record_problems,
)
from backend.database import GraphLimitExceeded, Neo4jDatabase
from backend.rag.generator import Assistant, Generator
from backend.rag.retriever import Retriever
from backend.rag.spelling import SpellCorrector, fix_identifiers
from backend.tests.conftest import Harness, make_settings, nvd_item

GOOD = {"id": "CVE-2024-1000", "description": "A buffer overflow in Example Server allows code execution.",
        "base_score": 9.8, "severity": "CRITICAL", "cvss_vector": "CVSS:3.1/AV:N", "cvss_version": "3.1",
        "related_cwe_ids": ["CWE-120"], "affected_products": ["example:server"],
        "reference_urls": ["https://x.test"], "published": "2024-01-01", "vuln_status": "Analyzed"}


def test_a_complete_record_is_accepted():
    assert cve_problems(GOOD, {"CWE-120"}) == []


@pytest.mark.parametrize("change", [
    {"vuln_status": "Rejected"}, {"description": "Rejected reason: not used. " + "x" * 40},
    {"description": "** DISPUTED ** " + "x" * 60}, {"base_score": None}, {"cvss_version": "2.0"},
    {"related_cwe_ids": []}, {"related_cwe_ids": ["CWE-99999"]}, {"affected_products": []},
    {"reference_urls": []}, {"published": None}, {"description": "short"}])
def test_rejected_obsolete_and_incomplete_records_are_refused(change):
    assert cve_problems({**GOOD, **change}, {"CWE-120"})


def test_obsolete_and_incomplete_mitre_records_are_refused():
    assert record_problems("CWE", {"name": "X", "description": "y", "status": "Obsolete"})
    assert record_problems("CWE", {"name": "X", "description": "y", "status": "Incomplete", "category": "Base"})
    assert not record_problems("CWE", {"name": "X", "description": "y", "status": "Incomplete",
                                       "category": "Base", "mitigations": ["do this"]})
    assert record_problems("CAPEC", {"name": "X", "description": ""})


def test_products_vendors_tactics_and_mitigations_are_derived():
    rows = [{**GOOD, "id": f"CVE-2024-{1000 + i}"} for i in range(5)]
    products, vendors = build_products(rows)
    assert [p["name"] for p in products] == ["Example Server"] and vendors[0]["id"] == "vendor:example"
    assert product_ids(rows[0], {"product:example:server"}) == ["product:example:server"]
    attack = [{"name": "Phishing", "tactics": ["initial-access"], "mitigations": ["M1017 User Training: teach."]}]
    tactics, mitigations = build_attack_entities(attack)
    assert tactics[0]["name"] == "Initial Access" and mitigations[0]["id"] == "M1017"
    assert attack[0]["mitigation_ids"] == ["M1017"]


class _Sized(Neo4jDatabase):
    def __init__(self, nodes, rels):
        super().__init__(make_settings())
        self.now, self.wrote, self.pruned = [nodes, rels], False, 0

    def size(self):
        return tuple(self.now)

    def get_property_map(self, *_):
        return {}

    def _write(self, work):
        self.wrote = True
        return 0

    def cve_count(self):
        return 150_000

    def prune_cves(self, keep, batch_size=5000):
        removed = 150_000 - keep
        self.now = [self.now[0] - removed, self.now[1] - 2 * removed]
        return removed


def test_limits_are_below_the_required_maximum_and_enforced_before_writing():
    assert NODE_LIMIT < 200_000 and REL_LIMIT < 400_000
    db = _Sized(NODE_LIMIT - 1, 0)
    with pytest.raises(GraphLimitExceeded):
        db.upsert_nodes("CWE", [{"id": "a"}, {"id": "b"}])
    assert not db.wrote
    db = _Sized(0, REL_LIMIT - 1)
    with pytest.raises(GraphLimitExceeded):
        db.upsert_cves([{"id": "CVE-2024-1", "related_cwe_ids": ["CWE-1"], "product_ids": ["product:a:b"]}])
    assert not db.wrote


def test_make_room_removes_old_cves_until_the_new_data_fits():
    db = _Sized(NODE_LIMIT - 10, REL_LIMIT - 10)
    assert db.make_room(500, 2000) > 0
    assert db.now[0] + 500 <= NODE_LIMIT and db.now[1] + 2000 <= REL_LIMIT


def test_updates_do_not_store_incomplete_records_and_remove_newly_rejected_ones():
    h = Harness(make_settings(curate=True, max_cves=100))
    for updater in (h.cwe, h.capec, h.attack):
        assert updater.sync().ok
    item = nvd_item("CVE-2024-5000", "SQL injection in ExampleApp allows reading the whole database.",
                    cwes=["CWE-89"], score=9.8)
    item["cve"]["configurations"] = [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:example:app:1.0:*:*:*:*:*:*:*"}]}]}]
    h.sources.nvd_items = [item, nvd_item("CVE-2024-5001", "An issue without a score or product.", cwes=["CWE-89"])]
    assert h.cve.sync().ok
    assert set(h.db.nodes["CVE"]) == {"CVE-2024-5000"}
    item["cve"]["vulnStatus"] = "Rejected"
    h.clock_now = h.clock_now.replace(day=20)
    h.sources.nvd_items = [item]
    assert h.cve.sync().ok
    assert not h.db.nodes["CVE"]


# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("typed, expected", [
    ("CEV-2021-44228", "CVE-2021-44228"), ("CVE-2O21-44228", "CVE-2021-44228"),
    ("what is cew 89", "what is CWE-89"), ("capce-66", "CAPEC-66")])
def test_misspelled_identifiers_are_repaired(typed, expected):
    assert fix_identifiers(typed)[0] == expected


@pytest.mark.parametrize("text", ["CVE-2021-44228", "CWE 89", "cve-2021-34527", "capec66", "escape 5 rooms"])
def test_correct_identifiers_are_left_alone(text):
    assert fix_identifiers(text) == (text, [])


def test_words_are_corrected_and_known_words_are_not():
    spell = SpellCorrector([("SQL injection buffer overflow phishing", 20)], ["firewall"],
                           ["Ewon"], ["log4shell"])
    assert spell.correct("wat is sql injecton")[0] == "what is sql injection"
    assert spell.correct("buffr overfow")[0] == "buffer overflow"
    assert spell.correct("log4shel")[0] == "log4shell"
    for text in ("how do I bake a chocolate cake", "who is Elon", "vulnerabilities in FooBarX 2.1",
                 "open C:/tmp/injecton.txt"):
        assert spell.correct(text) == (text, [])


def test_misspelled_question_gets_the_same_answer_a_note_and_a_confidence(knowledge):
    assistant = Assistant(Retriever(knowledge.db, knowledge.embedder, knowledge.settings),
                          Generator(knowledge.settings))
    clean, typed = assistant.ask("What is a firewall?"), assistant.ask("Waht is a firewal?")
    assert typed.result_found and typed.category == clean.category
    assert ["firewal", "firewall"] in typed.corrections and not clean.corrections
    assert 0 < typed.confidence.score <= clean.confidence.score <= 0.99
    assert assistant.ask("hello").confidence is None
    assert assistant.ask("What is CVE-2099-99999?").confidence is None


def test_pinned_records_only_skip_the_weakness_rule():
    row = {**GOOD, "id": next(iter(PINNED_CVES)), "related_cwe_ids": []}
    assert cve_problems(row) == [] and cve_problems({**row, "vuln_status": "Rejected"})
