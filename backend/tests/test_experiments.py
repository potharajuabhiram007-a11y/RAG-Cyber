"""Tuning parameters and the experiment harness metrics (no external services)."""
from __future__ import annotations

import json

import pytest

from backend.experiments import harness
from backend.models import ChatResponse, EvidenceItem, Metrics, RelatedEntity
from backend.rag.retriever import Retriever
from backend.rag.tuning import DEFAULT_TUNING, Tuning


def _response(answer, identifiers=(), related=(), evidence=()):
    return ChatResponse(
        answer=answer, category="CWE", supported=True, result_found=True, identifiers=list(identifiers),
        related_entities=[RelatedEntity(id=i, type="CWE", name=None, relation="x") for i in related],
        evidence=[EvidenceItem(kind="entity", source="s", text=t, identifier=None) for t in evidence],
        metrics=Metrics(), hint="", hint_applicable=False, retrieval_status="found",
        timestamp="2026-01-01T00:00:00+00:00")


# --------------------------------------------------------------------------- #
# Tuning object
# --------------------------------------------------------------------------- #
def test_defaults_keep_the_original_behaviour_values():
    t = DEFAULT_TUNING
    assert (t.name_search_k, t.vector_k, t.vector_min_score, t.cve_pool_k, t.cve_result_k, t.extra_entries) == \
           (8, 5, None, 40, 6, 3)
    assert (t.entity_full_cov, t.fundamentals_coverage, t.rank_mode, t.max_hops) == (0.75, 0.6, "lexicographic", 3)
    assert (t.temperature, t.answer_tokens, t.evidence_chars) == (0.1, 420, 6000)
    assert t.brief_answers and t.verified_facts and t.flag_unverified


def test_replace_validates_names_and_round_trips_through_a_file(tmp_path):
    changed = DEFAULT_TUNING.replace(vector_k=9, rank_mode="weighted")
    assert changed.vector_k == 9 and DEFAULT_TUNING.vector_k == 5          # frozen: the default is untouched
    with pytest.raises(ValueError, match="unknown tuning parameter"):
        DEFAULT_TUNING.replace(not_a_setting=1)
    path = tmp_path / "tuned.json"
    path.write_text(json.dumps({"parameters": changed.to_dict(), "selected": "x"}), encoding="utf-8")
    assert Tuning.from_file(path) == changed


def test_traversal_depth_is_limited_by_max_hops(knowledge):
    shallow = Retriever(knowledge.db, knowledge.embedder, knowledge.settings, DEFAULT_TUNING.replace(max_hops=1))
    deep = Retriever(knowledge.db, knowledge.embedder, knowledge.settings)
    assert {g.label for g in shallow.entity_context("CVE", "CVE-2024-0001").groups} == {"CWE"}
    assert {"CAPEC"} <= {g.label for g in deep.entity_context("CVE", "CVE-2024-0001").groups}


# --------------------------------------------------------------------------- #
# Metrics added by the harness
# --------------------------------------------------------------------------- #
def test_retrieval_metrics_use_the_rank_of_the_expected_entity():
    case = {"expect": "answer", "primary_id": "CWE-89", "required_ids": ["CWE-89", "CAPEC-66"]}
    first = harness.retrieval_scores(case, _response("a", ["CWE-89"], related=["CAPEC-66"]))
    assert first["mrr"] == 1.0 and first["p@1"] == 1.0 and first["r@1"] == 0.5 and first["r@3"] == 1.0
    third = harness.retrieval_scores(case, _response("a", ["CWE-1", "CWE-2", "CWE-89"]))
    assert third["mrr"] == pytest.approx(1 / 3) and third["r@1"] == 0.0 and third["r@3"] == 0.5
    assert harness.retrieval_scores(case, _response("a", ["CWE-9"]))["mrr"] == 0.0
    assert harness.retrieval_scores({"expect": "not_found"}, _response("a")) is None


def test_groundedness_counts_sentences_supported_by_the_evidence():
    evidence = ["SQL injection lets attackers modify database queries through unsanitised user input fields"]
    supported = _response("Attackers modify database queries through unsanitised user input fields.",
                          evidence=evidence)
    invented = _response("Quantum entanglement permits instantaneous teleportation between distant satellites.",
                         evidence=evidence)
    assert harness.groundedness(supported) == 1.0 and harness.groundedness(invented) == 0.0
    assert harness.groundedness(_response("RESULT NOT FOUND")) is None
    assert harness.groundedness(_response("Too short.", evidence=evidence)) is None


def test_stratified_sample_is_fixed_and_keeps_every_group(tmp_path):
    cases = [{"id": f"{c}-{e}-{i}", "category": c, "expect": e, "question": "q"}
             for c in ("CVE", "CWE") for e in ("answer", "not_found") for i in range(10 if e == "answer" else 3)]
    path = tmp_path / "set.json"
    path.write_text(json.dumps({"version": "t", "cases": cases}), encoding="utf-8")
    first, second = harness.load_cases(path, "all", 10), harness.load_cases(path, "all", 10)
    assert [c["id"] for c in first] == [c["id"] for c in second]
    assert {(c["category"], c["expect"]) for c in first} == {(c["category"], c["expect"]) for c in cases}
    assert len(harness.load_cases(path, "all")) == len(cases)
