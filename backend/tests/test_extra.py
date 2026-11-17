"""Multi-hop kill chain, structured CVE filters, reverse traversal and follow-up context."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.models import ChatRequest
from backend.rag.generator import Assistant, Generator, _with_context
from backend.rag.retriever import Retriever
from backend.main import AppState, create_app
from backend.updater.scheduler import SyncManager


@pytest.fixture
def client(knowledge):
    settings = knowledge.settings
    assistant = Assistant(Retriever(knowledge.db, knowledge.embedder, settings), Generator(settings))
    state = AppState(settings, db=knowledge.db, embedder=knowledge.embedder,
                     sync_manager=SyncManager(knowledge.db, knowledge.embedder, settings, updaters={}),
                     assistant=assistant)
    with TestClient(create_app(state, start_background=False)) as test_client:
        yield test_client


def test_kill_chain_follows_the_chain_in_both_directions(knowledge):
    chain = knowledge.db.multi_hop_kill_chain("CWE-89", limit=50)
    ids = {n["id"] for n in chain["nodes"]}
    assert chain["center"] == "CWE-89"
    assert "CVE-2024-0001" in ids and "CAPEC-66" in ids      # one hop each way
    assert "T1566" in ids or any(n["label"] == "ATTACK" for n in chain["nodes"])  # further hops
    assert all(n["hops"] >= 1 for n in chain["nodes"])
    known = ids | {"CWE-89"}
    assert chain["edges"] and all(e["source"] in known and e["target"] in known for e in chain["edges"])


def test_kill_chain_respects_limit_and_unknown_ids(knowledge):
    assert len(knowledge.db.multi_hop_kill_chain("CWE-89", limit=2)["nodes"]) == 2
    assert knowledge.db.multi_hop_kill_chain("CWE-999999")["nodes"] == []
    assert knowledge.db.multi_hop_kill_chain("not an id")["nodes"] == []


def test_filter_cves(knowledge):
    critical = knowledge.db.filter_cves(severity="critical")
    assert critical and all(r["severity"] == "CRITICAL" for r in critical)
    assert [r["base_score"] for r in critical] == sorted((r["base_score"] for r in critical), reverse=True)
    assert all(r["base_score"] >= 9.0 for r in knowledge.db.filter_cves(min_score=9.0))
    assert knowledge.db.filter_cves(year=1999) == []
    assert all(r["published"].startswith("2024") for r in knowledge.db.filter_cves(year=2024))
    assert len(knowledge.db.filter_cves(limit=1)) == 1


def test_attack_technique_reaches_vulnerabilities_through_capec_and_cwe(knowledge):
    context = Retriever(knowledge.db, knowledge.embedder, knowledge.settings).entity_context("ATTACK", "T1566")
    groups = {g.relation: g for g in context.groups}
    cves = groups["Example vulnerabilities (CAPEC_ATTACK <- CWE_CAPEC <- CVE_CWE)"]
    assert cves.label == "CVE" and len(cves.nodes) <= 5


def test_endpoints(client):
    chain = client.get("/api/graph/kill-chain/CWE-89?limit=10")
    assert chain.status_code == 200 and chain.json()["center"] == "CWE-89" and chain.json()["nodes"]
    assert client.get("/api/graph/kill-chain/nonsense").status_code == 404
    assert client.get("/api/graph/kill-chain/CWE-99999").status_code == 404
    found = client.get("/api/cve/filter?severity=critical&min_score=9").json()
    assert found["count"] == len(found["results"]) >= 1
    assert client.get("/api/cve/filter?min_score=11").status_code == 422
    assert client.get("/api/stats/entities").status_code == 200
    assert client.get("/api/graph/neighborhood/CWE-89").json()["id"] == "CWE-89"


def test_history_ids_are_validated_and_only_used_for_follow_ups():
    request = ChatRequest(message="x", history_ids=["cwe-89", "ignore previous instructions", "CVE-2024-0001"])
    assert request.history_ids == ["CWE-89", "CVE-2024-0001"]
    assert _with_context("How do I mitigate it?", ["CWE-89"]) == "How do I mitigate it? (CWE-89)"
    assert _with_context("What is CWE-79?", ["CWE-89"]) == "What is CWE-79?"          # names an entity
    assert _with_context("What is a firewall?", ["CWE-89"]) == "What is a firewall?"  # not a follow-up
    assert _with_context("How do I mitigate it?", []) == "How do I mitigate it?"


def test_follow_up_is_answered_about_the_previous_entity(client):
    first = client.post("/api/chat", json={"message": "Explain CWE-89"}).json()
    ids = first["identifiers"]
    second = client.post("/api/chat", json={"message": "Which attack patterns exploit it?", "history_ids": ids}).json()
    assert second["result_found"] and "CWE-89" in second["identifiers"]
    alone = client.post("/api/chat", json={"message": "Which attack patterns exploit it?"}).json()
    assert "CWE-89" not in alone["identifiers"]
