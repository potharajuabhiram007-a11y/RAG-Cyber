"""REST API and evaluation-module tests (FastAPI TestClient, no external services)."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from backend.config import ConfigurationError, load_settings
from backend.evaluation import (
    EvaluationStore, compute_metrics, judge_case, load_dataset, run_evaluation,
)
from backend.main import AppState, create_app
from backend.models import ChatResponse, Metrics
from backend.rag.generator import Assistant, Generator
from backend.rag.retriever import Retriever
from backend.updater.scheduler import SyncManager, expand_sources


@pytest.fixture
def client(knowledge, tmp_path):
    settings = knowledge.settings
    evaluation = EvaluationStore(tmp_path / "evaluation_results.json")
    assistant = Assistant(Retriever(knowledge.db, knowledge.embedder, settings),
                          Generator(settings), evaluation)
    updaters = {"cwe": knowledge.cwe, "capec": knowledge.capec, "attack": knowledge.attack,
                "nvd": knowledge.cve}
    manager = SyncManager(knowledge.db, knowledge.embedder, settings, updaters=updaters)
    state = AppState(settings, db=knowledge.db, embedder=knowledge.embedder, sync_manager=manager,
                     assistant=assistant, evaluation=evaluation)
    with TestClient(create_app(state, start_background=False)) as test_client:
        test_client.manager = manager
        yield test_client


def test_chat_endpoint_structured_response(client):
    body = client.post("/api/chat", json={"message": "Explain CVE-2024-0001"}).json()
    assert body["category"] == "CVE" and body["supported"] and body["result_found"]
    assert body["hint_applicable"] and body["hint"]
    assert body["metrics"] == {"precision": None, "f1_score": None, "accuracy": None, "recall": None,
                               "scope": None, "category": None, "sample_size": None,
                               "evaluated_at": None, "note": None}
    assert {"answer", "sources", "related_entities", "relationships", "evidence"} <= set(body)
    assert all("embedding" not in str(item) for item in body["evidence"])


def test_chat_endpoint_unsupported_and_greeting(client):
    unsupported = client.post("/api/chat", json={"message": "What is the capital of France?"}).json()
    assert unsupported["answer"] == "RESULT NOT FOUND" and unsupported["supported"] is False
    assert unsupported["hint"] == "THERE IS NO SOLUTION FOR THIS QUESTION"
    greeting = client.post("/api/chat", json={"message": "Hello"}).json()
    assert greeting["category"] == "GENERAL" and greeting["sources"] == []


@pytest.mark.parametrize("payload", [{}, {"message": ""}, {"message": "   "}, {"message": "x" * 2001},
                                     {"message": "hi", "extra": 1}, {"message": 5}])
def test_chat_request_validation(client, payload):
    assert client.post("/api/chat", json=payload).status_code == 422


def test_request_size_limit(client):
    response = client.post("/api/chat", content=b"x" * 20000, headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_status_endpoints_expose_no_secrets(client):
    health = client.get("/api/status").json()
    assert health["status"] == "ok" and health["database_connected"] is True
    assert "test-only" not in str(health) and "test-admin-key" not in str(health)
    database = client.get("/api/database/status").json()
    assert database["nodes"]["CWE"] == 4 and database["relationships"]["CWE_CAPEC"] == 2
    sync = client.get("/api/sync/status").json()
    by_source = {s["source"]: s for s in sync["sources"]}
    assert set(by_source) == {"foundation", "cwe", "capec", "attack", "nvd"}
    assert by_source["cwe"]["status"] == "success" and by_source["cwe"]["last_success_at"]
    assert by_source["nvd"]["checkpoint"]


def test_manual_sync_requires_admin_key(client):
    assert client.post("/api/admin/sync", json={"sources": ["cwe"]}).status_code == 401
    wrong = client.post("/api/admin/sync", json={"sources": ["cwe"]}, headers={"X-Admin-Key": "nope"})
    assert wrong.status_code == 401
    invalid = client.post("/api/admin/sync", json={"sources": ["bogus"]},
                          headers={"X-Admin-Key": "test-admin-key"})
    assert invalid.status_code == 422
    accepted = client.post("/api/admin/sync", json={"sources": ["cwe"]},
                           headers={"X-Admin-Key": "test-admin-key"})
    assert accepted.status_code == 202 and accepted.json()["sources"] == ["cwe"]
    for thread in client.manager._threads:
        thread.join(timeout=30)
    assert client.get("/api/sync/status").json()["running"] == []


def test_graph_explorer_endpoints(client):
    entity = client.get("/api/graph/entity/CVE-2024-0001").json()
    assert entity["id"] == "CVE-2024-0001" and entity["label"] == "CVE"
    assert "embedding" not in entity["properties"]
    assert all(group["total"] >= len(group["nodes"]) > 0 for group in entity["groups"])
    assert any(group["rel"] == "CVE_CWE" and group["outgoing"] for group in entity["groups"])
    lower = client.get("/api/graph/entity/cve-2024-0001")
    assert lower.status_code == 200 and lower.json()["id"] == "CVE-2024-0001"

    assert client.get("/api/graph/entity/CVE-1999-9999").status_code == 404      # well formed, not stored
    assert client.get("/api/graph/entity/not-an-id").status_code == 404          # not an identifier
    assert client.get("/api/graph/entity/CWE-79?per_group=500").status_code == 422

    found = client.get("/api/graph/search", params={"q": "CVE-2024"}).json()["results"]
    assert found and all(item["id"].startswith("CVE-2024") for item in found)
    assert client.get("/api/graph/search", params={"q": ""}).json() == {"results": []}
    assert client.get("/api/graph/search", params={"q": "x" * 200}).status_code == 422
    overview = client.get("/api/graph/overview").json()["results"]
    assert all({"id", "label", "name"} <= set(item) for item in overview)


def test_metrics_endpoint_without_benchmark(client):
    body = client.get("/api/metrics").json()
    assert body["available"] is False and body["overall"] is None


def test_frontend_is_served(client):
    page = client.get("/")
    assert page.status_code == 200 and "CyberIntelliX" in page.text
    assert all(f'id="view-{name}"' in page.text for name in ("assistant", "features", "history", "graph", "data"))


def test_sync_manager_prevents_overlapping_jobs(knowledge):
    manager = SyncManager(knowledge.db, knowledge.embedder, knowledge.settings,
                          updaters={"cwe": knowledge.cwe, "capec": knowledge.capec,
                                    "attack": knowledge.attack, "nvd": knowledge.cve})
    manager._locks["mitre"].acquire()
    try:
        assert manager.run_source("capec").status == "skipped"
    finally:
        manager._locks["mitre"].release()
    assert manager.run_source("capec").ok
    assert expand_sources(["all"]) == ["foundation", "cwe", "capec", "attack", "nvd"]
    assert expand_sources(["nvd", "mitre"]) == ["cwe", "capec", "attack", "nvd"]


def test_missing_configuration_gives_a_clear_error(monkeypatch):
    for name in ("NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD"):
        monkeypatch.setenv(name, "")
    with pytest.raises(ConfigurationError, match="NEO4J_URI"):
        load_settings()
    monkeypatch.setenv("NEO4J_URI", "bolt://x")
    monkeypatch.setenv("NEO4J_USERNAME", "u")
    monkeypatch.setenv("NEO4J_PASSWORD", "p")
    monkeypatch.setenv("LLM_PROVIDER", "magic")
    with pytest.raises(ConfigurationError, match="LLM_PROVIDER"):
        load_settings()


# --------------------------------------------------------------------------- #
# Evaluation module
# --------------------------------------------------------------------------- #
def _response(answer, identifiers=()):
    return ChatResponse(answer=answer, category="CWE", supported=True, result_found=True,
                        identifiers=list(identifiers), metrics=Metrics(), hint="", hint_applicable=False,
                        retrieval_status="found", timestamp="2026-01-01T00:00:00+00:00")


def test_judging_follows_the_documented_definition():
    answerable = {"id": "a", "category": "CWE", "question": "q", "expect": "answer",
                  "required_ids": ["CWE-89"], "required_facts": [["SQL Injection", "SQLi"]]}
    negative = {"id": "n", "category": "CWE", "question": "q", "expect": "not_found"}
    assert judge_case(answerable, _response("About sqli ...", ["CWE-89"]))["outcome"] == "TP"
    assert judge_case(answerable, _response("About XSS", ["CWE-89"]))["outcome"] == "FP"      # wrong fact
    assert judge_case(answerable, _response("SQL Injection", []))["outcome"] == "FP"         # id missing
    assert judge_case(answerable, _response("RESULT NOT FOUND"))["outcome"] == "FN"
    assert judge_case(negative, _response("RESULT NOT FOUND"))["outcome"] == "TN"
    assert judge_case(negative, _response("Made-up answer"))["outcome"] == "FP"


def test_metric_formulas():
    judgements = ([{"outcome": "TP", "required_ids_total": 1, "required_ids_retrieved": 1}] * 6
                  + [{"outcome": "FP", "required_ids_total": 1, "required_ids_retrieved": 0}] * 2
                  + [{"outcome": "FN", "required_ids_total": 0, "required_ids_retrieved": 0}] * 1
                  + [{"outcome": "TN", "required_ids_total": 0, "required_ids_retrieved": 0}] * 3)
    metrics = compute_metrics(judgements)
    assert (metrics["tp"], metrics["fp"], metrics["fn"], metrics["tn"]) == (6, 2, 1, 3)
    assert metrics["precision"] == 0.75 and metrics["recall"] == round(6 / 7, 4)
    assert metrics["f1_score"] == round(2 * 0.75 * (6 / 7) / (0.75 + 6 / 7), 4)
    assert metrics["accuracy"] == 0.75 and metrics["entity_recall"] == 0.75
    undefined = compute_metrics([{"outcome": "TN", "required_ids_total": 0, "required_ids_retrieved": 0}])
    assert undefined["precision"] is None and undefined["recall"] is None and undefined["f1_score"] is None


def test_shipped_dataset_is_valid_and_balanced():
    cases = load_dataset()["cases"]
    for category in ("CVE", "CWE", "CAPEC", "ATTACK"):
        subset = [c for c in cases if c["category"] == category]
        assert sum(c["expect"] == "answer" for c in subset) >= 5
        assert sum(c["expect"] == "not_found" for c in subset) >= 3


def test_run_evaluation_stores_results_for_the_api(assistant, tmp_path):
    dataset = {"version": "test", "cases": [
        {"id": "1", "category": "CWE", "question": "What is CWE-89?", "expect": "answer",
         "required_ids": ["CWE-89", "CAPEC-66"], "required_facts": [["SQL Command"]]},
        {"id": "2", "category": "CWE", "question": "What is CWE-943?", "expect": "answer",
         "required_facts": [["this text is not in the graph"]]},
        {"id": "3", "category": "CWE", "question": "What is CWE-55555?", "expect": "not_found"},
        {"id": "4", "category": "CAPEC", "question": "Explain CAPEC-98", "expect": "answer",
         "required_ids": ["T1566"], "required_facts": [["Phishing"]]},
    ]}
    path = tmp_path / "results.json"
    results = run_evaluation(assistant, dataset, results_path=path)
    cwe = results["by_category"]["CWE"]
    assert (cwe["tp"], cwe["fp"], cwe["fn"], cwe["tn"]) == (1, 1, 0, 1)
    assert cwe["precision"] == 0.5 and cwe["recall"] == 1.0 and cwe["accuracy"] == round(2 / 3, 4)
    store = EvaluationStore(path)
    served = store.metrics_for("CWE")
    assert served.precision == 0.5 and served.scope == "offline_benchmark" and served.sample_size == 3
    assert store.metrics_for("FUNDAMENTALS").precision is None
    assert store.summary()["available"] is True


def test_judging_requires_the_expected_primary_entity_and_no_unverified_note():
    case = {"id": "p", "category": "CWE", "question": "Which weakness is SQL injection?",
            "expect": "answer", "primary_id": "CWE-89", "required_ids": ["CWE-89"]}
    assert judge_case(case, _response("answer", ["CWE-89", "CWE-564"]))["outcome"] == "TP"
    # the right entity is only listed among other matches: the answer is about another one
    wrong = judge_case(case, _response("answer", ["CWE-564", "CWE-89"]))
    assert wrong["outcome"] == "FP" and wrong["wrong_primary"] and wrong["primary_got"] == "CWE-564"
    flagged = judge_case(case, _response("answer\n\n**Not verified:** CWE-1 ...", ["CWE-89"]))
    assert flagged["outcome"] == "FP" and flagged["unverified_identifiers"]


def test_benchmark_from_another_llm_or_dataset_is_not_served(assistant, tmp_path):
    dataset = {"version": "t", "cases": [
        {"id": "1", "category": "CWE", "question": "What is CWE-89?", "expect": "answer",
         "required_ids": ["CWE-89"], "difficulty": "direct"},
        {"id": "2", "category": "CWE", "question": "What is CWE-55555?", "expect": "not_found",
         "difficulty": "described"}]}
    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(json.dumps(dataset), encoding="utf-8")
    path = tmp_path / "results.json"
    results = run_evaluation(assistant, dataset, results_path=path,
                             environment={"llm_provider": "none", "llm_model": None})
    assert set(results["by_difficulty"]) == {"direct", "described"}
    same = EvaluationStore(path, current={"llm_provider": "none", "llm_model": None},
                           dataset_path=dataset_path)
    assert same.stale_reason() is None and same.metrics_for("CWE").accuracy == 1.0
    other = EvaluationStore(path, current={"llm_provider": "ollama", "llm_model": "llama3.2"})
    assert "LLM provider" in other.stale_reason() and other.metrics_for("CWE").accuracy is None
    assert other.summary()["available"] is False
    dataset["cases"].append({"id": "3", "category": "CWE", "question": "Explain CWE-79",
                             "expect": "answer"})
    dataset_path.write_text(json.dumps(dataset), encoding="utf-8")
    assert "dataset has changed" in same.stale_reason()


def test_chat_stream_ends_with_the_complete_response(client):
    response = client.post("/api/chat/stream", json={"message": "What is CWE-89?"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    events = [json.loads(line) for line in response.text.splitlines() if line.strip()]
    assert events[-1]["type"] == "final" and [e["type"] for e in events].count("final") == 1
    final = events[-1]["response"]
    assert final["category"] == "CWE" and final["identifiers"] == ["CWE-89"] and final["result_found"]
    assert final == client.post("/api/chat", json={"message": "What is CWE-89?"}).json() | {
        "timestamp": final["timestamp"]}
