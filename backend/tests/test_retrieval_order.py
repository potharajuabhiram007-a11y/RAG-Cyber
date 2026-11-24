"""Graph first, then semantic, then other sources."""
import dataclasses

import httpx
import pytest

from backend.config import RESULT_NOT_FOUND
from backend.rag.external import NVDLookup
from backend.rag.generator import Assistant, Generator, _hold_not_found
from backend.rag.retriever import STATUS_FOUND, RetrievalResult, Retriever
from backend.tests.test_rag import FakeLLM, llm_assistant


@pytest.fixture
def retriever(knowledge):
    return Retriever(knowledge.db, knowledge.embedder, knowledge.settings)


def nvd(settings, records, calls, fail=False):
    def handler(request):
        calls.append(dict(request.url.params))
        if fail:
            return httpx.Response(503)
        wanted = request.url.params.get("cveId")
        found = [r for r in records if wanted in (None, r["id"])]
        return httpx.Response(200, json={"totalResults": len(found), "vulnerabilities": [{"cve": r} for r in found]})

    return NVDLookup(dataclasses.replace(settings, nvd_live_lookup=True),
                     httpx.Client(transport=httpx.MockTransport(handler)))


def record(identifier, text="A flaw in WidgetServer allows remote attackers to run code on the host."):
    return {"id": identifier, "published": "2016-05-05T00:00:00", "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": text}],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-89"}]}]}


@pytest.mark.parametrize("question", ["What is CWE-89?", "What is a firewall?", "How many CWEs are there?",
                                      "which weaknesses lead to SQL injection?"])
def test_graph_answers_compute_no_embedding(retriever, question, monkeypatch):
    monkeypatch.setattr(retriever, "_measure", lambda result: None)
    monkeypatch.setattr(retriever.embedder, "embed_query", lambda text: pytest.fail("vector search used"))
    result = retriever.retrieve(question)
    assert result.found and result.method == "graph" and result.tried == ["graph"]


def test_each_step_runs_only_when_the_one_before_has_nothing(retriever, monkeypatch):
    order, answers = [], {}

    def step(name):
        def run(q):
            order.append(name)
            return answers.get(name) and RetrievalResult(STATUS_FOUND, "CWE", True, q.analysis)
        return run

    for name in ("graph", "semantic", "other"):
        monkeypatch.setattr(retriever, "_step_" + name, step(name))
    for answering, expected in (("graph", ["graph"]), ("semantic", ["graph", "semantic"]),
                                ("other", ["graph", "semantic", "other"]), (None, ["graph", "semantic", "other"])):
        order.clear()
        answers = {answering: True}
        result = retriever.retrieve("how do buffer overflow attacks work")
        assert order == expected == result.tried
        assert result.method == (answering or "none")
    order.clear()
    retriever.retrieve("how do buffer overflow attacks work", after="graph")
    assert order == ["semantic", "other"]


def test_a_cve_outside_the_graph_is_read_from_the_nvd(retriever):
    calls = []
    retriever.nvd = nvd(retriever.settings, [record("CVE-2016-99001")], calls)
    result = retriever.retrieve("Explain CVE-2016-99001")
    assert result.found and result.method == "other" and result.tried == ["graph", "other"]
    assert "live" in result.evidence[0].source and "WidgetServer" in result.evidence[0].text
    assert [e.identifier for e in result.evidence] == ["CVE-2016-99001", "CWE-89"]
    assert calls == [{"cveId": "CVE-2016-99001"}] and result.features["exact_id"] == 1.0
    retriever.retrieve("Explain CVE-2016-99001")
    assert len(calls) == 1                                  # cached
    assert not retriever.retrieve("Explain CVE-2099-99999").found


def test_a_cve_in_the_graph_never_reaches_the_nvd(retriever):
    calls = []
    retriever.nvd = nvd(retriever.settings, [], calls)
    known = next(iter(retriever.db.all_ids("CVE")))
    assert retriever.retrieve(f"Explain {known}").method == "graph" and calls == []


def test_a_failing_nvd_is_not_an_answer(retriever):
    retriever.nvd = nvd(retriever.settings, [], [], fail=True)
    assert not retriever.retrieve("Explain CVE-2016-99001").found


def test_a_product_the_graph_does_not_know_is_searched_at_the_nvd(retriever):
    calls = []
    retriever.nvd = nvd(retriever.settings, [record("CVE-2016-99001")], calls)
    result = retriever.retrieve("vulnerabilities in WidgetServer")
    assert result.found and result.method == "other" and result.tried == ["graph", "semantic", "other"]
    assert calls[0]["keywordSearch"].lower() == "widgetserver"         # not the whole question


def test_the_response_names_the_method(assistant, knowledge):
    assert assistant.ask("What is CWE-89?").retrieval_method == "graph"
    response = llm_assistant(knowledge, FakeLLM(reply="General knowledge: ...")).ask(
        "How does a firewall harden a network perimeter?")
    assert response.generation_mode == "llm_knowledge"
    assert response.retrieval_method == "other" and response.retrieval_steps == ["graph", "semantic", "other"]


def test_evidence_the_model_rejects_hands_over_to_the_next_step(knowledge, monkeypatch):
    class Picky(FakeLLM):
        def complete(self, system, user):
            self.calls.append(user)
            return RESULT_NOT_FOUND if len(self.calls) == 1 else "A grounded answer."

    llm = Picky()
    bot = llm_assistant(knowledge, llm)
    retriever = bot.retriever
    first = retriever.retrieve("What is a firewall?")
    monkeypatch.setattr(retriever, "_step_semantic", lambda q: RetrievalResult(
        STATUS_FOUND, first.category, True, q.analysis, evidence=first.evidence))
    response = bot.ask("What is a firewall?")
    assert response.answer.startswith("A grounded answer") and len(llm.calls) == 2
    assert response.retrieval_method == "semantic" and response.retrieval_steps == ["graph", "semantic"]


def test_a_streamed_not_found_is_held_back():
    sent = []
    send = _hold_not_found(sent.append)
    for piece in ("RESULT", " NOT", " FOUND"):
        send(piece)
    assert sent == []
    send = _hold_not_found(sent.append)
    for piece in ("Res", "ponse: yes", " ok"):
        send(piece)
    assert "".join(sent) == "Response: yes ok"
    assert _hold_not_found(None) is None


@pytest.mark.parametrize("question", ["SQL injectin", "What is SQL injection?"])
def test_a_term_is_followed_to_the_weakness_of_its_name(retriever, question, monkeypatch):
    row = {"id": "term:sqli", "term": "SQL Injection (SQLi)", "definition": "Malicious SQL in an input field.",
           "aliases": ["sqli", "sql injection"]}
    lexicon = retriever._get_lexicon()
    monkeypatch.setitem(lexicon.entries, ("sql", "injection"), [("term", row)])
    result = retriever.retrieve(question)
    assert result.method == "graph" and result.tried == ["graph"]
    assert result.evidence[0].kind == "term"
    assert result.contexts and result.contexts[0].label == "CWE" and result.relationships
    assert result.identifiers == ["CWE-89"]


def test_several_terms_are_not_followed(retriever):
    result = retriever.retrieve("What is the difference between TCP and UDP?")
    assert result.found and not result.contexts
