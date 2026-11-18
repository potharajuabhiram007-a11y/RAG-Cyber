"""Hosted-model answers: token cap, answers cut off by the cap, Unicode hyphens."""
from __future__ import annotations

import json

import httpx

from backend.rag.generator import LLMClient, normalize_hyphens, trim_incomplete
from backend.tests.conftest import make_settings


def openai_client(content: str, finish_reason: str = "stop", **settings):
    sent = {}

    def handler(request: httpx.Request) -> httpx.Response:
        sent.update(json.loads(request.content))
        return httpx.Response(200, json={"choices": [
            {"message": {"role": "assistant", "content": content}, "finish_reason": finish_reason}]})

    client = LLMClient(make_settings(llm_provider="openai", llm_api_key="test-key",
                                     llm_model="openai/gpt-oss-120b", **settings),
                       http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    return client, sent


def test_hosted_models_get_their_own_generous_token_cap():
    client, sent = openai_client("CWE-79 is cross-site scripting.")
    client.answer_tokens = 420                       # the short cap meant for Ollama
    client.complete("system", "question")
    assert sent["max_tokens"] == 2048                # default LLM_MAX_TOKENS
    client, sent = openai_client("ok.", llm_max_tokens=4096)
    client.complete("system", "question")
    assert sent["max_tokens"] == 4096


def test_answer_cut_by_the_token_cap_is_trimmed_to_complete_text():
    cut = ("T1110 is linked to these CVEs:\n"
           "- CVE-2026-44523 (CWE-326) - weak JWT secret handling\n"
           "- CVE-2026-73778 (CWE-521) - Credential")
    client, _ = openai_client(cut, finish_reason="length")
    answer = client.complete("system", "question")
    assert answer.endswith("weak JWT secret handling")
    assert "Credential" not in answer.splitlines()[-1]


def test_complete_answers_are_not_trimmed():
    text = "First point.\n- a list item without a full stop"
    client, _ = openai_client(text, finish_reason="stop")
    assert client.complete("system", "question") == text


def test_trim_incomplete_keeps_the_last_full_sentence():
    assert trim_incomplete("SQL injection is common. It lets an attacker rea") == "SQL injection is common."
    assert trim_incomplete("Done.") == "Done."
    assert trim_incomplete("no sentence end at all") == "no sentence end at all"   # nothing better to keep


def test_rate_limited_request_is_retried_smaller(knowledge, monkeypatch):
    """Groq's free plan answers 429/413 when prompt + max_tokens is over its token
    budget: the question is retried once with half the evidence and a smaller cap."""
    from backend.rag.generator import Generator
    from backend.rag.retriever import Retriever

    monkeypatch.setattr("backend.rag.generator.time.sleep", lambda s: None)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append((body["max_tokens"], len(body["messages"][1]["content"])))
        if len(calls) == 1:
            return httpx.Response(429, headers={"retry-after": "3"})
        return httpx.Response(200, json={"choices": [{"message": {"content": "CVE-2024-0001 is SQL injection."},
                                                      "finish_reason": "stop"}]})

    settings = make_settings(llm_provider="openai", llm_api_key="k", llm_model="m", llm_evidence_chars=4000)
    llm = LLMClient(settings, http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    result = Retriever(knowledge.db, knowledge.embedder, settings).retrieve("Which CVEs are related to CAPEC-66?")
    answer, mode = Generator(settings, llm=llm).generate(result)
    assert mode == "llm" and answer.startswith("CVE-2024-0001 is SQL injection.")
    assert len(calls) == 2
    assert calls[1][0] < calls[0][0]                   # smaller max_tokens on the retry
    assert calls[1][1] <= calls[0][1]                  # no more evidence than the first try
    assert llm.max_tokens is None                      # override cleared afterwards


def test_unicode_hyphens_in_identifiers_become_plain_hyphens():
    assert normalize_hyphens("CVE‑2026‑44523 and CWE‐326") == "CVE-2026-44523 and CWE-326"
    assert normalize_hyphens("a – dash stays") == "a – dash stays"   # punctuation dashes kept
