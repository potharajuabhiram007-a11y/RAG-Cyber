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


def test_unicode_hyphens_in_identifiers_become_plain_hyphens():
    assert normalize_hyphens("CVE‑2026‑44523 and CWE‐326") == "CVE-2026-44523 and CWE-326"
    assert normalize_hyphens("a – dash stays") == "a – dash stays"   # punctuation dashes kept
