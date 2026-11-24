"""Sentence-Transformers embedding provider (a stand-in model keeps the tests offline)."""
from __future__ import annotations

import math

import pytest

from backend.config import ConfigurationError, load_settings
from backend.tests.conftest import make_settings
from backend.updater.data_processor import ST_BATCH, EmbeddingClient


class FakeModel:
    """Mimics SentenceTransformer.encode / get_sentence_embedding_dimension."""

    def __init__(self, dims: int = 8):
        self.dims, self.calls = dims, []

    def get_sentence_embedding_dimension(self) -> int:
        return self.dims

    def encode(self, texts, batch_size, normalize_embeddings, convert_to_numpy, show_progress_bar):
        assert normalize_embeddings is True
        self.calls.append(list(texts))
        out = []
        for text in texts:
            raw = [float((len(text) * (i + 1)) % 7 + 1) for i in range(self.dims)]
            norm = math.sqrt(sum(v * v for v in raw))
            out.append([v / norm for v in raw])
        return out


def st_client(model=None) -> EmbeddingClient:
    settings = make_settings(embedding_provider="sentence-transformers",
                             embedding_model="sentence-transformers/all-MiniLM-L6-v2")
    return EmbeddingClient(settings, model=model or FakeModel())


def test_sentence_transformer_vectors_are_normalised_lists():
    vectors = st_client().embed(["SQL injection in a login form", "Cross-site scripting"])
    assert len(vectors) == 2
    for vector in vectors:
        assert isinstance(vector, list) and len(vector) == 8
        assert math.isclose(math.sqrt(sum(v * v for v in vector)), 1.0, rel_tol=1e-4)


def test_empty_texts_get_no_vector_and_are_not_sent_to_the_model():
    model = FakeModel()
    vectors = st_client(model).embed(["", "   ", "buffer overflow"])
    assert vectors[0] is None and vectors[1] is None and vectors[2]
    assert model.calls == [["buffer overflow"]]


def test_large_inputs_are_encoded_in_bounded_chunks():
    model = FakeModel()
    texts = [f"text {i}" for i in range(ST_BATCH * 2 + 5)]
    vectors = st_client(model).embed(texts)
    assert all(vectors) and len(vectors) == len(texts)
    assert [len(call) for call in model.calls] == [ST_BATCH, ST_BATCH, 5]


def test_dimensions_and_signature_come_from_the_model():
    client = st_client(FakeModel(dims=384))
    assert client.dimensions == 384
    assert client.signature == "sentence-transformers:sentence-transformers/all-MiniLM-L6-v2"


def test_sentence_transformers_is_the_default_provider(monkeypatch):
    monkeypatch.setattr("backend.config.load_dotenv", lambda *a, **k: None)  # ignore the real .env
    monkeypatch.setenv("NEO4J_URI", "bolt://x")
    monkeypatch.setenv("NEO4J_USERNAME", "u")
    monkeypatch.setenv("NEO4J_PASSWORD", "p")
    monkeypatch.setenv("EMBEDDING_PROVIDER", " ")
    monkeypatch.delenv("EMBEDDING_MODEL", raising=False)
    settings = load_settings()
    assert settings.embedding_provider == "sentence-transformers"
    assert settings.embedding_model == "BAAI/bge-small-en-v1.5"
    monkeypatch.setenv("EMBEDDING_PROVIDER", "st")
    assert load_settings().embedding_provider == "sentence-transformers"
    assert load_settings().embedding_runtime == "onnx"
    monkeypatch.setenv("EMBEDDING_RUNTIME", "torch")
    assert load_settings().embedding_runtime == "torch"
    monkeypatch.setenv("EMBEDDING_RUNTIME", "gpu")
    with pytest.raises(ConfigurationError):
        load_settings()
    monkeypatch.setenv("EMBEDDING_RUNTIME", "onnx")
    monkeypatch.setenv("EMBEDDING_PROVIDER", "word2vec")
    with pytest.raises(ConfigurationError):
        load_settings()


def test_reembed_resume_only_embeds_what_is_missing(knowledge):
    from backend.manage import reembed
    from backend.tests.fakes import InMemoryGraph

    db = InMemoryGraph()
    for label, nodes in knowledge.db.nodes.items():
        db.nodes[label] = {k: dict(v) for k, v in nodes.items()}
    model = FakeModel(dims=8)
    reembed(db, st_client(model), embed_cves=True)                    # full run
    total = sum(len(call) for call in model.calls)
    assert total > 0
    first = next(iter(db.nodes["CVE"].values()))
    first.pop("embedding"); first.pop("embedding_hash")             # "interrupted" node
    model.calls.clear()
    reembed(db, st_client(model), embed_cves=True, resume=True)
    assert sum(len(call) for call in model.calls) == 1                # only that node
    assert first["embedding"]


def test_real_onnx_model_matches_meaning_not_just_words(monkeypatch):
    """Runs only where the model is already downloaded (no network in tests)."""
    pytest.importorskip("onnxruntime")
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    from backend.updater.st_onnx import OnnxSentenceEncoder
    try:
        model = OnnxSentenceEncoder("sentence-transformers/all-MiniLM-L6-v2", threads=1)
    except Exception:  # noqa: BLE001 - model not in the local cache
        pytest.skip("all-MiniLM-L6-v2 is not downloaded")
    client = st_client(model)
    assert client.dimensions == 384
    query = client.embed_one("how do hackers steal cookies with malicious javascript")
    scores = {name: sum(a * b for a, b in zip(query, client.embed_one(text))) for name, text in {
        "xss": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "sqli": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "overflow": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
    }.items()}
    assert max(scores, key=scores.get) == "xss"
