"""Run the assistant over a labelled dataset and measure it.

Nothing here changes how a case is judged: classification and the precision / recall /
F1 / accuracy formulas are the ones in ``backend/evaluation.py`` (TP / FP / FN / TN,
documented there).  This module adds retrieval-quality figures, a groundedness figure
and latency, all computed from the assistant's actual responses.

Retrieval metrics (answer cases that name one expected entity, ``primary_id``).  The
ranked list is the response's identifiers in order, then its related entities:
    Precision@K  relevant entities among the first K / K
    Recall@K     share of the case's ``required_ids`` found in the first K
    MRR          1 / rank of the expected entity (0 when it is not retrieved)

Groundedness (answered cases): share of the answer's sentences whose content words
are found in the retrieved evidence or the question (a sentence with fewer than four
content words is not scored).  A low value means the answer says things the evidence
does not contain.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from backend.config import DATA_DIR, RESULT_NOT_FOUND
from backend.evaluation import compute_metrics, judge_case, load_dataset
from backend.rag.generator import Assistant, Generator
from backend.rag.retriever import Retriever, content_tokens, stem
from backend.rag.tuning import DEFAULT_TUNING, Tuning
from backend.updater.data_processor import phrase_tokens

HELDOUT_PATH = DATA_DIR / "heldout_dataset.json"      # final report only
TUNING_PATH = DATA_DIR / "tuning_dataset.json"        # choosing settings
EXPERIMENT_DIR = DATA_DIR / "experiments"
KS = (1, 3, 5)
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+|\n+")
_CONTEXT_WORDS = frozenset("knowledge graph source sources evidence record records retrieved verified".split())


def ranked_ids(response) -> list[str]:
    ordered: list[str] = []
    for identifier in list(response.identifiers) + [e.id for e in response.related_entities]:
        if identifier not in ordered:
            ordered.append(identifier)
    return ordered


def retrieval_scores(case: dict, response) -> dict | None:
    primary, required = case.get("primary_id"), list(case.get("required_ids") or [])
    if case["expect"] != "answer" or not primary:
        return None
    ranking = ranked_ids(response)
    out = {"mrr": 1.0 / (ranking.index(primary) + 1) if primary in ranking else 0.0}
    for k in KS:
        top = set(ranking[:k])
        out[f"p@{k}"] = len({i for i in required if i in top}) / k
        out[f"r@{k}"] = len([i for i in required if i in top]) / len(required)
    return out


def groundedness(response) -> float | None:
    """Mean sentence support of an answered case; None when nothing could be scored."""
    answer = response.answer.strip()
    if answer == RESULT_NOT_FOUND:
        return None
    pool = " ".join([e.text for e in response.evidence] + [e.title or "" for e in response.evidence]
                    + [n.name or "" for n in response.related_entities])
    available = {stem(t) for t in phrase_tokens(pool)}
    scores = []
    for sentence in _SENTENCE_RE.split(answer):
        words = [stem(t) for t in content_tokens(phrase_tokens(sentence)) if len(t) > 3]
        words = [w for w in words if w not in _CONTEXT_WORDS]
        if len(words) < 4:
            continue
        scores.append(1.0 if sum(w in available for w in words) / len(words) >= 0.6 else 0.0)
    return statistics.fmean(scores) if scores else None


def _mean(values):
    values = [v for v in values if v is not None]
    return round(statistics.fmean(values), 4) if values else None


def load_cases(path: Path, split: str | None, limit: int | None = None) -> list[dict]:
    cases = load_dataset(path)["cases"]
    cases = [c for c in cases if split in (None, "all") or c.get("split", "dev") == split]
    if limit and limit < len(cases):
        # fixed stratified sample (same cases for every configuration): proportional to the
        # size of each (category, expected outcome) group, at least one case per group
        import random
        rng, groups = random.Random(7), {}
        for case in cases:
            groups.setdefault((case["category"], case["expect"]), []).append(case)
        chosen = []
        for key in sorted(groups):
            group = groups[key]
            rng.shuffle(group)
            chosen += group[:max(1, round(limit * len(group) / len(cases)))]
        cases = sorted(chosen, key=lambda c: c["id"])
    return cases


def build_assistant(db, embedder, settings, tuning: Tuning, use_llm: bool) -> Assistant:
    settings = settings if use_llm else dataclasses.replace(settings, llm_provider="none", llm_model="")
    return Assistant(Retriever(db, embedder, settings, tuning), Generator(settings, tuning=tuning))


def evaluate(assistant: Assistant, cases: list[dict], progress=None) -> dict:
    judgements, retrieval, grounded, latencies = [], [], [], []
    for index, case in enumerate(cases):
        started = time.perf_counter()
        response = assistant.ask(case["question"])
        latencies.append(time.perf_counter() - started)
        judgement = judge_case(case, response)
        judgement["seconds"] = round(latencies[-1], 3)
        judgement["split"] = case.get("split")
        judgements.append(judgement)
        retrieval.append(retrieval_scores(case, response))
        grounded.append(groundedness(response))
        if progress:
            progress(index + 1, len(cases))
    scored = [r for r in retrieval if r]
    return {
        "overall": compute_metrics(judgements),
        "by_category": {c: compute_metrics([j for j in judgements if j["category"] == c])
                        for c in sorted({j["category"] for j in judgements})},
        "by_difficulty": {d: compute_metrics([j for j in judgements if j["difficulty"] == d])
                          for d in sorted({j["difficulty"] for j in judgements})},
        "retrieval": {"cases": len(scored), **{key: _mean([r[key] for r in scored])
                                               for key in ("mrr", *(f"p@{k}" for k in KS), *(f"r@{k}" for k in KS))}},
        "groundedness": {"answers_scored": len([g for g in grounded if g is not None]),
                         "sentence_support": _mean(grounded)},
        "latency_seconds": {"mean": round(statistics.fmean(latencies), 3),
                            "p95": round(sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)], 3)},
        "cases": judgements,
    }


def config_hash(tuning: Tuning, use_llm: bool, model: str) -> str:
    blob = json.dumps({"t": tuning.to_dict(), "llm": use_llm, "model": model}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


def run_experiment(db, embedder, settings, name: str, tuning: Tuning, split: str, use_llm: bool,
                   dataset_path: Path = HELDOUT_PATH, group: str = "", progress=None,
                   limit: int | None = None) -> dict:
    """Run one configuration on one split and save everything needed to reproduce it."""
    dataset = load_dataset(dataset_path)
    cases = load_cases(dataset_path, split, limit)
    assistant = build_assistant(db, embedder, settings, tuning, use_llm)
    result = evaluate(assistant, cases, progress)
    record = {
        "name": name, "group": group, "split": split, "llm": use_llm,
        "llm_model": settings.llm_model if use_llm else None,
        "embedding_provider": settings.embedding_provider,
        "temperature_used": tuning.temperature if use_llm else None,
        "parameters": tuning.to_dict(),
        "changed_from_default": {k: v for k, v in tuning.to_dict().items() if v != DEFAULT_TUNING.to_dict()[k]},
        "config_hash": config_hash(tuning, use_llm, settings.llm_model),
        "dataset": dataset_path.name, "dataset_version": dataset.get("version"), "dataset_seed": dataset.get("seed"),
        "dataset_cases": len(cases), "sample_limit": limit,
        "evaluated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **result,
    }
    EXPERIMENT_DIR.mkdir(parents=True, exist_ok=True)
    tag = "llm" if use_llm else "nollm"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    (EXPERIMENT_DIR / f"{safe}__{dataset_path.stem.split('_')[0]}-{split}{f'-n{limit}' if limit else ''}__{tag}.json").write_text(
        json.dumps(record, indent=1, ensure_ascii=False), encoding="utf-8")
    return record


def headline(record: dict) -> str:
    m = record["overall"]
    pct = lambda v: "  -- " if v is None else f"{v * 100:5.1f}"
    return (f"P {pct(m['precision'])}  R {pct(m['recall'])}  F1 {pct(m['f1_score'])}  Acc {pct(m['accuracy'])}"
            f"  | MRR {record['retrieval']['mrr']}  grounded {record['groundedness']['sentence_support']}"
            f"  | {record['latency_seconds']['mean']}s/q")
