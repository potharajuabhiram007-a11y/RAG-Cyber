"""Measure answers to clean and misspelled questions, and fit the confidence score.

    python -m backend.experiments.calibrate            # fit on tuning set, report on held-out set

Every labelled question whose expected record is in the graph is asked twice: as written and
with random spelling mistakes (seeded). The logistic model in
``backend/data/confidence_model.json`` is fitted on the tuning set only; the figures printed
for the held-out set come from questions it has not seen.
"""
from __future__ import annotations

import dataclasses
import json
import random
import re
import sys

import numpy as np

from backend.config import DATA_DIR, load_settings
from backend.database import LABEL_ATTACK, LABEL_CAPEC, LABEL_CWE, Neo4jDatabase, label_for_id
from backend.evaluation import compute_metrics, judge_case
from backend.experiments.harness import HELDOUT_PATH, TUNING_PATH, build_assistant, load_cases
from backend.rag.confidence import FEATURES, MODEL_PATH, model
from backend.rag.retriever import Evidence, RetrievalResult, describe_entity
from backend.rag.tuning import DEFAULT_TUNING
from backend.updater.data_processor import EmbeddingClient

_IDENTIFIER = re.compile(r"\b(?:CVE-\d+-\d+|CWE-\d+|CAPEC-\d+|T\d{4}(?:\.\d+)?)\b", re.I)


def misspell(text: str, rng: random.Random, rate: float = 0.5) -> str:
    """One mistake in about half of the longer words; digits are never touched."""
    def mistake(match: re.Match) -> str:
        word = match.group(0)
        if rng.random() > rate:
            return word
        i = rng.randrange(1, len(word) - 1)
        kind = rng.choice(("swap", "drop", "double", "replace"))
        if kind == "swap":
            return word[:i] + word[i + 1] + word[i] + word[i + 2:]
        if kind == "drop":
            return word[:i] + word[i + 1:]
        if kind == "double":
            return word[:i] + word[i] + word[i:]
        return word[:i] + rng.choice("aeioursntl") + word[i + 1:]

    out, last = [], 0
    for match in _IDENTIFIER.finditer(text):
        out += [re.sub(r"[A-Za-z]{5,}", mistake, text[last:match.start()]), match.group(0)]
        last = match.end()
    return "".join(out) + re.sub(r"[A-Za-z]{5,}", mistake, text[last:])


def answerable(case: dict, db: Neo4jDatabase, cache: dict) -> bool:
    """False for a question about a record the curated graph does not hold."""
    ids = [i for i in (case.get("required_ids") or []) if label_for_id(i)]
    for i in ids:
        if i not in cache:
            cache[i] = db.get_node(label_for_id(i), i) is not None
    return all(cache[i] for i in ids)


def run(assistant, cases, typos: bool, seed: int):
    rng = random.Random(seed)
    judged, rows = [], []
    for case in cases:
        question = misspell(case["question"], rng) if typos else case["question"]
        response = assistant.ask(question)
        verdict = judge_case(case, response)
        verdict.update(asked=question, corrections=response.corrections)
        judged.append(verdict)
        features = assistant.last_features
        if verdict["answered"] and features:
            rows.append(([float(features.get(k) or 0) for k in FEATURES], verdict["outcome"] == "TP",
                         response.confidence.score if response.confidence else None))
    return judged, rows


def paraphrases(assistant, db, count: int = 500):
    """Hard samples: a record's first sentence with half its words removed and some misspelled,
    matched by meaning only. Returns (tuning rows, held-out rows), split by record."""
    rng = random.Random(21)
    retriever, rows = assistant.retriever, ([], [])
    records = [(label, n) for label in (LABEL_CWE, LABEL_CAPEC, LABEL_ATTACK)
               for n in db.page_nodes(label, "", 2000) if len(n.get("description") or "") > 80]
    for label, node in rng.sample(records, count):
        words = node["description"].split(". ")[0].split()[:30]
        kept = [w for w in words if rng.random() < rng.choice((0.25, 0.5, 0.75))]
        if len(kept) < 3:
            continue
        question, changes = retriever._speller().correct(misspell(" ".join(kept), rng, 0.25))
        vector = retriever.embedder.embed_query(question)
        hits = [h for l in (LABEL_CWE, LABEL_CAPEC, LABEL_ATTACK) for h in db.vector_search(l, vector, 1)]
        best = max(hits, key=lambda h: h["_score"])
        result = RetrievalResult("found", best["_label"], True, retriever.analyze(question),
                                 corrections=changes, evidence=[Evidence(
                                     kind="entity", source="", identifier=best["id"], title=best["name"],
                                     text=describe_entity(best["_label"], best))])
        retriever._measure(result)
        rows[rng.random() < 0.4].append(([float(result.features.get(k) or 0) for k in FEATURES],
                                         best["id"] == node["id"], None))
    return rows


def fit(x: np.ndarray, y: np.ndarray, l2: float = 1.0) -> np.ndarray:
    """L2-regularised logistic regression (Newton's method); column 0 is the bias."""
    a = np.column_stack([np.ones(len(x)), x])
    w = np.zeros(a.shape[1])
    penalty = np.diag([1e-6] + [l2] * x.shape[1])
    for _ in range(60):
        p = 1 / (1 + np.exp(-a @ w))
        grad = a.T @ (p - y) + penalty @ w
        hess = (a * (p * (1 - p))[:, None]).T @ a + penalty
        step = np.linalg.solve(hess, grad)
        w -= step
        if np.abs(step).max() < 1e-8:
            break
    return w


def main() -> int:
    settings = load_settings()
    db = Neo4jDatabase(settings)
    assistant = build_assistant(db, EmbeddingClient(settings), settings, DEFAULT_TUNING, use_llm=False)
    original = assistant.retriever.retrieve

    def spy(message):
        result = original(message)
        assistant.last_features = result.features
        return result

    assistant.retriever.retrieve = spy
    cache: dict = {}
    report: dict = {}
    data = {}
    for name, path in (("tuning", TUNING_PATH), ("heldout", HELDOUT_PATH)):
        everything = load_cases(path, None)
        # "absent" questions stay: the right answer to them is RESULT NOT FOUND
        cases = [c for c in everything if answerable(c, db, cache)]
        report[name] = {"questions": len(cases), "about_excluded_records": len(everything) - len(cases)}
        data[name] = []
        for typos in (False, True):
            judged, rows = run(assistant, cases, typos, seed=11 if name == "tuning" else 12)
            kind = "misspelled" if typos else "clean"
            report[name][kind] = compute_metrics(judged)
            report[name][kind]["by_category"] = {
                c: compute_metrics([j for j in judged if j["category"] == c])["accuracy"]
                for c in sorted({j["category"] for j in judged})}
            report[name][kind + "_failures"] = [
                {k: j[k] for k in ("id", "outcome", "asked", "corrections", "primary_got", "missing_ids")}
                for j in judged if j["outcome"] in ("FP", "FN")]
            data[name] += rows
            print(name, kind, {k: v for k, v in report[name][kind].items()}, flush=True)
    extra = paraphrases(assistant, db)
    print("paraphrase samples", [(len(e), float(np.mean([r[1] for r in e]))) for e in extra])
    report["paraphrase_samples"] = [len(e) for e in extra]
    data["tuning"] += extra[0]
    data["heldout"] += extra[1]
    x = np.array([r[0] for r in data["tuning"]])
    y = np.array([r[1] for r in data["tuning"]], dtype=float)
    w = fit(x, y)
    w[1 + FEATURES.index("corrected_share")] = min(0.0, w[1 + FEATURES.index("corrected_share")])
    MODEL_PATH.write_text(json.dumps({
        "bias": w[0], "weights": dict(zip(FEATURES, w[1:])), "fitted_on": TUNING_PATH.name,
        "answers": len(y), "share_correct": y.mean()}, indent=1), encoding="utf-8")
    model.cache_clear()
    hx = np.array([r[0] for r in data["heldout"]])
    hy = np.array([r[1] for r in data["heldout"]], dtype=float)
    p = 1 / (1 + np.exp(-(w[0] + hx @ w[1:])))
    bins = []
    for lo, hi in ((0, .2), (.2, .4), (.4, .6), (.6, .8), (.8, .95), (.95, 1.01)):
        m = (p >= lo) & (p < hi)
        if m.any():
            bins.append({"range": [lo, hi], "answers": int(m.sum()), "mean_confidence": round(p[m].mean(), 3),
                         "share_correct": round(hy[m].mean(), 3)})
    report["confidence_on_heldout"] = {
        "answers": len(hy), "brier": round(float(((p - hy) ** 2).mean()), 4), "calibration": bins,
        "weights": {"bias": round(w[0], 3), **{k: round(v, 3) for k, v in zip(FEATURES, w[1:])}}}
    print(json.dumps(report["confidence_on_heldout"], indent=1))
    (DATA_DIR / "experiments" / "curated_graph_report.json").write_text(
        json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
