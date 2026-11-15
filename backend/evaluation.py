"""Offline benchmark evaluation (precision, recall, F1, accuracy).

Metrics shown in the UI are **never** computed for a single live answer - that
would need ground truth for an arbitrary question.  Instead this module runs
the complete assistant against a labelled dataset
(``backend/data/evaluation_dataset.json``) and stores the outcome in
``backend/data/evaluation_results.json``.  Until a benchmark has been run on
your own graph, every metric is ``None`` and the UI shows ``--``.

Evaluation definition (answer level, one decision per test case)
----------------------------------------------------------------
Each case is labelled ``expect: "answer"`` (the knowledge base should answer
it) or ``expect: "not_found"`` (the correct output is ``RESULT NOT FOUND``).
An answer is *correct* when

* ``primary_id``, when given, is the entity the answer is about (the first
  identifier of the response): listing the right entity among other matches while
  describing a different one does not count, and
* every ``required_ids`` entry was retrieved (it appears among the response's
  identifiers, related entities or relationships), and
* the answer carries no "Not verified" note (the model added identifiers that the
  retrieved evidence does not contain), and
* every ``required_facts`` group has at least one of its alternatives in the
  answer text (case-insensitive), and
* no ``forbidden_facts`` entry occurs in the answer.

==========================  ==========================================
TP  expect answer,     system answered correctly
FP  system answered, but wrongly  (wrong answer, or it should have said
    RESULT NOT FOUND)
FN  expect answer,     system said RESULT NOT FOUND
TN  expect not_found,  system said RESULT NOT FOUND
==========================  ==========================================

precision = TP / (TP + FP)      recall   = TP / (TP + FN)
F1        = 2PR / (P + R)       accuracy = (TP + TN) / all cases

Retrieval relevance is reported separately as *entity recall*: the share of
all ``required_ids`` that were retrieved.

Cases carry a ``difficulty``: ``direct`` questions name an exact identifier and
are close to a plain lookup, ``described`` questions do not.  Results are also
broken down by difficulty, because a score over direct lookups alone says little.
A stored benchmark is only served while it still describes the running system:
same dataset, same LLM.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from backend.config import DATA_DIR, DATASET_CATEGORIES, RESULT_NOT_FOUND
from backend.models import ChatResponse, Metrics
from backend.rag.tuning import DEFAULT_TUNING
from backend.updater.data_processor import content_hash

log = logging.getLogger(__name__)

DATASET_PATH = DATA_DIR / "evaluation_dataset.json"
RESULTS_PATH = DATA_DIR / "evaluation_results.json"
BENCHMARK_NOTE = ("Offline benchmark of this category on the labelled evaluation set - "
                  "not a guarantee that this individual answer is correct.")


def load_dataset(path: Path = DATASET_PATH) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("Evaluation dataset has no cases")
    for case in cases:
        if case.get("expect") not in {"answer", "not_found"}:
            raise ValueError(f"Case {case.get('id')!r}: expect must be 'answer' or 'not_found'")
        if not case.get("question") or not case.get("category"):
            raise ValueError(f"Case {case.get('id')!r}: question and category are required")
    return data


def retrieved_ids(response: ChatResponse) -> set[str]:
    ids = set(response.identifiers)
    ids.update(entity.id for entity in response.related_entities)
    for rel in response.relationships:
        ids.update((rel.source, rel.target))
    return ids


def judge_case(case: dict, response: ChatResponse) -> dict:
    """Classify one response as TP / FP / FN / TN according to the definition."""
    answered = response.answer.strip() != RESULT_NOT_FOUND
    answer_text = response.answer.lower()
    required_ids = list(case.get("required_ids") or [])
    got_ids = retrieved_ids(response)
    missing_ids = [i for i in required_ids if i not in got_ids]
    missing_facts = [group for group in case.get("required_facts") or []
                     if not any(str(alt).lower() in answer_text for alt in group)]
    forbidden = [fact for fact in case.get("forbidden_facts") or []
                 if str(fact).lower() in answer_text]
    primary = case.get("primary_id")
    wrong_primary = bool(primary) and (response.identifiers or [None])[0] != primary
    unverified = "**Not verified:**" in response.answer
    correct = (answered and not missing_ids and not missing_facts and not forbidden
               and not wrong_primary and not unverified)
    if case["expect"] == "answer":
        outcome = "TP" if correct else ("FP" if answered else "FN")
    else:
        outcome = "FP" if answered else "TN"
    return {"id": case.get("id"), "category": case["category"], "question": case["question"],
            "difficulty": case.get("difficulty") or "direct",
            "expect": case["expect"], "outcome": outcome, "answered": answered,
            "wrong_primary": wrong_primary, "unverified_identifiers": unverified,
            "primary_got": (response.identifiers or [None])[0],
            "missing_ids": missing_ids, "missing_facts": missing_facts, "forbidden_found": forbidden,
            "required_ids_total": len(required_ids),
            "required_ids_retrieved": len(required_ids) - len(missing_ids),
            "response_category": response.category}


def _ratio(numerator: int, denominator: int) -> float | None:
    """Undefined ratios stay None (shown as '--') instead of a made-up 0 or 1."""
    return round(numerator / denominator, 4) if denominator else None


def compute_metrics(judgements: list[dict]) -> dict:
    counts = {key: sum(1 for j in judgements if j["outcome"] == key) for key in ("TP", "FP", "FN", "TN")}
    precision = _ratio(counts["TP"], counts["TP"] + counts["FP"])
    recall = _ratio(counts["TP"], counts["TP"] + counts["FN"])
    f1 = (round(2 * precision * recall / (precision + recall), 4)
          if precision is not None and recall is not None and (precision + recall) > 0
          else (0.0 if precision == 0 or recall == 0 else None))
    return {
        "tp": counts["TP"], "fp": counts["FP"], "fn": counts["FN"], "tn": counts["TN"],
        "sample_size": len(judgements),
        "precision": precision, "recall": recall, "f1_score": f1,
        "accuracy": _ratio(counts["TP"] + counts["TN"], len(judgements)),
        "entity_recall": _ratio(sum(j["required_ids_retrieved"] for j in judgements),
                                sum(j["required_ids_total"] for j in judgements)),
    }


def run_evaluation(assistant, dataset: dict | None = None, environment: dict | None = None,
                   results_path: Path | None = RESULTS_PATH) -> dict:
    """Run every labelled case through the live assistant and store the results."""
    dataset = dataset or load_dataset()
    judgements = []
    for case in dataset["cases"]:
        try:
            response = assistant.ask(case["question"])
        except Exception as exc:
            raise RuntimeError(f"Evaluation aborted at case {case.get('id')!r}: "
                               f"{type(exc).__name__}: {exc}") from exc
        judgements.append(judge_case(case, response))
    by_category = {
        category: compute_metrics([j for j in judgements if j["category"] == category])
        for category in sorted({j["category"] for j in judgements})
    }
    results = {
        "scope": "offline_benchmark",
        "evaluated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset_version": dataset.get("version"),
        "dataset_hash": content_hash(dataset["cases"])[:16],
        "definition": "See backend/evaluation.py (answer-level TP/FP/FN/TN).",
        "environment": environment or {},
        "overall": compute_metrics(judgements),
        "by_category": by_category,
        "by_difficulty": {
            level: compute_metrics([j for j in judgements if j["difficulty"] == level])
            for level in sorted({j["difficulty"] for j in judgements})},
        "by_category_and_difficulty": {
            category: {level: compute_metrics([j for j in judgements if j["category"] == category
                                               and j["difficulty"] == level])
                       for level in sorted({j["difficulty"] for j in judgements
                                            if j["category"] == category})}
            for category in by_category},
        "cases": judgements,
    }
    if results_path is not None:
        save_results(results, results_path)
    return results


def save_results(results: dict, path: Path = RESULTS_PATH) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, path)          # atomic: readers never see a partial file


class EvaluationStore:
    """Serves stored benchmark results to the API (reloaded when the file changes)."""

    def __init__(self, path: Path = RESULTS_PATH, current: dict | None = None,
                 dataset_path: Path | None = None):
        """``current`` = {"llm_provider", "llm_model"} of the running system and
        ``dataset_path`` the benchmark file: when given, results produced with another
        LLM or another dataset are treated as out of date and not served."""
        self.path = Path(path)
        self.current = current
        self.dataset_path = dataset_path
        self._lock = threading.Lock()
        self._mtime: float | None = None
        self._results: dict | None = None

    def results(self) -> dict | None:
        with self._lock:
            try:
                mtime = self.path.stat().st_mtime
            except OSError:
                self._results, self._mtime = None, None
                return None
            if mtime != self._mtime:
                try:
                    self._results = json.loads(self.path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    log.warning("Evaluation results file is unreadable; metrics unavailable")
                    self._results = None
                self._mtime = mtime
            return self._results

    def stale_reason(self) -> str | None:
        """Why the stored benchmark no longer describes the running system, if so."""
        results = self.results()
        if not results:
            return None
        environment = results.get("environment") or {}
        if self.current is not None:
            for key, text in (("llm_provider", "LLM provider"), ("llm_model", "LLM model"),
                              ("tuning", "tuning parameters")):
                if key not in self.current:
                    continue
                recorded = environment.get(key)
                if key == "tuning" and recorded is None:
                    recorded = DEFAULT_TUNING.to_dict()      # run before tuning existed
                if (recorded or None) != (self.current.get(key) or None):
                    return (f"the benchmark was run with {text} "
                            f"{environment.get(key) or 'none'!s}, the system now uses "
                            f"{self.current.get(key) or 'none'!s}")
        if self.dataset_path is not None:
            try:
                current_hash = content_hash(load_dataset(self.dataset_path)["cases"])[:16]
            except (OSError, ValueError):
                return None
            if results.get("dataset_hash") != current_hash:
                return "the evaluation dataset has changed since the benchmark was run"
        return None

    def metrics_for(self, category: str) -> Metrics:
        """Benchmark metrics of one dataset category, or all-None when unavailable."""
        results = self.results()
        if category not in DATASET_CATEGORIES or not results or self.stale_reason():
            return Metrics()
        block = (results.get("by_category") or {}).get(category)
        if not block or not block.get("sample_size"):
            return Metrics()
        return Metrics(precision=block.get("precision"), recall=block.get("recall"),
                       f1_score=block.get("f1_score"), accuracy=block.get("accuracy"),
                       scope="offline_benchmark", category=category,
                       sample_size=block.get("sample_size"),
                       evaluated_at=results.get("evaluated_at"), note=BENCHMARK_NOTE)

    def summary(self) -> dict:
        results = self.results()
        if not results:
            return {"available": False, "scope": "offline_benchmark",
                    "message": ("No benchmark has been run yet. Run "
                                "'python -m backend.manage evaluate' after the initial data "
                                "synchronisation."),
                    "overall": None, "by_category": {}}
        stale = self.stale_reason()
        if stale:
            return {"available": False, "scope": "offline_benchmark",
                    "message": (f"The stored benchmark is out of date ({stale}). Run "
                                "'python -m backend.manage evaluate' again."),
                    "overall": None, "by_category": {}}
        return {"available": True, "scope": results.get("scope"), "note": BENCHMARK_NOTE,
                "by_difficulty": results.get("by_difficulty"),
                "evaluated_at": results.get("evaluated_at"),
                "dataset_version": results.get("dataset_version"),
                "environment": results.get("environment"), "overall": results.get("overall"),
                "by_category": results.get("by_category")}
