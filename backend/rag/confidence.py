"""Confidence score of one answer.

A logistic model over measurable properties of the retrieval, fitted on labelled questions
(with and without spelling mistakes) by ``backend/experiments/calibrate.py`` and checked on
questions that were not used for fitting. It estimates how likely the retrieved record is the
right one; it does not judge every sentence a language model writes, so a model-written
answer is lowered by the share of its sentences the evidence does not support.
"""
from __future__ import annotations

import json
import math
from functools import lru_cache

from backend.config import DATA_DIR

MODEL_PATH = DATA_DIR / "confidence_model.json"
FEATURES = ("exact_id", "similarity", "coverage", "name_match", "corrected_share")
# used until calibrate.py has been run
_DEFAULT = {"bias": -4.0, "weights": {"exact_id": 4.0, "similarity": 4.0, "coverage": 2.0,
                                      "name_match": 1.5, "corrected_share": -1.5}}


@lru_cache(maxsize=1)
def model() -> dict:
    try:
        return json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _DEFAULT


def retrieval_confidence(features: dict[str, float]) -> float:
    m = model()
    z = m["bias"] + sum(m["weights"][k] * float(features.get(k) or 0.0) for k in FEATURES)
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))


def label_of(score: float) -> str:
    return "high" if score >= 0.8 else "medium" if score >= 0.55 else "low"
