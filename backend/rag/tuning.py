"""Tunable retrieval and generation parameters.

Every default equals the behaviour the pipeline had before this module existed, so
importing it changes nothing.  ``backend/experiments`` builds variants of this object
to measure how each setting affects the benchmark; the configuration that is
selected from those measurements is stored in ``backend/data/tuned_config.json`` and
loaded with ``Tuning.from_file`` (see ``TUNING_CONFIG`` in ``.env.example``).
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields
from pathlib import Path


@dataclass(frozen=True)
class Tuning:
    # --- retrieval: candidate generation ------------------------------------
    name_search_k: int = 8            # full-text hits over CWE / CAPEC / ATT&CK names
    vector_k: int = 5                 # vector hits per dataset
    vector_min_score: float | None = None   # None: the embedder's default (Settings)
    cve_pool_k: int = 40              # CVE description hits fetched before re-ranking
    cve_result_k: int = 6             # CVE records kept (first one is described in full)
    extra_entries: int = 3            # further matching entries listed below the answer
    # --- retrieval: acceptance and ranking -----------------------------------
    entity_full_cov: float = 0.75     # share of the question words a description must hold
    fundamentals_coverage: float = 0.6
    rank_mode: str = "lexicographic"  # lexicographic | weighted
    w_name: float = 1.0               # weighted mode: name coverage
    w_vector: float = 0.5             # weighted mode: vector similarity
    w_desc: float = 0.0               # weighted mode: coverage in the description (re-ranking)
    w_length: float = 0.02            # weighted mode: penalty per word of the name
    # --- graph traversal ------------------------------------------------------
    max_hops: int = 3                 # longest relationship chain followed (1-3)
    traverse_limit: int = 200
    # --- generation ----------------------------------------------------------------
    temperature: float = 0.1
    answer_tokens: int = 420
    evidence_chars: int = 6000
    brief_answers: bool = True
    verified_facts: bool = True       # append the graph's own key facts to a model answer
    flag_unverified: bool = True      # list identifiers the evidence does not contain

    def replace(self, **changes) -> "Tuning":
        unknown = set(changes) - {f.name for f in fields(self)}
        if unknown:
            raise ValueError(f"unknown tuning parameter(s): {', '.join(sorted(unknown))}")
        return Tuning(**{**asdict(self), **changes})

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Tuning":
        return cls().replace(**data)

    @classmethod
    def from_file(cls, path) -> "Tuning":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload.get("parameters", payload))


DEFAULT_TUNING = Tuning()
