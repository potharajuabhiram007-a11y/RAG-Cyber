"""Additional read-only API endpoints (statistics, graph exploration, entity search).

The router is mounted under ``/api`` by ``create_app``.  Handlers read the
application state from ``request.app.state.rag`` and never build a second application.
"""
from __future__ import annotations

import math

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict

from backend.database import label_for_id
from backend.main import AppState, require_admin, require_database

router = APIRouter(prefix="/api")

# --------------------------------------------------------------------------- #
# CVSS v3.1 base score (FIRST specification, section 7)
# --------------------------------------------------------------------------- #
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_METRIC_KEYS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def roundup(value: float) -> float:
    """CVSS v3.1 Roundup: the smallest number with one decimal that is >= value."""
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def severity_rating(score: float) -> str:
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def parse_vector(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise ValueError("The vector must start with CVSS:3.1")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.partition(":")
        if key in _METRIC_KEYS and key not in metrics:
            metrics[key] = value
    return metrics


def cvss31_base_score(metrics: dict[str, str]) -> dict:
    """Base score of the eight base metrics (AV, AC, PR, UI, S, C, I, A)."""
    missing = [k for k in _METRIC_KEYS if k not in metrics]
    if missing:
        raise ValueError("Missing metrics: " + ", ".join(missing))
    try:
        scope_changed = {"U": False, "C": True}[metrics["S"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        av, ac, ui = _AV[metrics["AV"]], _AC[metrics["AC"]], _UI[metrics["UI"]]
        c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError as exc:
        raise ValueError(f"Invalid metric value: {exc.args[0]}") from exc
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed
              else 6.42 * iss)
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = roundup(min(impact + exploitability, 10))
    return {"score": score, "severity": severity_rating(score),
            "impact_subscore": round(impact, 1) if impact > 0 else 0.0,
            "exploitability_subscore": round(exploitability, 1)}


class SeverityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vector: str | None = None
    metrics: dict[str, str] | None = None


def _state(request: Request) -> AppState:
    return request.app.state.rag


@router.get("/stats/entities")
def get_entity_stats(request: Request, _: None = Depends(require_database)) -> dict:
    """Number of nodes per label."""
    return _state(request).db.counts()["nodes"]


@router.get("/stats/relationships")
def get_relationship_stats(request: Request, _: None = Depends(require_database)) -> dict:
    """Number of relationships per type."""
    return _state(request).db.counts()["relationships"]


@router.get("/graph/neighborhood/{entity_id}")
def get_graph_neighborhood(request: Request, entity_id: str,
                           limit: int = Query(10, ge=1, le=500),
                           _: None = Depends(require_database)) -> dict:
    """An entity plus a bounded sample of its neighbours, grouped by relation."""
    if label_for_id(entity_id) is None:
        raise HTTPException(404, "Not a CVE, CWE, CAPEC or ATT&CK identifier")
    found = _state(request).db.graph_entity(entity_id, per_group=min(limit, 25))
    if found is None:
        raise HTTPException(404, f"{entity_id.strip().upper()} is not in the knowledge graph")
    return found


@router.get("/graph/kill-chain/{entity_id}")
def get_kill_chain(request: Request, entity_id: str, limit: int = Query(25, ge=1, le=100),
                   _: None = Depends(require_database)) -> dict:
    """Entities up to four hops away along CVE -> CWE -> CAPEC -> ATT&CK (both directions)."""
    if label_for_id(entity_id) is None:
        raise HTTPException(404, "Not a CVE, CWE, CAPEC or ATT&CK identifier")
    chain = _state(request).db.multi_hop_kill_chain(entity_id, limit=limit)
    if not chain["nodes"] and not chain["edges"] and _state(request).db.get_node(
            label_for_id(entity_id), entity_id.strip().upper()) is None:
        raise HTTPException(404, f"{entity_id.strip().upper()} is not in the knowledge graph")
    return chain


@router.get("/cve/filter")
def filter_cves(request: Request, severity: str | None = Query(None, max_length=20),
                year: int | None = Query(None, ge=1988, le=2100),
                min_score: float | None = Query(None, ge=0.0, le=10.0),
                vendor: str | None = Query(None, max_length=80),
                limit: int = Query(20, ge=1, le=100),
                _: None = Depends(require_database)) -> dict:
    """CVEs by severity, publication year, minimum CVSS score or vendor / product."""
    results = _state(request).db.filter_cves(severity=severity, year=year, min_score=min_score,
                                             vendor=vendor, limit=limit)
    return {"results": results, "count": len(results)}


@router.get("/entities/search")
def search_entities(request: Request, query: str = Query("", max_length=80),
                    limit: int = Query(20, ge=1, le=100),
                    _: None = Depends(require_database)) -> list[dict]:
    """Find entities by identifier prefix or by name."""
    return _state(request).db.graph_search(query, limit=limit)


@router.get("/severity/cve/{cve_id}")
def get_cve_severity(request: Request, cve_id: str,
                     _: None = Depends(require_database)) -> dict:
    """The stored CVSS data of a CVE."""
    node = _state(request).db.get_node("CVE", cve_id.strip().upper())
    if node is None:
        raise HTTPException(404, f"{cve_id.strip().upper()} is not in the knowledge graph")
    return {"cve": node.get("id"), "severity": node.get("severity"),
            "base_score": node.get("base_score"), "vector": node.get("cvss_vector")}


@router.post("/severity/calculate")
def calculate_severity(payload: SeverityRequest) -> dict:
    """CVSS v3.1 base score from a ``vector`` string or a ``metrics`` object."""
    try:
        if payload.vector:
            metrics = parse_vector(payload.vector)
        elif payload.metrics:
            metrics = {k.upper(): v.upper() for k, v in payload.metrics.items()}
        else:
            raise ValueError("Provide a CVSS:3.1 'vector' or a 'metrics' object")
        result = cvss31_base_score(metrics)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    vector = "CVSS:3.1/" + "/".join(f"{k}:{metrics[k]}" for k in _METRIC_KEYS)
    return {"version": "3.1", "vector": vector, **result}


@router.post("/evaluation/run")
def run_evaluation_endpoint(request: Request, _: None = Depends(require_admin),
                            __: None = Depends(require_database)) -> dict:
    """Run the labelled benchmark through the live assistant (slow; admin only)."""
    from backend.evaluation import run_evaluation
    results = run_evaluation(_state(request).assistant)
    return {"completed": True, "metrics": results.get("metrics")}
