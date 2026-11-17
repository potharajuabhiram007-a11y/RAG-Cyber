"""Additional read-only API endpoints (statistics, graph exploration, entity search).

The router is not mounted by ``create_app`` by default; include it with
``app.include_router(router, prefix="/api/extra")``.  Handlers read the application
state from ``request.app.state.rag`` and never build a second application.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from backend.database import label_for_id
from backend.main import AppState, require_admin, require_database

router = APIRouter()


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


@router.post("/evaluation/run")
def run_evaluation_endpoint(request: Request, _: None = Depends(require_admin),
                            __: None = Depends(require_database)) -> dict:
    """Run the labelled benchmark through the live assistant (slow; admin only)."""
    from backend.evaluation import run_evaluation
    results = run_evaluation(_state(request).assistant)
    return {"completed": True, "metrics": results.get("metrics")}
