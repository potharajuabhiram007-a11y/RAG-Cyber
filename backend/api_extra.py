"""Additional API endpoints for the RAG‑Cyber frontend.
These provide the extra data needed for stats, graph exploration, entity search,
severity calculations and evaluation management. The implementations are simple
stubs that call the existing backend services where possible.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from backend.main import require_admin, require_database
from backend.models import SyncRequest
from typing import List, Optional

router = APIRouter()

# ------------------------------------------------------------------
# Statistics endpoints
# ------------------------------------------------------------------
@router.get("/stats/entities")
def get_entity_stats(_: None = Depends(require_database)) -> dict:
    """Return counts of each entity type.
    The underlying Neo4j database provides a ``counts`` method returning a dict
    with keys like ``cve``, ``cwe`` etc. We expose it directly.
    """
    # Access the global FastAPI app state via FastAPI's request state is not
    # available here, so we rely on the dependency that ensures the database is
    # ready. The ``AppState`` is stored on ``app.state.rag`` – we can retrieve it
    # via a temporary import hack.
    from backend.main import AppState, create_app
    state: AppState = create_app().state.rag
    return state.db.counts()

@router.get("/stats/relationships")
def get_relationship_stats(_: None = Depends(require_database)) -> dict:
    """Return total relationship count.
    """
    from backend.main import AppState, create_app
    state: AppState = create_app().state.rag
    return {"relationships": state.db.relationship_count()}

# ------------------------------------------------------------------
# Graph exploration endpoint
# ------------------------------------------------------------------
@router.get("/graph/neighborhood/{entity_id}")
def get_graph_neighborhood(
    entity_id: str,
    depth: int = Query(2, ge=1, le=4),
    limit: int = Query(200, ge=1, le=500),
    _: None = Depends(require_database),
) -> dict:
    """Return a sub‑graph around ``entity_id``.
    The Neo4j ``Database`` class already has a ``neighborhood`` helper; we call it
    and slice the results according to ``depth`` and ``limit``.
    """
    from backend.main import AppState, create_app
    state: AppState = create_app().state.rag
    try:
        subgraph = state.db.neighborhood(entity_id, depth=depth, limit=limit)
    except Exception as exc:
        raise HTTPException(404, f"Entity {entity_id} not found or no neighborhood") from exc
    return subgraph

# ------------------------------------------------------------------
# Entity search endpoint
# ------------------------------------------------------------------
@router.get("/entities/search")
def search_entities(
    query: str,
    limit: int = Query(20, ge=1, le=100),
    _: None = Depends(require_database),
) -> list[dict]:
    """Simple fuzzy search across all entity labels.
    Delegates to ``db.search_entities`` if it exists; otherwise returns empty.
    """
    from backend.main import AppState, create_app
    state: AppState = create_app().state.rag
    if hasattr(state.db, "search_entities"):
        return state.db.search_entities(query, limit=limit)
    return []

# ------------------------------------------------------------------
# Severity calculator endpoints
# ------------------------------------------------------------------
@router.get("/severity/cve/{cve_id}")
def get_cve_severity(cve_id: str, _: None = Depends(require_database)) -> dict:
    """Return stored CVSS vector and score for a CVE if present.
    This is a placeholder – real implementation would query a CVE store.
    """
    # Placeholder response
    return {"cve": cve_id, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8}

@router.post("/severity/calculate")
def calculate_severity(payload: dict, _: None = Depends(require_admin)) -> dict:
    """Calculate CVSS score from metrics.
    Expects ``version`` ("3.1" or "4.0") and a ``metrics`` dict. Returns a dummy
    score for demonstration.
    """
    # In a real system you would import the official CVSS library.
    version = payload.get("version", "3.1")
    metrics = payload.get("metrics", {})
    # Dummy calculation – just return a fixed score.
    return {"version": version, "score": 7.5, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"}

# ------------------------------------------------------------------
# Evaluation management endpoints
# ------------------------------------------------------------------
@router.get("/evaluation/history")
def evaluation_history(_: None = Depends(require_admin)) -> list[dict]:
    """List past evaluation runs.
    Placeholder returning an empty list.
    """
    return []

@router.post("/evaluation/run")
def run_evaluation(request: SyncRequest, _: None = Depends(require_admin)) -> dict:
    """Trigger a new evaluation run.
    This simply forwards to the existing admin sync endpoint for demonstration.
    """
    # Reuse the admin sync logic – could also call a dedicated evaluation routine.
    from backend.main import trigger_sync
    return trigger_sync(request, _: None, __: None)  # type: ignore
