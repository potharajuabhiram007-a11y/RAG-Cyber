"""RAG-Cyber FastAPI application.

Run from the RAG-Cyber folder:

    uvicorn backend.main:app --host 127.0.0.1 --port 8000

The frontend is served from ``/`` and talks to the REST API under ``/api``.
"""
from __future__ import annotations

import hmac
import json
import logging
import queue
import threading
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from neo4j.exceptions import Neo4jError

from backend.config import (
    FRONTEND_DIR, ConfigurationError, Settings, configure_logging, load_settings,
)
from backend.database import DatabaseUnavailable, Neo4jDatabase, SchemaMismatch, label_for_id
from backend.evaluation import DATASET_PATH, EvaluationStore
from backend.models import ChatRequest, ChatResponse, SyncRequest
from backend.rag.generator import Assistant, Generator
from backend.rag.retriever import Retriever
from backend.rag.tuning import DEFAULT_TUNING, Tuning
from backend.updater.data_processor import EmbeddingClient
from backend.updater.scheduler import SyncManager, expand_sources

log = logging.getLogger("backend.main")


class AppState:
    """Everything the request handlers need, built once at start-up."""

    def __init__(self, settings: Settings, db=None, embedder=None, sync_manager=None,
                 assistant=None, evaluation=None):
        self.settings = settings
        tuning = Tuning.from_file(settings.tuning_config) if settings.tuning_config else DEFAULT_TUNING
        self.db = db if db is not None else Neo4jDatabase(settings)
        self.embedder = embedder if embedder is not None else EmbeddingClient(settings)
        self.evaluation = evaluation if evaluation is not None else EvaluationStore(
            current={"llm_provider": settings.llm_provider, "llm_model": settings.llm_model or None,
                     "tuning": tuning.to_dict()},
            dataset_path=DATASET_PATH)
        self.sync = sync_manager if sync_manager is not None else SyncManager(
            self.db, self.embedder, settings)
        self.assistant = assistant if assistant is not None else Assistant(
            Retriever(self.db, self.embedder, settings, tuning), Generator(settings, tuning=tuning),
            self.evaluation)
        self.schema_ready = False
        self.startup_error: str | None = None

    def ensure_schema(self) -> bool:
        """Create constraints / indexes; retried lazily if Neo4j was down at start."""
        if self.schema_ready:
            return True
        try:
            self.db.init_schema(self.embedder.dimensions)
            self.schema_ready, self.startup_error = True, None
        except (DatabaseUnavailable, SchemaMismatch) as exc:
            self.startup_error = str(exc)
            log.error("Database not ready: %s", exc)
        except Exception as exc:
            self.startup_error = f"{type(exc).__name__} while preparing the database"
            log.exception("Unexpected error while initialising the schema")
        return self.schema_ready


def create_app(state: AppState | None = None, start_background: bool = True) -> FastAPI:
    if state is None:
        try:
            settings = load_settings()
        except ConfigurationError as exc:
            # A clear, single-line start-up error instead of a stack trace.
            raise SystemExit(f"RAG-Cyber configuration error: {exc}") from exc
        configure_logging(settings.log_level)
        state = AppState(settings)
    settings = state.settings

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        log.info("Starting RAG-Cyber with %s", settings.safe_summary())
        if start_background:
            if state.ensure_schema():
                state.sync.start()          # background threads only - never blocks start-up
            else:
                log.error("Start-up continues in degraded mode: %s", state.startup_error)
        yield
        state.sync.shutdown()
        state.db.close()

    app = FastAPI(title="RAG-Cyber", version="1.0.0", lifespan=lifespan,
                  description="AI-Powered Cybersecurity Assistant (Graph RAG over Neo4j)")
    app.state.rag = state
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins),
                       allow_methods=["GET", "POST"], allow_headers=["Content-Type", "X-Admin-Key"])

    # ------------------------------------------------------------------ #
    # Middleware and error handling
    # ------------------------------------------------------------------ #
    @app.middleware("http")
    async def limit_request_size(request: Request, call_next):
        length = request.headers.get("content-length")
        if request.method in {"POST", "PUT", "PATCH"}:
            if length is None or not length.isdigit():
                return JSONResponse({"detail": "Content-Length header is required"}, status_code=411)
            if int(length) > settings.max_request_bytes:
                return JSONResponse({"detail": "Request body is too large"}, status_code=413)
        return await call_next(request)

    @app.exception_handler(DatabaseUnavailable)
    async def database_unavailable(_: Request, exc: DatabaseUnavailable):
        return JSONResponse({"detail": str(exc)}, status_code=503)

    @app.exception_handler(Neo4jError)
    async def neo4j_error(_: Request, exc: Neo4jError):
        log.error("Neo4j error: %s", exc.code)
        return JSONResponse({"detail": "The knowledge graph reported an error. See the server log."},
                            status_code=503)

    @app.exception_handler(Exception)
    async def unexpected_error(_: Request, exc: Exception):
        log.exception("Unhandled error")
        return JSONResponse({"detail": "Internal server error"}, status_code=500)

    def require_admin(x_admin_key: str | None = Header(default=None)) -> None:
        if not settings.admin_api_key:
            raise HTTPException(503, "Manual synchronisation is disabled: set ADMIN_API_KEY in .env")
        if not x_admin_key or not hmac.compare_digest(x_admin_key.encode(), settings.admin_api_key.encode()):
            raise HTTPException(401, "Invalid or missing X-Admin-Key header")

    def require_database() -> None:
        if not state.ensure_schema():
            raise HTTPException(503, state.startup_error or "The knowledge graph is not available")

    # ------------------------------------------------------------------ #
    # Endpoints
    # ------------------------------------------------------------------ #
    @app.post("/api/chat", response_model=ChatResponse)
    def chat(request: ChatRequest, _: None = Depends(require_database)) -> ChatResponse:
        if len(request.message) > settings.max_message_chars:
            raise HTTPException(422, f"message is longer than {settings.max_message_chars} characters")
        return state.assistant.ask(request.message)

    @app.post("/api/chat/stream")
    def chat_stream(request: ChatRequest, _: None = Depends(require_database)) -> StreamingResponse:
        """The same answer as /api/chat, sent as newline-delimited JSON events:
        {"type": "delta", "text": ...} while a language model is writing, then one
        {"type": "final", "response": <ChatResponse>} (or {"type": "error"})."""
        if len(request.message) > settings.max_message_chars:
            raise HTTPException(422, f"message is longer than {settings.max_message_chars} characters")
        events: queue.Queue = queue.Queue()

        def work() -> None:
            try:
                response = state.assistant.ask(
                    request.message, on_delta=lambda text: events.put(("delta", text)))
                events.put(("final", response))
            except Exception as exc:        # reported to the client as an event
                log.exception("Streaming chat request failed")
                events.put(("error", type(exc).__name__))

        def lines():
            threading.Thread(target=work, daemon=True, name="chat-stream").start()
            while True:
                kind, payload = events.get()
                if kind == "delta":
                    yield json.dumps({"type": "delta", "text": payload}) + "\n"
                elif kind == "final":
                    yield json.dumps({"type": "final", "response": payload.model_dump(mode="json")}) + "\n"
                    return
                else:
                    yield json.dumps({"type": "error",
                                      "detail": f"The answer could not be produced ({payload})."}) + "\n"
                    return

        return StreamingResponse(lines(), media_type="application/x-ndjson",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    @app.get("/api/status")
    def health() -> dict:
        connected = state.db.verify()
        return {"status": "ok" if connected and state.ensure_schema() else "degraded",
                "service": "RAG-Cyber", "version": app.version, "database_connected": connected,
                "error": None if connected else (state.startup_error or "Neo4j is not reachable"),
                "configuration": settings.safe_summary()}

    @app.get("/api/database/status")
    def database_status() -> dict:
        if not state.db.verify():
            raise HTTPException(503, state.startup_error or "Neo4j is not reachable")
        require_database()
        return {"connected": True, "server": state.db.server_info(),
                "vector_search_available": state.db.vector_search_available,
                "embedding_dimensions": state.embedder.dimensions, **state.db.counts()}

    @app.get("/api/sync/status")
    def sync_status(_: None = Depends(require_database)) -> dict:
        return state.sync.status()

    @app.post("/api/admin/sync", status_code=202)
    def trigger_sync(request: SyncRequest, _: None = Depends(require_admin),
                     __: None = Depends(require_database)) -> dict:
        try:
            ordered = expand_sources(request.sources)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        busy = set(state.sync.running_sources())
        if busy & set(ordered):
            raise HTTPException(409, "Already synchronising: " + ", ".join(sorted(busy & set(ordered))))
        state.sync.start_background(ordered, full=request.full)
        return {"accepted": True, "sources": ordered, "full": request.full,
                "message": "Synchronisation started in the background; poll /api/sync/status."}

    @app.get("/api/graph/search")
    def graph_search(q: str = Query("", max_length=80), _: None = Depends(require_database)) -> dict:
        return {"results": state.db.graph_search(q)}

    @app.get("/api/graph/overview")
    def graph_overview(_: None = Depends(require_database)) -> dict:
        return {"results": state.db.graph_overview()}

    @app.get("/api/graph/entity/{entity_id}")
    def graph_entity(entity_id: str, per_group: int = Query(10, ge=1, le=25),
                     _: None = Depends(require_database)) -> dict:
        if label_for_id(entity_id) is None:
            raise HTTPException(404, "Not a CVE, CWE, CAPEC or ATT&CK identifier")
        found = state.db.graph_entity(entity_id, per_group)
        if found is None:
            raise HTTPException(404, f"{entity_id.strip().upper()} is not in the knowledge graph")
        return found

    @app.get("/api/metrics")
    def metrics() -> dict:
        return state.evaluation.summary()

    if FRONTEND_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
    return app


def __getattr__(name: str):
    # ``uvicorn backend.main:app`` builds the application lazily, so importing this
    # module (for tests or tooling) never requires a configured environment.
    if name == "app":
        application = create_app()
        globals()["app"] = application
        return application
    raise AttributeError(name)
