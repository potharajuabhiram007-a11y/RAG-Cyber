"""Automatic, non-blocking synchronisation of every knowledge source.

``SyncManager`` owns the updaters and guarantees that

* the MITRE sources (CWE, CAPEC, ATT&CK) and NVD run on separate schedules;
* a source is never synchronised twice at the same time (scheduled, manual and
  start-up runs all go through the same per-group locks);
* nothing here blocks FastAPI start-up - all work happens in background threads;
* every run records its outcome (last attempt / success / error) in Neo4j, so a
  failure is visible in ``/api/sync/status`` and simply retried next interval.
"""
from __future__ import annotations

import logging
import threading
from typing import Sequence

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from backend.config import Settings
from backend.database import utc_now_iso
from backend.updater.attack_updater import AttackUpdater
from backend.updater.capec_updater import CAPECUpdater
from backend.updater.cve_updater import CVEUpdater
from backend.updater.cwe_updater import CWEUpdater
from backend.updater.data_processor import (
    FOUNDATION_SOURCE, EmbeddingClient, FoundationIngestor, SyncResult, safe_error,
)

log = logging.getLogger(__name__)

MITRE_SOURCES = ("cwe", "capec", "attack")
ALL_SOURCES = (FOUNDATION_SOURCE, *MITRE_SOURCES, "nvd")
# CWE first so CAPEC and CVE records can link to weaknesses; NVD last (largest).
RUN_ORDER = {name: index for index, name in enumerate(ALL_SOURCES)}
_GROUP = {FOUNDATION_SOURCE: "foundation", "cwe": "mitre", "capec": "mitre",
          "attack": "mitre", "nvd": "nvd"}


def expand_sources(requested: Sequence[str]) -> list[str]:
    """Validate and order a list such as ['all'], ['mitre'] or ['nvd', 'cwe']."""
    selected: set[str] = set()
    for name in requested:
        key = name.strip().lower()
        if key == "all":
            selected.update(ALL_SOURCES)
        elif key == "mitre":
            selected.update(MITRE_SOURCES)
        elif key in ALL_SOURCES:
            selected.add(key)
        else:
            raise ValueError(f"Unknown source {name!r}. Valid: all, mitre, " + ", ".join(ALL_SOURCES))
    return sorted(selected, key=RUN_ORDER.__getitem__)


class SyncManager:
    def __init__(self, db, embedder: EmbeddingClient, settings: Settings, updaters: dict | None = None):
        self.db, self.embedder, self.settings = db, embedder, settings
        self.updaters = updaters or {
            "cwe": CWEUpdater(db, embedder, settings),
            "capec": CAPECUpdater(db, embedder, settings),
            "attack": AttackUpdater(db, embedder, settings),
            "nvd": CVEUpdater(db, embedder, settings),
        }
        self.ingestor = FoundationIngestor(db, embedder, settings)
        self._locks = {group: threading.Lock() for group in set(_GROUP.values())}
        self._running: set[str] = set()
        self._state_lock = threading.Lock()
        self._scheduler: BackgroundScheduler | None = None
        self._threads: list[threading.Thread] = []

    # ------------------------------------------------------------------ #
    # Running one source
    # ------------------------------------------------------------------ #
    def run_source(self, source: str, full: bool = False) -> SyncResult:
        """Synchronise one source; returns immediately with 'skipped' if its
        group is already being synchronised (prevents overlapping jobs)."""
        lock = self._locks[_GROUP[source]]
        if not lock.acquire(blocking=False):
            log.info("%s: a synchronisation of this group is already running - skipped", source)
            return SyncResult(source, "skipped", error="already running")
        with self._state_lock:
            self._running.add(source)
        try:
            if source == FOUNDATION_SOURCE:
                summary = self.ingestor.ingest_all(force=full)
                status = "failed" if summary["errors"] else "success"
                return SyncResult(source, status, records=summary["terms"] + summary["chunks"],
                                  error="; ".join(summary["errors"]) or None, details=summary)
            if source == "nvd":
                return self.updaters["nvd"].sync(full=full)
            return self.updaters[source].sync(force=full)
        except Exception as exc:        # the updaters already catch; this is a last resort
            log.exception("%s: unexpected synchronisation error", source)
            return SyncResult(source, "failed", error=safe_error(exc))
        finally:
            with self._state_lock:
                self._running.discard(source)
            lock.release()

    def run_many(self, sources: Sequence[str], full: bool = False) -> list[SyncResult]:
        results = []
        for source in expand_sources(sources):
            results.append(self.run_source(source, full=full))
        return results

    def start_background(self, sources: Sequence[str], full: bool = False) -> list[str]:
        """Start a background run; returns the ordered list of sources queued."""
        ordered = expand_sources(sources)
        thread = threading.Thread(target=self.run_many, args=(ordered, full),
                                  name="rag-cyber-sync", daemon=True)
        self._threads = [t for t in self._threads if t.is_alive()] + [thread]
        thread.start()
        return ordered

    def running_sources(self) -> list[str]:
        with self._state_lock:
            return sorted(self._running, key=RUN_ORDER.__getitem__)

    # ------------------------------------------------------------------ #
    # Scheduling
    # ------------------------------------------------------------------ #
    def _scheduled_mitre(self) -> None:
        self.run_many([FOUNDATION_SOURCE, *MITRE_SOURCES])

    def _scheduled_nvd(self) -> None:
        self.run_source("nvd")

    def start(self) -> None:
        """Start the scheduler and (optionally) the first synchronisation."""
        self._recover_interrupted_runs()
        if self.settings.scheduler_enabled and self._scheduler is None:
            scheduler = BackgroundScheduler(
                timezone="UTC",
                job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 3600})
            scheduler.add_job(self._scheduled_mitre, id="mitre",
                              trigger=IntervalTrigger(hours=self.settings.update_interval_hours))
            scheduler.add_job(self._scheduled_nvd, id="nvd",
                              trigger=IntervalTrigger(hours=self.settings.nvd_update_interval_hours))
            scheduler.start()
            self._scheduler = scheduler
            log.info("Scheduler started: MITRE every %dh, NVD every %dh",
                     self.settings.update_interval_hours, self.settings.nvd_update_interval_hours)
        if self.settings.run_initial_sync:
            # Brings every source up to date: sources that never succeeded get their
            # initial load, the others an incremental / hash-checked refresh.
            self.start_background(["all"])

    def shutdown(self) -> None:
        if self._scheduler is not None:
            self._scheduler.shutdown(wait=False)
            self._scheduler = None

    def _recover_interrupted_runs(self) -> None:
        """A process that died mid-run leaves status='running'; correct it.  The
        checkpoint was not advanced, so the next run repeats the work safely."""
        try:
            for state in self.db.all_sync_states():
                if state.get("status") == "running":
                    self.db.save_sync_state(
                        state["source"], status="failed", last_failure_at=utc_now_iso(),
                        last_error="Previous run was interrupted before it finished")
        except Exception as exc:
            log.warning("Could not check for interrupted sync runs: %s", type(exc).__name__)

    # ------------------------------------------------------------------ #
    # Status
    # ------------------------------------------------------------------ #
    def status(self) -> dict:
        states = {state["source"]: state for state in self.db.all_sync_states()}
        running = set(self.running_sources())
        next_runs: dict[str, str | None] = {}
        if self._scheduler is not None:
            for job in self._scheduler.get_jobs():
                next_runs[job.id] = job.next_run_time.isoformat() if job.next_run_time else None
        sources = []
        for name in ALL_SOURCES:
            state = states.get(name, {})
            status = "running" if name in running else state.get("status", "never_run")
            sources.append({
                "source": name,
                "status": status,
                "last_attempt_at": state.get("last_attempt_at"),
                "last_success_at": state.get("last_success_at"),
                "last_checked_at": state.get("last_checked_at"),
                "last_failure_at": state.get("last_failure_at"),
                "last_error": state.get("last_error") if status == "failed" else None,
                "records": state.get("records"),
                "checkpoint": state.get("checkpoint"),
                "initial_sync_progress": (
                    {"next_index": state.get("full_sync_next_index"),
                     "total": state.get("full_sync_total")}
                    if state.get("full_sync_next_index") is not None else None),
                "next_scheduled_run": next_runs.get(_GROUP[name] if name != FOUNDATION_SOURCE else "mitre"),
            })
        return {"scheduler_running": self._scheduler is not None,
                "running": sorted(running, key=RUN_ORDER.__getitem__), "sources": sources}
