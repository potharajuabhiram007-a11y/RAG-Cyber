"""Automatic, non-blocking synchronisation of every knowledge source.

``SyncManager`` owns the updaters and guarantees that

* each source has its own refresh interval: NVD (CVE) and the reference documents
  every ``NVD_UPDATE_INTERVAL_HOURS`` (default 24 h), the MITRE sources (CWE, CAPEC,
  ATT&CK) every ``UPDATE_INTERVAL_HOURS`` (default 2160 h, about 3 months);
* schedules survive restarts: an hourly check compares each source's last completed
  run (stored in Neo4j) with its interval, so a host that sleeps or restarts often
  (Render's free plan) neither resets the clock nor refreshes everything on boot;
* a source is never synchronised twice at the same time (scheduled, manual and
  start-up runs all go through the same per-group locks);
* nothing here blocks FastAPI start-up - all work happens in background threads;
* every run records its outcome (last attempt / success / error) in Neo4j, so a
  failure is visible in ``/api/sync/status`` and simply retried next interval.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone
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
CHECK_EVERY_HOURS = 1          # how often the scheduler looks for sources that are due
RETRY_AFTER_HOURS = 6          # a failed source is retried after this long, not at every check


def _parse_time(value) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def last_completed(state: dict) -> datetime | None:
    """When the source last finished a run: a real update, or a hash check that found
    nothing new (an unchanged MITRE file only moves last_checked_at)."""
    times = [t for t in (_parse_time(state.get("last_success_at")),
                         _parse_time(state.get("last_checked_at"))) if t]
    return max(times) if times else None


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
    def interval_hours(self, source: str) -> int:
        """CWE, CAPEC and ATT&CK follow UPDATE_INTERVAL_HOURS; CVE (NVD) and the local
        reference documents follow NVD_UPDATE_INTERVAL_HOURS."""
        if source in MITRE_SOURCES:
            return self.settings.update_interval_hours
        return self.settings.nvd_update_interval_hours

    def due_sources(self, now: datetime | None = None) -> list[str]:
        """Sources whose interval has passed since their last completed run, plus any
        that never completed or whose first NVD load is still part-way through."""
        now = now or datetime.now(timezone.utc)
        states = {state["source"]: state for state in self.db.all_sync_states()}
        running = set(self.running_sources())
        due = []
        for name in ALL_SOURCES:
            if name in running:
                continue
            state = states.get(name, {})
            failed_at = _parse_time(state.get("last_failure_at"))
            if (state.get("status") == "failed" and failed_at
                    and now - failed_at < timedelta(hours=RETRY_AFTER_HOURS)):
                continue                                   # failed recently: wait before retrying
            if name == "nvd" and state.get("full_sync_next_index") is not None:
                due.append(name)                           # finish an interrupted first load
                continue
            last = last_completed(state)
            if last is None or now - last >= timedelta(hours=self.interval_hours(name)):
                due.append(name)
        return due

    def next_run(self, source: str, state: dict) -> str | None:
        """When the source is next due (None: due now, it never completed a run)."""
        last = last_completed(state)
        if last is None:
            return None
        return _iso(last + timedelta(hours=self.interval_hours(source)))

    def run_due(self) -> list[SyncResult]:
        """Run every source that is due (the scheduled job, and the start-up check)."""
        try:
            due = self.due_sources()
        except Exception as exc:
            log.warning("Could not read sync states: %s", type(exc).__name__)
            return []
        if due:
            log.info("Sources due for an update: %s", ", ".join(due))
        return self.run_many(due) if due else []

    def start(self) -> None:
        """Start the scheduler and (optionally) the first synchronisation."""
        self._recover_interrupted_runs()
        if self.settings.scheduler_enabled and self._scheduler is None:
            scheduler = BackgroundScheduler(
                timezone="UTC",
                job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 3600})
            scheduler.add_job(self.run_due, id="due-check",
                              trigger=IntervalTrigger(hours=CHECK_EVERY_HOURS))
            scheduler.start()
            self._scheduler = scheduler
            log.info("Scheduler started: CVE (NVD) every %dh, CWE/CAPEC/ATT&CK every %dh",
                     self.settings.nvd_update_interval_hours, self.settings.update_interval_hours)
        if self.settings.run_initial_sync:
            # Only what is due: sources that never ran get their first load, the rest
            # wait for their interval (a restart does not trigger a full refresh).
            thread = threading.Thread(target=self.run_due, name="rag-cyber-sync", daemon=True)
            self._threads = [t for t in self._threads if t.is_alive()] + [thread]
            thread.start()

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
                "update_interval_hours": self.interval_hours(name),
                "next_scheduled_run": self.next_run(name, state),
            })
        return {"scheduler_running": self._scheduler is not None,
                "running": sorted(running, key=RUN_ORDER.__getitem__), "sources": sources}
