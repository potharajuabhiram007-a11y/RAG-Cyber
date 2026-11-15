"""CVE updater - official NVD CVE API 2.0.

Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0

* Initial full synchronisation (resumable page by page) or, when
  ``NVD_SYNC_START_DATE`` is set, an initial load limited to CVEs published on
  or after that date.
* Incremental updates with ``lastModStartDate`` / ``lastModEndDate`` in windows
  of at most 120 days (the API's limit), starting slightly *before* the last
  checkpoint (overlap) so records modified at a boundary are never missed.
* The checkpoint only moves forward after every page of a window has been
  written to Neo4j.
* Rate limits are respected (public: 5 requests / 30 s, with API key: 50 / 30 s)
  and failures are retried with exponential backoff.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterator

import httpx

from backend.config import Settings
from backend.database import LABEL_CVE, utc_now_iso
from backend.updater.data_processor import (
    EMBEDDING_TEXT, DataValidationError, EmbeddingClient, SyncResult, attach_embeddings,
    build_http_client, clean_text, content_hash, dedupe, http_get, normalize_cve_id,
    normalize_cwe_id, safe_error,
)

log = logging.getLogger(__name__)

SOURCE = "nvd"
_PATCH_TAGS = {"Patch", "Vendor Advisory", "Mitigation"}
# Preference order when several CVSS versions are present: v3.x carries the
# impact / exploitability sub-scores, v4.0 does not publish them.
_METRIC_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")


def format_nvd_datetime(moment: datetime) -> str:
    """NVD expects extended ISO-8601 with an explicit offset."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def parse_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def split_windows(start: datetime, end: datetime, max_days: int) -> list[tuple[datetime, datetime]]:
    """Consecutive [start, end] windows, each no longer than ``max_days``."""
    windows = []
    cursor = start
    while cursor < end:
        upper = min(cursor + timedelta(days=max_days), end)
        windows.append((cursor, upper))
        cursor = upper
    return windows


def _select_metric(metrics: dict) -> tuple[str | None, dict | None]:
    for key in _METRIC_KEYS:
        entries = [m for m in metrics.get(key) or [] if isinstance(m, dict)]
        if entries:
            primary = [m for m in entries if m.get("type") == "Primary"]
            return key, (primary or entries)[0]
    return None, None


def _number(value) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def parse_cve(item: dict) -> dict | None:
    """Convert one NVD ``vulnerabilities[]`` entry into a CVE node row.

    Fields the record does not contain stay ``None`` / empty - nothing is ever
    estimated or invented (many CVEs have no CVSS score or no CWE).
    """
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        return None
    cve_id = normalize_cve_id(cve.get("id"))
    if not cve_id:
        return None

    descriptions = [d for d in cve.get("descriptions") or [] if isinstance(d, dict)]
    english = [d.get("value") for d in descriptions if d.get("lang") == "en"]
    description = clean_text((english or [d.get("value") for d in descriptions] or [""])[0], 6000)

    _, metric = _select_metric(cve.get("metrics") or {})
    cvss = (metric or {}).get("cvssData") or {}
    severity = cvss.get("baseSeverity") or (metric or {}).get("baseSeverity")

    cwe_ids = []
    for weakness in cve.get("weaknesses") or []:
        for desc in (weakness or {}).get("description") or []:
            normalized = normalize_cwe_id((desc or {}).get("value"))   # drops NVD-CWE-noinfo etc.
            if normalized:
                cwe_ids.append(normalized)

    references, patches = [], []
    for ref in cve.get("references") or []:
        url = clean_text((ref or {}).get("url"), 500)
        if not url.startswith(("http://", "https://")):
            continue
        references.append(url)
        if _PATCH_TAGS & set((ref or {}).get("tags") or []):
            patches.append(url)

    products = []
    for config in cve.get("configurations") or []:
        for node in (config or {}).get("nodes") or []:
            for match in (node or {}).get("cpeMatch") or []:
                parts = str((match or {}).get("criteria", "")).split(":")
                if (match or {}).get("vulnerable") and len(parts) > 4:
                    products.append(f"{parts[3]}:{parts[4]}")

    row = {
        "id": cve_id,
        "name": cve_id,
        "description": description,
        "category": "Vulnerability",
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "cvss_version": str(cvss["version"]) if cvss.get("version") else None,
        "cvss_vector": cvss.get("vectorString"),
        "base_score": _number(cvss.get("baseScore")),
        "severity": str(severity).upper() if severity else None,
        "impact_score": _number((metric or {}).get("impactScore")),
        "exploitability_score": _number((metric or {}).get("exploitabilityScore")),
        "related_cwe_ids": dedupe(cwe_ids),
        "reference_urls": dedupe(references)[:20],
        "patch_urls": dedupe(patches)[:10],
        "affected_products": dedupe(products)[:25],
        "source": "NVD",
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }
    row["content_hash"] = content_hash(row)
    return row


class CVEUpdater:
    def __init__(self, db, embedder: EmbeddingClient, settings: Settings,
                 http_client: httpx.Client | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.db, self.embedder, self.settings = db, embedder, settings
        self._client = http_client
        self._sleep = sleep
        self._clock = clock
        # NVD: 5 requests / 30 s without a key, 50 / 30 s with one.
        self._request_interval = 0.7 if settings.nvd_api_key else 6.5
        self._last_request = 0.0

    # ------------------------------------------------------------------ #
    # HTTP
    # ------------------------------------------------------------------ #
    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = build_http_client(self.settings)
        return self._client

    def fetch_page(self, params: dict) -> dict:
        """One API page, rate-limited, retried, and schema-checked."""
        headers = {"apiKey": self.settings.nvd_api_key} if self.settings.nvd_api_key else {}
        last_problem = "malformed response"
        for attempt in range(3):
            wait = self._request_interval - (time.monotonic() - self._last_request)
            if wait > 0 and self._last_request:
                self._sleep(wait)
            response = http_get(self._http(), self.settings.nvd_api_url, params=params,
                                headers=headers, max_retries=self.settings.http_max_retries,
                                backoff_base=6.0, sleep=self._sleep)
            self._last_request = time.monotonic()
            try:
                body = response.json()
            except ValueError:
                body = None
            if (isinstance(body, dict) and isinstance(body.get("vulnerabilities"), list)
                    and isinstance(body.get("totalResults"), int)):
                return body
            last_problem = "response is not valid NVD CVE 2.0 JSON"
            log.warning("NVD returned a malformed page (attempt %d/3)", attempt + 1)
            self._sleep(6.0 * (attempt + 1))
        raise DataValidationError(f"NVD: {last_problem}")

    def iter_pages(self, base_params: dict, start_index: int = 0) -> Iterator[tuple[int, int, list]]:
        """Yield (next_start_index, total_results, vulnerabilities) for every page."""
        index = start_index
        while True:
            params = {**base_params, "startIndex": index,
                      "resultsPerPage": self.settings.nvd_results_per_page}
            body = self.fetch_page(params)
            items = body["vulnerabilities"]
            total = body["totalResults"]
            index += len(items)
            yield index, total, items
            if not items or index >= total:
                return

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #
    def persist(self, items: list) -> tuple[int, int]:
        """Write one page.  Returns (written, skipped_invalid)."""
        rows, skipped = [], 0
        for item in items:
            row = parse_cve(item)
            if row is None:
                skipped += 1
            else:
                rows.append(row)
        unique = list({row["id"]: row for row in rows}.values())
        if not unique:
            return 0, skipped
        stored = self.db.get_property_map(LABEL_CVE, [r["id"] for r in unique], "content_hash")
        if self.settings.embed_cves:
            attach_embeddings(self.db, self.embedder, LABEL_CVE, unique, EMBEDDING_TEXT[LABEL_CVE])
        now = utc_now_iso()
        to_write = [r for r in unique
                    if stored.get(r["id"]) != r["content_hash"] or "embedding" in r]
        for row in to_write:
            row["synced_at"] = now
        self.db.upsert_cves(to_write)
        return len(to_write), skipped

    # ------------------------------------------------------------------ #
    # Synchronisation
    # ------------------------------------------------------------------ #
    def sync(self, full: bool = False) -> SyncResult:
        started = self._clock()
        try:
            state = self.db.get_sync_state(SOURCE)
            self.db.save_sync_state(SOURCE, status="running",
                                    last_attempt_at=format_nvd_datetime(started))
            if full or not state.get("checkpoint"):
                stats = self._initial_sync(state, started, restart=full)
            else:
                stats = self._incremental_sync(parse_iso(state["checkpoint"]), started)
            finished = utc_now_iso()
            self.db.save_sync_state(SOURCE, status="success", last_error=None,
                                    last_success_at=finished, last_checked_at=finished,
                                    details=json.dumps(stats))
            log.info("nvd: %s", stats)
            return SyncResult(SOURCE, "success", records=stats["fetched"],
                              changed=stats["written"], details=stats)
        except Exception as exc:
            log.exception("nvd synchronisation failed")
            error = safe_error(exc)
            try:
                self.db.save_sync_state(SOURCE, status="failed", last_error=error,
                                        last_failure_at=utc_now_iso())
            except Exception:
                log.error("nvd: could not record the failure in Neo4j")
            return SyncResult(SOURCE, "failed", error=error)

    def _overlap(self) -> timedelta:
        return timedelta(minutes=self.settings.nvd_overlap_minutes)

    def _initial_sync(self, state: dict, started: datetime, restart: bool) -> dict:
        stats = {"mode": "initial", "fetched": 0, "written": 0, "skipped_invalid": 0, "windows": 0}
        if self.settings.nvd_sync_start_date:
            # Limited initial load: CVEs published on/after the configured date.
            begin = parse_iso(self.settings.nvd_sync_start_date)
            stats["mode"] = f"initial (published since {begin.date().isoformat()})"
            for lower, upper in split_windows(begin, started, self.settings.nvd_window_days):
                params = {"pubStartDate": format_nvd_datetime(lower),
                          "pubEndDate": format_nvd_datetime(upper)}
                for _, _, items in self.iter_pages(params):
                    self._account(stats, items)
                stats["windows"] += 1
        else:
            # Full catalogue, resumable: progress is saved after each stored page.
            resume = (not restart and state.get("full_sync_started_at")
                      and state.get("full_sync_next_index"))
            start_index = int(state["full_sync_next_index"]) if resume else 0
            if resume:
                started = parse_iso(state["full_sync_started_at"])
                stats["mode"] = f"initial (resumed at index {start_index})"
            else:
                self.db.save_sync_state(SOURCE, full_sync_started_at=format_nvd_datetime(started),
                                        full_sync_next_index=0)
            for next_index, total, items in self.iter_pages({}, start_index):
                self._account(stats, items)
                self.db.save_sync_state(SOURCE, full_sync_next_index=next_index,
                                        full_sync_total=total)
        # Everything up to `started` is stored: only now set the checkpoint.
        self.db.save_sync_state(SOURCE, checkpoint=format_nvd_datetime(started - self._overlap()),
                                full_sync_started_at=None, full_sync_next_index=None,
                                full_sync_completed_at=utc_now_iso())
        return stats

    def _incremental_sync(self, checkpoint: datetime, now: datetime) -> dict:
        stats = {"mode": "incremental", "fetched": 0, "written": 0, "skipped_invalid": 0,
                 "windows": 0}
        begin = checkpoint - self._overlap()
        for lower, upper in split_windows(begin, now, self.settings.nvd_window_days):
            params = {"lastModStartDate": format_nvd_datetime(lower),
                      "lastModEndDate": format_nvd_datetime(upper)}
            for _, _, items in self.iter_pages(params):
                self._account(stats, items)
            # The whole window is persisted -> the checkpoint may advance to its end.
            self.db.save_sync_state(SOURCE, checkpoint=format_nvd_datetime(upper))
            stats["windows"] += 1
        return stats

    def _account(self, stats: dict, items: list) -> None:
        written, skipped = self.persist(items)
        stats["fetched"] += len(items)
        stats["written"] += written
        stats["skipped_invalid"] += skipped
