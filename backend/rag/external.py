"""Last retrieval step: records the curated graph does not hold, read live from the NVD.

Only a CVE identifier or the product / vulnerability words of the question are sent, never the
question itself. One attempt with a short timeout: a user is waiting for the answer.
"""
from __future__ import annotations

import logging
import threading
import time

import httpx

from backend.config import Settings
from backend.updater.cve_updater import parse_cve

log = logging.getLogger(__name__)

TIMEOUT_SECONDS = 12.0
CACHE_SECONDS = 3600
WINDOW_SECONDS = 30.0


class NVDLookup:
    def __init__(self, settings: Settings, http_client: httpx.Client | None = None):
        self.settings, self._client = settings, http_client
        self._cache: dict[tuple, tuple[float, dict]] = {}
        self._sent: list[float] = []
        self._limit = 25 if settings.nvd_api_key else 4      # below the NVD's own limits
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.settings.nvd_live_lookup

    def _get(self, **params) -> dict | None:
        """The NVD's answer, or None when it could not be reached."""
        key, now = tuple(sorted(params.items())), time.monotonic()
        with self._lock:
            if key in self._cache and now - self._cache[key][0] < CACHE_SECONDS:
                return self._cache[key][1]
            self._sent = [t for t in self._sent if now - t < WINDOW_SECONDS]
            if len(self._sent) >= self._limit:
                return None
            self._sent.append(now)
        try:
            if self._client is None:
                self._client = httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=True)
            response = self._client.get(
                self.settings.nvd_api_url, params=params,
                headers={"apiKey": self.settings.nvd_api_key} if self.settings.nvd_api_key else {})
            if response.status_code == 404:
                body = {"vulnerabilities": [], "totalResults": 0}
            else:
                response.raise_for_status()
                body = response.json()
            if not isinstance(body.get("vulnerabilities"), list):
                return None
        except (httpx.HTTPError, ValueError, AttributeError) as exc:
            log.warning("Live NVD lookup failed (%s)", type(exc).__name__)
            return None
        with self._lock:
            if len(self._cache) >= 200:
                self._cache.pop(next(iter(self._cache)))
            self._cache[key] = (now, body)
        return body

    def cve(self, identifier: str) -> tuple[dict | None, bool]:
        """(record or None, whether the NVD answered)."""
        if not self.enabled:
            return None, False
        body = self._get(cveId=identifier)
        rows = [parse_cve(item) for item in (body or {}).get("vulnerabilities", [])]
        return next((r for r in rows if r and r["id"] == identifier and r["description"]), None), body is not None

    def search(self, words: list[str], limit: int = 5) -> tuple[list[dict], int]:
        """The newest records whose description contains every word, and how many there are."""
        if not self.enabled or not words:
            return [], 0
        query, page = " ".join(words), 20
        body = self._get(keywordSearch=query, resultsPerPage=page)
        total = int((body or {}).get("totalResults") or 0)
        if total > page:                          # the NVD lists the oldest first
            body = self._get(keywordSearch=query, resultsPerPage=page, startIndex=total - page) or body
        rows = [r for r in (parse_cve(i) for i in (body or {}).get("vulnerabilities", []))
                if r and r["description"] and r["vuln_status"] != "Rejected"]
        rows.sort(key=lambda r: r["published"] or "", reverse=True)
        return rows[:limit], total
