"""Local CVE advisory lookup, backing the `get_cve_details` MCP tool.

A local JSON feed rather than a live NVD API call, for one reason that matters
in this domain: an analyst triaging a finding is often handling a
confidentiality-sensitive leak report, and the prospect list here is a managed
security provider's customer base. Firing every `get_cve_details` at
`services.nvd.nist.gov` tells that third party which CVEs an Ironclad customer
is currently worried about, at what volume, at what times of day.

The feed is a plain JSON file (`data/cve/advisories.json`) and `_load` re-reads
it when its mtime changes, so a scheduled refresh job can replace the file
atomically without restarting the process or changing this service. A real
deployment would keep the local cache but add rate-limited upstream refresh,
never synchronous per-request lookups.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from backend.core.logging import get_logger
from backend.database.enums import Severity

logger = get_logger(__name__)

# CVSS v3 base score bands. Used to sanity-check the feed rather than to
# compute a severity -- the advisory's own severity is authoritative, because
# it is the one the analyst will be held to.
_CVSS_BANDS: tuple[tuple[float, str], ...] = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)


class CveNotFoundError(LookupError):
    """No advisory for this CVE id in the local feed."""


class CveService:
    """Read-only advisory lookup over a local JSON feed."""

    def __init__(self, feed_path: str | Path = "data/cve/advisories.json") -> None:
        self._feed_path = Path(feed_path)
        self._lock = threading.Lock()
        self._cache: dict[str, dict[str, Any]] | None = None
        self._mtime: float | None = None

    def _load(self) -> dict[str, dict[str, Any]]:
        """Read and cache the feed.

        Cached on first use and re-read on every mtime change, so an operator
        can drop in a refreshed feed without restarting the process. A missing
        or corrupt file yields an empty feed rather than an exception:
        `get_cve_details` on an unknown CVE then returns a clean "not in the
        local feed" answer, which is more useful than a 500.
        """
        with self._lock:
            if self._cache is not None and self._feed_path.exists():
                if self._mtime is not None and self._feed_path.stat().st_mtime == self._mtime:
                    return self._cache

            if not self._feed_path.exists():
                logger.warning(
                    "CVE feed not found path=%s; advisory lookups will miss", self._feed_path
                )
                self._cache = {}
                self._mtime = None
                return self._cache

            try:
                document = json.loads(self._feed_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.error(
                    "CVE feed unreadable path=%s error_type=%s", self._feed_path, type(exc).__name__
                )
                self._cache = {}
                self._mtime = None
                return self._cache

            advisories = document if isinstance(document, dict) else {}
            normalized: dict[str, dict[str, Any]] = {}
            for key, value in advisories.items():
                if not isinstance(value, dict):
                    continue
                cve_id = str(value.get("cve_id") or key).strip().upper()
                normalized[cve_id] = value

            self._cache = normalized
            self._mtime = self._feed_path.stat().st_mtime
            logger.info("loaded CVE feed advisories=%d", len(normalized))
            return normalized

    def get(self, cve_id: str) -> dict[str, Any]:
        """Return one advisory, or raise `CveNotFoundError`.

        Case-insensitive on the id, because CVEs get typed as `cve-2024-22195`
        at least as often as `CVE-2024-22195` and a lookup that fails on a
        case difference looks like a broken tool.
        """
        normalized = cve_id.strip().upper()
        feed = self._load()
        advisory = feed.get(normalized)
        if advisory is None:
            known = ", ".join(sorted(feed)[:5]) or "none"
            raise CveNotFoundError(
                f"no advisory for {normalized!r} in the local feed (loaded: {known})"
            )
        return self._normalize(advisory)

    def get_many(self, cve_ids: list[str]) -> dict[str, dict[str, Any] | None]:
        """Look up several ids at once. Missing ids map to `None`.

        Deliberately does not raise on a miss: this backs the
        `get_cve_details` tool, where a finding that references one known and
        one unknown CVE should return the known advisory, not an error.
        """
        feed = self._load()
        resolved: dict[str, dict[str, Any] | None] = {}
        for cve_id in cve_ids:
            key = cve_id.strip().upper()
            advisory = feed.get(key)
            resolved[key] = self._normalize(advisory) if advisory else None
        return resolved

    def search(self, *, product: str | None = None, min_cvss: float = 0.0) -> list[dict[str, Any]]:
        """Advisories affecting a product, at or above a CVSS floor."""
        feed = self._load()
        matches: list[dict[str, Any]] = []
        needle = product.strip().lower() if product else None

        for advisory in feed.values():
            if float(advisory.get("cvss_score") or 0.0) < min_cvss:
                continue
            if needle is not None:
                products = [
                    str(entry.get("product", "")).lower()
                    for entry in advisory.get("affected_products") or []
                    if isinstance(entry, dict)
                ]
                if not any(needle in p for p in products):
                    continue
            matches.append(self._normalize(advisory))

        matches.sort(key=lambda a: float(a.get("cvss_score") or 0.0), reverse=True)
        return matches

    @staticmethod
    def _normalize(advisory: dict[str, Any]) -> dict[str, Any]:
        """Fill in derived fields the feed does not carry.

        A finding that claims `severity: critical` for a CVSS 4.2 advisory is
        mislabelled somewhere upstream, and a triage tool that silently passes
        that through teaches analysts to distrust the severity column. Adding
        the derived band lets the caller show both and see the disagreement.
        """
        score = float(advisory.get("cvss_score") or 0.0)
        band = next((label for threshold, label in _CVSS_BANDS if score >= threshold), "none")
        declared = str(advisory.get("severity") or band).strip().lower()
        return {
            **advisory,
            "cve_id": str(advisory.get("cve_id", "")).strip().upper(),
            "cvss_band": band,
            "declared_severity": declared,
            "severity_mismatch": declared != band and band != "none",
            "severity": Severity(declared)
            if declared in {s.value for s in Severity}
            else Severity.MEDIUM,
        }
