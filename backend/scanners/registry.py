"""Scanner registry -- the only place that knows which scanners exist.

Constructed once at gRPC server startup from `SENTINEL_ENABLED_SCANNERS`.
Everything above this layer asks the registry for a scanner by name, so
adding one is: implement `Scanner`, add a line to `_FACTORIES`, done.

Unavailability is resolved here rather than at request time. A scanner whose
binary is missing is registered with `available=False` and a reason, and the
health endpoint reports it. A `Scan` request naming an unavailable scanner
fails loudly with that reason, which is the difference between "we found
nothing" and "we could not look" -- and getting that wrong in the other
direction is how a real critical ships unnoticed.
"""

from __future__ import annotations

from backend.config.settings import Settings, get_settings
from backend.core.logging import get_logger
from backend.database.enums import ScannerKind
from backend.scanners.base import Scanner, ScannerUnavailableError
from backend.scanners.fixture import FixtureScanner
from backend.scanners.semgrep import SemgrepScanner

logger = get_logger(__name__)


class ScannerRegistry:
    """Name-to-scanner lookup, with availability already resolved."""

    def __init__(self, scanners: list[Scanner] | None = None) -> None:
        self._scanners: dict[ScannerKind, Scanner] = {}
        for scanner in scanners or []:
            self.register(scanner)

    def register(self, scanner: Scanner) -> None:
        """Add a scanner, replacing any existing one of the same kind.

        Replacement (rather than rejection) so a test can substitute a fake
        scanner without having to un-register the real one first.
        """
        self._scanners[scanner.kind] = scanner

    def get(self, kind: ScannerKind) -> Scanner:
        """Return an *available* scanner, or raise.

        Raises `ScannerUnavailableError` for both "no such scanner" and "that
        scanner cannot run here", because from the caller's perspective those
        are the same failure and both must surface as an error rather than an
        empty result.
        """
        scanner = self._scanners.get(kind)
        if scanner is None:
            known = ", ".join(sorted(k.value for k in self._scanners)) or "none"
            raise ScannerUnavailableError(
                f"scanner {kind.value!r} is not registered on this service (registered: {known})"
            )
        if not scanner.available:
            raise ScannerUnavailableError(
                f"scanner {kind.value!r} is registered but unavailable: "
                f"{scanner.unavailable_reason or 'no reason given'}"
            )
        return scanner

    def all(self) -> list[Scanner]:
        """Every registered scanner, available or not."""
        return list(self._scanners.values())

    def available_kinds(self) -> list[ScannerKind]:
        """Scanner kinds that can actually run right now."""
        return [k for k, s in self._scanners.items() if s.available]

    def describe(self) -> dict[str, str]:
        """`{kind: description}` for the health endpoint and startup logging."""
        return {str(kind): scanner.describe() for kind, scanner in self._scanners.items()}


_FACTORIES: dict[str, type[Scanner]] = {
    ScannerKind.FIXTURE.value: FixtureScanner,
    ScannerKind.SEMGREP.value: SemgrepScanner,
}


def build_registry(settings: Settings | None = None) -> ScannerRegistry:
    """Build the registry described by `SENTINEL_ENABLED_SCANNERS`.

    A name in the setting with no matching factory is a configuration error
    and is logged loudly, then skipped -- startup continues with the scanners
    that do exist, because refusing to start over one bad config value in a
    portfolio project is worse than starting degraded and saying so.
    """
    resolved = settings or get_settings()
    scanners: list[Scanner] = []

    for name in resolved.enabled_scanners:
        factory = _FACTORIES.get(name.strip().lower())
        if factory is None:
            known = ", ".join(sorted(_FACTORIES))
            logger.error(
                "ignoring unknown scanner in SENTINEL_ENABLED_SCANNERS name=%s known=%s",
                name,
                known,
            )
            continue

        if factory is FixtureScanner:
            scanner: Scanner = FixtureScanner(resolved.fixtures_dir)
        elif factory is SemgrepScanner:
            scanner = SemgrepScanner(resolved.semgrep_binary)
        else:  # pragma: no cover - unreachable while _FACTORIES has two entries
            scanner = factory()

        scanners.append(scanner)

    if not scanners:
        logger.error(
            "no usable scanners configured; every scan will fail. "
            "Set SENTINEL_ENABLED_SCANNERS (default: fixture)."
        )

    registry = ScannerRegistry(scanners)
    for description in registry.describe().values():
        logger.info("registered scanner %s", description)
    return registry
