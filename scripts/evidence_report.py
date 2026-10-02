"""Produce the measured-evidence report for the remediation engine.

    python scripts/evidence_report.py                  # tiers 1, 2, and 3 (6 advisories)
    python scripts/evidence_report.py --all            # all 19 advisories
    python scripts/evidence_report.py --tiers 1 2      # skip the network tier
    python scripts/evidence_report.py --markdown -o docs/evidence-results.md

Exit code 0 when nothing measured failed, 1 when a tier failed a case, a tier 2
rule set was vacuous, or a Tier 3 advisory could not be fetched. Declines,
regressions and human steps are results, not failures -- see
`backend/evidence/runner.py::exit_code`.

Deliberately not a pytest module, for the same reason `scripts/smoke_e2e.py` is
not: this has to run on a machine with no test framework and no database.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.evidence.runner import (  # noqa: E402
    DEFAULT_TIER_LIMIT,
    build_report,
    exit_code,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--tiers",
        nargs="+",
        choices=["1", "2", "3"],
        default=["1", "2", "3"],
        help="which tiers to run (default: all three)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help=f"fetch every advisory in the manifest, not just {DEFAULT_TIER_LIMIT}",
    )
    parser.add_argument(
        "--corpus-limit",
        type=int,
        default=DEFAULT_TIER_LIMIT,
        help=f"advisories to fetch in tier 3 (default: {DEFAULT_TIER_LIMIT})",
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=None,
        help="the tree tier 2 patches and rescans (default: data/samples/vulnerable_app)",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="emit Markdown rather than the terminal report",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write to this file as well as stdout",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = build_report(
        tiers=tuple(args.tiers),
        corpus_limit=None if args.all else args.corpus_limit,
        target=args.target,
    )
    text = report.to_markdown() if args.markdown else report.to_text()
    print(text)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"\nwrote {args.output}", file=sys.stderr)
    return exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
