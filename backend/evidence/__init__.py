"""Measured evidence that the remediation engine's patches actually work.

Three tiers, each answering a different question, each able to fail on its own:

| tier | question | whose answer it is | needs a network |
|---|---|---|---|
| 1 `execution` | does the patch stop a real exploit? | ours, by execution | no |
| 2 `semgrep_check` | does an independent detector stop reporting it? | Semgrep's | first run only |
| 3 `corpus` | what happens on real CVEs and real upstream fixes? | upstream's | yes |

Read `docs/evidence.md` for what they found and how to read their output.

Not imported by any runtime path. Nothing in `api/`, `services/`, or
`grpc_service/` depends on this package; it exists to be run by
`scripts/evidence_report.py` and to be asserted on by the tests. That is why it
is allowed to reach across the layer diagram into both `agents/` and
`scanners/`: it is verification, not a component in the request path, and a
component in the request path that reaches sideways would be a real layering
violation.
"""
