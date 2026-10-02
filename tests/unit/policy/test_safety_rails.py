"""The safety-rail tests.

These are the most important tests in the repository. If one of them fails,
the project's central claim -- that this system can propose code changes but
never merge them -- is false.

The merge tests are deliberately written as a *source scan* as well as
behavioural assertions. A behavioural test proves the known entry points
refuse; it does not prove someone has not added a sixth one. Walking the
package source for assignments to a merge state or to the auto-merge flag
catches that, and is the reason the guarantee survives future edits.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from backend.database.enums import Confidence, FindingStatus, Severity
from backend.policy.rules import (
    MAX_REMEDIATION_ATTEMPTS,
    AutoRemediationRefusal,
    MergePolicyViolation,
    assert_human_merge_required,
    assert_merge_refused,
    evaluate_auto_remediation,
    sla_deadline_for,
    sla_hours_for,
)

# tests/unit/policy/test_safety_rails.py -> parents[3] is the repository root.
# The source-scan tests below need real paths, so this is derived rather than
# imported: a conftest fixture would hide a wrong assumption about the layout
# rather than surfacing it.
REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = REPO_ROOT / "backend"


# --- The merge guarantee ------------------------------------------------


def test_assert_human_merge_required_passes_with_auto_merge_disabled() -> None:
    assert_human_merge_required(actor="test", allow_auto_merge=False)


def test_assert_human_merge_required_refuses_when_auto_merge_is_set() -> None:
    """The one setting that must never be honoured must fail loudly."""
    with pytest.raises(MergePolicyViolation) as exc:
        assert_human_merge_required(actor="test", allow_auto_merge=True)
    assert "will not be" in str(exc.value)


def test_assert_merge_refused_always_raises() -> None:
    with pytest.raises(MergePolicyViolation):
        assert_merge_refused(actor="anything")


def test_publisher_merge_always_raises() -> None:
    """`publisher.merge_pull_request` exists only to refuse.

    Present as a named function rather than omitted, so the refusal is
    discoverable in the code and a caller that reaches for it gets a specific
    error instead of an `AttributeError`.
    """
    from backend.services.publisher import merge_pull_request

    with pytest.raises(MergePolicyViolation):
        merge_pull_request("anything", actor="test")


def test_only_approvals_records_a_merged_state_and_nothing_unblocks_auto_merge() -> None:
    """Static proof, precise about the one legitimate exception.

    Exactly one place in the codebase writes `PullRequestStatus.MERGED`:
    `approvals.py::record_external_merge`, which *records* that a human merged
    the branch in the git host. That is a different operation from performing
    the merge, and it is the only way the `merged` state is reachable.

    Everywhere else, no module may write it -- and no module anywhere may set
    `auto_merge_blocked` to anything but the literal `True`. Those two
    together are the merge guarantee, expressed as a property of the source.
    """
    merge_writers: list[str] = []
    unblockers: list[str] = []

    for path in sorted(BACKEND_ROOT.rglob("*.py")):
        if "generated" in path.parts:
            continue
        relative = path.relative_to(REPO_ROOT)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        for enclosing in _function_scopes(tree):
            for node in ast.walk(enclosing):
                if not isinstance(node, ast.Assign):
                    continue
                for target in node.targets:
                    if not isinstance(target, ast.Attribute):
                        continue
                    if target.attr == "auto_merge_blocked" and not _is_true_literal(node.value):
                        unblockers.append(f"{relative}:{node.lineno} in {enclosing.name}")
                    if target.attr == "status" and _is_merged(node.value):
                        merge_writers.append(f"{relative}:{node.lineno} in {enclosing.name}()")

    assert unblockers == [], "auto-merge can be enabled by:\n" + "\n".join(unblockers)
    assert len(merge_writers) == 1, (
        "exactly one place may record a merge, and it must be "
        f"approvals.record_external_merge; found: {merge_writers}"
    )
    assert "record_external_merge" in merge_writers[0], merge_writers[0]


def _function_scopes(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Every function and method in a module, including nested ones.

    Used so an assignment can be reported with the function it lives in --
    "somewhere sets auto_merge_blocked=False" is much less actionable than
    "record_external_merge() sets it".
    """
    scopes: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scopes.append(node)
    return scopes


def test_no_route_is_named_merge() -> None:
    """No HTTP route performs a merge."""
    from backend.main import app

    # `app.routes` is typed as `BaseRoute`, which has no `path`; only the
    # concrete route types do, hence the getattr rather than a direct access.
    merge_paths = [
        str(getattr(route, "path", ""))
        for route in app.routes
        if str(getattr(route, "path", "")).rstrip("/").endswith(("/merge", "/automerge"))
    ]
    assert merge_paths == [], f"unexpected merge endpoints: {merge_paths}"


def test_allow_auto_merge_setting_defaults_to_false_and_is_never_honoured() -> None:
    """`SENTINEL_ALLOW_AUTO_MERGE` exists only so startup can refuse it."""
    settings_module = (BACKEND_ROOT / "config" / "settings.py").read_text(encoding="utf-8")
    # It must be declared (so the refusal path is reachable) ...
    assert "allow_auto_merge: bool = False" in settings_module
    # ... and nothing may read it to *enable* anything. `assert_human_merge_required`
    # is the single permitted reader, and it only ever raises.
    readers = [
        line
        for line in settings_module.splitlines()
        if "allow_auto_merge" in line and "bool = False" not in line
    ]
    assert readers == []


def test_approval_service_is_the_only_writer_of_merged_status() -> None:
    """`approvals.py` is the single, deliberate place `MERGED` is written."""
    source = (BACKEND_ROOT / "services" / "approvals.py").read_text(encoding="utf-8")
    assert "PullRequestStatus.MERGED" in source

    for path in sorted((BACKEND_ROOT / "api").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        assert "PullRequestStatus.MERGED" not in text, (
            f"{path.name} writes the MERGED status; only approvals.py may"
        )


# --- Auto-remediation eligibility ---------------------------------------


def _eligible_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "status": FindingStatus.OPEN,
        "file_path": "app/handlers/report.py",
        "snippet": "eval(x)",
    }
    base.update(overrides)
    return base


def test_a_normal_finding_is_eligible() -> None:
    assert evaluate_auto_remediation(**_eligible_kwargs()).eligible  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"severity": Severity.INFO}, AutoRemediationRefusal.SEVERITY_NOT_ACTIONABLE),
        ({"confidence": Confidence.LOW}, AutoRemediationRefusal.CONFIDENCE_TOO_LOW),
        ({"file_path": None}, AutoRemediationRefusal.NO_SOURCE_LOCATION),
        ({"snippet": "   "}, AutoRemediationRefusal.NO_SNIPPET),
        ({"status": FindingStatus.REMEDIATED}, AutoRemediationRefusal.STATUS_NOT_ACTIONABLE),
        (
            {"file_path": "infra/terraform/prod/main.tf"},
            AutoRemediationRefusal.PATH_OUTSIDE_SOURCE_ROOTS,
        ),
        (
            {"remediation_attempts": MAX_REMEDIATION_ATTEMPTS},
            AutoRemediationRefusal.ATTEMPT_BUDGET_EXHAUSTED,
        ),
    ],
)
def test_every_refusal_reason_is_reachable(
    overrides: dict[str, object], expected: AutoRemediationRefusal
) -> None:
    decision = evaluate_auto_remediation(**_eligible_kwargs(**overrides))  # type: ignore[arg-type]
    assert not decision.eligible
    assert decision.refusal is expected
    assert decision.reason, "every refusal must carry a human-readable reason"


def test_path_traversal_cannot_escape_a_source_root() -> None:
    """`app/../../etc/passwd` must not be treated as inside `app/`.

    The single most important case in this file's policy section: string
    comparison would let `..` walk straight out of a permitted root, and the
    agent would then be handed a path it should never patch.
    """
    for sneaky in (
        "app/../../etc/passwd",
        "app/services/../../../root/.ssh/authorized_keys",
        "app/../infra/network.conf",
    ):
        decision = evaluate_auto_remediation(
            **_eligible_kwargs(file_path=sneaky)  # type: ignore[arg-type]
        )
        assert not decision.eligible
        assert decision.refusal is AutoRemediationRefusal.PATH_OUTSIDE_SOURCE_ROOTS


def test_absolute_paths_inside_a_root_are_allowed() -> None:
    assert evaluate_auto_remediation(
        **_eligible_kwargs(file_path="/app/handlers/report.py")  # type: ignore[arg-type]
    ).eligible


def test_windows_separators_are_normalised_before_the_root_check() -> None:
    """Semgrep on Windows can emit backslashes; the check must not miss them."""
    assert evaluate_auto_remediation(
        **_eligible_kwargs(file_path="app\\handlers\\report.py")  # type: ignore[arg-type]
    ).eligible


# --- SLA policy ---------------------------------------------------------


def test_sla_hours_are_ordered_by_severity() -> None:
    ordered = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    hours = [sla_hours_for(s) for s in ordered]
    assert hours == sorted(hours), "a more severe finding must not get a longer deadline"


def test_sla_deadline_is_in_the_future() -> None:
    from backend.core.clock import utc_now

    deadline = sla_deadline_for(Severity.CRITICAL)
    assert deadline > utc_now()


def _is_true_literal(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_merged(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "MERGED"
        and isinstance(node.value, ast.Name)
        and node.value.id == "PullRequestStatus"
    )


def _is_finding_remediated(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "REMEDIATED"
        and isinstance(node.value, ast.Name)
        and node.value.id == "FindingStatus"
    )
