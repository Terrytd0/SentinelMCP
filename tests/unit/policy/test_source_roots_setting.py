"""`SENTINEL_REMEDIATION_SOURCE_ROOTS` has to actually govern policy.

The writable-area allow-list is one of the safety rails: if the agent may only
draft patches under `app/`, `src/`, and friends, then it cannot propose a change
to `infra/terraform/prod/`. That guarantee is worth nothing if the operator
cannot change the list, and it is worth *less* than nothing if changing the env
var silently does nothing while the settings object advertises it.

These tests exist because the setting was previously declared, documented, and
read by nothing -- the policy module fell back to a hardcoded tuple with the same
values, so the behaviour looked correct and the configurability was fictional.
Same value, same behaviour: exactly why nothing failed.
"""

from __future__ import annotations

import pytest

from backend.config.settings import get_settings
from backend.database.enums import Confidence, FindingStatus, Severity
from backend.policy.rules import DEFAULT_SOURCE_ROOTS, evaluate_auto_remediation

# No `integration` marker: this is a pure unit test of a pure function. It needs
# no database and no socket, so making it wait for services would be a lie.


def _evaluate(file_path: str, source_roots: tuple[str, ...] | None = None) -> bool:
    """Run the policy gate over an otherwise-perfectly-eligible finding."""
    return evaluate_auto_remediation(
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        status=FindingStatus.OPEN,
        file_path=file_path,
        snippet="result = eval(user_input)",
        remediation_attempts=0,
        source_roots=source_roots,
    ).eligible


# --- the default is the documented allow-list -----------------------------


def test_the_default_roots_match_the_policy_module_constant() -> None:
    """Settings and the policy module must not drift apart."""
    assert tuple(get_settings().remediation_source_roots) == DEFAULT_SOURCE_ROOTS


@pytest.mark.parametrize(
    "path",
    [
        "app/views.py",
        "src/payments/client.py",
        "services/payments/api.py",
        "lib/util.py",
        "config/settings.toml",
    ],
)
def test_paths_under_the_default_roots_are_allowed(path: str) -> None:
    assert _evaluate(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "infra/terraform/prod/main.tf",
        "deploy/helm/values.yaml",
        "README.md",
        "scripts/seed.py",
    ],
)
def test_paths_outside_the_default_roots_are_refused(path: str) -> None:
    """The point of the allow-list: a finding the agent must not touch."""
    assert _evaluate(path) is False


# --- operator configurability --------------------------------------------


def test_a_configured_allow_list_replaces_the_default() -> None:
    """Narrowing the roots must actually narrow what the agent may patch."""
    assert _evaluate("app/views.py", source_roots=("services/",)) is False
    assert _evaluate("services/payments/api.py", source_roots=("services/",)) is True


def test_a_widened_allow_list_really_widens() -> None:
    assert _evaluate("infra/main.tf", source_roots=("infra/",)) is True


def test_an_empty_allow_list_refuses_everything() -> None:
    """Fail closed. An operator who empties the list gets no patches, not all of them."""
    assert _evaluate("app/views.py", source_roots=()) is False


# --- traversal is not a way around the allow-list ------------------------


@pytest.mark.parametrize(
    "path",
    [
        "app/../../etc/passwd",
        "app/../../../root/.ssh/authorized_keys",
        "services/../../secrets.env",
    ],
)
def test_traversal_out_of_an_allowed_prefix_is_refused(path: str) -> None:
    """A path that *starts* inside an allowed root can still escape it.

    This is the whole reason `_path_within_roots` resolves both sides to absolute
    paths before comparing, rather than doing a `startswith` on the string.
    """
    assert _evaluate(path) is False
