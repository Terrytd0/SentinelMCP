"""Tier 3 against real upstream fix commits.

Integration, because it needs `git` and the network. It skips itself when either
is absent, and -- more importantly -- it skips when an individual advisory
cannot be fetched, so one upstream repository moving a commit does not turn into
a red suite. Rule 1: a bare `pytest` with nothing running must pass.

The assertions here are about the *harness being honest*, not about the engine
scoring well. A corpus that failed whenever coverage dropped would be a test that
punishes the truth.
"""

from __future__ import annotations

import subprocess

import pytest

from backend.evidence.tier3 import (
    _fetch,
    _git_version,
    _is_not_source,
    _parents,
    _prepare_repo,
    _real_fixes,
    load_corpus,
    run_tier_3,
)


def _git() -> bool:
    return bool(_git_version())


def _can_reach_github() -> bool:
    if not _git():
        return False
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "ls-remote", "--exit-code", "https://github.com/psf/requests", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
    except OSError:
        return False
    return completed.returncode == 0


pytestmark = pytest.mark.integration


def test_the_corpus_loads_with_no_network() -> None:
    """Committed data has to be readable offline.

    Tier 3's value depends on the manifest being auditable, and a manifest that
    is only reachable with a network is not auditable.
    """
    corpus = load_corpus()
    assert len(corpus) == 19


def test_the_tier_skips_with_a_reason_when_git_is_missing() -> None:
    import backend.evidence.tier3 as tier3

    original = tier3._git_version
    tier3._git_version = lambda: ""  # type: ignore[assignment]
    try:
        result = tier3.run_tier_3(limit=1)
    finally:
        tier3._git_version = original  # type: ignore[assignment]
    assert not result.runs
    assert "git" in result.skipped_reason
    assert result.manifest, "the manifest is still reported even when the tier cannot run"


def test_a_manifest_without_a_full_sha_is_a_reported_failure_not_a_crash() -> None:
    import backend.evidence.tier3 as tier3
    from backend.evidence.tier3 import Advisory

    advisory = Advisory(
        advisory="GHSA-test",
        package="p",
        repo="o/r",
        cwe_ids=("CWE-1",),
        aliases=(),
        fixed_in=(),
        fix_commits=("abc1234",),
        why="",
        summary="",
    )
    outcome = tier3._run_one(advisory, cache_dir=tier3.CACHE_DIR)
    assert outcome.status == "fetch-failed"
    assert "full-length" in outcome.detail
    assert not outcome.files


def test_an_unreachable_commit_is_reported_rather_than_guessed() -> None:
    import backend.evidence.tier3 as tier3
    from backend.evidence.tier3 import Advisory

    advisory = Advisory(
        advisory="GHSA-test",
        package="p",
        repo="psf/requests",
        cwe_ids=("CWE-200",),
        aliases=(),
        fixed_in=(),
        fix_commits=("0" * 40,),
        why="",
        summary="",
    )
    outcome = tier3._run_one(advisory, cache_dir=tier3.CACHE_DIR)
    assert outcome.status == "fetch-failed"
    assert outcome.detail, "a failure with no reason is a failure with no diagnosis"
    assert not outcome.files, "a failed fetch must contribute nothing to any count"


def test_a_real_fix_fetched_from_upstream() -> None:
    """The one advisory whose fix is a single, clean, well-understood change.

    `requests` GHSA-j8r2-6x86-q33q: the fix commit strips `Proxy-Authorization`
    from TLS-tunnelled redirects. Small, so the assertions can be exact about
    *where* upstream changed the file and what it produced.
    """
    if not _can_reach_github():
        pytest.skip("git is missing or github is unreachable")

    corpus = {a.advisory: a for a in load_corpus()}
    advisory = corpus["GHSA-j8r2-6x86-q33q"]
    import backend.evidence.tier3 as tier3

    repo_dir = tier3.CACHE_DIR / advisory.repo.replace("/", "__")
    _prepare_repo(repo_dir, advisory.repo)
    _fetch(repo_dir, advisory.fix_commits[0])
    parents = _parents(repo_dir, advisory.fix_commits[0])
    assert parents, "the fetched commit has no resolvable parent"

    fixes = _real_fixes(repo_dir, parents[0], advisory.fix_commits[0])
    sessions = next((f for f in fixes if f.path.endswith("sessions.py")), None)
    assert sessions is not None, [f.path for f in fixes]
    assert sessions.lines_changed, "the real fix touched no lines we can compare against"
    assert sessions.added_lines > 0

    # The label has to be *real*: the vulnerable content must still contain the
    # construct and the fixed content must not.
    assert "Proxy-Authorization" in sessions.before
    assert sessions.before != sessions.after
    assert all(not _is_not_source(f.path) for f in fixes), (
        "test or docs paths leaked into the measured set"
    )


def test_the_tier_reports_engagement_without_claiming_more_than_it_measured() -> None:
    if not _can_reach_github():
        pytest.skip("git is missing or github is unreachable")
    result = run_tier_3(limit=6)
    assert result.runs
    assert len(result.measured) == 6

    engaged = [f for o in result.measured for f in o.engaged]
    for file_outcome in engaged:
        assert file_outcome.our_line is not None
        assert file_outcome.our_rewrite, "a proposed patch with no rewrite behind it"
        assert file_outcome.same_line_as_upstream in (True, False)
        assert file_outcome.real_lines, "no upstream lines to compare against"

    # Both reviewer measurements have to be taken and both have to be explained.
    # Reporting only the one-line number would be measuring the harness: the
    # reviewer is given a snippet and a diff and nothing else, so judging an
    # 18-line fix against one line is out of scope by construction.
    reviewed = result.real_fixes_reviewed
    assert reviewed, "no real fix was run through the reviewer at all"
    for file_outcome in reviewed:
        assert file_outcome.real_fix_would_pass in (True, False)
        assert file_outcome.real_fix_would_pass_with_context in (True, False)
        assert file_outcome.context_lines > 0
    for file_outcome in result.real_fixes_rejected:
        assert file_outcome.real_fix_comments, "a rejection with no stated reason"

    # The gap is the finding. It is not asserted to be a particular number --
    # the whole point is that it is *measured* rather than assumed -- but a
    # regression that closed it entirely would mean the context block had
    # quietly grown into the whole file, which is the version of this test that
    # would be measuring nothing.
    assert len(result.real_fixes_rejected) >= len(result.real_fixes_rejected_with_context), (
        "more fixes rejected with context than without it, which cannot be right: "
        "giving the reviewer more source can only change a verdict, never invent "
        "an objection it could not have had"
    )
