"""The checked-in advisory corpus, and the Tier 3 logic that consumes it.

These run with no network. The tests that need to fetch an upstream commit are
integration tests and skip themselves; everything checkable offline is checked
offline, so a checkout with no connectivity still gets this coverage.

The manifest is committed data with real identifiers in it, so the tests here are
about it being *well formed and honestly described* -- not about it being
convenient. A corpus of only the cases the engine handles would report a coverage
figure that means nothing, and that is asserted against below.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.agents.deterministic import _REWRITES
from backend.evidence.tier3 import (
    _NOT_SOURCE_DIRS,
    _NOT_SOURCE_FILES,
    MANIFEST_PATH,
    Advisory,
    _is_not_source,
    _summarise_lines,
    load_corpus,
)

# CWEs the rule table can act on, from the rewrites' own declarations. Used to
# check the corpus contains cases on *both* sides of this line.
COVERED_CWES = {cwe for rule in _REWRITES for cwe in rule.cwes}


@pytest.fixture(scope="module")
def corpus() -> tuple[Advisory, ...]:
    return load_corpus()


def test_the_manifest_is_committed_rather_than_fetched(corpus: tuple[Advisory, ...]) -> None:
    assert MANIFEST_PATH.is_file(), (
        "the manifest is committed so the corpus is auditable without a network. "
        "If you are seeing this in a fresh checkout, something removed a tracked file."
    )
    assert len(corpus) == 19


def test_every_advisory_carries_a_verifiable_identifier(corpus: tuple[Advisory, ...]) -> None:
    for advisory in corpus:
        assert advisory.advisory.startswith(("GHSA-", "PYSEC-"))
        assert advisory.repo.count("/") == 1, f"{advisory.advisory}: {advisory.repo}"
        assert advisory.package
        assert advisory.summary, f"{advisory.advisory} has no summary"


def test_every_advisory_carries_a_full_length_fix_commit(corpus: tuple[Advisory, ...]) -> None:
    """A 10-character SHA cannot be fetched.

    `git fetch origin <sha>` needs the full 40-character object name; an
    abbreviated one fails with "couldn't find remote ref", which is a confusing
    way to learn that a manifest field is too short.
    """
    for advisory in corpus:
        assert advisory.fix_commits, f"{advisory.advisory} has no fix commit"
        for sha in advisory.fix_commits:
            assert len(sha) == 40, f"{advisory.advisory}: {sha!r} is not a full SHA"
            assert all(c in "0123456789abcdef" for c in sha)


def test_the_corpus_spans_both_sides_of_the_rule_table(corpus: tuple[Advisory, ...]) -> None:
    """The point of the corpus.

    A corpus made only of CWEs the engine has a rewrite for would produce a
    flattering coverage number that means nothing. These assertions fail if
    someone trims the manifest down to the easy cases -- which is exactly the
    edit that would make this tier worthless while looking like an improvement.
    """
    cwes = {cwe for advisory in corpus for cwe in advisory.cwe_ids}
    covered = cwes & COVERED_CWES
    uncovered = cwes - COVERED_CWES
    assert covered, "no advisory in the corpus exercises a rule the engine has"
    assert uncovered, (
        "every advisory in the corpus is a CWE the engine can act on, which means the "
        "coverage number is measuring the corpus rather than the engine"
    )
    assert len({advisory.repo for advisory in corpus}) >= 6, "too few repositories"
    assert len(cwes) >= 8, "too few distinct CWEs"


def test_the_default_six_are_a_representative_sample(corpus: tuple[Advisory, ...]) -> None:
    """`runner.DEFAULT_TIER_LIMIT` fetches the first six.

    Alphabetically those were all aiohttp, none of which has a line any rule can
    act on, so a default run read as 0% coverage and looked broken rather than
    honest. This pins the curation.
    """
    from backend.evidence.runner import DEFAULT_TIER_LIMIT

    default = corpus[:DEFAULT_TIER_LIMIT]
    assert len({a.repo for a in default}) >= 4, "the default six are not spread across repos"
    assert len({c for a in default for c in a.cwe_ids}) >= 5
    # Both outcomes have to be present or the default run proves nothing either way.
    assert any(set(a.cwe_ids) & COVERED_CWES for a in default)
    assert any(not (set(a.cwe_ids) & COVERED_CWES) for a in default)


def test_the_manifest_documents_its_own_bias() -> None:
    document = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert "order" in document, "the deliberate ordering must be explained in the file"
    assert "caveats" in document, "the bias must be stated where the data lives"
    caveats = " ".join(document["caveats"]).lower()
    assert "upper bound" in caveats, (
        "the coverage figure is an upper bound because the candidate line is found by "
        "matching the rule table's own patterns. If that stops being said in the data "
        "file, the number starts being quoted as a detection rate."
    )


def test_no_upstream_source_is_vendored() -> None:
    """Licensing, and size.

    The manifest is metadata only. Committing someone else's source would import
    their licence and their maintenance burden for no benefit -- the fix commits
    are fetched on demand.
    """
    document = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for entry in document["advisories"]:
        assert set(entry) <= {
            "advisory",
            "package",
            "repo",
            "cwe_ids",
            "aliases",
            "fixed_in",
            "fix_commits",
            "why",
            "summary",
        }, f"{entry['advisory']} has a field the schema does not declare"
        assert "before" not in entry and "after" not in entry


def test_a_missing_manifest_is_an_explicit_error_not_a_silent_skip(
    tmp_path: Path,
) -> None:
    with pytest.raises(FileNotFoundError, match="committed"):
        load_corpus(tmp_path / "absent.json")


@pytest.mark.parametrize(
    "path",
    [
        "tests/unit/test_thing.py",
        "django/tests/__init__.py",
        "src/PIL/Tests/helper.py",
        "docs/conf.py",
        "examples/demo.py",
        "benchmarks/bench.py",
        "vendor/lib/thing.py",
        "conftest.py",
        "setup.py",
        # celery's test layout, which a substring rule for "test/" misses: the
        # directory is `t/` and the files are named `test_*.py`. It appeared in
        # the measured set and inflated the rejection count by one.
        "t/unit/backends/test_base.py",
        "t/unit/conftest.py",
        # and the filename half of the rule, for repositories that keep tests
        # alongside the code they test.
        "src/requests/test_requests.py",
        "pkg/handlers/user_test.py",
    ],
)
def test_test_and_docs_paths_are_excluded_from_the_counts(path: str) -> None:
    """A fix that rewrites a test is not a fix to the vulnerability.

    Including them would inflate both the coverage figure and the "would our
    reviewer reject a real fix" count with files that are not vulnerable code.
    """
    assert _is_not_source(path), path


@pytest.mark.parametrize(
    "path",
    [
        "aiohttp/client.py",
        "src/PIL/Image.py",
        "celery/app/main.py",
        "requests/sessions.py",
        "django/db/backends/oracle/creation.py",
        # A directory called `contest/` or a module called `testing_utils.py`
        # must not be swept up by a component match.
        "app/contest/entry.py",
        "src/testing_utils.py",
    ],
)
def test_real_source_paths_are_not_excluded(path: str) -> None:
    assert not _is_not_source(path)
    parts = path.lower().split("/")
    assert not (set(parts[:-1]) & _NOT_SOURCE_DIRS)
    assert parts[-1] not in _NOT_SOURCE_FILES


def test_line_summaries_read_as_a_sentence() -> None:
    assert _summarise_lines(()) == "nothing"
    assert _summarise_lines((7,)) == "line 7"
    assert _summarise_lines((3, 4, 5)) == "3 lines (3-5)"
