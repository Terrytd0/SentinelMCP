"""`enrich_snippet`: how much source the remediation loop is shown.

The property that matters is not "returns more lines". It is **never returns less
than the scanner reported**, because the failure mode of getting this wrong is an
agent that has been shown less than it used to be, and a fix nobody can reproduce.

Each test also pins *which* strategy was used, because the strategy is recorded in
the audit trail. A reader of the audit trail is entitled to assume the enclosing
block was shown whole when it says `enclosing-block`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.scanners.snippet import WINDOW_LINES, SnippetStrategy, enrich_snippet

PYTHON_MODULE = '''\
"""A module with three functions, one of which is vulnerable."""

import os

SECRET = "REDACTED_PLACEHOLDER_NOT_A_REAL_KEY"


class Gateway:
    def __init__(self, url):
        self.url = url

    def fetch(self, path, allow_redirects=True):
        return _client().get(self.url + path, allow_redirects=allow_redirects)

    def close(self):
        return None


def run_report(expression):
    evaluated = eval(expression)
    return evaluated


def render(user_template):
    return user_template


def _client():
    raise NotImplementedError
'''

GO_SOURCE = """\
package main

import (
\t"crypto/tls"
\t"net/http"
)

func newGatewayClient() *http.Client {
\ttransport := &http.Transport{
\t\tTLSClientConfig: &tls.Config{InsecureSkipVerify: true},
\t}
\treturn &http.Client{Transport: transport}
}
"""


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(PYTHON_MODULE, encoding="utf-8")
    (tmp_path / "gateway.go").write_text(GO_SOURCE, encoding="utf-8")
    return tmp_path


def _lines(source: str) -> list[str]:
    return source.splitlines()


# --- the enclosing block -------------------------------------------------


def test_a_finding_inside_a_function_gets_the_whole_function(tree: Path) -> None:
    """The reviewer's scope check needs the lines around the finding, not just
    the finding, or a fix touching the same function is 'out of scope'.
    """
    line = _lines(PYTHON_MODULE).index("    evaluated = eval(expression)") + 1
    result = enrich_snippet(
        file_path="app.py",
        reported="    evaluated = eval(expression)",
        start_line=line,
        end_line=line,
        root=tree,
    )
    assert result.strategy is SnippetStrategy.ENCLOSING_BLOCK
    assert result.text.startswith("def run_report(expression):")
    assert "return evaluated" in result.text
    # and nothing from the *next* function
    assert "def render" not in result.text


def test_a_method_gets_its_method_not_its_class(tree: Path) -> None:
    """The function is the unit a patch touches; the class is not."""
    line = (
        _lines(PYTHON_MODULE).index(
            "        return _client().get(self.url + path, allow_redirects=allow_redirects)"
        )
        + 1
    )
    result = enrich_snippet(
        file_path="app.py",
        reported="x",
        start_line=line,
        end_line=line,
        root=tree,
    )
    assert result.strategy is SnippetStrategy.ENCLOSING_BLOCK
    assert "def fetch" in result.text
    assert "def run_report" not in result.text


def test_it_works_on_go_as_well_as_python(tree: Path) -> None:
    """Both languages this project scans are indentation-structured.

    Note what it does *not* do: the enclosing block here is the composite
    literal, not the whole `func`. The rule is "the smallest indented run
    containing the finding", which is honest and language-agnostic; walking
    further up to the next `func` would need to know the language's keywords,
    which is a parser. The literal is still three times the context a scanner
    gives, and the file header is not dragged in.
    """
    line = (
        _lines(GO_SOURCE).index("\t\tTLSClientConfig: &tls.Config{InsecureSkipVerify: true},") + 1
    )
    result = enrich_snippet(
        file_path="gateway.go",
        reported="x",
        start_line=line,
        end_line=line,
        root=tree,
    )
    assert result.strategy is SnippetStrategy.ENCLOSING_BLOCK
    assert "InsecureSkipVerify: true" in result.text
    assert "transport := &http.Transport{" in result.text
    assert "package main" not in result.text, "the block must not run to the top of the file"
    assert "import (" not in result.text
    assert result.line_count > 1


def test_a_blank_line_inside_a_block_does_not_end_it(tree: Path) -> None:
    line = _lines(PYTHON_MODULE).index("    evaluated = eval(expression)") + 1
    with_gap = PYTHON_MODULE.replace(
        "    evaluated = eval(expression)\n    return evaluated",
        "    evaluated = eval(expression)\n\n    return evaluated",
    )
    (tree / "gapped.py").write_text(with_gap, encoding="utf-8")
    result = enrich_snippet(
        file_path="gapped.py",
        reported="x",
        start_line=line,
        end_line=line,
        root=tree,
    )
    assert "return evaluated" in result.text


# --- the top-level case --------------------------------------------------


def test_a_finding_at_indentation_zero_gets_a_window_not_the_file(
    tree: Path,
) -> None:
    """The failure mode a naive implementation hits on a module constant.

    `SECRET = "sk_live_..."` is at column zero. The indented-run rule would say
    "the block is the file", and putting a whole module into an LLM prompt is
    not a snippet.
    """
    line = _lines(PYTHON_MODULE).index('SECRET = "REDACTED_PLACEHOLDER_NOT_A_REAL_KEY"') + 1
    result = enrich_snippet(
        file_path="app.py",
        reported="x",
        start_line=line,
        end_line=line,
        root=tree,
    )
    assert result.strategy is SnippetStrategy.CONTEXT_WINDOW
    assert result.line_count <= WINDOW_LINES * 2 + 1, "a window is bounded"
    assert result.line_count < len(_lines(PYTHON_MODULE)), "but it is still context, not the file"
    assert "class Gateway" in result.text
    assert "def _client" not in result.text, "and it does not run to the end of the file"


def test_a_window_never_runs_off_the_end_of_the_file(tree: Path) -> None:
    result = enrich_snippet(file_path="app.py", reported="x", start_line=1, end_line=1, root=tree)
    assert result.strategy is SnippetStrategy.CONTEXT_WINDOW
    assert result.start_line == 1
    assert result.line_count <= WINDOW_LINES * 2 + 1


# --- the floor -----------------------------------------------------------


def test_a_missing_file_leaves_the_scanners_own_text_untouched(tree: Path) -> None:
    """The fixture scanner's findings point at files that do not exist.

    That is not a hypothetical: `data/fixtures/*.json` names
    `app/handlers/report.py` and nothing creates it. Every fixture-driven test in
    the suite depends on this path returning the reported text.
    """
    reported = "    return eval(request.args['expr'])"
    result = enrich_snippet(
        file_path="app/handlers/report.py", reported=reported, start_line=42, end_line=42
    )
    assert result.strategy is SnippetStrategy.REPORTED
    assert result.text == reported
    assert not result.widened
    assert result.line_count == 1, (
        "the count is how many lines the loop is being shown; zero reads in an audit "
        "row as though it were shown nothing"
    )


def test_the_line_count_is_never_zero_whenever_anything_is_shown(tmp_path: Path) -> None:
    """Across every branch, `line_count` means what a reader will take it to mean."""
    (tmp_path / "f.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    cases = [
        ("f.py", 2, 2),
        ("f.py", 1, 1),  # top level -> window
        ("f.py", None, None),
        ("gone.py", 1, 1),
        ("", 1, 1),
    ]
    for path, start, end in cases:
        for reported in ("", "one line", "a\nb\nc"):
            result = enrich_snippet(
                file_path=path,
                reported=reported,
                start_line=start,
                end_line=end,
                root=tmp_path,
            )
            assert result.line_count >= 1 or not (result.text or reported), (
                f"{path!r} reported={reported!r} recorded zero lines for text it did show"
            )


def test_a_finding_with_no_line_numbers_is_left_alone(tree: Path) -> None:
    reported = "eval(x)"
    for start in (None, 0, -1):
        result = enrich_snippet(file_path="app.py", reported=reported, start_line=start, root=tree)
        assert result.strategy is SnippetStrategy.REPORTED
        assert result.text == reported


def test_a_finding_with_no_path_is_left_alone() -> None:
    result = enrich_snippet(file_path="", reported="eval(x)", start_line=1)
    assert result.strategy is SnippetStrategy.REPORTED


def test_a_line_number_past_the_end_of_the_file_is_clamped_not_a_crash(
    tree: Path,
) -> None:
    result = enrich_snippet(
        file_path="app.py", reported="x", start_line=9999, end_line=9999, root=tree
    )
    assert result.strategy is not SnippetStrategy.REPORTED
    assert result.text


def test_a_directory_is_not_read_as_a_file(tree: Path) -> None:
    (tree / "adir").mkdir()
    result = enrich_snippet(
        file_path="adir", reported="reported", start_line=1, end_line=1, root=tree
    )
    assert result.strategy is SnippetStrategy.REPORTED
    assert result.text == "reported"


# --- the ceiling ---------------------------------------------------------


def test_a_block_larger_than_the_ceiling_is_cut_and_says_so(tmp_path: Path) -> None:
    """A 2,000-line class must not become an LLM prompt.

    And a truncated block must not claim to be a block: `enclosing-block` would
    tell a reader of the audit trail that the whole thing was shown.
    """
    body = "\n".join(f"    step_{i} = {i}" for i in range(400))
    (tmp_path / "big.py").write_text(
        f"def enormous():\n{body}\n    return step_0\n", encoding="utf-8"
    )
    result = enrich_snippet(
        file_path="big.py", reported="x", start_line=2, end_line=2, max_lines=50, root=tmp_path
    )
    assert result.strategy is SnippetStrategy.TRUNCATED
    assert result.line_count == 50
    assert "step_0" in result.text, "the finding itself must survive the cut"


def test_a_ceiling_of_zero_disables_the_ceiling(tmp_path: Path) -> None:
    """Zero means "no ceiling", not "show nothing".

    Worth being explicit about because the alternative reading -- a ceiling of
    zero lines -- is the one that would silently stop the loop seeing any code.
    """
    (tmp_path / "f.py").write_text("def f():\n" + "    x = 1\n" * 30, encoding="utf-8")
    capped = enrich_snippet(
        file_path="f.py", reported="x", start_line=2, end_line=2, max_lines=5, root=tmp_path
    )
    assert capped.strategy is SnippetStrategy.TRUNCATED
    assert capped.line_count == 5

    uncapped = enrich_snippet(
        file_path="f.py", reported="x", start_line=2, end_line=2, max_lines=0, root=tmp_path
    )
    assert uncapped.strategy is SnippetStrategy.ENCLOSING_BLOCK
    assert uncapped.line_count == 31, "the whole function"


def test_the_tier3_ceiling_matches_the_shipped_setting() -> None:
    """Tier 3 duplicates the ceiling so its report is reproducible.

    The duplication is deliberate -- reading the setting would make the committed
    report depend on whatever the machine running it had configured -- so the two
    have to be kept in step, and the way to keep them in step is a test.
    """
    from backend.config.settings import Settings
    from backend.evidence.tier3 import _SNIPPET_MAX_LINES

    assert _SNIPPET_MAX_LINES == Settings().remediation_snippet_max_lines


def test_the_setting_is_actually_threaded_through_to_the_reader() -> None:
    """A setting nothing reads is worse than no setting. Checked, not assumed."""
    from backend.config.settings import Settings
    from backend.services.remediation import RemediationService

    source = Path(RemediationService.__module__.replace(".", "/") + ".py")
    if not source.is_file():  # pragma: no cover - only under an unusual loader
        source = Path(__file__).resolve().parents[3] / "backend/services/remediation.py"
    text = source.read_text(encoding="utf-8")
    assert "remediation_snippet_max_lines" in text
    assert Settings().remediation_snippet_max_lines > 0, (
        "a ceiling of zero disables the ceiling; see enrich_snippet"
    )


def test_the_reported_text_survives_whenever_the_file_is_the_one_it_came_from(
    tmp_path: Path,
) -> None:
    """The floor, for the case that matters.

    An agent shown less than it used to be is a regression nobody asked for, and
    the caller cannot detect it -- it only ever sees a string.
    """
    (tmp_path / "p.py").write_text(PYTHON_MODULE, encoding="utf-8")
    (tmp_path / "short.py").write_text("x = 1\n", encoding="utf-8")
    for name in ("p.py", "short.py"):
        source = (tmp_path / name).read_text(encoding="utf-8")
        for start, reported in enumerate(source.splitlines(), start=1):
            for path in (name, "absent.py", ""):
                result = enrich_snippet(
                    file_path=path,
                    reported=reported,
                    start_line=start,
                    end_line=start,
                    root=tmp_path,
                )
                assert reported in result.text, (
                    f"{path}:{start} lost the reported line: {result.text!r}"
                )


def test_a_stale_finding_shows_the_file_not_the_scanners_snapshot(
    tmp_path: Path,
) -> None:
    """The one case where the reported text is *not* preserved, deliberately.

    A finding is a snapshot. The file can have moved on since the scan, and when
    it has, the file is what a patch gets applied to. Handing the loop the
    scanner's stale copy and calling it context would produce a patch that
    cannot apply -- so the file wins, and the audit trail records
    `enclosing-block` rather than implying the snapshot was shown.
    """
    (tmp_path / "moved.py").write_text("def current():\n    return 2\n", encoding="utf-8")
    result = enrich_snippet(
        file_path="moved.py",
        reported="    return 1  # as the scanner saw it",
        start_line=2,
        end_line=2,
        max_lines=10,
        root=tmp_path,
    )
    assert result.strategy is SnippetStrategy.ENCLOSING_BLOCK
    assert "return 2" in result.text
    assert "return 1" not in result.text
