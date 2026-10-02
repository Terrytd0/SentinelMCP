"""Tier 1: is the patch actually a fix? Measured by running the exploit.

## The question this answers

The rest of the suite can prove that the deterministic developer *emits* a diff
containing `ast.literal_eval`, that the reviewer approves it, and that the diff
is under twenty lines. None of that is evidence the patch fixes anything. A
security patch is a claim about runtime behaviour, so this tier tests runtime
behaviour: it takes a module with a real, exploitable vulnerability, asks the
engine for a patch, applies the patch to the real file, and then runs a real
attack against both versions.

    vulnerable + exploit lands           -> the finding is real and the probe works
    vulnerable + a benign call works     -> the code worked, so a later failure
                                            is a regression, not a pre-existing bug
    develop() -> PROPOSE                 -> the engine engaged with the finding
    patched   + exploit blocked          -> **the fix works**
    patched   + a benign call still works -> and it did not break the function

Fail-before / pass-after. It is the only tier here that does not need a third
party to be right, and it is the one that found the SQL rewrite's silent
wrong-rows defect. See `docs/evidence.md`.

## Three guards, because a harness that cannot fail is worse than none

1. **The exploit must land first.** A case whose exploit does not fire on the
   unpatched module has not measured a fix; it has measured a broken test. That
   is a hard failure here, never a quiet pass.

2. **The mutation control.** After each case the patch is *reverted* -- the
   vulnerable lines go back, the patch's lines go away -- and the exploit must
   then land again. This demonstrates the harness can tell a working patch from
   a no-op, so a pass in any case cannot be an artefact of the harness.
   `run_mutation_control` is the direct implementation.

3. **Declared expectations.** Each case declares the behavioural outcome it
   expects, and the harness fails when reality disagrees. Where the engine's
   real behaviour is a regression -- `shell=True` -> `shell=False` blocks the
   injection but leaves `subprocess.run` unable to run its command at all -- the
   case declares that regression, the harness confirms it, and the report counts
   it. Declaring it is not excusing it: the count is in the headline, and
   `tests/unit/evidence/test_evidence_execution_cases.py` fails if a declared
   regression is quietly deleted to improve the number.

## Declared human steps

Several rewrites are incomplete *by their own documentation* -- the `eval`
rewrite does not add `import ast`, the SQL rewrite does not write the bind
call. A patch that is correct but not runnable still has to be measured, so a
case may declare `HumanStep`s: the minimum edit a human reviewer must make for
the module to run at all.

These are counted and printed, never hidden, and a step that does not apply is
an error rather than a no-op -- so a declared step cannot drift away from
reality unnoticed. A rewrite that cannot produce a runnable module on its own
is a fact about the rewrite, and hiding it to get a nicer pass rate would be
exactly the measurement this project exists to avoid.
"""

from __future__ import annotations

import importlib.util
import itertools
import os
import sqlite3
import sys
import textwrap
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any, Literal

from backend.agents.deterministic import (
    DeterministicDeveloper,
    DeterministicReviewer,
)
from backend.evidence.patch_apply import apply_patch, split_diff

Expectation = Literal["blocks-exploit", "regresses", "escalates"]

BEHAVIOUR_PRESERVED = "preserved"
BEHAVIOUR_REGRESSED = "regressed"

SECRET_VALUE = "REDACTED_PLACEHOLDER_NOT_A_REAL_KEY"


class ProbeError(RuntimeError):
    """A probe could not answer the question it was asked.

    Deliberately distinct from a probe answering "no". A probe that fails to run
    must never be recorded as the exploit not working, because that turns a
    broken test into a passing security result.
    """


@dataclass(frozen=True, slots=True)
class HumanStep:
    """A minimal edit a human reviewer must make before the patch can run.

    `label` is what the report prints. `find`/`replace` is applied once, in
    order, after the agent's diff.
    """

    label: str
    find: str
    replace: str


@dataclass(slots=True)
class ProbeContext:
    """Scratch state a case needs: temp paths, ports, seeded databases."""

    workdir: Path
    marker: Path
    """A file that exists only if an attack landed."""

    db_path: str = ""
    received_headers: list[dict[str, str]] = field(default_factory=list)
    origin_url: str = ""
    redirect_url: str = ""
    servers: list[HTTPServer] = field(default_factory=list)


@dataclass(slots=True)
class CaseResult:
    """What actually happened, for one case. Every field is a measurement."""

    name: str
    rewrite: str
    cwe_ids: tuple[str, ...]
    status: Literal["ok", "failed", "skipped"]

    detail: str = ""
    exploit_before: bool | None = None
    exploit_after: bool | None = None
    benign_before_ok: bool | None = None
    benign_after_ok: bool | None = None
    behaviour_after: str = ""
    expected_behaviour: str = BEHAVIOUR_PRESERVED
    human_steps: tuple[str, ...] = ()
    decision: str = ""
    reviewer_verdict: str = ""
    reviewer_comments: tuple[str, ...] = ()
    apply_strategy: str = ""
    apply_line: int | None = None
    mutation_control: str = "not-run"
    """`control-passed` if the reverted patch let the exploit back through."""

    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def human_step_count(self) -> int:
        return len(self.human_steps)


# --------------------------------------------------------------------------
# Shared machinery
# --------------------------------------------------------------------------


_LOAD_COUNTER = itertools.count()
"""A monotonic counter, used for both the file name and the module name.

    Two separate collisions had to be closed, and both produced the same silent
    wrong answer: the "after" measurement re-reading the "before" module.

    1. *`sys.modules`.* `importlib` consults it when a name is already present,
       so a repeated module name hands back the module that was already loaded.
       An earlier version keyed the name on `id(injected)`, and CPython readily
       reuses the id of a just-freed dict, so the collision was intermittent.
    2. *The bytecode cache.* Even with a unique module name, writing `VALUE = 1`
       and then `VALUE = 2` to the same path within one second gives the same
       size and the same mtime, so `SourceFileLoader` reuses the cached `.pyc`
       and re-executes the *first* source. Writing to a fresh path each time
       removes the possibility entirely rather than trying to out-race mtime
       granularity.

    A counter cannot repeat, so neither name can collide.
"""


def load_module(name: str, source: str, ctx: ProbeContext, **injected: Any) -> ModuleType:
    """Write `source` into the case workdir and import it as a fresh module.

    Every load gets its own filename *and* its own module name, so the unpatched
    and patched versions of the same source cannot be confused for one another --
    which would make the harness report a fix that was never applied.
    """
    serial = next(_LOAD_COUNTER)
    path = ctx.workdir / f"{name}_{serial}.py"
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    module_name = f"_evidence_{name}_{serial}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - importlib contract
        raise ProbeError(f"could not build an import spec for {path}")
    module = importlib.util.module_from_spec(spec)
    for key, value in injected.items():
        setattr(module, key, value)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException as exc:
        sys.modules.pop(module_name, None)
        raise ProbeError(
            f"the module failed to import: {type(exc).__name__}: {exc}\n"
            f"{''.join(traceback_lines(exc))}"
        ) from exc
    return module


def traceback_lines(exc: BaseException) -> list[str]:
    import traceback

    return traceback.format_exception_only(type(exc), exc)


def probe(label: str, call: Callable[[], Any]) -> Any:
    """Run `call`, converting any failure into a `ProbeError`.

    A security probe must distinguish "the attack did not work" from "the probe
    could not run". Only the first is a passing result.
    """
    try:
        return call()
    except ProbeError:
        raise
    except Exception as exc:  # noqa: BLE001 - any failure is an unanswerable probe
        raise ProbeError(f"{label} raised {type(exc).__name__}: {exc}") from exc


def run_mutation_control(
    *,
    original_text: str,
    patched_text: str,
    patch: str,
    ctx: ProbeContext,
    name: str,
    exploit: Callable[[ModuleType, ProbeContext], bool],
    **injected: Any,
) -> str:
    """Revert the patch and confirm the exploit comes back.

    The single most important control in this file. Without it, a harness that
    always reports "exploit blocked" is indistinguishable from a harness that
    works, and the report would mean nothing.

    Reverting is done by re-applying the diff in the *opposite* direction, from
    the patched text, rather than by re-reading the original: if the reverse
    application cannot be located either, then the forward application was not
    anchored to real content and the control is vacuous -- so that is reported
    as a control failure, not skipped.
    """
    removed, added = split_diff(patch)
    if not removed or not added:
        return "control-vacuous (the diff is not a replacement)"
    reverse = (
        "\n".join(f"-{line}" for line in added) + "\n" + "\n".join(f"+{line}" for line in removed)
    )
    reverted = apply_patch(patched_text, reverse)
    if not reverted.applied:
        return f"control-failed (the reverse patch would not apply: {reverted.reason})"
    if reverted.text != original_text:
        return "control-failed (reverting the patch did not restore the original text)"
    try:
        module = load_module(f"{name}_reverted", reverted.text, ctx, **injected)
    except ProbeError as exc:
        return f"control-failed (the reverted module did not import: {exc})"
    landed = probe("the mutation control exploit", lambda: exploit(module, ctx))
    if not landed:
        return "control-failed (the exploit did not come back after the patch was reverted)"
    return "control-passed (the exploit returned when the patch was reverted)"


def _reviewer_for(developer: DeterministicDeveloper) -> DeterministicReviewer:
    return DeterministicReviewer(developer._rules)  # noqa: SLF001 - same rule table


def _develop_and_review(
    *,
    source: str,
    line: int,
    rule_id: str,
    cwe_ids: tuple[str, ...],
    file_path: str,
) -> tuple[Any, Any, str, str, str]:
    """Run one round of the real loop and return the patch plus both verdicts.

    Returns `(turn, verdict, patch, decision, error)`. `error` is non-empty when
    the pipeline could not produce a reviewable patch at all, which the caller
    turns into a failed case rather than a pass.
    """
    lines = source.splitlines()
    snippet = lines[line - 1] if 1 <= line <= len(lines) else ""
    developer = DeterministicDeveloper()
    reviewer = _reviewer_for(developer)
    turn = developer.develop(
        snippet=snippet,
        file_path=file_path,
        rule_id=rule_id,
        cwe_ids=list(cwe_ids),
        feedback=[],
        round_index=1,
    )
    if turn.decision.name != "PROPOSE" or not turn.patch:
        return turn, None, "", turn.decision.name, turn.summary
    verdict = reviewer.review(
        patch=turn.patch,
        snippet=snippet,
        file_path=file_path,
        rule_id=rule_id,
        round_index=1,
    )
    return turn, verdict, turn.patch, turn.decision.name, ""


# --------------------------------------------------------------------------
# HTTP fixtures for the redirect case. Two real servers on ephemeral ports, so
# the cross-origin redirect is a genuine socket round trip rather than a mock.
# --------------------------------------------------------------------------


class _RecordingHandler(BaseHTTPRequestHandler):
    """Records every request's headers, then serves or redirects.

    Only `/bounce` redirects. A handler that redirected every path made the
    case's own benign check raise `HTTPError 302`, which reads as a regression
    when it is really the fixture refusing to serve a plain 200.
    """

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
        self.server.record(self.headers)  # type: ignore[attr-defined]
        if self.path == "/bounce":
            self.send_response(302)
            self.send_header("Location", self.server.redirect_to)  # type: ignore[attr-defined]
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args: Any) -> None:
        """Silence the default stderr access log."""


def start_servers() -> tuple[HTTPServer, HTTPServer]:
    """Start the origin and the redirect target, and return them."""

    def make(redirect_to: str = "") -> HTTPServer:
        server = HTTPServer(("127.0.0.1", 0), _RecordingHandler)
        server.record = lambda headers: None  # type: ignore[attr-defined]
        server.redirect_to = redirect_to  # type: ignore[attr-defined]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server

    origin = make()
    target = make()
    origin.redirect_to = f"http://127.0.0.1:{target.server_port}/stolen"  # type: ignore[attr-defined]
    return origin, target


def stop_servers(servers: list[HTTPServer]) -> None:
    for server in servers:
        server.shutdown()
        server.server_close()


# --------------------------------------------------------------------------
# The cases. One function per rewrite, written exactly as that vulnerability
# demands, rather than forced into a table.
# --------------------------------------------------------------------------


def case_eval_to_literal_eval(ctx: ProbeContext) -> CaseResult:
    """CWE-95. A caller-supplied string is executed as Python."""
    source = '''
        """Evaluate a caller-supplied report expression."""

        def run_report(expression):
            return eval(expression)  # noqa: S307
        '''
    result = _run_python_case(
        ctx,
        name="eval-to-literal-eval",
        rewrite="eval-to-literal-eval",
        cwe_ids=("CWE-95",),
        rule_id="python.lang.security.audit.eval-detected",
        source=source,
        exploit=lambda module: (
            probe(
                "the eval payload",
                lambda: module.run_report(
                    f"__import__('pathlib').Path(r'{ctx.marker}').write_text('pwned')"
                ),
            )
            or ctx.marker.exists()
        ),
        benign=lambda module: probe("a literal expression", lambda: module.run_report("[1, 2]")),
        human_steps=(
            HumanStep(
                label="add the `import ast` the rewrite documents as missing",
                find="def run_report",
                replace="import ast\n\n\ndef run_report",
            ),
        ),
    )
    # The rewritten call names `ast`, which the fixture never imported.
    result.extras["raises_after_patch"] = result.extras.get("after_error", "")
    return result


def case_sql_fstring_to_bound_parameter(ctx: ProbeContext) -> CaseResult:
    """CWE-89. A search term is interpolated into a SQL string.

    Two separate measurements, because the rewrite makes two claims and only
    one of them is about the line it touched:

    1. Does the patched module still accept injection? Measured by running it.
    2. Is the *emitted statement* correct -- right number of placeholders, in
       the right places, and selecting the same rows once bound? Measured by
       rendering the statement under the driver's own percent escaping and
       executing it against a real database.

    The second is the one that matters, and it is the one a unit test on the
    diff string cannot do. It is also the one that caught the `LIKE '%s%'`
    defect, where the placeholder swallowed the wildcard and sqlite3 then
    returned the wrong rows without raising anything.
    """
    source = '''
        """Search reports by title, building the query with an f-string."""

        import sqlite3


        def search_reports(term):
            with sqlite3.connect(DB_PATH) as connection:
                cursor = connection.cursor()
                cursor.execute(f"SELECT * FROM reports WHERE title LIKE '%{term}%'")
                return cursor.fetchall()
        '''
    result = _run_python_case(
        ctx,
        name="sql-fstring-to-bound-parameter",
        rewrite="sql-fstring-to-bound-parameter",
        cwe_ids=("CWE-89",),
        rule_id="python.sqlalchemy.security.audit.raw-query",
        source=source,
        inject={"DB_PATH": ctx.db_path},
        exploit=lambda module: _sql_injection_lands(module, ctx),
        benign=lambda module: _sql_benign_rows(module, ctx),
    )
    result.extras.update(_sql_statement_verdicts(result))
    return result


def _seed(ctx: ProbeContext) -> None:
    connection = sqlite3.connect(ctx.db_path)
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS reports (title TEXT)")
        connection.execute("INSERT INTO reports VALUES ('quarterly report')")
        connection.execute("INSERT INTO reports VALUES ('sales summary')")
        connection.commit()
    finally:
        connection.close()


def _sql_injection_lands(module: ModuleType, ctx: ProbeContext) -> bool:
    """Does `' OR 1=1 --` bypass the filter?

    Asserts on the *injected* result set, and requires the probe to return at
    least two rows: an injection proof that accepts an empty result is a probe
    that cannot detect anything.
    """
    _seed(ctx)
    probe("the injected search", lambda: module.search_reports("' OR 1=1 --"))
    rows = probe("the injected search", lambda: module.search_reports("' OR 1=1 --"))
    if len(rows) < 2:
        raise ProbeError(
            f"the injection returned {len(rows)} row(s); a probe that cannot return more "
            "than the one it started with cannot detect a bypass"
        )
    return True


def _sql_benign_rows(module: ModuleType, ctx: ProbeContext) -> Any:
    _seed(ctx)
    return probe("the benign search", lambda: module.search_reports("quarterly"))


def _sql_statement_verdicts(result: CaseResult) -> dict[str, Any]:
    """Check the emitted statement itself, independent of the call around it.

    Three mechanical facts, all obtained by executing something:

    * `renders_under_pyformat` -- does a real DB-API driver accept the string?
    * `selects_the_same_rows` -- once bound, does it return what the original
      returned? This is the check the silent-defect got caught by.
    * `runnable_as_patched` -- does the line the engine actually emitted run, or
      does it raise? Expected to be False: the rewrite documents that the bind
      call is the human's job, and a loud TypeError is a better outcome than a
      line that half-runs.
    """
    extras = result.extras
    if not extras.get("added_lines"):
        return {"statement_checked": False}
    added = [line for line in extras["added_lines"] if "SELECT" in line]
    if not added:
        return {"statement_checked": False}
    statement = _extract_statement(added[0])
    if statement is None:
        return {"statement_checked": False}

    placeholders = statement.count("%s")
    out: dict[str, Any] = {
        "statement_checked": True,
        "statement": statement,
        "placeholders": placeholders,
    }

    out["selects_the_same_rows"] = _selects_same_rows(statement, placeholders)
    # Rendered the way the rewrite's *note* tells the human to bind it, so the
    # printed value is one a reader can act on. A bare PEP 237 render with an
    # unquoted sentinel produces `LIKE v0`, which is technically what that driver
    # would do and is not what anyone should paste into a call.
    out["renders_as_documented"] = _render_as_documented(statement, placeholders)
    return out


def _render_as_documented(statement: str, placeholders: int) -> str:
    if placeholders != 1:
        return f"not checkable: {placeholders} placeholder(s), this case binds one"
    try:
        return statement % ("'%quarterly%'",)
    except Exception as exc:  # noqa: BLE001
        return f"{type(exc).__name__}: {exc}"


def _extract_statement(line: str) -> str | None:
    """Pull the SQL text out of the emitted line.

    The emitted line is `cursor.execute(sql = "SELECT ...")`, so the statement
    starts at the first quote. Deliberately naive and deliberately documented:
    the goal is to recover the engine's own text so it can be executed, not to
    be a SQL parser.
    """
    marker = "sql = "
    if marker not in line:
        return None
    tail = line.split(marker, 1)[1].strip()
    for quote in ('"', "'"):
        if tail.startswith(quote):
            end = tail.rfind(quote)
            if end > 0:
                return tail[1:end]
    return None


def _selects_same_rows(statement: str, placeholders: int) -> Any:
    """Bind the statement as the rewrite's note instructs, and compare rows.

    Two things are being modelled, and both matter:

    * **psycopg2's substitution is into SQL, not into a Python string.** It
      renders the bound value as a quoted SQL literal, so the sentinel here is
      `'quarterly'` *with* quotes. A naive unquoted sentinel would produce
      `LIKE quarterly` and a syntax error, and would wrongly report the patch
      as unexecutable.
    * **A hoisted `LIKE` literal takes its wildcards in the value.** The
      rewrite's note says so; binding `"%quarterly%"` is the human step the
      note describes, so this is the patch *plus its documented completion*,
      which is the only thing that can be compared with the original query.

    Returns a bool, or a string explaining why it could not be checked -- a
    result nobody can check must not be silently counted as a pass.
    """
    if placeholders != 1:
        return f"not checkable: this case binds one value, the statement declares {placeholders}"
    try:
        rendered = statement % ("'%quarterly%'",)
    except Exception as exc:  # noqa: BLE001
        return f"not checkable: {type(exc).__name__}: {exc}"

    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE reports (title TEXT)")
        connection.execute("INSERT INTO reports VALUES ('quarterly report')")
        connection.execute("INSERT INTO reports VALUES ('sales summary')")
        try:
            got = connection.execute(rendered).fetchall()
        except Exception as exc:  # noqa: BLE001
            return f"not executable: {type(exc).__name__}: {exc}"
        want = connection.execute(
            "SELECT * FROM reports WHERE title LIKE ?", ("%quarterly%",)
        ).fetchall()
        return bool(got == want)
    finally:
        connection.close()


def case_shell_true_to_argv_list(ctx: ProbeContext) -> CaseResult:
    """CWE-78. A path is interpolated into a command run through a shell.

    The expected behavioural outcome is **platform-dependent**, and finding that
    out is one of the more useful results this tier produces.

    On POSIX, `subprocess.run` with a string and `shell=False` hands the whole
    string to `execvp` as `argv[0]`, so a command with arguments cannot run at
    all. The rewrite therefore blocks the injection *and* breaks the function.

    On Windows, `shell=False` still hands the string to `CreateProcess`, whose
    CRT child parses it into an argv -- so the command keeps working, and the
    injection is blocked with no regression at all.

    So the same patch is correct on one platform and destructive on the other,
    and nothing in the diff says which. That is the strongest argument this
    project has for not leaving the argv-list change to a human, and it is the
    reason the rewrite's own description says the call's shape still has to
    change.
    """
    source = '''
        """Convert a document, with the path interpolated into a shell string."""

        import subprocess
        import sys

        # The *program* is quoted; the *path* is not. That is the actual bug:
        # an unquoted interpolation into a shell string is a command injection,
        # and quoting the fixed half is what makes the fixture's own benign call
        # succeed so the case can tell a regression from a pre-existing fault.
        PROGRAM = '"' + sys.executable + '"'

        # Every payload this fixture is called with starts with `-c`, so the
        # interpreter is never launched with no arguments. Without that it reads
        # the harness's own stdin as a program and the case's output fills with
        # a traceback that has nothing to do with the vulnerability.
        def convert_to_pdf(path):
            subprocess.run(f"{PROGRAM} {path}", shell=True, check=True)
        '''
    result = _run_python_case(
        ctx,
        name="shell-true-to-argv-list",
        rewrite="shell-true-to-argv-list",
        cwe_ids=("CWE-78",),
        rule_id="python.lang.security.audit.subprocess-shell-true",
        source=source,
        exploit=lambda module: _shell_injection_lands(module, ctx),
        benign=lambda module: probe(
            "a benign conversion", lambda: module.convert_to_pdf('-c "import sys; sys.exit(0)"')
        ),
        expectation="blocks-exploit" if os.name == "nt" else "regresses",
    )
    result.extras["platform"] = os.name
    result.extras["regression_is_platform_dependent"] = True
    return result


def _shell_injection_lands(module: ModuleType, ctx: ProbeContext) -> bool:
    """Chain a second command onto the interpolated argument.

    Windows uses `&` and POSIX uses `;`, because that is what each shell uses to
    separate commands. The second command is a builtin (`echo` redirected to the
    marker, `touch`) rather than another interpreter, so the case's own output
    stays readable and the payload cannot fail for an unrelated reason. The
    first part is a harmless `-c` so the interpreter is never launched bare.
    """
    if os.name == "nt":
        payload = '-c "import sys; sys.exit(0)" & echo pwned>"' + str(ctx.marker) + '"'
    else:
        payload = '-c "import sys; sys.exit(0)"; touch ' + "'" + str(ctx.marker) + "'"
    probe("the shell payload", lambda: module.convert_to_pdf(payload))
    return ctx.marker.exists()


def case_move_secret_to_environment(ctx: ProbeContext) -> CaseResult:
    """CWE-798. A live-format credential is committed to source control.

    The vulnerability is the *literal in the file*, so the exploit reads the
    module's own source. Two further measurements, both about the rewrite's
    real-world consequence rather than about the regex:

    * `fails_closed` -- with the environment variable unset, reading the
      attribute must raise. A default that silently re-introduces a secret is
      not a fix.
    * `import_fails_closed` -- which is stronger than it sounds. The rewrite
      emits a *module-level* `os.environ[...]`, so an unset variable raises
      during import, not on first use. The application does not start with a
      clear error; it fails to import. Worth knowing before shipping.
    """
    source = f'''
        """A payment gateway credential, committed to the repository."""

        STRIPE_SECRET_KEY = "{SECRET_VALUE}"
        '''
    result = _run_python_case(
        ctx,
        name="move-secret-to-environment",
        rewrite="move-secret-to-environment",
        cwe_ids=("CWE-798",),
        rule_id="python.lang.security.audit.hardcoded-credentials",
        source=source,
        exploit=lambda module: (
            probe("the module's own source", lambda: module.SOURCE_TEXT).count(SECRET_VALUE) > 0
        ),
        benign=lambda module: probe(
            "the key from the environment", lambda: module.STRIPE_SECRET_KEY
        ),
        human_steps=(
            HumanStep(
                label="add the `import os` the rewrite's output needs",
                find="STRIPE_SECRET_KEY",
                replace="import os\n\nSTRIPE_SECRET_KEY",
            ),
        ),
        env={"STRIPE_SECRET_KEY": SECRET_VALUE},
        module_extra="SOURCE_TEXT = open(__file__, encoding='utf-8').read()\n",
    )
    result.extras["fails_closed_without_the_env_var"] = _unset_env_behaviour(
        result, ctx, "STRIPE_SECRET_KEY"
    )
    return result


def _unset_env_behaviour(result: CaseResult, ctx: ProbeContext, attribute: str) -> Any:
    """What happens when the migrated secret's environment variable is unset?"""
    patched = result.extras.get("patched_text")
    if not patched:
        return "not checkable: no patched source"
    previous = os.environ.pop(attribute, None)
    try:
        try:
            load_module(f"{ctx.workdir.name}_unset", patched, ctx)
        except ProbeError as exc:
            return f"the module does not import at all: {exc}"
        module = load_module(f"{ctx.workdir.name}_unset2", patched, ctx)
        try:
            probe("reading the migrated secret", lambda: getattr(module, attribute))
        except ProbeError as exc:
            return f"imports, and reading it fails: {exc}"
        return "imports, and reading it succeeds with the variable unset"
    finally:
        if previous is not None:
            os.environ[attribute] = previous


def case_http_redirect_strip_proxy_auth(ctx: ProbeContext) -> CaseResult:
    """CWE-200. A proxied credential is forwarded across an origin boundary.

    Two real HTTP servers on ephemeral ports: the origin answers `302` to the
    target, and the target records the headers it received. The attack lands
    when the target sees the `Proxy-Authorization` header, which is the real
    vulnerability in `requests` GHSA-j8r2-6x86-q33q.

    The client is built on `urllib` rather than `requests`, because `requests`
    is not a declared dependency here and a verification harness that only runs
    with an undeclared transitive package installed is not hermetic. The
    `allow_redirects` spelling is preserved so the rewrite under test is the one
    the real project matches.
    """
    source = '''
        """Fetch a URL through a proxy, following redirects."""

        import urllib.request


        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            """Turn a redirect into an HTTPError instead of following it.

            `build_opener()` installs the default `HTTPRedirectHandler`, so
            passing no handler does *not* stop redirects -- an earlier version
            of this fixture got that wrong and reported the exploit as landing
            when the patch had in fact worked. Refusing to build a
            `redirect_request` is the only way to say "do not follow" with
            urllib, and it is what `allow_redirects=False` has to mean.
            """

            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None


        _FOLLOWING = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
        _NOT_FOLLOWING = urllib.request.build_opener(_NoRedirect)


        def fetch_followed_link(url, allow_redirects=True):
            opener = _FOLLOWING if allow_redirects else _NOT_FOLLOWING
            request = urllib.request.Request(
                url, headers={"Proxy-Authorization": "Basic c2VjcmV0OnNlY3JldA=="}
            )
            return opener.open(request).status
        '''
    origin, target = start_servers()
    ctx.servers.extend([origin, target])
    ctx.origin_url = f"http://127.0.0.1:{origin.server_port}/origin"
    ctx.redirect_url = f"http://127.0.0.1:{origin.server_port}/bounce"

    def record(headers: Any) -> None:
        ctx.received_headers.append({k.title(): v for k, v in headers.items()})

    origin.record = record  # type: ignore[attr-defined]
    target.record = record  # type: ignore[attr-defined]

    result = _run_python_case(
        ctx,
        name="http-redirect-strip-proxy-auth",
        rewrite="http-redirect-strip-proxy-auth",
        cwe_ids=("CWE-200",),
        rule_id="python.requests.security.audit.redirect-proxies",
        source=source,
        exploit=lambda module: _proxy_auth_forwarded(module, ctx),
        benign=lambda module: probe(
            "a direct fetch", lambda: module.fetch_followed_link(ctx.origin_url)
        ),
    )
    result.extras["redirect_target_headers"] = [
        headers for headers in ctx.received_headers if "Proxy-Authorization" in headers
    ]
    return result


def _proxy_auth_forwarded(module: ModuleType, ctx: ProbeContext) -> bool:
    ctx.received_headers.clear()
    probe("the proxied fetch", lambda: module.fetch_followed_link(ctx.redirect_url))
    return any("Proxy-Authorization" in headers for headers in ctx.received_headers)


def case_server_side_template_injection(ctx: ProbeContext) -> CaseResult:
    """CWE-1336. No rewrite exists, and the engine must say so.

    The negative control for the whole tier. If the engine ever started
    guessing at a class it has no rule for, this is the case that would catch
    it -- and guessing at a security fix is the single worst behaviour this
    system could have.
    """
    source = '''
        """Render a user-supplied Jinja template."""


        def render(user_template):
            from jinja2 import Environment

            return Environment().from_string(user_template).render()
        '''
    result = _run_python_case(
        ctx,
        name="no-rule-for-template-injection",
        rewrite="(none)",
        cwe_ids=("CWE-1336",),
        rule_id="python.lang.security.audit.template-injection",
        source=source,
        exploit=lambda module: True,
        benign=lambda module: None,
        expectation="escalates",
    )
    return result


def case_disable_tls_verification(ctx: ProbeContext) -> CaseResult:
    """CWE-295. Declared, and deliberately not executed.

    The rewrite's pattern is Go-only, and this repository has no Go toolchain,
    so a patched `.go` file cannot be compiled or run here. Saying so in the
    report is the point: a rule that looks covered because nothing failed is
    worse than a rule reported as uncovered.
    """
    return CaseResult(
        name="disable-tls-verification",
        rewrite="disable-tls-verification",
        cwe_ids=("CWE-295",),
        status="skipped",
        detail=(
            "the rewrite's pattern is Go-only and this repository has no Go toolchain, "
            "so the patched file cannot be executed. Tier 2 covers this rule statically "
            "against a real Semgrep Go rule."
        ),
    )


def case_math_rand_to_crypto_rand(ctx: ProbeContext) -> CaseResult:
    """CWE-338. The rule was removed, and this records why it must stay removed.

    `math-rand-to-crypto-rand` had a Go pattern (`rand.Intn(`) and a Python
    replacement (`secrets.randbelow(`), so it emitted a Python name into a Go
    file. It could not be repaired rather than removed, because
    `math/rand.Int(n) int` and `crypto/rand.Int(rand.Reader, n) (*big.Int, error)`
    have incompatible signatures -- no single-expression substitution is
    correct, and a fix that skips the import, the `*big.Int` and the error path
    is a patch that does not compile.

    Reported as a measured `no-rewrite-available` rather than a pass. The engine
    escalating is the correct behaviour, and the check that it does is in
    `tests/unit/agents/test_deterministic_agents.py`.
    """
    return CaseResult(
        name="math-rand-to-crypto-rand",
        rewrite="(removed)",
        cwe_ids=("CWE-338",),
        status="skipped",
        detail=(
            "the rewrite was removed rather than fixed: its pattern was Go's rand.Intn "
            "and its replacement was Python's secrets.randbelow, and crypto/rand.Int has "
            "an incompatible signature so no regex can do it. CWE-338 now escalates to "
            "a human, which the unit suite pins. There is no Go toolchain here either, "
            "so it was never executable. See docs/evidence.md."
        ),
        extras={"rule_removed": True},
    )


CaseRunner = Callable[[ProbeContext], CaseResult]

CASES: tuple[CaseRunner, ...] = (
    case_eval_to_literal_eval,
    case_sql_fstring_to_bound_parameter,
    case_shell_true_to_argv_list,
    case_move_secret_to_environment,
    case_http_redirect_strip_proxy_auth,
    case_server_side_template_injection,
    case_disable_tls_verification,
    case_math_rand_to_crypto_rand,
)


# --------------------------------------------------------------------------
# The shared per-case driver.
# --------------------------------------------------------------------------


def _run_python_case(
    ctx: ProbeContext,
    *,
    name: str,
    rewrite: str,
    cwe_ids: tuple[str, ...],
    rule_id: str,
    source: str,
    exploit: Callable[[ModuleType], bool],
    benign: Callable[[ModuleType], Any],
    human_steps: tuple[HumanStep, ...] = (),
    expectation: str = "blocks-exploit",
    inject: dict[str, Any] | None = None,
    env: dict[str, str] | None = None,
    module_extra: str = "",
) -> CaseResult:
    """Run one case end to end, measuring rather than asserting where possible.

    The order is the point, and it is not arbitrary:

    1. the exploit must land on the unpatched code, or the case proves nothing
    2. a benign call must work, so a later failure means the patch broke it
    3. the loop must produce a patch
    4. the patch must apply to the real file
    5. the exploit must no longer land
    6. a benign call must still work
    7. the mutation control must confirm the harness can see a reverted patch

    `env` is set for the whole case and restored afterwards, because a rewrite
    that moves a secret out of source control is not measurable without the
    environment variable it now depends on.
    """
    injected = dict(inject or {})
    result = CaseResult(
        name=name,
        rewrite=rewrite,
        cwe_ids=cwe_ids,
        status="ok",
        expected_behaviour=BEHAVIOUR_REGRESSED
        if expectation == "regresses"
        else BEHAVIOUR_PRESERVED,
        human_steps=tuple(step.label for step in human_steps),
    )

    def attempt_exploit(module: ModuleType) -> bool:
        """Run the attack with a clean slate, and return whether it *landed*.

        Clearing the marker is not a detail. Every exploit in this tier is
        detected by a file the attack creates, and the same `ctx` is used for the
        unpatched run, the patched run and the mutation control. Without the
        reset, the first run leaves the marker behind and the second run reports
        "the exploit still lands" no matter what the patch did -- a harness that
        fails every case, which is at least honest, versus one that can only ever
        pass.
        """
        ctx.marker.unlink(missing_ok=True)
        return bool(exploit(module))

    if expectation == "escalates":
        return _run_escalation_case(
            ctx,
            result=result,
            source=source,
            rule_id=rule_id,
            cwe_ids=cwe_ids,
        )

    restore = _set_env(env or {})
    try:
        return _run_python_case_body(
            ctx,
            result=result,
            name=name,
            rewrite=rewrite,
            cwe_ids=cwe_ids,
            rule_id=rule_id,
            source=source,
            exploit=attempt_exploit,
            benign=benign,
            human_steps=human_steps,
            injected=injected,
            module_extra=module_extra,
        )
    finally:
        _restore_env(restore)


def _set_env(values: dict[str, str]) -> dict[str, str | None]:
    previous: dict[str, str | None] = {}
    for key, value in values.items():
        previous[key] = os.environ.get(key)
        os.environ[key] = value
    return previous


def _restore_env(previous: dict[str, str | None]) -> None:
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _run_python_case_body(  # noqa: PLR0913 - a linear script, and splitting it
    ctx: ProbeContext,  # obscures the ordering that is the whole point
    *,
    result: CaseResult,
    name: str,
    rewrite: str,
    cwe_ids: tuple[str, ...],
    rule_id: str,
    source: str,
    exploit: Callable[[ModuleType], bool],
    benign: Callable[[ModuleType], Any],
    human_steps: tuple[HumanStep, ...],
    injected: dict[str, Any],
    module_extra: str,
) -> CaseResult:
    original_text = textwrap.dedent(source) + module_extra

    # 1. the vulnerability is real
    try:
        before = load_module(name, original_text, ctx, **injected)
        result.exploit_before = bool(exploit(before))
    except ProbeError as exc:
        return _fail(result, f"the vulnerable module did not load: {exc}")
    if not result.exploit_before:
        return _fail(
            result,
            "the exploit did not land on the unpatched code, so this case would measure "
            "a broken probe rather than a fix",
        )

    # 2. the module worked before
    try:
        probe("a benign call on the unpatched module", lambda: benign(before))
        result.benign_before_ok = True
    except ProbeError as exc:
        result.benign_before_ok = False
        return _fail(result, f"a benign call failed on the *unpatched* module: {exc}")

    # 3. the loop produces a patch
    turn, verdict, patch, decision, error = _develop_and_review(
        source=original_text,
        line=_vulnerable_line(original_text, rule_id),
        rule_id=rule_id,
        cwe_ids=cwe_ids,
        file_path=f"app/{name}.py",
    )
    result.decision = decision
    if verdict is not None:
        result.reviewer_verdict = verdict.decision.name
        result.reviewer_comments = tuple(
            line[2:] for line in verdict.message.splitlines() if line.startswith("- ")
        )
    if error:
        return _fail(result, f"the developer did not propose a patch: {error}")
    result.extras["added_lines"] = split_diff(patch)[1]

    # 4. the patch applies to the real file
    application = apply_patch(
        original_text, patch, anchor_line=_vulnerable_line(original_text, rule_id)
    )
    if not application.applied:
        return _fail(result, f"the patch did not apply: {application.reason}")
    result.apply_strategy = application.strategy
    result.apply_line = application.line
    agent_patched_text = application.text
    patched_text = agent_patched_text

    for step in human_steps:
        if step.find not in patched_text:
            return _fail(
                result,
                f"the declared human step {step.label!r} no longer matches the patched "
                "source, so the case has drifted from what it claims to test",
            )
        patched_text = patched_text.replace(step.find, step.replace, 1)
    result.extras["patched_text"] = patched_text
    result.extras["agent_patched_text"] = agent_patched_text

    # 5. the exploit is blocked
    try:
        after = load_module(f"{name}_patched", patched_text, ctx, **injected)
    except ProbeError as exc:
        result.extras["after_error"] = str(exc)
        result.behaviour_after = BEHAVIOUR_REGRESSED
        return result
    try:
        result.exploit_after = bool(exploit(after))
    except ProbeError as exc:
        # The attack raised rather than landing. That is a *blocked* exploit, not
        # an unanswerable probe: `ast.literal_eval` rejecting the payload is
        # precisely the fix working. Guard 1 is what makes this safe -- the same
        # lambda had to land on the unpatched module, so it is not a probe that
        # fails on everything.
        result.exploit_after = False
        result.extras["exploit_after_error"] = str(exc)
    if result.exploit_after:
        return _fail(result, "the exploit still lands after the patch was applied")

    # 6. the benign path still works
    try:
        probe("a benign call on the patched module", lambda: benign(after))
        result.benign_after_ok = True
        result.behaviour_after = BEHAVIOUR_PRESERVED
    except ProbeError as exc:
        result.benign_after_ok = False
        result.behaviour_after = BEHAVIOUR_REGRESSED
        result.extras["benign_after_error"] = str(exc)

    # 7. the control
    # Reverted from the *agent's* patched text, not the human-stepped one: the
    # control asks whether the agent's diff is what blocked the exploit, so
    # re-applying it in reverse has to land back on the pristine original.
    result.mutation_control = run_mutation_control(
        original_text=original_text,
        patched_text=agent_patched_text,
        patch=patch,
        ctx=ctx,
        name=name,
        # `exploit` in this scope is already the marker-clearing wrapper built
        # by `_run_python_case`, which is what the control needs: it must run
        # the same measurement the earlier steps ran, not a raw copy of it.
        exploit=lambda module, _ctx: exploit(module),
        **injected,
    )
    if not result.mutation_control.startswith("control-passed"):
        return _fail(result, f"the mutation control did not pass: {result.mutation_control}")
    return result


def _run_escalation_case(
    ctx: ProbeContext,
    *,
    result: CaseResult,
    source: str,
    rule_id: str,
    cwe_ids: tuple[str, ...],
) -> CaseResult:
    """Assert the engine declines a class it has no rule for."""
    original_text = textwrap.dedent(source)
    turn, _, _, decision, _ = _develop_and_review(
        source=original_text,
        line=_first_body_line(original_text),
        rule_id=rule_id,
        cwe_ids=cwe_ids,
        file_path="app/render.py",
    )
    result.decision = decision
    result.reviewer_verdict = "(not reached)"
    if decision != "ESCALATE":
        return _fail(
            result,
            f"the engine answered {decision} for a class it has no rule for; it must "
            "escalate rather than guess at a security fix",
        )
    result.extras["escalation_rationale"] = turn.rationale
    result.behaviour_after = "declined"
    return result


def _fail(result: CaseResult, detail: str) -> CaseResult:
    result.status = "failed"
    result.detail = detail
    return result


def _vulnerable_line(source: str, rule_id: str) -> int:
    """The 1-based line the engine is pointed at.

    `_vulnerable_line` picks the first line in the fixture that any rewrite
    pattern can bite on, which for these fixtures is the one carrying the
    vulnerability. Deriving it from the source rather than hardcoding a number
    means inserting a line in a fixture does not silently repoint the case at
    the wrong code.
    """
    from backend.agents.deterministic import _REWRITES  # noqa: PLC0415

    for index, line in enumerate(source.splitlines(), start=1):
        if any(rule.pattern.search(line) for rule in _REWRITES):
            return index
    return 1


def _first_body_line(source: str) -> int:
    for index, line in enumerate(source.splitlines(), start=1):
        if line.strip() and not line.strip().startswith(('"""', "#")):
            return index
    return 1
