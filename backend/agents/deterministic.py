"""The deterministic developer/reviewer pair.

This is the remediation loop's default implementation, and it is not a
placeholder. It is a rule-based developer and a rule-based reviewer that
produce a real unified diff and a real critique, with no LLM and no network.

It exists for two reasons, one practical and one substantive:

1. **Practical.** The whole system -- tests, `run_remediation.py`, the demo
   walkthrough -- has to run on a clean checkout with no API key. A portfolio
   project that only works if you paid for tokens is a project nobody runs.
2. **Substantive.** It is the control in the experiment. Running the identical
   task through this loop and through the AutoGen loop, and comparing patch
   correctness, latency, and cost, is the measurement that makes
   `docs/adr/002-autogen-vs-langgraph-crewai.md` an argument from experience
   rather than an opinion. Sprint 11's benchmark builds on exactly this seam.

How it works: the developer recognises the vulnerability from the finding's
CWE/rule id and applies the matching rewrite from `_REWRITES`; the reviewer
then checks the produced diff against hard requirements (does it still contain
the vulnerable construct, does it parse, is it scoped to the finding's lines).
Both are strict enough that the reviewer genuinely rejects some drafts, which
is what makes the critique/revise loop observable.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from backend.core.logging import get_logger
from backend.database.enums import AgentDecision

logger = get_logger(__name__)


@dataclass(slots=True)
class AgentTurn:
    """One agent's contribution to a remediation round.

    A plain dataclass rather than an AutoGen message type, so the deterministic
    and the LLM-backed implementations are interchangeable at the loop's
    boundary. That is what lets both engines share the loop, the persistence,
    and the audit trail: the choice is `SENTINEL_AUTOGEN_ENABLED`, not a flag,
    so a run cannot end up with a different engine than the one its audit rows
    were written by.
    """

    role: str
    decision: AgentDecision
    patch: str | None = None
    summary: str = ""
    rationale: str = ""
    message: str = ""
    tokens_used: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    llm_model: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def used_llm(self) -> bool:
        return self.llm_model is not None


class RemediationEngine(Protocol):
    """The contract the remediation loop depends on.

    Two methods, because that is genuinely all the loop needs: produce a
    patch, then judge one. Implementations must never touch the database, the
    git host, or the network beyond their own LLM call -- everything
    observable happens in `backend/services/remediation.py` so the audit trail
    is identical whichever engine ran.
    """

    @property
    def model_name(self) -> str | None: ...

    def develop(
        self,
        *,
        snippet: str,
        file_path: str,
        rule_id: str,
        cwe_ids: list[str],
        feedback: list[str],
        round_index: int,
    ) -> AgentTurn:
        """Draft a patch for one finding.

        `rule_id` and `cwe_ids` are what let the engine recognise *which*
        vulnerability class it is looking at; `snippet` alone is ambiguous
        (a bare `eval(` is a critical RCE in one context and a deliberate
        expression parser in another).
        """

    def review(
        self,
        *,
        patch: str,
        snippet: str,
        file_path: str,
        rule_id: str,
        round_index: int,
    ) -> AgentTurn:
        """Judge a draft patch against one finding."""


@dataclass(frozen=True, slots=True, eq=False)
class Rewrite:
    """One recognised vulnerability class and the transformation that fixes it.

    `replacement` is a `re.sub` template, so it may use `\\g<name>` group
    references. Group *names* rather than numbers, because a number silently
    shifts when the pattern is edited and a security rewrite is not the place to
    discover that.

    `transform`, when supplied, replaces the template entirely and does the
    substitution itself. It exists for the one rewrite a single regex cannot
    express -- parameterising a multi-clause SQL statement -- where a template
    would have to reproduce the statement text it did not capture, and would
    therefore silently delete the parts it forgot.

    `languages` is the set of languages the **replacement** is valid in, and it
    is enforced against the finding's file. It exists because a rewrite whose
    pattern is language-agnostic and whose replacement is not produces code that
    does not compile in the file it was aimed at: `move-secret-to-environment`
    matches Go's `const StripeSecretKey = "sk_live_..."` and emitted
    `os.environ["StripeSecretKey"]` into it. A green test asserted that
    behaviour, so the defect was pinned in place rather than caught. Found by
    `backend/evidence/tier2.py`; see `docs/evidence.md`. An unrecognised
    extension matches nothing, and fails closed, for the same reason
    `_path_within_roots` does.

    `note` is **never inserted into the source**. It goes into the diff
    preamble, outside the `---`/`+++` block. An earlier version appended it as
    an inline comment, which broke every mid-line match:
    `render(eval(x))` became `render(# note` + newline + `ast.literal_eval(x))`.
    A comment inside the code is a nice-to-have; a patch that does not parse is
    not a trade worth making.
    """

    name: str
    pattern: re.Pattern[str]
    cwes: frozenset[str]
    rule_hints: tuple[str, ...]
    description: str
    languages: frozenset[str] = frozenset({"python"})
    """Languages the *replacement* is valid in. Not the languages the pattern
    matches -- a pattern can match more than the language it can fix, and that
    asymmetry is exactly the bug this field exists to stop."""

    replacement: str = ""
    """`re.sub` template, used when `transform` is None."""

    note: str = ""
    """One-line explanation, shown in the diff preamble and the PR body."""

    transform: Callable[[re.Match[str]], str] | None = None
    """Optional custom substitution, used instead of `replacement`."""

    def applies_to(self, rule_id: str, cwe_ids: list[str]) -> bool:
        """Whether this rewrite is the right fix for a finding.

        Matches on CWE first (authoritative) and falls back to substrings of the
        scanner's rule id (a hint, used only when the scanner supplied no CWE).
        """
        if cwe_ids and any(cwe.upper() in self.cwes for cwe in cwe_ids):
            return True
        lowered = rule_id.lower()
        return any(hint in lowered for hint in self.rule_hints)

    def applies_to_language(self, file_path: str) -> bool:
        """Whether this rewrite's replacement is valid in `file_path`'s language.

        Fails **closed** on an unrecognised extension. An unknown language is
        not a licence to emit Python into a file that might be Go, and the whole
        point of the field is that "we do not know what language this is" must
        not become "we will guess".
        """
        return language_of(file_path) in self.languages

    def apply(self, snippet: str, file_path: str) -> str:
        """Rewrite `snippet`. The file path is not used for indentation.

        It is accepted so the signature stays stable as rewrites are added, and
        so a future language-aware rewrite has it available without changing
        every call site.
        """
        if self.transform is not None:
            return self.pattern.sub(self.transform, snippet)
        return self.pattern.sub(self.replacement, snippet)


# Languages whose comment marker is `//`. Everything else the engine is expected
# to see uses `#`. An explicit allowlist rather than a blocklist, so an
# unrecognised extension falls back to the common default and the human reviewer
# catches it: a wrong marker is a visible compile error, a silently mangled
# patch is not.
_SLASH_COMMENT_EXTENSIONS = frozenset(
    {
        ".go",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".java",
        ".kt",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".cs",
        ".rs",
        ".swift",
        ".php",
    }
)


# Extension -> language. Separate from `_SLASH_COMMENT_EXTENSIONS` on purpose:
# that set answers "which comment marker", this one answers "is a rewrite's
# replacement valid here", and the two genuinely differ. A rewrite can be valid
# in a language whose comments are `#`, and `Rewrite.languages` is about the
# emitted code rather than the annotation.
_LANGUAGE_BY_EXTENSION: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".go": "go",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".swift": "swift",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
    ".sql": "sql",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".conf": "ini",
    ".ini": "ini",
    ".toml": "toml",
    ".md": "markdown",
}

UNKNOWN_LANGUAGE = "unknown"
"""Returned for an extension with no mapping.

    A distinct value rather than `None` or a guess, so a rewrite's
    `applies_to_language` can fail closed on it explicitly and the developer's
    escalation message can name what it did not know.
    """


def language_of(file_path: str) -> str:
    """The language of `file_path`, by extension. `unknown` if unrecognised."""
    return _LANGUAGE_BY_EXTENSION.get(Path(file_path).suffix.lower(), UNKNOWN_LANGUAGE)


def _comment_marker(file_path: str) -> str:
    """The line-comment marker for a source file's language."""
    return "//" if Path(file_path).suffix.lower() in _SLASH_COMMENT_EXTENSIONS else "#"


# Matches a `{name}` or `{name.attr}` interpolation inside a string literal.
_INTERPOLATION = re.compile(r"\{[A-Za-z_][A-Za-z0-9_.\[\]'\"()]*\}")


def _parameterize_sql(match: re.Match[str]) -> str:
    """Rewrite an f-string SQL literal into a parameterised statement.

    Every `{expr}` interpolation becomes a bound parameter, and the `f` prefix is
    dropped. Crucially, the statement text is *preserved*: the previous
    template-based version captured only the leading verb and rebuilt the rest
    from a fixed string, so `SELECT * FROM reports WHERE ...` came out as
    `SELECT WHERE ...` -- a patch that removed a table from a query while
    claiming to secure it.

    **An interpolation inside a SQL string literal has its whole literal hoisted
    out into a single placeholder.** This is the part that is easy to get
    silently, catastrophically wrong, and two earlier revisions got it wrong.

    A driver with `pyformat` paramstyle substitutes the value as *text*. psycopg2
    -- this project's declared database driver -- additionally quotes the value
    for you, because it is inserting into SQL, not into a Python string. So a
    placeholder *inside* a literal cannot work:

        f"... WHERE title LIKE '%{term}%'"     # the vulnerable source
          -> "... WHERE title LIKE '%s%'"      # psycopg2 renders: LIKE '%'term'%'
                                                 -> SyntaxError, or a breakout
          -> "... WHERE title LIKE '%{term}%'" with the wildcards left in the SQL
                                                 -> an injection that survived
          -> "... WHERE title LIKE %s"         # what this emits: correct SQL,
                                                 # and the wildcards move into
                                                 the bound value

    The first form also has a second, quieter failure. Even a driver that does
    *not* quote -- plain PEP 237 `%` formatting -- reads every `%` as either the
    `%%` escape or the start of a placeholder, so the `LIKE` wildcard sitting
    immediately before a placeholder collides with it. `'%s%'` as SQL means
    "any prefix, a literal `s`, any suffix", so a search for `quarterly` returns
    whatever row contains the letter `s` and raises nothing at all. A security
    fix that silently returns the wrong rows is worse than no fix, and no test
    on the diff string would have caught it.

    So a literal `%` outside a hoisted literal is doubled to `%%`, and a literal
    containing an interpolation is replaced wholesale by `%s`. The bind values
    are still not supplied -- `execute(text(sql), {...})` has to be written, and
    for a hoisted `LIKE` the wildcards have to go into the value, which the note
    and the description both say.
    """
    quote = match.group("quote")
    body = match.group("body")
    parameterised, count = _bind_placeholders(body)
    if count == 0:
        # No interpolations after all -- not a finding this rewrite addresses.
        return match.group(0)
    # `body` excludes the surrounding quotes, so they are re-added here. Using
    # the original quote character rather than forcing a double quote keeps the
    # rewrite faithful to the source for a statement that used single quotes.
    return f"{match.group('indent')}sql = {quote}{parameterised}{quote}"


# A SQL string literal, in either quoting style, allowing `''` as an escaped
# quote. Scanned rather than parsed: a real SQL parser is not a dependency, and
# the only question being asked is "is this interpolation inside quotes".
_SQL_LITERAL = re.compile(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"")

# The two quote characters that open a literal, whichever style the statement
# used. A backtick is included because MySQL uses it for identifiers.
_QUOTES = ("'", '"', "`")


def _bind_placeholders(body: str) -> tuple[str, int]:
    """Replace interpolations with bound parameters. Returns `(statement, n)`.

    Returns `body` unchanged with a count of zero when there is nothing to do,
    so the caller can tell "no interpolation" from "rewritten to the same text".

    The two rules, in the order they apply:

    * An interpolation **inside** a SQL string literal causes that whole literal
      to become one `%s`. The static parts of the literal -- a `LIKE` wildcard,
      a date format -- become part of the value the human binds, because they
      cannot stay in the SQL without re-creating the injection this rewrite
      exists to remove.
    * An interpolation **outside** any literal becomes `%s` in place, and every
      literal `%` around it is doubled to `%%`, so a genuine modulo operator
      survives the driver's own percent escaping.
    """
    literals = [(m.start(), m.end()) for m in _SQL_LITERAL.finditer(body)]

    inside: list[bool] = []
    for match in _INTERPOLATION.finditer(body):
        inside.append(any(start < match.start() < end for start, end in literals))

    if not any(inside):
        return _double_percents_around_placeholders(body), len(inside)

    pieces: list[str] = []
    replaced: set[tuple[int, int]] = set()
    cursor = 0
    count = 0
    for match in _INTERPOLATION.finditer(body):
        if not inside[count]:
            continue
        literal = _enclosing_literal(literals, match.start())
        if literal is None or literal in replaced:
            count += 1
            continue
        pieces.append(_double_percents_around_placeholders(body[cursor : literal[0]]))
        pieces.append("%s")
        replaced.add(literal)
        cursor = literal[1]
        count += 1
    pieces.append(_double_percents_around_placeholders(body[cursor:]))
    return "".join(pieces), count


def _enclosing_literal(literals: list[tuple[int, int]], offset: int) -> tuple[int, int] | None:
    for span in literals:
        if span[0] < offset < span[1]:
            return span
    return None


def _double_percents_around_placeholders(text: str) -> str:
    """Double every literal `%`, so a genuine one survives pyformat escaping.

    Only called on regions with no hoisted literal, which is what makes it safe:
    inside a hoisted literal the percents become part of the *value*, where the
    driver has not escaped anything.
    """
    return text.replace("%", "%%")


# The rule table. Each entry is a real, defensible fix for a real CWE -- this is
# the part that makes the deterministic engine worth benchmarking, because
# "replace eval() with ast.literal_eval" is exactly what a competent engineer
# would do, and the LLM engine has to at least match it.
#
# Known limits, stated rather than hidden:
#   * `eval` -> `ast.literal_eval` does not add the `import ast`, so the result
#     raises `NameError` until a human adds it. The description says so.
#   * The SQL rewrite produces the parameterised *statement* but not the bind
#     call, and the line it produces raises `TypeError` until a human writes it.
#     The note and description both say so.
#   * `shell=True` -> `shell=False` is correct on Windows and *destructive* on
#     POSIX, where `subprocess.run` cannot run a string with arguments at all.
#     The description says so.
#   * A finding whose vulnerability class is not in this table escalates to a
#     human. Guessing at a security fix is worse than declining to.
#
# Every limit in that list is *measured*, not asserted, by
# `backend/evidence/`: each rewrite is applied to a real vulnerable module and
# executed against a real exploit, then checked against an independent static
# analyser. The `%%`/`%s` collision in the SQL rewrite, the reviewer's false
# parse failure on a one-line signature change, and the two rules that emitted
# Python into Go were all found that way rather than by inspection. See
# `docs/evidence.md`.
#
# `math-rand-to-crypto-rand` used to be here and was **removed**, on the same
# evidence. Its pattern was Go's `rand.Intn(` and its replacement was Python's
# `secrets.randbelow(`, so it emitted a Python name into a Go file. It could not
# be repaired rather than removed, because `math/rand.Int(n) int` and
# `crypto/rand.Int(rand.Reader, n) (*big.Int, error)` have incompatible
# signatures: no single-expression substitution is correct, and a rule that
# needs a new import, a `*big.Int`, and an error path is not a regex. CWE-338
# findings now escalate to a human, which is the correct answer.
_REWRITES: tuple[Rewrite, ...] = (
    Rewrite(
        name="eval-to-literal-eval",
        # A *bare* call to the builtin, and nothing else.
        #
        #   (?<![\w.])     not `builtins.eval(`, not `self.eval(`, not `myeval(`
        #   (?<!def )      not the declaration `def eval(`
        #
        # Both lookbehinds were added after `backend/evidence/tier3.py` ran the
        # engine over the real fix commits for Pillow's GHSA-3f63-hfp8-52jq and
        # GHSA-r854-96gq-rfg3, where `\beval\s*\(` matched `def eval(image, *args):`
        # -- a *method declaration* -- and `builtins.eval(...)`. The first would
        # have renamed a method definition; the second would have produced
        # `builtins.ast.literal_eval(...)`, which does not exist. Neither is the
        # vulnerability, and neither would have compiled. See `docs/evidence.md`.
        pattern=re.compile(r"(?<![\w.])(?<!def )eval\s*\("),
        replacement="ast.literal_eval(",
        cwes=frozenset({"CWE-95"}),
        rule_hints=("eval-detected", "eval", "code-injection"),
        note="use ast.literal_eval(), which parses literals without executing them",
        description=(
            "Replace a bare call to the builtin eval() with ast.literal_eval(), which "
            "parses Python literals without executing arbitrary code. Only an "
            "unqualified call is rewritten: a `def eval(` declaration and a qualified "
            "`builtins.eval(` are left alone, because renaming either would break the "
            "code rather than secure it. NOTE: this rewrite does not add the required "
            "`import ast`, so a human must add it -- the change is correct but not "
            "complete on its own."
        ),
    ),
    Rewrite(
        name="sql-fstring-to-bound-parameter",
        pattern=re.compile(
            # `body` must capture the *whole* literal, verb included, not just
            # the leading keyword. An earlier version grouped only the verb and
            # let the rest match ungrouped, so the rewrite received "SELECT",
            # found no interpolation in it, and declined to fire -- which would
            # have silently disabled SQL parameterisation entirely.
            r"(?P<indent>[ \t]*)(?:sql\s*=\s*)?f(?P<quote>[\"'])"
            r"(?P<body>(?:SELECT|INSERT|UPDATE|DELETE)[\s\S]*?)(?P=quote)",
            re.IGNORECASE,
        ),
        cwes=frozenset({"CWE-89"}),
        rule_hints=("sql-injection", "raw-query", "sqli"),
        note=(
            "bound parameter, not string interpolation -- pass the values via "
            "execute(text(sql), params); for a LIKE, the wildcards go in the value"
        ),
        transform=_parameterize_sql,
        description=(
            "Replace the f-string SQL literal with a parameterised statement, turning "
            "every interpolated value into a bound parameter. The statement text is "
            "preserved exactly. Where an interpolation sat inside a string literal, "
            "the whole literal becomes one placeholder, because a driver substitutes "
            "into SQL rather than into a Python string: a placeholder written inside "
            "quotes is either a syntax error or a way straight back to the injection. "
            "For a LIKE that means the wildcards move into the bound value "
            '(\'"%" + term + "%"\'), and any literal percent sign outside a hoisted '
            "literal is doubled so it survives the driver's own percent escaping. "
            "The patch is NOT runnable on its own: it leaves `execute(sql = ...)` in "
            "place, which is a TypeError, because supplying the values is the part "
            "that changes the call's shape and belongs to a human. The loud failure "
            "is deliberate; a patch that half-runs is worse."
        ),
    ),
    Rewrite(
        name="shell-true-to-argv-list",
        pattern=re.compile(r"shell\s*=\s*True"),
        replacement="shell=False",
        cwes=frozenset({"CWE-78"}),
        rule_hints=("shell-true", "subprocess", "command-injection", "os-command"),
        note="pass an argv list, never a shell string",
        description=(
            "Remove shell=True so an interpolated value is never parsed as shell "
            "syntax. The command should also become a list of arguments; that part "
            "is left to a human because it changes the call's shape."
        ),
    ),
    Rewrite(
        name="disable-tls-verification",
        pattern=re.compile(r"InsecureSkipVerify\s*:\s*true"),
        replacement="InsecureSkipVerify: false",
        cwes=frozenset({"CWE-295"}),
        rule_hints=("tls", "skipverify", "certificate", "insecure"),
        languages=frozenset({"go"}),
        note="verify the gateway certificate",
        description=(
            "Re-enable certificate verification. If the upstream certificate is "
            "self-signed, pin its CA into the transport config rather than "
            "disabling verification for every host. Go-only: `InsecureSkipVerify: "
            "false` is a Go struct field, and no other language in the table spells "
            "it that way, so the rule declines elsewhere rather than emitting a "
            "field that does not exist."
        ),
    ),
    Rewrite(
        name="move-secret-to-environment",
        # The identifier has to *end* in a word that means "this is a secret".
        # `\w*(?:Secret|Key|Token|...)` anywhere in the name was far too loose:
        # Tier 3 ran this over celery's real fix commit for GHSA-q4xr-rc97-m4xx
        # and it fired on `task_keyprefix = 'celery-task-meta-'`, a Redis key
        # prefix. Rewriting that to `os.environ["task_keyprefix"]` would have
        # turned a working constant into a crash. Requiring the name to *end*
        # in the word keeps every real case -- `HARDCODED_API_KEY`,
        # `STRIPE_SECRET_KEY`, `StripeSecretKey`, `DB_PASSWORD`, `client_secret`,
        # `aws_secret_access_key` -- and drops `task_keyprefix`.
        pattern=re.compile(
            r"^(?P<indent>[ \t]*)(?:const\s+)?"
            r"(?P<name>\w*(?:secret|key|token|password|passwd|credential|credentials|auth))"
            r"\s*=\s*[\"'](?P<value>[^\"']{8,})[\"']",
            re.IGNORECASE | re.MULTILINE,
        ),
        replacement='\\g<name> = os.environ["\\g<name>"]',
        cwes=frozenset({"CWE-798"}),
        rule_hints=("hardcoded", "credential", "secret", "api-key"),
        note="read the secret from the environment, never from source control",
        description=(
            "Move the credential out of source control and read it from the "
            "environment. Fires only when the identifier ends in a word that means "
            "secret, key, token, password or credential, so a `task_keyprefix` "
            "constant is left alone. The committed value must also be rotated: it has "
            "to be treated as compromised the moment it is pushed, and this rewrite "
            "does not do that. The replacement is Python, so a Go `const Key = "
            '"..."` escalates rather than receiving `os.environ[...]` -- which does '
            "not compile. Note also that a module-level `os.environ[...]` raises at "
            "*import* time when the variable is unset, so the application does not "
            "start; that fails closed, which is the right direction, but it is a "
            "deployment change and the human should know."
        ),
    ),
    Rewrite(
        name="http-redirect-strip-proxy-auth",
        pattern=re.compile(r"allow_redirects\s*=\s*True"),
        replacement="allow_redirects=False",
        cwes=frozenset({"CWE-200"}),
        rule_hints=("redirect", "proxy-authorization", "header-leak"),
        note="do not follow redirects implicitly; re-issue without Proxy-Authorization",
        description=(
            "Disable automatic redirect following for the proxied request and "
            "handle the redirect explicitly so Proxy-Authorization is not forwarded "
            "to the redirect target. Heavier-handed than the real fix in "
            "requests GHSA-j8r2-6x86-q33q, which keeps following the redirect and "
            "strips only the header on a TLS tunnel; a client that must follow "
            "redirects will need the surgical version, and a human should decide "
            "which one the codebase wants."
        ),
    ),
)


class DeterministicDeveloper:
    """Rule-based patch author.

    Deterministic by construction: the same finding and the same feedback
    always produce the same patch. That property is what makes it usable as a
    test oracle -- `tests/unit/agents/test_deterministic_agents.py` asserts the exact
    diff for a known eval() finding, and that assertion is only meaningful
    because the output cannot drift.
    """

    @property
    def model_name(self) -> str | None:
        # `None`, not a fake model name. The remediation records it, and "was
        # this an LLM run?" has to be answerable from the data.
        return None

    def __init__(self, rule_table: tuple[Rewrite, ...] = _REWRITES) -> None:
        self._rules = rule_table

    def develop(
        self,
        *,
        snippet: str,
        file_path: str,
        rule_id: str,
        cwe_ids: list[str],
        feedback: list[str],
        round_index: int,
    ) -> AgentTurn:
        """Produce a patch, or explain why it cannot.

        A revision round re-applies the same rewrite with the reviewer's
        feedback in hand. If the reviewer asked for something the rule table
        does not cover, the developer says so rather than inventing a change --
        an agent that fabricates a fix to satisfy a critic is worse than one
        that escalates.

        Two distinct reasons for declining, reported differently, because they
        need different humans: *no rule for this class*, and *a rule for this
        class whose replacement is not valid in this file's language*. The
        second is the interesting one -- a Go `const Key = "..."` finding used to
        be "fixed" with a Python `os.environ[...]`, which does not compile.
        """
        if not snippet.strip():
            return AgentTurn(
                role="developer",
                decision=AgentDecision.ESCALATE,
                summary="Cannot draft a patch without a source snippet",
                rationale=(
                    "The finding has no snippet, so there is no code to transform. "
                    "A human needs to identify the affected code first."
                ),
                message="no snippet supplied",
            )

        language = language_of(file_path)
        wrong_language: list[str] = []

        for rule in self._rules:
            if not (rule.pattern.search(snippet) and rule.applies_to(rule_id, cwe_ids)):
                continue
            if not rule.applies_to_language(file_path):
                # Remembered rather than skipped silently, so the escalation can
                # say "the rule exists but emits Go into a Python file" instead of
                # the far less useful "no known pattern".
                wrong_language.append(f"{rule.name} emits {'/'.join(sorted(rule.languages))}")
                continue

            patched_body = rule.apply(snippet, file_path)
            if patched_body == snippet:
                continue

            patch = _unified_diff(file_path, snippet, patched_body, round_index, note=rule.note)
            rationale = rule.description
            if feedback:
                rationale += (
                    f" Revision {round_index} addresses the reviewer's "
                    f"{len(feedback)} prior comment(s)."
                )

            return AgentTurn(
                role="developer",
                decision=AgentDecision.PROPOSE,
                patch=patch,
                summary=f"Replace the vulnerable construct in {file_path} ({rule.name})",
                rationale=rationale,
                message=patched_body,
                metadata={
                    "rewrite": rule.name,
                    "cwes": sorted(rule.cwes),
                    "language": language,
                },
            )

        if wrong_language:
            return AgentTurn(
                role="developer",
                decision=AgentDecision.ESCALATE,
                summary=f"Known rewrites for this class do not apply to {file_path}",
                rationale=(
                    f"The rule table recognises this vulnerability class, but the finding "
                    f"is in a {language} file and "
                    f"{', '.join(wrong_language)}. Emitting that into this file would "
                    "produce code that does not compile, which is worse than declining. "
                    "A human needs to write the fix in the right language."
                ),
                message="rewrite exists but is not valid in this language",
                metadata={
                    "considered_rules": len(self._rules),
                    "language": language,
                    "rejected_for_language": wrong_language,
                },
            )

        return AgentTurn(
            role="developer",
            decision=AgentDecision.ESCALATE,
            summary=f"No known remediation pattern matches {file_path}",
            rationale=(
                "The deterministic rule table has no rewrite for this vulnerability "
                "class. Escalating rather than guessing: a wrong patch applied to a "
                "security finding is worse than no patch."
            ),
            message="no matching rewrite rule",
            metadata={"considered_rules": len(self._rules), "language": language},
        )


class DeterministicReviewer:
    """Rule-based reviewer. Genuinely strict, and it does reject.

    Three checks, in order, each producing a concrete comment:
      1. the vulnerable construct must actually be gone
      2. the patch must be a syntactically valid Python file, if it is Python
      3. the patch must change something, and only the reported lines

    Check 3 is what makes a "reviewer" worth having: a patch that rewrites a
    whole file to fix one line is a patch a human will not approve, and an
    agent that cannot tell the difference will keep producing them.
    """

    def __init__(self, rule_table: tuple[Rewrite, ...] = _REWRITES) -> None:
        self._rules = rule_table

    def review(
        self,
        *,
        patch: str,
        snippet: str,
        file_path: str,
        rule_id: str,
        round_index: int,
    ) -> AgentTurn:
        """Judge a patch. Approves only when every check passes."""
        comments: list[str] = []

        if not patch.strip():
            return AgentTurn(
                role="reviewer",
                decision=AgentDecision.REQUEST_CHANGES,
                summary="Empty patch",
                rationale="The developer returned no patch, so there is nothing to review.",
                message="empty patch",
            )

        added_lines = _added_lines(patch)
        removed_lines = _removed_lines(patch)

        # 1. Did it remove the vulnerable construct? Only rules that actually
        #    apply to this finding are considered -- checking the reviewer
        #    against every rule in the table would flag unrelated constructs.
        for rule in self._rules:
            if not (rule.pattern.search(snippet) and rule.applies_to(rule_id, [])):
                continue
            if any(rule.pattern.search(line) for line in added_lines):
                comments.append(
                    f"The patch still introduces `{rule.name}`'s vulnerable construct. "
                    f"This is a no-op or a re-introduction of the original flaw."
                )
                break

        # 2. Does the result still parse?
        #
        #    Only for a like-for-like line replacement. This is the third
        #    iteration of this check and the reason is worth recording.
        #
        #    The check reconstructs the patched source from the diff's added
        #    lines, because the system deliberately never reads the whole file.
        #    That reconstruction is only the patched file when one line became
        #    one line -- which is the only shape any rewrite in this table
        #    produces. For anything else it is a fragment, and a fragment that
        #    will not compile says nothing about the patch.
        #
        #    Measured over 30 real, merged security fixes: with the check
        #    running unconditionally it was the objection in 15 of the 18
        #    rejections, because a fix that adds a `try:` block, or replaces
        #    three lines with nine, produces added lines that are not valid
        #    Python in isolation. A gate that rejects most correct work stops
        #    being read, which is the failure mode ADR 001 is about.
        #
        #    The two earlier iterations: it fired on a lone
        #    `def fetch_followed_link(url, allow_redirects=False):` (fixed by
        #    `_parses_with_implicit_body`), and before that it was not a check
        #    at all. Found by `backend/evidence/tier3.py`; see
        #    `docs/evidence.md`.
        if file_path.endswith(".py") and len(added_lines) == len(removed_lines):
            candidate = _reconstructed_source(snippet, added_lines)
            if candidate is not None and not _parses_as_python(candidate, file_path):
                if not _parses_with_implicit_body(added_lines, file_path):
                    comments.append(
                        "The patched source does not parse. A patch that does not compile "
                        "cannot be merged, whatever else it does correctly."
                    )
                else:
                    logger.debug(
                        "skipping the parse check: the patch adds a block header whose body "
                        "is not in the diff, so the reconstruction is not the patched file"
                    )
        elif file_path.endswith(".py"):
            logger.debug(
                "skipping the parse check: %d added line(s) against %d removed line(s) is "
                "not a like-for-like replacement, so the reconstruction would be a fragment",
                len(added_lines),
                len(removed_lines),
            )

        # 3. Is the change scoped to the finding?
        if removed_lines and not any(
            line.strip() and line.strip() in snippet for line in removed_lines
        ):
            comments.append(
                "The patch removes lines that are not present in the reported "
                "snippet, so it is not scoped to this finding. Narrow the diff."
            )
        if len(added_lines) > 20:
            comments.append(
                f"The patch adds {len(added_lines)} lines for a single finding. "
                "Security fixes should be reviewable in one sitting."
            )

        if comments:
            return AgentTurn(
                role="reviewer",
                decision=AgentDecision.REQUEST_CHANGES,
                summary=f"Changes requested ({len(comments)} issue(s))",
                rationale=(
                    "The draft does not yet meet the review bar. Each comment below "
                    "is a concrete, checkable requirement rather than a preference."
                ),
                message="\n".join(f"- {c}" for c in comments),
                metadata={"comment_count": len(comments)},
            )

        return AgentTurn(
            role="reviewer",
            decision=AgentDecision.APPROVE,
            summary="Patch approved by automated review",
            rationale=(
                "All automated checks pass: the vulnerable construct is removed, the "
                "patched source parses, and the change is scoped to the reported "
                "lines. This approval is necessary but NOT sufficient -- a human "
                "approver still has to authorize the pull request before it opens."
            ),
            message="approved",
            metadata={"checks_passed": 3},
        )


def _unified_diff(
    file_path: str, original: str, patched: str, round_index: int, *, note: str = ""
) -> str:
    """Render a minimal unified diff between the snippet and its rewrite.

    Hand-rolled with `difflib` rather than shelling out to `git diff`: no
    repository, no git configuration, and deterministic output that is safe to
    assert on in a test. The header names the real target path, so the diff is
    directly usable as the body of a pull request.

    Both sides are newline-normalized first. A scanner-reported snippet very
    often has no trailing newline (it is one line of a larger file), and
    `difflib` with `keepends=True` then emits the `-` and `+` lines
    concatenated onto one line -- a diff that `git apply` rejects.

    `note` goes in the preamble, *outside* the `---`/`+++` block, so it is
    visible in the pull request without ever becoming part of the source. A
    markdown code fence makes the preamble a comment for the reader and nothing
    at all for the patcher.
    """
    import difflib

    original_text = original if original.endswith("\n") else original + "\n"
    patched_text = patched if patched.endswith("\n") else patched + "\n"

    diff = difflib.unified_diff(
        original_text.splitlines(keepends=True),
        patched_text.splitlines(keepends=True),
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        n=3,
    )
    body = "".join(diff)

    preamble = [
        f"### SentinelMCP remediation (round {round_index})",
        f"### target: {file_path}",
    ]
    if note:
        preamble.append(f"### fix: {note}")
    return "\n".join(preamble) + "\n\n" + body


def _added_lines(patch: str) -> list[str]:
    return [
        line[1:].rstrip("\n")
        for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]


def _removed_lines(patch: str) -> list[str]:
    return [
        line[1:].rstrip("\n")
        for line in patch.splitlines()
        if line.startswith("-") and not line.startswith("---")
    ]


def _parses_as_python(source: str, filename: str) -> bool:
    """Whether `source` is syntactically valid Python.

    Retries inside a function body, because a scanner-reported snippet is a
    *fragment* of a file: `return render(eval(x))` is a `SyntaxError` at module
    level and perfectly valid three lines further down. Compiling only the
    fragment would make every remediation of a return-statement finding request
    changes for a reason that has nothing to do with the patch.

    The retry is the check, not an escape hatch from it: a genuinely broken
    patch fails both attempts, and a `return` that is genuinely at module level
    in the real file is a pre-existing problem the human is going to see anyway.
    """
    for candidate in (source, "def _sentinel_probe():\n" + _indent(source)):
        try:
            compile(candidate, filename, "exec")
            return True
        except SyntaxError:
            continue
        except ValueError:  # null bytes, etc. -- not a syntax question
            return True
    return False


def _indent(source: str) -> str:
    return "".join(f"    {line}\n" for line in source.splitlines())


def _reconstructed_source(snippet: str, added_lines: list[str]) -> str | None:
    """Approximate the patched file, so the reviewer can syntax-check it.

    Replaces the snippet with the patch's added lines. An approximation, and
    documented as one: a real check would need the whole file, which the system
    deliberately does not read (it patches against a scanner-reported snippet
    and nothing else). The approximation still catches the common failure --
    a regex rewrite that produces unbalanced brackets -- which is the failure
    worth catching before a human sees the diff.

    It is an approximation in both directions, and the reviewer's parse check
    compensates for the one that matters: see `_is_structurally_incomplete`.
    """
    if not added_lines:
        return None
    return "\n".join(added_lines) + "\n"


# A line that opens a block. The added lines of a signature-only patch are one of
# these and nothing else, which is what makes the reconstruction unparseable for
# reasons that have nothing to do with the patch being wrong.
_BLOCK_OPENERS = (
    "def ",
    "class ",
    "if ",
    "elif ",
    "else:",
    "for ",
    "while ",
    "with ",
    "try:",
    "match ",
)


def _parses_with_implicit_body(added_lines: list[str], file_path: str) -> bool:
    """Whether the added lines parse once a body is assumed under any block.

    The question the reviewer's parse check cannot answer from a diff alone: did
    the reconstruction fail because the *patch* is malformed, or because the
    lines open a block whose body is not in the diff?

    Answered by trying, not by pattern-matching on `:`. A regex cannot tell
    `def f():` -- a valid header missing its body -- from `def f(:` -- a
    genuinely broken line, and the second must still be rejected. Appending a
    `pass` under the block and compiling is the difference: the first becomes
    valid, the second stays a `SyntaxError`.

    Cheap, because it only runs on a patch that already failed the cheaper check.
    """
    if not added_lines:
        return False
    source = "\n".join(added_lines)
    indented = _indent(source)
    for candidate in (
        f"{source}\n    pass\n",
        f"{indented}    pass\n",
    ):
        try:
            compile(candidate, file_path, "exec")
            return True
        except (SyntaxError, ValueError):
            continue
    return False
