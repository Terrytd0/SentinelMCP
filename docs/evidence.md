# Measured evidence: does the remediation engine actually fix things?

The system can prove it cannot merge its own code. `tests/unit/policy/test_safety_rails.py`
AST-walks `backend/` to prove no new code can add a merge path, and that guarantee
is solid. But it says nothing about whether a drafted patch is *correct*, and until
this document existed nothing in the repository did.

That is a specific and serious gap, because the entire product is the claim that an
agent can turn a finding into a change. A tool that drafts a security patch and
cannot say whether the patch works is a brochure with a database attached.

## What this is

Three tiers of evidence, each answering a different question, each able to fail on
its own. Run it with:

```bash
python scripts/evidence_report.py            # all three tiers, six advisories
python scripts/evidence_report.py --all      # all nineteen
python scripts/evidence_report.py --tiers 1  # no network, ~2 seconds
```

Tier 1 needs nothing but the interpreter. Tier 2 needs the `semgrep` binary and, on
first run, the network for its rule packs. Tier 3 needs `git` and GitHub.

| tier | question | whose answer is it | needs a network |
|---|---|---|---|
| 1 `execution` | does the patch stop a real exploit? | ours, by running it | no |
| 2 `semgrep_check` | does an independent detector stop reporting it? | Semgrep's | first run only |
| 3 `corpus` | what happens on real CVEs and real upstream fixes? | upstream's | yes |

## Why there is no pass rate

A security tool that reports "92% of patches verified" is claiming a number it
cannot support, because every available denominator is chosen by the thing being
measured. The rule table is six rewrites. The Tier 1 cases are eight, six of which
were written *about* the rules they test. The Tier 3 corpus is nineteen advisories
this project picked. Any percentage built on those is flattering by construction.

So the report leads with what each tier could not check, and the counts of patches
that are incomplete, that regress the function, that needed a human step before
they would run, and that no tier covers at all. Those numbers are hard to fake,
and they are the ones worth reading.

## What it found

Eight findings: **seven code defects and one measurement defect.** Four of the code
defects were invisible to the 300-test suite, and one of those was being actively
asserted as correct by a green test. Every one is now fixed, pinned by a regression
test, and the report still shows the consequences.

### 1. The SQL rewrite emitted a statement that silently returned the wrong rows

`sql-fstring-to-bound-parameter` turned `LIKE '%{term}%'` into `LIKE '%s%'`. The
`%` wildcard immediately before the placeholder collides with it, and the failure
depends on the driver:

- **psycopg2** — this project's declared database driver — raises
  `ValueError: unsupported format character "'"`. The patch does not run.
- **sqlite3**, which does not treat `%` specially, runs the statement happily and
  returns **the wrong rows with no error at all**: `'%s%'` as SQL means "any
  prefix, a literal `s`, any suffix", so a search for `quarterly` returns whichever
  row happens to contain the letter `s`.

The existing test asserted the emitted text contained `%s`. The broken form
contains `%s`. It passed.

The fix is two rules, and the second is the one that matters: an interpolation
**inside** a SQL string literal has its whole literal hoisted into a single
placeholder, because a driver substitutes into SQL rather than into a Python
string. A placeholder written inside quotes is either a syntax error or a way
straight back to the injection. `LIKE '%{term}%'` now becomes `LIKE %s`, with the
wildcards moved into the bound value, which is what a competent engineer does.
Literal percents outside a hoisted literal are doubled so a genuine modulo
operator survives the driver's own escaping — which also fixed
`SELECT {a} % {b}`, previously emitted as `SELECT %s % %s` and broken.

### 2. The reviewer requested changes on a correct patch

The parse check reconstructs the patched source from the diff's *added lines*,
because the system deliberately never reads the whole file. For a one-line change
to a function signature, that reconstruction is a lone
`def fetch_followed_link(url, allow_redirects=False):` — a block header with no
body, which cannot compile. The reviewer therefore asked for changes on a
completely correct patch, and would have sent a security fix back for a reason
that had nothing to do with it.

The discrimination is made by trying rather than by pattern-matching on a colon,
because a regex cannot tell `def f():` (a valid header missing its body) from
`def f(:` (genuinely broken). Appending a `pass` and compiling separates them; the
broken one stays a `SyntaxError` and is still rejected.

### 3. The same check rejected most real upstream fixes

Fixing 2 was not enough, and Tier 3 said so loudly. The check is only valid for a
**like-for-like line replacement** — which is the only shape any rewrite in the
table produces. For anything else the added lines are a *fragment*: a fix that
replaces three lines with nine, or adds a `try:` block, produces added lines that
are not valid Python standing alone.

Run over the 30 real files, that check was the objection in **15 of 18
rejections**. It now runs only when the added and removed line counts match, with
the reasoning in a comment next to the condition. Rejections fell from **18 of 30
to 9 of 30**, and the cause moved to the checks that are arguing a real point.

### 4. Two rules emitted Python into Go files

`move-secret-to-environment` matched Go's `const StripeSecretKey = "sk_live_..."`
and answered with `StripeSecretKey = os.environ["StripeSecretKey"]`, which does not
compile. The test for it asserted that was correct, on a `.go` path — so the suite
was not merely blind to the defect, it was holding it in place.

`math-rand-to-crypto-rand` was worse: a Go pattern (`rand.Intn(`) with a Python
replacement (`secrets.randbelow(`). It could not be *repaired* and removed,
because `math/rand.Int(n) int` and `crypto/rand.Int(rand.Reader, n) (*big.Int, error)`
have incompatible signatures. No single-expression substitution is correct, and a
rule needing a new import, a `*big.Int` and an error path is not a regex. CWE-338
now escalates to a human.

The general fix is a `languages` field on every rewrite, naming the languages the
*replacement* is valid in — not the languages the pattern matches, and that
asymmetry is precisely the bug. An unrecognised extension matches nothing and
fails closed, for the same reason `_path_within_roots` does. The developer now
reports *which* rule it declined and why, rather than "no known remediation
pattern".

### 5. `eval(` matched the declaration of a method named `eval`

Tier 3 ran the engine over the real fix commits for Pillow's GHSA-3f63-hfp8-52jq
and GHSA-r854-96gq-rfg3. `\beval\s*\(` matched `def eval(image, *args):` — a
*method declaration*, which the rewrite would have renamed, breaking the class. It
also matched `builtins.eval(...)`, which the rewrite would have turned into
`builtins.ast.literal_eval(...)`, which does not exist.

Both are now excluded by lookbehinds: a bare, unqualified call only.

### 6. `task_keyprefix` was treated as a secret

Tier 3 ran the engine over celery's real fix commit for GHSA-q4xr-rc97-m4xx.
`task_keyprefix = 'celery-task-meta-'` matched the secret rule, because the
identifier contained `key` and the value was eight characters long. Rewriting it
to `os.environ["task_keyprefix"]` would have turned a working constant into a
crash. The pattern now requires the identifier to *end* in a word meaning secret,
key, token, password or credential — which keeps every real case
(`HARDCODED_API_KEY`, `STRIPE_SECRET_KEY`, `StripeSecretKey`, `DB_PASSWORD`,
`client_secret`, `aws_secret_access_key`) and drops the false positive.

### 7. Two defects in the harness itself, found by its own controls

Worth recording, because a harness that cannot fail is worse than no harness.

- **A stale `.pyc`.** Writing `VALUE = 1` and then `VALUE = 2` to the same path
  within one second gives the same size and the same mtime, so
  `SourceFileLoader` reused the cached bytecode and the "after" measurement
  silently re-measured the "before" module. Every load now gets its own filename
  as well as its own module name.
- **A marker that was never reset.** Every exploit in Tier 1 is detected by a file
  the attack creates, and the same context is used for the unpatched run, the
  patched run, and the mutation control. The first run left the marker behind and
  the second reported "the exploit still lands" no matter what the patch did. The
  marker is now cleared before every attempt.

### 8. The rejection rate was two-thirds a measurement artifact

Not a code defect — a *measurement* defect, and the most important correction in
this document.

The first version of this number fed the reviewer one line as the "reported
snippet" and then judged real upstream fixes of up to 67 lines against it. The
reviewer's scope check therefore failed by construction, and the report presented
that as a property of the reviewer.

The same fixes re-judged with a plausible amount of surrounding source came out at
**3 of 30**, against 9 of 30 for the one-line case. Two-thirds of the "scary"
number was the harness, and the conclusion was that the fix was a one-line change
to widen the snippet.

Building that change (`backend/scanners/snippet.py`) and re-measuring produced
**8 of 30**, not 3. The gap is the finding: a ±10 line window satisfies the
scope check by sweeping in the neighbouring lines a typical small fix touches,
which is passing by accident, while an enclosing block satisfies it by being the
right context. The residual 8 are fixes that also edit something far from the
finding, and no snippet anchored on one line reaches them.

That is a smaller win than the harness promised, and the harness was wrong rather
than the code. It is recorded here because the error is instructive: **when a
change makes a number look better, establish whether it made the number better or
the mechanism more defensible.** Those are different, and only one is a fix.

## The numbers

From `python scripts/evidence_report.py --all` on Semgrep 1.178.0, Python 3.13,
Windows 11.

### Tier 1 — execution

Six of eight cases measurable; two declared skipped with a reason. Six passed,
zero failed.

| case | CWE | outcome | reviewer | human steps needed |
|---|---|---|---|---|
| `eval-to-literal-eval` | CWE-95 | exploit blocked, behaviour preserved | APPROVE | 1 |
| `sql-fstring-to-bound-parameter` | CWE-89 | exploit blocked, behaviour preserved | APPROVE | 0 |
| `shell-true-to-argv-list` | CWE-78 | exploit blocked, behaviour preserved | APPROVE | 0 |
| `move-secret-to-environment` | CWE-798 | exploit blocked, behaviour preserved | APPROVE | 1 |
| `http-redirect-strip-proxy-auth` | CWE-200 | exploit blocked, behaviour preserved | APPROVE | 0 |
| `no-rule-for-template-injection` | CWE-1336 | declined to a human | not reached | 0 |
| `disable-tls-verification` | CWE-295 | *skipped — no Go toolchain* | — | — |
| `math-rand-to-crypto-rand` | CWE-338 | *skipped — rule removed* | — | — |

**The deterministic reviewer approved five of these.** That is the point of the
tier: the reviewer's approval is not evidence that a patch fixes anything, and
only execution distinguishes the two. The reviewer checks three structural
properties — the vulnerable construct is gone, the result parses, the diff is
small — and those are all true of a patch that returns the wrong rows.

Two results worth reading twice:

- **`shell-true-to-argv-list` is platform-dependent.** `shell=False` blocks the
  injection on both Windows and POSIX, but on POSIX `subprocess.run` hands the whole
  string to `execvp` as `argv[0]`, so a command *with arguments* cannot run at all.
  The same patch is correct on one platform and destructive on the other, and
  nothing in the diff says which. That is the strongest argument this project has
  for not leaving the argv-list change to a human.
- **`move-secret-to-environment` fails closed, loudly.** The rewrite emits a
  *module-level* `os.environ[...]`, so an unset variable raises during **import**
  and the application does not start. That is the right direction, and it is a
  deployment change the human should be told about rather than discovering.

### Tier 2 — independent static analysis

Semgrep 1.178.0 over `data/samples/vulnerable_app/`, pinned registry rules.
Eight findings before, four after.

| outcome | n | meaning |
|---|---|---|
| `fixed` | 4 | we patched the line and the rule stopped firing |
| `declined-correctly` | 1 | we recognised the class and refused, because the fix would not compile |
| `no-rewrite-available` | 2 | no rule covers this class, so the engine escalated |
| `still-firing` | 1 | we patched the line and a *different* rule still reports a *different* problem there |

Credited CWE classes: `CWE-78`, `CWE-798`, `CWE-89`, `CWE-95`.

**The vacuity guard is load-bearing.** `semgrep --config <a URL that is not a rule>
--json` exits 0 and reports zero findings. There is no error and no non-zero
status. While building this tier, four of eleven guessed rule ids resolved to
nothing and reported "0 hits" in exactly the way a *fixed* vulnerability would. A
harness built on that assumption reports a perfect score for a rule set that never
ran. So the tier refuses to report anything unless at least one pinned rule fired
on the unpatched tree, and `run_tier_2` exits non-zero when it cannot.

### Tier 3 — real CVEs and the real commits that fixed them

Nineteen GitHub Security Advisories across seven repositories, fetched from their
upstream fix commits. All nineteen fetched, 30 real source files examined, about a
minute with a warm git cache.

The label is not a judgement call. For an advisory with fix commit `S`, the pair is
the content of the files `S` changed, read at `S` and at `S`'s first parent. For
merge commits the first parent is used, because diffing a merge against anything
else measures the wrong change.

**Coverage: 3 of 30 files (10%) had a line the rule table could act on.** Twenty-
seven had no candidate line at all. That is the honest number for a six-rule table
and it is low. The candidate line is found by scanning for a pattern the rule table
already matches, so 10% is an *upper* bound on what the engine could find, not a
measurement of how many real vulnerabilities it detects.

Of the three patches proposed, **two landed on a line upstream also changed** —
`django`'s hardcoded `PASSWORD`, and `shell=True` in Pillow's `ImageShow`. The
third patched a real `allow_redirects=True` that was not the vulnerability: pattern
presence is not vulnerability location, and no regex can close that gap from a
one-line snippet.

**9 of 30 real, merged, human-reviewed security fixes (30%) would be rejected by
`DeterministicReviewer` given the one line a scanner reports.** Given the
enclosing block the loop is now actually shown, 26 lines on average:
**8 of 30 (26%)**. By which check, in the one-line configuration:

| check | objections | what it asserts |
|---|---|---|
| `scoped` | 8 | the change is confined to the reported lines |
| `size` | 3 | a single-finding patch stays under 20 added lines |

The widening is shipped (`backend/scanners/snippet.py`), and it is worth having
for a reason this measurement does not capture: the AutoGen engine drafts from
the same snippet, and drafting a patch from one line of a 200-line function is
worse than drafting from the function. That part is **not measured and not
claimed**.

What is still missing is the other half of the measurement, and it is the half that
matters: **this corpus is all good patches.** A reviewer that rejects even 8 of 30
correct work is bad news, but the number that would settle whether the gate earns
its place is how often it rejects a patch that is *wrong*, and that needs a corpus
of bad patches labelled by a human. That does not exist.
[docs/architecture.md §13](architecture.md) argues the two readings of what the
gate is for.

The corpus is a deliberate mix of CWEs the table covers (78, 89, 95, 200, 295,
798) and CWEs it does not (77, 94, 113, 601, 670, 770). Including the second group
is the entire point: a corpus of only the easy cases would report a coverage figure
that means nothing, and a test asserts the mix is preserved.

## Known blind spots

Unconditional. These do not change when a run goes well.

- **CWE-295** (TLS verification) has no execution coverage here — the rewrite is
  Go-only and there is no Go toolchain — and no pinned Semgrep rule was found that
  fires on `InsecureSkipVerify: true`. Tier 1 and Tier 2 independently record it as
  unverified. Two tiers agreeing a rule is unverified is a result.
- **CWE-200** (credential forwarded across a redirect) is verifiable only by
  execution. No static analyser flags `allow_redirects=True`; it is a library
  behaviour, not a pattern. Tier 1 covers it with two real HTTP servers on
  ephemeral ports, because a mocked HTTP client asserts only that the mock was
  called.
- **CWE-338** (weak randomness) has no rewrite. Escalating is correct and is
  asserted in the unit suite.
- **CWE-489, CWE-1336, CWE-190, CWE-352 and CWE-319** in `data/fixtures/` all have
  no rewrite. Escalating is what the engine does.
- **No tier can see a vulnerability whose vulnerable line is not a single line the
  rule table matches.** Tier 3 measures how often that is, and the answer is most
  of the time.
- **Tier 1's cases were written by the same author as the rules.** That is the
  weakness Tier 3 exists to offset, and Tier 3 covers only the part of it that
  overlaps with six CWE classes.

## Why the gates are shaped this way

Three things in this package exist only to stop it flattering itself.

**The mutation control.** After each case, the diff is re-applied *in reverse* and
the exploit has to come back. Without it, a harness that always reports "exploit
blocked" is indistinguishable from a harness that works. Six of the eight cases
pass it, and a control that cannot fail reports `control-failed` rather than
skipping.

**The exploit must land first.** A case whose exploit does not fire on the
unpatched module has measured a broken test, not a fix. Those cases fail.

**Declared regressions stay declared.** Where the engine's real behaviour *is* a
regression, the case declares that, the harness confirms it, and the report counts
it. Declaring it is not excusing it: the count is in the headline, and a test fails
if a declared regression is quietly deleted to make the report look better.

Same reasoning behind the `apply_patch` failure modes. A patch whose removed lines
cannot be located is reported with a reason and leaves the text untouched, because
a verification harness that silently skipped the patch it was measuring would be
worse than no harness. `apply_patch` had to be written: the diff this codebase
produces is `difflib` over a *snippet* treated as a one-line document, with
`@@ -1 +1 @@` always and `---`/`+++` headers naming the whole file. `git apply` and
`patch` both reject that, and nothing in `backend/` had ever written a patched file
to disk — which is why every existing test asserted on the diff *string* and none
on the diff *applied*.

## Reproducing

```bash
python scripts/evidence_report.py --all --markdown -o docs/evidence-results.md
```

The committed `docs/evidence-results.md` is a generated snapshot of that command
and carries its own header saying so. Regenerate it rather than editing it; a
number in it that disagrees with a fresh run is a question about the engine, not
about the file.

Tier 3 caches fetched repositories under `data/evidence/.cache/` (gitignored), so
only the first run needs the network. Semgrep caches its own rule packs. Numbers
are recorded with the Semgrep version that produced them, because the rule packs
are third-party and versioned: without it, a changed number cannot be attributed
to anything.

A run where an advisory cannot be fetched **exits non-zero** and says so above the
numbers. That happened once while writing this — 18 of 19 fetched, and the report
showed the missing one rather than quietly measuring 18 and calling it 19.

Integration coverage for the network-dependent tiers lives in
`tests/integration/test_semgrep_patch_verification.py` and
`tests/integration/test_real_advisory_corpus.py`, and skips itself when the
dependency is absent — a bare `pytest` with nothing running passes.

The tier logic itself is unit-tested in `tests/unit/evidence/`, including tests
that deliberately break the harness to confirm it reports red. Those run in the
normal suite, in about ten seconds, and need no network.
