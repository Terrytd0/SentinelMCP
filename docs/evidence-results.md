# Measured evidence: does the remediation engine actually fix things?

> **This is a generated snapshot.** Produced by `python scripts/evidence_report.py --all --markdown`, not written by hand. Regenerate it rather than editing it, and treat a number here that disagrees with a fresh run as a question about the engine, not about the file.

Every number below is produced by running the engine, not by asserting on its output. Read [how to read this](#how-to-read-this) and [known blind spots](#known-blind-spots) before the numbers. The narrative version, including what the tiers found and why the gates are shaped the way they are, is in [evidence.md](evidence.md).

## How to read this

There is deliberately **no single pass rate**. Every denominator available here -- 6 rewrites in the rule table, 8 hand-written execution cases, 19 advisories this project chose -- is flattering by construction, and a percentage built on one of them would be a claim the evidence does not support.

| tier | question | whose answer |
| --- | --- | --- |
| 1 execution | does the patch stop a real exploit? | ours, by running it |
| 2 static | does an independent detector stop reporting it? | Semgrep's |
| 3 corpus | what happens on real CVEs and real upstream fixes? | upstream's |

## The run

| | |
| --- | --- |
| python | `3.13.0` |
| platform | `Windows 11` |
| semgrep | `C:\Users\terry\OneDrive\Documents\AI Engineering Folder\SentinelMCP\.venv\Scripts\semgrep.exe` |
| corpus | `19 advisories, 19 fetched` |
| tiers run | 3 of 3 |
| things a reader must not miss | 0 |

## Tier 1: execution

6 of 8 cases measurable, 2 declared skipped with a reason. **6 passed, 0 failed.** Exploit blocked in 5, behaviour regressed in 1, 2 needed a declared human step before the patched module would run at all.

> The deterministic reviewer approved **5** of these patches. That is the point of the tier: the reviewer's approval is not evidence that a patch fixes anything, and only execution distinguishes the two.

| case | CWE | outcome | reviewer | human steps needed |
| --- | --- | --- | --- | --- |
| `eval-to-literal-eval` | CWE-95 | preserved | APPROVE | 1 |
| `sql-fstring-to-bound-parameter` | CWE-89 | preserved | APPROVE | 0 |
| `shell-true-to-argv-list` | CWE-78 | preserved | APPROVE | 0 |
| `move-secret-to-environment` | CWE-798 | preserved | APPROVE | 1 |
| `http-redirect-strip-proxy-auth` | CWE-200 | preserved | APPROVE | 0 |
| `no-rule-for-template-injection` | CWE-1336 | preserved | (not reached) | 0 |
| `disable-tls-verification` | CWE-295 | _skipped: the rewrite's pattern is Go-only and this repository has no Go toolchain, so the patched file cannot be executed_ | not reached | 0 |
| `math-rand-to-crypto-rand` | CWE-338 | _skipped: the rewrite was removed rather than fixed: its pattern was Go's rand_ | not reached | 0 |

**`sql-fstring-to-bound-parameter`, on the statement itself:** the rewrite emits `SELECT * FROM reports WHERE title LIKE %s`, which binds as the note instructs to `SELECT * FROM reports WHERE title LIKE '%quarterly%'`, and selects the same rows as the original query: `True`. The statement is never executed as emitted -- the rewrite leaves `execute(sql = ...)`, which is a `TypeError`, because writing the bind call is the human's job.

## Tier 2: static analysis

Semgrep `1.178.0`, pinned rules (`p/security-audit`, `p/golang`, `p/secrets`, `https://semgrep.dev/r/python.lang.security.audit.formatted-sql-query`). **8 findings before, 4 after.**

| outcome | n | meaning |
| --- | --- | --- |
| `fixed` | 4 | we patched the line, and the rule stopped firing |
| `no-rewrite-available` | 2 | no rule covers this class, so the engine escalated |
| `declined-correctly` | 1 | we recognised the class and refused, e.g. the fix would not compile |
| `still-firing` | 1 | we patched the line and the rule still fires |

| rule | location | CWE | rewrite | outcome |
| --- | --- | --- | --- | --- |
| `generic.secrets.security.detected-stripe-api-key.detected-stripe-api-key` | `app.py:21` | CWE-798 | `move-secret-to-environment` | fixed |
| `python.lang.security.audit.eval-detected.eval-detected` | `app.py:26` | CWE-95 | `eval-to-literal-eval` | fixed |
| `python.lang.security.audit.formatted-sql-query.formatted-sql-query` | `app.py:35` | CWE-89 | `sql-fstring-to-bound-parameter` | fixed |
| `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true` | `app.py:41` | CWE-78 | `shell-true-to-argv-list` | fixed |
| `python.flask.security.audit.debug-enabled.debug-enabled` | `app.py:65` | CWE-489 | `--` | no-rewrite-available |
| `go.lang.security.audit.crypto.math_random.math-random-used` | `gateway.go:19` | CWE-338 | `--` | no-rewrite-available |
| `generic.secrets.security.detected-stripe-api-key.detected-stripe-api-key` | `gateway.go:25` | CWE-798 | `--` | declined-correctly |
| `go.lang.security.audit.crypto.missing-ssl-minversion.missing-ssl-minversion` | `gateway.go:30` | CWE-327 | `disable-tls-verification` | still-firing |

Credited CWE classes: `CWE-78`, `CWE-798`, `CWE-89`, `CWE-95`.

Declined, with the reason:

- `gateway.go:25 move-secret-to-environment -> ESCALATE: rewrite exists but is not valid in this language`

## Tier 3: real CVEs and the real commits that fixed them

19 GitHub Security Advisories, fetched from their upstream fix commits. **19 fetched, 30 real source files examined** (38.8s).

### Coverage: how often does a real CVE have a line this engine can act on?

| | count | of |
| --- | --- | --- |
| files where a rule engaged | 3 | 30 |
| files with no candidate line at all | 27 | 30 |
| files where the engine declined | 0 | 30 |

**3 of 30** -- 10%. That is the honest coverage number for a six-rule table, and it is low. The candidate line is found by scanning for a pattern the table already matches, so this is an *upper* bound on what the engine could find, not a measurement of how many real vulnerabilities it detects.

### Line agreement with the real fix

Of the 3 patches proposed, **2 landed on a line upstream also changed.** This is a comparison against ground truth, not a self-assessment -- and it says nothing about whether a patch is *correct*, which is why it is reported as a count and never as a percentage.

| advisory | repository | CWEs | our line | upstream lines | agree |
| --- | --- | --- | --- | --- | --- |
| `GHSA-j8r2-6x86-q33q` | `psf/requests` | CWE-200 | `requests/sessions.py:511` | 1 | no |
| `GHSA-mv8g-fhh6-6267` | `django/django` | CWE-798 | `django/db/backends/oracle/creation.py:11` | 5 | yes |
| `GHSA-4x4j-2g7c-83w6` | `python-pillow/Pillow` | CWE-78 | `src/PIL/ImageShow.py:148` | 18 | yes |

### Would a real, merged fix pass our own reviewer?

**9 of 30** real, merged, human-reviewed security fixes (30%) would be rejected by `DeterministicReviewer` given the one line a scanner reports.

With the enclosing block the loop is actually shown (`context-window, enclosing-block, truncated`, averaging 26 lines): **8 of 30** (26%).

**That is a smaller win than it looks, and the reason is the interesting part.** The scope check fires when *no* removed line of the patch appears in the snippet. A real fix usually also edits something a long way from the reported finding — an import, a declaration, a type — and no snippet anchored on one line reaches it. The ceiling here exists precisely to stop the snippet becoming the whole file, so this cannot be closed by showing more: it is not a context problem.

Which is the finding. The residual objections are mostly the reviewer being *right* — a patch that also edits an import 400 lines away does deserve a second look. It is raised here against upstream's own merged fixes, so it is a precision problem, not a correctness one. See [docs/architecture.md §13](architecture.md).

The widening is still worth having, for a reason this measurement cannot see: the AutoGen engine drafts from the same snippet, and drafting a patch from one line of a 200-line function is worse than drafting from the function. That part is not measured here and is not claimed to be.

Which check objected, and how often:

| check | objections | what it asserts |
| --- | --- | --- |
| `scoped` | 8 | the change is confined to the reported lines |
| `size` | 3 | a single-finding patch stays under 20 added lines |

What is still missing is the other half of the measurement, and it is the half that matters: **this corpus is all good patches.** A reviewer that rejects even 10% of correct work is bad news, but the number that would settle whether this gate earns its place is how often it rejects a patch that is *wrong* — which needs a corpus of bad patches labelled by a human, and does not exist. [docs/architecture.md §13](architecture.md) argues the two readings of what the gate is for.

| rejected | advisory | file | upstream size | what we said |
| --- | --- | --- | --- | --- |
| yes | `GHSA-mv8g-fhh6-6267` | `django/db/backends/oracle/creation.py` | +12/-4 | The patch removes lines that are not present in the reported snippet, so it is not scoped to this finding. Narrow the diff. |
| yes | `GHSA-4x4j-2g7c-83w6` | `src/PIL/ImageShow.py` | +18/-17 | The patch removes lines that are not present in the reported snippet, so it is not scoped to this finding. Narrow the diff.; The patch adds 57 lines f |
| yes | `GHSA-cf7p-gm2m-833m` | `src/cryptography/hazmat/primitives/serialization/ssh.py` | +16/-2 | The patch removes lines that are not present in the reported snippet, so it is not scoped to this finding. Narrow the diff. |
| yes | `GHSA-9wx4-h78v-vm56` | `src/requests/adapters.py` | +57/-1 | The patch removes lines that are not present in the reported snippet, so it is not scoped to this finding. Narrow the diff.; The patch adds 57 lines f |
| yes | `GHSA-q4xr-rc97-m4xx` | `celery/backends/base.py` | +67/-27 | The patch adds 67 lines for a single finding. Security fixes should be reviewable in one sitting. |
| yes | `GHSA-mh33-7rrq-662w` | `src/urllib3/poolmanager.py` | +5/-2 | The patch removes lines that are not present in the reported snippet, so it is not scoped to this finding. Narrow the diff. |
| yes | `GHSA-gwvm-45gx-3cf8` | `src/urllib3/poolmanager.py` | +5/-2 | The patch removes lines that are not present in the reported snippet, so it is not scoped to this finding. Narrow the diff. |
| yes | `GHSA-www2-v7xj-xrc6` | `urllib3/poolmanager.py` | +10/-1 | The patch removes lines that are not present in the reported snippet, so it is not scoped to this finding. Narrow the diff. |
| yes | `GHSA-www2-v7xj-xrc6` | `urllib3/util/retry.py` | +11/-1 | The patch removes lines that are not present in the reported snippet, so it is not scoped to this finding. Narrow the diff. |

## Known blind spots

Unconditional: a set of known blind spots that does not change when a run happens to go well.

- **CWE-295 (TLS verification) has no execution coverage here -- the rewrite is Go-only and there is no Go toolchain -- and no pinned Semgrep rule was found that fires on `InsecureSkipVerify: true`.** Tier 1 and Tier 2 independently record it as unverified.
- **CWE-200 (credential forwarded across a redirect) is verifiable only by execution.** No static analyser flags `allow_redirects=True`; it is a library behaviour, not a pattern. Tier 1 covers it with two real HTTP servers.
- **CWE-338 (weak randomness) has no rewrite.** The rule that used to claim it emitted a Python name into a Go file, and `math/rand.Int` and `crypto/rand.Int` have incompatible signatures, so it was removed rather than patched. These findings escalate to a human.
- **CWE-489 (debug mode), CWE-1336 (server-side template injection), CWE-190 (integer overflow), CWE-352 and CWE-319 in `data/fixtures/` all have no rewrite.** Escalating is the correct behaviour and is what the engine does.
- **No tier can see a vulnerability whose vulnerable line is not a single line the rule table matches.** Tier 3 measures how often that is, and the answer is most of the time.
