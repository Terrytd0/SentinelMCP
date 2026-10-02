# 002 — AutoGen for the developer/reviewer loop, not LangGraph or CrewAI

**Status:** accepted

The roadmap deliberately lists LangGraph, CrewAI, and AutoGen as near-duplicate
tools and says the portfolios should articulate the trade-off from lived
experience. This is that articulation, for one specific loop: a
developer/reviewer pair that produces a patch, critiques it, revises, and stops.

## Context

The loop is a develop/review/revise counter with a hard budget:

```
for round in range(max_rounds):        # default 3
    patch = developer.propose(snippet, feedback)   # may ESCALATE
    verdict = reviewer.critique(patch)             # APPROVE / REQUEST_CHANGES / REJECT
    if verdict.approved:  return patch
    feedback = verdict.comments
return escalate_to_human()
```

Bounded at three rounds and eight LLM calls. No branching, no fan-out, no
dynamic team membership, no shared scratchpad, no tool-calling loop, no
persistence across sessions. The interesting engineering here is not the control
flow — it is the *independence* of the reviewer and the accounting of cost.

## Decision

**Use `autogen-agentchat` + `autogen-core` + `autogen-ext`, installed as three
separate distributions rather than the legacy `autogen` meta-package.**

Three reasons, in order of weight:

**1. The reviewer must not be anchored by the developer.** This is the
requirement that decides it. A reviewer that has read the developer's
justification agrees with it; the entire value of the review step is that it
does not. So the two roles run as **separate single-agent chats** —

```python
team = RoundRobinGroupChat([agent], termination_condition=MaxMessageTermination(max_messages=2))
```

— one per role per round, driven from `run_remediation_loop` in `autogen_loop.py`
rather than by a team. AutoGen makes this the default shape: the developer and
the reviewer each own their own `ChatCompletionClient` and their own context, and
there is no shared message list for anchoring to happen through. It also means
the two roles can run on *different models*, which is a real operational option
— a cheap model drafting and an expensive model reviewing is a sensible default
if the cheap model is the one with the high false-positive rate.

CrewAI's unit of abstraction is a role-playing agent in a team that talks to each
other. That is the wrong primitive here: the reviewer and developer are
deliberately *not* having a discussion, and making them talk is how anchoring
gets introduced.

**2. Per-call usage for real cost attribution.** `autogen-core` exposes
`usage.total_tokens` per call. Every `agent_runs` row records tokens, cost, and
latency, and the smoke test asserts the accounting is consistent with whichever
engine ran. Sprint 11's Aegis needs per-tenant cost accounting, and a
framework that gives you the numbers per call is doing you a favour that is
tedious to add later.

**3. Not a state graph.** The flow is a fixed counter. LangGraph's
state-machine ergonomics — conditional edges, checkpointing, cycles, graph
visualisation — are real advantages when the control flow has genuine branches
and you need to resume a half-finished run. Here there is nothing to branch on
and nothing to resume: a run that gets interrupted is a `LoopResult` that never
arrived, and re-running it from the finding is the correct recovery because a
patch is cheap and the attempt budget already bounds the damage. A graph would
be ceremony around a counter.

The three-package split is deliberate: the `autogen` meta-package also pulls in
`autogen_ext`'s code-executors and Docker runtimes, which is an execution
sandbox this project has no use for and would rather not have installed. An
agent that writes a patch is not an agent that should be able to execute code.

## Consequences

**Good.** Both engines implement one `RemediationEngine` protocol, so
`RemediationService` cannot tell which ran and the audit trail is identical. The
deterministic engine is the default (`SENTINEL_AUTOGEN_ENABLED=false`), so the
entire remediation path is runnable and testable with no API key and no network —
and it is the test oracle for the loop's control flow. The framework choice is
therefore *not load-bearing for the tests*, which is what makes the framework
swappable at all.

**Inconvenient.** Two `AssistantAgent` constructions and two team runs per round
means two context assemblies per round, which is slower and more expensive than
a single team run would be. Accepted: the context is small (a snippet, a diff,
a rubric) and independence is worth more than the tokens.

**Also inconvenient, and it is the sharpest edge here.** The engine is
**non-deterministic**: the same finding can produce different patches across
runs. That is fine for AutoGen and fatal for a test oracle, which is exactly
why the deterministic engine exists and why it is the default. It also means the
AutoGen path is exercised by structural tests (does it parse a diff, does it
attribute cost, does it escalate rather than guess) and not by golden-patch
assertions, which would be flaky by construction.

**Sharpest edge of all, and worth stating plainly:** a review performed by the
same model that produced the patch is a *weaker* control than a review performed
by a different model or a person. This project's reviewer is not the safety
guarantee — [ADR 001](001-safety-rails-and-human-approval.md) is. The reviewer
is a cheap first filter that reduces how much human attention the queue needs.
Treating an agent review as the control would be a misreading of the design.

## Alternatives considered

**LangGraph.** Rejected on the grounds above: a state graph for a counter. Worth
revisiting if the loop ever gains real branching — conditional routing on
finding type, a third "security reviewer" role that only sees critical findings,
or checkpoint-and-resume across a long-running remediation. All three are
plausible extensions, and all three would justify the move on merit. `langgraph`
also has a genuine claim in Sprint 4's SupportOps triage flow, where the control
flow *is* branchy and human-in-the-loop pause/resume is the whole point.

**CrewAI.** Rejected: its team abstraction is designed for agents that
collaborate, and this reviewer must not collaborate with the developer. Also a
heavier dependency with a smaller ecosystem for the per-call token accounting.

**Hand-rolled: two `OpenAI` SDK calls and a `while` loop.** Seriously considered,
and the version that exists as `DeterministicRemediationEngine` is arguably
already this. Rejected as the *default* because the two-Agent abstraction
buys model-client separation and usage accounting that would otherwise be
re-implemented, and because "we wrote our own agent loop" is a weaker answer to
"what did you use, and why?" than "AutoGen, and here is why not the other two".

**A single agent asked to both write and review its own patch.** Cheapest, and
worth naming because it is the thing most people build first. It has no
independence at all: the model that just produced the diff is being asked to
judge it, and models are well known to be agreeable about their own output.
