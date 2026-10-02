"""AutoGen-backed developer/reviewer pair.

The real multi-agent implementation, using `autogen-agentchat` and
`autogen-core`. It implements the same `RemediationEngine` protocol as the
deterministic pair in `deterministic.py`, so `backend/services/remediation.py`
cannot tell which one ran -- which is what makes the two comparable in
`docs/adr/002-autogen-vs-langgraph-crewai.md`.

Why AutoGen and not LangGraph or CrewAI for this loop:

    LangGraph   models the loop as a state graph. Excellent when the control
                flow has real branches and cycles; here the flow is a fixed
                develop/review/revise counter, and a graph would be ceremony.
    CrewAI      models it as a *team* of role-playing agents that talk to each
                other. The reviewer here is not a colleague having a discussion
                -- it is an independent reviewer who must not be anchored by
                the developer's reasoning. AutoGen's explicit message passing
                and separate model clients per agent make that separation the
                default rather than something to be engineered around.
    AutoGen     gives each agent its own `ChatCompletionClient`, so the
                developer and the reviewer can run on different models, and
                `usage` is available per call for real cost attribution.

Structure, and why it is not a two-agent team: each role runs as its *own*
single-agent `RoundRobinGroupChat([agent], MaxMessageTermination(max_messages=2))`.
Putting the developer and the reviewer in one group would let the reviewer's
verdict be anchored on the developer's reasoning, which is the failure mode a
reviewer exists to catch. Keeping them in separate runs costs one extra
context assembly and buys genuine independence; the surrounding critique/revise
loop lives in `run_remediation_loop`, which is what makes the two comparable.

`run_remediation.py` needs `SENTINEL_LLM_API_KEY` *and*
`SENTINEL_AUTOGEN_ENABLED=true`; without them the deterministic engine is used
instead and the run still works end to end.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from backend.agents.deterministic import AgentTurn
from backend.config.settings import Settings, get_settings
from backend.core.logging import get_logger
from backend.database.enums import AgentDecision

logger = get_logger(__name__)

DEVELOPER_SYSTEM_MESSAGE = """\
You are a security remediation developer working on an authorised, \
human-supervised vulnerability fix in a client codebase.

You will be given:
  - the exact source snippet a static analyser flagged
  - the rule id and CWE identifiers for the finding
  - any reviewer comments from previous rounds

Respond with a unified diff and nothing else. Requirements:
  1. The diff's file paths must be exactly the paths you were given.
  2. Change only the lines necessary to remove the vulnerability. A one-line \
vulnerability must not become a file rewrite.
  3. The patched source must still be valid Python/Go. It is checked before \
the reviewer sees it.
  4. Prefer the standard-library fix over a new dependency.
  5. If a credential is exposed, move it to configuration AND say in the \
commit body that it must be rotated.

If you cannot produce a correct patch, respond with the single word \
UNRESOLVABLE and nothing else. An honest failure is more useful than a \
plausible wrong patch.
"""

REVIEWER_SYSTEM_MESSAGE = """\
You are an independent security reviewer. You did not write this patch and \
you must review it on its own merits.

You will be given the flagged snippet, the rule id, and a candidate diff. \
Check, in order:
  1. Does the patch actually remove the vulnerability, or only rearrange it?
  2. Does the patched code still compile/parse?
  3. Is the change minimal and scoped to the reported lines?
  4. Does the fix introduce a new problem (a disabled security control, a \
bypassed validation, a silently swallowed error)?
  5. Would you approve this as a reviewer who has to justify it afterwards?

Respond with APPROVE if every check passes. Otherwise respond with \
REQUEST_CHANGES followed by numbered, specific, checkable comments. \
Do not accept a patch because it looks plausible.
"""

# Emitted by the developer when it cannot produce a patch. Treated as an
# escalation, not a parse failure.
_UNRESOLVABLE = "UNRESOLVABLE"

_DIFF_BLOCK = re.compile(r"```(?:diff)?\n(?P<body>[\s\S]*?)```", re.IGNORECASE)
_FENCE_BLOCK = re.compile(r"```(?:\w+)?\n(?P<body>[\s\S]*?)```")

# Reviewer verdicts, longest-first so "REQUEST_CHANGES" is not shadowed by a
# substring check for "CHANGES".
_APPROVE = re.compile(r"\bAPPROVE\b", re.IGNORECASE)
_REQUEST_CHANGES = re.compile(r"\bREQUEST[_ ]CHANGES\b", re.IGNORECASE)
_REJECT = re.compile(r"\bREJECT\b", re.IGNORECASE)


class AutogenRemediationEngine:
    """`RemediationEngine` backed by two AutoGen assistant agents."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        if not self._settings.llm_api_key:
            raise ValueError(
                "AutogenRemediationEngine requires SENTINEL_LLM_API_KEY. "
                "Without it, use DeterministicRemediationEngine instead -- "
                "see docs/adr/002-autogen-vs-langgraph-crewai.md."
            )
        self._client = self._build_client()

    @property
    def model_name(self) -> str | None:
        return self._settings.llm_model

    def _build_client(self) -> Any:
        """One OpenAI-backed `ChatCompletionClient` shared by both agents.

        Imported from `autogen_ext`, not `autogen_core`: `autogen-core` defines
        the abstract `ChatCompletionClient` protocol, and `autogen-ext` is the
        distribution that provides the concrete OpenAI implementation. Splitting
        them is the reason the dependency is three packages rather than the
        legacy `autogen` meta-package -- see the ADR.

        Shared on purpose: two clients means two connections and two sets of
        credentials for no benefit. The *models* can still differ per agent if a
        deployment wants a stronger reviewer, by constructing a second client.
        """
        from autogen_ext.models.openai import OpenAIChatCompletionClient

        kwargs: dict[str, Any] = {
            "model": self._settings.llm_model,
            "api_key": self._settings.llm_api_key,
        }
        if self._settings.llm_base_url:
            # A base_url override is how a self-hosted or Azure-hosted model is
            # pointed at; useful, and the reason `llm_base_url` exists.
            kwargs["base_url"] = self._settings.llm_base_url
        return OpenAIChatCompletionClient(**kwargs)

    # --- Protocol implementation ----------------------------------------

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
        """Ask the developer agent for a diff, synchronously.

        Synchronous because the `RemediationEngine` protocol is synchronous:
        the loop in `backend/services/remediation.py` must be identical for
        both engines, or the comparison between them is not a comparison. The
        async call is driven to completion with `asyncio.run`, which is safe
        here because the loop is called from a worker thread (via `run_sync`),
        never from inside a running loop.
        """
        prompt = _developer_prompt(
            snippet=snippet,
            file_path=file_path,
            rule_id=rule_id,
            cwe_ids=cwe_ids,
            feedback=feedback,
            round_index=round_index,
        )
        return self._run_single_agent(
            role="developer",
            name="developer",
            system_message=DEVELOPER_SYSTEM_MESSAGE,
            prompt=prompt,
            postprocess=lambda text: self._to_developer_turn(text, file_path, round_index),
        )

    def review(
        self,
        *,
        patch: str,
        snippet: str,
        file_path: str,
        rule_id: str,
        round_index: int,
    ) -> AgentTurn:
        """Ask the reviewer agent for a verdict.

        Deliberately not a `RoundRobinGroupChat` with the developer: the
        reviewer must see the patch, not a conversation about the patch.
        Anchoring on the developer's own reasoning is the specific failure mode
        an independent reviewer exists to avoid, so the two agents are invoked
        separately and the reviewer is given only the artefacts.
        """
        prompt = _reviewer_prompt(
            patch=patch,
            snippet=snippet,
            file_path=file_path,
            rule_id=rule_id,
            round_index=round_index,
        )
        return self._run_single_agent(
            role="reviewer",
            name="reviewer",
            system_message=REVIEWER_SYSTEM_MESSAGE,
            prompt=prompt,
            postprocess=lambda text: self._to_reviewer_turn(text, round_index),
        )

    # --- Agent plumbing --------------------------------------------------

    def _run_single_agent(
        self,
        *,
        role: str,
        name: str,
        system_message: str,
        prompt: str,
        postprocess: Any,
    ) -> AgentTurn:
        """Run one agent to completion and shape its output into an `AgentTurn`.

        Each agent runs as its own single-agent chat rather than through a
        two-agent team, because the two roles must not see each other's
        reasoning. A reviewer that has read the developer's justification
        anchors on it, and the whole value of the review step is that it does
        not. The multi-agent *win* here is role separation and independent
        model clients, not conversation between them; the critique/revise cycle
        that does need both roles is `run_remediation_loop` in
        `autogen_loop.py`, which drives them one turn at a time.
        """
        from autogen_agentchat.agents import AssistantAgent
        from autogen_agentchat.conditions import MaxMessageTermination
        from autogen_agentchat.teams import RoundRobinGroupChat

        agent = AssistantAgent(
            name=name,
            model_client=self._client,
            system_message=system_message,
            # A single message in, a single message out. Higher values let the
            # agent call tools in a loop, which neither role has tools for.
            max_tool_iterations=0,
            reflect_on_tool_use=False,
        )
        team = RoundRobinGroupChat(
            [agent],
            termination_condition=MaxMessageTermination(max_messages=2),
        )

        started = time.perf_counter()
        text, usage = _run_coroutine(team.run(task=prompt))
        latency_ms = (time.perf_counter() - started) * 1000.0

        tokens_used, cost_usd = _usage_from(usage, self._settings.llm_model)
        turn = postprocess(text)
        turn.tokens_used = tokens_used
        turn.cost_usd = cost_usd
        turn.latency_ms = latency_ms
        turn.llm_model = self._settings.llm_model
        logger.info(
            "autogen %s turn complete model=%s tokens=%d latency_ms=%.1f",
            role,
            self._settings.llm_model,
            tokens_used,
            latency_ms,
        )
        return turn

    # --- Output shaping --------------------------------------------------

    @staticmethod
    def _to_developer_turn(text: str, file_path: str, round_index: int) -> AgentTurn:
        """Turn the developer's reply into an `AgentTurn`.

        An `UNRESOLVABLE` reply becomes an `ESCALATE` decision. That mapping is
        the whole reason to parse the reply: an agent that says "I cannot fix
        this" must be able to stop the loop and hand the problem to a human,
        not be handed to a reviewer as an empty patch.
        """
        stripped = text.strip()
        if _UNRESOLVABLE in stripped.upper() and len(stripped) <= len(_UNRESOLVABLE) + 40:
            return AgentTurn(
                role="developer",
                decision=AgentDecision.ESCALATE,
                summary="Developer agent could not produce a patch",
                rationale=(
                    "The developer agent reported the finding as unresolvable. "
                    "Escalating to a human rather than sending an empty patch to "
                    "the reviewer."
                ),
                message=stripped,
            )

        patch = _extract_diff(stripped)
        if patch is None:
            return AgentTurn(
                role="developer",
                decision=AgentDecision.ESCALATE,
                summary="Developer reply contained no unified diff",
                rationale=(
                    "The developer agent's reply had no fenced diff block. Sending an "
                    "unparseable reply to the reviewer would waste a round and could "
                    "be mistaken for an empty patch."
                ),
                message=stripped[:2000],
            )

        return AgentTurn(
            role="developer",
            decision=AgentDecision.PROPOSE,
            patch=patch,
            summary=f"Draft patch for {file_path} (round {round_index})",
            rationale=_rationale_from(stripped, patch),
            message=stripped,
        )

    @staticmethod
    def _to_reviewer_turn(text: str, round_index: int) -> AgentTurn:
        """Turn the reviewer's reply into an `AgentTurn`.

        Precedence is REJECT > REQUEST_CHANGES > APPROVE, and it is checked in
        that order because a reviewer that writes "I would REQUEST_CHANGES
        before I can APPROVE this" means request-changes. Defaulting to
        approve-when-unclear would be the dangerous direction to be wrong in.
        """
        stripped = text.strip()
        if _REJECT.search(stripped):
            decision = AgentDecision.REJECT
            summary = "Patch rejected by automated review"
        elif _REQUEST_CHANGES.search(stripped):
            decision = AgentDecision.REQUEST_CHANGES
            summary = "Changes requested by automated review"
        elif _APPROVE.search(stripped):
            decision = AgentDecision.APPROVE
            summary = "Patch approved by automated review"
        else:
            decision = AgentDecision.REQUEST_CHANGES
            summary = "Reviewer verdict unrecognised; treated as changes requested"

        return AgentTurn(
            role="reviewer",
            decision=decision,
            summary=summary,
            rationale=(
                stripped
                if decision is not AgentDecision.APPROVE
                else (
                    "Automated review passed. This is necessary but NOT sufficient: "
                    "a human approver must still authorize the pull request."
                )
            ),
            message=stripped,
            metadata={"round": round_index},
        )


# --- Prompt construction -------------------------------------------------


def _developer_prompt(
    *,
    snippet: str,
    file_path: str,
    rule_id: str,
    cwe_ids: list[str],
    feedback: list[str],
    round_index: int,
) -> str:
    parts = [
        f"Round {round_index}.",
        f"File path: {file_path}",
        f"Rule id: {rule_id}",
        f"CWE: {', '.join(cwe_ids) if cwe_ids else 'not supplied'}",
        "",
        "Flagged source (this is the exact code the analyser reported):",
        "```",
        snippet,
        "```",
    ]
    if feedback:
        parts += [
            "",
            "The reviewer asked for these changes in an earlier round:",
            *(f"  {i}. {c}" for i, c in enumerate(feedback, start=1)),
            "",
            "Address every point, or reply with UNRESOLVABLE if you cannot.",
        ]
    parts += ["", "Respond with the unified diff only."]
    return "\n".join(parts)


def _reviewer_prompt(
    *, patch: str, snippet: str, file_path: str, rule_id: str, round_index: int
) -> str:
    return "\n".join(
        [
            f"Review round {round_index} for {file_path} (rule {rule_id}).",
            "",
            "Flagged source:",
            "```",
            snippet,
            "```",
            "",
            "Candidate diff:",
            "```diff",
            patch,
            "```",
            "",
            "Reply with APPROVE, or REQUEST_CHANGES followed by numbered comments.",
        ]
    )


# --- Response parsing ---------------------------------------------------


def _extract_diff(text: str) -> str | None:
    """Pull the first fenced diff block out of a reply.

    Tolerant of the model wrapping the diff in a bare ``` fence, which
    happens often enough that a strict ```diff-only match would discard usable
    output. The first *diff-looking* block wins, so prose fences containing a
    code sample are not mistaken for the patch.
    """
    for pattern in (_DIFF_BLOCK, _FENCE_BLOCK):
        for match in pattern.finditer(text):
            body = match.group("body").strip()
            if "---" in body and "+++" in body:
                return body
    return None


def _rationale_from(text: str, patch: str) -> str:
    """The developer's prose around the diff, as its stated rationale.

    Used to populate the pull request body, so the human approver reads the
    agent's reasoning instead of being asked to reverse-engineer it from the
    diff alone.
    """
    without_diff = _DIFF_BLOCK.sub("", text).strip()
    return without_diff[:2000] if without_diff else "No rationale supplied."


def _usage_from(usage: Any, model: str) -> tuple[int, float]:
    """Extract `(tokens, cost_usd)` from AutoGen's usage record.

    AutoGen accumulates `TokenUsage` on `task_result.usage`. Anything missing
    or unrecognised reports zero rather than raising: cost accounting must not
    be able to fail a remediation.
    """
    tokens = 0
    raw = getattr(usage, "total_tokens", None)
    if isinstance(raw, int):
        tokens = raw
    elif isinstance(getattr(usage, "input_tokens", None), int):
        tokens = int(usage.input_tokens) + int(getattr(usage, "output_tokens", 0) or 0)

    return tokens, _estimate_cost(tokens, model)


# Indicative USD per 1M tokens, input/output blended. Documented as an
# estimate in docs/architecture.md §3.4: a real deployment would read live
# pricing from the provider's response rather than hardcoding it here, and the
# number exists so the fleet cost dashboard has a consistent unit across
# projects, not so anyone can invoice from it.
_PRICE_PER_MILLION_TOKENS = 0.30


def _estimate_cost(tokens: int, model: str) -> float:
    if tokens <= 0:
        return 0.0
    return round(tokens / 1_000_000 * _PRICE_PER_MILLION_TOKENS, 6)


def _run_coroutine(coro: Any) -> Any:
    """Drive an async agent run to completion from sync code.

    `asyncio.run` is correct here and not merely convenient: the caller is
    always a worker thread (the service layer reaches the engine through
    `run_sync`), so there is never an enclosing loop to conflict with. The
    `get_running_loop` guard turns that assumption into an error rather than a
    confusing `RuntimeError` from deep inside asyncio if it is ever violated.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise RuntimeError(
        "AutogenRemediationEngine was called from a thread with a running event "
        "loop; reach it through backend.core.asyncio_utils.run_sync()"
    )
