"""The bounded developer/reviewer loop.

Controls the *process*, not the content: who speaks, in what order, when to
stop, and what happens when the loop cannot converge. The content lives in an
engine (`deterministic.py` or `autogen_engine.py`), which is what lets the same
loop, the same audit trail, and the same persistence run against either.

Three ways this loop can end, and all three are normal outcomes rather than
exceptions:

    approved    the reviewer accepted the patch. A human still has to approve
                the pull request -- see `backend/services/approvals.py`.
    rejected    the reviewer rejected it outright. No PR is opened.
    escalated   the round budget ran out, or an agent gave up, or the call
                budget ran out. The finding goes to a human with the full
                dialogue attached.

`escalated` is the one that matters most and the one multi-agent demos usually
omit. Two agents that cannot agree in three rounds will not agree in thirty,
and a loop that keeps spending tokens on that argument is a denial-of-wallet
on yourself. The budget is enforced here, in the control flow, where it cannot
be talked out of by a model.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from backend.agents.deterministic import (
    AgentTurn,
    DeterministicDeveloper,
    DeterministicReviewer,
    RemediationEngine,
)
from backend.config.settings import Settings, get_settings
from backend.core.logging import get_logger
from backend.database.enums import AgentDecision

logger = get_logger(__name__)


class LoopBudgetExhausted(RuntimeError):
    """The loop hit its LLM call budget before it hit a verdict.

    Distinct from a plain escalation because it is an operational signal: a
    budget exhaustion on cheap findings means the prompt or the round cap needs
    tuning, whereas a reviewer rejection means the finding is genuinely hard.
    """


@dataclass(slots=True)
class RoundRecord:
    """What happened in one develop/review exchange."""

    round_index: int
    developer: AgentTurn
    reviewer: AgentTurn | None = None
    stopped_because: str = ""

    def feedback_lines(self) -> list[str]:
        """The reviewer's complaints, for the next round's prompt."""
        if self.reviewer is None or not self.reviewer.message:
            return []
        return [
            line.strip().lstrip("-*").strip()
            for line in self.reviewer.message.splitlines()
            if line.strip().startswith(("-", "*"))
        ]


@dataclass(slots=True)
class LoopResult:
    """The outcome of a complete loop, ready to be persisted and audited."""

    approved: bool
    patch: str | None
    summary: str
    rationale: str
    outcome: str
    """`approved` | `rejected` | `escalated`."""

    rounds: list[RoundRecord] = field(default_factory=list)
    rounds_completed: int = 0
    llm_calls: int = 0
    tokens_used: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    llm_model: str | None = None
    escalated_reason: str | None = None
    correlation_id: str | None = None

    @property
    def is_approved(self) -> bool:
        return self.approved

    def all_feedback(self) -> list[str]:
        """Every reviewer comment across every round, in order.

        Passed to the pull request body and stored on the proposal, so the
        human approver can see the full negotiation rather than only the last
        round's verdict.
        """
        return [line for record in self.rounds for line in record.feedback_lines()]

    def transcript(self) -> list[dict[str, Any]]:
        """The whole dialogue as structured data, for `agent_runs` rows."""
        transcript: list[dict[str, Any]] = []
        for record in self.rounds:
            transcript.append(
                {
                    "round": record.round_index,
                    "developer_decision": record.developer.decision.value,
                    "developer_summary": record.developer.summary,
                    "developer_rationale": record.developer.rationale,
                    "developer_tokens": record.developer.tokens_used,
                    "developer_cost_usd": record.developer.cost_usd,
                    "reviewer_decision": (
                        record.reviewer.decision.value if record.reviewer else None
                    ),
                    "reviewer_message": record.reviewer.message if record.reviewer else None,
                    "stopped_because": record.stopped_because,
                }
            )
        return transcript


def run_remediation_loop(
    engine: RemediationEngine,
    *,
    snippet: str,
    file_path: str,
    rule_id: str,
    cwe_ids: list[str],
    correlation_id: str | None = None,
    settings: Settings | None = None,
) -> LoopResult:
    """Run develop/review/revise until a verdict, a refusal, or a budget stop.

    Synchronous, matching the `RemediationEngine` protocol and the sync nature
    of both engines. The service layer runs it through `run_sync` so it does
    not block the event loop.
    """
    resolved = settings or get_settings()
    max_rounds = max(1, resolved.remediation_max_rounds)
    max_calls = max(2, resolved.remediation_max_llm_calls)

    logger.info(
        "remediation loop starting engine=%s max_rounds=%d max_llm_calls=%d correlation_id=%s",
        engine.model_name or "deterministic",
        max_rounds,
        max_calls,
        correlation_id,
    )

    started = time.perf_counter()
    rounds: list[RoundRecord] = []
    feedback: list[str] = []
    llm_calls = 0
    tokens = 0
    cost = 0.0
    escalated_reason: str | None = None

    for round_index in range(1, max_rounds + 1):
        if llm_calls >= max_calls:
            escalated_reason = (
                f"LLM call budget of {max_calls} reached after round {round_index - 1}. "
                "The loop was stopped to bound cost."
            )
            raise LoopBudgetExhausted(escalated_reason)

        developer = engine.develop(
            snippet=snippet,
            file_path=file_path,
            rule_id=rule_id,
            cwe_ids=cwe_ids,
            feedback=feedback,
            round_index=round_index,
        )
        llm_calls += 1
        tokens += developer.tokens_used
        cost += developer.cost_usd
        record = RoundRecord(round_index=round_index, developer=developer)

        # The developer escalating ends the loop immediately. Sending an
        # "I cannot fix this" to a reviewer would only burn another round.
        if developer.decision is AgentDecision.ESCALATE:
            record.stopped_because = "developer_escalated"
            rounds.append(record)
            escalated_reason = developer.rationale or developer.summary
            logger.info(
                "remediation loop escalated by developer round=%d reason=%s",
                round_index,
                developer.summary,
            )
            break

        reviewer = engine.review(
            patch=developer.patch or "",
            snippet=snippet,
            file_path=file_path,
            rule_id=rule_id,
            round_index=round_index,
        )
        llm_calls += 1
        tokens += reviewer.tokens_used
        cost += reviewer.cost_usd
        record.reviewer = reviewer
        rounds.append(record)

        match reviewer.decision:
            case AgentDecision.APPROVE:
                record.stopped_because = "reviewer_approved"
                logger.info(
                    "remediation loop approved round=%d calls=%d tokens=%d",
                    round_index,
                    llm_calls,
                    tokens,
                )
                return LoopResult(
                    approved=True,
                    patch=developer.patch,
                    summary=developer.summary,
                    rationale=developer.rationale,
                    outcome="approved",
                    rounds=rounds,
                    rounds_completed=round_index,
                    llm_calls=llm_calls,
                    tokens_used=tokens,
                    cost_usd=round(cost, 6),
                    latency_ms=(time.perf_counter() - started) * 1000.0,
                    llm_model=engine.model_name,
                    correlation_id=correlation_id,
                )

            case AgentDecision.REJECT:
                record.stopped_because = "reviewer_rejected"
                logger.info(
                    "remediation loop rejected round=%d reason=%s", round_index, reviewer.summary
                )
                return LoopResult(
                    approved=False,
                    patch=None,
                    summary=reviewer.summary,
                    rationale=developer.rationale,
                    outcome="rejected",
                    rounds=rounds,
                    rounds_completed=round_index,
                    llm_calls=llm_calls,
                    tokens_used=tokens,
                    cost_usd=round(cost, 6),
                    latency_ms=(time.perf_counter() - started) * 1000.0,
                    llm_model=engine.model_name,
                    escalated_reason=reviewer.rationale,
                    correlation_id=correlation_id,
                )

            case _:
                # REQUEST_CHANGES: carry the comments into the next round.
                feedback = record.feedback_lines()
                record.stopped_because = "revision_requested"
                logger.info(
                    "remediation loop round=%d needs revision comments=%d",
                    round_index,
                    len(feedback),
                )

    # The round budget ran out. This is the expected failure mode for a finding
    # the agents cannot fix, and the reason string says so explicitly, because
    # "escalated with no reason" is not actionable for whoever picks it up.
    if escalated_reason is None:
        escalated_reason = (
            f"Reached the {max_rounds}-round limit without the reviewer and "
            "developer agreeing. Escalating to a human."
        )
    logger.info(
        "remediation loop escalated rounds=%d calls=%d reason=%s",
        len(rounds),
        llm_calls,
        escalated_reason,
    )
    last = rounds[-1] if rounds else None
    return LoopResult(
        approved=False,
        patch=None,
        summary="Remediation escalated for human review",
        rationale=last.developer.rationale if last else "no rounds completed",
        outcome="escalated",
        rounds=rounds,
        rounds_completed=len(rounds),
        llm_calls=llm_calls,
        tokens_used=tokens,
        cost_usd=round(cost, 6),
        latency_ms=(time.perf_counter() - started) * 1000.0,
        llm_model=engine.model_name,
        escalated_reason=escalated_reason,
        correlation_id=correlation_id,
    )


def build_engine(settings: Settings | None = None) -> RemediationEngine:
    """Pick an engine from configuration.

    The AutoGen path is opt-in via `SENTINEL_AUTOGEN_ENABLED` and additionally
    requires an API key. Defaulting to deterministic is what keeps `pytest`,
    `run_remediation.py`, and a fresh clone all working with no credentials.
    """
    resolved = settings or get_settings()
    if resolved.autogen_enabled:
        from backend.agents.autogen_engine import AutogenRemediationEngine

        try:
            autogen_engine = AutogenRemediationEngine(resolved)
            logger.info("remediation engine: autogen model=%s", autogen_engine.model_name)
            return autogen_engine
        except ValueError as exc:
            # Misconfiguration, not a runtime failure: say so loudly and fall
            # back rather than refusing to remediate anything at all.
            logger.error("autogen engine unavailable (%s); falling back to deterministic", exc)

    deterministic = DeterministicRemediationEngine()
    logger.info("remediation engine: deterministic (no LLM calls)")
    return deterministic


class DeterministicRemediationEngine:
    """`RemediationEngine` over the deterministic developer/reviewer pair.

    Bundled into one object so it satisfies the two-method protocol, while the
    two halves stay separately importable and separately testable.
    """

    def __init__(self) -> None:
        self._developer = DeterministicDeveloper()
        self._reviewer = DeterministicReviewer()

    @property
    def model_name(self) -> str | None:
        return None

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
        return self._developer.develop(
            snippet=snippet,
            file_path=file_path,
            rule_id=rule_id,
            cwe_ids=cwe_ids,
            feedback=feedback,
            round_index=round_index,
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
        return self._reviewer.review(
            patch=patch,
            snippet=snippet,
            file_path=file_path,
            rule_id=rule_id,
            round_index=round_index,
        )
