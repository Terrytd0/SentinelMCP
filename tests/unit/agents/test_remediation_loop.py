"""The remediation loop's control flow.

The loop is the part that decides when to stop, and "when to stop" is the
safety-relevant behaviour. Three outcomes must be possible -- approved,
rejected, escalated -- and the third is the one multi-agent demos usually
omit, so it is tested most thoroughly here.
"""

from __future__ import annotations

from typing import Any

import pytest

from backend.agents.autogen_loop import (
    LoopBudgetExhausted,
    build_engine,
    run_remediation_loop,
)
from backend.agents.deterministic import AgentTurn
from backend.config.settings import Settings, get_settings
from backend.database.enums import AgentDecision

SNIPPET = '    return render(eval(request.args["expr"]))'


def _settings(**overrides: Any) -> Settings:
    return Settings(**overrides)


class ScriptedEngine:
    """A test double that replays a fixed sequence of decisions.

    Needed to reach states the deterministic engine cannot produce on demand --
    a reviewer that always rejects, a developer that always escalates, a run
    that never converges. The real engine's behaviour is asserted separately in
    `test_deterministic_agents.py`; this double exists to drive the *loop*.
    """

    def __init__(
        self,
        *,
        developer_decisions: list[AgentDecision] | None = None,
        reviewer_decisions: list[AgentDecision] | None = None,
        model: str | None = "scripted-model",
    ) -> None:
        self._developer_decisions = developer_decisions or [AgentDecision.PROPOSE]
        self._reviewer_decisions = reviewer_decisions or [AgentDecision.APPROVE]
        self._developer_index = 0
        self._reviewer_index = 0
        self.develop_calls = 0
        self.review_calls = 0
        self.feedback_seen: list[list[str]] = []
        self._model = model

    @property
    def model_name(self) -> str | None:
        return self._model

    def develop(self, **kwargs: Any) -> AgentTurn:
        self.develop_calls += 1
        self.feedback_seen.append(list(kwargs.get("feedback", [])))
        index = min(self._developer_index, len(self._developer_decisions) - 1)
        self._developer_index += 1
        decision = self._developer_decisions[index]
        return AgentTurn(
            role="developer",
            decision=decision,
            patch=None if decision is AgentDecision.ESCALATE else "--- a/x\n+++ b/x\n-old\n+new\n",
            summary=f"scripted developer turn {self.develop_calls}",
            rationale="scripted",
            tokens_used=100,
            cost_usd=0.001,
        )

    def review(self, **kwargs: Any) -> AgentTurn:
        self.review_calls += 1
        index = min(self._reviewer_index, len(self._reviewer_decisions) - 1)
        self._reviewer_index += 1
        decision = self._reviewer_decisions[index]
        message = {
            AgentDecision.APPROVE: "approved",
            AgentDecision.REJECT: "rejected outright",
            AgentDecision.REQUEST_CHANGES: "- narrow the change\n- add a test",
        }.get(decision, "")
        return AgentTurn(
            role="reviewer",
            decision=decision,
            summary=f"scripted reviewer turn {self.review_calls}",
            rationale="scripted",
            message=message,
        )


def _run(engine: Any, **overrides: Any) -> Any:
    kwargs: dict[str, Any] = {
        "snippet": SNIPPET,
        "file_path": "app/handlers/report.py",
        "rule_id": "python.eval-detected",
        "cwe_ids": ["CWE-95"],
        "correlation_id": "test-correlation",
    }
    kwargs.update(overrides)
    return run_remediation_loop(engine, **kwargs)


# --- Outcomes -----------------------------------------------------------


def test_first_round_approval_ends_the_loop_immediately() -> None:
    """An approving run must cost one round-trip, not the configured maximum.

    A loop that keeps going after approval wastes tokens and risks the developer
    "improving" an already-approved patch into something worse.
    """
    engine = ScriptedEngine()
    result = _run(engine, settings=_settings(remediation_max_rounds=5))

    assert result.approved
    assert result.outcome == "approved"
    assert result.rounds_completed == 1
    assert engine.develop_calls == 1
    assert engine.review_calls == 1
    assert result.llm_calls == 2


def test_rejection_ends_the_loop_and_produces_no_patch() -> None:
    engine = ScriptedEngine(reviewer_decisions=[AgentDecision.REJECT])
    result = _run(engine, settings=_settings(remediation_max_rounds=5))

    assert not result.approved
    assert result.outcome == "rejected"
    assert result.patch is None, "a rejected loop must not hand a patch forward"
    assert engine.develop_calls == 1


def test_repeated_change_requests_escalate_at_the_round_limit() -> None:
    engine = ScriptedEngine(reviewer_decisions=[AgentDecision.REQUEST_CHANGES])
    result = _run(engine, settings=_settings(remediation_max_rounds=3))

    assert not result.approved
    assert result.outcome == "escalated"
    assert result.rounds_completed == 3
    assert engine.develop_calls == 3
    assert result.escalated_reason
    assert "3-round limit" in result.escalated_reason


def test_escalation_carries_the_full_transcript() -> None:
    """The most useful field on an escalated finding is *why* the agents
    disagreed. A loop that gives up silently leaves nobody anything to act on."""
    engine = ScriptedEngine(reviewer_decisions=[AgentDecision.REQUEST_CHANGES])
    result = _run(engine, settings=_settings(remediation_max_rounds=2))

    assert len(result.rounds) == 2
    assert result.all_feedback(), "reviewer comments must survive to the caller"
    assert "narrow the change" in result.all_feedback()
    assert len(result.transcript()) == 2


def test_a_developer_escalation_stops_before_the_reviewer_runs() -> None:
    """Sending "I cannot fix this" to a reviewer would burn a round for nothing."""
    engine = ScriptedEngine(developer_decisions=[AgentDecision.ESCALATE])
    result = _run(engine, settings=_settings(remediation_max_rounds=3))

    assert result.outcome == "escalated"
    assert engine.develop_calls == 1
    assert engine.review_calls == 0
    assert result.rounds[0].stopped_because == "developer_escalated"


def test_feedback_from_one_round_reaches_the_next() -> None:
    engine = ScriptedEngine(
        reviewer_decisions=[AgentDecision.REQUEST_CHANGES, AgentDecision.APPROVE]
    )
    result = _run(engine, settings=_settings(remediation_max_rounds=3))

    assert result.approved
    assert engine.feedback_seen[0] == []
    assert "narrow the change" in engine.feedback_seen[1]
    assert "add a test" in engine.feedback_seen[1]


def test_a_second_round_approval_returns_the_latest_patch() -> None:
    engine = ScriptedEngine(
        reviewer_decisions=[AgentDecision.REQUEST_CHANGES, AgentDecision.APPROVE]
    )
    result = _run(engine)
    assert result.approved
    assert result.patch and "+new" in result.patch


# --- Budgets ------------------------------------------------------------


def test_the_round_budget_is_actually_enforced() -> None:
    engine = ScriptedEngine(reviewer_decisions=[AgentDecision.REQUEST_CHANGES])
    _run(engine, settings=_settings(remediation_max_rounds=2))
    assert engine.develop_calls == 2, "the loop ran past its round budget"


def test_the_llm_call_budget_stops_the_loop() -> None:
    """Cost control has to be able to stop a run the round budget would allow.

    A budget that only counts rounds cannot bound spend when a round makes
    several calls.
    """
    engine = ScriptedEngine(reviewer_decisions=[AgentDecision.REQUEST_CHANGES])
    with pytest.raises(LoopBudgetExhausted):
        _run(engine, settings=_settings(remediation_max_rounds=10, remediation_max_llm_calls=4))
    assert engine.develop_calls <= 2


def test_cost_and_tokens_accumulate_across_rounds() -> None:
    engine = ScriptedEngine(
        reviewer_decisions=[AgentDecision.REQUEST_CHANGES, AgentDecision.APPROVE]
    )
    result = _run(engine, settings=_settings(remediation_max_rounds=3))

    # Two rounds, two calls per round. The scripted reviewer reports no token
    # usage, so the total is the two developer turns only -- which is also what
    # makes this assertion meaningful about *accumulation* rather than a sum.
    assert result.llm_calls == 4
    assert result.tokens_used == 200
    assert result.cost_usd == pytest.approx(0.002)
    assert result.latency_ms > 0
    assert result.llm_model == "scripted-model"


# --- Engine selection ---------------------------------------------------


def test_the_default_engine_is_deterministic_and_free() -> None:
    """`pytest`, the scripts, and a fresh clone must all work with no API key."""
    engine = build_engine(_settings(autogen_enabled=False))
    assert engine.model_name is None
    turn = engine.develop(
        snippet=SNIPPET,
        file_path="app/handlers/report.py",
        rule_id="python.eval-detected",
        cwe_ids=["CWE-95"],
        feedback=[],
        round_index=1,
    )
    assert turn.decision is AgentDecision.PROPOSE
    assert turn.tokens_used == 0
    assert turn.cost_usd == 0.0


def test_autogen_is_not_selected_without_an_api_key() -> None:
    """Falls back loudly rather than failing the remediation."""
    settings = _settings(autogen_enabled=True, llm_api_key="")
    engine = build_engine(settings)
    assert engine.model_name is None, "should have fallen back to deterministic"


def test_autogen_is_selected_when_enabled_and_keyed() -> None:
    """Selected, without contacting anything -- constructing the client is lazy."""
    from backend.agents.autogen_engine import AutogenRemediationEngine

    settings = _settings(autogen_enabled=True, llm_api_key="test-key", llm_model="gpt-4o-mini")
    engine = build_engine(settings)
    assert isinstance(engine, AutogenRemediationEngine)
    assert engine.model_name == "gpt-4o-mini"


def test_the_autogen_engine_refuses_to_build_without_a_key() -> None:
    from backend.agents.autogen_engine import AutogenRemediationEngine

    with pytest.raises(ValueError, match="SENTINEL_LLM_API_KEY"):
        AutogenRemediationEngine(_settings(llm_api_key=""))


def test_the_configured_round_default_is_sane() -> None:
    """A default of 1 would mean no loop; a default of 50 would mean no bound."""
    settings = get_settings()
    assert 1 <= settings.remediation_max_rounds <= 10
    assert settings.remediation_max_llm_calls >= settings.remediation_max_rounds * 2
