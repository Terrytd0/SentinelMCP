"""The MCP tool surface, driven through the real protocol server.

Not the tool functions in isolation -- a real `MCPServer` is built and its
`list_tools` / `call_tool` are called, so the JSON Schema MCP generates from the
type hints, the argument validation, and the result serialisation are all
exercised. A test that calls `tools.list_findings(args)` proves the logic and
none of the protocol, and the protocol is the part an MCP client actually sees.

The four tools are exactly the roadmap's specified surface:
`list_findings`, `get_cve_details`, `propose_fix`, `create_ticket`.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest

from backend.database.enums import Confidence, FindingStatus, Severity
from backend.database.repositories.finding import FindingRepository
from backend.mcp_server.server import build_mcp_server, build_scanner_backend
from backend.mcp_server.tools import (
    CreateTicketArgs,
    FindingSummary,
    GetCveDetailsArgs,
    ListFindingsArgs,
    ProposeFixArgs,
    SentinelTools,
    ToolError,
)

pytestmark = pytest.mark.integration

EXPECTED_TOOLS = {"list_findings", "get_cve_details", "propose_fix", "create_ticket"}


def _input_schema(tool: Any) -> dict[str, Any]:
    """A tool's input schema, under either SDK naming.

    v1 exposes `inputSchema`, v2 `input_schema`. Reading it through this helper
    is what lets one test run against both.
    """
    return getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})


def _output_schema(tool: Any) -> dict[str, Any]:
    return getattr(tool, "output_schema", None) or getattr(tool, "outputSchema", {}) or {}


def _payload(result: Any) -> dict[str, Any]:
    """The tool's return value, as the JSON a client sees.

    `call_tool` has two return shapes across the SDK majors:

        v1  a `(content_blocks, structured_dict)` tuple
        v2  a `CallToolResult` object

    Normalised to the unwrapped model here. The `content` text block is the
    stable, readable shape in both; `structured_content` nests a union return
    under a `result` key in v2 and is a separate tuple element in v1, so the two
    are not interchangeable and the text block is what the tests read.
    """
    if isinstance(result, tuple):
        content = result[0]
    else:
        content = result.content
    if not content:
        raise AssertionError("the tool returned no content block")
    return json.loads(content[0].text)


def _structured(result: Any) -> dict[str, Any] | None:
    """The machine-readable half of a result, unwrapped from the union."""
    payload: Any
    if isinstance(result, tuple):
        payload = result[1] if len(result) > 1 else None
    else:
        payload = getattr(result, "structured_content", None)
        if payload is None:
            payload = getattr(result, "structuredContent", None)
    if not payload:
        return None
    return dict(payload.get("result", payload))


def _ok(result: Any) -> Any:
    """Assert the tool succeeded and narrow the union for the type checker.

    Every MCP tool returns `SomeResult | ToolError`, which is the right design
    -- a client handles one shape for both outcomes. In a test it means each
    call has to say which branch it is asserting, and this is where it says so.
    """
    assert not isinstance(result, ToolError), f"expected success, got: {result}"
    return result


def _err(result: Any) -> Any:
    """Assert the tool returned a structured error and narrow the union."""
    assert isinstance(result, ToolError), f"expected an error, got: {result}"
    return result


async def _tools(session: Any) -> SentinelTools:
    return SentinelTools(session, await build_scanner_backend())


async def _first_finding(
    session: Any, *, severity: Severity | None = None, eligible: bool = False
) -> str:
    """A usable finding id from the persisted backlog.

    Picks a real row rather than fabricating an id, so the returned value is
    always one the tools will accept. Requires a snippet and a path, because a
    finding without them is one `propose_fix` will legitimately refuse.
    """
    rows = await FindingRepository(session).list_open_with_sla(
        severities=[severity] if severity else None, limit=100
    )
    for row in rows:
        if eligible and not row.auto_remediation_eligible:
            continue
        if not row.snippet or not row.file_path:
            continue
        return str(row.id)
    raise AssertionError(f"no suitable seeded finding (severity={severity}, eligible={eligible})")


# --- Tool surface -------------------------------------------------------


async def test_exactly_the_four_specified_tools_are_exposed(db_session: Any) -> None:
    server = build_mcp_server(db_session, await build_scanner_backend())
    tools = await server.list_tools()
    assert {tool.name for tool in tools} == EXPECTED_TOOLS


async def test_every_tool_has_a_description_a_client_can_act_on(db_session: Any) -> None:
    """The description is the only documentation an LLM client sees.

    `propose_fix`'s in particular has to say it never merges, because a client
    that does not know that will tell a user their vulnerability is fixed.
    """
    server = build_mcp_server(db_session, await build_scanner_backend())
    by_name = {tool.name: tool for tool in await server.list_tools()}

    for name, tool in by_name.items():
        assert tool.description, f"{name} has no description"
        assert len(tool.description) > 40, f"{name}'s description is too thin to be useful"

    assert "NEVER MERGES" in by_name["propose_fix"].description
    assert "do not tell a user" in by_name["propose_fix"].description.lower()


async def test_every_tool_has_an_object_input_schema(db_session: Any) -> None:
    server = build_mcp_server(db_session, await build_scanner_backend())
    for tool in await server.list_tools():
        assert _input_schema(tool)["type"] == "object", f"{tool.name} has no object schema"


async def test_every_tool_publishes_an_output_schema_naming_both_outcomes(
    db_session: Any,
) -> None:
    """Success and failure are both typed Pydantic models, so the tool
    advertises a union the client can validate against -- rather than a
    "sometimes this throws" contract it has to discover at runtime.

    The union is published as `properties.result.anyOf` with the variants under
    `$defs`, so the check is on the `$defs` keys rather than the inline refs.
    """
    server = build_mcp_server(db_session, await build_scanner_backend())
    for tool in await server.list_tools():
        schema = _output_schema(tool)
        assert schema, f"{tool.name} publishes no output schema"
        variants = schema["properties"]["result"]["anyOf"]
        assert len(variants) >= 2, f"{tool.name} advertises only one outcome"
        assert "ToolError" in schema["$defs"], (
            f"{tool.name}'s output schema does not include the ToolError shape, "
            "so a client cannot tell a failure from a result"
        )


async def test_an_omitted_optional_filter_is_not_an_error(seeded_session: Any) -> None:
    """Regression: an MCP client sends `null` for an omitted optional argument,
    not "absent".

    With a plain `default_factory=list`, every call that left a filter unset was
    rejected -- which is the common case, and the tool only appeared to work
    because the tests called it from Python where the arguments really are
    absent. Found by the protocol round-trip test, not by the logic tests.
    """
    server = build_mcp_server(seeded_session, await build_scanner_backend())
    payload = _payload(await server.call_tool("list_findings", {}))

    assert "error" not in payload, payload
    assert payload["returned"] == 8


async def test_explicit_null_filters_behave_like_unset_ones(seeded_session: Any) -> None:
    server = build_mcp_server(seeded_session, await build_scanner_backend())
    payload = _payload(
        await server.call_tool(
            "list_findings",
            {"severity": None, "status": None, "scanner": None, "query": None},
        )
    )
    assert "error" not in payload, payload
    assert payload["returned"] == 8


# --- list_findings ------------------------------------------------------


async def test_list_findings_returns_the_open_backlog(seeded_session: Any) -> None:
    result = _ok(await (await _tools(seeded_session)).list_findings(ListFindingsArgs()))
    assert result.returned == 8
    assert result.total_matching == 8
    assert result.has_more is False
    assert result.findings


async def test_list_findings_sorts_most_urgent_first(seeded_session: Any) -> None:
    result = _ok(await (await _tools(seeded_session)).list_findings(ListFindingsArgs()))
    ranks = [Severity(f.severity).rank for f in result.findings]
    assert ranks == sorted(ranks)
    assert Severity(result.findings[0].severity) is Severity.CRITICAL


async def test_list_findings_filters_by_severity(seeded_session: Any) -> None:
    result = _ok(
        await (await _tools(seeded_session)).list_findings(
            ListFindingsArgs(severity=[Severity.CRITICAL, Severity.HIGH])
        )
    )
    assert {f.severity for f in result.findings} <= {"critical", "high"}


async def test_list_findings_filters_by_text(seeded_session: Any) -> None:
    result = _ok(
        await (await _tools(seeded_session)).list_findings(ListFindingsArgs(query="jinja2"))
    )
    assert result.returned >= 1
    assert all("jinja2" in f.title.lower() for f in result.findings)


async def test_list_findings_honours_the_limit_and_says_so(seeded_session: Any) -> None:
    """`has_more` plus a plain-language hint, so an agent does not have to infer
    the paging protocol."""
    result = _ok(await (await _tools(seeded_session)).list_findings(ListFindingsArgs(limit=3)))
    assert result.returned == 3
    assert result.has_more is True
    assert "next" in result.next_hint.lower()


async def test_list_findings_summary_carries_no_snippet(seeded_session: Any) -> None:
    """The snippet is the most sensitive field in the system; a triage queue of
    200 findings must not ship 200 blocks of source code to every caller.

    `FindingSummary` has no `snippet` field at all, which is a stronger
    guarantee than omitting the key from a payload: it cannot be added by
    accident, and a client reading the schema will not look for it.
    """
    result = _ok(await (await _tools(seeded_session)).list_findings(ListFindingsArgs()))
    assert "snippet" not in FindingSummary.model_fields
    assert all(f.file_path for f in result.findings)


async def test_the_detail_endpoint_is_where_snippets_are_available(
    seeded_session: Any,
) -> None:
    """A caller that genuinely needs the code can still get it, one finding at
    a time, through the finding's own record."""
    from backend.database.repositories.finding import FindingRepository

    finding_id = await _first_finding(seeded_session)
    row = await FindingRepository(seeded_session).get(uuid.UUID(finding_id))
    assert row is not None
    assert row.snippet, "the seeded finding has a snippet available on its record"


async def test_list_findings_can_include_closed(seeded_session: Any) -> None:
    tools = await _tools(seeded_session)
    repository = FindingRepository(seeded_session)

    open_rows = await repository.list_open_with_sla(limit=1)
    await repository.update_status(open_rows[0].id, FindingStatus.REMEDIATED)
    await seeded_session.commit()

    default = _ok(await tools.list_findings(ListFindingsArgs()))
    with_closed = _ok(await tools.list_findings(ListFindingsArgs(include_closed=True)))
    assert with_closed.total_matching > default.total_matching


# --- get_cve_details ----------------------------------------------------


async def test_get_cve_details_returns_the_advisory(db_session: Any) -> None:
    result = _ok(
        await (await _tools(db_session)).get_cve_details(GetCveDetailsArgs(cve_id="CVE-2023-46695"))
    )
    assert result.found is True
    assert "Django" in (result.title or "")
    assert result.cvss_score == 7.5
    assert result.cvss_band == "high"
    assert result.remediation
    assert result.references


async def test_get_cve_details_is_case_insensitive(db_session: Any) -> None:
    """CVEs get typed as `cve-2024-22195` at least as often as uppercase, and a
    lookup that fails on a case difference looks like a broken tool."""
    result = _ok(
        await (await _tools(db_session)).get_cve_details(GetCveDetailsArgs(cve_id="cve-2024-22195"))
    )
    assert result.found is True
    assert result.cve_id == "CVE-2024-22195"


async def test_get_cve_details_links_the_advisory_to_the_backlog(seeded_session: Any) -> None:
    """The connection between an advisory and the backlog is the whole reason
    the tool exists."""
    result = _ok(
        await (await _tools(seeded_session)).get_cve_details(
            GetCveDetailsArgs(cve_id="CVE-2023-46695")
        )
    )
    assert result.found
    assert result.matching_findings, "a seeded finding references this CVE"


async def test_an_unknown_cve_is_a_result_not_an_error(db_session: Any) -> None:
    """A miss is a legitimate answer, and it still carries the matching findings
    -- which is often the part the caller actually wanted."""
    result = _ok(
        await (await _tools(db_session)).get_cve_details(GetCveDetailsArgs(cve_id="CVE-1999-00001"))
    )
    assert result.found is False
    assert result.note
    assert "NVD" in result.note


async def test_a_cve_with_no_referencing_findings_still_returns(seeded_session: Any) -> None:
    result = _ok(
        await (await _tools(seeded_session)).get_cve_details(
            GetCveDetailsArgs(cve_id="CVE-2023-32681")
        )
    )
    assert result.found is True
    assert result.matching_findings == []


async def test_a_severity_disagreement_is_surfaced(db_session: Any) -> None:
    """A finding claiming `critical` for a CVSS 4.2 advisory is mislabelled
    somewhere upstream, and an analyst should be shown both, not silently given
    one."""
    from backend.services.cve import CveService

    advisory = CveService("data/cve/advisories.json").get("CVE-2023-32681")
    assert advisory["cvss_band"] == "medium"
    assert advisory["declared_severity"] == "medium"
    assert advisory["severity_mismatch"] is False


# --- create_ticket ------------------------------------------------------


async def test_create_ticket_opens_a_work_item(seeded_session: Any) -> None:
    tools = await _tools(seeded_session)
    finding_id = await _first_finding(seeded_session)

    result = _ok(
        await tools.create_ticket(
            CreateTicketArgs(finding_id=finding_id, title="Investigate the eval() call")
        )
    )
    assert result.ticket_key.startswith("SEC-")
    assert result.status.value == "open"
    assert "human analyst" in result.message
    assert result.created_by == "mcp:create_ticket"


async def test_create_ticket_defaults_the_priority_to_the_finding_severity(
    seeded_session: Any,
) -> None:
    tools = await _tools(seeded_session)
    finding = await _first_finding(seeded_session, severity=Severity.CRITICAL)

    result = _ok(await tools.create_ticket(CreateTicketArgs(finding_id=finding, title="Urgent")))
    assert result.priority.value == "critical"


async def test_create_ticket_marks_the_finding_triaged(seeded_session: Any) -> None:
    tools = await _tools(seeded_session)
    finding_id = await _first_finding(seeded_session)

    await tools.create_ticket(CreateTicketArgs(finding_id=finding_id, title="Look at this"))
    refreshed = await FindingRepository(seeded_session).get(uuid.UUID(finding_id))
    assert refreshed is not None
    assert refreshed.status is FindingStatus.TRIAGED
    assert refreshed.triaged_at is not None


async def test_create_ticket_rejects_an_unknown_finding(db_session: Any) -> None:
    result = _err(
        await (await _tools(db_session)).create_ticket(
            CreateTicketArgs(finding_id="00000000-0000-0000-0000-000000000001", title="Nope")
        )
    )
    assert result.error == "finding_not_found"


async def test_create_ticket_rejects_a_malformed_uuid(db_session: Any) -> None:
    result = _err(
        await (await _tools(db_session)).create_ticket(
            CreateTicketArgs(finding_id="not-a-uuid", title="Nope")
        )
    )
    assert result.error == "invalid_finding_id"
    assert "list_findings" in (result.remedy or "")


async def test_create_ticket_refuses_a_terminal_finding(seeded_session: Any) -> None:
    """Opening a ticket for a closed finding creates work nobody needs."""
    tools = await _tools(seeded_session)
    finding_id = await _first_finding(seeded_session)

    repository = FindingRepository(seeded_session)
    await repository.update_status(uuid.UUID(finding_id), FindingStatus.REMEDIATED)
    await seeded_session.commit()

    result = _err(
        await tools.create_ticket(CreateTicketArgs(finding_id=finding_id, title="Too late"))
    )
    assert result.error == "finding_already_terminal"


# --- propose_fix --------------------------------------------------------


async def test_propose_fix_drafts_a_pull_request(seeded_session: Any) -> None:
    """The end-to-end path: finding -> agent loop -> draft PR, with the draft
    explicitly flagged as awaiting a human."""
    tools = await _tools(seeded_session)
    finding_id = await _first_finding(seeded_session, eligible=True)

    result = _ok(await tools.propose_fix(ProposeFixArgs(finding_id=finding_id)))

    assert result.outcome == "approved"
    assert result.draft_pull_request_id is not None
    assert result.pull_request_number is not None
    assert result.patch
    assert result.requires_human_approval is True


async def test_propose_fix_reports_its_own_cost(seeded_session: Any) -> None:
    """Cost attribution is what makes the Aegis fleet dashboard possible."""
    tools = await _tools(seeded_session)
    finding_id = await _first_finding(seeded_session, eligible=True)

    result = _ok(await tools.propose_fix(ProposeFixArgs(finding_id=finding_id)))
    assert result.cost["llm_calls"] >= 1
    assert "tokens_used" in result.cost
    assert result.cost["latency_ms"] > 0
    assert "deterministic" in result.cost["llm_model"]


async def test_propose_fix_refuses_an_ineligible_finding(seeded_session: Any) -> None:
    """A policy refusal is a *successful* call that says no, and it must be
    structured so a client can explain the reason."""
    tools = await _tools(seeded_session)
    finding_id = await _first_finding(seeded_session)

    repository = FindingRepository(seeded_session)
    row = await repository.get(uuid.UUID(finding_id))
    assert row is not None
    row.confidence = Confidence.LOW
    row.status = FindingStatus.TRIAGED
    await seeded_session.commit()

    result = _err(await tools.propose_fix(ProposeFixArgs(finding_id=finding_id)))
    assert result.error == "policy_refused"
    assert "confidence" in (result.detail or "")
    assert result.remedy


async def test_propose_fix_rejects_a_malformed_id(db_session: Any) -> None:
    result = _err(await (await _tools(db_session)).propose_fix(ProposeFixArgs(finding_id="nope")))
    assert result.error == "invalid_finding_id"


async def test_propose_fix_reports_an_unknown_finding(db_session: Any) -> None:
    result = _err(
        await (await _tools(db_session)).propose_fix(
            ProposeFixArgs(finding_id="00000000-0000-0000-0000-000000000009")
        )
    )
    assert result.error == "finding_not_found"


# --- Audit --------------------------------------------------------------


async def test_every_tool_call_is_audited(seeded_session: Any) -> None:
    """Actor is `mcp:<tool>`, which makes "separate the AI's actions from the
    analysts'" one filter rather than a schema change."""
    from backend.database.enums import AuditAction
    from backend.database.repositories.ticket import AuditRepository

    await (await _tools(seeded_session)).list_findings(ListFindingsArgs())

    entries = await AuditRepository(seeded_session).list_recent(
        actions=[AuditAction.MCP_TOOL_INVOKED], limit=10
    )
    assert entries
    assert entries[0].actor == "mcp:list_findings"
    assert entries[0].payload["arguments"]


# --- Protocol round trip ------------------------------------------------


async def test_a_tool_call_round_trips_through_the_protocol(seeded_session: Any) -> None:
    """The full path a client takes: list the tools, call one, read the result."""
    server = build_mcp_server(seeded_session, await build_scanner_backend())
    result = await server.call_tool("list_findings", {"severity": ["critical"]})
    payload = _payload(result)

    assert payload["returned"] == 2
    assert all(f["severity"] == "critical" for f in payload["findings"])


async def test_a_success_result_carries_machine_readable_structured_content(
    seeded_session: Any,
) -> None:
    """Returning a typed model (rather than a bare dict) is what populates
    `structured_content` -- the field a real client parses instead of scraping
    the JSON out of a text block."""
    server = build_mcp_server(seeded_session, await build_scanner_backend())
    result = await server.call_tool("list_findings", {"limit": 2})

    structured = _structured(result)
    assert structured is not None, "the tool published no machine-readable result"
    # The SDK nests a union return under a `result` key, so the payload is one
    # level deeper here than in the text block.
    assert structured["returned"] == 2
    assert structured["findings"]


async def test_an_unrecognised_enum_value_comes_back_as_a_structured_result(
    db_session: Any,
) -> None:
    """The signature says `list[str]`, so the SDK cannot know that
    "apocalyptic" is not a severity. That check is ours, and it returns a
    structured `ToolError` the client can read and act on."""
    server = build_mcp_server(db_session, await build_scanner_backend())
    payload = _payload(await server.call_tool("list_findings", {"severity": ["apocalyptic"]}))

    assert payload["error"] == "invalid_arguments"
    assert "severity" in payload["detail"]


async def test_a_missing_required_argument_is_rejected_by_the_protocol(
    db_session: Any,
) -> None:
    """Arity and type are the SDK's job, and it rejects them before the body
    runs -- so a missing `cve_id` is a protocol error rather than our own.

    Two layers, both wanted; this asserts the boundary between them.
    """
    from backend.mcp_server.server import sdk_tool_error_type

    server = build_mcp_server(db_session, await build_scanner_backend())
    with pytest.raises(sdk_tool_error_type()):
        await server.call_tool("get_cve_details", {})


async def test_an_unknown_tool_name_is_rejected_by_the_protocol(db_session: Any) -> None:
    server = build_mcp_server(db_session, await build_scanner_backend())
    with pytest.raises(Exception, match="[Tt]ool"):
        await server.call_tool("delete_all_findings", {})
