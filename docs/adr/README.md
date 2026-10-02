# Architecture Decision Records

Four decisions worth writing down, each with the alternatives that were
rejected and why. An ADR is only worth keeping if it records something a
reader would otherwise have to reverse-engineer, or would otherwise "clean up"
without knowing what it cost.

| # | decision | status |
|---|---|---|
| [001](001-safety-rails-and-human-approval.md) | The system proposes code; a human merges it. Enforced five ways. | accepted |
| [002](002-autogen-vs-langgraph-crewai.md) | AutoGen for the developer/reviewer loop, not LangGraph or CrewAI. | accepted |
| [003](003-grpc-scanning-boundary.md) | A typed gRPC boundary for scanning, with an in-process implementation behind the same interface. | accepted |
| [004](004-mcp-sdk-major-version.md) | Support both `mcp` SDK majors rather than pinning one. | accepted |

## Format

Each record is: context (what forced a decision), decision, consequences
(including the ones that are inconvenient), and alternatives considered with the
reason each was rejected. Status is one of `proposed`, `accepted`, `superseded
by NNN`, `rejected`.

Records are numbered and never renumbered — a superseded record keeps its
number, because a link in a commit message from six months ago has to keep
pointing at the argument that was actually made.

## What is deliberately not here

Decisions that were not hard. The choice of FastAPI, of SQLAlchemy, of
`argparse` over `click`, of Pydantic v2 — those are not decisions worth a
record; they are the current default, and a reader who disagrees can change them
without invalidating an argument. An ADR that records every easy choice is noise
that trains people to skip the file.

Two of these four records exist because the *first* implementation of the
decision was wrong, and the record is more useful for the correction than for
the original choice. That is the point of writing them down.
