# 004 — Support both `mcp` SDK majors rather than pinning one

**Status:** accepted

## Context

The MCP Python SDK renamed its high-level server class between v1 and v2:

| major | import |
|---|---|
| v1 | `mcp.server.fastmcp.FastMCP` |
| v2 | `mcp.server.mcpserver.MCPServer` (`FastMCP` was renamed) |

Everything this project actually uses — the constructor, `.tool()`,
`.list_tools()`, `.call_tool()`, `.run_stdio_async()`,
`.run_streamable_http_async()` — kept the same names and semantics across the
rename. So the API surface this project depends on is unchanged, and the only
difference is one import line.

That makes the usual response tempting: pin a version and move on.

The complication is the dependency graph. **`semgrep` pins `mcp<2` hard.** And
Semgrep is the roadmap's SAST stretch goal for this sprint — it is a real
scanner here (`backend/scanners/semgrep.py`), just not in the container image.

So pinning to v2 makes it impossible to install the scanner and the MCP surface
in the same environment. Pinning to v1 freezes the project on an SDK major that
the ecosystem is moving off.

## Decision

**Unpinned `mcp>=1.2.0`, with a fifteen-line import shim.**

```python
def _server_class() -> type:
    try:
        from mcp.server.mcpserver import MCPServer

        return MCPServer
    except ModuleNotFoundError:
        from mcp.server.fastmcp import FastMCP

        return FastMCP
```

Three details make the shim honest rather than hopeful:

- **Detection is by trying the v2 import, not by reading a version string.**
  The v2 `ModuleNotFoundError` is a deliberate, explicit error from the SDK, and
  which import exists is what actually determines the API.
- **The major version is reported, never hidden.** `mcp_sdk_major_version()` is
  logged at startup and returned on `GET /health/policy`, so a deployment always
  knows which one it got. A compatibility shim that leaves you guessing which
  branch it took is worse than no shim.
- **Constructor kwargs are filtered against the live signature**, and the SDK's
  own tool-argument error type is resolved the same way, so v1/v2 differences in
  either are handled rather than hoped about.

## Consequences

**Good.** A reviewer who runs `pip install -e .` gets whatever `pip` resolves and
it works. Someone who needs Semgrep — which is the roadmap's stretch goal for
this very sprint — can install both in one environment. That is a real
capability, not a hypothetical: without the shim, this project's SAST goal and
its MCP surface are mutually exclusive.

**And it is verified, not asserted.** `scripts/verify_mcp_sdk.py` runs the same
ten checks against whichever major is installed: four tools exposed, every tool
publishing an object input schema, every tool carrying an actionable
description, the SDK's error type resolving, protocol-level rejection of a
missing argument and of an unknown tool name, plus four round trips proving a
known CVE returns its advisory, an unknown CVE is a *result* rather than an
exception, a malformed UUID comes back as a structured error with a remedy, and
an omitted filter is not an error.

The two environments genuinely land on different majors, and that is not
arranged — it falls out of the dependency graph:

| environment | `mcp` resolved | why |
|---|---|---|
| local venv | **v1** | something in the tree pins `mcp<2` |
| runtime image | **v2** | the image deliberately does not install `semgrep` |

So `make verify-mcp` and CI's `mcp-sdk` job check one branch, and CI's `docker`
job runs the identical script inside the image to check the other. A change that
works on only one major fails CI instead of failing in a reviewer's
environment. Both branches currently pass all ten.

**Inconvenient.** Someone can install a v3 that renames things again and the
import will fail with a `ModuleNotFoundError` pointing at *our* line rather than
at the SDK's changelog. That is a legible failure, but it is ours to own. The
`>=1.2.0` floor is also not tested against — it is a floor to express intent
(the API this project uses arrived in 1.2), not a claim that 1.2 was tested.

**Also:** `pyproject.toml` unpins `mcp` deliberately, and that decision is load-
bearing for anyone who tries to tidy the dependency list. There is a comment on
the line saying so. Please read it before pinning.

## Alternatives considered

**Pin `mcp>=2,<3`.** Simplest, most honest for a portfolio project, and what most
projects do. Rejected because it makes Semgrep uninstallable alongside the MCP
server, and the roadmap explicitly asks for SAST as this sprint's stretch goal.
Trading a working feature path for tidier dependencies is the wrong trade for a
project whose purpose is demonstrating the features.

**Pin `mcp<2`.** Keeps Semgrep happy and is a real, defensible choice if Semgrep
matters more. Rejected because it freezes the project on the older major while
the SDK is clearly moving forward, and the shim makes supporting both nearly
free.

**Vendor the relevant parts of the SDK.** Maximum control, and a maintenance
burden that would consume this sprint on a project whose actual subject is
security triage.

**Detect via `importlib.metadata.version("mcp")`.** Rejected: version strings and
importable module layouts are not the same thing, and the one time they agree is
not the time you find out they do not. `mcp_sdk_major_version()` uses
`importlib.util.find_spec` for the same reason the server class does — asking
what is importable is asking the question directly.
