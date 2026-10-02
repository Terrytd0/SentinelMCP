# Generated gRPC code

Everything in this directory is produced by `protoc` from
`proto/sentinel/v1/scanner.proto`. Do not hand-edit it.

## Regenerate

```bash
make proto
```

or directly:

```bash
uv run python -m grpc_tools.protoc -I proto \
    --python_out=backend/grpc_service/generated \
    --pyi_out=backend/grpc_service/generated \
    --grpc_python_out=backend/grpc_service/generated \
    proto/sentinel/v1/scanner.proto
```

`grpcio-tools` is a **dev** dependency, not a runtime one, precisely because
this output is committed. A runtime service should not need a compiler
installed to start.

## Why the output is committed

Three reasons, in order of weight:

1. **The build should not need a protobuf compiler.** Anyone cloning this can
   `pip install -e .` and run the whole system. A build step that shells out to
   `protoc` is a build step that fails on a machine without it, and a reviewer is
   exactly that machine.
2. **The generated diff is reviewable.** A PR that changes `scanner.proto` shows
   both the schema change and its effect on the generated code, in the same
   diff. Regenerating at build time means the generated half is never reviewed.
3. **CI can prove the committed output matches the schema.** If regeneration
   produces a different diff, that is a real finding — a stale commit, or a
   different `grpcio-tools` version than the one the output came from.

## Why nothing lints or type-checks this tree

Both `pyproject.toml` files exclude it:

```toml
# ruff
extend-exclude = ["backend/grpc_service/generated", ...]

# mypy
exclude = ["backend/grpc_service/generated/", ...]
```

Reformatting generated output **obscures what the generator actually decided.**
A whitespace-only change to `scanner_pb2.py` makes the next real change to the
proto impossible to read in a diff, and a linter that "fixes" machine-written
code is actively destroying information. Type-checking it produces errors that
cannot be fixed without editing generated code, which is a loop with no exit.

The practical consequence, which is the thing to watch: **nothing will tell you
the committed output is stale.** If you change the `.proto` and forget
`make proto`, the suite fails on an import error rather than a clear message.
That is a worse error than it should be. Run `make proto` and
`make check` in the same commit.

## `__init__.py` and the `sys.path` insertion

`protoc` emits `from sentinel.v1 import ...` — an absolute import rooted at
`generated/`, not a relative one. Python does not treat a sibling directory as a
package root, so `generated/__init__.py` inserts this directory onto `sys.path`
at import time.

That is the one non-generated line in the tree. It is hand-written on purpose
and the nested `__init__.py` files exist only to make `generated` a package so
this one runs.

The alternative is post-processing every generated file to rewrite its imports,
which is a script that has to be kept working across `grpcio-tools` versions and
is strictly more fragile than a four-line `sys.path` insertion.

## Files here

| file | what it is |
|---|---|
| `scanner_pb2.py` | message classes and the serialized descriptor |
| `scanner_pb2.pyi` | type stubs, so mypy can see the message fields |
| `scanner_pb2_grpc.py` | `ScannerServiceStub` and the servicer base class |
| `__init__.py` | the `sys.path` insertion described above |
| `sentinel/`, `sentinel/v1/` | package markers protoc expects to emit into |

The `.pyi` is worth keeping. Without it, `mypy` sees an opaque generated class
and `scanner_pb2.HealthRequest(healthy=...)` type-checks as anything at all —
which is how a field name typo survives to runtime.

## When you add a field

1. Add it to the `.proto`, with the **next free number** — never renumber.
   Renumbering a protobuf enum or field is a wire-breaking change for any client
   built against the old schema.
2. `make proto`.
3. Update `backend/grpc_service/conversion.py` for the new field. This is the
   step that is easy to forget, and nothing catches it: an unmapped field simply
   does not appear in the response.
4. `make check`.

See [ADR 003](../../../docs/adr/003-grpc-scanning-boundary.md) for why the enum
values are numbered with gaps, and for why `HealthResponse` carries
`fixture_targets` at all.
