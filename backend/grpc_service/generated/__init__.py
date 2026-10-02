"""Bootstrap for the generated protobuf modules.

`grpc_tools.protoc` emits `from sentinel.v1 import scanner_pb2` -- an
*absolute* import rooted at the generation directory -- no matter where the
output was written. That import only resolves if this directory is on
`sys.path`.

Doing the `sys.path` surgery here (rather than in a conftest, a sitecustomize,
or by post-editing the generated files) means there is exactly one place that
knows about this quirk, and every entry point gets it for free just by
importing `backend.grpc_service.generated`. The alternative -- rewriting the
generated imports to be relative -- would be silently undone the next time
someone runs `make proto`, and would break the "the generated tree is exactly
what protoc produced" property that makes it safe to delete and regenerate.
"""

from __future__ import annotations

import sys
from pathlib import Path

_GENERATED_DIR = Path(__file__).resolve().parent

if str(_GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(_GENERATED_DIR))

# Importing the concrete modules here (rather than leaving callers to do it)
# means `import backend.grpc_service.generated` alone is enough to make
# `sentinel.v1.scanner_pb2` and `scanner_pb2_grpc` importable.
from sentinel.v1 import scanner_pb2, scanner_pb2_grpc  # noqa: E402,F401  (import order is the whole point of this module)

__all__ = ["scanner_pb2", "scanner_pb2_grpc"]
