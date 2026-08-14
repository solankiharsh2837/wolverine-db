# API specification

The public TypeScript surface is conceptually `connect`, `verify`, `history`, `diff`, `checkpoint`, `anchor`, `inspect`, and `recover`.

`verify(scope?)` returns a typed result with status, checked boundary, failures, and evidence references. `recover(plan)` only creates a proposal unless the caller presents a policy-valid approval. `history` and `diff` are read-only. Exact TypeScript types, authentication integration, and async job semantics are **UNRESOLVED**; no API may expose an unsafe implicit recovery shortcut.
