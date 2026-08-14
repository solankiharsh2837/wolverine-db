# Recovery engine

Recovery flow: detect, localize, identify last trusted state, reconstruct candidate state, compare, propose a transaction, obtain policy-required approval, commit, and verify the resulting new version.

Recovery is field- and record-selective by default. It preserves compromised values and all evidence in immutable history. A single field may be corrected from a trusted version; multiple records require an explicit scope; table-wide recovery and history reconstruction are exceptional and require elevated approval. If trust cannot be established, WolverineDB must stop with an indeterminate outcome.
