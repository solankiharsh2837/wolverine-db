# Implementation rules

Implement from specifications, not assumptions. Canonical bytes are the only hash input; never hash language objects, database dumps, or unordered JSON. Use fixed-width comparisons for hashes where practical and reject malformed data.

Maintain append-only history. Record failures and indeterminate states; do not collapse them into success. Design capture around committed PostgreSQL transactions. Keep authorization provenance separate from cryptographic evidence and never interpret a mismatch as proof of malicious intent.

Before implementing a marked unresolved choice, propose the decision, update the normative specification and vectors, assess compatibility, then obtain review.
