# Final data flow

1. An application, DBA, or migration supplies SQL plus an identity/session/request context.
2. The authorization ledger creates or references an authorization envelope: who, what, why, policy outcome, and approval/change ticket.
3. PostgreSQL commits the transaction. Current state changes and capture receives the committed mutation.
4. Capture creates a raw change record; the canonical encoder produces bytes; SHA-256 produces a 32-byte change hash linked to its predecessor.
5. The append-only log and version engine record the event and derive record/state leaf hashes. Ordered leaves form a Merkle root at a checkpoint, which may be externally anchored.

Verification follows `tampering -> mismatch -> localization -> provenance analysis -> classification -> approved recovery -> new version`. A mismatch is evidence of divergence, not evidence of malicious intent.
