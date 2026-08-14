# Architecture

`Application/DBA/Migration -> Auth + Context -> Authorization Ledger -> PostgreSQL transaction -> Change Capture -> Canonical Encoder -> Hash Chain -> Immutable Log -> Version/State Engine -> Merkle Engine -> Checkpoint -> optional External Anchor`.

The SDK supplies identity and request context. The authorization ledger records who approved what and why. PostgreSQL holds current state. Capture observes committed changes; the immutable log records canonical events; the version engine derives immutable versions; the integrity engine verifies chains, state, and commitments; the recovery engine proposes a new corrective version; and the anchor manager publishes external commitments.

The capture mechanism is **UNRESOLVED**: v0.1 must select and specify logical decoding, triggers, or a constrained hybrid. Capture must be transaction-aware and must never emit committed history for a rolled-back transaction.
