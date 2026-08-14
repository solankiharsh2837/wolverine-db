# PostgreSQL adapter

The PostgreSQL adapter protects configured schemas and tables, enforces strict transaction-boundary change capture, persists WolverineDB metadata separately in the `wolverine_sys` schema, and maintains an authoritative transaction commit sequence (`wolverine_sys.commit_seq`).

## Transaction Boundaries & Rollback Safety

- Capture is executed inside the PostgreSQL transaction context using PL/pgSQL triggers and helper functions.
- If a database transaction rolls back or aborts, all uncommitted history records written to `wolverine_sys` roll back atomically, producing exactly zero change records.

## Global Ordering & Sequence Locking

- Concurrent transactions obtain an authoritative monotonically increasing commit sequence from `wolverine_sys.commit_seq` during transaction commit.
- Ensures a deterministic, strictly ordered global change stream across concurrent writers.

## Threat Model & Security Boundaries

- **Capabilities**: Detects unauthorized application-level mutations, improper modifications, and unapproved data changes occurring through application connections.
- **Limitations**: Triggers **cannot** prevent an administrative superuser (DBA) from disabling triggers, modifying `session_replication_role`, or directly manipulating `wolverine_sys` tables.
- **Divergence Detection**: Offline verification against external Merkle tree checkpoints detects history deletion, direct table edits, or trigger bypass.

Normative specs: [`specs/WDB-0001-protocol.md`](file:///c:/Users/harsh/Documents/Codex/2026-08-13/referenced-chatgpt-conversation-this-is-an/wolverine-db/specs/WDB-0001-protocol.md) and [`specs/WDB-0003-hash-chain.md`](file:///c:/Users/harsh/Documents/Codex/2026-08-13/referenced-chatgpt-conversation-this-is-an/wolverine-db/specs/WDB-0003-hash-chain.md).
