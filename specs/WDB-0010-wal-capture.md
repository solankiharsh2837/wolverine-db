# WDB-0010: WAL Capture

Status: Normative Specification (v0.2 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification defines the native PostgreSQL Write-Ahead Log (WAL) logical decoding capture subsystem. WAL capture operates alongside or in conjunction with trigger-based capture, extracting committed mutations directly from PostgreSQL logical replication streams and producing deterministic `ChangeRecordData` instances conforming to `WDB-0001` and `WDB-0002`.

## 2. Replication Slot Protocol

Implementations MUST interact with PostgreSQL via standard logical replication slots using a supported output plugin (`test_decoding`, `pgoutput`, or `wal2json`).

### 2.1 Slot Lifecycle
1. **Creation**: The replication slot MUST be created with logical decoding enabled (`pg_create_logical_replication_slot`).
2. **Streaming**: The capture engine MUST consume changes via streaming protocol (`START_REPLICATION SLOT ... LOGICAL`).
3. **Acknowledgment (Feedback)**: The capture engine MUST only advance and acknowledge the confirmed flush LSN (`Log Sequence Number`) to PostgreSQL after the corresponding change batch has been deterministically hashed, committed to the local hash chain (`WDB-0003`), or anchored.
4. **Restart & Idempotency**: Upon engine restart or network reconnection, the capture engine MUST resume from the last acknowledged LSN. Any re-streamed transactions MUST be deduplicated by comparing transaction IDs (`txId`) against the committed chain.

## 3. Transaction Boundary & Mutation Ordering

1. **Atomic Grouping**: WAL events belonging to a single PostgreSQL transaction MUST be accumulated between `BEGIN` and `COMMIT` records.
2. **Rollback Discard**: Transactions terminated with `ABORT` or `ROLLBACK` (or truncated streams) MUST be discarded immediately, emitting zero change records.
3. **Commit Ordering**: Change records produced from WAL decoding MUST be ordered monotonically by their PostgreSQL Commit LSN / transaction commit sequence.
4. **Primary Key Reconstruction**: For each mutated tuple, the capture engine MUST extract the primary key columns according to the table's replica identity (`REPLICA IDENTITY DEFAULT` or `FULL`) and encode them into the canonical binary primary key tuple representation (`WDB-0002`).

## 4. Normalization to WDB-0001 Canonical Change

The WAL decoder MUST output a `ChangeRecordData` payload with:
- `formatVersion`: `1`
- `versionId`: Monotonically derived or assigned UUID v4.
- `transactionId`: PostgreSQL transaction identifier as UTF-8 string (e.g., `"pg-tx:<xid>"`).
- `timestampUs`: PostgreSQL transaction commit timestamp in Unix microseconds (UTC).
- `tableId`: Fully qualified `"schema.table"` string.
- `recordId`: Canonical binary primary key tuple.
- `operation`: Mapped to `MutationOperation` (`INSERT=1`, `UPDATE=2`, `DELETE=3`).
- `fieldSet`: `{ new: Record<string, unknown> | null, old: Record<string, unknown> | null }` normalized according to RFC 8785 canonical JSON rules.
- `provenance`: Provenance envelope containing session origin, replication slot name, and commit LSN.
- `previousHash`: The 32-byte SHA-256 digest of the immediately preceding committed change record in the chain.

## 5. Security & Isolation

- WAL capture MUST operate in read-only logical replication mode without modifying user tables.
- If the WAL stream contains mutations for tables not registered in `protected_scopes`, those mutations MUST be safely ignored without disrupting the stream or hash chain sequence.
