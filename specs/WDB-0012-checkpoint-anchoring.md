# WDB-0012: Checkpoint Anchoring

Status: Normative Specification (v0.2 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope

This specification defines the cryptographic anchoring of WolverineDB state checkpoints into external storage systems, establishing an independent chain of trust that resists database superuser tampering.

## 2. Checkpoint Structure & Canonical Representation

A Checkpoint record represents an immutable commitment over a specific database state at commit sequence `commit_seq`.

### 2.1 Checkpoint Fields
Every checkpoint payload MUST contain:
1. `checkpoint_id`: Unique identifier (UUID v4 string).
2. `scope`: Protected database scope / schema name (UTF-8 string).
3. `commit_seq`: Authoritative monotonic transaction sequence number (`I64`).
4. `previous_checkpoint`: Identifier of the previous checkpoint in the sequence (`null` for initial checkpoint).
5. `merkle_root`: 32-byte SHA-256 Merkle root across all active protected records (`WDB-0004`).
6. `change_chain_head`: 32-byte SHA-256 hash of the most recent committed change record (`WDB-0003`).
7. `created_at`: Unix microseconds timestamp UTC (`I64`).
8. `protocol_version`: WolverineDB protocol version integer (`2` for v0.2.0).

### 2.2 Canonical Checkpoint Digest Computation

The canonical checkpoint digest MUST be calculated using SHA-256 domain separation:

```
CheckpointDigest = SHA-256(
    "WDB:CHECKPOINT:v1:" ||
    checkpoint_id_bytes (16 bytes UUID) ||
    scope_length (4 bytes BE) || scope_bytes (UTF-8) ||
    commit_seq (8 bytes BE I64) ||
    previous_checkpoint_bytes (16 bytes UUID, zeroed if null) ||
    merkle_root (32 bytes) ||
    change_chain_head (32 bytes) ||
    created_at (8 bytes BE I64) ||
    protocol_version (4 bytes BE I32)
)
```

## 3. Anchoring Workflow

```
CHANGE 1 ──► CHANGE 2 ──► CHANGE 3
                             │
                             ▼
                        Merkle Root
                             │
                             ▼
                       Checkpoint #42
                             │
                             ▼
                   Canonical Digest Calc
                             │
                             ▼
                   External Checkpoint Store
                   (Local / S3 Object Lock / WORM)
```

1. **Emission**: Upon reaching a checkpoint interval (e.g., every $N$ transactions, periodic time window, or explicit manual trigger), the engine constructs the Checkpoint record.
2. **Hashing**: The engine computes the canonical Checkpoint Digest.
3. **External Write**: The checkpoint payload and digest are committed to the configured `CheckpointStore`.
4. **Receipt Confirmation**: The external storage receipt (ETag, URI, version ID, or local file hash) is persisted to `wolverine_sys.checkpoints`.

## 4. Verification & State Divergence Detection (Split-Brain)

During offline or real-time verification (`wdb verify`):
1. The Verifier queries the current PostgreSQL live state and recalculates the observed state Merkle root.
2. The Verifier retrieves the latest authoritative external checkpoint from the external store.
3. The Verifier validates the external checkpoint's canonical digest.
4. The Verifier compares the expected Merkle root and change chain head from the external checkpoint with the PostgreSQL live state.

### 4.1 Divergence Reporting
If the PostgreSQL database has been altered directly by a compromised DBA (bypassing Wolverine or rolling back local history), but the external store retains the authentic checkpoint, the verifier MUST report:

```
STATUS: CRITICAL INTEGRITY DIVERGENCE (SPLIT-BRAIN)
Expected Root (External): 7a91b2c4e5...
Observed Root (PostgreSQL): c31f98d01a...
External Checkpoint ID: 429f9c0e-128a-40f3-8bd2-55d326ef6009
External Anchor: VALID
Database Status: CORRUPTED / TAMPERED
```
