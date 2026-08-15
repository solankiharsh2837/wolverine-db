# WDB-0011: External Checkpoint Store

Status: Normative Specification (v0.2 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Architectural Invariant

The external checkpoint store is strictly an **external anchor and trust boundary**; it **MUST NOT** replace PostgreSQL as the live database of record, and **MUST NOT** be embedded directly into the deterministic inner cryptographic loop.

```
WolverineDB Core
    ├── PostgreSQL metadata (wolverine_sys)
    └── External immutable checkpoint store (Local / S3 / WORM)
```

## 2. CheckpointStore Interface

All external store implementations MUST adhere to the following interface contract:

```typescript
export interface CheckpointRecordData {
  checkpointId: string;
  protectedScope: string;
  commitSeq: bigint;
  previousCheckpointId: string | null;
  merkleRoot: Buffer; // 32 bytes SHA-256
  changeChainHead: Buffer; // 32 bytes SHA-256
  timestampUs: bigint;
  protocolVersion: number;
}

export interface CheckpointStore {
  /**
   * Persists a canonical checkpoint payload immutably.
   * If a checkpoint with the same ID already exists with differing payload,
   * MUST throw a CheckpointConflictError.
   */
  put(checkpoint: CheckpointRecordData): Promise<void>;

  /**
   * Retrieves a checkpoint by its unique identifier.
   * Returns null if the checkpoint does not exist.
   */
  get(id: string): Promise<CheckpointRecordData | null>;

  /**
   * Lists all checkpoints within a protected scope in ascending commit order.
   */
  list(scope: string): Promise<CheckpointRecordData[]>;

  /**
   * Cryptographically verifies the integrity of an externally stored checkpoint.
   * Recalculates the canonical digest and verifies absence of local/remote tampering.
   */
  verify(id: string): Promise<boolean>;
}
```

## 3. Store Implementations

### 3.1 LocalCheckpointStore
- Persists canonical checkpoint JSON/binary files to a dedicated local directory.
- Files MUST be set with read-only permissions (`0444` / read-only attributes) post-write.
- Used for local development, embedded deployments, and deterministic unit testing.

### 3.2 S3CheckpointStore
- Persists checkpoints to an Amazon S3 (or S3-compatible, e.g., MinIO, Cloudflare R2) bucket.
- Checkpoint keys MUST follow the deterministic hierarchy: `<scope>/checkpoints/<checkpoint_id>.wdbchk`.
- Objects SHOULD be configured with S3 Object Lock (Legal Hold or Compliance Retention Mode) where supported.
- Checkpoint content SHA-256 digest MUST be attached as S3 Object Metadata (`x-amz-meta-wdb-digest`).

### 3.3 WORMCheckpointStore
- Hardware or cloud-enforced Write-Once-Read-Many (WORM) storage abstraction.
- Any attempt to overwrite or delete an existing checkpoint key MUST be rejected by the underlying storage tier with an immutable retention error.

## 4. Error Model & Fail-Soft Invariants

- If the external checkpoint store is temporarily unreachable (`STORE_UNAVAILABLE`), WolverineDB capture **MAY** buffer pending checkpoints locally, but the verifier MUST flag the state as unanchored until external persistence succeeds.
- Deletion or substitution of an external checkpoint MUST be treated as a catastrophic integrity failure (`SPLIT_BRAIN_DETECTED`).
