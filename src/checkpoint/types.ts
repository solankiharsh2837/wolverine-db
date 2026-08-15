export interface AnchoredCheckpoint {
  checkpointId: string;
  scope: string;
  commitSeq: bigint;
  previousCheckpointId: string | null;
  merkleRoot: Buffer; // 32 bytes SHA-256
  changeChainHead: Buffer; // 32 bytes SHA-256
  createdAtUs: bigint;
  protocolVersion: number;
  digest: Buffer; // 32 bytes SHA-256 canonical digest
}

export interface CheckpointStore {
  /**
   * Persists a canonical checkpoint payload immutably.
   * If a checkpoint with the same ID exists with differing payload/digest, throws an error.
   */
  put(checkpoint: AnchoredCheckpoint): Promise<void>;

  /**
   * Retrieves an anchored checkpoint by its ID. Returns null if not found.
   */
  get(checkpointId: string): Promise<AnchoredCheckpoint | null>;

  /**
   * Lists all checkpoints within a scope in ascending commit sequence order.
   */
  list(scope: string): Promise<AnchoredCheckpoint[]>;

  /**
   * Cryptographically verifies the integrity and immutability of an external checkpoint.
   */
  verify(checkpointId: string): Promise<boolean>;
}
