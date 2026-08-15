import { AnchoredCheckpoint, CheckpointStore } from './types.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { computeCheckpointDigest } from './anchor.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export class WORMCheckpointStore implements CheckpointStore {
  private wormStorage = new Map<string, AnchoredCheckpoint>();

  public async put(checkpoint: AnchoredCheckpoint): Promise<void> {
    if (this.wormStorage.has(checkpoint.checkpointId)) {
      const existing = this.wormStorage.get(checkpoint.checkpointId)!;
      if (!timingSafeEqualHashes(existing.digest, checkpoint.digest)) {
        throw new WolverineError(
          WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
          `WORMRetentionViolation: Checkpoint ${checkpoint.checkpointId} is locked under WORM compliance and cannot be overwritten`
        );
      }
      return; // Idempotent
    }

    // Clone and freeze object in memory/storage
    const frozen: AnchoredCheckpoint = {
      checkpointId: checkpoint.checkpointId,
      scope: checkpoint.scope,
      commitSeq: checkpoint.commitSeq,
      previousCheckpointId: checkpoint.previousCheckpointId,
      merkleRoot: Buffer.from(checkpoint.merkleRoot),
      changeChainHead: Buffer.from(checkpoint.changeChainHead),
      createdAtUs: checkpoint.createdAtUs,
      protocolVersion: checkpoint.protocolVersion,
      digest: Buffer.from(checkpoint.digest),
    };

    this.wormStorage.set(checkpoint.checkpointId, Object.freeze(frozen));
  }

  public async get(checkpointId: string): Promise<AnchoredCheckpoint | null> {
    const chk = this.wormStorage.get(checkpointId);
    return chk || null;
  }

  public async list(scope: string): Promise<AnchoredCheckpoint[]> {
    const list: AnchoredCheckpoint[] = [];
    for (const chk of this.wormStorage.values()) {
      if (chk.scope === scope) {
        list.push(chk);
      }
    }
    return list.sort((a, b) => Number(a.commitSeq - b.commitSeq));
  }

  public async verify(checkpointId: string): Promise<boolean> {
    const chk = await this.get(checkpointId);
    if (!chk) return false;
    const computed = computeCheckpointDigest(chk);
    return timingSafeEqualHashes(computed, chk.digest);
  }
}
