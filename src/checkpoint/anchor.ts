import crypto from 'node:crypto';
import { AnchoredCheckpoint, CheckpointStore } from './types.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

function toBuffer(val: any): Buffer {
  if (Buffer.isBuffer(val)) return val;
  if (typeof val === 'string') return Buffer.from(val, 'hex');
  if (val && typeof val === 'object' && Array.isArray(val.data)) return Buffer.from(val.data);
  return Buffer.from(val);
}

export function computeCheckpointDigest(checkpoint: Omit<AnchoredCheckpoint, 'digest'>): Buffer {
  const domain = Buffer.from('WDB:CHECKPOINT:v1:', 'utf8');

  const checkpointIdBytes = Buffer.alloc(16);
  Buffer.from(checkpoint.checkpointId.replace(/-/g, ''), 'hex').copy(checkpointIdBytes, 0);

  const scopeBuf = Buffer.from(checkpoint.scope, 'utf8');
  const scopeLenBuf = Buffer.alloc(4);
  scopeLenBuf.writeUInt32BE(scopeBuf.length, 0);

  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigInt64BE(BigInt(checkpoint.commitSeq), 0);

  const prevCheckpointBytes = Buffer.alloc(16, 0);
  if (checkpoint.previousCheckpointId) {
    Buffer.from(checkpoint.previousCheckpointId.replace(/-/g, ''), 'hex').copy(prevCheckpointBytes, 0);
  }

  const timeBuf = Buffer.alloc(8);
  timeBuf.writeBigInt64BE(BigInt(checkpoint.createdAtUs), 0);

  const verBuf = Buffer.alloc(4);
  verBuf.writeInt32BE(Number(checkpoint.protocolVersion), 0);

  const merkleRootBuf = toBuffer(checkpoint.merkleRoot);
  const changeChainHeadBuf = toBuffer(checkpoint.changeChainHead);

  const preimage = Buffer.concat([
    domain,
    checkpointIdBytes,
    scopeLenBuf,
    scopeBuf,
    seqBuf,
    prevCheckpointBytes,
    merkleRootBuf,
    changeChainHeadBuf,
    timeBuf,
    verBuf,
  ]);

  return crypto.createHash('sha256').update(preimage).digest();
}

export interface SplitBrainVerificationResult {
  status: 'VALID' | 'STATE_DIVERGENCE_DETECTED' | 'CHECKPOINT_TAMPERED' | 'STORE_UNAVAILABLE';
  localRoot: string;
  expectedRoot: string;
  externalAnchorValid: boolean;
  checkpointId: string;
  errorMessage?: string;
}

export class CheckpointAnchorEngine {
  /**
   * Anchors a state checkpoint to an external immutable CheckpointStore
   */
  public static async anchorCheckpoint(
    store: CheckpointStore,
    params: Omit<AnchoredCheckpoint, 'digest'>
  ): Promise<AnchoredCheckpoint> {
    const digest = computeCheckpointDigest(params);
    const anchored: AnchoredCheckpoint = {
      ...params,
      digest,
    };

    await store.put(anchored);
    return anchored;
  }

  /**
   * Verifies local PostgreSQL state against external store anchor to detect split-brain
   */
  public static async verifyAgainstExternalAnchor(
    store: CheckpointStore,
    checkpointId: string,
    observedLocalMerkleRoot: Buffer
  ): Promise<SplitBrainVerificationResult> {
    let externalCheckpoint: AnchoredCheckpoint | null = null;
    try {
      externalCheckpoint = await store.get(checkpointId);
    } catch (err: any) {
      return {
        status: 'STORE_UNAVAILABLE',
        localRoot: observedLocalMerkleRoot.toString('hex'),
        expectedRoot: 'unknown',
        externalAnchorValid: false,
        checkpointId,
        errorMessage: `External store error: ${err.message}`,
      };
    }

    if (!externalCheckpoint) {
      return {
        status: 'CHECKPOINT_TAMPERED',
        localRoot: observedLocalMerkleRoot.toString('hex'),
        expectedRoot: 'missing',
        externalAnchorValid: false,
        checkpointId,
        errorMessage: `Checkpoint ${checkpointId} not found in external store`,
      };
    }

    // Verify external anchor digest
    const recomputedDigest = computeCheckpointDigest(externalCheckpoint);
    const externalDigest = toBuffer(externalCheckpoint.digest);
    if (!timingSafeEqualHashes(recomputedDigest, externalDigest)) {
      return {
        status: 'CHECKPOINT_TAMPERED',
        localRoot: observedLocalMerkleRoot.toString('hex'),
        expectedRoot: toBuffer(externalCheckpoint.merkleRoot).toString('hex'),
        externalAnchorValid: false,
        checkpointId,
        errorMessage: 'External checkpoint digest is tampered or corrupted',
      };
    }

    // Compare observed live root against external anchor root
    const expectedRootBuf = toBuffer(externalCheckpoint.merkleRoot);
    if (!timingSafeEqualHashes(observedLocalMerkleRoot, expectedRootBuf)) {
      return {
        status: 'STATE_DIVERGENCE_DETECTED',
        localRoot: observedLocalMerkleRoot.toString('hex'),
        expectedRoot: expectedRootBuf.toString('hex'),
        externalAnchorValid: true,
        checkpointId,
        errorMessage: 'PostgreSQL state has diverged from independently retained external checkpoint',
      };
    }

    return {
      status: 'VALID',
      localRoot: observedLocalMerkleRoot.toString('hex'),
      expectedRoot: expectedRootBuf.toString('hex'),
      externalAnchorValid: true,
      checkpointId,
    };
  }
}
