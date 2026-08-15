import { AnchoredCheckpoint, CheckpointStore } from './types.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { computeCheckpointDigest } from './anchor.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

function parseCheckpointJson(jsonStr: string): AnchoredCheckpoint {
  return JSON.parse(jsonStr, (k, v) => {
    if (['merkleRoot', 'changeChainHead', 'digest'].includes(k)) {
      if (typeof v === 'string') return Buffer.from(v, 'hex');
      if (v && typeof v === 'object' && Array.isArray(v.data)) return Buffer.from(v.data);
    }
    if (['commitSeq', 'createdAtUs'].includes(k) && typeof v === 'string') {
      return BigInt(v);
    }
    return v;
  });
}

function serializeCheckpoint(chk: AnchoredCheckpoint): string {
  const obj = {
    checkpointId: chk.checkpointId,
    scope: chk.scope,
    commitSeq: chk.commitSeq.toString(),
    previousCheckpointId: chk.previousCheckpointId,
    merkleRoot: Buffer.isBuffer(chk.merkleRoot) ? chk.merkleRoot.toString('hex') : chk.merkleRoot,
    changeChainHead: Buffer.isBuffer(chk.changeChainHead) ? chk.changeChainHead.toString('hex') : chk.changeChainHead,
    createdAtUs: chk.createdAtUs.toString(),
    protocolVersion: chk.protocolVersion,
    digest: Buffer.isBuffer(chk.digest) ? chk.digest.toString('hex') : chk.digest,
  };
  return JSON.stringify(obj, null, 2);
}

export interface S3StoreConfig {
  bucket: string;
  prefix?: string;
  objectLockEnabled?: boolean;
  mockClient?: boolean;
}

export class S3CheckpointStore implements CheckpointStore {
  private config: S3StoreConfig;
  private inMemoryObjects = new Map<string, { body: string; metadata: Record<string, string> }>();

  constructor(config: S3StoreConfig) {
    this.config = config;
  }

  private getKey(scope: string, checkpointId: string): string {
    const prefix = this.config.prefix ? `${this.config.prefix}/` : '';
    return `${prefix}${scope}/checkpoints/${checkpointId}.wdbchk`;
  }

  public async put(checkpoint: AnchoredCheckpoint): Promise<void> {
    const key = this.getKey(checkpoint.scope, checkpoint.checkpointId);

    // If object lock is enabled or object already exists, check immutability
    if (this.inMemoryObjects.has(key)) {
      const existingObj = this.inMemoryObjects.get(key)!;
      const existingDigest = existingObj.metadata['x-amz-meta-wdb-digest'];
      const newDigestHex = Buffer.isBuffer(checkpoint.digest)
        ? checkpoint.digest.toString('hex')
        : checkpoint.digest;

      if (existingDigest !== newDigestHex) {
        throw new WolverineError(
          WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
          `S3ObjectLockViolation: Checkpoint ${checkpoint.checkpointId} cannot be overwritten or altered`
        );
      }
      return; // Idempotent put
    }

    const serialized = serializeCheckpoint(checkpoint);
    const digestHex = Buffer.isBuffer(checkpoint.digest)
      ? checkpoint.digest.toString('hex')
      : checkpoint.digest;

    this.inMemoryObjects.set(key, {
      body: serialized,
      metadata: {
        'x-amz-meta-wdb-digest': digestHex,
        'x-amz-meta-wdb-version': String(checkpoint.protocolVersion),
        'x-amz-object-lock-mode': this.config.objectLockEnabled ? 'COMPLIANCE' : 'NONE',
      },
    });
  }

  public async get(checkpointId: string): Promise<AnchoredCheckpoint | null> {
    for (const [key, obj] of this.inMemoryObjects.entries()) {
      if (key.endsWith(`/${checkpointId}.wdbchk`) || key === `${checkpointId}.wdbchk`) {
        return parseCheckpointJson(obj.body);
      }
    }
    return null;
  }

  public async list(scope: string): Promise<AnchoredCheckpoint[]> {
    const results: AnchoredCheckpoint[] = [];
    for (const [key, obj] of this.inMemoryObjects.entries()) {
      if (key.includes(`/${scope}/checkpoints/`)) {
        results.push(parseCheckpointJson(obj.body));
      }
    }
    return results.sort((a, b) => Number(a.commitSeq - b.commitSeq));
  }

  public async verify(checkpointId: string): Promise<boolean> {
    const chk = await this.get(checkpointId);
    if (!chk) return false;
    const computed = computeCheckpointDigest(chk);
    const storedDigest = Buffer.isBuffer(chk.digest) ? chk.digest : Buffer.from((chk.digest as any), 'hex');
    return timingSafeEqualHashes(computed, storedDigest);
  }
}
