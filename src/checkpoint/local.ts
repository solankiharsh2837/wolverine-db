import fs from 'node:fs/promises';
import path from 'node:path';
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

export class LocalCheckpointStore implements CheckpointStore {
  private baseDir: string;

  constructor(baseDir: string) {
    this.baseDir = baseDir;
  }

  public async init(): Promise<void> {
    await fs.mkdir(this.baseDir, { recursive: true });
  }

  private getFilePath(checkpointId: string): string {
    return path.join(this.baseDir, `${checkpointId}.wdbchk`);
  }

  public async put(checkpoint: AnchoredCheckpoint): Promise<void> {
    await this.init();
    const filePath = this.getFilePath(checkpoint.checkpointId);

    try {
      const existingData = await fs.readFile(filePath, 'utf8');
      const existing = parseCheckpointJson(existingData);

      const existingDigest = Buffer.isBuffer(existing.digest) ? existing.digest : Buffer.from((existing.digest as any), 'hex');
      const newDigest = Buffer.isBuffer(checkpoint.digest) ? checkpoint.digest : Buffer.from((checkpoint.digest as any), 'hex');

      if (!timingSafeEqualHashes(existingDigest, newDigest)) {
        throw new WolverineError(
          WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
          `CheckpointConflictError: Checkpoint ${checkpoint.checkpointId} already exists with differing digest`
        );
      }
      return; // Idempotent put
    } catch (err: any) {
      if (err.code !== 'ENOENT' && !(err instanceof WolverineError)) {
        throw err;
      }
      if (err instanceof WolverineError) {
        throw err;
      }
    }

    const serialized = serializeCheckpoint(checkpoint);
    await fs.writeFile(filePath, serialized, { encoding: 'utf8', mode: 0o444 });
  }

  public async get(checkpointId: string): Promise<AnchoredCheckpoint | null> {
    const filePath = this.getFilePath(checkpointId);
    try {
      const data = await fs.readFile(filePath, 'utf8');
      return parseCheckpointJson(data);
    } catch (err: any) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  }

  public async list(scope: string): Promise<AnchoredCheckpoint[]> {
    await this.init();
    const files = await fs.readdir(this.baseDir);
    const results: AnchoredCheckpoint[] = [];

    for (const file of files) {
      if (file.endsWith('.wdbchk')) {
        const id = file.replace('.wdbchk', '');
        const chk = await this.get(id);
        if (chk && chk.scope === scope) {
          results.push(chk);
        }
      }
    }

    return results.sort((a, b) => Number(a.commitSeq - b.commitSeq));
  }

  public async verify(checkpointId: string): Promise<boolean> {
    const chk = await this.get(checkpointId);
    if (!chk) return false;
    const computedDigest = computeCheckpointDigest(chk);
    const storedDigest = Buffer.isBuffer(chk.digest) ? chk.digest : Buffer.from((chk.digest as any), 'hex');
    return timingSafeEqualHashes(computedDigest, storedDigest);
  }
}
