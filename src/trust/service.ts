import crypto from 'node:crypto';
import { IWolverineTrustService, TrustCommitmentRecord } from './types.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export class WolverineTrustService implements IWolverineTrustService {
  private commitments = new Map<string, TrustCommitmentRecord>();

  public async anchorCheckpoint(
    tenantId: string,
    databaseId: string,
    checkpointId: string,
    checkpointDigest: Buffer,
    commitSeq: bigint
  ): Promise<TrustCommitmentRecord> {
    const commitmentId = `wts-${crypto.randomUUID()}`;
    const anchoredEpochUs = BigInt(Date.now()) * 1000n;

    const record: TrustCommitmentRecord = {
      commitmentId,
      tenantId,
      databaseId,
      checkpointId,
      checkpointDigest,
      commitSeq,
      anchoredEpochUs,
      ledgerProof: `wts-proof:${checkpointId}:${commitSeq}:${checkpointDigest.toString('hex').slice(0, 16)}`,
    };

    this.commitments.set(checkpointId, record);
    return record;
  }

  public async getCommitment(checkpointId: string): Promise<TrustCommitmentRecord | null> {
    return this.commitments.get(checkpointId) || null;
  }

  public async verifyCommitment(checkpointId: string, expectedDigest: Buffer): Promise<boolean> {
    const record = this.commitments.get(checkpointId);
    if (!record) return false;
    return timingSafeEqualHashes(record.checkpointDigest, expectedDigest);
  }
}
