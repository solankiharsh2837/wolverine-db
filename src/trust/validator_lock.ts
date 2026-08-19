import { EquivocationEvidence, createEquivocationEvidence } from './equivocation.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface SequenceLockRecord {
  tenantId: string;
  databaseId: string;
  epoch: number;
  commitSeq: bigint;
  commitmentDigestHex: string;
  lockedAtUs: bigint;
  validatorSignatureHex?: string;
}

export interface LockAcquisitionResult {
  acquired: boolean;
  isIdempotent: boolean;
  existingLock?: SequenceLockRecord;
  equivocation?: EquivocationEvidence;
}

export class ValidatorLockTable {
  private validatorId: string;
  private locks = new Map<string, SequenceLockRecord>();
  private slashingLog: EquivocationEvidence[] = [];

  constructor(validatorId: string) {
    this.validatorId = validatorId;
  }

  private makeKey(tenantId: string, databaseId: string, epoch: number, commitSeq: bigint): string {
    return `${tenantId}:${databaseId}:${epoch}:${commitSeq}`;
  }

  /**
   * Evaluates or acquires the non-equivocation sequence lock.
   */
  public checkOrAcquireLock(
    tenantId: string,
    databaseId: string,
    epoch: number,
    commitSeq: bigint,
    commitmentDigestHex: string
  ): LockAcquisitionResult {
    const key = this.makeKey(tenantId, databaseId, epoch, commitSeq);
    const existing = this.locks.get(key);

    if (!existing) {
      const lockRecord: SequenceLockRecord = {
        tenantId,
        databaseId,
        epoch,
        commitSeq,
        commitmentDigestHex,
        lockedAtUs: BigInt(Date.now()) * 1000n,
      };
      this.locks.set(key, lockRecord);
      return { acquired: true, isIdempotent: false };
    }

    // Existing lock found
    if (existing.commitmentDigestHex === commitmentDigestHex) {
      // Idempotent duplicate submission
      return { acquired: false, isIdempotent: true, existingLock: existing };
    }

    // EQUIVOCATION DETECTED: Same key, differing digest
    const equivocation = createEquivocationEvidence(
      this.validatorId,
      tenantId,
      databaseId,
      epoch,
      commitSeq,
      existing.commitmentDigestHex,
      commitmentDigestHex
    );

    this.slashingLog.push(equivocation);

    throw new WolverineError(
      WolverineErrorCode.HISTORY_MUTATION_DETECTED,
      `EQUIVOCATION_DETECTED: Sequence ${commitSeq} in epoch ${epoch} already locked with digest ${existing.commitmentDigestHex}, conflicting digest ${commitmentDigestHex} presented`
    );
  }

  public attachSignature(
    tenantId: string,
    databaseId: string,
    epoch: number,
    commitSeq: bigint,
    signatureHex: string
  ): void {
    const key = this.makeKey(tenantId, databaseId, epoch, commitSeq);
    const existing = this.locks.get(key);
    if (existing) {
      existing.validatorSignatureHex = signatureHex;
    }
  }

  public getLock(tenantId: string, databaseId: string, epoch: number, commitSeq: bigint): SequenceLockRecord | undefined {
    const key = this.makeKey(tenantId, databaseId, epoch, commitSeq);
    return this.locks.get(key);
  }

  public getSlashingEvidence(): EquivocationEvidence[] {
    return [...this.slashingLog];
  }

  public restoreLockFromJournal(record: SequenceLockRecord): void {
    const key = this.makeKey(record.tenantId, record.databaseId, record.epoch, record.commitSeq);
    this.locks.set(key, { ...record });
  }

  public clear(): void {
    this.locks.clear();
    this.slashingLog = [];
  }
}
