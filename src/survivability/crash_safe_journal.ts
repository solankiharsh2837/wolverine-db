import crypto from 'node:crypto';
import { ValidatorJournalRecord } from './types.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export function computeJournalRecordDigest(
  record: Omit<ValidatorJournalRecord, 'journalRecordDigest'>
): Buffer {
  const domain = Buffer.from('WDB:VAL_JOURNAL:v1:', 'utf8');
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(record.ledgerSeq);

  const epochBuf = Buffer.alloc(4);
  epochBuf.writeUInt32BE(record.epoch);

  const timeBuf = Buffer.alloc(8);
  timeBuf.writeBigUInt64BE(record.timestampUs);

  return crypto
    .createHash('sha256')
    .update(
      Buffer.concat([
        domain,
        Buffer.from(record.validatorId, 'utf8'),
        epochBuf,
        seqBuf,
        record.commitmentDigest,
        record.previousLedgerDigest,
        record.attestationDigest,
        record.stateRoot,
        record.validatorSetDigest,
        timeBuf,
        record.previousRecordDigest,
      ])
    )
    .digest();
}

export class CrashSafeValidatorJournal {
  public readonly validatorId: string;
  private records: ValidatorJournalRecord[] = [];
  private headDigest: Buffer = Buffer.alloc(32, 0);
  private isCorruptedState: boolean = false;

  constructor(validatorId: string) {
    this.validatorId = validatorId;
  }

  public append(
    epoch: number,
    ledgerSeq: bigint,
    commitmentDigest: Buffer,
    previousLedgerDigest: Buffer,
    attestationDigest: Buffer,
    stateRoot: Buffer,
    validatorSetDigest: Buffer
  ): ValidatorJournalRecord {
    if (this.isCorruptedState) {
      throw new WolverineError(
        WolverineErrorCode.HISTORY_MUTATION_DETECTED,
        `Validator journal ${this.validatorId} is in FAIL_CLOSED_CORRUPTED state`
      );
    }

    // Check duplicate or fork
    const existing = this.records.find((r) => r.ledgerSeq === ledgerSeq);
    if (existing) {
      if (Buffer.compare(existing.commitmentDigest, commitmentDigest) !== 0) {
        throw new WolverineError(
          WolverineErrorCode.HISTORY_MUTATION_DETECTED,
          `Fork detected in validator journal ${this.validatorId} at seq ${ledgerSeq}`
        );
      }
      return existing; // Idempotent
    }

    const previousRecordDigest = this.headDigest;
    const timestampUs = BigInt(Date.now()) * 1000n;

    const base = {
      validatorId: this.validatorId,
      epoch,
      ledgerSeq,
      commitmentDigest,
      previousLedgerDigest,
      attestationDigest,
      stateRoot,
      validatorSetDigest,
      timestampUs,
      previousRecordDigest,
    };

    const journalRecordDigest = computeJournalRecordDigest(base);

    const record: ValidatorJournalRecord = {
      ...base,
      journalRecordDigest,
    };

    this.records.push(record);
    this.headDigest = journalRecordDigest;

    return record;
  }

  public getRecords(): ValidatorJournalRecord[] {
    return [...this.records];
  }

  public getHeadDigest(): Buffer {
    return this.headDigest;
  }

  public recoverFromRaw(rawRecords: ValidatorJournalRecord[]): {
    recoveredCount: number;
    truncatedTail: boolean;
  } {
    this.records = [];
    this.headDigest = Buffer.alloc(32, 0);
    this.isCorruptedState = false;

    let prevDigest = Buffer.alloc(32, 0);
    let truncatedTail = false;

    for (let i = 0; i < rawRecords.length; i++) {
      const rec = rawRecords[i]!;

      // Verify record digest
      const expectedDigest = computeJournalRecordDigest(rec);
      const isDigestValid = timingSafeEqualHashes(rec.journalRecordDigest, expectedDigest);
      const isChainValid = Buffer.compare(rec.previousRecordDigest, prevDigest) === 0;

      if (!isDigestValid || !isChainValid) {
        if (i === rawRecords.length - 1) {
          // Truncated tail on last record (power loss / partial write)
          truncatedTail = true;
          break;
        } else {
          // Corrupted intermediate record
          this.isCorruptedState = true;
          throw new WolverineError(
            WolverineErrorCode.HISTORY_MUTATION_DETECTED,
            `Corrupted journal record at index ${i} in validator ${this.validatorId}`
          );
        }
      }

      this.records.push(rec);
      this.headDigest = Buffer.from(rec.journalRecordDigest);
      prevDigest = Buffer.from(rec.journalRecordDigest);
    }

    return {
      recoveredCount: this.records.length,
      truncatedTail,
    };
  }

  public corruptIntermediateRecord(index: number): void {
    if (this.records[index]) {
      this.records[index]!.commitmentDigest = Buffer.alloc(32, 0xff);
    }
  }
}
