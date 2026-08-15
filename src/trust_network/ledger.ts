import crypto from 'node:crypto';
import { TrustLedgerRecord, TrustLedgerRecordType } from './types.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export function computeLedgerRecordDigest(
  previousRecordDigest: Buffer,
  ledgerSeq: bigint,
  payload: Record<string, unknown>
): Buffer {
  const domain = Buffer.from('WDB:LEDGER_REC:v1:', 'utf8');
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(ledgerSeq);

  const canonicalPayload = canonicalizeJson(payload);

  return crypto
    .createHash('sha256')
    .update(Buffer.concat([domain, previousRecordDigest, seqBuf, Buffer.from(canonicalPayload, 'utf8')]))
    .digest();
}

export class WolverineTrustLedger {
  private records: TrustLedgerRecord[] = [];
  private headDigest: Buffer = Buffer.alloc(32, 0);
  private currentSeq: bigint = 0n;

  // Track finalized commitment sequences per (tenantId, databaseId) -> { commitSeq, commitmentDigest }
  private finalizedCommitments = new Map<string, { commitSeq: bigint; commitmentDigest: Buffer }>();

  public appendRecord(
    recordType: TrustLedgerRecordType,
    payload: Record<string, unknown>,
    epoch: number = 1,
    validatorSetId: string = 'valset-genesis',
    tenantId?: string,
    databaseId?: string
  ): TrustLedgerRecord {
    const nextSeq = this.currentSeq + 1n;
    const timestampUs = BigInt(Date.now()) * 1000n;

    // Check for equivocation on finalization
    if (recordType === 'FINALIZATION' && tenantId && databaseId && payload['commitSeq'] && payload['commitmentDigestHex']) {
      const commitSeq = BigInt(payload['commitSeq'] as string);
      const commitmentDigestHex = payload['commitmentDigestHex'] as string;
      const key = `${tenantId}:${databaseId}:${commitSeq}`;
      const existing = this.finalizedCommitments.get(key);

      if (existing) {
        if (existing.commitmentDigest.toString('hex') !== commitmentDigestHex) {
          throw new WolverineError(
            WolverineErrorCode.HISTORY_MUTATION_DETECTED,
            `TRUST_EQUIVOCATION: Attempted conflicting finalization for tenant ${tenantId}, db ${databaseId} at seq ${commitSeq}`
          );
        }
      }
    }

    const recordDigest = computeLedgerRecordDigest(this.headDigest, nextSeq, payload);

    const record: TrustLedgerRecord = {
      recordType,
      ledgerSeq: nextSeq,
      epoch,
      validatorSetId,
      tenantId,
      databaseId,
      payload,
      previousRecordDigest: this.headDigest,
      recordDigest,
      timestampUs,
    };

    this.records.push(record);
    this.headDigest = Buffer.from(recordDigest);
    this.currentSeq = nextSeq;

    if (recordType === 'FINALIZATION' && tenantId && databaseId && payload['commitSeq'] && payload['commitmentDigestHex']) {
      const commitSeq = BigInt(payload['commitSeq'] as string);
      const commitmentDigest = Buffer.from(payload['commitmentDigestHex'] as string, 'hex');
      this.finalizedCommitments.set(`${tenantId}:${databaseId}:${commitSeq}`, { commitSeq, commitmentDigest });
    }

    return record;
  }

  public getRecords(): readonly TrustLedgerRecord[] {
    return this.records;
  }

  public getHeadDigest(): Buffer {
    return this.headDigest;
  }

  public getCurrentSequence(): bigint {
    return this.currentSeq;
  }

  public verifyLedgerIntegrity(): boolean {
    let prevDigest: Buffer = Buffer.alloc(32, 0);
    let expectedSeq = 1n;

    for (const record of this.records) {
      if (record.ledgerSeq !== expectedSeq) {
        return false;
      }
      if (!timingSafeEqualHashes(record.previousRecordDigest, prevDigest)) {
        return false;
      }
      const expectedDigest = computeLedgerRecordDigest(prevDigest, record.ledgerSeq, record.payload);
      if (!timingSafeEqualHashes(record.recordDigest, expectedDigest)) {
        return false;
      }

      prevDigest = Buffer.from(record.recordDigest);
      expectedSeq += 1n;
    }

    return true;
  }
}
