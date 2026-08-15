import { timingSafeEqualHashes } from '../crypto/hash.js';
import { NormalizedWalChange } from '../wal/normalizer.js';
import { canonicalizeJson } from '../binary/c14n.js';

export interface EquivalenceComparisonResult {
  passed: boolean;
  totalTransactionsCompared: number;
  totalChangesCompared: number;
  failureReason?: string;
  mismatchDetails?: {
    index: number;
    property: 'sequence' | 'operation' | 'table' | 'record_id' | 'payload' | 'prev_hash' | 'change_hash';
    triggerValue: string;
    walValue: string;
  };
}

export class CaptureEquivalenceEngine {
  /**
   * Compares two streams of change records (Trigger-captured vs WAL-captured)
   * asserting strict, bit-for-bit equivalence.
   */
  public static compareChangeStreams(
    triggerChanges: NormalizedWalChange[],
    walChanges: NormalizedWalChange[]
  ): EquivalenceComparisonResult {
    if (triggerChanges.length !== walChanges.length) {
      return {
        passed: false,
        totalTransactionsCompared: 0,
        totalChangesCompared: Math.min(triggerChanges.length, walChanges.length),
        failureReason: `Stream length mismatch: Trigger emitted ${triggerChanges.length} changes, WAL emitted ${walChanges.length} changes`,
        mismatchDetails: {
          index: Math.min(triggerChanges.length, walChanges.length),
          property: 'sequence',
          triggerValue: `length=${triggerChanges.length}`,
          walValue: `length=${walChanges.length}`,
        },
      };
    }

    for (let i = 0; i < triggerChanges.length; i++) {
      const tc = triggerChanges[i];
      const wc = walChanges[i];

      // 1. Operation check
      if (tc.changeRecordData.operation !== wc.changeRecordData.operation) {
        return {
          passed: false,
          totalTransactionsCompared: 0,
          totalChangesCompared: i,
          failureReason: `Operation mismatch at change index ${i}`,
          mismatchDetails: {
            index: i,
            property: 'operation',
            triggerValue: String(tc.changeRecordData.operation),
            walValue: String(wc.changeRecordData.operation),
          },
        };
      }

      // 2. Table identifier check
      if (tc.changeRecordData.tableId !== wc.changeRecordData.tableId) {
        return {
          passed: false,
          totalTransactionsCompared: 0,
          totalChangesCompared: i,
          failureReason: `Table ID mismatch at change index ${i}`,
          mismatchDetails: {
            index: i,
            property: 'table',
            triggerValue: tc.changeRecordData.tableId,
            walValue: wc.changeRecordData.tableId,
          },
        };
      }

      // 3. Primary Key Tuple binary check
      if (Buffer.compare(tc.changeRecordData.recordId, wc.changeRecordData.recordId) !== 0) {
        return {
          passed: false,
          totalTransactionsCompared: 0,
          totalChangesCompared: i,
          failureReason: `Primary Key tuple binary mismatch at change index ${i}`,
          mismatchDetails: {
            index: i,
            property: 'record_id',
            triggerValue: tc.changeRecordData.recordId.toString('hex'),
            walValue: wc.changeRecordData.recordId.toString('hex'),
          },
        };
      }

      // 4. Canonical payload JSON check (RFC 8785)
      const triggerFieldSetJson = canonicalizeJson(tc.changeRecordData.fieldSet);
      const walFieldSetJson = canonicalizeJson(wc.changeRecordData.fieldSet);

      if (triggerFieldSetJson !== walFieldSetJson) {
        return {
          passed: false,
          totalTransactionsCompared: 0,
          totalChangesCompared: i,
          failureReason: `Canonical payload JSON mismatch at change index ${i}`,
          mismatchDetails: {
            index: i,
            property: 'payload',
            triggerValue: triggerFieldSetJson,
            walValue: walFieldSetJson,
          },
        };
      }

      // 5. Predecessor Hash check
      if (!timingSafeEqualHashes(tc.changeRecordData.previousHash, wc.changeRecordData.previousHash)) {
        return {
          passed: false,
          totalTransactionsCompared: 0,
          totalChangesCompared: i,
          failureReason: `Predecessor hash mismatch at change index ${i}`,
          mismatchDetails: {
            index: i,
            property: 'prev_hash',
            triggerValue: tc.changeRecordData.previousHash.toString('hex'),
            walValue: wc.changeRecordData.previousHash.toString('hex'),
          },
        };
      }

      // 6. Change Hash check
      if (!timingSafeEqualHashes(tc.changeHash, wc.changeHash)) {
        return {
          passed: false,
          totalTransactionsCompared: 0,
          totalChangesCompared: i,
          failureReason: `Change hash mismatch at change index ${i}`,
          mismatchDetails: {
            index: i,
            property: 'change_hash',
            triggerValue: tc.changeHash.toString('hex'),
            walValue: wc.changeHash.toString('hex'),
          },
        };
      }
    }

    return {
      passed: true,
      totalTransactionsCompared: triggerChanges.length,
      totalChangesCompared: triggerChanges.length,
    };
  }
}
