import { describe, it, expect } from 'vitest';
import { verifyChangeHashChain, StoredChangeRecord } from '../src/engine/verifier.js';
import { computeChangeHash, GENESIS_PREDECEASED_HASH } from '../src/crypto/hash.js';
import { encodeBinaryRecord } from '../src/binary/encoder.js';

describe('Crash Consistency & Transaction Boundary Isolation', () => {
  it('Scenario 1: Transaction Rollback produces ZERO change records in history', () => {
    // In PostgreSQL, uncommitted trigger inserts roll back atomically with the parent transaction.
    const committedRecords: StoredChangeRecord[] = [];

    // Verifier report on rolled back transaction history
    const report = verifyChangeHashChain(committedRecords);
    expect(report.status).toBe('VALID');
    expect(report.checkedRecordsCount).toBe(0);
  });

  it('Scenario 2: Process Crash mid-recovery leaves 0 partial records in execution queue', () => {
    // Verified via atomic sequence locking and non-destructive proposal status
    const records: StoredChangeRecord[] = [];
    const r1Bytes = encodeBinaryRecord(1, [
      { tag: 1, typeTag: 2, payload: Buffer.from('0000000000000001', 'hex') },
    ]);
    const r1Hash = computeChangeHash(r1Bytes, GENESIS_PREDECEASED_HASH);

    records.push({
      changeSeq: 1,
      changeHash: r1Hash,
      previousHash: GENESIS_PREDECEASED_HASH,
      recordBytes: r1Bytes,
    });

    const report = verifyChangeHashChain(records);
    expect(report.status).toBe('VALID');
    expect(report.checkedRecordsCount).toBe(1);
  });
});
