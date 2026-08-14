import { describe, it, expect } from 'vitest';
import {
  verifyChangeHashChain,
  verifyVersionChain,
  verifyMerkleCheckpoint,
  StoredChangeRecord,
} from '../src/engine/verifier.js';
import { computeChangeHash, GENESIS_PREDECEASED_HASH } from '../src/crypto/hash.js';
import { encodeBinaryRecord } from '../src/binary/encoder.js';

describe('Verifier Engine (docs/09-INTEGRITY-VERIFICATION)', () => {
  it('verifies valid change hash chain', () => {
    const r1Bytes = encodeBinaryRecord(1, [
      { tag: 1, typeTag: 2, payload: Buffer.from('0000000000000001', 'hex') },
    ]);
    const r1Hash = computeChangeHash(r1Bytes, GENESIS_PREDECEASED_HASH);

    const r2Bytes = encodeBinaryRecord(1, [
      { tag: 1, typeTag: 2, payload: Buffer.from('0000000000000001', 'hex') },
    ]);
    const r2Hash = computeChangeHash(r2Bytes, r1Hash);

    const records: StoredChangeRecord[] = [
      {
        changeSeq: 1,
        changeHash: r1Hash,
        previousHash: GENESIS_PREDECEASED_HASH,
        recordBytes: r1Bytes,
      },
      {
        changeSeq: 2,
        changeHash: r2Hash,
        previousHash: r1Hash,
        recordBytes: r2Bytes,
      },
    ];

    const report = verifyChangeHashChain(records);
    expect(report.status).toBe('VALID');
    expect(report.checkedRecordsCount).toBe(2);
  });

  it('detects change hash mismatch if payload is tampered', () => {
    const r1Bytes = encodeBinaryRecord(1, [
      { tag: 1, typeTag: 2, payload: Buffer.from('0000000000000001', 'hex') },
    ]);
    const r1Hash = computeChangeHash(r1Bytes, GENESIS_PREDECEASED_HASH);

    const tamperedBytes = encodeBinaryRecord(1, [
      { tag: 1, typeTag: 2, payload: Buffer.from('0000000000000002', 'hex') }, // Tampered
    ]);

    const records: StoredChangeRecord[] = [
      {
        changeSeq: 1,
        changeHash: r1Hash,
        previousHash: GENESIS_PREDECEASED_HASH,
        recordBytes: tamperedBytes,
      },
    ];

    const report = verifyChangeHashChain(records);
    expect(report.status).toBe('CHANGE_HASH_MISMATCH');
    expect(report.firstFailureSeq).toBe(1);
  });

  it('detects broken predecessor link if previous_hash is modified', () => {
    const r1Bytes = encodeBinaryRecord(1, [
      { tag: 1, typeTag: 2, payload: Buffer.from('0000000000000001', 'hex') },
    ]);
    const r1Hash = computeChangeHash(r1Bytes, GENESIS_PREDECEASED_HASH);

    const records: StoredChangeRecord[] = [
      {
        changeSeq: 1,
        changeHash: r1Hash,
        previousHash: Buffer.alloc(32, 0xff), // Broken link
        recordBytes: r1Bytes,
      },
    ];

    const report = verifyChangeHashChain(records);
    expect(report.status).toBe('CHANGE_HASH_MISMATCH');
  });
});
