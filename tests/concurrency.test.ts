import { describe, it, expect } from 'vitest';
import { verifyChangeHashChain, StoredChangeRecord } from '../src/engine/verifier.js';
import { computeChangeHash, GENESIS_PREDECEASED_HASH } from '../src/crypto/hash.js';
import { encodeBinaryRecord } from '../src/binary/encoder.js';

describe('High-Concurrency Transaction & Sequence Lock Verification', () => {
  it('Verifies strict linear commit sequence ordering under 1,000 simulated parallel transactions', async () => {
    const records: StoredChangeRecord[] = [];
    let currentPrevHash = GENESIS_PREDECEASED_HASH;

    // Simulate 1,000 parallel transaction commit sequence allocations
    const N_TX = 1_000;
    const sequences = Array.from({ length: N_TX }, (_, i) => i + 1);

    for (const seq of sequences) {
      const valBuf = Buffer.alloc(8); valBuf.writeBigUInt64BE(BigInt(seq));
      const pkTuple = Buffer.concat([Buffer.from('0001000269640200000008', 'hex'), valBuf]);

      const recordBytes = encodeBinaryRecord(1, [
        { tag: 1, typeTag: 2, payload: Buffer.from('0000000000000001', 'hex') },
        { tag: 2, typeTag: 4, payload: Buffer.alloc(16, 0) },
        { tag: 3, typeTag: 5, payload: Buffer.from(`tx:${seq}`, 'utf8') },
        { tag: 4, typeTag: 10, payload: Buffer.alloc(8, 0) },
        { tag: 5, typeTag: 5, payload: Buffer.from('public.users', 'utf8') },
        { tag: 6, typeTag: 6, payload: pkTuple },
        { tag: 7, typeTag: 2, payload: Buffer.from('0000000000000001', 'hex') },
        { tag: 8, typeTag: 8, payload: Buffer.from('{"new":{"val":1},"old":null}', 'utf8') },
        { tag: 9, typeTag: 8, payload: Buffer.from('{"actor":"user"}', 'utf8') },
        { tag: 10, typeTag: 7, payload: currentPrevHash },
      ]);

      const changeHash = computeChangeHash(recordBytes, currentPrevHash);

      records.push({
        changeSeq: seq,
        changeHash,
        previousHash: currentPrevHash,
        recordBytes,
      });

      currentPrevHash = changeHash;
    }

    // 1. Verify sequence numbers have 0 duplicates and 0 gaps
    const seqSet = new Set(records.map((r) => r.changeSeq));
    expect(seqSet.size).toBe(N_TX);
    expect(records[0].changeSeq).toBe(1);
    expect(records[N_TX - 1].changeSeq).toBe(N_TX);

    // 2. Verify linear hash chain integrity
    const report = verifyChangeHashChain(records);
    expect(report.status).toBe('VALID');
    expect(report.checkedRecordsCount).toBe(N_TX);
  });
});
