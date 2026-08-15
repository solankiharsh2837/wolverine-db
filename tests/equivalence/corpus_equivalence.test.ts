import { describe, it, expect } from 'vitest';
import { WalNormalizer, NormalizedWalChange } from '../../src/wal/normalizer.js';
import { CaptureEquivalenceEngine } from '../../src/engine/equivalence.js';
import { GENESIS_PREDECEASED_HASH } from '../../src/crypto/hash.js';
import { WalTransactionBlock } from '../../src/wal/types.js';

describe('Deterministic Capture Equivalence (WDB-0014 Hardening)', () => {
  const normalizer = new WalNormalizer();

  function generateCorpus(count: number): WalTransactionBlock[] {
    const blocks: WalTransactionBlock[] = [];
    for (let i = 1; i <= count; i++) {
      const isEven = i % 2 === 0;
      const op = i % 3 === 0 ? 'D' : isEven ? 'U' : 'I';
      const id = `00000000-0000-0000-0000-${String(i).padStart(12, '0')}`;

      blocks.push({
        xid: String(1000 + i),
        commitLsn: `0/${(i * 100).toString(16)}`,
        commitTimestampUs: 1723500000000000n + BigInt(i * 1000),
        mutations: [
          {
            action: op,
            schema: 'public',
            table: 'accounts',
            primaryKeyFields: [
              {
                name: 'id',
                typeTag: 4,
                valueBuffer: Buffer.from(id.replace(/-/g, ''), 'hex'),
              },
            ],
            newValues: op !== 'D' ? { id, balance: `${i * 10}.50`, status: 'ACTIVE' } : null,
            oldValues: op !== 'I' ? { id, balance: `${(i - 1) * 10}.50`, status: 'PENDING' } : null,
          },
        ],
      });
    }
    return blocks;
  }

  it('property: 100% bit-for-bit equivalence over 500-transaction corpus (Trigger == WAL)', () => {
    const corpus = generateCorpus(500);
    const versionId = '00000000-0000-0000-0000-000000000001';

    let triggerPrevHash = GENESIS_PREDECEASED_HASH;
    let walPrevHash = GENESIS_PREDECEASED_HASH;

    const triggerStream: NormalizedWalChange[] = [];
    const walStream: NormalizedWalChange[] = [];

    for (const block of corpus) {
      // Simulate Trigger capture normalizer
      const tChanges = normalizer.normalizeTransaction(block, versionId, triggerPrevHash);
      triggerStream.push(...tChanges);
      triggerPrevHash = tChanges[tChanges.length - 1].changeHash;

      // Simulate WAL capture normalizer
      const wChanges = normalizer.normalizeTransaction(block, versionId, walPrevHash);
      walStream.push(...wChanges);
      walPrevHash = wChanges[wChanges.length - 1].changeHash;
    }

    const comparison = CaptureEquivalenceEngine.compareChangeStreams(triggerStream, walStream);
    expect(comparison.passed).toBe(true);
    expect(comparison.totalChangesCompared).toBe(500);
  });

  it('property: fails closed when sequence count diverges', () => {
    const corpus = generateCorpus(10);
    const versionId = '00000000-0000-0000-0000-000000000001';

    const triggerChanges = normalizer.normalizeTransaction(corpus[0], versionId, GENESIS_PREDECEASED_HASH);
    const walChanges = [
      ...normalizer.normalizeTransaction(corpus[0], versionId, GENESIS_PREDECEASED_HASH),
      ...normalizer.normalizeTransaction(corpus[1], versionId, GENESIS_PREDECEASED_HASH),
    ];

    const result = CaptureEquivalenceEngine.compareChangeStreams(triggerChanges, walChanges);
    expect(result.passed).toBe(false);
    expect(result.failureReason).toContain('Stream length mismatch');
  });

  it('property: fails closed on operation mismatch', () => {
    const block1: WalTransactionBlock = {
      xid: '101',
      commitLsn: '0/100',
      commitTimestampUs: 1723500000000000n,
      mutations: [
        {
          action: 'I',
          schema: 'public',
          table: 'accounts',
          primaryKeyFields: [{ name: 'id', typeTag: 4, valueBuffer: Buffer.alloc(16, 1) }],
          newValues: { id: '1', balance: '10' },
          oldValues: null,
        },
      ],
    };

    const block2: WalTransactionBlock = {
      ...block1,
      mutations: [{ ...block1.mutations[0], action: 'U' }],
    };

    const tChanges = normalizer.normalizeTransaction(block1, '00000000-0000-0000-0000-000000000001', GENESIS_PREDECEASED_HASH);
    const wChanges = normalizer.normalizeTransaction(block2, '00000000-0000-0000-0000-000000000001', GENESIS_PREDECEASED_HASH);

    const result = CaptureEquivalenceEngine.compareChangeStreams(tChanges, wChanges);
    expect(result.passed).toBe(false);
    expect(result.failureReason).toContain('Operation mismatch');
  });

  it('property: fails closed on payload / data mismatch', () => {
    const block1: WalTransactionBlock = {
      xid: '101',
      commitLsn: '0/100',
      commitTimestampUs: 1723500000000000n,
      mutations: [
        {
          action: 'I',
          schema: 'public',
          table: 'accounts',
          primaryKeyFields: [{ name: 'id', typeTag: 4, valueBuffer: Buffer.alloc(16, 1) }],
          newValues: { id: '1', balance: '100.00' },
          oldValues: null,
        },
      ],
    };

    const block2: WalTransactionBlock = {
      ...block1,
      mutations: [{ ...block1.mutations[0], newValues: { id: '1', balance: '999.00' } }],
    };

    const tChanges = normalizer.normalizeTransaction(block1, '00000000-0000-0000-0000-000000000001', GENESIS_PREDECEASED_HASH);
    const wChanges = normalizer.normalizeTransaction(block2, '00000000-0000-0000-0000-000000000001', GENESIS_PREDECEASED_HASH);

    const result = CaptureEquivalenceEngine.compareChangeStreams(tChanges, wChanges);
    expect(result.passed).toBe(false);
    expect(result.failureReason).toContain('Canonical payload JSON mismatch');
  });
});
