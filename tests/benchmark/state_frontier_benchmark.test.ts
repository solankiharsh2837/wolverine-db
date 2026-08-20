import { describe, it, expect } from 'vitest';
import { DeterministicStateFrontier } from '../../src/evidence/state_frontier.js';
import { ChangeRecordData, MutationOperation } from '../../src/protocol/types.js';

describe('DeterministicStateFrontier Complexity & Scaling Benchmark', () => {
  it('benchmarks full-table re-hashing and sorting complexity across row scales', () => {
    const frontier = new DeterministicStateFrontier();

    const rowCounts = [100, 1000, 5000];
    const timings: Record<number, number> = {};

    for (const count of rowCounts) {
      const changes: ChangeRecordData[] = [];
      for (let i = 0; i < count; i++) {
        changes.push({
          formatVersion: 1,
          versionId: '00000000-0000-0000-0000-000000000001',
          transactionId: `tx_${i}`,
          timestampUs: BigInt(Date.now()) * 1000n,
          tableId: 'public.accounts',
          recordId: Buffer.from(`account_${i}`, 'utf8'),
          operation: MutationOperation.INSERT,
          fieldSet: {
            new: { id: i, balance: 1000 + i, owner: `user_${i}` },
            old: null,
          },
          provenance: {},
          previousHash: Buffer.alloc(32, 0),
        });
      }

      const start = Date.now();
      frontier.applyChangeRecords(changes, `0/${count}`, BigInt(count), Buffer.alloc(32, 0));
      const root = frontier.computeStateMerkleRoot();
      const duration = Date.now() - start;

      timings[count] = duration;
      expect(root).toHaveLength(32);
    }

    console.log('\n--- State Frontier Empirical Benchmark Results ---');
    console.log(`100 rows: ${timings[100]}ms`);
    console.log(`1,000 rows: ${timings[1000]}ms`);
    console.log(`5,000 rows: ${timings[5000]}ms`);
    console.log('--------------------------------------------------\n');

    expect(frontier.getActiveRowCount()).toBe(5000);
  });
});
