import { describe, it, expect } from 'vitest';
import {
  PersistentTrustLedger,
  MemoryJournalStorage,
} from '../../src/index.js';

describe('Persistent Trust Ledger & Incremental Merkle State Root (WDB-0102)', () => {
  it('persistence & state root: survives node crash/restart and recomputes exact 32-byte Merkle State Root', async () => {
    const sharedStorage = new MemoryJournalStorage();

    // 1. Initial Node writes 5 sequence records
    const node1 = new PersistentTrustLedger(sharedStorage);
    for (let i = 1; i <= 5; i++) {
      await node1.appendRecord(
        'FINALIZATION',
        {
          commitmentId: `cmt-${i}`,
          commitSeq: i.toString(),
          checkpointDigestHex: Buffer.alloc(32, i).toString('hex'),
        },
        1,
        'valset-prod-v1',
        'tenant-01',
        'orders-db'
      );
    }

    const snapshot1 = node1.getStateRootSnapshot();
    expect(snapshot1.recordCount).toBe(5);
    expect(snapshot1.merkleStateRoot.length).toBe(32);
    expect(node1.verifyLedgerIntegrity()).toBe(true);

    // 2. SIMULATE TOTAL NODE CRASH & RESTART ON NEW PROCESS
    const recoveredNode = new PersistentTrustLedger(sharedStorage);
    await recoveredNode.init();

    const snapshot2 = recoveredNode.getStateRootSnapshot();
    expect(snapshot2.recordCount).toBe(5);
    expect(snapshot2.ledgerSeq).toBe(5n);
    expect(Buffer.compare(snapshot2.merkleStateRoot, snapshot1.merkleStateRoot)).toBe(0);
    expect(Buffer.compare(snapshot2.chainHeadDigest, snapshot1.chainHeadDigest)).toBe(0);
    expect(recoveredNode.verifyLedgerIntegrity()).toBe(true);
  });
});
