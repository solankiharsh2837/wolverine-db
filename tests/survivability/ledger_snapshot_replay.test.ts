import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  PersistentTrustLedger,
  TrustLedgerRecoveryEngine,
  computeSnapshotDigest,
  LedgerSnapshot,
} from '../../src/index.js';

describe('Ledger Snapshot and Replay Recovery (WDB-0122)', () => {
  it('reconstructs state root from baseline snapshot + journal suffix and detects broken sequences', async () => {
    // 1. Build an authentic 10-record ledger
    const masterLedger = new PersistentTrustLedger();
    for (let i = 1; i <= 10; i++) {
      await masterLedger.appendRecord(
        'FINALIZATION',
        { commitSeq: i.toString(), digestHex: Buffer.alloc(32, i).toString('hex') },
        1,
        'valset-prod-v1',
        'tenant-01',
        'orders-db'
      );
    }

    const allRecords = masterLedger.getRecords();
    const expectedStateRoot = masterLedger.getMerkleStateRoot();

    // 2. Create baseline snapshot at sequence 5
    const snapshotRecords = allRecords.slice(0, 5);
    const snapshotBase = {
      snapshotId: 'snap-0005',
      epoch: 1,
      snapshotLedgerSeq: 5n,
      stateRoot: masterLedger.getMerkleStateRoot(),
      chainHeadDigest: snapshotRecords[4]!.recordDigest,
      validatorSetDigest: Buffer.alloc(32, 1),
      timestampUs: 1723500000000000n,
      records: snapshotRecords,
    };
    const snapshotDigest = computeSnapshotDigest(snapshotBase);
    const snapshot: LedgerSnapshot = {
      ...snapshotBase,
      snapshotDigest,
    };

    // 3. Extract journal suffix (sequences 6 to 10)
    const suffix = allRecords.slice(5);

    // 4. Replay recovery
    const recoveryResult = TrustLedgerRecoveryEngine.recoverLedgerState(snapshot, suffix);
    expect(recoveryResult.isSuccess).toBe(true);
    expect(recoveryResult.replayStartSeq).toBe(6n);
    expect(recoveryResult.replayEndSeq).toBe(10n);
    expect(Buffer.compare(recoveryResult.reconstructedStateRoot, expectedStateRoot)).toBe(0);

    // 5. Test Broken Sequence Gap in suffix
    const brokenSuffix = [allRecords[7]!, allRecords[8]!]; // Starts at 8 instead of 6
    expect(() => TrustLedgerRecoveryEngine.recoverLedgerState(snapshot, brokenSuffix)).toThrow(
      /Ledger sequence gap/
    );
  });
});
