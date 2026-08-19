import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {
  ValidatorDurableJournal,
  TornWriteSimulator,
  ValidatorLockTable,
} from '../src/index.js';

describe('Milestone 6.2 — Crash-Consistency & Torn Write Laboratory', () => {
  let tmpDir: string;
  let journalPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wdb-m6-durability-'));
    journalPath = path.join(tmpDir, 'val_test.wdbjrn');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('1. Torn Write Recovery: recovers valid pre-crash locks and ignores truncated tail after power loss', async () => {
    const journal = new ValidatorDurableJournal('val-01', journalPath);

    // Append 5 valid locks
    for (let seq = 1n; seq <= 5n; seq++) {
      const cmtDigestHex = crypto.createHash('sha256').update(`cmt_${seq}`).digest('hex');
      await journal.appendLock({
        tenantId: 'tenant-1',
        databaseId: 'db-1',
        epoch: 1,
        commitSeq: seq,
        commitmentDigestHex: cmtDigestHex,
        lockedAtUs: 1723800000000000n + seq * 1000n,
      });
    }
    await journal.close();

    // Append raw 6th record with torn write (truncate last 15 bytes)
    const fileBuf = fs.readFileSync(journalPath);
    const fakeIncompleteTail = Buffer.concat([
      Buffer.from('WDBL', 'utf8'),
      Buffer.from('00000030', 'hex'), // fake length (48 bytes)
      Buffer.from('incomplete_payload_data_during_power_loss', 'utf8'),
    ]);
    fs.writeFileSync(journalPath, Buffer.concat([fileBuf, fakeIncompleteTail]));

    // Restart journal and verify replay
    const restartedJournal = new ValidatorDurableJournal('val-01', journalPath);
    const lockTable = new ValidatorLockTable('val-01');

    // Replay should safely recover the 5 valid locks without failing
    const replayedRecords = await restartedJournal.replay();
    expect(replayedRecords.length).toBe(5);

    for (const r of replayedRecords) {
      lockTable.restoreLockFromJournal(r);
    }

    // Verify lock table state
    for (let seq = 1n; seq <= 5n; seq++) {
      const lock = lockTable.getLock('tenant-1', 'db-1', 1, seq);
      expect(lock).toBeDefined();
    }
    expect(lockTable.getLock('tenant-1', 'db-1', 1, 6n)).toBeUndefined();
  });

  it('2. Corrupted Magic Header: torn file creation is rejected at boot', () => {
    TornWriteSimulator.simulateTornHeader(journalPath);

    expect(() => {
      new ValidatorDurableJournal('val-01', journalPath);
    }).toThrow();
  });
});
