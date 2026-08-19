import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import {
  TrustHistoryAuditor,
  DurableDisasterQueue,
  DisasterType,
  DisasterState,
  EvidenceJournalEntry,
  computeChangeHash,
  encodeBinaryRecord,
  MutationOperation,
} from '../src/index.js';

describe('Milestone 4.6 & 4.7 — History Truncation Defense & Journal Corruption Quarantine', () => {
  const testDir = path.join(process.cwd(), 'tmp', 'test_history_audit');
  const disastersPath = path.join(testDir, 'disasters.wdbjrn');

  beforeEach(() => {
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
  });

  afterEach(() => {
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  function makeMockJournalEntry(seq: bigint, prevHash: Buffer): EvidenceJournalEntry {
    const rawChange = {
      formatVersion: 1,
      versionId: '00000000-0000-0000-0000-000000000001',
      transactionId: `tx-${seq}`,
      timestampUs: 1723800000000000n + seq * 1000n,
      tableId: 'public.accounts',
      recordId: Buffer.from(`acc_${seq}`, 'utf8'),
      operation: MutationOperation.INSERT,
      fieldSet: { id: `acc_${seq}`, balance: '100.00' },
      provenance: {},
      previousHash: prevHash,
    };

    const recordBytes = encodeBinaryRecord(
      1,
      [
        { tag: 1, typeTag: 2, payload: Buffer.alloc(8) },
        { tag: 3, typeTag: 5, payload: Buffer.from(rawChange.transactionId, 'utf8') },
        { tag: 5, typeTag: 5, payload: Buffer.from(rawChange.tableId, 'utf8') },
        { tag: 6, typeTag: 6, payload: rawChange.recordId },
        { tag: 8, typeTag: 8, payload: Buffer.from(JSON.stringify(rawChange.fieldSet), 'utf8') },
      ],
      0
    );

    const changeHash = computeChangeHash(recordBytes, prevHash);

    return {
      sequenceNumber: seq,
      lsn: `0/${(1000000n + seq * 100n).toString(16)}`,
      xid: rawChange.transactionId,
      timestampUs: rawChange.timestampUs,
      changeRecord: rawChange,
      recordBytes,
      changeHash,
      previousHash: prevHash,
    };
  }

  it('1. History Truncation Attack Defense: sequence gap (deleting 4..6) raises TRUST_HISTORY_GAP and halts in quarantine', () => {
    const disasterQueue = new DurableDisasterQueue(disastersPath);
    const auditor = new TrustHistoryAuditor(disasterQueue);

    // Build contiguous chain for seq 1..10
    const allEntries: EvidenceJournalEntry[] = [];
    let runningHead = Buffer.alloc(32, 0);

    for (let i = 1n; i <= 10n; i++) {
      const entry = makeMockJournalEntry(i, runningHead);
      allEntries.push(entry);
      runningHead = Buffer.from(entry.changeHash);
    }

    // Attacker deletes sequences 4, 5, 6
    const truncatedEntries = [
      allEntries[0]!, // seq 1
      allEntries[1]!, // seq 2
      allEntries[2]!, // seq 3
      allEntries[6]!, // seq 7 (GAP!)
      allEntries[7]!, // seq 8
    ];

    expect(() => auditor.auditJournalHistory(truncatedEntries)).toThrowError(
      /TRUST_HISTORY_GAP detected: Expected sequence 4, observed 7/
    );

    // Assert disaster was persistently logged in quarantine
    const activeDisasters = disasterQueue.getActiveDisasters();
    expect(activeDisasters.length).toBe(1);
    expect(activeDisasters[0]!.disasterType).toBe(DisasterType.D008_TRUST_HISTORY_GAP);
    expect(activeDisasters[0]!.state).toBe(DisasterState.QUARANTINED);
    expect(activeDisasters[0]!.metadata?.missingRangeStart).toBe('4');
    expect(activeDisasters[0]!.metadata?.missingRangeEnd).toBe('6');
  });

  it('2. Journal Bit-Flip Corruption Defense: corrupted record payload raises JOURNAL_CORRUPTION and refuses silent truncation', () => {
    const disasterQueue = new DurableDisasterQueue(disastersPath);
    const auditor = new TrustHistoryAuditor(disasterQueue);

    const allEntries: EvidenceJournalEntry[] = [];
    let runningHead = Buffer.alloc(32, 0);

    for (let i = 1n; i <= 5n; i++) {
      const entry = makeMockJournalEntry(i, runningHead);
      allEntries.push(entry);
      runningHead = Buffer.from(entry.changeHash);
    }

    // Corrupt payload of record #3 (flip a byte)
    allEntries[2]!.recordBytes[15] = (allEntries[2]!.recordBytes[15] || 0) ^ 0xff;

    expect(() => auditor.auditJournalHistory(allEntries)).toThrowError(
      /JOURNAL_CORRUPTION: Payload checksum mismatch at sequence 3/
    );

    const activeDisasters = disasterQueue.getActiveDisasters();
    expect(activeDisasters.length).toBe(1);
    expect(activeDisasters[0]!.disasterType).toBe(DisasterType.D005_JOURNAL_CORRUPTION);
    expect(activeDisasters[0]!.state).toBe(DisasterState.QUARANTINED);
  });
});
