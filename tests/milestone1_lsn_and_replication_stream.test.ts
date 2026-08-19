import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import {
  PgLogicalClient,
  PgReplicationStream,
  DeterministicStateFrontier,
  DurableEvidenceJournal,
  BootstrapSnapshot,
  encodePrimaryKeyTuple,
} from '../src/index.js';

describe('Milestone 1.1 — PostgreSQL Logical Replication Stream, LSN Continuity & Slot Loss Recovery', () => {
  const testJournalDir = path.join(process.cwd(), 'tmp', 'test_stream_journal');
  const testJournalPath = path.join(testJournalDir, `stream_journal_${Date.now()}.wdbjrn`);

  beforeEach(() => {
    if (!fs.existsSync(testJournalDir)) {
      fs.mkdirSync(testJournalDir, { recursive: true });
    }
  });

  afterEach(() => {
    if (fs.existsSync(testJournalDir)) {
      fs.rmSync(testJournalDir, { recursive: true, force: true });
    }
  });

  it('1. PostgreSQL CopyData Replication Framing: encodes and decodes XLogData, PrimaryKeepalive, and StandbyStatusUpdate', () => {
    // 1. Standby Status Update encoding
    const statusUpdate = PgReplicationStream.encodeStandbyStatusUpdate({
      writeLsnBig: 0x18A4200n,
      flushedLsnBig: 0x18A4200n,
      appliedLsnBig: 0x18A4200n,
      sendTimeUs: 1723800000000000n,
      replyRequested: false,
    });

    expect(statusUpdate.length).toBe(34);
    expect(String.fromCharCode(statusUpdate[0]!)).toBe('r');
    expect(statusUpdate.readBigUInt64BE(9)).toBe(0x18A4200n);

    // 2. Primary Keepalive decoding
    const keepaliveFrame = PgReplicationStream.createKeepaliveFrame(0x18A5000n, 1723800000100000n, true);
    const decodedKeepalive = PgReplicationStream.decodeCopyDataMessage(keepaliveFrame);

    expect(decodedKeepalive.type).toBe('PrimaryKeepalive');
    if (decodedKeepalive.type === 'PrimaryKeepalive') {
      expect(decodedKeepalive.header.endLsnBig).toBe(0x18A5000n);
      expect(decodedKeepalive.header.replyRequested).toBe(true);
    }

    // 3. XLogData decoding
    const dummyPayload = Buffer.from('TEST_PGOUTPUT_PAYLOAD', 'utf8');
    const xlogFrame = PgReplicationStream.createXLogDataFrame(0x18A4000n, 0x18A4200n, 1723800000050000n, dummyPayload);
    const decodedXlog = PgReplicationStream.decodeCopyDataMessage(xlogFrame);

    expect(decodedXlog.type).toBe('XLogData');
    if (decodedXlog.type === 'XLogData') {
      expect(decodedXlog.header.startLsnBig).toBe(0x18A4000n);
      expect(decodedXlog.header.endLsnBig).toBe(0x18A4200n);
      expect(decodedXlog.header.payload.toString('utf8')).toBe('TEST_PGOUTPUT_PAYLOAD');
    }
  });

  it('2. Full Replication Stream Pipeline: XLogData stream -> Transaction Buffer -> Journal fsync -> Deterministic Frontier H1 -> Crash Replay H1 == H1', async () => {
    const journal = new DurableEvidenceJournal(testJournalPath);
    const frontier = new DeterministicStateFrontier(1);

    const client = new PgLogicalClient(
      {
        slotName: 'wolverine_prod_slot',
        publicationName: 'wolverine_pub',
        plugin: 'pgoutput',
        protectedTables: ['public.accounts'],
        startLsn: '0/1000000',
      },
      journal,
      frontier
    );

    // Bootstrap initial snapshot S0
    const snapshot0: BootstrapSnapshot = {
      snapshotId: 'snap-genesis-000',
      snapshotLsn: '0/1000000',
      createdAtUs: 1723800000000000n,
      schemaEpoch: 1,
      tables: ['public.accounts'],
      rows: [
        {
          tableName: 'public.accounts',
          primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_100', 'utf8') }],
          values: { id: 'acc_100', balance: '10000.00', status: 'ACTIVE' },
        },
      ],
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    };
    frontier.bootstrap(snapshot0);
    const root0 = frontier.computeStateMerkleRoot();

    // Register relation (column typeOid 25 is text)
    client.registerRelation({
      relationId: 501,
      schema: 'public',
      table: 'accounts',
      replicaIdentity: 'd',
      columns: [
        { flags: 1, name: 'id', typeOid: 25, typeModifier: -1 },
        { flags: 0, name: 'balance', typeOid: 1700, typeModifier: -1 },
        { flags: 0, name: 'status', typeOid: 25, typeModifier: -1 },
      ],
    });

    // Stream 3 real transactions over XLogData frames:
    // Tx 1 (Insert acc_200 at LSN 0/1100000)
    // Tx 2 (Update acc_100 balance=15000.00 at LSN 0/1200000)
    // Tx 3 (Insert acc_300 at LSN 0/1300000)

    const txs = [
      {
        xid: 701,
        lsnBig: 0x1100000n,
        action: 'I' as const,
        id: 'acc_200',
        bal: '20000.00',
        status: 'ACTIVE',
      },
      {
        xid: 702,
        lsnBig: 0x1200000n,
        action: 'U' as const,
        id: 'acc_100',
        bal: '15000.00',
        status: 'ACTIVE',
      },
      {
        xid: 703,
        lsnBig: 0x1300000n,
        action: 'I' as const,
        id: 'acc_300',
        bal: '30000.00',
        status: 'PENDING',
      },
    ];

    for (const tx of txs) {
      // 1. Begin
      const beginBuf = Buffer.alloc(21);
      beginBuf.write('B', 0, 1, 'utf8');
      beginBuf.writeBigUInt64BE(tx.lsnBig, 1);
      beginBuf.writeBigInt64BE(1723800001000000n, 9);
      beginBuf.writeUInt32BE(tx.xid, 17);
      const xlogBegin = PgReplicationStream.createXLogDataFrame(tx.lsnBig - 0x50n, tx.lsnBig, 1723800001000000n, beginBuf);
      const decBegin = PgReplicationStream.decodeCopyDataMessage(xlogBegin);
      if (decBegin.type === 'XLogData') {
        await client.ingestPgOutputMessage(decBegin.header.payload);
      }

      // 2. DML
      const valId = Buffer.from(tx.id, 'utf8');
      const valBal = Buffer.from(tx.bal, 'utf8');
      const valStatus = Buffer.from(tx.status, 'utf8');

      const dmlBuf = Buffer.concat([
        Buffer.from(tx.action, 'utf8'),
        Buffer.from([0x00, 0x00, 0x01, 0xf5]), // relId 501
        Buffer.from('N', 'utf8'),
        Buffer.from([0x00, 0x03]),
        Buffer.from('t', 'utf8'),
        Buffer.from([0x00, 0x00, 0x00, valId.length]),
        valId,
        Buffer.from('t', 'utf8'),
        Buffer.from([0x00, 0x00, 0x00, valBal.length]),
        valBal,
        Buffer.from('t', 'utf8'),
        Buffer.from([0x00, 0x00, 0x00, valStatus.length]),
        valStatus,
      ]);
      const xlogDml = PgReplicationStream.createXLogDataFrame(tx.lsnBig, tx.lsnBig + 0x10n, 1723800001000000n, dmlBuf);
      const decDml = PgReplicationStream.decodeCopyDataMessage(xlogDml);
      if (decDml.type === 'XLogData') {
        await client.ingestPgOutputMessage(decDml.header.payload);
      }

      // 3. Commit
      const commitBuf = Buffer.alloc(26);
      commitBuf.write('C', 0, 1, 'utf8');
      commitBuf.writeUInt8(0, 1);
      commitBuf.writeBigUInt64BE(tx.lsnBig + 0x50n, 2);
      commitBuf.writeBigUInt64BE(tx.lsnBig + 0x50n, 10);
      commitBuf.writeBigInt64BE(1723800001000500n, 18);
      const xlogCommit = PgReplicationStream.createXLogDataFrame(tx.lsnBig + 0x10n, tx.lsnBig + 0x50n, 1723800001000500n, commitBuf);
      const decCommit = PgReplicationStream.decodeCopyDataMessage(xlogCommit);
      if (decCommit.type === 'XLogData') {
        await client.ingestPgOutputMessage(decCommit.header.payload);
      }
    }

    const rootH1 = frontier.computeStateMerkleRoot();
    expect(rootH1.toString('hex')).not.toBe(root0.toString('hex'));
    expect(frontier.getActiveRowCount()).toBe(3);

    const pkTuple = encodePrimaryKeyTuple([{ name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_100', 'utf8') }]);
    expect(frontier.getLiveRow('public.accounts', pkTuple.toString('hex'))?.values.balance).toBe('15000.00');

    await journal.close();

    // Replay from journal file on simulated crash
    const replayJournal = new DurableEvidenceJournal(testJournalPath);
    const entries = await replayJournal.replay();
    expect(entries.length).toBe(3);

    const replayedFrontier = new DeterministicStateFrontier(1);
    replayedFrontier.bootstrap(snapshot0);

    for (const entry of entries) {
      replayedFrontier.applyChangeRecords([entry.changeRecord], entry.lsn, entry.sequenceNumber, entry.changeHash);
    }

    const replayedRootH1 = replayedFrontier.computeStateMerkleRoot();
    expect(replayedRootH1.toString('hex')).toBe(rootH1.toString('hex'));

    await replayJournal.close();
  });

  it('3. LSN Discontinuity & Regression Defense: detects LSN regression, throws LSN_DISCONTINUITY_ERROR, halts processing and refuses false continuity', async () => {
    const journal = new DurableEvidenceJournal(testJournalPath);
    const frontier = new DeterministicStateFrontier(1);

    const client = new PgLogicalClient(
      {
        slotName: 'lsn_defense_slot',
        plugin: 'pgoutput',
        protectedTables: ['public.accounts'],
        startLsn: '0/2000000',
      },
      journal,
      frontier
    );

    client.registerRelation({
      relationId: 10,
      schema: 'public',
      table: 'accounts',
      replicaIdentity: 'd',
      columns: [{ flags: 1, name: 'id', typeOid: 25, typeModifier: -1 }],
    });

    // 1. First valid transaction at LSN 0/2500000
    const beginValid = Buffer.alloc(21);
    beginValid.write('B', 0, 1, 'utf8');
    beginValid.writeBigUInt64BE(0x2500000n, 1);
    beginValid.writeBigInt64BE(1723800000000000n, 9);
    beginValid.writeUInt32BE(801, 17);
    await client.ingestPgOutputMessage(beginValid);

    const valId = Buffer.from('acc_801', 'utf8');
    const insertValid = Buffer.concat([
      Buffer.from('I', 'utf8'),
      Buffer.from([0x00, 0x00, 0x00, 0x0a]),
      Buffer.from('N', 'utf8'),
      Buffer.from([0x00, 0x01]),
      Buffer.from('t', 'utf8'),
      Buffer.from([0x00, 0x00, 0x00, valId.length]),
      valId,
    ]);
    await client.ingestPgOutputMessage(insertValid);

    const commitValid = Buffer.alloc(26);
    commitValid.write('C', 0, 1, 'utf8');
    commitValid.writeUInt8(0, 1);
    commitValid.writeBigUInt64BE(0x2500100n, 2);
    commitValid.writeBigUInt64BE(0x2500100n, 10);
    commitValid.writeBigInt64BE(1723800000000500n, 18);
    await client.ingestPgOutputMessage(commitValid);

    expect(client.confirmedLsn).toBe('0/2500100');

    // 2. Corrupt / Regressed Transaction attempting to inject LSN 0/1500000 (behind confirmed LSN 0/2500100)
    const beginRegressed = Buffer.alloc(21);
    beginRegressed.write('B', 0, 1, 'utf8');
    beginRegressed.writeBigUInt64BE(0x1500000n, 1); // REGRESSION!
    beginRegressed.writeBigInt64BE(1723800000000000n, 9);
    beginRegressed.writeUInt32BE(802, 17);

    // Assert that client rejects with LSN_DISCONTINUITY_ERROR and halts
    await expect(client.ingestPgOutputMessage(beginRegressed)).rejects.toThrowError(
      /LSN_DISCONTINUITY_ERROR/
    );

    expect(client.isHaltedState).toBe(true);

    // 3. Assert that any subsequent mutation is rejected while halted
    await expect(client.ingestPgOutputMessage(beginValid)).rejects.toThrowError(
      /SLOT_INVALIDATED/
    );

    await journal.close();
  });

  it('4. Slot Loss & Verified Resynchronization: halts on slot drop and resumes only upon verified baseline snapshot S0\' with incremented epoch', async () => {
    const journal = new DurableEvidenceJournal(testJournalPath);
    const frontier = new DeterministicStateFrontier(1);

    const client = new PgLogicalClient(
      {
        slotName: 'slot_recovery_test',
        plugin: 'pgoutput',
        protectedTables: ['public.accounts'],
      },
      journal,
      frontier
    );

    // Initial state S0
    const snapshot1: BootstrapSnapshot = {
      snapshotId: 'snap-pre-loss',
      snapshotLsn: '0/3000000',
      createdAtUs: 1723800000000000n,
      schemaEpoch: 1,
      tables: ['public.accounts'],
      rows: [
        {
          tableName: 'public.accounts',
          primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_orig', 'utf8') }],
          values: { id: 'acc_orig', balance: '500.00' },
        },
      ],
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    };
    frontier.bootstrap(snapshot1);
    expect(frontier.getActiveRowCount()).toBe(1);

    // PostgreSQL replication slot dropped / invalidated by DBA
    client.reportSlotLoss('PostgreSQL replication slot dropped during maintenance');

    expect(client.isHaltedState).toBe(true);
    expect(client.currentHaltReason).toContain('SLOT_LOST');

    // Attempting to ingest while slot is lost is rejected (fail-closed)
    const dummyBegin = Buffer.alloc(21);
    dummyBegin.write('B', 0, 1, 'utf8');
    await expect(client.ingestPgOutputMessage(dummyBegin)).rejects.toThrowError(
      /SLOT_INVALIDATED/
    );

    // Perform Verified Resynchronization Protocol with fresh snapshot S0' (epoch = 2)
    const snapshot2: BootstrapSnapshot = {
      snapshotId: 'snap-post-recovery',
      snapshotLsn: '0/5000000',
      createdAtUs: 1723800005000000n,
      schemaEpoch: 2,
      tables: ['public.accounts'],
      rows: [
        {
          tableName: 'public.accounts',
          primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_orig', 'utf8') }],
          values: { id: 'acc_orig', balance: '750.00' },
        },
        {
          tableName: 'public.accounts',
          primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_new', 'utf8') }],
          values: { id: 'acc_new', balance: '1200.00' },
        },
      ],
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    };

    client.resynchronizeWithSnapshot(snapshot2);

    expect(client.isHaltedState).toBe(false);
    expect(client.confirmedLsn).toBe('0/5000000');
    expect(frontier.schemaEpoch).toBe(2);
    expect(frontier.getActiveRowCount()).toBe(2);

    const origPkTuple = encodePrimaryKeyTuple([{ name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_orig', 'utf8') }]);
    expect(frontier.getLiveRow('public.accounts', origPkTuple.toString('hex'))?.values.balance).toBe('750.00');

    await journal.close();
  });
});
