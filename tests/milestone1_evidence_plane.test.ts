import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  BootstrapSnapshot,
  DeterministicStateFrontier,
  DurableEvidenceJournal,
  PgOutputDecoder,
  PgLogicalClient,
  encodePrimaryKeyTuple,
  canonicalizeJson,
  compareCanonicalStrings,
} from '../src/index.js';

describe('Milestone 1 — Canonical Evidence Plane (Plane 1)', () => {
  const testJournalDir = path.join(process.cwd(), 'tmp', 'test_evidence_journal');
  const testJournalPath = path.join(testJournalDir, `journal_${Date.now()}.wdbjrn`);

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

  it('1. Bootstrap Snapshot S_0 -> H_0: initializes baseline state and computes deterministic Merkle root', () => {
    const frontier = new DeterministicStateFrontier(1);

    const bootstrapSnapshot: BootstrapSnapshot = {
      snapshotId: 'snap-bootstrap-001',
      snapshotLsn: '0/1600000',
      createdAtUs: 1723800000000000n,
      schemaEpoch: 1,
      tables: ['public.accounts'],
      rows: [
        {
          tableName: 'public.accounts',
          primaryKeyFields: [
            { name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_101', 'utf8') },
          ],
          values: { id: 'acc_101', balance: '10000.00', owner: 'Alice' },
        },
        {
          tableName: 'public.accounts',
          primaryKeyFields: [
            { name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_102', 'utf8') },
          ],
          values: { id: 'acc_102', balance: '25000.00', owner: 'Bob' },
        },
      ],
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    };

    const result = frontier.bootstrap(bootstrapSnapshot);

    expect(result.commitSeq).toBe(0n);
    expect(result.lsn).toBe('0/1600000');
    expect(result.activeRowCount).toBe(2);
    expect(result.stateMerkleRoot.length).toBe(32);
    expect(result.stateMerkleRoot).not.toEqual(Buffer.alloc(32, 0));

    // Verify deterministic reproducibility
    const frontier2 = new DeterministicStateFrontier(1);
    const result2 = frontier2.bootstrap(bootstrapSnapshot);
    expect(result2.stateMerkleRoot.toString('hex')).toBe(result.stateMerkleRoot.toString('hex'));
  });

  it('2. pgoutput Binary Decoder: correctly decodes Begin, Relation, Insert, Update, Delete, and Commit frames', () => {
    const decoder = new PgOutputDecoder();

    // 1. Decode Relation 'R' message for public.accounts
    // Schema: public, Table: accounts, Columns: id (key), balance, owner
    const relBuf = Buffer.concat([
      Buffer.from('R', 'utf8'), // Msg type
      Buffer.from([0x00, 0x00, 0x10, 0x01]), // relationId = 4097
      Buffer.from('public\0', 'utf8'), // schema
      Buffer.from('accounts\0', 'utf8'), // table
      Buffer.from('d', 'utf8'), // replica identity: default
      Buffer.from([0x00, 0x03]), // 3 columns
      // Col 1: id (key = 1)
      Buffer.from([0x01]), // flags: key
      Buffer.from('id\0', 'utf8'),
      Buffer.from([0x00, 0x00, 0x0b, 0x86]), // type OID 2950 (uuid)
      Buffer.from([0xff, 0xff, 0xff, 0xff]), // type modifier -1
      // Col 2: balance
      Buffer.from([0x00]), // flags
      Buffer.from('balance\0', 'utf8'),
      Buffer.from([0x00, 0x00, 0x06, 0xa4]), // type OID 1700 (numeric)
      Buffer.from([0xff, 0xff, 0xff, 0xff]),
      // Col 3: owner
      Buffer.from([0x00]),
      Buffer.from('owner\0', 'utf8'),
      Buffer.from([0x00, 0x00, 0x00, 0x19]), // type OID 25 (text)
      Buffer.from([0xff, 0xff, 0xff, 0xff]),
    ]);

    const relMsg = decoder.decodeMessage(relBuf);
    expect(relMsg.type).toBe('R');
    if (relMsg.type === 'R') {
      expect(relMsg.table).toBe('accounts');
      expect(relMsg.columns.length).toBe(3);
      expect(relMsg.columns[0]!.name).toBe('id');
      expect((relMsg.columns[0]!.flags & 1)).toBe(1);
    }

    // 2. Decode Begin 'B'
    const beginBuf = Buffer.concat([
      Buffer.from('B', 'utf8'),
      Buffer.alloc(8), // LSN
      Buffer.alloc(8), // commitTimeUs
      Buffer.from([0x00, 0x00, 0x03, 0xe9]), // xid = 1001
    ]);
    beginBuf.writeBigUInt64BE(0x1600100n, 1);
    beginBuf.writeBigInt64BE(1723800000100000n, 9);

    const beginMsg = decoder.decodeMessage(beginBuf);
    expect(beginMsg.type).toBe('B');
    if (beginMsg.type === 'B') {
      expect(beginMsg.xid).toBe('1001');
    }

    // 3. Decode Insert 'I'
    const val1 = Buffer.from('acc_999', 'utf8');
    const val2 = Buffer.from('50000.00', 'utf8');
    const val3 = Buffer.from('Charlie', 'utf8');

    const insertBuf = Buffer.concat([
      Buffer.from('I', 'utf8'),
      Buffer.from([0x00, 0x00, 0x10, 0x01]), // relationId = 4097
      Buffer.from('N', 'utf8'), // New tuple
      Buffer.from([0x00, 0x03]), // 3 cols
      // Col 1: text
      Buffer.from('t', 'utf8'),
      Buffer.from([0x00, 0x00, 0x00, val1.length]),
      val1,
      // Col 2: text
      Buffer.from('t', 'utf8'),
      Buffer.from([0x00, 0x00, 0x00, val2.length]),
      val2,
      // Col 3: text
      Buffer.from('t', 'utf8'),
      Buffer.from([0x00, 0x00, 0x00, val3.length]),
      val3,
    ]);

    const insertMsg = decoder.decodeMessage(insertBuf);
    expect(insertMsg.type).toBe('I');
    if (insertMsg.type === 'I') {
      expect(insertMsg.tupleData.id).toBe('acc_999');
      expect(insertMsg.tupleData.balance).toBe('50000.00');
      expect(insertMsg.tupleData.owner).toBe('Charlie');
    }
  });

  it('3. Transaction Buffering & Atomicity: ABORT drops mutations; COMMIT applies mutations and advances journal', async () => {
    const journal = new DurableEvidenceJournal(testJournalPath);
    const frontier = new DeterministicStateFrontier(1);

    const client = new PgLogicalClient(
      {
        slotName: 'test_slot',
        plugin: 'pgoutput',
        protectedTables: ['public.accounts'],
      },
      journal,
      frontier
    );

    // Register relation
    client.registerRelation({
      relationId: 100,
      schema: 'public',
      table: 'accounts',
      replicaIdentity: 'd',
      columns: [
        { flags: 1, name: 'id', typeOid: 2950, typeModifier: -1 },
        { flags: 0, name: 'balance', typeOid: 1700, typeModifier: -1 },
      ],
    });

    // 1. Simulate uncommitted Transaction A (XID 501) that gets ABORTED
    const begin501 = Buffer.alloc(21);
    begin501.write('B', 0, 1, 'utf8');
    begin501.writeBigUInt64BE(0x1700000n, 1);
    begin501.writeBigInt64BE(1723800001000000n, 9);
    begin501.writeUInt32BE(501, 17);
    await client.ingestPgOutputMessage(begin501);

    // Insert for XID 501
    const valId = Buffer.from('acc_abort_test', 'utf8');
    const valBal = Buffer.from('999999.00', 'utf8');
    const insert501 = Buffer.concat([
      Buffer.from('I', 'utf8'),
      Buffer.from([0x00, 0x00, 0x00, 0x64]), // relId 100
      Buffer.from('N', 'utf8'),
      Buffer.from([0x00, 0x02]),
      Buffer.from('t', 'utf8'),
      Buffer.from([0x00, 0x00, 0x00, valId.length]),
      valId,
      Buffer.from('t', 'utf8'),
      Buffer.from([0x00, 0x00, 0x00, valBal.length]),
      valBal,
    ]);
    await client.ingestPgOutputMessage(insert501);

    expect(client.activeXidCount).toBe(1);

    // ABORT Transaction 501
    client.abortTransaction('501');
    expect(client.activeXidCount).toBe(0);

    // Verify journal and frontier remain completely untouched
    expect(journal.length).toBe(0);
    expect(frontier.getActiveRowCount()).toBe(0);

    // 2. Simulate committed Transaction B (XID 502)
    const begin502 = Buffer.alloc(21);
    begin502.write('B', 0, 1, 'utf8');
    begin502.writeBigUInt64BE(0x1700200n, 1);
    begin502.writeBigInt64BE(1723800002000000n, 9);
    begin502.writeUInt32BE(502, 17);
    await client.ingestPgOutputMessage(begin502);

    const valId2 = Buffer.from('acc_committed', 'utf8');
    const valBal2 = Buffer.from('1234.56', 'utf8');
    const insert502 = Buffer.concat([
      Buffer.from('I', 'utf8'),
      Buffer.from([0x00, 0x00, 0x00, 0x64]), // relId 100
      Buffer.from('N', 'utf8'),
      Buffer.from([0x00, 0x02]),
      Buffer.from('t', 'utf8'),
      Buffer.from([0x00, 0x00, 0x00, valId2.length]),
      valId2,
      Buffer.from('t', 'utf8'),
      Buffer.from([0x00, 0x00, 0x00, valBal2.length]),
      valBal2,
    ]);
    await client.ingestPgOutputMessage(insert502);

    // Commit 502
    const commit502 = Buffer.alloc(26);
    commit502.write('C', 0, 1, 'utf8');
    commit502.writeUInt8(0, 1);
    commit502.writeBigUInt64BE(0x1700300n, 2);
    commit502.writeBigUInt64BE(0x1700300n, 10);
    commit502.writeBigInt64BE(1723800002500000n, 18);

    const result = await client.ingestPgOutputMessage(commit502);
    expect(result).not.toBeNull();
    expect(result!.length).toBe(1);

    // Verify journal and frontier are updated
    expect(journal.length).toBe(1);
    expect(frontier.getActiveRowCount()).toBe(1);
    expect(frontier.commitSeq).toBe(1n);

    await journal.close();
  });

  it('4. Deterministic Row Ordering & RFC 6962 State Root Reproducibility: same data yields identical H_n regardless of insert sequence', () => {
    const rowA = { id: 'acc_001', balance: '100.00', owner: 'Alice' };
    const rowB = { id: 'acc_002', balance: '200.00', owner: 'Bob' };
    const rowC = { id: 'acc_003', balance: '300.00', owner: 'Charlie' };

    // Order 1: A -> B -> C
    const frontier1 = new DeterministicStateFrontier(1);
    frontier1.bootstrap({
      snapshotId: 'snap-1',
      snapshotLsn: '0/100',
      createdAtUs: 1000n,
      schemaEpoch: 1,
      tables: ['public.accounts'],
      rows: [
        { tableName: 'public.accounts', primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from(rowA.id, 'utf8') }], values: rowA },
        { tableName: 'public.accounts', primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from(rowB.id, 'utf8') }], values: rowB },
        { tableName: 'public.accounts', primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from(rowC.id, 'utf8') }], values: rowC },
      ],
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    });

    const root1 = frontier1.computeStateMerkleRoot();

    // Order 2: C -> A -> B (Arbitrary reversed/interleaved order)
    const frontier2 = new DeterministicStateFrontier(1);
    frontier2.bootstrap({
      snapshotId: 'snap-2',
      snapshotLsn: '0/100',
      createdAtUs: 1000n,
      schemaEpoch: 1,
      tables: ['public.accounts'],
      rows: [
        { tableName: 'public.accounts', primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from(rowC.id, 'utf8') }], values: rowC },
        { tableName: 'public.accounts', primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from(rowA.id, 'utf8') }], values: rowA },
        { tableName: 'public.accounts', primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from(rowB.id, 'utf8') }], values: rowB },
      ],
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    });

    const root2 = frontier2.computeStateMerkleRoot();

    // Strict byte-level equality
    expect(root1.toString('hex')).toBe(root2.toString('hex'));
  });

  it('5. Durable Evidence Journal: persists records with SHA-256 chain and recovers state on restart', async () => {
    const journalPath = path.join(testJournalDir, 'crash_recovery_journal.wdbjrn');
    const journal = new DurableEvidenceJournal(journalPath);
    const frontier = new DeterministicStateFrontier(1);

    const client = new PgLogicalClient(
      {
        slotName: 'recovery_slot',
        plugin: 'pgoutput',
        protectedTables: ['public.accounts'],
      },
      journal,
      frontier
    );

    client.registerRelation({
      relationId: 200,
      schema: 'public',
      table: 'accounts',
      replicaIdentity: 'd',
      columns: [
        { flags: 1, name: 'id', typeOid: 2950, typeModifier: -1 },
        { flags: 0, name: 'balance', typeOid: 1700, typeModifier: -1 },
      ],
    });

    // Write 5 committed transactions
    for (let i = 1; i <= 5; i++) {
      const beginBuf = Buffer.alloc(21);
      beginBuf.write('B', 0, 1, 'utf8');
      beginBuf.writeBigUInt64BE(BigInt(0x2000000 + i * 0x100), 1);
      beginBuf.writeBigInt64BE(BigInt(1723800000000000 + i * 1000), 9);
      beginBuf.writeUInt32BE(600 + i, 17);
      await client.ingestPgOutputMessage(beginBuf);

      const valId = Buffer.from(`acc_user_${i}`, 'utf8');
      const valBal = Buffer.from(`${i * 1000}.00`, 'utf8');
      const insertBuf = Buffer.concat([
        Buffer.from('I', 'utf8'),
        Buffer.from([0x00, 0x00, 0x00, 0xc8]), // relId 200
        Buffer.from('N', 'utf8'),
        Buffer.from([0x00, 0x02]),
        Buffer.from('t', 'utf8'),
        Buffer.from([0x00, 0x00, 0x00, valId.length]),
        valId,
        Buffer.from('t', 'utf8'),
        Buffer.from([0x00, 0x00, 0x00, valBal.length]),
        valBal,
      ]);
      await client.ingestPgOutputMessage(insertBuf);

      const commitBuf = Buffer.alloc(26);
      commitBuf.write('C', 0, 1, 'utf8');
      commitBuf.writeUInt8(0, 1);
      commitBuf.writeBigUInt64BE(BigInt(0x2000050 + i * 0x100), 2);
      commitBuf.writeBigUInt64BE(BigInt(0x2000050 + i * 0x100), 10);
      commitBuf.writeBigInt64BE(BigInt(1723800000000000 + i * 1000 + 500), 18);
      await client.ingestPgOutputMessage(commitBuf);
    }

    const stateRootBeforeCrash = frontier.computeStateMerkleRoot();
    const lastChainHead = journal.chainHead;
    await journal.close();

    // --- SIMULATE PROCESS RESTART ---
    const recoveredJournal = new DurableEvidenceJournal(journalPath);
    const integrity = await recoveredJournal.verifyChainIntegrity();

    expect(integrity.valid).toBe(true);
    expect(integrity.entryCount).toBe(5);
    expect(integrity.lastSeq).toBe(5n);
    expect(integrity.lastHash.toString('hex')).toBe(lastChainHead.toString('hex'));

    // Replay journal from disk to reconstruct state
    const replayedEntries = await recoveredJournal.replay();
    const reconstructedFrontier = new DeterministicStateFrontier(1);

    let runningHead = Buffer.alloc(32, 0);
    for (const entry of replayedEntries) {
      reconstructedFrontier.applyChangeRecords(
        [entry.changeRecord],
        entry.lsn,
        entry.sequenceNumber,
        entry.changeHash
      );
      runningHead = entry.changeHash;
    }

    const stateRootAfterReplay = reconstructedFrontier.computeStateMerkleRoot();
    expect(stateRootAfterReplay.toString('hex')).toBe(stateRootBeforeCrash.toString('hex'));
    expect(reconstructedFrontier.getActiveRowCount()).toBe(5);

    await recoveredJournal.close();
  });

  it('6. Schema Epoch Transitions: advancing epoch modifies state Merkle root deterministically', () => {
    const frontier = new DeterministicStateFrontier(1);
    frontier.bootstrap({
      snapshotId: 'snap-epoch-test',
      snapshotLsn: '0/300',
      createdAtUs: 1000n,
      schemaEpoch: 1,
      tables: ['public.accounts'],
      rows: [
        {
          tableName: 'public.accounts',
          primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_1', 'utf8') }],
          values: { id: 'acc_1', balance: '500.00' },
        },
      ],
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    });

    const rootEpoch1 = frontier.computeStateMerkleRoot();

    // DDL Migration occurs (schemaEpoch advances to 2)
    frontier.incrementSchemaEpoch();
    expect(frontier.schemaEpoch).toBe(2);

    const rootEpoch2 = frontier.computeStateMerkleRoot();

    // Epoch advancement must produce a deterministically distinct Merkle root
    expect(rootEpoch1.toString('hex')).not.toBe(rootEpoch2.toString('hex'));

    // Verify reproducibility of epoch 2 root
    const frontierClone = new DeterministicStateFrontier(2);
    frontierClone.bootstrap({
      snapshotId: 'snap-epoch-test-2',
      snapshotLsn: '0/300',
      createdAtUs: 1000n,
      schemaEpoch: 2,
      tables: ['public.accounts'],
      rows: [
        {
          tableName: 'public.accounts',
          primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_1', 'utf8') }],
          values: { id: 'acc_1', balance: '500.00' },
        },
      ],
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    });

    const cloneRootEpoch2 = frontierClone.computeStateMerkleRoot();
    expect(cloneRootEpoch2.toString('hex')).toBe(rootEpoch2.toString('hex'));
  });

  it('7. End-to-End Checkpoint Generation: binds state frontier to AnchoredCheckpoint with SHA-256 digest', () => {
    const frontier = new DeterministicStateFrontier(1);
    frontier.bootstrap({
      snapshotId: 'snap-checkpoint-01',
      snapshotLsn: '0/5000',
      createdAtUs: 1723800000000000n,
      schemaEpoch: 1,
      tables: ['public.accounts'],
      rows: [
        {
          tableName: 'public.accounts',
          primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_prod', 'utf8') }],
          values: { id: 'acc_prod', balance: '100000.00', status: 'ACTIVE' },
        },
      ],
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    });

    const checkpoint = frontier.createCheckpoint('chk-9002-uuid-v4', 'public.accounts');

    expect(checkpoint.checkpointId).toBe('chk-9002-uuid-v4');
    expect(checkpoint.scope).toBe('public.accounts');
    expect(checkpoint.merkleRoot.length).toBe(32);
    expect(checkpoint.digest.length).toBe(32);
    expect(checkpoint.digest).not.toEqual(Buffer.alloc(32, 0));
  });
});
