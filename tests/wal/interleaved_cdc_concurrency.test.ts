import { describe, it, expect } from 'vitest';
import { PgLogicalClient } from '../../src/wal/pg_logical_client.js';
import { DeterministicStateFrontier } from '../../src/evidence/state_frontier.js';
import { DurableEvidenceJournal } from '../../src/evidence/journal.js';

describe('PostgreSQL CDC Concurrency & Interleaving Isolation', () => {
  function encodeBegin(xid: number, commitLsnBig: bigint): Buffer {
    const buf = Buffer.alloc(21);
    buf.writeUInt8('B'.charCodeAt(0), 0);
    buf.writeBigUInt64BE(commitLsnBig, 1);
    buf.writeBigInt64BE(BigInt(Date.now()) * 1000n, 9);
    buf.writeUInt32BE(xid, 17);
    return buf;
  }

  function encodeCommit(commitLsnBig: bigint): Buffer {
    const buf = Buffer.alloc(26);
    buf.writeUInt8('C'.charCodeAt(0), 0);
    buf.writeUInt8(0, 1); // flags
    buf.writeBigUInt64BE(commitLsnBig, 2);
    buf.writeBigUInt64BE(commitLsnBig + 100n, 10);
    buf.writeBigInt64BE(BigInt(Date.now()) * 1000n, 18);
    return buf;
  }

  function encodeRelation(relationId: number, schema: string, table: string): Buffer {
    const sBuf = Buffer.from(schema + '\0', 'utf8');
    const tBuf = Buffer.from(table + '\0', 'utf8');
    const cNameBuf = Buffer.from('id\0', 'utf8');
    const valNameBuf = Buffer.from('val\0', 'utf8');

    const totalLen = 1 + 4 + sBuf.length + tBuf.length + 1 + 2 + (1 + cNameBuf.length + 4 + 4) + (1 + valNameBuf.length + 4 + 4);
    const buf = Buffer.alloc(totalLen);
    let offset = 0;

    buf.writeUInt8('R'.charCodeAt(0), offset++);
    buf.writeUInt32BE(relationId, offset);
    offset += 4;

    sBuf.copy(buf, offset);
    offset += sBuf.length;

    tBuf.copy(buf, offset);
    offset += tBuf.length;

    buf.writeUInt8('d'.charCodeAt(0), offset++); // replica identity
    buf.writeUInt16BE(2, offset); // 2 columns
    offset += 2;

    // Col 1: id (flag 1 = pk)
    buf.writeUInt8(1, offset++);
    cNameBuf.copy(buf, offset);
    offset += cNameBuf.length;
    buf.writeUInt32BE(23, offset); // INT4
    offset += 4;
    buf.writeInt32BE(-1, offset);
    offset += 4;

    // Col 2: val
    buf.writeUInt8(0, offset++);
    valNameBuf.copy(buf, offset);
    offset += valNameBuf.length;
    buf.writeUInt32BE(25, offset); // TEXT
    offset += 4;
    buf.writeInt32BE(-1, offset);
    offset += 4;

    return buf;
  }

  function encodeInsert(relationId: number, idVal: string, textVal: string): Buffer {
    const idBytes = Buffer.from(idVal, 'utf8');
    const textBytes = Buffer.from(textVal, 'utf8');

    const totalLen = 1 + 4 + 1 + 2 + (1 + 4 + idBytes.length) + (1 + 4 + textBytes.length);
    const buf = Buffer.alloc(totalLen);
    let offset = 0;

    buf.writeUInt8('I'.charCodeAt(0), offset++);
    buf.writeUInt32BE(relationId, offset);
    offset += 4;

    buf.writeUInt8('N'.charCodeAt(0), offset++);
    buf.writeUInt16BE(2, offset);
    offset += 2;

    // Col 1 (id)
    buf.writeUInt8('t'.charCodeAt(0), offset++);
    buf.writeUInt32BE(idBytes.length, offset);
    offset += 4;
    idBytes.copy(buf, offset);
    offset += idBytes.length;

    // Col 2 (val)
    buf.writeUInt8('t'.charCodeAt(0), offset++);
    buf.writeUInt32BE(textBytes.length, offset);
    offset += 4;
    textBytes.copy(buf, offset);
    offset += textBytes.length;

    return buf;
  }

  it('isolates mutations between concurrent interleaved transactions and handles rollback', async () => {
    const frontier = new DeterministicStateFrontier({ tenantId: 't1', databaseId: 'db1' });
    const client = new PgLogicalClient(
      {
        slotName: 'test_slot',
        plugin: 'pgoutput',
        protectedTables: ['public.accounts'],
      },
      undefined,
      frontier
    );

    // Bootstrap baseline
    await client.bootstrapFromClient(
      {
        query: async () => ({ rows: [] }),
      } as any,
      ['public.accounts']
    );

    // Register Relation
    await client.ingestPgOutputMessage(encodeRelation(1001, 'public', 'accounts'));

    // Interleave XID 101 and XID 202
    // 1. Begin XID 101
    await client.ingestPgOutputMessage(encodeBegin(101, 0x1000n));

    // 2. Insert into XID 101
    await client.ingestPgOutputMessage(encodeInsert(1001, '101', 'committed_value'));

    // 3. Begin XID 202
    await client.ingestPgOutputMessage(encodeBegin(202, 0x2000n));

    // 4. Insert into XID 202
    await client.ingestPgOutputMessage(encodeInsert(1001, '202', 'uncommitted_rollback_value'));

    // 5. Abort / Rollback XID 202
    client.abortTransaction('202');

    // 6. Commit XID 101
    const committedChanges = await client.ingestPgOutputMessage(encodeCommit(0x1000n));

    expect(committedChanges).not.toBeNull();
    expect(committedChanges!).toHaveLength(1);
    expect(committedChanges![0]!.changeRecordData.transactionId).toBe('tx:101');
    expect((committedChanges![0]!.changeRecordData.fieldSet.new as any).id).toBe('101');

    // Verify State Frontier contains row 101, but NOT row 202
    const root = frontier.computeStateMerkleRoot();
    expect(root).toBeDefined();
    expect(frontier.getActiveRowCount()).toBe(1);
  });
});
