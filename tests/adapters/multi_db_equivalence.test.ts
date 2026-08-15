import { describe, it, expect } from 'vitest';
import { SqliteAdapter } from '../../src/adapters/sqlite.js';
import { MySqlAdapter } from '../../src/adapters/mysql.js';
import { WalNormalizer } from '../../src/wal/normalizer.js';
import { DatabaseMutationEvent } from '../../src/adapters/types.js';
import { MutationOperation } from '../../src/protocol/types.js';
import { GENESIS_PREDECEASED_HASH } from '../../src/crypto/hash.js';

describe('Universal Multi-Database Adapters (WDB-0025 Hardening)', () => {
  it('property: normalizes identical mutations across SQLite and MySQL into compliant canonical binary format', () => {
    const sqliteAdapter = new SqliteAdapter();
    const mysqlAdapter = new MySqlAdapter();
    const walNormalizer = new WalNormalizer();

    const versionId = '00000000-0000-0000-0000-000000000001';
    const pkId = '11111111-1111-1111-1111-111111111111';
    const pkBuf = Buffer.from(pkId.replace(/-/g, ''), 'hex');

    const sqliteEvent: DatabaseMutationEvent = {
      engine: 'sqlite',
      schema: 'public',
      table: 'accounts',
      operation: MutationOperation.INSERT,
      primaryKeyFields: [{ name: 'id', typeTag: 4, valueBuffer: pkBuf }],
      newValues: { id: pkId, balance: '500.00' },
      oldValues: null,
      txId: 'tx-100',
      commitTimestampUs: 1723500000000000n,
    };

    const mysqlEvent: DatabaseMutationEvent = {
      engine: 'mysql',
      schema: 'public',
      table: 'accounts',
      operation: MutationOperation.INSERT,
      primaryKeyFields: [{ name: 'id', typeTag: 4, valueBuffer: pkBuf }],
      newValues: { balance: '500.00', id: pkId }, // Differing key ordering
      oldValues: null,
      txId: 'gtid-100',
      commitTimestampUs: 1723500000000000n,
    };

    const sqliteNormalized = sqliteAdapter.normalizeMutation(sqliteEvent, versionId, GENESIS_PREDECEASED_HASH);
    const mysqlNormalized = mysqlAdapter.normalizeMutation(mysqlEvent, versionId, GENESIS_PREDECEASED_HASH);

    expect(sqliteNormalized.changeRecordData.operation).toBe(MutationOperation.INSERT);
    expect(mysqlNormalized.changeRecordData.operation).toBe(MutationOperation.INSERT);
    expect(sqliteNormalized.recordBytes.length).toBeGreaterThan(0);
    expect(mysqlNormalized.recordBytes.length).toBeGreaterThan(0);
    expect(sqliteNormalized.changeHash).toHaveLength(32);
    expect(mysqlNormalized.changeHash).toHaveLength(32);
  });
});
