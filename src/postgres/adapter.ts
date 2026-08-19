import pg from 'pg';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { CREATE_WOLVERINE_SYS_SCHEMA_SQL } from './schema.js';
import { generateTableTriggerSql, validateSqlIdentifier } from './triggers.js';
import { ChangeRecordData, MutationOperation } from '../protocol/types.js';
import { validateChangeRecordData } from '../protocol/validators.js';
import { PostgresNonceStore } from './nonce_store.js';
import { BootstrapSnapshot } from '../evidence/types.js';
import { PgLogicalClient } from '../wal/pg_logical_client.js';
import { sha256 } from '../crypto/hash.js';
import { canonicalizeJson } from '../binary/c14n.js';

export interface DatabaseConfig {
  connectionString: string;
  protectedTables: string[];
}

export class PostgresAdapter {
  private pool: pg.Pool;
  public readonly protectedTables: string[];
  private lastMutationHash: Buffer = Buffer.alloc(32, 0);

  constructor(config: DatabaseConfig) {
    this.pool = new pg.Pool({ connectionString: config.connectionString });
    this.protectedTables = config.protectedTables;
  }

  public async initializeSchema(): Promise<void> {
    let client: pg.PoolClient;
    try {
      client = await this.pool.connect();
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.DATABASE_CONNECTION_ERROR,
        `Database connection failed: ${err.message}`,
        { cause: err }
      );
    }

    try {
      await client.query('BEGIN;');
      await client.query(CREATE_WOLVERINE_SYS_SCHEMA_SQL);
      await client.query('COMMIT;');
    } catch (err: any) {
      await client.query('ROLLBACK;');
      throw new WolverineError(
        WolverineErrorCode.SCHEMA_MIGRATION_ERROR,
        `Failed to initialize wolverine_sys schema: ${err.message}`,
        { cause: err }
      );
    } finally {
      client.release();
    }
  }

  /**
   * Creates a native PostgreSQL logical replication slot.
   */
  public async createReplicationSlot(
    slotName: string,
    plugin: 'pgoutput' | 'test_decoding' = 'pgoutput'
  ): Promise<{ slotName: string; snapshotName?: string; consistentPoint?: string }> {
    validateSqlIdentifier(slotName, 'slotName');
    let client: pg.PoolClient;
    try {
      client = await this.pool.connect();
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.DATABASE_CONNECTION_ERROR,
        `Database connection failed: ${err.message}`,
        { cause: err }
      );
    }

    try {
      const res = await client.query(
        `SELECT slot_name, consistent_point, snapshot_name, output_plugin 
         FROM pg_create_logical_replication_slot($1, $2, false);`,
        [slotName, plugin]
      );
      const row = res.rows[0];
      return {
        slotName: row?.slot_name || slotName,
        snapshotName: row?.snapshot_name,
        consistentPoint: row?.consistent_point,
      };
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.QUERY_EXECUTION_ERROR,
        `Failed to create logical replication slot "${slotName}": ${err.message}`,
        { cause: err }
      );
    } finally {
      client.release();
    }
  }

  /**
   * Drops a logical replication slot.
   */
  public async dropReplicationSlot(slotName: string): Promise<void> {
    validateSqlIdentifier(slotName, 'slotName');
    let client: pg.PoolClient;
    try {
      client = await this.pool.connect();
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.DATABASE_CONNECTION_ERROR,
        `Database connection failed: ${err.message}`,
        { cause: err }
      );
    }

    try {
      await client.query(`SELECT pg_drop_replication_slot($1);`, [slotName]);
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.QUERY_EXECUTION_ERROR,
        `Failed to drop logical replication slot "${slotName}": ${err.message}`,
        { cause: err }
      );
    } finally {
      client.release();
    }
  }

  /**
   * Creates a PostgreSQL publication for logical replication.
   */
  public async createPublication(pubName: string, tables: string[]): Promise<void> {
    validateSqlIdentifier(pubName, 'pubName');
    let client: pg.PoolClient;
    try {
      client = await this.pool.connect();
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.DATABASE_CONNECTION_ERROR,
        `Database connection failed: ${err.message}`,
        { cause: err }
      );
    }

    try {
      const tableList = tables.map((t) => {
        const [s, tbl] = t.includes('.') ? t.split('.') : ['public', t];
        return `"${validateSqlIdentifier(s!, 'schema')}"."${validateSqlIdentifier(tbl!, 'table')}"`;
      }).join(', ');

      await client.query(`DROP PUBLICATION IF EXISTS "${pubName}";`);
      await client.query(`CREATE PUBLICATION "${pubName}" FOR TABLE ${tableList};`);
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.QUERY_EXECUTION_ERROR,
        `Failed to create publication "${pubName}": ${err.message}`,
        { cause: err }
      );
    } finally {
      client.release();
    }
  }

  /**
   * Bootstraps the initial state snapshot S_0 across protected tables.
   */
  public async exportSnapshot(tables: string[] = this.protectedTables): Promise<BootstrapSnapshot> {
    let client: pg.PoolClient;
    try {
      client = await this.pool.connect();
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.DATABASE_CONNECTION_ERROR,
        `Database connection failed: ${err.message}`,
        { cause: err }
      );
    }

    try {
      const logicalClient = new PgLogicalClient({
        slotName: 'bootstrap_slot',
        plugin: 'pgoutput',
        protectedTables: tables,
      });
      return await logicalClient.bootstrapFromClient(client, tables);
    } finally {
      client.release();
    }
  }

  public async protectTable(schemaName: string, tableName: string, primaryKeyCols: string[]): Promise<void> {
    if (!primaryKeyCols || primaryKeyCols.length === 0) {
      throw new WolverineError(
        WolverineErrorCode.MISSING_PRIMARY_KEY,
        `Cannot protect table ${schemaName}.${tableName} without primary key columns`
      );
    }

    let client: pg.PoolClient;
    try {
      client = await this.pool.connect();
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.DATABASE_CONNECTION_ERROR,
        `Database connection failed: ${err.message}`,
        { cause: err }
      );
    }

    try {
      const triggerSql = generateTableTriggerSql(schemaName, tableName, primaryKeyCols);
      await client.query(triggerSql);
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.TRIGGER_INSTALLATION_ERROR,
        `Failed to install change capture trigger on ${schemaName}.${tableName}: ${err.message}`,
        { cause: err }
      );
    } finally {
      client.release();
    }
  }

  public async fetchPendingMutations(limit = 100): Promise<Array<{ mutationId: bigint; record: ChangeRecordData }>> {
    let client: pg.PoolClient;
    try {
      client = await this.pool.connect();
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.DATABASE_CONNECTION_ERROR,
        `Database connection failed: ${err.message}`,
        { cause: err }
      );
    }

    try {
      const res = await client.query(
        `SELECT mutation_id, table_name, record_id, op_type, new_data, old_data, created_at_us
         FROM wolverine_sys.pending_mutations
         ORDER BY mutation_id ASC
         LIMIT $1;`,
        [limit]
      );

      return res.rows.map((row: any) => {
        let operation: MutationOperation;
        const opStr = String(row.op_type).toUpperCase();
        if (opStr === 'INSERT' || opStr === '1') operation = MutationOperation.INSERT;
        else if (opStr === 'UPDATE' || opStr === '2') operation = MutationOperation.UPDATE;
        else if (opStr === 'DELETE' || opStr === '3') operation = MutationOperation.DELETE;
        else {
          throw new WolverineError(
            WolverineErrorCode.UNKNOWN_RECORD_TYPE,
            `Unknown mutation op_type: ${row.op_type}`
          );
        }

        const prevHash = Buffer.from(this.lastMutationHash);

        const changeRecordData: ChangeRecordData = {
          formatVersion: 1,
          versionId: row.mutation_id.toString(),
          transactionId: row.mutation_id.toString(),
          timestampUs: BigInt(row.created_at_us ?? Date.now() * 1000),
          tableId: row.table_name || row.scope || 'public.unknown',
          recordId: Buffer.from(row.record_id ?? '01', 'hex'),
          operation,
          fieldSet: {
            new: row.new_data ?? {},
            old: row.old_data ?? {},
          },
          provenance: {
            actorId: 'system_capture',
            serviceId: 'postgres_cdc',
          },
          previousHash: prevHash,
        };

        validateChangeRecordData(changeRecordData);

        const canonical = canonicalizeJson({
          versionId: changeRecordData.versionId,
          transactionId: changeRecordData.transactionId,
          timestampUs: changeRecordData.timestampUs.toString(),
          tableId: changeRecordData.tableId,
          recordId: changeRecordData.recordId.toString('hex'),
          operation: changeRecordData.operation,
          fieldSet: changeRecordData.fieldSet,
          provenance: changeRecordData.provenance,
          previousHash: prevHash.toString('hex'),
        });
        this.lastMutationHash = sha256(Buffer.from(`WDB:CHANGE:v1:${canonical}`, 'utf8'));

        return {
          mutationId: BigInt(row.mutation_id),
          record: changeRecordData,
        };
      });
    } catch (err: any) {
      if (err instanceof WolverineError) throw err;
      throw new WolverineError(
        WolverineErrorCode.QUERY_EXECUTION_ERROR,
        `Failed to fetch pending mutations: ${err.message}`,
        { cause: err }
      );
    } finally {
      client.release();
    }
  }

  public async markMutationsProcessed(mutationIds: bigint[]): Promise<void> {
    if (!mutationIds || mutationIds.length === 0) return;

    let client: pg.PoolClient;
    try {
      client = await this.pool.connect();
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.DATABASE_CONNECTION_ERROR,
        `Database connection failed: ${err.message}`,
        { cause: err }
      );
    }

    try {
      await client.query(
        `DELETE FROM wolverine_sys.pending_mutations WHERE mutation_id = ANY($1::bigint[]);`,
        [mutationIds.map((id) => id.toString())]
      );
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.QUERY_EXECUTION_ERROR,
        `Failed to mark mutations processed: ${err.message}`,
        { cause: err }
      );
    } finally {
      client.release();
    }
  }

  public getNonceStore(): PostgresNonceStore {
    return new PostgresNonceStore(this.pool);
  }

  public async isNonceConsumed(nonce: Buffer | string): Promise<boolean> {
    return this.getNonceStore().isConsumed(nonce);
  }

  public async recordConsumedNonce(
    nonce: Buffer | string,
    incidentId: string,
    approverPubkey: Buffer,
    client?: pg.PoolClient
  ): Promise<void> {
    return this.getNonceStore().recordConsumed(nonce, incidentId, approverPubkey, client);
  }

  public async close(): Promise<void> {
    await this.pool.end();
  }
}
