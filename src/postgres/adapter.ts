import pg from 'pg';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { CREATE_WOLVERINE_SYS_SCHEMA_SQL } from './schema.js';
import { generateTableTriggerSql } from './triggers.js';
import { ChangeRecordData, MutationOperation } from '../protocol/types.js';
import { validateChangeRecordData } from '../protocol/validators.js';
import { PostgresNonceStore } from './nonce_store.js';

export interface DatabaseConfig {
  connectionString: string;
  protectedTables: string[];
}

export class PostgresAdapter {
  private pool: pg.Pool;
  public readonly protectedTables: string[];

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
        if (row.op_type === 'INSERT') operation = MutationOperation.INSERT;
        else if (row.op_type === 'UPDATE') operation = MutationOperation.UPDATE;
        else if (row.op_type === 'DELETE') operation = MutationOperation.DELETE;
        else {
          throw new WolverineError(
            WolverineErrorCode.UNKNOWN_RECORD_TYPE,
            `Unknown mutation op_type: ${row.op_type}`
          );
        }

        const changeRecordData: ChangeRecordData = {
          formatVersion: 1,
          versionId: row.mutation_id.toString(),
          transactionId: row.mutation_id.toString(),
          timestampUs: BigInt(row.created_at_us ?? Date.now() * 1000),
          tableId: row.table_name,
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
          previousHash: Buffer.alloc(32, 0),
        };

        // Mandatory Schema & Semantic Validation
        validateChangeRecordData(changeRecordData);

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
