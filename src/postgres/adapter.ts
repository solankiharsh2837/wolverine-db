import pg from 'pg';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { CREATE_WOLVERINE_SYS_SCHEMA_SQL } from './schema.js';
import { generateTableTriggerSql } from './triggers.js';

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
    const client = await this.pool.connect();
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

    const client = await this.pool.connect();
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

  public async close(): Promise<void> {
    await this.pool.end();
  }
}
