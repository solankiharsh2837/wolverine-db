import pg from 'pg';
import { IApprovalNonceStore, formatNonceUuid } from '../engine/nonce_store.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export class PostgresNonceStore implements IApprovalNonceStore {
  private pool: pg.Pool;

  constructor(pool: pg.Pool) {
    this.pool = pool;
  }

  public async isConsumed(nonce: Buffer | string): Promise<boolean> {
    const nonceUuid = formatNonceUuid(nonce);
    let client: pg.PoolClient;
    try {
      client = await this.pool.connect();
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.DATABASE_CONNECTION_ERROR,
        `Database connection failed while checking nonce: ${err.message}`,
        { cause: err }
      );
    }

    try {
      const res = await client.query(
        `SELECT 1 FROM wolverine_sys.approval_nonces WHERE nonce = $1::uuid LIMIT 1;`,
        [nonceUuid]
      );
      return (res.rowCount ?? 0) > 0;
    } catch (err: any) {
      if (err instanceof WolverineError) throw err;
      throw new WolverineError(
        WolverineErrorCode.QUERY_EXECUTION_ERROR,
        `Failed to check approval nonce ${nonceUuid}: ${err.message}`,
        { cause: err }
      );
    } finally {
      client.release();
    }
  }

  public async recordConsumed(
    nonce: Buffer | string,
    incidentId: string,
    approverPubkey: Buffer,
    externalClient?: pg.PoolClient
  ): Promise<void> {
    const nonceUuid = formatNonceUuid(nonce);
    const incidentUuid = formatNonceUuid(incidentId);

    const client = externalClient ?? (await this.pool.connect());
    const isOwnedClient = !externalClient;

    try {
      await client.query(
        `INSERT INTO wolverine_sys.approval_nonces (nonce, incident_id, approver_pubkey)
         VALUES ($1::uuid, $2::uuid, $3::bytea);`,
        [nonceUuid, incidentUuid, approverPubkey]
      );
    } catch (err: any) {
      // 23505 is PostgreSQL unique_violation code
      if (err.code === '23505' || err.message?.includes('duplicate key') || err.message?.includes('unique constraint')) {
        throw new WolverineError(
          WolverineErrorCode.REPLAYED_APPROVAL_NONCE,
          `Approval nonce ${nonceUuid} has already been consumed (durable constraint violation)`,
          { cause: err }
        );
      }
      if (err instanceof WolverineError) throw err;
      throw new WolverineError(
        WolverineErrorCode.QUERY_EXECUTION_ERROR,
        `Failed to record consumed approval nonce ${nonceUuid}: ${err.message}`,
        { cause: err }
      );
    } finally {
      if (isOwnedClient) {
        client.release();
      }
    }
  }
}
