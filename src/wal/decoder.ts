import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { WalTransactionBlock, WalRawMutation } from './types.js';
import { PrimaryKeyField } from '../binary/record_id.js';

export class WalDecoder {
  private currentXid: string | null = null;
  private currentLsn: string | null = null;
  private currentMutations: WalRawMutation[] = [];
  private inTransaction = false;

  /**
   * Resets the decoder state machine.
   */
  public reset(): void {
    this.currentXid = null;
    this.currentLsn = null;
    this.currentMutations = [];
    this.inTransaction = false;
  }

  /**
   * Ingests a raw logical decoding message (e.g. from test_decoding or wal2json).
   * Returns a completed WalTransactionBlock on COMMIT, or null if in-flight.
   */
  public processLine(line: string, fallbackTimestampUs: bigint = BigInt(Date.now()) * 1000n): WalTransactionBlock | null {
    const trimmed = line.trim();
    if (!trimmed) return null;

    // test_decoding pattern: "BEGIN 1001"
    if (trimmed.startsWith('BEGIN')) {
      const match = trimmed.match(/^BEGIN\s+(\d+)/);
      this.currentXid = match ? match[1] : 'unknown_xid';
      this.currentMutations = [];
      this.inTransaction = true;
      return null;
    }

    // test_decoding pattern: "COMMIT 1001 (at 2026-08-15 ...)" or "COMMIT"
    if (trimmed.startsWith('COMMIT')) {
      if (!this.inTransaction) {
        throw new WolverineError(
          WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
          'Encountered COMMIT without corresponding BEGIN in WAL stream'
        );
      }

      const block: WalTransactionBlock = {
        xid: this.currentXid || 'unknown_xid',
        commitLsn: this.currentLsn || '0/0',
        commitTimestampUs: fallbackTimestampUs,
        mutations: [...this.currentMutations],
      };

      this.reset();
      return block;
    }

    // test_decoding pattern: "ABORT" or "ROLLBACK"
    if (trimmed.startsWith('ABORT') || trimmed.startsWith('ROLLBACK')) {
      // Discard accumulated mutations immediately
      this.reset();
      return null;
    }

    // Parse DML lines from test_decoding:
    // "table public.users: INSERT: id[uuid]:'...' name[text]:'Alice'"
    // "table public.users: UPDATE: id[uuid]:'...' old-key: ... new-tuple: ..."
    // "table public.users: DELETE: id[uuid]:'...'"
    if (trimmed.startsWith('table ')) {
      const parsedMutation = this.parseTestDecodingMutation(trimmed);
      if (parsedMutation) {
        this.currentMutations.push(parsedMutation);
      }
      return null;
    }

    // Structured JSON / wal2json support
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const jsonMsg = JSON.parse(trimmed);
        return this.processJsonMessage(jsonMsg, fallbackTimestampUs);
      } catch (err: any) {
        throw new WolverineError(
          WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
          `Failed to parse WAL JSON message: ${err.message}`,
          { cause: err }
        );
      }
    }

    return null;
  }

  /**
   * Parses test_decoding text format for table DML
   */
  private parseTestDecodingMutation(line: string): WalRawMutation | null {
    // Example: "table public.accounts: INSERT: id[uuid]:'...' balance[numeric]:'100.00'"
    const match = line.match(/^table\s+([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+):\s+(INSERT|UPDATE|DELETE):\s*(.*)$/);
    if (!match) return null;

    const [, schema, table, opStr, dataStr] = match;
    const action = (opStr === 'INSERT' ? 'I' : opStr === 'UPDATE' ? 'U' : 'D') as 'I' | 'U' | 'D';

    const values: Record<string, unknown> = {};
    const pkFields: PrimaryKeyField[] = [];

    // Parse column tokens: "colname[type]:'val'" or "colname[type]:val"
    const colRegex = /([a-zA-Z0-9_]+)\[([a-zA-Z0-9_]+)\]:(?:'([^']*)'|(\S+))/g;
    let colMatch;

    while ((colMatch = colRegex.exec(dataStr)) !== null) {
      const colName = colMatch[1];
      const colType = colMatch[2].toLowerCase();
      const colVal = colMatch[3] !== undefined ? colMatch[3] : colMatch[4];

      values[colName] = colVal;

      if (colName === 'id' || colName.endsWith('_id') || colName === 'pk') {
        const pkBuf = Buffer.from(colVal, 'utf8');
        pkFields.push({
          name: colName,
          typeTag: colType === 'uuid' ? 4 : 5, // UTF8 / UUID
          valueBuffer: pkBuf,
        });
      }
    }

    // Default primary key fallback if none detected
    if (pkFields.length === 0 && Object.keys(values).length > 0) {
      const firstCol = Object.keys(values)[0];
      pkFields.push({
        name: firstCol,
        typeTag: 5,
        valueBuffer: Buffer.from(String(values[firstCol]), 'utf8'),
      });
    }

    return {
      action,
      schema,
      table,
      primaryKeyFields: pkFields,
      newValues: action !== 'D' ? values : null,
      oldValues: action !== 'I' ? values : null,
    };
  }

  /**
   * Processes structured JSON (wal2json) message format
   */
  private processJsonMessage(msg: any, fallbackTimestampUs: bigint): WalTransactionBlock | null {
    if (msg.xid && Array.isArray(msg.change)) {
      const mutations: WalRawMutation[] = [];

      for (const change of msg.change) {
        const kind = change.kind;
        const action = (kind === 'insert' ? 'I' : kind === 'update' ? 'U' : 'D') as 'I' | 'U' | 'D';
        const schema = change.schema;
        const table = change.table;

        const values: Record<string, unknown> = {};
        const pkFields: PrimaryKeyField[] = [];

        if (change.columnnames && change.columnvalues) {
          for (let i = 0; i < change.columnnames.length; i++) {
            const colName = change.columnnames[i];
            const colVal = change.columnvalues[i];
            values[colName] = colVal;

            if (colName === 'id' || (change.pk && change.pk.some((p: any) => p.name === colName))) {
              pkFields.push({
                name: colName,
                typeTag: 5,
                valueBuffer: Buffer.from(String(colVal), 'utf8'),
              });
            }
          }
        }

        if (pkFields.length === 0 && Object.keys(values).length > 0) {
          const firstCol = Object.keys(values)[0];
          pkFields.push({
            name: firstCol,
            typeTag: 5,
            valueBuffer: Buffer.from(String(values[firstCol]), 'utf8'),
          });
        }

        mutations.push({
          action,
          schema,
          table,
          primaryKeyFields: pkFields,
          newValues: action !== 'D' ? values : null,
          oldValues: action !== 'I' ? (change.oldkeys?.keyvalues ? change.oldkeys : null) : null,
        });
      }

      return {
        xid: String(msg.xid),
        commitLsn: msg.nextlsn || '0/0',
        commitTimestampUs: msg.timestamp ? BigInt(new Date(msg.timestamp).getTime()) * 1000n : fallbackTimestampUs,
        mutations,
      };
    }

    return null;
  }
}
