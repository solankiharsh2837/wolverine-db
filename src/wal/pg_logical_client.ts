import { EventEmitter } from 'node:events';
import pg from 'pg';
import { PgLogicalReplicationConfig, BootstrapSnapshot, BootstrapRow } from '../evidence/types.js';
import { WalTransactionBlock, WalRawMutation } from './types.js';
import { PgOutputDecoder } from './pgoutput_decoder.js';
import { WalNormalizer, NormalizedWalChange } from './normalizer.js';
import { DurableEvidenceJournal } from '../evidence/journal.js';
import { DeterministicStateFrontier } from '../evidence/state_frontier.js';
import { PrimaryKeyField } from '../binary/record_id.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export class PgLogicalClient extends EventEmitter {
  private config: PgLogicalReplicationConfig;
  private pgOutputDecoder: PgOutputDecoder;
  private walNormalizer: WalNormalizer;
  private evidenceJournal?: DurableEvidenceJournal;
  private stateFrontier?: DeterministicStateFrontier;

  private activeTransactions = new Map<string, { commitLsn: string; commitLsnBig: bigint; commitTimeUs: bigint; mutations: WalRawMutation[] }>();
  private currentXid: string | null = null;
  private lastFlushedLsnStr: string = '0/0';
  private lastFlushedLsnBig: bigint = 0n;
  private currentSeq: bigint = 0n;
  private isHalted: boolean = false;
  private haltReason?: string;

  constructor(
    config: PgLogicalReplicationConfig,
    journal?: DurableEvidenceJournal,
    frontier?: DeterministicStateFrontier
  ) {
    super();
    this.config = config;
    this.pgOutputDecoder = new PgOutputDecoder();
    this.walNormalizer = new WalNormalizer();
    this.evidenceJournal = journal;
    this.stateFrontier = frontier;
    if (config.startLsn) {
      this.lastFlushedLsnStr = config.startLsn;
      this.lastFlushedLsnBig = this.parseLsnToBigInt(config.startLsn);
    }
  }

  public get confirmedLsn(): string {
    return this.lastFlushedLsnStr;
  }

  public get confirmedLsnBig(): bigint {
    return this.lastFlushedLsnBig;
  }

  public get activeXidCount(): number {
    return this.activeTransactions.size;
  }

  public get isHaltedState(): boolean {
    return this.isHalted;
  }

  public get currentHaltReason(): string | undefined {
    return this.haltReason;
  }

  /**
   * Bootstraps the baseline state S_0 from a real PostgreSQL client snapshot.
   */
  public async bootstrapFromClient(client: pg.ClientBase, tables: string[]): Promise<BootstrapSnapshot> {
    const bootstrapRows: BootstrapRow[] = [];
    const snapshotId = `snap-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;

    // Query current LSN
    const lsnResult = await client.query('SELECT pg_current_wal_lsn() as lsn');
    const currentLsn = lsnResult.rows[0]?.lsn || '0/0';
    const lsnBig = this.parseLsnToBigInt(currentLsn);

    for (const tableFullName of tables) {
      const [schema, table] = tableFullName.includes('.') ? tableFullName.split('.') : ['public', tableFullName];

      // Query primary key columns
      const pkQuery = `
        SELECT kcu.column_name, c.data_type, c.udt_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
          ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
        JOIN information_schema.columns c
          ON c.table_schema = kcu.table_schema AND c.table_name = kcu.table_name AND c.column_name = kcu.column_name
        WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = $1 AND tc.table_name = $2
        ORDER BY kcu.ordinal_position;
      `;
      const pkRes = await client.query(pkQuery, [schema, table]);
      const pkColNames = pkRes.rows.map((r: any) => r.column_name);

      // Select all live rows
      const dataRes = await client.query(`SELECT * FROM "${schema}"."${table}"`);

      for (const row of dataRes.rows) {
        const pkFields: PrimaryKeyField[] = [];

        if (pkColNames.length > 0) {
          for (const colName of pkColNames) {
            const val = row[colName];
            pkFields.push({
              name: colName,
              typeTag: 5,
              valueBuffer: Buffer.from(String(val !== undefined && val !== null ? val : ''), 'utf8'),
            });
          }
        } else {
          // Default first column
          const firstCol = Object.keys(row)[0] || 'id';
          pkFields.push({
            name: firstCol,
            typeTag: 5,
            valueBuffer: Buffer.from(String(row[firstCol] || ''), 'utf8'),
          });
        }

        bootstrapRows.push({
          tableName: tableFullName,
          primaryKeyFields: pkFields,
          values: row,
        });
      }
    }

    const snapshot: BootstrapSnapshot = {
      snapshotId,
      snapshotLsn: currentLsn,
      createdAtUs: BigInt(Date.now()) * 1000n,
      schemaEpoch: 1,
      tables,
      rows: bootstrapRows,
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    };

    if (this.stateFrontier) {
      const frontierSnap = this.stateFrontier.bootstrap(snapshot);
      snapshot.initialStateMerkleRoot = frontierSnap.stateMerkleRoot;
    }

    this.lastFlushedLsnStr = currentLsn;
    this.lastFlushedLsnBig = lsnBig;
    this.isHalted = false;
    this.haltReason = undefined;

    this.emit('bootstrap', { snapshot });
    return snapshot;
  }

  /**
   * Ingests a raw pgoutput binary message buffer.
   */
  public async ingestPgOutputMessage(
    buffer: Buffer,
    versionId: string = '00000000-0000-0000-0000-000000000001'
  ): Promise<NormalizedWalChange[] | null> {
    if (this.isHalted) {
      throw new WolverineError(
        WolverineErrorCode.SLOT_INVALIDATED,
        `[SLOT_INVALIDATED] Cannot ingest logical replication message: client is halted due to ${this.haltReason}`
      );
    }

    const msg = this.pgOutputDecoder.decodeMessage(buffer);

    switch (msg.type) {
      case 'B': {
        const commitLsnBig = this.parseLsnToBigInt(msg.commitLsn);

        // Strict LSN Continuity Verification
        if (this.lastFlushedLsnBig > 0n && commitLsnBig < this.lastFlushedLsnBig) {
          this.isHalted = true;
          this.haltReason = `LSN_DISCONTINUITY_ERROR: Transaction LSN ${msg.commitLsn} regressed behind confirmed LSN ${this.lastFlushedLsnStr}`;
          throw new WolverineError(
            WolverineErrorCode.LSN_DISCONTINUITY_ERROR,
            this.haltReason
          );
        }

        this.currentXid = msg.xid;
        this.activeTransactions.set(msg.xid, {
          commitLsn: msg.commitLsn,
          commitLsnBig,
          commitTimeUs: msg.commitTimeUs,
          mutations: [],
        });
        return null;
      }

      case 'R': {
        // Relation metadata is cached by decoder
        return null;
      }

      case 'I': {
        if (!this.currentXid || !this.activeTransactions.has(this.currentXid)) {
          throw new WolverineError(WolverineErrorCode.MALFORMED_FIELD_PAYLOAD, 'Insert received outside transaction');
        }
        const rel = this.pgOutputDecoder.getRelation(msg.relationId);
        if (!rel) {
          throw new WolverineError(WolverineErrorCode.MALFORMED_FIELD_PAYLOAD, `Relation ${msg.relationId} not found`);
        }

        const pkFields = this.pgOutputDecoder.extractPrimaryKeyFields(rel, msg.tupleData);
        this.activeTransactions.get(this.currentXid)!.mutations.push({
          action: 'I',
          schema: rel.schema,
          table: rel.table,
          primaryKeyFields: pkFields,
          newValues: msg.tupleData,
          oldValues: null,
        });
        return null;
      }

      case 'U': {
        if (!this.currentXid || !this.activeTransactions.has(this.currentXid)) {
          throw new WolverineError(WolverineErrorCode.MALFORMED_FIELD_PAYLOAD, 'Update received outside transaction');
        }
        const rel = this.pgOutputDecoder.getRelation(msg.relationId);
        if (!rel) {
          throw new WolverineError(WolverineErrorCode.MALFORMED_FIELD_PAYLOAD, `Relation ${msg.relationId} not found`);
        }

        const pkFields = this.pgOutputDecoder.extractPrimaryKeyFields(rel, msg.tupleData);
        this.activeTransactions.get(this.currentXid)!.mutations.push({
          action: 'U',
          schema: rel.schema,
          table: rel.table,
          primaryKeyFields: pkFields,
          newValues: msg.tupleData,
          oldValues: msg.oldTupleData || msg.keyTupleData || null,
        });
        return null;
      }

      case 'D': {
        if (!this.currentXid || !this.activeTransactions.has(this.currentXid)) {
          throw new WolverineError(WolverineErrorCode.MALFORMED_FIELD_PAYLOAD, 'Delete received outside transaction');
        }
        const rel = this.pgOutputDecoder.getRelation(msg.relationId);
        if (!rel) {
          throw new WolverineError(WolverineErrorCode.MALFORMED_FIELD_PAYLOAD, `Relation ${msg.relationId} not found`);
        }

        const data = msg.oldTupleData || msg.keyTupleData || {};
        const pkFields = this.pgOutputDecoder.extractPrimaryKeyFields(rel, data);
        this.activeTransactions.get(this.currentXid)!.mutations.push({
          action: 'D',
          schema: rel.schema,
          table: rel.table,
          primaryKeyFields: pkFields,
          newValues: null,
          oldValues: data,
        });
        return null;
      }

      case 'C': {
        const tx = this.activeTransactions.get(this.currentXid || '');
        const xid = this.currentXid || 'unknown';
        this.activeTransactions.delete(xid);
        this.currentXid = null;

        if (!tx || tx.mutations.length === 0) {
          return [];
        }

        const block: WalTransactionBlock = {
          xid,
          commitLsn: msg.commitLsn,
          commitTimestampUs: msg.commitTimeUs,
          mutations: tx.mutations,
        };

        const prevChainHead = this.evidenceJournal
          ? this.evidenceJournal.chainHead
          : this.stateFrontier?.chainHead || Buffer.alloc(32, 0);

        const normalized = this.walNormalizer.normalizeTransaction(
          block,
          versionId,
          prevChainHead,
          this.config.protectedTables
        );

        this.currentSeq++;
        this.lastFlushedLsnStr = msg.commitLsn;
        this.lastFlushedLsnBig = this.parseLsnToBigInt(msg.commitLsn);

        // Append to durable evidence journal
        if (this.evidenceJournal) {
          for (let i = 0; i < normalized.length; i++) {
            const item = normalized[i]!;
            await this.evidenceJournal.append({
              sequenceNumber: this.currentSeq,
              lsn: msg.commitLsn,
              xid,
              timestampUs: msg.commitTimeUs,
              changeRecord: item.changeRecordData,
              recordBytes: item.recordBytes,
              changeHash: item.changeHash,
              previousHash: item.changeRecordData.previousHash,
            });
          }
        }

        // Apply to state frontier
        if (this.stateFrontier) {
          const changeRecords = normalized.map((n) => n.changeRecordData);
          const lastHash = normalized[normalized.length - 1]!.changeHash;
          this.stateFrontier.applyChangeRecords(changeRecords, msg.commitLsn, this.currentSeq, lastHash);
        }

        this.emit('transaction', { block, changes: normalized });
        return normalized;
      }

      case 'T': {
        // Truncate
        return null;
      }
    }
  }

  /**
   * Reports that the replication slot was lost, invalidated, or dropped.
   * Immediately halts processing to prevent silent or fabricated continuity.
   */
  public reportSlotLoss(reason: string): void {
    this.isHalted = true;
    this.haltReason = `SLOT_LOST: ${reason}`;
    this.activeTransactions.clear();
    this.currentXid = null;
    this.emit('slot_lost', { reason: this.haltReason });
  }

  /**
   * Resynchronizes the client and state frontier from a fresh baseline snapshot after slot loss.
   */
  public resynchronizeWithSnapshot(newSnapshot: BootstrapSnapshot): void {
    this.activeTransactions.clear();
    this.currentXid = null;
    this.lastFlushedLsnStr = newSnapshot.snapshotLsn;
    this.lastFlushedLsnBig = this.parseLsnToBigInt(newSnapshot.snapshotLsn);
    this.isHalted = false;
    this.haltReason = undefined;

    if (this.stateFrontier) {
      this.stateFrontier.bootstrap(newSnapshot);
    }

    this.emit('resynchronized', { snapshot: newSnapshot });
  }

  /**
   * Aborts an active transaction and purges buffered mutations.
   */
  public abortTransaction(xid: string): void {
    this.activeTransactions.delete(xid);
    if (this.currentXid === xid) {
      this.currentXid = null;
    }
    this.emit('abort', { xid });
  }

  public registerRelation(metadata: { relationId: number; schema: string; table: string; replicaIdentity: string; columns: any[] }): void {
    this.pgOutputDecoder.registerRelation(metadata);
  }

  private parseLsnToBigInt(lsnStr: string): bigint {
    const parts = lsnStr.split('/');
    if (parts.length !== 2) return 0n;
    const high = BigInt(`0x${parts[0]!}`);
    const low = BigInt(`0x${parts[1]!}`);
    return (high << 32n) | low;
  }
}
