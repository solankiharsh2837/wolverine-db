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

interface ActiveTxContext {
  xid: string;
  commitLsn: string;
  commitLsnBig: bigint;
  commitTimeUs: bigint;
  mutations: WalRawMutation[];
  isStreaming?: boolean;
}

export class PgLogicalClient extends EventEmitter {
  private config: PgLogicalReplicationConfig;
  private pgOutputDecoder: PgOutputDecoder;
  private walNormalizer: WalNormalizer;
  private evidenceJournal?: DurableEvidenceJournal;
  private stateFrontier?: DeterministicStateFrontier;

  // Fully isolated per-XID transaction map (no single shared mutable currentXid)
  private activeTransactions = new Map<string, ActiveTxContext>();
  private activeXidStack: string[] = [];
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
   * Bootstraps baseline state S_0 from a PostgreSQL client snapshot.
   */
  public async bootstrapFromClient(client: pg.ClientBase, tables: string[]): Promise<BootstrapSnapshot> {
    const bootstrapRows: BootstrapRow[] = [];
    const snapshotId = `snap-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;

    const lsnResult = await client.query('SELECT pg_current_wal_lsn() as lsn');
    const currentLsn = lsnResult.rows[0]?.lsn || '0/0';
    const lsnBig = this.parseLsnToBigInt(currentLsn);

    for (const tableFullName of tables) {
      const [schema, table] = tableFullName.includes('.') ? tableFullName.split('.') : ['public', tableFullName];

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
   * Ingests a raw pgoutput binary message buffer with per-transaction isolation.
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

        if (this.lastFlushedLsnBig > 0n && commitLsnBig < this.lastFlushedLsnBig) {
          this.isHalted = true;
          this.haltReason = `LSN_DISCONTINUITY_ERROR: Transaction LSN ${msg.commitLsn} regressed behind confirmed LSN ${this.lastFlushedLsnStr}`;
          throw new WolverineError(
            WolverineErrorCode.LSN_DISCONTINUITY_ERROR,
            this.haltReason
          );
        }

        const ctx: ActiveTxContext = {
          xid: msg.xid,
          commitLsn: msg.commitLsn,
          commitLsnBig,
          commitTimeUs: msg.commitTimeUs,
          mutations: [],
        };
        this.activeTransactions.set(msg.xid, ctx);
        this.activeXidStack.push(msg.xid);
        return null;
      }

      case 'S': {
        // Stream Start
        if (!this.activeTransactions.has(msg.xid)) {
          this.activeTransactions.set(msg.xid, {
            xid: msg.xid,
            commitLsn: this.lastFlushedLsnStr,
            commitLsnBig: this.lastFlushedLsnBig,
            commitTimeUs: BigInt(Date.now()) * 1000n,
            mutations: [],
            isStreaming: true,
          });
          this.activeXidStack.push(msg.xid);
        }
        return null;
      }

      case 'E': {
        // Stream Stop
        return null;
      }

      case 'A': {
        // Stream Abort
        this.abortTransaction(msg.xid);
        return null;
      }

      case 'R': {
        return null;
      }

      case 'I': {
        const targetXid = this.resolveActiveXid();
        const tx = this.activeTransactions.get(targetXid);
        if (!tx) {
          throw new WolverineError(WolverineErrorCode.MALFORMED_FIELD_PAYLOAD, 'Insert received outside transaction');
        }

        const rel = this.pgOutputDecoder.getRelation(msg.relationId);
        if (!rel) {
          throw new WolverineError(WolverineErrorCode.MALFORMED_FIELD_PAYLOAD, `Relation ${msg.relationId} not found`);
        }

        const pkFields = this.pgOutputDecoder.extractPrimaryKeyFields(rel, msg.tupleData);
        tx.mutations.push({
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
        const targetXid = this.resolveActiveXid();
        const tx = this.activeTransactions.get(targetXid);
        if (!tx) {
          throw new WolverineError(WolverineErrorCode.MALFORMED_FIELD_PAYLOAD, 'Update received outside transaction');
        }

        const rel = this.pgOutputDecoder.getRelation(msg.relationId);
        if (!rel) {
          throw new WolverineError(WolverineErrorCode.MALFORMED_FIELD_PAYLOAD, `Relation ${msg.relationId} not found`);
        }

        const pkFields = this.pgOutputDecoder.extractPrimaryKeyFields(rel, msg.tupleData);
        tx.mutations.push({
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
        const targetXid = this.resolveActiveXid();
        const tx = this.activeTransactions.get(targetXid);
        if (!tx) {
          throw new WolverineError(WolverineErrorCode.MALFORMED_FIELD_PAYLOAD, 'Delete received outside transaction');
        }

        const rel = this.pgOutputDecoder.getRelation(msg.relationId);
        if (!rel) {
          throw new WolverineError(WolverineErrorCode.MALFORMED_FIELD_PAYLOAD, `Relation ${msg.relationId} not found`);
        }

        const data = msg.oldTupleData || msg.keyTupleData || {};
        const pkFields = this.pgOutputDecoder.extractPrimaryKeyFields(rel, data);
        tx.mutations.push({
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
        // Commit for non-streaming or top-of-stack transaction
        const targetXid = this.activeXidStack.pop() || '';
        const tx = this.activeTransactions.get(targetXid);
        this.activeTransactions.delete(targetXid);

        if (!tx || tx.mutations.length === 0) {
          return [];
        }

        return this.flushCommittedTransaction(targetXid, msg.commitLsn, msg.commitTimeUs, tx.mutations, versionId);
      }

      case 'c': {
        // Stream Commit
        const tx = this.activeTransactions.get(msg.xid);
        this.activeTransactions.delete(msg.xid);
        this.activeXidStack = this.activeXidStack.filter((id) => id !== msg.xid);

        if (!tx || tx.mutations.length === 0) {
          return [];
        }

        return this.flushCommittedTransaction(msg.xid, msg.commitLsn, msg.commitTimeUs, tx.mutations, versionId);
      }

      case 'T': {
        return null;
      }
    }
  }

  private resolveActiveXid(): string {
    if (this.activeXidStack.length === 0) {
      throw new WolverineError(WolverineErrorCode.MALFORMED_FIELD_PAYLOAD, 'No active transaction in context');
    }
    return this.activeXidStack[this.activeXidStack.length - 1]!;
  }

  private async flushCommittedTransaction(
    xid: string,
    commitLsn: string,
    commitTimeUs: bigint,
    mutations: WalRawMutation[],
    versionId: string
  ): Promise<NormalizedWalChange[]> {
    const block: WalTransactionBlock = {
      xid,
      commitLsn,
      commitTimestampUs: commitTimeUs,
      mutations,
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
    this.lastFlushedLsnStr = commitLsn;
    this.lastFlushedLsnBig = this.parseLsnToBigInt(commitLsn);

    if (this.evidenceJournal) {
      for (let i = 0; i < normalized.length; i++) {
        const item = normalized[i]!;
        await this.evidenceJournal.append({
          sequenceNumber: this.currentSeq,
          lsn: commitLsn,
          xid,
          timestampUs: commitTimeUs,
          changeRecord: item.changeRecordData,
          recordBytes: item.recordBytes,
          changeHash: item.changeHash,
          previousHash: item.changeRecordData.previousHash,
        });
      }
    }

    if (this.stateFrontier) {
      const changeRecords = normalized.map((n) => n.changeRecordData);
      const lastHash = normalized[normalized.length - 1]!.changeHash;
      this.stateFrontier.applyChangeRecords(changeRecords, commitLsn, this.currentSeq, lastHash);
    }

    this.emit('transaction', { block, changes: normalized });
    return normalized;
  }

  public reportSlotLoss(reason: string): void {
    this.isHalted = true;
    this.haltReason = `SLOT_LOST: ${reason}`;
    this.activeTransactions.clear();
    this.activeXidStack = [];
    this.emit('slot_lost', { reason: this.haltReason });
  }

  public resynchronizeWithSnapshot(newSnapshot: BootstrapSnapshot): void {
    this.activeTransactions.clear();
    this.activeXidStack = [];
    this.lastFlushedLsnStr = newSnapshot.snapshotLsn;
    this.lastFlushedLsnBig = this.parseLsnToBigInt(newSnapshot.snapshotLsn);
    this.isHalted = false;
    this.haltReason = undefined;

    if (this.stateFrontier) {
      this.stateFrontier.bootstrap(newSnapshot);
    }

    this.emit('resynchronized', { snapshot: newSnapshot });
  }

  public abortTransaction(xid: string): void {
    this.activeTransactions.delete(xid);
    this.activeXidStack = this.activeXidStack.filter((id) => id !== xid);
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
