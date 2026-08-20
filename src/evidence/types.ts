import { ChangeRecordData } from '../protocol/types.js';
import { PrimaryKeyField } from '../binary/record_id.js';

export interface BootstrapRow {
  tableName: string;
  primaryKeyFields: PrimaryKeyField[];
  values: Record<string, unknown>;
}

export interface BootstrapSnapshot {
  snapshotId: string;
  snapshotLsn: string;
  createdAtUs: bigint;
  schemaEpoch: number;
  tables: string[];
  rows: BootstrapRow[];
  initialStateMerkleRoot: Buffer;
}

export interface EvidenceJournalEntry {
  sequenceNumber: bigint;
  lsn: string;
  xid: string;
  timestampUs: bigint;
  changeRecord: ChangeRecordData;
  recordBytes: Buffer;
  changeHash: Buffer;
  previousHash: Buffer;
}

export interface EvidenceJournalHeader {
  magic: string; // "WDB:EV_JRNL:v1"
  formatVersion: number;
  createdAtUs: bigint;
  schemaEpoch: number;
}

export interface StateFrontierRow {
  tableName: string;
  primaryKeyTuple: Buffer;
  values: Record<string, unknown>;
  versionId: string;
  commitSeq: bigint;
  lsn: string;
  deleted: boolean;
}

export interface StateFrontierSnapshot {
  commitSeq: bigint;
  lsn: string;
  schemaEpoch: number;
  activeRowCount: number;
  stateMerkleRoot: Buffer;
  changeChainHead: Buffer;
  timestampUs: bigint;
}

export interface PgLogicalReplicationConfig {
  connectionString?: string;
  host?: string;
  port?: number;
  database?: string;
  user?: string;
  password?: string;
  slotName: string;
  publicationName?: string;
  plugin: 'pgoutput' | 'test_decoding' | 'wal2json';
  protectedTables: string[]; // ["schema.table"]
  startLsn?: string;
  standbyStatusIntervalMs?: number;
}

export type PgOutputMessage =
  | { type: 'B'; xid: string; commitLsn: string; commitTimeUs: bigint }
  | { type: 'C'; flags: number; commitLsn: string; endLsn: string; commitTimeUs: bigint }
  | { type: 'R'; relationId: number; schema: string; table: string; replicaIdentity: string; columns: PgOutputColumn[] }
  | { type: 'I'; relationId: number; tupleData: Record<string, unknown> }
  | { type: 'U'; relationId: number; keyTupleData?: Record<string, unknown>; oldTupleData?: Record<string, unknown>; tupleData: Record<string, unknown> }
  | { type: 'D'; relationId: number; keyTupleData?: Record<string, unknown>; oldTupleData?: Record<string, unknown> }
  | { type: 'T'; options: number; relationIds: number[] }
  | { type: 'S'; xid: string; firstSegment: number }
  | { type: 'E' }
  | { type: 'c'; xid: string; flags: number; commitLsn: string; endLsn: string; commitTimeUs: bigint }
  | { type: 'A'; xid: string; subxid: string };

export interface PgOutputColumn {
  flags: number; // 1 if part of key
  name: string;
  typeOid: number;
  typeModifier: number;
}
