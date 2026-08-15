import { PrimaryKeyField } from '../binary/record_id.js';

export interface WalColumnValue {
  name: string;
  typeTag?: number;
  value: any;
  isPrimaryKey?: boolean;
}

export interface WalRawMutation {
  action: 'I' | 'U' | 'D'; // Insert, Update, Delete
  schema: string;
  table: string;
  primaryKeyFields: PrimaryKeyField[];
  newValues: Record<string, unknown> | null;
  oldValues: Record<string, unknown> | null;
}

export interface WalTransactionBlock {
  xid: string;
  commitLsn: string;
  commitTimestampUs: bigint;
  mutations: WalRawMutation[];
}

export interface WalReceiverConfig {
  slotName: string;
  plugin?: 'test_decoding' | 'pgoutput' | 'wal2json';
  protectedTables: string[]; // ["schema.table"]
  startLsn?: string;
}

export interface WalAcknowledgment {
  confirmedFlushLsn: string;
  timestampUs: bigint;
}
