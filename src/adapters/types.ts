import { ChangeRecordData, MutationOperation } from '../protocol/types.js';
import { PrimaryKeyField } from '../binary/record_id.js';

export interface DatabaseMutationEvent {
  engine: 'postgresql' | 'mysql' | 'sqlite';
  schema: string;
  table: string;
  operation: MutationOperation;
  primaryKeyFields: PrimaryKeyField[];
  newValues: Record<string, unknown> | null;
  oldValues: Record<string, unknown> | null;
  txId: string;
  commitTimestampUs: bigint;
}

export interface UniversalDatabaseAdapter {
  readonly engineName: 'postgresql' | 'mysql' | 'sqlite';
  normalizeMutation(
    event: DatabaseMutationEvent,
    versionId: string,
    previousHash: Buffer
  ): {
    changeRecordData: ChangeRecordData;
    recordBytes: Buffer;
    changeHash: Buffer;
  };
}
