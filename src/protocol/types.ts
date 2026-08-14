/**
 * Data structures for WolverineDB Protocol Records
 */

export enum RecordType {
  CHANGE = 1,
  VERSION = 2,
  CHECKPOINT = 3,
  ANCHOR = 4,
  INCIDENT = 5,
  RECOVERY = 6,
}

export enum MutationOperation {
  INSERT = 1,
  UPDATE = 2,
  DELETE = 3,
}

export enum VersionStatus {
  ACTIVE = 1,
  SUPERSEDED = 2,
  RECOVERED = 3,
}

export interface ChangeRecordData {
  formatVersion: number; // 1
  versionId: string; // UUID string
  transactionId: string; // UTF8
  timestampUs: bigint; // I64 Unix microseconds UTC
  tableId: string; // "schema.table"
  recordId: Buffer; // Canonical Primary Key Tuple binary
  operation: MutationOperation;
  fieldSet: {
    new: Record<string, unknown> | null;
    old: Record<string, unknown> | null;
  };
  provenance: Record<string, unknown>;
  previousHash: Buffer; // 32 bytes SHA256
}

export interface VersionRecordData {
  versionId: string;
  parentVersionId: string;
  transactionId: string;
  commitTimestampUs: bigint;
  orderedChangeHashes: Buffer[];
  stateRoot: Buffer;
  status: VersionStatus;
}

export interface CheckpointRecordData {
  checkpointId: string;
  protectedScope: string;
  versionId: string;
  leafCount: number;
  merkleRoot: Buffer;
  timestampUs: bigint;
}
