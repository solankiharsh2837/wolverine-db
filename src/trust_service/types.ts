import {
  TrustLedgerRecord,
} from '../trust_network/types.js';

export interface ByzantineValidatorConfig {
  validatorId: string;
  validatorSetId: string;
  epoch: number;
  port: number;
  host: string;
}

export interface SlashingEvidenceRecord {
  evidenceId: string;
  offendingValidatorId?: string | undefined;
  offendingGatewayId?: string | undefined;
  tenantId: string;
  databaseId: string;
  commitSeq: string;
  conflictingDigestHex1: string;
  conflictingDigestHex2: string;
  detectedAtUs: string;
  proofType: 'DOUBLE_SIGNING' | 'CONFLICTING_COMMITMENT' | 'FORGED_ATTESTATION';
}

export interface LedgerStateRootSnapshot {
  ledgerSeq: bigint;
  recordCount: number;
  merkleStateRoot: Buffer;
  chainHeadDigest: Buffer;
  timestampUs: bigint;
}

export interface IPersistentStorage {
  writeRecord(record: TrustLedgerRecord): Promise<void>;
  readAllRecords(): Promise<TrustLedgerRecord[]>;
  clear(): Promise<void>;
}
