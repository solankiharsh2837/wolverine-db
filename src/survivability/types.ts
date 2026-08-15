import {
  TrustLedgerRecord,
} from '../trust_network/types.js';
import { ImmutableTrustReceipt } from '../bft_hardening/types.js';

export type DurabilityState =
  | 'HEALTHY'
  | 'DEGRADED'
  | 'PARTITIONED'
  | 'QUORUM_LOST'
  | 'LEDGER_RECOVERY'
  | 'VALIDATOR_RECOVERY'
  | 'EPOCH_TRANSITION'
  | 'CATASTROPHIC_PARTIAL_LOSS'
  | 'RECOVERED';

export type TrustSlaStatus =
  | 'TRUST_CURRENT'
  | 'TRUST_DEGRADED'
  | 'TRUST_PENDING'
  | 'TRUST_OUTAGE';

export interface ValidatorJournalRecord {
  validatorId: string;
  epoch: number;
  ledgerSeq: bigint;
  commitmentDigest: Buffer;
  previousLedgerDigest: Buffer;
  attestationDigest: Buffer;
  stateRoot: Buffer;
  validatorSetDigest: Buffer;
  timestampUs: bigint;
  journalRecordDigest: Buffer;
  previousRecordDigest: Buffer;
}

export interface LedgerSnapshot {
  snapshotId: string;
  epoch: number;
  snapshotLedgerSeq: bigint;
  stateRoot: Buffer;
  chainHeadDigest: Buffer;
  timestampUs: bigint;
  validatorSetDigest: Buffer;
  snapshotDigest: Buffer;
  records: TrustLedgerRecord[];
}

export interface LedgerRecoveryResult {
  isSuccess: boolean;
  snapshotDigest: Buffer;
  replayStartSeq: bigint;
  replayEndSeq: bigint;
  reconstructedStateRoot: Buffer;
  reconstructedLedgerDigest: Buffer;
  recoveryProofDigest: Buffer;
  error?: string | undefined;
}

export interface EpochTransitionCertificate {
  certificateId: string;
  oldEpoch: number;
  newEpoch: number;
  oldValidatorSetDigestHex: string;
  newValidatorSetDigestHex: string;
  transitionLedgerSeq: string;
  transitionReason: string;
  oldQuorumSignatures: Array<{ validatorId: string; signatureHex: string }>;
  newQuorumSignatures: Array<{ validatorId: string; signatureHex: string }>;
  certificateDigestHex: string;
}

export interface ValidatorStateProof {
  validatorId: string;
  ledgerSeq: bigint;
  ledgerStateRootHex: string;
  journalHeadDigestHex: string;
  epoch: number;
  validatorSetDigestHex: string;
  latestReceipt?: ImmutableTrustReceipt | undefined;
}

export interface TrustServiceStatus {
  trustStatus: TrustSlaStatus;
  lastFinalizedDatabaseSeq: bigint;
  latestObservedDatabaseSeq: bigint;
  pendingCommitments: number;
  lastFinalizedTrustSeq: bigint;
  currentEpoch: number;
  validatorQuorum: string;
  ledgerHealth: DurabilityState;
}
