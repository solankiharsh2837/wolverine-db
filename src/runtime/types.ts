import {
  TrustCommitment,
  ValidatorAttestation,
  TrustLedgerRecord,
} from '../trust_network/types.js';

export interface ValidatorNodeConfig {
  validatorId: string;
  validatorSetId: string;
  port: number;
  host: string;
  publicKeyHex: string;
}

export interface LedgerReplicaConfig {
  replicaId: string;
  port: number;
  host: string;
  role: 'PRIMARY' | 'BACKUP' | 'AUDIT';
}

export interface TrustGatewayConfig {
  gatewayId: string;
  port: number;
  host: string;
  requiredQuorum: number;
  totalValidators: number;
  validatorEndpoints: Array<{ validatorId: string; endpoint: string }>;
  replicaEndpoints: Array<{ replicaId: string; endpoint: string }>;
}

export interface AttestRpcRequest {
  commitment: TrustCommitment;
  tenantPubkeyHex: string;
}

export interface AttestRpcResponse {
  success: boolean;
  attestation?: ValidatorAttestation | undefined;
  error?: string | undefined;
}

export interface ReplicateRecordRpcRequest {
  record: TrustLedgerRecord;
}

export interface ReplicateRecordRpcResponse {
  success: boolean;
  acknowledgedSeq: string;
  error?: string | undefined;
}

export interface TrustTimeRecord {
  databaseId: string;
  commitSeq: bigint;
  checkpointId: string;
  checkpointDigestHex: string;
  ledgerSeq: bigint;
  epoch: number;
  finalizedAtUs: bigint;
  quorumDigestHex: string;
}

export type PeerFailureReason =
  | 'TIMEOUT'
  | 'UNREACHABLE'
  | 'PEER_REJECTED'
  | 'MALFORMED_RESPONSE'
  | 'AUTH_FAILURE'
  | 'INTERNAL_ERROR';

export interface PeerFailureRecord {
  peerId: string;
  endpoint: string;
  reason: PeerFailureReason;
  errorMessage: string;
  timestampUs: bigint;
}
