import { SecurityEventEnvelope } from '../fabric/types.js';

export type NodeTrustStatus = 'TRUSTED' | 'DEGRADED' | 'QUARANTINED' | 'REVOKED';

export type NodeCapability =
  | 'DATABASE_MUTATION_CAPTURE'
  | 'RUNTIME_EXECUTION_OBSERVER'
  | 'AEGIS_THREAT_ANALYTICS'
  | 'SENTINEL_ADVISORY_ENGINE'
  | 'POLICY_GATEKEEPER'
  | 'RECOVERY_EXECUTOR';

export interface NodeIdentity {
  nodeId: string;
  publicKey: Buffer; // 32 bytes Ed25519
  capabilities: NodeCapability[];
  creationEpochUs: bigint;
  organizationId: string;
  clusterId: string;
  status: NodeTrustStatus;
  attestationSignature: Buffer; // 64 bytes
}

export interface FederatedEventEnvelope {
  event: SecurityEventEnvelope;
  originNodeId: string;
  nodeSequence: bigint;
  previousEventHash: Buffer; // 32 bytes
  eventChainHash: Buffer; // 32 bytes
  nodeSignature: Buffer; // 64 bytes
}

export interface NodeCheckpointAttestation {
  nodeId: string;
  checkpointId: string;
  checkpointDigest: Buffer; // 32 bytes
  commitSeq: bigint;
  merkleRoot: Buffer; // 32 bytes
  timestampUs: bigint;
  signature: Buffer; // 64 bytes
}

export interface FederatedConsensusPolicy {
  requiredQuorum: number; // M
  totalNodes: number;     // N
}

export type FederatedConsensusVerdict =
  | 'FEDERATION_CONSENSUS_VALID'
  | 'FEDERATION_CONSENSUS_DEGRADED'
  | 'FEDERATION_CONSENSUS_DIVERGENCE'
  | 'FEDERATION_CONSENSUS_INDETERMINATE';

export interface NodeQuarantineRecord {
  nodeId: string;
  quarantineEpochUs: bigint;
  reason:
    | 'INVALID_EVENT_SIGNATURE'
    | 'DIVERGENT_CHECKPOINT_ATTESTATION'
    | 'IMPOSSIBLE_EVENT_SEQUENCE'
    | 'ANOMALOUS_RECOVERY_ATTEMPT'
    | 'ADMINISTRATIVE_ISOLATION';
  lastValidEventSequence: bigint;
  lastValidEventHash: Buffer;
  lastValidCheckpointId?: string | undefined;
  triggeringEvidence: Record<string, unknown>;
  quarantineAuthority: string;
}

export interface FederatedRecoveryAuthorizationRequest {
  proposalId: string;
  incidentId: string;
  protectedScope: string;
  proposedChangesHash: Buffer;
  proposingNodeId: string;
  signatures: Array<{
    nodeId: string;
    signature: Buffer; // 64 bytes
  }>;
}
