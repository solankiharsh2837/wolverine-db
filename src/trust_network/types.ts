export interface TrustCommitment {
  commitmentId: string;
  tenantId: string;
  databaseId: string;
  checkpointId: string;
  commitSeq: bigint;
  checkpointDigest: Buffer; // 32 bytes SHA-256
  previousTrustCommitment: Buffer; // 32 bytes SHA-256
  protocolVersion: number;
  logicalTimestamp: bigint;
  ingestionTimestamp?: bigint | undefined;
  epoch: number;
  validatorSetId: string;
  customerPubkey: Buffer; // 32 bytes Ed25519 public key
  customerSignature: Buffer; // 64 bytes Ed25519 signature
  commitmentDigest: Buffer; // 32 bytes SHA-256
}

export type TrustLedgerRecordType =
  | 'COMMITMENT'
  | 'ATTESTATION'
  | 'FINALIZATION'
  | 'REVOCATION'
  | 'EPOCH_CHANGE'
  | 'VALIDATOR_SET_CHANGE';

export interface TrustLedgerRecord {
  recordType: TrustLedgerRecordType;
  ledgerSeq: bigint;
  epoch: number;
  validatorSetId: string;
  tenantId?: string | undefined;
  databaseId?: string | undefined;
  payload: Record<string, unknown>;
  previousRecordDigest: Buffer; // 32 bytes SHA-256
  recordDigest: Buffer; // 32 bytes SHA-256
  timestampUs: bigint;
}

export interface ValidatorAttestation {
  commitmentId: string;
  validatorId: string;
  validatorSetId: string;
  observedCommitmentDigest: Buffer; // 32 bytes SHA-256
  attestationSequence: bigint;
  timestampUs: bigint;
  signature: Buffer; // 64 bytes Ed25519 signature
}

export interface QuorumCertificate {
  commitmentId: string;
  commitmentDigest: Buffer; // 32 bytes SHA-256
  validatorSetId: string;
  epoch: number;
  attestations: ValidatorAttestation[];
  quorumCount: number;
  totalValidators: number;
  finalityStatus: 'FINALIZED';
  finalizedAtUs: bigint;
  certificateDigest: Buffer; // 32 bytes SHA-256
}

export interface PortableTrustProof {
  proofVersion: number;
  tenantId: string;
  databaseId: string;
  commitment: {
    commitmentId: string;
    checkpointId: string;
    commitSeq: string;
    checkpointDigestHex: string;
    previousTrustCommitmentHex: string;
    protocolVersion: number;
    logicalTimestamp: string;
    epoch: number;
    validatorSetId: string;
    customerPubkeyHex: string;
    customerSignatureHex: string;
    commitmentDigestHex: string;
  };
  validatorSet: Array<{
    validatorId: string;
    publicKeyHex: string;
  }>;
  quorumCertificate: {
    commitmentId: string;
    commitmentDigestHex: string;
    validatorSetId: string;
    epoch: number;
    quorumCount: number;
    totalValidators: number;
    finalizedAtUs: string;
    certificateDigestHex: string;
  };
  validatorAttestations: Array<{
    validatorId: string;
    observedCommitmentDigestHex: string;
    signatureHex: string;
    timestampUs: string;
  }>;
  ledgerRecord: {
    ledgerSeq: string;
    previousRecordDigestHex: string;
    recordDigestHex: string;
  };
  proofDigestHex: string;
}

export type OfflineProofVerificationStatus =
  | 'VALID'
  | 'INVALID_SIGNATURE'
  | 'INVALID_TENANT_BINDING'
  | 'INVALID_CHAIN'
  | 'INVALID_QUORUM'
  | 'EQUIVOCATION'
  | 'UNKNOWN_VALIDATOR_SET'
  | 'EXPIRED_PROTOCOL'
  | 'MALFORMED_PROOF';

export interface OfflineProofVerificationResult {
  status: OfflineProofVerificationStatus;
  isValid: boolean;
  reason: string;
  details?: Record<string, unknown> | undefined;
}
