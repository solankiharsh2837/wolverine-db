import { ChangeRecordData } from '../protocol/types.js';

export interface TableRowVersion {
  tableName: string;
  primaryKeyTuple: Buffer;
  values: Record<string, unknown>;
  versionId: string;
  commitSeq: bigint;
  deleted: boolean;
}

export type ReconstructedDatabaseState = Map<string, Map<string, TableRowVersion>>;

export interface FrontierVerificationResult {
  frontierCommitSeq: bigint;
  frontierTimestampUs: bigint;
  isFrontierValid: boolean;
  baseCheckpointId: string;
  baseCheckpointCommitSeq: bigint;
  preservedChanges: ChangeRecordData[];
  excludedChanges: ChangeRecordData[];
  exclusionReasons: Record<string, string>;
  firstInvalidCommitSeq: bigint | null;
  compromiseReason: string | null;
}

export interface ReconstructionManifest {
  manifestVersion: number;
  manifestId: string;
  databaseId: string;
  tenantId: string;
  sourceCheckpointId: string;
  sourceCheckpointDigest: Buffer;
  sourceCheckpointCommitSeq: bigint;
  startingMerkleRoot: Buffer;
  endingCommitSeq: bigint;
  replayedChangeIds: string[];
  replayedCommitSeqs: bigint[];
  excludedChangeIds: string[];
  exclusionReasons: Record<string, string>;
  verificationResults: {
    checkpointValid: boolean;
    externalVaultMatch: boolean;
    blockchainAnchorMatch: boolean;
    hashChainContinuous: boolean;
    sequenceMonotonic: boolean;
    provenanceValid: boolean;
    authorizationValid: boolean;
  };
  reconstructedMerkleRoot: Buffer;
  reconstructionDigest: Buffer;
  recoveryBoundary: {
    lastValidCommitSeq: bigint;
    lastValidTimestampUs: bigint;
    firstInvalidCommitSeq: bigint | null;
    compromiseReason: string;
  };
  policyVersion: number;
  approvalQuorumRequired: number;
  approverIdentities: string[];
  timestampUs: bigint;
  postRecoveryCheckpointId?: string | undefined;
}

export interface StateRecoveryCertificate {
  certificateVersion: number;
  certificateId: string;
  databaseId: string;
  recoveryId: string;
  compromiseBoundaryCommitSeq: bigint;
  compromiseReason: string;
  lastVerifiedCheckpointId: string;
  verifiedStateFrontierCommitSeq: bigint;
  authorizedChangesPreservedCount: number;
  unauthorizedChangesExcludedCount: number;
  resultingCommitSequence: bigint;
  resultingMerkleRootHex: string;
  externalAnchorDigestHex: string;
  policyApprovalStatus: 'PASS' | 'FAIL';
  cryptographicVerificationStatus: 'PASS' | 'FAIL';
  issuedAtUs: bigint;
  issuerIdentity: string;
  certificateSignature: string;
}

export interface ReconstructionProof {
  proofVersion: number;
  manifestDigest: Buffer;
  sourceCheckpointDigest: Buffer;
  startingMerkleRoot: Buffer;
  reconstructedMerkleRoot: Buffer;
  changeChainProof: {
    firstChangeHash: Buffer;
    lastChangeHash: Buffer;
    totalChangesVerified: number;
    hashChainDigest: Buffer;
  };
  policyGateApprovalDigest: Buffer;
  approverSignatures: Array<{
    approverPubkey: Buffer;
    signature: Buffer;
  }>;
  externalAnchorReference: {
    chainId: string;
    contractAddress: string;
    transactionHash?: string | undefined;
    anchorDigest: Buffer;
  };
}
