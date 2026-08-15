import { ReconstructedDatabaseState } from '../reconstruction/types.js';

export type MutationClassificationStatus =
  | 'VALID'
  | 'COMPROMISED'
  | 'UNAUTHORIZED'
  | 'UNVERIFIABLE'
  | 'DEPENDENCY_BLOCKED'
  | 'STATE_CONFLICT'
  | 'REVOKED'
  | 'MISSING';

export type ReconstructionAction = 'PRESERVE' | 'EXCLUDE' | 'BLOCK' | 'CONFLICT';

export interface ProofGraphNode {
  nodeId: string;
  type: 'CHECKPOINT' | 'MUTATION' | 'AUTHORIZATION' | 'PROVENANCE' | 'EXTERNAL_COMMITMENT';
  commitSeq: bigint;
  hash: Buffer;
  parentIds: string[];
  proofData: Record<string, unknown>;
  evaluationStatus: 'VERIFIED' | 'FAILED' | 'UNVERIFIABLE';
}

export interface ReconstructionProofGraph {
  nodes: ProofGraphNode[];
  edges: Array<{ from: string; to: string; relationship: string }>;
}

export interface DependencyEdge {
  targetChangeId: string;
  targetCommitSeq: bigint;
  dependsOnChangeId: string;
  dependsOnCommitSeq: bigint;
  dependencyType: 'ROW_VERSION_PREDECESSOR' | 'KEY_NON_EXISTENCE' | 'FOREIGN_KEY';
  isDependencySatisfied: boolean;
  failureReason?: string | undefined;
}

export interface StateDependencyGraph {
  dependencies: DependencyEdge[];
  blockedChangeIds: string[];
  conflictChangeIds: string[];
}

export interface ReconstructionDecision {
  changeId: string;
  commitSeq: bigint;
  decision: ReconstructionAction;
  classification: MutationClassificationStatus;
  reason: string;
  proofReferences: string[];
  predecessorStatus: 'VERIFIED' | 'BROKEN' | 'INDEPENDENT';
  authorizationStatus: 'VERIFIED' | 'FAILED' | 'MISSING';
  provenanceStatus: 'VERIFIED' | 'COMPROMISED' | 'UNVERIFIABLE';
  externalAnchorStatus: 'ANCHORED' | 'NOT_ANCHORED';
  resultingStateDigest?: Buffer | undefined;
}

export interface StateRecoveryCertificateV2 {
  certificateVersion: number; // 2
  certificateId: string; // UUID v4
  databaseId: string;
  recoveryId: string;
  sourceCheckpointId: string;
  sourceCheckpointCommitSeq: bigint;
  contiguousVerifiedFrontierSeq: bigint;
  maximumReconstructableCommitSeq: bigint;
  preservedMutationIds: string[];
  excludedMutationIds: string[];
  blockedMutationIds: string[];
  conflictingMutationIds: string[];
  unverifiableMutationIds: string[];
  dependencyGraphDigest: string; // Hex SHA-256
  reconstructionGraphDigest: string; // Hex SHA-256
  resultingStateMerkleRootHex: string;
  resultingDatabaseStateDigest: string; // Hex SHA-256
  externalAnchorDigestHex: string;
  policyApprovalStatus: 'PASS' | 'FAIL';
  cryptographicVerificationStatus: 'PASS' | 'FAIL';
  issuedAtUs: bigint;
  issuerIdentity: string;
  certificateSignature: string;
}

export interface ContinuousReconstructionAnalysis {
  contiguousVerifiedFrontierSeq: bigint;
  maximumReconstructableCommitSeq: bigint;
  decisions: ReconstructionDecision[];
  proofGraph: ReconstructionProofGraph;
  dependencyGraph: StateDependencyGraph;
  reconstructionGraphDigest: Buffer;
  dependencyGraphDigest: Buffer;
  reconstructedState: ReconstructedDatabaseState;
  resultingMerkleRoot: Buffer;
}
