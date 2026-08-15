# WDB-0075: State Recovery Certificate V2 Protocol

Status: Normative Specification (v0.7.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the **State Recovery Certificate V2** (`StateRecoveryCertificateV2`), extending v0.6.0 to provide complete auditor-verifiable transparency across the Contiguous Verified Frontier, Maximum Reconstructable State, Dependency Graph, and Reconstruction Proof Graph.

## 2. Canonical Certificate V2 Schema

```typescript
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
  certificateSignature: string; // Hex Ed25519 signature
}
```
