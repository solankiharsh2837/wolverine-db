# WDB-0065: Post-Recovery State Certificate Protocol

Status: Normative Specification (v0.6.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the **State Recovery Certificate** (`StateRecoveryCertificate`). The certificate is emitted immediately following the atomic execution and external re-anchoring of a verified state reconstruction, certifying the exact state provenance and integrity.

## 2. Canonical Certificate Schema

```typescript
export interface StateRecoveryCertificate {
  certificateVersion: number; // 1
  certificateId: string; // UUID v4
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
  certificateSignature: string; // Hex-encoded Ed25519 signature
}
```

## 3. Human-Readable Formatting

The certificate MUST be renderable in standard formatted plain text for operator/CLI inspection:

```text
================================================================================
                         STATE RECOVERY CERTIFICATE
================================================================================
Database:                            pg-prod-ledger-01
Recovery ID:                         rec-20260816-000184
Compromise Boundary:                 CommitSeq 42 (10:00:00 UTC)
Last Verified Checkpoint:            chk-00000000-0000-0000-0000-000000001842
Verified State Frontier:             CommitSeq 46 (09:45:00 UTC)
Authorized Changes Preserved:        4
Unauthorized Changes Excluded:       4
Resulting Commit Sequence:           47
Resulting Merkle Root:               9f8e7d6c5b4a3...
External Anchor:                     WDB:ANCHOR:v1:8a7b6c5d...
Policy Approval:                     PASS (2/2 Ed25519 signatures verified)
Cryptographic Verification:          PASS (100% hash chain & Merkle match)
================================================================================
```
