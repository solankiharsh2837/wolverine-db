# WDB-0061: Reconstruction Manifest Protocol

Status: Normative Specification (v0.6.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the canonical schema and cryptographic commitment rules for the **Reconstruction Manifest** (`ReconstructionManifest`). The manifest is a tamper-evident audit record detailing every preserved legitimate change, every excluded malicious change, and the exact cryptographic proof of the reconstructed database state.

## 2. Canonical Manifest Schema

```typescript
export interface ReconstructionManifest {
  manifestVersion: number; // 1
  manifestId: string; // UUID v4
  databaseId: string;
  tenantId: string;
  sourceCheckpointId: string;
  sourceCheckpointDigest: Buffer; // 32 bytes SHA-256
  sourceCheckpointCommitSeq: bigint;
  startingMerkleRoot: Buffer; // 32 bytes SHA-256
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
  reconstructedMerkleRoot: Buffer; // 32 bytes SHA-256
  reconstructionDigest: Buffer; // 32 bytes SHA-256 over canonical manifest payload
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
  postRecoveryCheckpointId?: string;
}
```

## 3. Reconstruction Digest Computation

The `reconstructionDigest` binds the entire reconstruction manifest into a single 32-byte cryptographic root:

```
ReconstructionDigest = SHA-256(
    "WDB:RECON_MANIFEST:v1:" ||
    RFC8785_Canonicalize({
        manifestId,
        databaseId,
        tenantId,
        sourceCheckpointId,
        sourceCheckpointDigest: hex(sourceCheckpointDigest),
        startingMerkleRoot: hex(startingMerkleRoot),
        endingCommitSeq: endingCommitSeq.toString(),
        replayedChangeIds,
        replayedCommitSeqs: replayedCommitSeqs.map(s => s.toString()),
        excludedChangeIds,
        exclusionReasons,
        reconstructedMerkleRoot: hex(reconstructedMerkleRoot),
        recoveryBoundary,
        policyVersion,
        timestampUs: timestampUs.toString()
    })
)
```

The manifest digest is the exact payload signed by Ed25519 approvers prior to state restoration.
