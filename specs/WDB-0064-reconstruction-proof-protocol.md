# WDB-0064: Reconstruction Proof Protocol

Status: Normative Specification (v0.6.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification defines the cryptographic proof payload that allows any independent auditor, regulator, or external peer node to verify the correctness of a state reconstruction without access to proprietary live database engine internals.

## 2. Reconstruction Proof Schema

```typescript
export interface ReconstructionProof {
  proofVersion: number; // 1
  manifestDigest: Buffer; // 32 bytes SHA-256
  sourceCheckpointDigest: Buffer; // 32 bytes SHA-256
  startingMerkleRoot: Buffer; // 32 bytes SHA-256
  reconstructedMerkleRoot: Buffer; // 32 bytes SHA-256
  changeChainProof: {
    firstChangeHash: Buffer;
    lastChangeHash: Buffer;
    totalChangesVerified: number;
    hashChainDigest: Buffer; // Cumulative hash over all replayed changes
  };
  policyGateApprovalDigest: Buffer; // 32 bytes
  approverSignatures: Array<{
    approverPubkey: Buffer; // 32 bytes Ed25519
    signature: Buffer;      // 64 bytes Ed25519
  }>;
  externalAnchorReference: {
    chainId: string;
    contractAddress: string;
    transactionHash?: string;
    anchorDigest: Buffer;
  };
}
```

## 3. Independent Verification Invariant

An external verifier given a `ReconstructionProof` and `ReconstructionManifest` can verify state authenticity by executing three mathematical checks:
1. `computeReconstructionDigest(manifest) == proof.manifestDigest`.
2. All `approverSignatures` verify against authorized public keys for `manifestDigest`.
3. `proof.externalAnchorReference.anchorDigest` matches the on-chain anchor commitment.
