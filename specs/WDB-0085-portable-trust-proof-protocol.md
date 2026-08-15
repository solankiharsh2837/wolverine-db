# WDB-0085: Portable Trust Proof Protocol

Status: Normative Specification (v0.8.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details the **Portable Trust Proof** (`PortableTrustProof`). The Portable Trust Proof is a standalone, self-contained JSON artifact allowing any third-party auditor, customer, or regulatory verifier to mathematically verify checkpoint existence and validator quorum **WITHOUT connecting to or trusting Wolverine servers**.

## 2. Portable Trust Proof Schema

```typescript
export interface PortableTrustProof {
  proofVersion: number; // 1
  tenantId: string;
  databaseId: string;
  commitment: {
    commitmentId: string;
    checkpointId: string;
    commitSeq: string; // Serialized bigint
    checkpointDigestHex: string;
    previousTrustCommitmentHex: string;
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
  proofDigestHex: string; // 32 bytes SHA-256 over canonical proof payload
}
```

## 3. Offline Verification Algorithm

An independent offline verifier executes 5 mathematical checks using only the proof file and protocol rules:

1. **Commitment Authenticity**: `computeTrustCommitmentDigest(commitment) == commitment.commitmentDigestHex` AND `verifyEd25519(commitmentDigest, customerPubkey, customerSignature) == PASS`.
2. **Attestation Quorum**: At least `quorumCount` valid attestations exist from registered validators in `validatorSet`.
3. **Validator Signatures**: Every attestation signature verifies against that validator's public key for `commitmentDigestHex`.
4. **Certificate Integrity**: `quorumCertificate.commitmentDigestHex == commitment.commitmentDigestHex`.
5. **Proof Commitment**: `SHA-256("WDB:PROOF_VERIFY:v1:" || CanonicalJSON(proof)) == proof.proofDigestHex`.
