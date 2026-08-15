# WDB-0083: Validator Attestation Protocol

Status: Normative Specification (v0.8.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification defines the cryptographic verification duties and attestation format of independent **Trust Validators** (`TrustValidator`).

## 2. Validator Attestation Schema

```typescript
export interface ValidatorAttestation {
  commitmentId: string;
  validatorId: string;
  validatorSetId: string;
  observedCommitmentDigest: Buffer; // 32 bytes SHA-256
  attestationSequence: bigint;
  timestampUs: bigint;
  signature: Buffer; // 64 bytes Ed25519 signature
}
```

## 3. Validator Verification Checklist

Before emitting a signed `ValidatorAttestation`, an independent validator MUST verify:
1. **Canonical Encoding**: The commitment adheres to RFC 8785 JSON rules and binary grammar.
2. **Customer Signature**: The `customerSignature` verifies against the registered `customerPubkey` for that tenant.
3. **Tenant & Database Binding**: The commitment digest includes valid domain separation (`WDB:TRUST:v1:`).
4. **Sequence Monotonicity**: `commitSeq` is strictly greater than the tenant's last finalized commitment.
5. **Previous Commitment Hash Binding**: `previousTrustCommitment` matches the last observed commitment digest for that tenant's database.
6. **No Equivocation**: No conflicting commitment exists with identical `(tenantId, databaseId, commitSeq)` but differing `checkpointDigest`.

## 4. Attestation Digest & Signature

$$\text{AttestationDigest} = \text{SHA-256}(\text{"WDB:ATTEST:v1:"} \parallel \text{commitmentId} \parallel \text{validatorId} \parallel \text{observedCommitmentDigest} \parallel \text{u64be}(\text{timestampUs}))$$

The validator signs `AttestationDigest` using its Ed25519 private key.
