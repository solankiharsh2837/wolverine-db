# WDB-0081: Tenant-Isolated Trust Commitment Protocol

Status: Normative Specification (v0.8.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details the cryptographic structure and domain separation rules for the `TrustCommitment`. Every commitment is strictly bound to an isolated tenant identifier, preventing cross-tenant replay, spoofing, or unauthorized historical inference.

## 2. Canonical Trust Commitment Schema

```typescript
export interface TrustCommitment {
  commitmentId: string; // UUID v4
  tenantId: string;
  databaseId: string;
  checkpointId: string;
  commitSeq: bigint;
  checkpointDigest: Buffer; // 32 bytes SHA-256
  previousTrustCommitment: Buffer; // 32 bytes SHA-256 of prior commitment (or 32 zero bytes for genesis)
  protocolVersion: number; // 1
  logicalTimestamp: bigint;
  ingestionTimestamp?: bigint;
  epoch: number;
  validatorSetId: string;
  customerPubkey: Buffer; // 32 bytes Ed25519 public key
  customerSignature: Buffer; // 64 bytes Ed25519 signature
  commitmentDigest: Buffer; // 32 bytes SHA-256
}
```

## 3. Cryptographic Commitment Digest Calculation

The `commitmentDigest` binds all fields under strict domain separation:

$$\text{CommitmentDigest} = \text{SHA-256}(\text{"WDB:TRUST:v1:"} \parallel \text{RFC8785\_Canonicalize}(\text{payload}))$$

```typescript
const canonicalPayload = canonicalizeJson({
  commitmentId: commitment.commitmentId,
  tenantId: commitment.tenantId,
  databaseId: commitment.databaseId,
  checkpointId: commitment.checkpointId,
  commitSeq: commitment.commitSeq.toString(),
  checkpointDigestHex: commitment.checkpointDigest.toString('hex'),
  previousTrustCommitmentHex: commitment.previousTrustCommitment.toString('hex'),
  protocolVersion: commitment.protocolVersion,
  logicalTimestamp: commitment.logicalTimestamp.toString(),
  epoch: commitment.epoch,
  validatorSetId: commitment.validatorSetId,
});
```

## 4. Tenant Isolation Invariants

1. **Cross-Tenant Non-Transferability**: A signature from Tenant $A$ verified under Tenant $B$'s domain MUST fail validation.
2. **Namespace Privacy**: Checkpoint digests are irreversible SHA-256 hashes; tenant identifiers MUST NOT leak private database schema or table metadata.
3. **Monotonic Sequence Enforcement**: For a given `(tenantId, databaseId)`, commitments MUST have strictly increasing `commitSeq` values and unbroken `previousTrustCommitment` hash links.
