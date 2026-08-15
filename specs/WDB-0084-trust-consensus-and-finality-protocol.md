# WDB-0084: Trust Consensus and Finality Protocol

Status: Normative Specification (v0.8.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the $M$-of-$N$ threshold consensus and finality engine for the Wolverine Trust Network.

## 2. Quorum Certificate Schema

```typescript
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
```

## 3. Finality State Machine

```text
       [SUBMITTED]
            │
            ▼
        [OBSERVED]
            │
            ▼
        [ATTESTED] (1 <= Valid Signatures < M)
            │
            ▼
    [QUORUM_REACHED] (M Valid Signatures Reached)
            │
            ▼
        [FINALIZED] (Committed to Trust Ledger)
```

## 4. Consensus Invariants

1. **Threshold Quorum ($M$-of-$N$)**: A commitment transitions to `FINALIZED` if and only if at least $M$ unique, registered, and non-revoked validators submit valid attestations for the identical `commitmentDigest`.
2. **Equivocation Detection**: If validators observe conflicting digests for the same `(tenantId, databaseId, commitSeq)`, consensus is aborted with `CONSENSUS_DIVERGENCE`, and an `EQUIVOCATION_DETECTED` event is permanently recorded in the ledger.
3. **Irreversible Finality**: Once a `FINALIZATION` record is appended to the Trust Ledger, it CANNOT be modified, replaced, or rolled back.
