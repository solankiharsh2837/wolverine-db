# WDB-0076: Wolverine Trust Service Interface Protocol

Status: Normative Specification (v0.7.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details the architectural interfaces for the **Wolverine Trust Service** (`WolverineTrustService`). This establishes the clean abstraction layer separating local customer WolverineDB nodes from the managed, tenant-isolated Wolverine Trust Ledger, preparing the system for v0.8.0 enterprise trust networking without public blockchain dependencies.

## 2. Core Trust Service Interfaces

```typescript
export interface TrustCommitmentRecord {
  commitmentId: string;
  tenantId: string;
  databaseId: string;
  checkpointId: string;
  checkpointDigest: Buffer; // 32 bytes SHA-256
  commitSeq: bigint;
  anchoredEpochUs: bigint;
  ledgerProof: string;
}

export interface IWolverineTrustService {
  anchorCheckpoint(
    tenantId: string,
    databaseId: string,
    checkpointId: string,
    checkpointDigest: Buffer,
    commitSeq: bigint
  ): Promise<TrustCommitmentRecord>;

  getCommitment(checkpointId: string): Promise<TrustCommitmentRecord | null>;

  verifyCommitment(checkpointId: string, expectedDigest: Buffer): Promise<boolean>;
}
```
