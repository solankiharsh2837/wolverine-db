# WDB-0082: Trust Ledger Record Format Protocol

Status: Normative Specification (v0.8.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the immutable, append-only record format of the **Wolverine Trust Ledger** (`TrustLedger`).

## 2. Permitted Record Types

The Trust Ledger permits exactly six distinct record types:

1. `COMMITMENT`: Ingestion of an authenticated customer `TrustCommitment`.
2. `ATTESTATION`: Ingestion of an independent `ValidatorAttestation`.
3. `FINALIZATION`: Materialization of a `QuorumCertificate` reaching consensus.
4. `REVOCATION`: Ingestion of an authenticated key or node revocation event.
5. `EPOCH_CHANGE`: Logical epoch increment and validator set snapshot.
6. `VALIDATOR_SET_CHANGE`: Registration or removal of validator node identities.

## 3. Trust Ledger Record Schema

```typescript
export interface TrustLedgerRecord {
  recordType:
    | 'COMMITMENT'
    | 'ATTESTATION'
    | 'FINALIZATION'
    | 'REVOCATION'
    | 'EPOCH_CHANGE'
    | 'VALIDATOR_SET_CHANGE';
  ledgerSeq: bigint;
  epoch: number;
  validatorSetId: string;
  tenantId?: string | undefined;
  databaseId?: string | undefined;
  payload: Record<string, unknown>;
  previousRecordDigest: Buffer; // 32 bytes SHA-256
  recordDigest: Buffer; // 32 bytes SHA-256
  timestampUs: bigint;
}
```

## 4. Ledger Record Digest Computation

$$\text{RecordDigest} = \text{SHA-256}(\text{"WDB:LEDGER\_REC:v1:"} \parallel \text{previousRecordDigest} \parallel \text{u64be}(\text{ledgerSeq}) \parallel \text{RFC8785\_Canonicalize}(\text{payload}))$$

## 5. Ledger Integrity Invariants

- The ledger sequence MUST be strictly monotonic ($S_i = S_{i-1} + 1$).
- Any insertion, deletion, out-of-order sequence, or hash discontinuity MUST cause immediate ledger halt (`LEDGER_CORRUPTED`).
