# WDB-0102: Persistent Ledger and Merkle State Root Protocol

Status: Normative Specification (v1.0.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification defines the persistence model and incremental Merkle State Root calculation for the Wolverine Trust Ledger.

## 2. Merkle State Root Invariant

In addition to sequential hash chains ($H_i = \text{SHA256}(H_{i-1} \parallel R_i)$), the Trust Ledger maintains an **Incremental Merkle Tree** over all finalized record digests $\{D_1, D_2, \dots, D_k\}$:

$$\text{LedgerStateRoot}_k = \text{MerkleRoot}(D_1, D_2, \dots, D_k)$$

```text
               LedgerStateRoot_k (32 Bytes)
                     /             \
             Node(1..2)           Node(3..4)
             /        \           /        \
          Hash(D1)  Hash(D2)   Hash(D3)  Hash(D4)
```

## 3. Storage Persistence Engine

The persistent ledger backend **MUST**:
1. Flush record payloads and sequence headers to durable storage (e.g. disk journal / PostgreSQL table / NVMe block device) before acknowledging consensus finalization.
2. Provide deterministic recovery on restart by recalculating the sequential hash chain and Merkle State Root from persisted records.
