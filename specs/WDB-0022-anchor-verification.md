# WDB-0022: Cross-Domain Anchor Verification Protocol

Status: Normative Specification (v0.3 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification establishes the normative algorithm for verifying database state integrity across three independent trust domains:
1. **Live Database** (PostgreSQL / MySQL / SQLite metadata)
2. **External Object Vault** (S3 Object Lock / WORM)
3. **Public Cryptographic Anchors** (EVM / Public Trust Domains)

## 2. Cross-Domain Verification Workflow

```
                LOCAL DATABASE
                      │
                      ▼
               Merkle State Root
                      │
                      ▼
             Checkpoint Digest (D_local)
                      │
           ┌──────────┴──────────┐
           ▼                     ▼
      S3/WORM Vault         EVM Anchor
     (D_external)           (D_anchor)
           │                     │
           └──────────┬──────────┘
                      ▼
              TRIPLE COMPARATOR
                      │
           [CROSS-DOMAIN REPORT]
```

## 3. Verification Algorithm & State Matrix

The Verifier executes the following deterministic procedure for a checkpoint ID:

1. Query local database state and recalculate the live Merkle root $R_{\text{local}}$ and Checkpoint Digest $D_{\text{local}}$.
2. Retrieve the checkpoint record from the external object store and recalculate $D_{\text{external}}$.
3. Query the configured blockchain / public anchor contract and retrieve $D_{\text{anchor}}$.
4. Compare $D_{\text{local}}$, $D_{\text{external}}$, and $D_{\text{anchor}}$ against the evaluation matrix below:

| Condition | Database ($D_{\text{local}}$) | Vault ($D_{\text{external}}$) | Anchor ($D_{\text{anchor}}$) | Verdict | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **All Match** | $D$ | $D$ | $D$ | **`AUTHENTIC`** | Complete triple-plane integrity verified. |
| **DB Tampered** | $D'$ | $D$ | $D$ | **`LOCAL_TAMPERING_DETECTED`** | DBA modified live database; external anchors intact. |
| **Vault Tampered** | $D$ | $D'$ | $D$ | **`VAULT_TAMPERING_DETECTED`** | Object storage corrupted; DB and chain agree. |
| **Chain Divergence** | $D$ | $D$ | $D'$ | **`ANCHOR_DIVERGENCE`** | Blockchain commitment mismatch. |
| **Full Disagreement** | $D_1$ | $D_2$ | $D_3$ | **`CATASTROPHIC_SPLIT_BRAIN`** | All trust planes disagree. |
| **Anchor Pending** | $D$ | $D$ | `PENDING` | **`PENDING_ANCHOR`** | Local & vault valid; chain awaiting finality. |

## 4. Reporting Invariants

- If any divergence is detected, the verifier MUST NOT attempt automatic recovery or silent state modification.
- The verifier MUST produce a detailed forensic report containing exact hex digests, block numbers, transaction hashes, and timestamps from all participating domains.
