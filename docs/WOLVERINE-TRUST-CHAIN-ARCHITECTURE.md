# Wolverine Trust Chain Architecture — Hyperledger Besu Authority

**Document Status**: Canonical Architecture Specification  
**Authority**: Production Release Baseline  
**Network**: Wolverine Permissioned Trust Chain (`Chain ID: 13370`)  
**Consensus**: QBFT (Quorum Byzantine Fault Tolerance)

---

## 1. Executive Summary & Thesis

WolverineDB provides independent cryptographic trust, temporal witnessing, and verified state reconstruction for relational databases.

> **"Your database can lie. Your externally witnessed history cannot be rewritten without defeating Wolverine's independent trust network."**

The authoritative finality layer for WolverineDB is the **Hyperledger Besu permissioned blockchain network**. The previous TypeScript in-memory BFT consensus and ledger have been formally demoted to reference and test harnesses. There is exactly **one source of finality** in the production Wolverine architecture: **Besu QBFT Blockchain Finality**.

---

## 2. Three-Plane Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                   PLANE 1 — CUSTOMER EVIDENCE PLANE                    │
│                                                                        │
│   PostgreSQL (Logical Replication / pgoutput)                          │
│        │                                                               │
│        ▼                                                               │
│   Wolverine Evidence Agent                                             │
│        ├── Canonical Binary Serialization (RFC 8785)                   │
│        ├── Durable Evidence Journal & Hash Chain                       │
│        ├── Deterministic State Frontier                                │
│        └── RFC 6962 State Merkle Root Calculation                      │
│                 │                                                      │
│                 ▼                                                      │
│          Dual Authorization                                            │
│          ├── Agent Attestation:    σ_agent = Sign(Digest || LSN)       │
│          └── Customer Auth:        σ_cust  = Sign(Digest || Seq)       │
│                 │                                                      │
│                 ▼                                                      │
│          Trust Commitment C_n                                          │
└─────────────────┬──────────────────────────────────────────────────────┘
                  │ mTLS Secure HTTP/2 Transport
                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   PLANE 2 — WOLVERINE TRUST CLOUD                      │
│                                                                        │
│   Wolverine Trust Gateway                                              │
│        ├── Admission Control & Rate Limiting                           │
│        ├── Cryptographic Signature Authentication                      │
│        └── Besu JSON-RPC Dispatcher                                    │
│                 │                                                      │
│                 ▼ (commitState RPC)                                    │
│   Hyperledger Besu Permissioned Cluster (5 Validators, QBFT)           │
│        ├── Besu Validator 1 (0x7E5F...5Bdf)                            │
│        ├── Besu Validator 2 (0x2B5A...D6cF)                            │
│        ├── Besu Validator 3 (0x6813...cBA69)                           │
│        ├── Besu Validator 4 (0x1efF...A718)                            │
│        └── Besu Validator 5 (0xe1AB...b276)                            │
│                 │                                                      │
│                 ▼ (Smart Contract: WolverineTrustRegistry.sol)         │
│          FINALIZED BLOCK (Instant 1-Block BFT Finality)                │
│                 │                                                      │
│                 ▼                                                      │
│   Universal Trust Receipt Materialization                              │
└─────────────────┬──────────────────────────────────────────────────────┘
                  │ (Optional Periodic Batch Anchoring)
                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   PLANE 3 — OPTIONAL PUBLIC ANCHOR PLANE               │
│                                                                        │
│   Ethereum / Base L2 Public Notary Registry                            │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Consensus & Finality: Besu QBFT

Wolverine utilizes **QBFT (Quorum Byzantine Fault Tolerance)**:
- **Validators**: $N = 5$ dedicated Besu nodes.
- **Fault Tolerance**: Tolerates up to $F = 1$ Byzantine (malicious or offline) validator:
  $$N \ge 3F + 1 \implies 5 \ge 3(1) + 1 = 4$$
- **Quorum Threshold**: $2F + 1 = 3$ validators for safety; $N - F = 4$ for liveness.
- **Block Time**: 1 second fixed block period.
- **Finality**: Deterministic, instant 1-block finality (zero reorganizations, unlike PoW or Nakamoto PoS).
- **Gas Model**: Zero base fee with internal permissioning.

---

## 4. Smart Contract Architecture (`WolverineTrustRegistry.sol`)

The canonical registry contract records state commitments with **Data Non-Disclosure Guarantee**:
- **Zero Plaintext Storage**: Only 32-byte cryptographic hashes (`stateMerkleRoot`, `checkpointDigest`, `changeChainHead`), sequence numbers, timestamps, and signatures are recorded.
- **Sequence Monotonicity**: Enforces strict sequence increments ($commitSeq_{n} = commitSeq_{n-1} + 1$) and cryptographic link to the previous commitment digest.
- **Dual Signature Verification**: Demands both customer authorization and agent attestation signatures.

---

## 5. Security Invariants & Guarantees

1. **Non-Disclosure**: Plaintext rows, column values, SQL queries, and WAL payloads never leave customer VPC.
2. **Immutability**: Once committed to Besu, historical state cannot be modified, reordered, or deleted by any DBA, cloud provider, or Wolverine operator.
3. **Fail-Closed Dual Attestation**: The Trust Gateway cannot forge commitments because it lacks both the Customer KMS private key and the Agent private key.
4. **Air-Gapped Verifiability**: Any auditor can take a Universal Trust Receipt and verify it offline against a copy of the database or snapshot.
