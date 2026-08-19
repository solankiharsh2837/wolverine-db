# WolverineDB // Project Overview

> **Source Code is Authoritative.**  
> This document describes the core problem domain, cryptographic trust model, operational boundaries, and system guarantees of **WolverineDB v1.3.0**.

---

## 1. Executive Summary

Relational databases like PostgreSQL, MySQL, and SQLite form the transactional backbone of modern financial, healthcare, enterprise, and cloud infrastructures. However, traditional database architectures operate under a critical trust vulnerability:

> **The Database Administrator (DBA) / Root Infrastructure Trust Dilemma**:  
> Anyone with raw database storage access, root OS credentials, or physical volume control can modify rows, drop audit logs, alter past transactions, and recalculate database checksums without leaving a cryptographic proof of tampering.

**WolverineDB** solves this dilemma by introducing a **non-intrusive, independent cryptographic trust and survivability layer**. It captures database mutations at the Write-Ahead Log (WAL) boundary, computes deterministic Merkle roots, anchors checkpoints to external WORM/blockchain storage, validates commits via Byzantine Fault Tolerant (BFT) quorums, and provides continuous verified state reconstruction.

---

## 2. What WolverineDB IS vs. What It IS NOT

### What WolverineDB IS:
- **An Independent Cryptographic Engine**: Operates alongside existing database deployments to capture, normalize, and cryptographically prove transaction validity.
- **A Tamper-Evident State Verifier**: Implements deterministic Merkle trees and hash chains to detect silent data corruption, malicious DBA tampering, and bitrot at transaction granularity.
- **A Byzantine Fault Tolerant Consensus Cluster**: Coordinates independent validator nodes that attest to transaction sequence ordering and issue cryptographic `QuorumCertificate` tokens.
- **A Continuous State Reconstruction System**: Enables point-in-time recovery and autonomous disaster remediation through deterministic replay of verified mutations against anchored checkpoints.
- **An Autonomous Policy Gate (Sentinel)**: Evaluates automated remediation proposals against registered table scopes, blast-radius caps, and EVM on-chain anchor digests before allowing state modifications.

### What WolverineDB IS NOT:
- **NOT a Replacement Storage Engine**: It does not replace PostgreSQL, SQLite, or RocksDB storage layers. It wraps them.
- **NOT a Centralized Audit Log**: It uses decentralized validator quorums, WORM storage, and EVM smart contracts rather than a single database table for security proofs.
- **NOT a Generic Web Application**: It is systems software composed of TypeScript/Node.js core libraries, native PostgreSQL adapters, RPC transports, and the `wdb` command-line binary.

---

## 3. Core Threat Model & Attack Vectors

| Attack Vector | Adversary Capability | WolverineDB Defense |
| :--- | :--- | :--- |
| **Direct Table Mutation** | Malicious DBA executes `UPDATE users SET balance = 1000000;` directly in PostgreSQL. | State Merkle root deviates from the validator-signed `QuorumCertificate`. Verification fails immediately. |
| **WAL Replay & History Forgery** | Attacker replays historical WAL records or inserts duplicate transactions. | Strict monotonically increasing commit sequence (`commitSeq`) and durable `IApprovalNonceStore` unique key constraints prevent replay. |
| **Compromised Gateway** | Ingress gateway attempts to fabricate validator signatures or alter customer commitments. | Validators verify customer Ed25519 signatures independently; offline proof verifiers validate all $2f+1$ validator signatures against registered public keys. |
| **Byzantine Validator Collusion** | Up to $f$ malicious validators attempt to equivocate or sign conflicting sequence roots. | Quorum threshold requires $2f+1$ matching signatures out of $3f+1$ total validators, guaranteeing Byzantine consensus safety. |
| **Rogue Autonomous Repair** | AI remediation agent attempts to modify arbitrary system configurations. | Sentinel `PolicyGate` enforces strict table scope matching (`matchesProtectedScope`) and blast radius limits (max 1000 records). |
| **Check-Then-Use (TOCTOU) Storage Attacks** | Attacker replaces basis checkpoint after verification but before repair execution. | Policy Gate performs atomic pre-approval re-verification of the basis checkpoint digest and finalized on-chain EVM anchor. |

---

## 4. Key Architectural Layers

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          APPLICATION & DATABASE                         │
│   PostgreSQL / SQLite / MySQL Engine (SQL Transactions & WAL Generation) │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Logical Replication / WAL Stream
┌────────────────────────────────────▼────────────────────────────────────┐
│ 1. INGRESS & WAL NORMALIZATION LAYER                                    │
│   WalReceiver → WalDecoder → WalNormalizer → Canonical JSON (c14n)       │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Normalized Mutation Tuples
┌────────────────────────────────────▼────────────────────────────────────┐
│ 2. CRYPTOGRAPHIC INTEGRITY & STATE ENGINE                               │
│   Merkle Tree State Roots → Hash Chains → Trust Commitment Construction │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Customer Signed TrustCommitment
┌────────────────────────────────────▼────────────────────────────────────┐
│ 3. BYZANTINE TRUST NETWORK & GATEWAY                                    │
│   TrustGatewayServer → Validator Cluster (2f+1) → Quorum Certificate    │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Finalized Ledger Record & Proof
┌────────────────────────────────────▼────────────────────────────────────┐
│ 4. DISASTER RECOVERY & SENTINEL AUTONOMY                                │
│   WORM Stores → EVM Anchor Adapter → Sentinel PolicyGate → Coordinator  │
└─────────────────────────────────────────────────────────────────────────┘
```
