# WolverineDB // Master Documentation Index

> **Source Code is Authoritative.**  
> This documentation suite describes the authoritative technical architecture, cryptographic primitives, Byzantine fault-tolerant consensus, Write-Ahead Log (WAL) normalization, continuous verified state reconstruction, and disaster survivability engines of **WolverineDB v1.3.0**.

---

## 1. What is WolverineDB?

**WolverineDB** is an independent, non-intrusive **cryptographic trust and survivability layer for relational and distributed databases** (primary adapter: **PostgreSQL**).

It transforms standard transactional databases into tamper-evident, Byzantine fault-tolerant systems with continuous verified state reconstruction and immutable trust receipts—**without requiring changes to database engines or application code**.

### Core Value Proposition:
1. **Continuous Verified State Reconstruction**: Mathematically proves database integrity at transaction granularity using Merkle trees, hash-chains, and canonical JSON tuple encoding (`c14n`).
2. **Byzantine Fault Tolerant (BFT) Consensus**: A cluster of independent validator daemons validates customer commitments, producing threshold $2f+1$ Quorum Certificates and portable offline trust proofs.
3. **Automated Incident Recovery & Sentinel Policy Gates**: An AI-assisted behavioral anomaly engine (Sentinel) drafts advisory recovery proposals that are strictly validated against on-chain EVM anchors, WORM immutability, and blast-radius invariants before autonomous execution.
4. **Zero-Trust Independent Auditability**: Generates self-contained `PortableTrustProof` receipts that can be validated completely offline by third-party auditors without connecting to the database or trust network.

---

## 2. Start Here: Guide for Engineers & AI Coding Agents

If you are a developer, security auditor, or autonomous AI agent entering this repository with zero prior conversational context, read the documents in the following order:

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. docs/PROJECT_OVERVIEW.md           → Mission, Invariants & Guarantees │
│ 2. docs/ARCHITECTURE.md               → High-Level Layered Architecture │
│ 3. docs/DIRECTORY_MAP.md              → Subsystem Map & Source Layout   │
│ 4. docs/CRYPTO_SPECIFICATION.md       → Merkle, c14n, Ed25519 & Hashes  │
│ 5. docs/BYZANTINE_CONSENSUS.md        → Quorum, Validators & Proofs     │
│ 6. docs/POSTGRES_ADAPTER.md           → WAL Normalization & Replay Store│
│ 7. docs/CONTINUOUS_RECONSTRUCTION.md  → State Frontier & Replay Engine  │
│ 8. docs/SENTINEL_POLICY_GATE.md       → Anomaly Engine & TOCTOU Defense │
│ 9. docs/CONSTRAINTS.md                → Non-Malleability & Hard Rules   │
│ 10. docs/AI_CONTEXT.md                → AI Guardrails & Workflows       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Complete Documentation Sitemap

| Category | Document | Description |
| :--- | :--- | :--- |
| **Foundations** | [`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md) | Problem statement, database trust guarantees, threat model |
| | [`ARCHITECTURE.md`](./ARCHITECTURE.md) | Full 8-layer system architecture from WAL ingress to EVM anchor |
| | [`DIRECTORY_MAP.md`](./DIRECTORY_MAP.md) | Source directory breakdown across `src/`, file roles, dependencies |
| | [`CLI_SPECIFICATION.md`](./CLI_SPECIFICATION.md) | `wdb` CLI binary commands, flags, daemon processes, subcommands |
| **Cryptography & Invariants** | [`CRYPTO_SPECIFICATION.md`](./CRYPTO_SPECIFICATION.md) | Ed25519 signing, Merkle trees, canonical JSON (`c14n`), SHA-256 domains |
| | [`BYZANTINE_CONSENSUS.md`](./BYZANTINE_CONSENSUS.md) | Quorum Certificates, $2f+1$ threshold, Byzantine safety theorems |
| | [`PORTABLE_TRUST_PROOFS.md`](./PORTABLE_TRUST_PROOFS.md) | Offline verifiable trust receipts, verifier algorithms, format specs |
| **Database & Runtime** | [`POSTGRES_ADAPTER.md`](./POSTGRES_ADAPTER.md) | PostgreSQL logical replication, WAL decoding, durable nonces |
| | [`DATA_FLOW.md`](./DATA_FLOW.md) | End-to-end commit flow: SQL $\to$ WAL $\to$ Merkle $\to$ Quorum $\to$ Proof |
| | [`STATE_MANAGEMENT.md`](./STATE_MANAGEMENT.md) | Ledger state root, persistent nonce store, node registries, clusters |
| **Recovery & Self-Healing** | [`CONTINUOUS_RECONSTRUCTION.md`](./CONTINUOUS_RECONSTRUCTION.md) | State frontier, dependency safety graph, replay engine, disaster queues |
| | [`SENTINEL_POLICY_GATE.md`](./SENTINEL_POLICY_GATE.md) | Anomaly engine, deterministic policy gate, TOCTOU defense, blast radius |
| | [`SECURITY_FABRIC.md`](./SECURITY_FABRIC.md) | Distributed risk engine, node quarantine lifecycle, incident graphs |
| **Operations & Quality** | [`PERFORMANCE.md`](./PERFORMANCE.md) | Throughput, Merkle batching, serialization overhead, concurrency |
| | [`TESTING_AND_VERIFICATION.md`](./TESTING_AND_VERIFICATION.md) | Vitest test suite (91 files / 222 tests), adversarial vectors, fuzz tests |
| | [`CONSTRAINTS.md`](./CONSTRAINTS.md) | Cryptographic invariants, non-malleability rules, hard constraints |
| | [`DECISIONS.md`](./DECISIONS.md) | Architectural Decision Records (ADRs from v0.1 to v1.3.0) |
| | [`KNOWN_ISSUES.md`](./KNOWN_ISSUES.md) | Security audit findings #1–#4, status, pull request references |
| | [`CHANGE_GUIDE.md`](./CHANGE_GUIDE.md) | Step-by-step modification recipes for adapters, consensus, recovery |
| | [`AI_CONTEXT.md`](./AI_CONTEXT.md) | Autonomous AI agent instructions, guardrails, and anti-patterns |
| | [`METADATA.md`](./METADATA.md) | Documentation versioning, commit hashes, test suite metrics |
| | [`project-manifest.json`](./project-manifest.json) | Structured machine-readable repository blueprint (JSON) |
| | [`DOCUMENTATION_AUDIT.md`](./DOCUMENTATION_AUDIT.md) | Formal audit report cross-checking 100% of source files |

---

## 4. Critical Invariants & Rules

1. **Non-Malleability & Canonical Serialization**:
   - All cryptographic hashing over structured data MUST use `canonicalizeJson` from [`src/binary/c14n.ts`](../src/binary/c14n.ts) with strict UTF-8 domain separation prefixes (`WDB:COMMITMENT:v1:`, `WDB:TRUST:v1:`, `WDB:ATTESTATION:v1:`).
2. **Durable Replay Protection**:
   - Recovery approval nonces MUST be persisted via `IApprovalNonceStore` (backed by `wolverine_sys.approval_nonces` in PostgreSQL). In-memory nonce tracking without durable persistence violates Issue #1.
3. **Gateway Ingress Cryptographic Authentication**:
   - Trust Gateways MUST authenticate customer Ed25519 signatures at the network ingress boundary via `verifyCustomerCommitment` before dispatching attestation RPCs to validators (Issue #3).
4. **Ledger Record Cryptographic Binding**:
   - Ingested commitments MUST be explicitly bound to the returned `ledgerRecord` and `PortableTrustProof` via `processAttestationsWithRecord` (Issue #2).
5. **Sentinel Policy Gate TOCTOU Defense**:
   - Policy evaluations MUST verify external store immutability (`externalVaultStore.verify()`) and perform atomic pre-approval re-verification of the basis checkpoint Merkle root and on-chain EVM anchor digest before issuing `POLICY_APPROVED` (Issue #4).
