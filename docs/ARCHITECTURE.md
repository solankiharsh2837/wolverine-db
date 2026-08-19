# WolverineDB // System Architecture (v1.3.0)

> **Source Code is Authoritative.**  
> This document specifies the comprehensive layered architecture, subsystem interactions, trust boundaries, and cryptographic flows of **WolverineDB v1.3.0**.

---

## 1. High-Level Architectural Model

WolverineDB operates as a modular, non-intrusive cryptographic middleware and trust network for relational and distributed databases.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            DATABASE ENGINE TIER                             │
│   PostgreSQL / SQLite / MySQL (Transactional Workloads & WAL Generation)    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Logical Replication Stream
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ LAYER 1: INGRESS, DECODING & NORMALIZATION                                  │
│   - WalReceiver (src/wal/receiver.ts): Streams raw WAL packets.             │
│   - WalDecoder (src/wal/decoder.ts): Extracts schema, table, operation.     │
│   - WalNormalizer (src/wal/normalizer.ts): Generates canonical tuples.      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Canonical Mutation Tuples
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ LAYER 2: CRYPTOGRAPHIC STATE & INTEGRITY                                    │
│   - Merkle Tree State Roots (src/crypto/merkle.ts): Balanced binary tree.   │
│   - Canonical JSON (src/binary/c14n.ts): Deterministic non-malleable c14n.  │
│   - Customer Signing Provider (src/crypto/signing_provider.ts): Ed25519.    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Customer Signed TrustCommitment
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ LAYER 3: BYZANTINE TRUST NETWORK & CONSENSUS                                │
│   - TrustGatewayServer (src/runtime/gateway.ts): Ingress boundary auth.    │
│   - TrustValidator Cluster (src/trust_network/validator.ts): 2f+1 quorum.   │
│   - TrustConsensusEngine (src/trust_network/consensus.ts): Quorum Certs.    │
│   - WolverineTrustLedger (src/trust_network/ledger.ts): Finalized records.  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ QuorumCertificate & PortableTrustProof
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ LAYER 4: EXTERNAL ANCHORING & PERSISTENCE                                   │
│   - WORM Checkpoint Store (src/checkpoint/worm.ts): Immutability store.     │
│   - EVM Anchor Adapter (src/anchors/evm.ts): On-chain digest registry.      │
│   - PostgresNonceStore (src/postgres/nonce_store.ts): Durable replay store. │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Finalized State Milestone
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ LAYER 5: SENTINEL BEHAVIORAL POLICY GATE                                    │
│   - AnomalyEngine (src/sentinel/anomaly_engine.ts): Velocity/drift detector.│
│   - PolicyGate (src/sentinel/policy_gate.ts): TOCTOU defense & blast cap.   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Verified Autonomous Recovery Proposal
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ LAYER 6: CONTINUOUS STATE RECONSTRUCTION                                    │
│   - ContinuousEngine (src/continuous_reconstruction/continuous_engine.ts).  │
│   - DependencyGraph (src/continuous_reconstruction/dependency_graph.ts).    │
│   - ReplayEngine (src/reconstruction/replay_engine.ts): Clean state replay. │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Layer-by-Layer Subsystem Specifications

### Layer 1: Ingress, Decoding & Normalization (`src/wal/`)
- Subscribes to PostgreSQL logical replication slots (`pgoutput` or `test_decoding`).
- Decodes table names, primary keys, old/new column values, and timestamps.
- Produces normalized mutation tuples with UTC microsecond timestamps and hexadecimal primary keys.

### Layer 2: Cryptographic State & Integrity (`src/crypto/`, `src/binary/`)
- Computes SHA-256 Merkle roots over batched mutation tuples within a commit window.
- Serializes structured payloads using deterministic, non-malleable canonical JSON (`c14n`).
- Signs commitments with the customer's Ed25519 private key.

### Layer 3: Byzantine Trust Network (`src/trust_network/`, `src/runtime/`)
- **Trust Gateway**: Authenticates customer signatures at the network ingress boundary (`verifyCustomerCommitment`) before dispatching attestation RPCs to validators.
- **Validator Cluster**: Independently verifies customer signatures, commit sequence monotonicity, and logical timestamps before signing attestations.
- **Consensus Engine**: Gathers $2f+1$ attestations, generates a `QuorumCertificate`, and appends a `FINALIZATION` record to `WolverineTrustLedger`.

### Layer 4: External Anchoring & Persistence (`src/checkpoint/`, `src/anchors/`, `src/postgres/`)
- Persists canonical checkpoint payloads into WORM storage with strict immutability verification (`externalVaultStore.verify()`).
- Anchors checkpoint digests to EVM smart contracts with block confirmation tracking.
- Tracks consumed recovery nonces durably in `wolverine_sys.approval_nonces` table.

### Layer 5: Sentinel Behavioral Policy Gate (`src/sentinel/`)
- Detects anomalous transaction bursts, mass deletions, and unauthorized schema alterations.
- Generates structured `AdvisoryRecoveryProposal` records.
- Evaluates proposals against 6 strict mathematical invariants, including scope bounding, blast radius limits (max 1000 records), and atomic pre-approval TOCTOU re-verification.

### Layer 6: Continuous State Reconstruction (`src/continuous_reconstruction/`, `src/reconstruction/`)
- Maintains the verified state frontier and transaction dependency graph.
- Isolates compromised transactions while replaying verified mutations against anchored checkpoint baselines.
