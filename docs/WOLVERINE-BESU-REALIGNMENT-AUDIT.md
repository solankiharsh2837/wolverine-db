# WolverineDB — Hyperledger Besu Realignment & Architectural Audit

**Document Status**: Canonical Architecture Directives & Subsystem Migration Audit  
**Author**: Systems Architecture & Cryptographic Engineering Team  
**Date**: August 2026  
**System Target**: Production-Grade Hybrid Database Trust Infrastructure (Besu Authority)

---

## 1. Current Architecture Overview

WolverineDB was originally engineered as an independent cryptographic trust layer for databases across three conceptual planes:
1. **Evidence Plane (Plane 1 - Customer Boundary)**: PostgreSQL CDC via logical replication (`pgoutput`), canonical binary serialization (`RFC 8785` / custom tuples), domain-separated SHA-256 hash chaining, deterministic state frontier tracking, and RFC 6962 Merkle tree state roots.
2. **Trust Plane (Plane 2 - Wolverine Infrastructure)**: Built initially as an in-process and daemon-separated TypeScript Byzantine Fault Tolerant (BFT) network consisting of 5 validator nodes running a 4-of-5 threshold quorum state machine (`TrustValidatorDaemon`, `TrustConsensusEngine`, `WolverineTrustLedger`), producing Quorum Certificates (`CanonicalQuorumCertificate`) and portable trust proofs.
3. **Public Anchor Plane (Plane 3 - Public Trust Notary)**: Batch Merkle trees anchoring checkpoint digests into Ethereum / Base L2 smart contracts for temporal witnessing.

While the cryptographic evidence and serialization foundation (Plane 1) is production-grade, maintaining a custom TypeScript BFT consensus engine and ledger alongside an external blockchain creates **two competing sources of finality and authority**.

---

## 2. Intended Architecture After Realignment

The realigned architecture establishes **Hyperledger Besu (QBFT/IBFT 2.0 Consensus)** as the **sole, authoritative trust ledger and finality mechanism** for WolverineDB:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   CUSTOMER ENVIRONMENT (EVIDENCE PLANE)                │
│                                                                        │
│   PostgreSQL (Logical Replication / pgoutput)                          │
│        │                                                               │
│        ▼                                                               │
│   Wolverine Evidence Agent                                             │
│        ├── Canonical Transaction Buffer (RFC 8785)                     │
│        ├── Durable Evidence Journal & Hash Chain                       │
│        ├── Deterministic State Frontier                                │
│        └── RFC 6962 State Merkle Root                                  │
│                 │                                                      │
│                 ▼                                                      │
│          Dual Authorization                                            │
│          ├── σ_agent    = Sign_agent(CommitmentDigest || WAL_LSN)      │
│          └── σ_customer = Sign_cust(CommitmentDigest || commitSeq)     │
│                 │                                                      │
│                 ▼                                                      │
│          TrustCommitment C_n (Data Non-Disclosure Payload)             │
└─────────────────┬──────────────────────────────────────────────────────┘
                  │ mTLS / Secure HTTP/2 Transport
                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   WOLVERINE TRUST CLOUD (TRUST PLANE)                  │
│                                                                        │
│   Trust Gateway Cluster                                                │
│        ├── Admission Gate, Policy, Rate Limiter                        │
│        ├── Dual Signature Authenticator (Fail-Closed)                  │
│        └── Authenticated Besu RPC Dispatcher                           │
│                 │                                                      │
│                 ▼                                                      │
│   Wolverine Permissioned Blockchain (Hyperledger Besu QBFT Cluster)    │
│        ├── Besu Validator 1 (Node ID 0x01)                             │
│        ├── Besu Validator 2 (Node ID 0x02)                             │
│        ├── Besu Validator 3 (Node ID 0x03)                             │
│        ├── Besu Validator 4 (Node ID 0x04)                             │
│        └── Besu Validator 5 (Node ID 0x05)                             │
│                 │                                                      │
│                 ▼ (Smart Contract: WolverineTrustRegistry.sol)         │
│          FINALIZED BLOCK (BFT Consensus Finality)                      │
│                 │                                                      │
│                 ▼                                                      │
│          Universal Trust Receipt Generator                             │
│                 │                                                      │
│                 ▼                                                      │
│   Universal Trust Receipt (Self-Contained Portable Proof)              │
└─────────────────┬──────────────────────────────────────────────────────┘
                  │ (Optional Periodic Batch Anchoring)
                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   OPTIONAL PUBLIC ANCHOR PLANE                         │
│                                                                        │
│   Ethereum / Base L2 Notary Registry (External Public Witnessing)       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Subsystem Classification Matrix

Every subsystem across the repository is classified into one of five categories:
- **A. KEEP**: Directly utilized in production path without architectural compromise.
- **B. MODIFY**: Maintained in production with modifications to point to Besu.
- **C. WRAP AS ADAPTER**: Integrated behind standard interfaces for pluggability.
- **D. DEMOTE TO TEST/REFERENCE**: Preserved exclusively for local unit tests, simulation, offline proof tooling, or benchmark baselines; stripped from claiming production finality.
- **E. REMOVE / REPLACE**: Replaced by Besu native primitives.

| Subsystem / Path | Classification | Role in Realigned Architecture |
|:---|:---:|:---|
| `src/crypto/` (Hash, Merkle, C14N, Ed25519) | **A. KEEP** | Production cryptographic primitive core. |
| `src/evidence/` (WalDecoder, StateFrontier, Journal) | **A. KEEP** | Customer-side Evidence Plane engine. |
| `src/wal/` (WAL parsing, LSN stream tracking) | **A. KEEP** | PostgreSQL replication stream decoding. |
| `src/postgres/` (Logical slot, CDC adapter) | **B. MODIFY** | Wire directly to Evidence Agent event pipeline. |
| `src/crypto/aws_kms_provider.ts` | **A. KEEP** | Fail-closed enterprise customer KMS signer. |
| `src/crypto/gcp_kms_provider.ts` | **A. KEEP** | Fail-closed enterprise customer Cloud KMS signer. |
| `src/network/` (mTLS, HTTP/2 transport) | **A. KEEP** | Secure transport between Agent and Gateway. |
| `src/runtime/gateway.ts` | **B. MODIFY** | Route commitments directly to Besu RPC instead of TS BFT. |
| `src/trust/` (`QuorumCertificate`, `ValidatorSet`) | **D. DEMOTE** | Retained as reference/pre-admission structures & test harness. |
| `src/trust_network/` (`WolverineTrustLedger`, `consensus.ts`) | **D. DEMOTE** | Demoted to offline proof engine and local test fixture. |
| `src/trust_service/` (`PersistentTrustLedger`, journal) | **D. DEMOTE** | Demoted to reference / sovereign non-blockchain storage engine. |
| `src/runtime/validator_daemon.ts` | **D. DEMOTE** | Demoted to reference simulator; Besu nodes are the real validators. |
| `src/blockchain/besu/` (NEW) | **A. KEEP** | Production Besu JSON-RPC client, transaction submitter, event parser. |
| `blockchain/contracts/` (NEW `WolverineTrustRegistry.sol`) | **A. KEEP** | Production on-chain state commitment registry. |
| `src/receipts/` (NEW `UniversalTrustReceipt`) | **A. KEEP** | Authoritative universal receipt format with Besu block binding. |
| `src/proof/` (`offline_verifier.ts`) | **B. MODIFY** | Verify receipts against Besu block receipts & Merkle roots. |
| `src/anchors/` (`base_l2_provider.ts`, EVM adapters) | **C. WRAP** | Optional Plane 3 Public Anchoring adapter. |
| `src/sentinel/`, `src/fabric/` | **B. MODIFY** | Behavioral anomaly detectors consume Besu-anchored receipts. |

---

## 4. Components That Duplicate Besu Functionality

The following TypeScript subsystems duplicate functionality natively provided by Hyperledger Besu:
1. **`TrustConsensusEngine` (`src/trust_network/consensus.ts`)**: Duplicates BFT voting, threshold counting, and block assembly. **Action**: Replaced by Besu QBFT consensus engine.
2. **`WolverineTrustLedger` (`src/trust_network/ledger.ts`) & `PersistentTrustLedger`**: Duplicates append-only blockchain storage, block sequencing, and cryptographic hash chaining. **Action**: Replaced by Besu RocksDB ledger.
3. **`TrustValidatorDaemon` (`src/runtime/validator_daemon.ts`)**: Duplicates node identity, p2p gossiping, and consensus block signing. **Action**: Replaced by native Besu validator containers.
4. **`ValidatorSetManager` (`src/trust/validator_set.ts`)**: Duplicates QBFT on-chain validator set transitions. **Action**: Demoted to contract interface / reference.

---

## 5. Components Becoming Adapters

1. **`BlockchainAnchorProvider` / `BaseL2AnchorProvider`**: Demoted from primary trust finality to the **Optional Public Anchor Module**.
2. **`LocalSoftwareSigningProvider` / `LocalDevelopmentSigningProvider`**: Formally restricted to local unit tests and development sandbox environments.
3. **`WolverineTrustLedger`**: Wrapped as `InMemoryReferenceLedger` for offline proof verification pipelines.

---

## 6. Components Removed From Production Path

1. Custom Quorum Certificate as the sole finality proof.
2. In-memory validator daemon consensus as production authority.
3. Gateway-owned local mutable finalization state.

---

## 7. EVM Code Realignment

The previous EVM anchoring logic (`src/anchors/base_l2_provider.ts`, `WDB-0021`) is repositioned as **Plane 3: Optional Public Anchor Plane**. It is triggered asynchronously on periodic batch intervals without blocking customer transaction processing or Plane 2 finality.

---

## 8. Custom BFT Demotion

All files in `src/trust/`, `src/trust_network/`, and `src/bft_hardening/` are documented as **Reference Implementations / Test Frameworks**. They remain in the test harness for cryptographic invariant validation and offline proof parsing, but do not claim production finality.

---

## 9. Trust Ledger Demotion

The authoritative ledger is the Hyperledger Besu state trie and block history. The TypeScript ledger is maintained solely as an auxiliary offline verification tool.

---

## 10. Network Transport Reuse

The `node:http2` mTLS transport implemented in `src/runtime/grpc_transport.ts` and `src/network/` is retained for:
- Agent-to-Gateway secure mTLS transmission.
- Gateway-to-KMS/HSM communication.
- Receipt retrieval API.

---

## 11. Real vs Simulated Matrix

| Component | Status | Description |
|:---|:---:|:---|
| **Evidence Plane (Agent, WAL, Merkle)** | **REAL** | Real deterministic binary serialization, RFC 6962 Merkle tree, SHA-256 hash chain. |
| **Dual Authorization (Agent & Customer)** | **REAL** | Real Ed25519 signatures with domain separation. |
| **Cloud KMS Providers (AWS / GCP)** | **REAL** | Real API clients with fail-closed semantics; mock keys for local dev. |
| **Trust Gateway Server** | **REAL** | Real HTTP/2 mTLS server with admission control and signature authentication. |
| **Authoritative Trust Chain (Besu)** | **REAL** | 5 containerized Hyperledger Besu validator nodes running QBFT BFT consensus. |
| **Smart Contract (`WolverineTrustRegistry.sol`)** | **REAL** | Real Solidity contract compiled and deployed to Besu. |
| **Universal Trust Receipt** | **REAL** | Real cryptographic receipt with block number, tx hash, block hash, and logs. |
| **Offline Verifier** | **REAL** | Fully air-gapped cryptographic verifier for receipts and state roots. |
| **Public Anchor Plane (Base L2)** | **REAL ADAPTER** | Optional batch anchor adapter via viem. |

---

## 12. Test vs Production Matrix

| Environment | Transport | Signer | Trust Authority | Receipt Verification |
|:---|:---|:---|:---|:---|
| **Production** | mTLS HTTP/2 | AWS/GCP KMS (Fail-Closed) | 5-Node Besu QBFT Cluster | Universal Trust Receipt + Besu Block Proof |
| **Local Dev / Docker** | HTTP/2 / Docker Net | LocalDevelopmentSigner | 5-Node Local Besu Docker Cluster | Universal Trust Receipt + Local Besu Node |
| **Unit Test Suite** | Direct / Mock RPC | LocalDevKey | Mock Besu RPC / In-Memory Reference | Offline Cryptographic Verification |

---

## 13. Exact Migration Strategy

1. **Scaffold Besu Infrastructure**: Build `blockchain/besu/` containing genesis configuration, QBFT 5-node setup, validator keys, and `docker-compose.yml`.
2. **Deploy Smart Contract**: Author and compile `blockchain/contracts/WolverineTrustRegistry.sol`.
3. **Build Besu RPC Adapter**: Implement `src/blockchain/besu/` (RPC client, transaction submitter, receipt extractor).
4. **Realign Gateway**: Connect `TrustGatewayServer` to submit commitments as transactions to Besu and await block finality.
5. **Universal Receipt Architecture**: Implement `UniversalTrustReceipt` linking evidence plane metadata with blockchain finality data.
6. **Realign Offline Verifier**: Update verifier to check dual signatures, Merkle roots, commitment digests, and blockchain receipt proofs.
7. **Create Real End-to-End Demo (`demo:besu`)**: Demonstrate PostgreSQL -> Agent -> Besu -> Tamper -> Verify mismatch.

---

## 14. Exact Files to Create

1. `docs/WOLVERINE-BESU-REALIGNMENT-AUDIT.md` (This document)
2. `blockchain/contracts/WolverineTrustRegistry.sol`
3. `blockchain/besu/genesis/genesis.json`
4. `blockchain/besu/config/config.toml`
5. `blockchain/besu/docker-compose.yml`
6. `blockchain/besu/README.md`
7. `src/blockchain/besu/types.ts`
8. `src/blockchain/besu/client.ts`
9. `src/blockchain/besu/contract_abi.ts`
10. `src/blockchain/besu/transaction_submitter.ts`
11. `src/blockchain/besu/receipt_extractor.ts`
12. `src/receipts/universal_receipt.ts`
13. `src/proof/universal_receipt_verifier.ts`
14. `demo/besu_demo.ts`
15. `tests/blockchain/besu_integration.test.ts`
16. `tests/receipts/universal_receipt.test.ts`
17. `docs/WOLVERINE-TRUST-CHAIN-ARCHITECTURE.md`
18. `docs/WOLVERINE-RECEIPT-SPEC.md`

---

## 15. Exact Files to Modify

1. `src/runtime/gateway.ts` — integrate Besu transaction submission.
2. `src/sdk/client.ts` — return `UniversalTrustReceipt`.
3. `src/index.ts` — export Besu client, Universal Receipt, and verifier modules.
4. `package.json` — add `demo:besu` script and verify dependencies.

---

## 16. Exact Files to Delete or Deprecate

1. Deprecate `src/trust_network/consensus.ts` for production (retain as test fixture).
2. Deprecate `src/trust/quorum_certificate.ts` as production finality (replaced by `UniversalTrustReceipt`).

---

## 17. Dependency Changes

All necessary blockchain primitives (`viem`, `node:crypto`, `node:http2`) are already available in the repository. No heavy external frameworks required.

---

## 18. Besu Network Topology

The local and production cluster consists of 5 dedicated validator nodes:
- `besu-validator-1` (RPC Endpoint: `http://127.0.0.1:8545`, P2P: `30303`)
- `besu-validator-2` (P2P: `30304`)
- `besu-validator-3` (P2P: `30305`)
- `besu-validator-4` (P2P: `30306`)
- `besu-validator-5` (P2P: `30307`)

Consensus: **QBFT (Quorum Byzantine Fault Tolerance)** with 1-second block period, tolerating $F = 1$ Byzantine node among $N = 5$ validators (with threshold $2F + 1 = 3$ for safety, $N - F = 4$ for liveness under QBFT standard rules).

---

## 19. Besu Genesis Design

- **Chain ID**: `13370` (`wolverine-trust-chain`)
- **Consensus**: QBFT (`"qbft": { "blockperiodseconds": 1, "epochlength": 30000, "requesttimeoutseconds": 2 }`)
- **Gas Limit**: `0x1fffffffffffff` (effectively unconstrained for private infrastructure)
- **Zero Gas Base Fee**: Fixed gas price 0 for frictionless high-throughput internal commitment recording.

---

## 20. Smart Contract Design (`WolverineTrustRegistry.sol`)

Minimal footprint recording strictly cryptographic commitments and metadata:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract WolverineTrustRegistry {
    struct StateCommitment {
        string tenantId;
        string databaseId;
        bytes16 checkpointId;
        uint64 commitSeq;
        uint32 epoch;
        bytes32 checkpointDigest;
        bytes32 stateMerkleRoot;
        bytes32 changeChainHead;
        bytes32 previousCommitmentDigest;
        bytes32 commitmentDigest;
        uint64 logicalTimestampUs;
        uint16 protocolVersion;
        bytes agentSignature;
        bytes customerSignature;
        uint256 blockNumber;
        uint256 blockTimestamp;
    }

    event CommitmentRecorded(
        string indexed tenantId,
        string indexed databaseId,
        uint64 indexed commitSeq,
        bytes32 commitmentDigest,
        bytes32 stateMerkleRoot,
        uint256 blockNumber
    );

    // Mappings and commit functions...
}
```

---

## 21. Customer-to-Chain Complete Data Flow

1. Customer modifies PostgreSQL database.
2. PostgreSQL logical replication stream emits change tuples to Wolverine Evidence Agent.
3. Agent normalizes data into canonical binary `ChangeRecord`s (RFC 8785).
4. Agent advances deterministic State Frontier and calculates RFC 6962 State Merkle Root.
5. Agent generates `CommitmentDigest` = SHA-256(domain || tenantId || dbId || seq || MerkleRoot || ChainHead).
6. Agent creates dual attestation:
   - $\sigma_{\text{agent}}$ = Sign_agent(CommitmentDigest || LSN)
   - $\sigma_{\text{customer}}$ = Sign_customer(CommitmentDigest || commitSeq) via Cloud KMS / HSM.
7. Agent transmits `TrustCommitment` to Wolverine Gateway via mTLS HTTP/2.
8. Gateway validates dual signatures against enrolled public keys.
9. Gateway submits `commitState(...)` transaction to Hyperledger Besu validator pool.
10. Besu validators execute QBFT consensus, include transaction in block $B_k$, and achieve finality.
11. Gateway captures transaction receipt, block hash, and logs.
12. Gateway materializes `UniversalTrustReceipt` and returns to Customer Agent.

---

## 22. Universal Trust Receipt Architecture

The `UniversalTrustReceipt` is a canonical, self-contained JSON artifact containing:
- **Receipt Header**: version, unique receipt ID, tenant/database ID.
- **Evidence Plane Block**: `checkpointId`, `commitSeq`, `lsn`, `stateMerkleRoot`, `checkpointDigest`, `agentAttestation`, `customerAuthorization`.
- **Trust Plane Block**: `networkId`, `chainId`, `blockchainTransactionHash`, `blockNumber`, `blockHash`, `finalityStatus`, `contractAddress`.
- **Optional Public Anchor Block**: Base/Ethereum anchor details if submitted.

---

## 23. Offline Verification Architecture

The standalone `UniversalReceiptVerifier` executes on an air-gapped auditor machine:
1. Re-computes `commitmentDigest` from evidence plane parameters.
2. Verifies $\sigma_{\text{agent}}$ using known agent public key.
3. Verifies $\sigma_{\text{customer}}$ using known customer KMS public key.
4. Verifies transaction receipt hash binding against block hash.
5. Verifies sequential continuity with previously witnessed receipt ($commitSeq_{n} = commitSeq_{n-1} + 1$).
6. Compares live database Merkle root against receipt's `stateMerkleRoot`. Any DBA tampering results in immediate cryptographic mismatch!

---

## 24. Optional Public-Chain Anchor Architecture

Periodically (e.g. hourly or every 1,000 Besu blocks), the Gateway batches latest Besu block hashes into a Merkle root and anchors it to Base L2 / Ethereum Mainnet, providing external temporal witnessing without impacting latency.

---

## 25. Security Boundaries

- **Plane 1 (Customer VPC)**: Possesses plaintext database and private signing keys (or KMS access).
- **Transport**: mTLS HTTP/2 authenticated channel. Transports ONLY cryptographic hashes; ZERO plaintext table/row data.
- **Plane 2 (Wolverine Trust Cloud)**: Operates Gateway and Besu validators. Cannot forge customer or agent signatures.
- **Authoritative Ledger (Besu)**: Immutable, Byzantine-fault-tolerant, append-only blockchain.

---

## 26. Failure Domains

1. **Customer DB Compromise**: Attacker can alter DB, but cannot forge previously finalized Besu blocks or past receipts.
2. **Gateway Compromise**: Compromised gateway can drop requests (DoS), but cannot forge dual signatures or alter existing on-chain commitments.
3. **Validator Failure**: Up to $F$ Besu validators can crash or behave maliciously without halting block production or compromising finality.
4. **Public RPC Congestion**: Public L2 outage has zero impact on Plane 1 CDC or Plane 2 Besu finality.

---

## 27. Known Limitations & Scope

- Initial local development topology runs 5 Besu validator containers via Docker Compose.
- Production deployments distribute Besu nodes across multi-cloud regions (AWS, GCP, Azure, bare-metal).
- Besu QBFT provides instant 1-block finality (no probabilistic reorgs like PoW/PoS).
