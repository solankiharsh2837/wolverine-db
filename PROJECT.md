# Project: WolverineDB Adversarial Independent Security Review

## Architecture
WolverineDB is designed as a tamper-evident database evidence plane combining PostgreSQL Change Data Capture (CDC), cryptographic Merkle state frontier computation, dual-attestation client/agent authorization, and an immutable enterprise blockchain consensus ledger powered by Hyperledger Besu QBFT.

### Subsystem Boundaries:
1. **Evidence Plane (`src/wal/`, `src/postgres/`, `src/evidence/`)**:
   - Ingests WAL mutations via PostgreSQL logical decoding (`pgoutput`).
   - Maintains transactional boundaries (BEGIN, COMMIT, ROLLBACK).
   - Computes incremental deterministic Merkle tree state frontiers (`DeterministicStateFrontier`).
2. **Gateway & Authorization Plane (`src/runtime/`, `src/daemons/`, `src/crypto/`, `src/trust/`)**:
   - Ingests customer transactions and evidence checkpoints.
   - Orchestrates Dual-Attestation signing ($\sigma_{\text{cust}}$ via KMS / Ed25519, $\sigma_{\text{agent}}$).
   - Manages KMS signing providers (AWS KMS, GCP KMS, Vault, local mock signers).
3. **Consensus & Blockchain Trust Plane (`blockchain/`, `src/blockchain/besu/`)**:
   - Hyperledger Besu QBFT private consortium network (5 validator nodes, 1-second block time).
   - Smart Contract `WolverineTrustRegistry.sol` recording on-chain state commitments, sequence numbers, and previous hashes.
   - Submitter client (`BesuTransactionSubmitter`, `BesuClient`).
4. **Verification & Proof Plane (`src/receipts/`, `src/proof/`)**:
   - Generates Universal Trust Receipt (`v2`).
   - `UniversalReceiptVerifier` and `AirGappedProofVerifier` for offline zero-trust auditability.

---

## Feature & Finding Inventory

| # | Domain / Feature | Finding ID | Severity | Description | Milestone | Source | Status |
|---|------------------|------------|----------|-------------|-----------|--------|--------|
| 1 | Consensus Authority | SEC-R1-01 | CRITICAL | Dual Consensus & Split-Brain: Live daemons (`GrpcGatewayServer`, `WdbGatewayDaemon`) run legacy TS BFT ledger instead of Besu QBFT | M1 | Explorer 1 | AUDITED |
| 2 | Consensus Key Management | SEC-R1-02 | CRITICAL | Plaintext Validator Keys: All 5 Besu QBFT validator private keys (`0x01`..`0x05`) committed in repo | M1 | Explorer 1 | AUDITED |
| 3 | Besu RPC Infrastructure | SEC-R1-03 | HIGH | Single Point of Failure & Unauthenticated RPC on validator-1 (open CORS, admin APIs enabled) | M1 | Explorer 1 | AUDITED |
| 4 | Validator Governance | SEC-R1-04 | MEDIUM | Missing Besu QBFT Dynamic Validator Rotation (rotation code only updates dead TS state) | M1 | Explorer 1 | AUDITED |
| 5 | Smart Contract Auth | SEC-R3-01 | CRITICAL | Unpermissioned `commitState()` in `WolverineTrustRegistry.sol`: anyone can commit for any tenant | M1 | Explorer 1 & 2 | AUDITED |
| 6 | Smart Contract Signatures | SEC-R3-02 / CRIT-01 | CRITICAL | Zero On-Chain Signature Verification: `agentSignature` and `customerSignature` stored without validation | M1 | Explorer 1 & 2 | AUDITED |
| 7 | Smart Contract Sequence | SEC-R3-03 | CRITICAL | Tenant Squatting & Frontrunning DoS: unpermissioned sequence 1 claim bricks legitimate customer onboarding | M1 | Explorer 1 | AUDITED |
| 8 | Smart Contract Digest | SEC-R3-04 | HIGH | Decoupled Commitment Digest: contract does not verify `commitmentDigest == hash(fields)` | M1 | Explorer 1 & 2 | AUDITED |
| 9 | Smart Contract Storage | SEC-R3-05 | MEDIUM | Global Mapping Collision Griefing in `commitments` map | M1 | Explorer 1 | AUDITED |
| 10 | Smart Contract Gas | SEC-R3-06 | LOW | Storage layout bloat (>300k gas per commitment) | M1 | Explorer 1 | AUDITED |
| 11 | Gateway Architecture | HIGH-01 | HIGH | Gateway Daemon Decoupled from Besu: runtime never invokes `BesuTransactionSubmitter` | M1 | Explorer 2 | AUDITED |
| 12 | Dual-Attestation Schema | HIGH-02 | HIGH | Triple-Conflicting Preimage Schemas & Missing Domain Separation (`chainId`, `contractAddress`, `tenantId`) | M1 | Explorer 2 | AUDITED |
| 13 | KMS Provider Security | HIGH-03 | HIGH | Silent HMAC Fallback in `CloudKmsSigningProvider` / `HsmSigningProvider` violates fail-closed invariant | M1 | Explorer 2 | AUDITED |
| 14 | KMS Dependencies | MEDIUM-01 | MEDIUM | Missing Cloud SDK dependencies and uninitialized zero-key buffers | M1 | Explorer 2 | AUDITED |
| 15 | Offline Receipt Proofs | SEC-R4-01 | HIGH | Universal Trust Receipt `v2` completely lacks EVM block headers, MPT inclusion proofs, and QBFT commit seals | M1 | Explorer 3 | AUDITED |
| 16 | Receipt Verifier Logic | SEC-R4-02 | HIGH | `UniversalReceiptVerifier.verifyOffline()` only checks non-empty strings and status, giving 0 cryptographic blockchain proof | M1 | Explorer 3 | AUDITED |
| 17 | CDC Transaction Races | SEC-R5-01 | HIGH | Shared mutable `currentXid` in `PgLogicalClient` leaks mutations across concurrent interleaved transactions | M1 | Explorer 3 | AUDITED |
| 18 | CDC Protocol Support | SEC-R5-02 | MEDIUM | `PgOutputDecoder` crashes on PostgreSQL 14+ streaming replication messages (`STREAM START`, `PREPARE`) | M1 | Explorer 3 | AUDITED |
| 19 | Merkle Frontier Perf | SEC-R5-03 | MEDIUM | Full table in-memory re-hashing and sorting on every commit ($O(N \log N)$ bottleneck) | M1 | Explorer 3 | AUDITED |
| 20 | Docker Fault Domains | SEC-R5-04 | MEDIUM | Single-host 5-node Docker deployment provides logical process isolation only ($f_{\text{actual}} = 0$) | M1 | Explorer 3 | AUDITED |

---

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Draft Canonical 3-Part Security Audit Report | Synthesize all 20 findings into Section A (Verdict /100), Section B (Ranked Findings), and Section C (5-Task Roadmap) in `docs/WOLVERINE-INDEPENDENT-SECURITY-AUDIT.md` | Survey Complete | DONE |
| M2 | Multi-Reviewer & Adversarial Challenger Verification | 2 Reviewers + 2 Challengers verify accuracy, completeness, byte-level schemas, and theorem proofs | M1 | DONE |
| M3 | Forensic Audit & Quality Gate | 1 Forensic Auditor verifies zero integrity violations, no dummy claims, complete coverage | M2 | DONE |
| M4 | Final Gate Approval & Delivery | Verify all acceptance criteria from ORIGINAL_REQUEST.md and deliver to Sentinel | M3 | DONE |

---

## Code Layout
- Target Delivery File: `docs/WOLVERINE-INDEPENDENT-SECURITY-AUDIT.md`
- Audited Codebases:
  - `blockchain/contracts/WolverineTrustRegistry.sol`
  - `blockchain/besu/` (configs, genesis, docker-compose, node keys)
  - `src/blockchain/besu/` (`client.ts`, `deploy.ts`, `transaction_submitter.ts`)
  - `src/runtime/` (`gateway.ts`, `grpc_gateway_server.ts`)
  - `src/daemons/` (`wdb_gateway_daemon.ts`)
  - `src/crypto/` (`signing_provider.ts`, `kms_signer.ts`, `dual_attestation.ts`)
  - `src/trust/` & `src/trust_network/` (`commitment.ts`)
  - `src/receipts/` (`universal_receipt.ts`)
  - `src/proof/` (`universal_receipt_verifier.ts`, `air_gapped_verifier.ts`)
  - `src/wal/` (`pg_logical_client.ts`, `pgoutput_decoder.ts`)
  - `src/evidence/` (`state_frontier.ts`, `journal.ts`)
