# WolverineDB — Live Besu Trust Chain Specification & Operations Manual

**Document Version**: 2.0 (Live Implementation Baseline)  
**System Status**: Production-Aligned Physical Integration  
**Primary Trust Ledger**: Hyperledger Besu Permissioned QBFT Cluster (`Chain ID: 13370`)

---

## 1. Architecture Overview

WolverineDB provides continuous, tamper-evident state witnessing and verifiable reconstruction for relational databases:

```
[CUSTOMER VPC]
PostgreSQL Database ───(Logical Replication / pgoutput)───> Wolverine Evidence Agent
                                                                  │
                                                                  ├── Durable Journal (Append-only)
                                                                  ├── State Frontier
                                                                  └── RFC 6962 State Merkle Root
                                                                         │
                                                                  Dual Attestation
                                                                  ├── σ_agent  = Sign(Digest || LSN)
                                                                  └── σ_cust   = Sign_KMS(Digest || Seq)
                                                                         │
                                                                  TrustCommitment C_n

[TRANSPORT]
Real HTTP/2 mTLS Sockets (node:http2) ─────────────────────────> Trust Gateway (Untrusted Router)

[AUTHORITATIVE TRUST PLANE]
Trust Gateway ───(viem JSON-RPC)───────────────────────────────> Hyperledger Besu Cluster
                                                                  ├── 5 Dedicated QBFT Validators
                                                                  ├── WolverineTrustRegistry.sol
                                                                  └── Instant 1-Block BFT Finality
                                                                         │
                                                                  Universal Trust Receipt
                                                                         │
                                                        ┌────────────────┴────────────────┐
                                                        ▼                                 ▼
                                                Customer Archive                  Air-Gapped Auditor
```

---

## 2. Core System Components

1. **Wolverine Evidence Agent (`src/evidence/`, `src/wal/`)**:
   - Ingests native `pgoutput` logical replication bytes directly from PostgreSQL.
   - Normalizes transactions deterministically into `ChangeRecordData`.
   - Maintains an append-only hash chain in `DurableEvidenceJournal`.
   - Updates `DeterministicStateFrontier` and computes RFC 6962 State Merkle Root.
2. **KMS Signing Providers (`src/crypto/`)**:
   - `AwsKmsSigningProvider` & `GcpKmsSigningProvider`: Enforce strict fail-closed semantics (no HMAC or software fallbacks).
   - `LocalDevelopmentSigningProvider`: Explicit local testing signer requiring `WOLVERINE_DEV_SIGNER=1`.
3. **Trust Gateway (`src/runtime/`, `src/daemons/`)**:
   - Operates as an untrusted router over HTTP/2 (`node:http2`).
   - Verifies customer authorization and agent attestation signatures.
   - Dispatches `commitState` transaction to Hyperledger Besu.
4. **Hyperledger Besu QBFT Cluster (`blockchain/besu/`)**:
   - 5 containerized validator nodes maintaining the authoritative trust ledger.
   - Executes smart contract [`WolverineTrustRegistry.sol`](file:///c:/Users/harsh/Documents/Codex/2026-08-13/referenced-chatgpt-conversation-this-is-an/wolverine-db/blockchain/contracts/WolverineTrustRegistry.sol).
5. **Universal Trust Receipt & Verifier (`src/receipts/`, `src/proof/`)**:
   - Portable, canonical v2 receipt containing evidence plane, trust plane, and block binding.
   - Standalone `UniversalReceiptVerifier` executes on air-gapped auditor machines.

---

## 3. Docker & Besu Network Topology

- **Docker Compose File**: [`blockchain/besu/docker-compose.yml`](file:///c:/Users/harsh/Documents/Codex/2026-08-13/referenced-chatgpt-conversation-this-is-an/wolverine-db/blockchain/besu/docker-compose.yml)
- **Validators**:
  - `besu-validator-1`: `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf` (RPC port: `8545`, P2P: `30303`)
  - `besu-validator-2`: `0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF` (P2P: `30304`)
  - `besu-validator-3`: `0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69` (P2P: `30305`)
  - `besu-validator-4`: `0x1efF47bc3a10a45D4B230B5d10E37751FE6AA718` (P2P: `30306`)
  - `besu-validator-5`: `0xe1AB8145F7E55DC933d51a18c793F901A3A0b276` (P2P: `30307`)

---

## 4. QBFT Consensus & Finality

- **Consensus**: QBFT (Quorum Byzantine Fault Tolerance).
- **Fault Model**: $N = 5, F = 1$. The cluster tolerates 1 Byzantine (offline or malicious) validator:
  $$N \ge 3F + 1 \implies 5 \ge 4$$
- **Quorum**: Safety requires $2F + 1 = 3$ validators; Liveness requires $N - F = 4$ validators.
- **Block Time**: 1 second.
- **Finality**: Deterministic, instant 1-block finality with zero chain forks.

---

## 5. Smart Contract Architecture (`WolverineTrustRegistry.sol`)

- **State Storage**: Records `tenantId`, `databaseId`, `checkpointId`, `commitSeq`, `epoch`, `checkpointDigest`, `stateMerkleRoot`, `changeChainHead`, `previousCommitmentDigest`, `commitmentDigest`, `logicalTimestampUs`, `protocolVersion`, `agentSignature`, and `customerSignature`.
- **Enforcement**:
  - Sequence monotonicity: Rejects any gap or regression ($commitSeq_n = commitSeq_{n-1} + 1$).
  - Predecessor linkage: Rejects if `previousCommitmentDigest` does not match sequence $n-1$.
  - Replay protection: Rejects duplicate `commitmentDigest`.
- **Data Non-Disclosure**: Zero plaintext rows, column values, SQL text, or database names are stored on-chain.

---

## 6. Failure Semantics & Fail-Closed Policies

1. **Besu Unavailable**: Gateway queues or rejects; **NO fake transaction hashes or synthetic block numbers are ever fabricated**.
2. **KMS Outage**: Agent fails closed with `KMS_OUTAGE` (WDB703); **NO HMAC or silent software fallback**.
3. **Attestation Mismatch**: Gateway rejects incoming commitment; no transaction is submitted.
4. **PostgreSQL Slot Invalidation**: Agent halts immediately to prevent fabricated continuity.

---

## 7. Local Operational Commands

```bash
# 1. Start the 5-node Besu QBFT cluster
npm run besu:up

# 2. Check cluster status, peer count, and contract deployment
npm run besu:status

# 3. Deploy WolverineTrustRegistry.sol to live Besu network
npm run besu:deploy

# 4. Run real live end-to-end demonstration against Besu
npm run demo:besu-live

# 5. Run air-gapped simulation demonstration (explicitly flagged)
npm run demo:besu-simulated

# 6. Stop the Besu cluster
npm run besu:down
```

---

## 8. What is NOT Yet Production-Ready (Honest Disclosures)

- **Public Chain Anchors**: Base/Ethereum notary batching is specified and simulated, but live public testnet anchoring is optional Plane 3 work.
- **Hardware Enclave Attestation**: The Evidence Agent currently executes as a software daemon with Ed25519 keys rather than inside AWS Nitro Enclaves / Intel SGX.
- **Multi-Cloud Geo-Distribution**: Local cluster executes via Docker bridge; production deployment requires distributed Kubernetes clusters across distinct cloud regions.
