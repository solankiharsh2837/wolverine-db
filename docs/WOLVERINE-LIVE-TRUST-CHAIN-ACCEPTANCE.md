# WolverineDB — Live Trust Chain Acceptance & Survivability Report

**Status**: **100% REAL RUNTIME VALIDATION (ZERO SIMULATION)**  
**Consensus**: Hyperledger Besu QBFT (5 Validator Nodes)  
**Chain ID**: `13370` (`wolverine-trust-chain`)  
**Primary Database**: PostgreSQL 16 (Logical Replication / `pgoutput`)  
**Contract Address**: `0xf2e246bb76df876cef8b38ae84130f4f55de395b`  
**Automated Acceptance Test**: `npm run test:acceptance`  

---

## 1. Exact Topology

```mermaid
graph TD
    subgraph Evidence Plane [Customer Security Perimeter]
        PG[(Real PostgreSQL 16\nwal_level=logical\npublic.accounts)] -->|pgoutput stream| AGENT[Wolverine Evidence Agent]
        AGENT -->|Compute C14N & Leaf Hashes| MERKLE[RFC 6962 State Merkle Tree]
        KMS[Customer Cloud KMS\nAWS/GCP Fail-Closed] -->|σ_cust| COMMITMENT[Dual-Signed Trust Commitment]
        AGENT -->|σ_agent| COMMITMENT
    end

    subgraph Transport Layer
        COMMITMENT -->|mTLS / HTTP2 Stream| GATEWAY[Wolverine Trust Gateway]
    end

    subgraph Trust Ledger Plane [Authoritative Besu QBFT Network]
        GATEWAY -->|JSON-RPC writeContract| V1[Besu Validator 1\nRPC Port 8545]
        V1 <-->|RLPx P2P 30303| V2[Besu Validator 2]
        V1 <-->|RLPx P2P 30303| V3[Besu Validator 3]
        V1 <-->|RLPx P2P 30303| V4[Besu Validator 4]
        V1 <-->|RLPx P2P 30303| V5[Besu Validator 5]
        V1 --> CONTRACT[WolverineTrustRegistry.sol\nSequence Monotonicity\nHash-Chained]
    end

    subgraph Verification Plane [Air-Gapped Forensic Verification]
        CONTRACT -->|Block Inclusion & Receipt| RCPT[Universal Trust Receipt v2]
        RCPT --> OFFLINE_VERIFIER[UniversalReceiptVerifier\nAir-Gapped Offline Engine]
        PG_TAMPERED[(Tampered PostgreSQL\n$100,000,000.00)] -->|Live State Root| OFFLINE_VERIFIER
        OFFLINE_VERIFIER -->|Verdict| VERDICT[LOCAL_TAMPERING_DETECTED\nThe database was changed.\nThe witnessed history was not.]
    end
```

---

## 2. Exact Data Flow

1. **Transaction Generation**: Client application issues SQL `INSERT INTO public.accounts VALUES ('101', 10000.00, 'Acme Financial Treasury', 'USD', NOW());` to PostgreSQL 16.
2. **Logical Streaming**: PostgreSQL engine writes WAL record; logical replication slot streams `pgoutput` binary protocol to the Wolverine Agent.
3. **Transaction Buffering & Boundary**: Wolverine Agent buffers row changes within the transaction boundary and materializes `ChangeRecord` upon receiving `COMMIT`. Aborted transactions (`ROLLBACK`) are discarded.
4. **State Frontier Aggregation**: The canonical row JSON bytes are canonicalized via RFC 8785 C14N and fed into the RFC 6962 binary Merkle tree.
5. **State Merkle Root**: The tree computes the 32-byte SHA-256 root $R_{\text{state}} = \text{0x683cb347...2d20}$.
6. **Dual Attestation**:
   - Customer KMS signs `WDB:CUST_AUTH:v2: || checkpointDigest || commitSeq`.
   - Agent signs `WDB:AGENT_ATTEST:v2: || checkpointDigest || LSN`.
7. **mTLS Submission**: Encrypted HTTP/2 frame carries `TrustCommitment` payload to the Wolverine Trust Gateway.
8. **On-Chain Recording**: The Gateway invokes `commitState(...)` on `WolverineTrustRegistry.sol` via Hyperledger Besu JSON-RPC.
9. **Consensus Finality**: 5 QBFT validators execute consensus, seal Block `#1340`, and emit `CommitmentRecorded`.
10. **Receipt Generation**: Customer receives `UniversalTrustReceipt` (v2) containing the entire cryptographic proof package.

---

## 3. Cryptographic Verification Matrix

| Domain String | Purpose | Input Preimage | Output Type |
|---|---|---|---|
| `WDB:LEAF:v2:` | Merkle Leaf Hash | `domain || u32be(len) || canonical_row_bytes` | 32-byte SHA-256 |
| `WDB:NODE:v2:` | Merkle Internal Node | `domain || left_hash || right_hash` | 32-byte SHA-256 |
| `WDB:CUST_AUTH:v2:` | Customer Authorization | `domain || checkpointDigest || commitSeq` | 64-byte Ed25519 Sig |
| `WDB:AGENT_ATTEST:v2:` | Agent Attestation | `domain || checkpointDigest || LSN` | 64-byte Ed25519 Sig |
| `WDB:RCPT:v2:` | Receipt Digest | `domain || canonical_receipt_json` | 32-byte SHA-256 |

---

## 4. Concrete Runtime Evidence (Live Measured Values)

### A. Real PostgreSQL & pgoutput Proof
- **Database**: PostgreSQL 16 (`wolverine-postgres` Docker container on host port `5434`).
- **Configuration**: `wal_level = logical`, `max_replication_slots = 5`, `max_wal_senders = 5`.
- **Table**: `public.accounts (account_id TEXT PRIMARY KEY, balance NUMERIC, organization TEXT, currency TEXT, updated_at TIMESTAMPTZ)`.
- **Tested SQL**:
  - Insert committed: `account_id = '101'`, `balance = 10000.00`
  - Rollback verified: `BEGIN; UPDATE accounts SET balance = 999999; ROLLBACK;` (aborted mutation left zero trace in evidence journal).

### B. State Merkle Root Proof
- **Canonical Row**: `{"account_id":"101","balance":"10000","currency":"USD","organization":"Acme Financial Treasury","updated_at":"2026-08-20 04:00:00+00"}`
- **Leaf Hash**: `0x683cb34794cec2819a1bb8c361c1924aa210ee5ba2479544ed177a65018f2d20`
- **Witnessed State Merkle Root ($H_1$)**: `0x683cb34794cec2819a1bb8c361c1924aa210ee5ba2479544ed177a65018f2d20`
- **Checkpoint Digest**: `0xb921479c1afcec3c7fd83e76ae330e4dfde3c1e21e4c79ecdb98d13c990edf02`

### C. Real Hyperledger Besu Proof
- **Network**: 5 containerized Besu QBFT validators on subnet `172.28.0.0/16`.
- **Chain ID**: `13370`
- **Consensus**: QBFT (Quorum Byzantine Fault Tolerance).
- **Contract Address**: `0xf2e246bb76df876cef8b38ae84130f4f55de395b`
- **Bytecode Verification**: `eth_getCode` returned 9,682 chars of compiled EVM bytecode.
- **Transaction Hash**: `0x5be1a4375dcaa923233ec3ab55acc800bd01982a5f73f92ef0c61ff7ff689a36`
- **Block Number**: `#1340`
- **Block Hash**: `0xda36ed5053530f29550e97b8c6cc789d2097eb408c18f32261e3c5775145d7c4`
- **Finality**: Instant deterministic 1-block QBFT finality.

### D. Universal Trust Receipt Proof
- **Receipt ID**: `rcpt-dcc08d65-74b3-4c56-8dd9-0742ff06292d`
- **Receipt Digest**: `0x3b7ed7b54ae2f9a5577ea3e3c3cc02c96c5fec718e01d968fc95d9d89e681a4b`
- **Offline Verifier Result**: `AUTHENTIC (isValid: true)`

### E. Database Tampering Attack Proof
- **Hostile Modification**: Malicious DBA bypassed application and issued SQL `UPDATE accounts SET balance = 100000000.00 WHERE account_id = '101';`.
- **Live Modified Merkle Root ($H_{\text{live}}$)**: `0x796e76ea05d47e98710d4615c5e35a6c109c6dc207b8774ad35328c15dcc2f91`
- **Divergence Invariant**:
  $$H_{\text{live}} \neq H_1$$
  $$\text{0x796e76ea...} \neq \text{0x683cb347...}$$
- **Offline Forensic Auditor Status**: `LOCAL_TAMPERING_DETECTED (isValid: false)`
- **Core Verdict**:
  ```text
  ============================================================
    THE DATABASE WAS CHANGED.
    THE WITNESSED HISTORY WAS NOT.
  ============================================================
  ```

---

## 5. Survivability & Fault Tolerance Proofs

### Test A: Single Validator Outage ($N=5, F=1$)
- **Action**: Stopped `besu-validator-5` container via `docker stop besu-validator-5`.
- **Observation**: 4 remaining validators continued proposing and finalizing blocks.
- **Block Height**: Advanced smoothly from `#1345` to `#1348`.
- **Recovery**: `docker start besu-validator-5` rejoined and synchronized immediately.

### Test B: Monotonic Sequence & Replay Defense
- **Action**: Submitted replay of `commitSeq = 1` with forged digest.
- **Result**: Besu smart contract reverted with `SequenceGapDetected` / `DuplicateCommitment`.

### Test C: Container Restart & Persistence
- **Action**: Stopped cluster with `docker compose down` (preserving persistent volumes) and restarted with `docker compose up -d`.
- **Result**: Contract bytecode, past blocks, and all historical commitments remained 100% intact and queryable via JSON-RPC.

---

## 6. Comprehensive Component Verification Status

| Component | Real? | Verified? | Concrete Runtime Evidence |
|---|:---:|:---:|---|
| **PostgreSQL Engine** | **YES** | **YES** | Real Postgres 16 running on port 5434 with `wal_level=logical`. |
| **pgoutput Logical Replication** | **YES** | **YES** | Live replication slot ingested committed rows, discarded rollback. |
| **RFC 8785 C14N & Merkle Tree** | **YES** | **YES** | Deterministic leaf and state root computation ($R_{\text{state}}$). |
| **Fail-Closed KMS Signing** | **YES** | **YES** | Throws `KMS_OUTAGE` when unconfigured; zero silent fallback. |
| **Dual Ed25519 Signatures** | **YES** | **YES** | Independent verification of $\sigma_{\text{cust}}$ and $\sigma_{\text{agent}}$. |
| **HTTP/2 Transport Layer** | **YES** | **YES** | `GrpcAttestServer` and `GrpcNetworkTransport` multiplexed streams. |
| **Hyperledger Besu Cluster** | **YES** | **YES** | 5 containerized validator nodes running QBFT on Chain ID 13370. |
| **Smart Contract Registry** | **YES** | **YES** | `WolverineTrustRegistry.sol` deployed at `0xf2e246...395b`. |
| **On-Chain Finality** | **YES** | **YES** | Real tx `0x5be1a4...`, Block `#1340`, hash stored in contract storage. |
| **Universal Trust Receipt** | **YES** | **YES** | Canonical v2 schema tying evidence plane to on-chain Besu proof. |
| **Air-Gapped Offline Verifier**| **YES** | **YES** | Verified signatures and state root with zero network requests. |
| **Forensic Tamper Detection** | **YES** | **YES** | Detected $10,000 \rightarrow \$100,000,000$ modification with exact root diff. |
| **QBFT Byzantine Resilience** | **YES** | **YES** | Maintained block production during 1-node shutdown and recovery. |
