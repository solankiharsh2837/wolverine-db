# Architectural Abstract: AI (Sentinel/AEGIS) & Blockchain (EVM Anchoring) Layers

This document outlines the architectural blueprints, technical requirements, interfaces, and integration paths for the two remaining specialized layers in WolverineDB: the **Autonomous AI Defense Layer (Sentinel / AEGIS Fabric)** and the **Production Decentralized Blockchain Layer (EVM Anchoring & Rollup Verifier)**.

---

## 1. Autonomous AI Defense Layer (AEGIS / Sentinel Fabric)

### 1.1 Current In-Code State
- **Deterministic Baseline Tracker & Anomaly Detector** (`src/sentinel/baseline.ts`, `src/sentinel/anomaly_engine.ts`): Tracks statistical limits, typical transaction volumes, maintenance windows, and generates deterministic anomaly scores.
- **Rule-Based Sentinel Advisor & Policy Gate** (`src/sentinel/advisor.ts`, `src/sentinel/policy_gate.ts`): Proposes scope quarantine, actor suspension, or throttle actions based on invariant threshold violations.
- **Security Fabric & Incident Graph** (`src/fabric/correlation_graph.ts`, `src/fabric/risk_engine.ts`): Creates canonical, deterministic directed acyclic graph (DAG) representations of causal incident nodes, actors, processes, and state changes.

### 1.2 Future Production AI Layer Requirements
1. **Transformer-Based Causal Semantic Anomaly Modeling**:
   - **Offline Model Training**: Train an embedding model on normalized SQL change payloads (`ChangeRecordData`) and actor behavioral vectors to identify sophisticated multi-step prompt injection or database exfiltration behaviors.
   - **Local Inference Engine (ONNX Runtime / GGML / Wasm)**: Execute low-latency (< 2ms) local inferences without leaking sensitive plaintext database column payloads over public LLM APIs.
2. **Autonomous Multi-Agent Incident Response (AEGIS Orchestration)**:
   - **Decentralized Multi-Agent Consensus**: When the AI proposes a quarantine or schema freeze, a multi-party MPC or validator quorum must evaluate the mathematical safety invariants before automated rollback or partition is applied.
   - **Formal Policy Verifier (Policy Gate Extension)**: Strict mathematical verification of LLM/AI output (AST validation) to prevent hallucinations from causing unintended table drops or invalid data state overrides.
3. **Federated Threat Intelligence Sharing**:
   - **Zero-Knowledge Incident Proofs**: Allow independent organizations running WolverineDB to share incident correlation graph digests and malicious actor behavioral signatures across clusters without revealing confidential data values or database schema specifics.

---

## 2. Production Blockchain Layer (EVM & Rollup Layer)

### 2.1 Current In-Code State
- **Mock EVM Anchor Adapter** (`src/anchors/evm.ts`): Simulates block advancement, gas limits, transaction finality confirmations, and chain reorganization unwinding.
- **WORM Vault & Cross-Domain Verifier** (`src/checkpoint/worm.ts`, `src/anchors/verifier.ts`): Binds local state checkpoints with remote cryptographic proofs.
- **Decentralized Receipt Serialization** (`src/trust_receipt/receipt.ts`): Portable, standalone cryptographic receipts containing dual-signed customer commitments and BFT quorum certificates.

### 2.2 Future Production Blockchain Integration Requirements
1. **Solidity / Vyper Smart Contracts**:
   - **`WolverineCheckpointRegistry.sol`**:
     - State storage for `(tenantId, databaseId, commitSeq, checkpointDigest, merkleRoot, valsetHash)`.
     - Direct on-chain verification of BLS12-381 or Ed25519 threshold quorum signatures submitted by the validator network.
     - Slashing mechanics: On-chain submission of equivocation proofs (conflicting commitments signed by the same validator for the same sequence) to immediately burn validator stake.
2. **Web3 RPC Adapter (`src/anchors/web3_adapter.ts`)**:
   - Production JSON-RPC provider (e.g. Infura, Alchemy, or self-hosted Erigon/Geth nodes) supporting Ethereum mainnet, Polygon, Arbitrum, Base, and private enterprise networks (Hyperledger Besu).
   - Dynamic EIP-1559 gas fee estimation, automated transaction resubmission, nonce management, and reorg re-anchoring.
3. **ZK-Rollup & Succinct State Validity Proofs (Groth16 / STARK)**:
   - Generate SNARK validity proofs over thousands of database mutations (`ChangeRecordData`), verifying the transition from Merkle state root $R_{t}$ to $R_{t+1}$.
   - Post compact validity proofs to L1 / L2, reducing on-chain gas costs by ~98% while providing cryptographic data availability and immutability guarantees.

---

## 3. Recommended Decision Path & Next Steps

When ready to implement either layer:
1. **AI Layer Decision**: Choose between an embedded ONNX runtime for sub-millisecond local inference vs. a gRPC-connected dedicated microservice for cluster-wide incident analysis.
2. **Blockchain Layer Decision**: Deploy `WolverineCheckpointRegistry.sol` to a testnet (e.g. Sepolia or Arbitrum Sepolia) and replace the mock `EvmAnchorAdapter` with a production Web3/Ethers.js provider that consumes contract ABIs.
