# Handoff Report — Explorer 1: Consensus (R1) & Smart Contracts (R3) Audit

**Agent**: Explorer 1  
**Milestone / Task**: Adversarial Independent Security Review — R1 (Consensus & Finality Authority) & R3 (Smart Contract Invariant & Authorization)  
**Date**: 2026-08-20  
**Status**: Hard Handoff (Complete)

---

## 1. Observation

### R1: Consensus & Finality Authority Observations
1. **Divergent Consensus Subsystems in Active Runtime**:
   - `src/runtime/grpc_gateway_server.ts:34-123` instantiates and invokes `TrustGatewayServer.ingestCommitment()`.
   - `src/runtime/gateway.ts:45-51, 163-166` directly instantiates `TrustConsensusEngine` and `WolverineTrustLedger`, running 3-of-5 threshold BFT voting in TypeScript and generating an `ImmutableTrustReceipt` (`src/trust_receipt/receipt.ts:94-97`).
   - `docker-compose.m3.yml:52-142` provisions five standalone TypeScript validator containers (`dist/bin/wdb-validator.js`) and a gateway container (`dist/bin/wdb-gateway.js`), listening on ports 9001–9005.
   - `BesuClient` (`src/blockchain/besu/client.ts`) is only called in `src/acceptance/live_acceptance.ts` and demo scripts (`src/demo/besu_live_demo.ts`, `src/demo/besu_simulated_demo.ts`). It is **completely unreferenced** in `src/runtime/gateway.ts` and `src/daemons/wdb_gateway_daemon.ts`.
2. **Hardcoded Plaintext Validator & Operator Private Keys**:
   - `blockchain/besu/nodes/node-1/key` through `node-5/key` contain private keys `0000000000000000000000000000000000000000000000000000000000000001` through `...05`.
   - `src/blockchain/besu/deploy.ts:26` hardcodes `operatorPrivateKeyHex = '0x0000000000000000000000000000000000000000000000000000000000000001'`.
   - `src/acceptance/live_acceptance.ts:35` also hardcodes `operatorPrivateKeyHex = '0x000...01'`.
3. **RPC Single Point of Failure & Unauthenticated Configuration**:
   - `blockchain/besu/docker-compose.yml:48-49` exposes ports 8545/8546 only on `besu-validator-1`. Validators 2–5 have no exposed RPC endpoints.
   - `blockchain/besu/config/config.toml:11-15` configures `rpc-http-api=["ETH", "NET", "WEB3", "QBFT", "PERM", "TXPOOL"]` on `0.0.0.0:8545` with `rpc-http-cors-origins=["*"]` and zero token authentication.
4. **Missing Besu QBFT Validator Set Rotation**:
   - Grep search for `qbft_` across the codebase returns 0 matches.
   - Dynamic rotation scripts in `src/bft_hardening/` (`epoch_rotation.ts`, `key_rotation.ts`) only manipulate the TypeScript `PersistentTrustLedger` and `ValidatorSetManager`, with zero effect on Besu QBFT state.

### R3: Smart Contract Invariants & Authorization Observations
1. **Unpermissioned Access on `commitState()`**:
   - `blockchain/contracts/WolverineTrustRegistry.sol:81-96` defines:
     ```solidity
     function commitState(
         string calldata tenantId,
         string calldata databaseId,
         bytes16 checkpointId,
         uint64 commitSeq,
         uint32 epoch,
         bytes32 checkpointDigest,
         bytes32 stateMerkleRoot,
         bytes32 changeChainHead,
         bytes32 previousCommitmentDigest,
         bytes32 commitmentDigest,
         uint64 logicalTimestampUs,
         uint16 protocolVersion,
         bytes calldata agentSignature,
         bytes calldata customerSignature
     ) external returns (bool)
     ```
   - The function lacks `onlyOwner`, caller whitelists, or tenant permission checks.
2. **Zero Cryptographic Signature Verification in Contract**:
   - `blockchain/contracts/WolverineTrustRegistry.sol:120-141` stores `agentSignature` and `customerSignature` verbatim into `commitments[commitmentDigest]`.
   - The contract never executes `ecrecover`, EIP-712, ERC-1271, or Ed25519 verification.
3. **Sequence Monotonicity Logic & Frontrunning DoS**:
   - `blockchain/contracts/WolverineTrustRegistry.sol:104-118`:
     ```solidity
     if (currentHead == 0) {
         if (commitSeq != 1) revert SequenceGapDetected(1, commitSeq);
     } else {
         if (commitSeq != currentHead + 1) revert SequenceGapDetected(currentHead + 1, commitSeq);
         bytes32 expectedPrev = sequenceIndex[tenantId][databaseId][currentHead];
         if (expectedPrev != previousCommitmentDigest) revert InvalidPreviousCommitment(expectedPrev, previousCommitmentDigest);
     }
     ```
   - Any third party calling `commitState("target_tenant", "target_db", ..., commitSeq=1, ...)` advances `latestSequence` to 1, causing the legitimate customer's initial sequence 1 commitment to revert with `SequenceGapDetected(2, 1)`.
4. **Unvalidated Commitment Digest Calculation**:
   - `WolverineTrustRegistry.sol` never recomputes `commitmentDigest` from constituent fields (`stateMerkleRoot`, `checkpointDigest`, etc.).
5. **Global Digest Collision Griefing**:
   - `blockchain/contracts/WolverineTrustRegistry.sol:34, 97-99` maps `commitments[commitmentDigest]` globally. An attacker committing digest $D$ under a dummy tenant prevents any other tenant from committing digest $D$.

---

## 2. Logic Chain

1. **Split-Brain Consensus Vulnerability**:
   - *Premise 1*: The architectural documentation claims Hyperledger Besu QBFT is the sole authoritative consensus and finality layer.
   - *Observation*: The actual production daemon `GrpcGatewayServer` (`src/runtime/grpc_gateway_server.ts`) and `WdbGatewayDaemon` (`src/daemons/wdb_gateway_daemon.ts`) invoke `TrustConsensusEngine` + `WolverineTrustLedger`, producing `ImmutableTrustReceipt` with TypeScript validator QuorumCertificates.
   - *Observation*: Besu is only invoked directly in acceptance test scripts and standalone demo files.
   - *Deduction*: The production runtime has **not migrated** to Hyperledger Besu. Two competing, incompatible consensus planes exist in the source tree, creating severe split-brain finality risk.

2. **Total QBFT Validator Compromise**:
   - *Premise*: QBFT Byzantine fault tolerance requires $>2/3$ honest validators ($4/5$ for $N=5$).
   - *Observation*: All 5 validator private keys (`0x01` .. `0x05`) are committed in plaintext under `blockchain/besu/nodes/node-[1..5]/key`.
   - *Deduction*: Any adversary reading the codebase possesses 100% of validator keys ($5/5$), enabling arbitrary block forgery, double signing, and state mutation.

3. **Smart Contract Authorization Bypass Under Gateway Compromise**:
   - *Premise*: A zero-trust security architecture requires the smart contract to independently enforce customer cryptographic authorization before committing state.
   - *Observation*: `WolverineTrustRegistry.sol:commitState()` contains no caller access controls and zero on-chain signature verification.
   - *Deduction*: An attacker with root access to the Gateway can submit arbitrary state Merkle roots and fake signatures directly to Besu, and the smart contract will finalize them on-chain without reverting.

4. **Permanent Customer Denial of Service (Frontrunning DoS)**:
   - *Premise*: Sequence numbers must start at 1 and strictly increment by 1 for each `(tenantId, databaseId)`.
   - *Observation*: `commitState()` is callable by anyone without tenant registration or signatures.
   - *Deduction*: An attacker can watch the network and claim sequence 1 for any tenant ID with fake data, permanently bricking onboarding for legitimate enterprise customers.

---

## 3. Caveats

1. **Air-Gapped Customer Verifier vs On-Chain Blockchain Truth**:
   - While the smart contract accepts unverified signatures, the off-chain `UniversalReceiptVerifier.verifyOffline()` does independently verify customer Ed25519 signatures if the auditor possesses the genuine customer public key. However, the on-chain Besu state itself is corrupted and cannot be trusted as an independent arbiter.
2. **Ed25519 in EVM Constraints**:
   - Standard EVM does not provide a native Ed25519 precompile (unlike Secp256k1 via `0x01`). Enforcing customer authorization on-chain requires either Secp256k1/EIP-712 customer keys, a Solidity Ed25519 verifier library, or an off-chain ZK proof / gateway signature scheme.
3. **Local Docker Environment**:
   - Audit was performed on static code analysis, configuration inspection, and cryptographic verification suites. Live Docker container execution requires starting the Docker engine.

---

## 4. Conclusion

1. **Consensus Authority (R1)**: Hyperledger Besu QBFT is **NOT yet the sole authoritative consensus layer in the runtime daemons**. The codebase exhibits a dual-authority architecture where the live HTTP/2 gateway still executes the legacy TypeScript BFT engine while Besu is used in isolated test scripts. All 5 Besu validator private keys are hardcoded in plaintext (`0x01`..`0x05`), resulting in complete Byzantine consensus compromise.
2. **Smart Contract Security (R3)**: `WolverineTrustRegistry.sol` has **CRITICAL authorization and invariant vulnerabilities**. It permits unpermissioned execution, does not verify cryptographic signatures on-chain, does not validate commitment digest integrity, and allows frontrunning sequence exhaustion (tenant squatting DoS) and global mapping collision griefing.

---

## 5. Verification Method

### 1. Code Inspection Points
- **Competing BFT in Gateway**: Inspect `src/runtime/grpc_gateway_server.ts:94-97` and `src/runtime/gateway.ts:45-51, 163-166`.
- **Hardcoded Validator Keys**: Inspect `blockchain/besu/nodes/node-1/key` through `node-5/key` and `src/blockchain/besu/deploy.ts:26`.
- **Smart Contract Vulnerabilities**: Inspect `blockchain/contracts/WolverineTrustRegistry.sol:81-154`.

### 2. Test Execution Commands
- Run blockchain unit & integration tests:
  ```powershell
  npx vitest run tests/blockchain/
  ```
- Run legacy BFT consensus tests:
  ```powershell
  npx vitest run tests/bft_hardening/ tests/runtime/
  ```
- Run full test suite:
  ```powershell
  npx vitest run
  ```

### 3. Invalidation Conditions
- This audit's findings regarding R1 would be invalidated if `GrpcGatewayServer` and `TrustGatewayServer` are refactored to route all incoming commitments exclusively through `BesuTransactionSubmitter` and all legacy TS consensus code is removed from runtime entry points.
- Findings regarding R3 would be invalidated if `WolverineTrustRegistry.sol` is upgraded with on-chain access controls, tenant registration, EIP-712/Ed25519 signature checks, and digest recomputation.
