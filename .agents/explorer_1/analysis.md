# WolverineDB — Independent Technical Security Audit: R1 & R3
**Target Subsystems**: Consensus & Finality Authority (R1) and Smart Contract Invariants & Authorization (R3)  
**Auditor**: Explorer 1 (Principal Architect & Security Auditor)  
**Date**: August 2026  
**Scope**: All consensus, ledger, daemon, network transport, Docker Compose, genesis, Besu integration, and Solidity smart contract source files in `wolverine-db`.

---

## 1. Executive Summary & Findings Matrix

| Ref ID | Subsystem | Severity | Finding Summary | Impact |
|:---|:---|:---:|:---|:---|
| **SEC-R1-01** | Architecture / Consensus | **CRITICAL** | **Dual Competing Consensus Authorities & Split-Brain Finality**: Production gateway daemons (`GrpcGatewayServer`, `WdbGatewayDaemon`) still execute legacy in-memory/journaled TypeScript BFT consensus (`TrustConsensusEngine`, `QuorumAggregator`, `WolverineTrustLedger`) and issue `ImmutableTrustReceipt` / `CanonicalQuorumCertificate`, completely disconnected from Hyperledger Besu QBFT. | Divergent finality proofs, uncoordinated sequence numbers, and split-brain trust plane. |
| **SEC-R1-02** | Besu Cluster / Key Security | **CRITICAL** | **Hardcoded Plaintext Private Keys for All 5 QBFT Validators & Operator**: Genesis validator private keys (`0x01` .. `0x05`) are committed in plaintext under `blockchain/besu/nodes/node-[1..5]/key` and hardcoded in `deploy.ts` / `live_acceptance.ts`. | 100% Byzantine validator compromise (>2/3 supermajority). Any adversary can forge blocks, reorganize history, or halt consensus. |
| **SEC-R1-03** | Besu Infrastructure / RPC | **HIGH** | **Single Point of Failure (SPOF) & Unauthenticated Open RPC**: Only `besu-validator-1` exposes RPC port 8545; `BesuClient` hardcodes a single endpoint. RPC API exposes administrative namespaces (`QBFT`, `PERM`, `TXPOOL`) with CORS `*` and no JWT/TLS authentication. | Total service outage if Validator 1 restarts; unauthorized transaction submission / mempool tampering. |
| **SEC-R1-04** | Besu Governance | **MEDIUM** | **Absence of On-Chain / JSON-RPC Besu QBFT Validator Rotation**: The codebase contains zero validator voting or dynamic rotation mechanisms for Besu QBFT. Rotation logic in `src/bft_hardening/` only modifies dead TypeScript in-memory state. | Inability to rotate compromised validator keys or decommission failed nodes in production. |
| **SEC-R3-01** | Smart Contract / Auth | **CRITICAL** | **Unpermissioned Public Invocation on `commitState()`**: `WolverineTrustRegistry.sol:commitState` lacks access control modifiers (`onlyOwner` / whitelist). Any arbitrary EVM account can submit commitments for any `tenantId` and `databaseId`. | Unauthorized parties can register fraudulent state commitments or hijack tenant identities on-chain. |
| **SEC-R3-02** | Smart Contract / Crypto | **CRITICAL** | **Zero On-Chain Cryptographic Signature Verification**: `agentSignature` and `customerSignature` are accepted as raw calldata `bytes` and stored in EVM storage without any verification (`ecrecover`, EIP-712, or Ed25519). | Compromised gateway or malicious actor can submit commitments with fabricated signatures that finalize on-chain. |
| **SEC-R3-03** | Smart Contract / State | **CRITICAL** | **Tenant Squatting & Sequence Frontrunning Permanent DoS**: Because sequence numbers must start at 1, any adversary can frontrun a new tenant by calling `commitState("victim_tenant", "victim_db", commitSeq=1, ...)` with garbage data, permanently locking out the legitimate customer with `SequenceGapDetected`. | Permanent DoS of customer onboarding and trust registration. |
| **SEC-R3-04** | Smart Contract / Integrity | **HIGH** | **Unverified Commitment Digest Calculation**: `WolverineTrustRegistry.sol` never recomputes `commitmentDigest` from constituent fields (`stateMerkleRoot`, `checkpointDigest`, etc.), accepting arbitrary decoupled values. | Attackers can store inconsistent state roots where the digest does not bind to the Merkle root. |
| **SEC-R3-05** | Smart Contract / Griefing | **MEDIUM** | **Global Mapping Digest Collision Vulnerability**: `commitments[commitmentDigest]` is indexed globally without namespacing by `(tenantId, databaseId)`. Submitting a target digest under a dummy tenant blocks the target via `DuplicateCommitment`. | Cross-tenant frontrunning and transaction griefing. |
| **SEC-R3-06** | Smart Contract / Gas | **LOW** | **High EVM Storage Overhead & State Bloat**: `StateCommitment` struct occupies 12-14 storage slots per record (~300k gas), storing dynamic strings and signature byte arrays directly in RocksDB state. | Rapid Besu disk bloat and suboptimal transaction throughput. |

---

## 2. R1: Consensus & Finality Authority Audit

### 2.1 Full Inventory of Consensus & Ledger Subsystems
The WolverineDB codebase contains multiple distinct consensus implementations authored across different engineering milestones:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                REPOSITORY CONSENSUS TAXONOMY                                │
├──────────────────────────────────────────────────────────┬──────────────────────────────────┤
│ 1. HYPERLEDGER BESU QBFT (Target Production Authority)    │ 2. TYPESCRIPT BFT (Legacy Plane 2)│
│    • blockchain/besu/genesis/genesis.json (Chain 13370)  │    • src/trust_network/consensus.ts│
│    • blockchain/besu/docker-compose.yml (5 nodes)        │    • src/trust_network/ledger.ts │
│    • blockchain/contracts/WolverineTrustRegistry.sol     │    • src/trust/quorum_certificate.ts │
│    • src/blockchain/besu/client.ts (viem integration)    │    • src/trust/validator_set.ts  │
│    • src/blockchain/besu/transaction_submitter.ts        │    • src/runtime/gateway.ts      │
│                                                          │    • src/runtime/grpc_gateway_...│
│                                                          │    • docker-compose.m3.yml (M3)  │
├──────────────────────────────────────────────────────────┼──────────────────────────────────┤
│ 3. PERSISTENT BFT ENGINE (Milestone 8/10/12)             │ 4. FEDERATED & MULTI-ANCHOR BFT  │
│    • src/trust_service/bft_consensus_engine.ts (N=5,M=4) │    • src/federation/consensus.ts │
│    • src/trust_service/persistent_ledger.ts (Disk journal)│    • src/anchors/consensus.ts    │
│    • src/bft_hardening/epoch_rotation.ts                 │    • src/anchors/contracts/WDB...│
└──────────────────────────────────────────────────────────┴──────────────────────────────────┘
```

### 2.2 Forensic Investigation of Competing Consensus Authorities

#### Evidence 1: Live HTTP/2 Gateway Routes to TypeScript BFT Engine
Inspection of `src/runtime/grpc_gateway_server.ts` (lines 34–123) and `src/runtime/gateway.ts` (lines 26–208) demonstrates that the active network daemon service `GrpcGatewayServer` delegates directly to `TrustGatewayServer`, which executes the legacy TypeScript consensus engine:

```typescript
// File: src/runtime/gateway.ts (lines 45-51)
this.ledger = ledger ?? new WolverineTrustLedger();
this.consensusEngine = new TrustConsensusEngine(
  this.ledger,
  config.requiredQuorum,
  config.totalValidators
);

// File: src/runtime/gateway.ts (lines 163-166)
const { certificate, ledgerRecord } = this.consensusEngine.processAttestationsWithRecord(
  commitment,
  validAttestations
);

// File: src/runtime/grpc_gateway_server.ts (lines 94-97)
const receipt = ImmutableTrustReceiptGenerator.generateReceipt(
  result.proof,
  result.ledgerRecord.recordDigest
);
```

#### Evidence 2: Milestone 3 Docker Compose Provisions TypeScript Cluster
The deployment file `docker-compose.m3.yml` (lines 52–142) launches five distinct containerized TypeScript validator daemons (`dist/bin/wdb-validator.js`) and a TypeScript gateway (`dist/bin/wdb-gateway.js`), listening on ports 9001–9005:

```yaml
# File: docker-compose.m3.yml (lines 73-78)
validator-1:
  build:
    context: .
    dockerfile: Dockerfile
  container_name: wdb-validator-1
  command: ["node", "dist/bin/wdb-validator.js", "--id", "validator-01", "--port", "9001"]
```

#### Evidence 3: Besu Client Only Invoked in Scripts and Demos
Searching for references to `BesuClient` across the codebase reveals that it is **only instantiated in**:
1. `src/acceptance/live_acceptance.ts` (lines 41, 159)
2. `src/demo/besu_live_demo.ts` (lines 28, 122)
3. `src/demo/besu_simulated_demo.ts` (line 68)
4. `src/blockchain/besu/status.ts` (line 6)
5. `tests/blockchain/besu_integration.test.ts` (lines 29, 67)

**Architectural Assessment**: `BesuClient` is **NOT** integrated into the runtime daemons (`src/runtime/gateway.ts`, `src/runtime/grpc_gateway_server.ts`, `src/daemons/wdb_gateway_daemon.ts`). There are two disjoint code paths. If a client connects to the running HTTP/2 daemon, it receives an `ImmutableTrustReceipt` signed by the 5 TypeScript nodes. If a client executes the acceptance test script, it writes to Besu and receives a `UniversalTrustReceipt`.

#### Evidence 4: Incompatible Receipt & Finality Proof Structures
The codebase defines two incompatible trust receipt formats:
1. **`ImmutableTrustReceipt` (`src/bft_hardening/types.ts`)**: Binds to `QuorumCertificate` (threshold Ed25519 signatures of TS validators) and `TrustLedgerRecord` (`WDB:LEDGER_REC:v1:`).
2. **`UniversalTrustReceipt` (`src/receipts/universal_receipt.ts`)**: Binds to `trustPlane` containing Besu `blockchainTransactionHash`, `blockNumber`, `blockHash`, and `contractAddress`.

**Split-Brain Risk**: If both systems operate concurrently, they maintain separate sequence numbers, separate hash chains, and separate finality assertions with zero cross-plane synchronization.

---

### 2.3 Besu QBFT Validator Set Configuration & Security Audit

#### Genesis Analysis (`blockchain/besu/genesis/genesis.json`)
```json
{
  "config": {
    "chainId": 13370,
    "qbft": {
      "blockperiodseconds": 1,
      "epochlength": 30000,
      "requesttimeoutseconds": 2,
      "validators": [
        "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
        "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF",
        "0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69",
        "0x1efF47bc3a10a45D4B230B5d10E37751FE6AA718",
        "0xe1AB8145F7E55DC933d51a18c793F901A3A0b276"
      ]
    },
    "zeroBaseFee": true
  }
}
```

#### Vulnerability Analysis:
1. **Hardcoded Plaintext Validator Keys (SEC-R1-02)**:
   - `blockchain/besu/nodes/node-1/key` = `0000000000000000000000000000000000000000000000000000000000000001`
   - `blockchain/besu/nodes/node-2/key` = `0000000000000000000000000000000000000000000000000000000000000002`
   - `blockchain/besu/nodes/node-3/key` = `0000000000000000000000000000000000000000000000000000000000000003`
   - `blockchain/besu/nodes/node-4/key` = `0000000000000000000000000000000000000000000000000000000000000004`
   - `blockchain/besu/nodes/node-5/key` = `0000000000000000000000000000000000000000000000000000000000000005`
   - In `src/blockchain/besu/deploy.ts` (line 26), `operatorPrivateKeyHex` is hardcoded as `0x...01`.
   - **Impact**: Any attacker with read access to the repository possesses the private keys for all 5 QBFT validators. They can assemble a valid QBFT round proposal, forge round commit seals, sign contradictory blocks at the same height, and force arbitrary consensus reorganizations or state rewrites.
2. **Missing Besu QBFT Validator Rotation (SEC-R1-04)**:
   - The repository contains zero implementation of the QBFT JSON-RPC voting interface (`qbft_proposeValidatorVote`, `qbft_discardValidatorVote`, `qbft_getValidatorsAtHead`).
   - The key rotation modules in `src/bft_hardening/` only rotate Ed25519 keys inside the TypeScript `PersistentTrustLedger` and have no effect on Besu's consensus state.
3. **RPC Architecture & Single Point of Failure (SEC-R1-03)**:
   - In `blockchain/besu/docker-compose.yml`:
     - Only `besu-validator-1` maps port `8545:8545` to the host.
     - Validators 2–5 operate in the internal Docker bridge network without exposed RPC ports.
     - In `src/blockchain/besu/client.ts`, `BesuClient` connects to a single `rpcUrl`. If Validator 1 goes down or its container restarts, transaction submission halts completely, even though the QBFT cluster retains 4/5 nodes ($F=1$ fault tolerance is defeated at the client ingress layer).
   - In `blockchain/besu/config/config.toml`:
     - `rpc-http-host="0.0.0.0"`
     - `rpc-http-api=["ETH", "NET", "WEB3", "QBFT", "PERM", "TXPOOL"]`
     - `rpc-http-cors-origins=["*"]`
     - **Impact**: The JSON-RPC endpoint exposes sensitive administrative methods (`QBFT`, `PERM`) without authentication tokens, IP whitelisting, or TLS termination.

---

## 3. R3: Smart Contract Invariant & Authorization Review

### 3.1 Smart Contract Specification & Call Graph
The canonical on-chain smart contract is `blockchain/contracts/WolverineTrustRegistry.sol` (Solidity `^0.8.20`). A secondary anchor notary contract exists at `src/anchors/contracts/WolverineAnchorRegistry.sol`.

```
┌────────────────────────────────────────────────────────────────────────┐
│              WolverineTrustRegistry.sol State Machine                  │
├────────────────────────────────────────────────────────────────────────┤
│ Storage Mappings:                                                      │
│   • commitments: mapping(bytes32 => StateCommitment)                   │
│   • latestSequence: mapping(string => mapping(string => uint64))       │
│   • sequenceIndex: mapping(string => mapping(string => mapping(uint64 => bytes32))) │
├────────────────────────────────────────────────────────────────────────┤
│ Public Entry Points:                                                   │
│   • commitState(...) [external, NO ACCESS CONTROL, NO SIG VERIFICATION]│
│   • getCommitment(bytes32) [external view]                             │
│   • getLatestCommitment(string, string) [external view]                │
│   • getCommitmentBySequence(string, string, uint64) [external view]    │
│   • recordOptionalAnchor(...) [external onlyOwner]                     │
│   • advanceEpoch(uint32) [external onlyOwner]                          │
└────────────────────────────────────────────────────────────────────────┘
```

---

### 3.2 Detailed Vulnerability Analysis

#### Vulnerability 1: Completely Unpermissioned Ingress on `commitState()` (SEC-R3-01)
- **Location**: `blockchain/contracts/WolverineTrustRegistry.sol` (lines 81–96)
- **Code**:
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
  ) external returns (bool) { ... }
  ```
- **Analysis**:
  - The function is declared `external` without `onlyOwner`, without role-based access control, and without any whitelist verifying that `msg.sender` is an authorized gateway or registered customer.
  - Any EVM account that can send a transaction to the Besu node can invoke `commitState()` for ANY arbitrary `tenantId` and ANY `databaseId`.

#### Vulnerability 2: Zero On-Chain Cryptographic Signature Verification (SEC-R3-02)
- **Location**: `blockchain/contracts/WolverineTrustRegistry.sol` (lines 120–139)
- **Code**:
  ```solidity
  StateCommitment memory entry = StateCommitment({
      tenantId: tenantId,
      databaseId: databaseId,
      checkpointId: checkpointId,
      commitSeq: commitSeq,
      epoch: epoch,
      checkpointDigest: checkpointDigest,
      stateMerkleRoot: stateMerkleRoot,
      changeChainHead: changeChainHead,
      previousCommitmentDigest: previousCommitmentDigest,
      commitmentDigest: commitmentDigest,
      logicalTimestampUs: logicalTimestampUs,
      protocolVersion: protocolVersion,
      agentSignature: agentSignature,
      customerSignature: customerSignature,
      blockNumber: block.number,
      blockTimestamp: block.timestamp
  });

  commitments[commitmentDigest] = entry;
  ```
- **Analysis**:
  - The contract receives `agentSignature` and `customerSignature` as raw calldata `bytes` and copies them directly into EVM storage.
  - The contract **does not execute any signature verification**:
    - No `ecrecover` for Secp256k1.
    - No EIP-712 structured data hashing.
    - No Ed25519 verification precompile or library.
  - **Attack Vector**: An attacker or compromised gateway can pass `agentSignature = hex"00"` and `customerSignature = hex"00"`. The contract will execute without error, emit `CommitmentRecorded`, and record the fake state commitment into canonical on-chain storage. The smart contract provides **zero independent authorization guarantees**.

#### Vulnerability 3: Tenant Squatting & Sequence Frontrunning Permanent DoS (SEC-R3-03)
- **Location**: `blockchain/contracts/WolverineTrustRegistry.sol` (lines 104–112)
- **Code**:
  ```solidity
  uint64 currentHead = latestSequence[tenantId][databaseId];

  // Sequence monotonicity enforcement
  if (currentHead == 0) {
      // First commitment for this tenant/database
      if (commitSeq != 1) {
          revert SequenceGapDetected(1, commitSeq);
      }
  } else {
      if (commitSeq != currentHead + 1) {
          revert SequenceGapDetected(currentHead + 1, commitSeq);
      }
      // Verify previous commitment linkage
      bytes32 expectedPrev = sequenceIndex[tenantId][databaseId][currentHead];
      if (expectedPrev != previousCommitmentDigest) {
          revert InvalidPreviousCommitment(expectedPrev, previousCommitmentDigest);
      }
  }
  ```
- **Step-by-Step Attack Walkthrough**:
  1. An enterprise customer with tenant ID `"enterprise_acme"` prepares their initial database state commitment ($commitSeq = 1$).
  2. An attacker (monitoring the network or predicting the tenant name) broadcasts a transaction directly to Besu:
     ```solidity
     commitState(
       "enterprise_acme",
       "production_db",
       0x00000000000000000000000000000001,
       1, // commitSeq = 1
       1,
       0xdeadbeef..., // arbitrary checkpointDigest
       0xbad0cafe..., // arbitrary stateMerkleRoot
       0x00...,
       0x00...,
       0xfa5e...,     // arbitrary commitmentDigest
       1700000000,
       2,
       hex"00",       // fake signature
       hex"00"        // fake signature
     );
     ```
  3. The attacker's transaction is mined. On-chain state becomes:
     - `latestSequence["enterprise_acme"]["production_db"] = 1`
     - `sequenceIndex["enterprise_acme"]["production_db"][1] = 0xfa5e...`
  4. The legitimate customer's transaction for $commitSeq = 1$ arrives.
  5. The contract evaluates `currentHead = 1`. Since $commitSeq = 1 \neq currentHead + 1 (2)$, the transaction **reverts with `SequenceGapDetected(2, 1)`**.
  6. The legitimate customer can **never register sequence 1** again for that database. The victim's database trust registration is permanently bricked.

#### Vulnerability 4: Unverified Commitment Digest & Hash Decoupling (SEC-R3-04)
- **Location**: `blockchain/contracts/WolverineTrustRegistry.sol` (lines 97–118)
- **Analysis**:
  - The contract accepts `checkpointDigest`, `stateMerkleRoot`, `changeChainHead`, `previousCommitmentDigest`, and `commitmentDigest`.
  - The contract **never computes** `keccak256(...)` or `sha256(...)` over the supplied fields to verify that `commitmentDigest` matches the data.
  - A malicious caller can supply a completely arbitrary `stateMerkleRoot` while providing a valid `commitmentDigest` from another context, causing a severe decoupling between the on-chain indexed Merkle root and the signed commitment digest.

#### Vulnerability 5: Global Mapping Collision & Frontrunning Griefing (SEC-R3-05)
- **Location**: `blockchain/contracts/WolverineTrustRegistry.sol` (lines 34, 97–99)
- **Code**:
  ```solidity
  mapping(bytes32 => StateCommitment) private commitments;

  if (commitments[commitmentDigest].blockNumber != 0) {
      revert DuplicateCommitment(commitmentDigest);
  }
  ```
- **Analysis**:
  - `commitments` is a single global mapping keyed by `commitmentDigest`.
  - If Tenant A generates a legitimate commitment with digest $D$, an attacker who intercepts $D$ in transit can submit a transaction for `"dummy_tenant"` with digest $D$.
  - Once mined, `commitments[D].blockNumber != 0`. When Tenant A's transaction is executed, it reverts with `DuplicateCommitment(D)`.

#### Vulnerability 6: Heavy EVM Storage Layout & Gas Overhead (SEC-R3-06)
- **Location**: `blockchain/contracts/WolverineTrustRegistry.sol` (lines 10–27)
- **Analysis**:
  - Each `StateCommitment` struct stores two dynamic `string` fields (`tenantId`, `databaseId`), two dynamic `bytes` fields (`agentSignature`, `customerSignature`), two `uint256` timestamp fields, and seven 32/16-byte hashes.
  - Storing this full struct requires 12 to 14 EVM storage slots (SSTORE operations).
  - At ~20,000 gas per new storage slot, committing one state entry consumes over 300,000 gas.
  - On a high-throughput database producing hundreds of commitments per minute, this creates unnecessary storage bloat on the Besu validator nodes.

#### Vulnerability 7: Event Indexing Incompatibility
- **Location**: `blockchain/contracts/WolverineTrustRegistry.sol` (lines 43–51)
- **Code**:
  ```solidity
  event CommitmentRecorded(
      string indexed tenantId,
      string indexed databaseId,
      uint64 indexed commitSeq,
      bytes32 commitmentDigest,
      bytes32 stateMerkleRoot,
      bytes32 changeChainHead,
      uint256 blockNumber
  );
  ```
- **Analysis**:
  - In Solidity, `indexed string` parameters do not store the plain UTF-8 string in event logs; they store `keccak256(bytes(tenantId))` in the EVM log topic.
  - Off-chain indexers querying logs by `tenantId` must compute the Keccak-256 hash of the string to match the topic filter.
  - The event omits `previousCommitmentDigest`, `checkpointDigest`, and signatures, requiring listeners to query contract storage via RPC to obtain full verification records.

---

## 4. Architectural Proofs & Failure Modes

### 4.1 Proof: Gateway Root Compromise Bypasses Customer Authorization
```
                       ADVERSARIAL ATTACK FLOW (ROOT GATEWAY COMPROMISE)
                       
[Attacker on Gateway] 
        │
        ├── 1. Generates fraudulent stateMerkleRoot (0xCAFE...)
        ├── 2. Generates dummy Ed25519 signature bytes (0x00...00)
        ├── 3. Uses hardcoded Operator Key (0x000...01)
        │
        ▼ Calls Besu JSON-RPC: eth_sendRawTransaction
[Hyperledger Besu Cluster]
        │
        ▼ Executes WolverineTrustRegistry.commitState()
        ├── Access Control Check: NONE (Passes)
        ├── Signature Verification: NONE (Passes)
        ├── Sequence Check: commitSeq == currentHead + 1 (Passes)
        ├── Previous Hash Check: matches previous stored digest (Passes)
        │
        ▼ QBFT Block Inclusion
[Finalized Besu Block #N] ───► Fraudulent State Root Permanently Written to Blockchain!
        │
        ▼ Fabricates Receipt Metadata
[Forged UniversalTrustReceipt]
        │
        ▼ Submitted to Auditor / Customer
[UniversalReceiptVerifier]
        ├── Status Check: receipt.trustPlane.finalityStatus === 'FINALIZED' (Passes)
        ├── Tx Hash Check: exists on-chain (Passes)
        └── Customer Sig Check: FAILS ONLY IF offline verifier has real Customer Ed25519 PubKey!
```

**Theorem**: *Under the current implementation, the Hyperledger Besu blockchain does NOT protect against a compromised gateway creating fraudulent on-chain state commitments, because authorization checks are completely absent from the smart contract layer.*

---

## 5. Required Technical Remediations

### Remediation Plan for R1 (Consensus & Authority):
1. **Complete Stripping / Migration of Legacy TS BFT in Runtime Daemons**:
   - Refactor `src/runtime/gateway.ts` and `src/runtime/grpc_gateway_server.ts` to submit directly to `BesuTransactionSubmitter` instead of `TrustConsensusEngine`.
   - Update `docker-compose.m3.yml` or deprecate it in favor of `blockchain/besu/docker-compose.yml`.
   - Add explicit deprecation annotations to all files in `src/trust/`, `src/trust_network/`, and `src/trust_service/`.
2. **Validator Key Security & Genesis Rotation**:
   - Generate high-entropy SECP256k1 private keys for all 5 Besu validators using an air-gapped cryptographic RNG.
   - Remove hardcoded `0x01`..`0x05` keys from the git tree; load validator keys via Docker environment variables / HashiCorp Vault secrets.
3. **High-Availability RPC Cluster & RPC Hardening**:
   - Expose JSON-RPC on all 5 Besu validator nodes on unique internal ports (e.g. 8545, 8547, 8549, 8551, 8553).
   - Implement an RPC failover connection pool in `BesuClient` that automatically retries across all 5 validator endpoints upon network timeout.
   - Restrict `rpc-http-api` in `config.toml` to `["ETH", "NET", "WEB3"]` on public interfaces and disable `QBFT`/`PERM` on unauthenticated ports.

### Remediation Plan for R3 (Smart Contracts):
1. **On-Chain Tenant Registration & Access Control**:
   - Add a `registerTenant(string calldata tenantId, address tenantAdmin, address authorizedGateway)` function callable only by contract owner or with customer signature.
   - Enforce that `commitState()` can only be called by `authorizedGateway` or `tenantAdmin`.
2. **On-Chain Cryptographic Authorization**:
   - For Secp256k1/EVM KMS keys: Verify customer authorization on-chain using `ecrecover` or `ERC-1271` over an EIP-712 structured hash (`hashStruct(StateCommitment)`).
   - For Ed25519 customer keys: Hash the commitment payload on-chain, and record `keccak256(signatures)` or verify via a zero-knowledge proof / Ed25519 Solidity verifier library.
3. **Commitment Digest Recomputation**:
   - Recompute `commitmentDigest = keccak256(abi.encode(tenantId, databaseId, commitSeq, stateMerkleRoot, changeChainHead, previousCommitmentDigest))` inside `commitState()`, rejecting any mismatched digest.
4. **Tenant-Scoped Sequence & Collision Fix**:
   - Namespace the commitment mapping by tenant: `mapping(bytes32 => mapping(bytes32 => StateCommitment))`.
5. **Storage Optimization**:
   - Store only `bytes32 commitmentDigest`, `bytes32 stateMerkleRoot`, and `uint64 commitSeq` in contract storage (2 slots per commitment), emitting the full data in event logs (`calldata` indexing).
6. **Upgradeability**:
   - Deploy `WolverineTrustRegistry` behind an `ERC-1967` UUPS or Transparent Upgradeable Proxy pattern to enable secure security patches and governance evolution.
