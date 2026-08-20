# Comprehensive Technical Audit: R4 (Air-Gapped Offline Verifiability) & R5 (PostgreSQL CDC & Fault Domain Realism)

**Auditor**: Explorer 3 (Principal Cryptography & Distributed Systems Security Auditor)  
**Date**: 2026-08-20  
**Scope**: 
1. R4: Universal Trust Receipt (`v2`), `UniversalReceiptVerifier`, Air-Gapped Offline Verification Completeness, EVM/QBFT Proof Inclusion.
2. R5: PostgreSQL CDC / `pgoutput` Logical Replication Pipeline, Transaction Boundaries, State Frontier Merkle Tree Computation, Docker BFT Fault Domain Realism, Formal Security Theorem.

---

## 1. Executive Summary & Verdict

| Audit Dimension | Evaluation | Verdict |
| :--- | :--- | :--- |
| **R4: Offline Receipt Completeness** | Receipts contain dual Ed25519 signatures ($\sigma_{\text{cust}}$, $\sigma_{\text{agent}}$) and metadata hashes, but **completely lack** EVM block headers, Merkle Patricia Trie (MPT) inclusion proofs, and Besu QBFT validator commit seals. | **CRITICAL ARCHITECTURAL GAP** (Overclaimed Air-Gapped Finality) |
| **R4: Air-Gapped Verifiability** | An air-gapped verifier can verify customer/agent authorization and local DB Merkle state match, but **cannot cryptographically verify blockchain consensus or inclusion** without online RPC or trusting infrastructure. | **PARTIAL PROOF / INFRASTRUCTURE TRUST** |
| **R5: Transaction Boundaries & CDC** | Uncommitted/aborted mutations do not reach state frontier under single-stream execution, but **concurrent transactions trigger mutation cross-contamination** due to a single shared `currentXid` variable. Streamed pgoutput messages crash decoder. | **HIGH SEVERITY FLAW** |
| **R5: Merkle Tree Frontier Computation** | State frontier executes full $O(N \log N)$ in-memory table scan and re-hashing on every commit rather than incremental Sparse Merkle Tree updates. | **PERFORMANCE / SCALABILITY BOTTLENECK** |
| **R5: Docker Fault Domain Realism** | 5 Besu containers on a single host provide **logical process isolation only**, zero physical Byzantine fault domain independence ($f_{\text{actual}} = 0$ against host/admin failure). | **DEFICIENT REALISM / TESTBED ONLY** |

---

## 2. R4: Air-Gapped Offline Verifiability & Receipt Completeness Audit

### 2.1 Anatomy of Universal Trust Receipt (`v2`)
In `src/receipts/universal_receipt.ts:36-46`:
```typescript
export interface UniversalTrustReceipt {
  receiptVersion: number; // 2
  receiptId: string;
  tenantId: string;
  databaseId: string;
  timestampUs: string; // stringified bigint
  evidencePlane: EvidencePlaneReceiptData;
  trustPlane: TrustPlaneReceiptData;
  optionalPublicAnchor: OptionalPublicAnchorData;
  receiptDigestHex: string;
}
```

The `evidencePlane` (`src/receipts/universal_receipt.ts:5-14`) contains:
- `checkpointId`, `commitSeq`, `lsn`, `checkpointDigestHex`, `stateMerkleRootHex`, `changeChainHeadHex`
- `agentAttestationHex` ($\sigma_{\text{agent}}$)
- `customerAuthorizationHex` ($\sigma_{\text{cust}}$)

The `trustPlane` (`src/receipts/universal_receipt.ts:16-26`) contains:
- `networkId`, `chainId`, `blockchainTransactionHash`, `blockNumber`, `blockHash`, `finalityStatus`, `contractAddress`, `contractEventDataHex`, `previousCommitmentDigestHex`

### 2.2 Deep Audit of `UniversalReceiptVerifier`
In `src/proof/universal_receipt_verifier.ts:55-180`, the offline verification algorithm executes 6 verification checks:
1. **Receipt Digest Integrity**:
   ```typescript
   const computedDigest = computeReceiptDigest(receipt);
   const claimedDigest = Buffer.from(receipt.receiptDigestHex, 'hex');
   if (!timingSafeEqualHashes(computedDigest, claimedDigest)) return { isValid: false, status: 'RECEIPT_CORRUPTED' };
   ```
2. **Sequence Continuity**:
   ```typescript
   if (previousReceipt) {
     const prevSeq = BigInt(previousReceipt.evidencePlane.commitSeq);
     const currSeq = BigInt(receipt.evidencePlane.commitSeq);
     if (currSeq !== prevSeq + 1n) return { isValid: false, status: 'SEQUENCE_DISCONTINUITY' };
   }
   ```
3. **Customer Authorization Signature**:
   Preimage: `WDB:CUST_AUTH:v2: || checkpointDigest || commitSeq`
   Verifies Ed25519 signature against `customerPublicKey`.
4. **Agent Attestation Signature**:
   Preimage: `WDB:AGENT_ATTEST:v2: || checkpointDigest || lsn`
   Verifies Ed25519 signature against `agentPublicKey`.
5. **Blockchain Binding Check** (`src/proof/universal_receipt_verifier.ts:145-156`):
   ```typescript
   // 5. Verify Blockchain Finality Field Invariants
   if (
     !receipt.trustPlane.blockchainTransactionHash ||
     receipt.trustPlane.blockchainTransactionHash === '' ||
     !receipt.trustPlane.blockHash ||
     receipt.trustPlane.finalityStatus !== 'FINALIZED'
   ) {
     return {
       isValid: false,
       status: 'BLOCKCHAIN_BINDING_MISMATCH',
       details: 'Trust plane does not contain finalized Besu block binding',
     };
   }
   ```
6. **Live Merkle Root Comparison**:
   ```typescript
   if (currentDatabaseMerkleRootHex) {
     const witnessedRoot = receipt.evidencePlane.stateMerkleRootHex.toLowerCase();
     const liveRoot = currentDatabaseMerkleRootHex.toLowerCase();
     if (witnessedRoot !== liveRoot) {
       return { isValid: false, status: 'LOCAL_TAMPERING_DETECTED', ... };
     }
   }
   ```

### 2.3 Critical Vulnerabilities & Cryptographic Omissions in R4

#### Vulnerability 1: Zero Cryptographic Proof of Blockchain Inclusion or Finality
- **Observation**: Step 5 of `UniversalReceiptVerifier` performs **no cryptographic verification**. It only verifies that `blockchainTransactionHash` and `blockHash` strings are non-empty and `finalityStatus` is the string `'FINALIZED'`.
- **Missing Proofs**:
  1. **EVM Block Header**: No RLP-encoded block header is supplied or verified.
  2. **QBFT Validator Commit Seals**: Besu QBFT places $\ge 2f+1$ secp256k1 validator signatures in the header's `extraData` (`IstanbulExtra`). These commit seals are completely absent from the receipt and the verifier.
  3. **Merkle Patricia Trie (MPT) Proof**: No MPT proof linking the transaction to `transactionsRoot`, the event log to `receiptsRoot`, or contract storage to `stateRoot` is provided.
- **Exploit Scenario**: An attacker who compromises the customer KMS key or Gateway can fabricate arbitrary random 32-byte hashes for `blockchainTransactionHash` and `blockHash`, set `finalityStatus = 'FINALIZED'`, and `UniversalReceiptVerifier.verifyOffline()` will return `isValid: true, status: 'AUTHENTIC'`. The commitment was never submitted to Besu.
- **Air-Gapped Auditor Incapacity**: An air-gapped auditor possessing only the genesis file / Besu validator public keys, the database state, and the receipt **cannot verify** that the transaction was recorded on the authoritative blockchain without contacting an online Besu RPC endpoint.

#### Vulnerability 2: Pseudo-Verifications in `AirGappedProofVerifier` (Milestone 5)
In `src/proof/air_gapped_verifier.ts:215-245`:
- Step 10: `pkg.merkleProof.rowHashHex.length === 64 && pkg.receipt.stateMerkleRootHex.length === 64`
- Step 11: `pkg.ledgerProof.batchRootHex.length === 64`
- Step 12: `pkg.anchor.txHashHex.startsWith('0x') && pkg.anchor.blockNumber !== '0'`
These steps do not execute Merkle path hashing or blockchain signature checks; they merely test string lengths and prefixes.

### 2.4 Cryptographically Proven vs. Infrastructure Trust Matrix

| Verification Dimension | Cryptographically Proven in Receipt | Relies on Infrastructure / Online Trust |
| :--- | :--- | :--- |
| **Receipt Structure & Self-Digest** | **PROVEN** (SHA-256 over Canonical JSON) | None |
| **Customer Authorization** | **PROVEN** (Ed25519 $\sigma_{\text{cust}}$ over commitment digest + commitSeq) | None (Requires trusted $\text{pk}_{\text{cust}}$) |
| **Agent Attestation** | **PROVEN** (Ed25519 $\sigma_{\text{agent}}$ over commitment digest + LSN) | None (Requires trusted $\text{pk}_{\text{agent}}$) |
| **Sequence Continuity** | **PROVEN** ($k_{i} = k_{i-1} + 1$ when both receipts available) | None |
| **Database State Integrity** | **PROVEN** (Matches Merkle root if auditor hashes DB) | Auditor computes local state hash |
| **Row-Level Merkle Inclusion** | **NOT PROVEN** (No Merkle path included in v2 receipt) | Requires DB scan or trusting root |
| **Besu Block Header Validity** | **NOT PROVEN** (EVM header omitted) | Requires online Besu RPC (`eth_getBlockByHash`) |
| **Besu QBFT Consensus Finality** | **NOT PROVEN** (No QBFT commit seals in receipt) | Requires trusting Gateway / online node |
| **On-Chain Contract Execution** | **NOT PROVEN** (No MPT receipt/log proof) | Requires online Besu RPC (`getCommitment`) |

---

## 3. R5: PostgreSQL Evidence Capture & Fault Domain Realism Audit

### 3.1 PostgreSQL CDC Pipeline & Transaction Boundaries

#### CDC Pipeline Architecture
- Ingestion occurs via `PgLogicalClient` (`src/wal/pg_logical_client.ts`) using PostgreSQL logical replication protocol (`pgoutput` plugin) over streaming replication connection (`src/wal/pg_replication_stream.ts`).
- Alternatively, trigger-based capture is supported via `PostgresAdapter` (`src/postgres/adapter.ts`) writing to `wolverine_sys.pending_mutations`.

#### Transaction Boundary Invariants (BEGIN, COMMIT, ROLLBACK, Savepoints)
1. **PostgreSQL Engine Guarantee**:
   - Under standard PostgreSQL logical replication, PostgreSQL reorder buffers discard uncommitted transactions. Transactions that `ROLLBACK` or abort mid-flight are **never emitted** to the `pgoutput` stream.
   - For trigger-based capture, `pending_mutations` rows participate in the same PostgreSQL transaction. If the transaction executes `ROLLBACK`, the inserted mutations in `wolverine_sys.pending_mutations` are atomically rolled back by the database engine.
2. **Wolverine Ingestion Invariant**:
   - In `PgLogicalClient`:
     - `B` (Begin): Allocates transaction buffer in `this.activeTransactions`.
     - `I` / `U` / `D`: Pushes raw mutations to `tx.mutations`.
     - `C` (Commit): Normalizes mutations, increments sequence, writes to `DurableEvidenceJournal`, and applies to `DeterministicStateFrontier`.
     - `abortTransaction(xid)`: Purges buffered mutations.

#### Critical Vulnerabilities in CDC Capture
1. **Race Condition & Mutation Cross-Contamination under Concurrent Transactions**:
   - In `src/wal/pg_logical_client.ts:20`:
     ```typescript
     private currentXid: string | null = null;
     ```
   - In `src/wal/pg_logical_client.ts:180`:
     ```typescript
     case 'B': {
       this.currentXid = msg.xid;
       this.activeTransactions.set(msg.xid, ...);
     }
     ```
   - In `src/wal/pg_logical_client.ts:205`:
     ```typescript
     this.activeTransactions.get(this.currentXid)!.mutations.push(...);
     ```
   - **Bug**: `currentXid` is a single class variable. If two transactions $T_1$ and $T_2$ are interleaved in the stream (e.g. $B(T_1) \to B(T_2) \to I(T_1)$), `currentXid` is overwritten with $T_2$. $T_1$'s insert is mistakenly appended into $T_2$'s buffer! If $T_2$ commits and $T_1$ rolls back, $T_1$'s aborted mutation is permanently incorporated into the Merkle state frontier under $T_2$.
2. **Crash on PostgreSQL 14+ Streaming Replication Messages**:
   - `PgOutputDecoder` (`src/wal/pgoutput_decoder.ts:235-240`) throws `MALFORMED_FIELD_PAYLOAD` on unknown message types.
   - It only handles `B`, `C`, `R`, `I`, `U`, `D`, `T`.
   - When PostgreSQL streams long-running or 2-phase transactions (`S` Stream Start, `E` Stream Stop, `A` Stream Abort, `c` Stream Commit, `P` Prepare, `K` Commit Prepared), the decoder throws an unhandled exception, halting replication.
3. **TOAST Pointer Mutation Overwrite**:
   - When updating large text/binary columns where TOASTed values are unchanged (`colKind === 'u'`), `pgoutput_decoder` sets `tupleData[colName] = undefined`.
   - In `DeterministicStateFrontier.applyChangeRecords`:
     ```typescript
     const mergedValues = { ...existingValues, ...updateValues };
     ```
     This assigns `mergedValues[colName] = undefined`, which can corrupt state serialization in `canonicalizeJson`.

---

### 3.2 Merkle Tree State Frontier Computation & Scalability

#### Algorithm & Complexity Breakdown
In `src/evidence/state_frontier.ts:169-205`:
```typescript
public computeStateMerkleRoot(): Buffer {
  const rowHashes: { sortKey: string; hash: Buffer }[] = [];

  for (const [tableName, tableMap] of this.tables.entries()) {
    for (const [pkHex, row] of tableMap.entries()) {
      if (row.deleted) continue;

      const canonicalRowJson = canonicalizeJson({
        table: tableName,
        pk: pkHex,
        values: row.values,
        epoch: this.currentSchemaEpoch,
      });

      const rowHash = crypto.createHash('sha256').update(Buffer.from(canonicalRowJson, 'utf8')).digest();
      rowHashes.push({ sortKey: `${tableName}:${pkHex}`, hash: rowHash });
    }
  }

  if (rowHashes.length === 0) return Buffer.alloc(32, 0);

  rowHashes.sort((a, b) => compareCanonicalStrings(a.sortKey, b.sortKey));
  const leaves = rowHashes.map((r) => r.hash);
  const tree = new MerkleTree(leaves);
  return tree.root;
}
```

#### Critical Performance & Concurrency Findings
1. **$O(N \log N)$ Non-Incremental Recomputation**:
   - On **every transaction commit**, the state frontier traverses every row in every table in memory ($N$), stringifies each row to canonical JSON, hashes each row with SHA-256, sorts all $N$ hashes, and builds a complete binary Merkle tree.
   - For $N = 1,000,000$ rows, committing a single insert takes seconds of pure CPU hashing on Node.js's main thread.
   - Production systems require a **Sparse Merkle Tree (SMT)** or **Persistent Radix Tree** where updates cost $O(\log N)$ hashes.
2. **Unbounded Heap Memory Consumption**:
   - `this.tables` holds all database rows in uncompressed V8 heap memory. A 10 GB database will exceed Node.js default memory limits (~1.4 GB–4 GB), throwing `ERR_HEAP_OUT_OF_MEMORY`.

---

### 3.3 Byzantine Fault Domain Realism: 5-Node Local Docker Evaluation

In `blockchain/besu/docker-compose.yml` and `blockchain/besu/genesis/genesis.json`:
- 5 Besu validator nodes (`besu-validator-1` to `besu-validator-5`) run as containers on the same Docker host on bridge subnet `172.28.0.0/16`.
- Validator private keys are hardcoded in repository files (`nodes/node-1/key` = `0x1`, `node-2/key` = `0x2`, ..., `node-5/key` = `0x5`).

#### Fault Domain Independence Breakdown

| Fault Domain Level | Isolation in 5-Node Docker | Byzantine Realism Assessment |
| :--- | :--- | :--- |
| **Physical Hardware** | **NONE** (Shared CPU, RAM, Disk, Power Supply) | Single host hardware failure crashes all 5 nodes ($F=5 > f=1$). Zero physical BFT. |
| **Host OS & Kernel** | **NONE** (Shared Linux/Windows Kernel) | Kernel panic, OS freeze, or Docker daemon crash halts entire cluster. |
| **Administrative Access** | **NONE** (Single root/admin account controls host & volumes) | Compromise of host user grants root read/write access to all 5 validator keys & data directories. |
| **Network & Infrastructure** | **NONE** (Single virtual bridge `172.28.0.0/16`) | Virtual interface partition or host NIC drop cuts off all nodes. Zero ASN/cross-cloud diversity. |
| **Software Diversity** | **NONE** (Identical Besu image `hyperledger/besu:latest`, JVM, config) | Common-mode bugs (e.g. JVM GC pauses, Besu QBFT parsing zero-days) impact all 5 nodes identically. |
| **Key Management** | **UNSAFE** (Plaintext dev keys `0x1`...`0x5` in host FS) | Attacker accessing filesystem takes over 100% of voting weight ($5/5 > 4/5$). |

**Verdict**: The 5-container Docker configuration is a **functional development harness providing logical process separation only**. It provides **zero physical Byzantine Fault Tolerance**. In production, validators must be deployed across distinct cloud providers, independent ASNs, hardware HSM key storage, and heterogeneous administrative credentials.

---

## 4. Formal Security Theorem & Bounds

### 4.1 System Model & Cryptographic Primitives
1. **Entities**:
   - Customer KMS: Generates Ed25519 keypair $(\text{pk}_{\text{cust}}, \text{sk}_{\text{cust}})$ in an isolated HSM.
   - Evidence Agent: Generates Ed25519 keypair $(\text{pk}_{\text{agent}}, \text{sk}_{\text{agent}})$.
   - Database State $S_k \in \mathcal{S}$ at commit sequence $k \in \mathbb{N}^+$.
   - Hyperledger Besu QBFT Ledger $\mathcal{L}$ with $n=5$ validators, quorum threshold $q = 4$ ($3f+1$ model with $f=1$).
2. **Cryptographic Functions**:
   - $\mathcal{H}: \{0,1\}^* \to \{0,1\}^{256}$: SHA-256 hash function modeled as a random oracle.
   - $\text{c14n}(x)$: RFC 8785 canonical JSON encoder.
   - $\text{MerkleRoot}(S_k)$: Deterministic RFC 6962 tree hash over sorted leaf digests $\mathcal{H}(\text{c14n}(r))$ for all $r \in S_k$.
3. **Commitment Structure**:
   $$C_k = \langle \text{tenantId}, \text{databaseId}, \text{checkpointId}_k, k, \text{epoch}, \text{chkDigest}_k, \text{stateMerkleRoot}_k, \text{changeChainHead}_k, C_{k-1}.\text{digest}, \text{ts}_k, \text{ver} \rangle$$
   $$\text{digest}(C_k) = \mathcal{H}(\text{domain}_{\text{cmt}} \parallel \text{c14n}(C_k))$$
   $$\sigma_{\text{cust}}^{(k)} = \text{Sign}_{\text{sk}_{\text{cust}}}(\text{domain}_{\text{cust}} \parallel \text{digest}(C_k) \parallel k)$$
   $$\sigma_{\text{agent}}^{(k)} = \text{Sign}_{\text{sk}_{\text{agent}}}(\text{domain}_{\text{agent}} \parallel \text{digest}(C_k) \parallel \text{LSN}_k)$$

---

### 4.2 Formal Security Theorems

#### Theorem 1 (Dual-Attestation Authorization Invariant)
*Let $\mathcal{A}$ be a probabilistic polynomial-time (PPT) adversary having complete control over the Wolverine Gateway, evidence journal, and untrusted PostgreSQL database, but without access to $\text{sk}_{\text{cust}}$ or $\text{sk}_{\text{agent}}$.*

**Claim**: $\mathcal{A}$ cannot forge a commitment $C_k^*$ that is accepted by `UniversalReceiptVerifier` or recorded on `WolverineTrustRegistry.sol`, except with probability:
$$\Pr[\mathcal{A}\text{ succeeds}] \le \text{Adv}_{\text{Ed25519}}^{\text{EUF-CMA}}(\mathcal{A}) + \text{Adv}_{\mathcal{H}}^{\text{CR}}(\mathcal{A}) \le \text{negl}(\lambda)$$
*Proof Sketch*: Acceptance requires valid $\sigma_{\text{cust}}$ over $\text{domain}_{\text{cust}} \parallel \text{digest}(C_k) \parallel k$ and $\sigma_{\text{agent}}$ over $\text{domain}_{\text{agent}} \parallel \text{digest}(C_k) \parallel \text{LSN}_k$. Under EUF-CMA security of Ed25519 and collision resistance of $\mathcal{H}$, $\mathcal{A}$ cannot forge signatures on new commitment preimages or find preimage collisions. $\blacksquare$

#### Theorem 2 (State Tamper-Evidence Invariant)
*Let $S_k$ be the authentic database state corresponding to commitment $C_k$ with root $R_k = \text{MerkleRoot}(S_k)$. Suppose an adversary modifies the live database state out-of-band to $S_k' \neq S_k$.*

**Claim**: The probability that $\text{MerkleRoot}(S_k') = R_k$ is bounded by $\text{Adv}_{\mathcal{H}}^{\text{CR}}(\mathcal{A}) \le \text{negl}(\lambda)$. When evaluated against receipt $R_k$, `UniversalReceiptVerifier` strictly outputs `LOCAL_TAMPERING_DETECTED`.
*Proof Sketch*: By definition of RFC 6962 tree and RFC 8785 canonical serialization, any modification, insertion, or deletion of a row modifies at least one leaf hash $\mathcal{H}(\text{c14n}(r))$. By collision resistance of SHA-256, the resulting root $R_k' \neq R_k$. `UniversalReceiptVerifier` compares $R_k'$ to $R_k$ and rejects. $\blacksquare$

#### Theorem 3 (On-Chain Monotonicity & Linkage Invariant)
*In `WolverineTrustRegistry.sol`, commitments for a tenant and database form a strictly monotonic sequence $k = 1, 2, \dots$ linked by $C_k.\text{previousCommitmentDigest} = C_{k-1}.\text{digest}$.*

**Claim**: For any sequence of valid commitments submitted to Besu QBFT, no forks, sequence skips, or history substitutions can be accepted by the smart contract.
*Proof Sketch*: `WolverineTrustRegistry.commitState()` verifies `commitSeq == latestSequence + 1` and `previousCommitmentDigest == sequenceIndex[currentHead]`. If violated, it reverts with `SequenceGapDetected` or `InvalidPreviousCommitment`. $\blacksquare$

---

### 4.3 Explicitly Non-Defensible Claims & Boundary Conditions

1. **NON-DEFENSIBLE CLAIM: "Universal Trust Receipt (v2) enables zero-trust air-gapped verification of blockchain finality."**
   - **Why Non-Defensible**: The receipt contains zero cryptographic proofs of blockchain inclusion (no EVM block headers, no MPT inclusion proofs, no QBFT commit seals). An air-gapped auditor cannot distinguish between an authentic transaction finalized on Besu and a fabricated hash string generated by an adversary.
2. **NON-DEFENSIBLE CLAIM: "The 5-node local Docker configuration provides Byzantine Fault Tolerance."**
   - **Why Non-Defensible**: All 5 containers share a single host, kernel, disk, and administrative credential. Effective Byzantine fault tolerance is $f = 0$ against host/admin failure.
3. **NON-DEFENSIBLE CLAIM: "The CDC pipeline supports arbitrary concurrent PostgreSQL transactions."**
   - **Why Non-Defensible**: `PgLogicalClient` maintains a single `currentXid` variable, which causes mutation corruption and attribution errors when multiple transactions are streamed concurrently.

---

## 5. Required Technical Remediations

1. **Upgrade `UniversalTrustReceipt` to Include Verifiable EVM Inclusion & QBFT Seals**:
   - Embed RLP-encoded EVM Block Header.
   - Embed Besu QBFT validator commit seals from `header.extraData` (`IstanbulExtra`) and verify $\ge 2f+1$ secp256k1 signatures against genesis validator public keys offline.
   - Embed Merkle Patricia Trie (MPT) inclusion proof for the `CommitmentRecorded` event receipt.
2. **Fix CDC Transaction Concurrency & Streaming Replication**:
   - Refactor `PgLogicalClient` to index all mutation routing by message relation/xid rather than a single `currentXid`.
   - Implement handlers for `pgoutput` streaming messages (`S`, `E`, `A`, `c`, `P`, `K`).
3. **Implement Sparse Merkle Tree (SMT) for State Frontier**:
   - Replace $O(N \log N)$ full-table scan in `DeterministicStateFrontier` with an incremental Sparse Merkle Tree or Patricia Radix Tree to achieve $O(\log N)$ commit latency.
