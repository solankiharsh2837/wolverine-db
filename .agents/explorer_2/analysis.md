# R2: Adversarial Gateway & Threat Model Evaluation

**Independent Technical Security Audit & Architectural Evaluation**
**Target**: WolverineDB Cryptographic Trust Plane, Gateway Daemon, KMS Providers, and Besu RPC Subsystem
**Author**: Explorer 2 (Adversarial Principal Security Auditor)
**Date**: 2026-08-20

---

## Executive Summary & Scope

This audit evaluates the **Adversarial Gateway & Threat Model (R2)** of WolverineDB under the assumption of a **full Gateway root compromise** (Byzantine operator model). The evaluation examines whether a malicious or compromised Gateway operator can forge, tamper with, censor, or replay database commitments, bypass customer KMS root authorization, or poison the canonical Hyperledger Besu state.

### Key Audit Findings Summary
1. **Critical On-Chain Signature Bypass (CRITICAL-01)**: The smart contract WolverineTrustRegistry.sol stores customerSignature and gentSignature as raw bytes but **never cryptographically verifies them**. Furthermore, commitState is an unpermissioned xternal function that performs no caller validation (msg.sender) or digest preimage checks. A compromised Gateway can submit completely fabricated state roots and dummy signatures directly to the Besu ledger, permanently bricking or poisoning a tenant's on-chain history.
2. **Architectural Decoupling of Gateway Daemons and Besu RPC (HIGH-01)**: The production daemon WdbGatewayDaemon (src/daemons/wdb_gateway_daemon.ts) and TrustGatewayServer (src/runtime/gateway.ts) operate strictly on an off-chain TypeScript BFT quorum model. They **do not invoke BesuClient or BesuTransactionSubmitter** during live request handling. The blockchain submission path exists only in standalone demo scripts and acceptance test fixtures.
3. **Triple-Conflicting Signature Preimage Specifications (HIGH-02)**: Three mutually incompatible signature preimage schemas exist across src/trust/commitment.ts, src/trust_network/commitment.ts, and src/proof/universal_receipt_verifier.ts. None of the schemes include EVM chainId or contractAddress, exposing customer KMS signatures to cross-chain and cross-environment replay attacks.
4. **Silent HMAC Simulation Fallbacks in Legacy KMS Providers (HIGH-03)**: CloudKmsSigningProvider and HsmSigningProvider in src/crypto/signing_provider.ts contain silent HMAC-SHA512 fallbacks using the public keyArn / keyId string as the secret key when unconfigured, violating the fail-closed security principle.
5. **Missing Cloud KMS SDK Dependencies & Default Zero-Key Initialization (MEDIUM-01)**: Neither @aws-sdk/client-kms nor @google-cloud/kms is listed in package.json. Furthermore, AwsKmsSigningProvider and GcpKmsSigningProvider default uninitialized public keys to Buffer.alloc(32, 0) rather than throwing an immediate configuration error.

---

## 1. Threat Model & Adversarial Gateway Analysis

### 1.1 Threat Model Definition
* **Adversary Capability**: The adversary has achieved full root access / remote code execution on the Wolverine Trust Gateway node, or is a malicious internal cloud infrastructure operator (Byzantine Operator).
* **Adversary Controls**:
  - Ingress API endpoints (/v1/commitments, /v1/receipts/*).
  - Gateway private TLS keys and mTLS communication channels.
  - Besu node operator Ethereum private key (operatorPrivateKeyHex) used for submitting transactions to Hyperledger Besu QBFT.
  - Gateway in-memory caches, receipt stores, and replica dispatch channels.
* **Adversary Does NOT Control**:
  - Customer secure hardware / Cloud KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault, PKCS#11 HSM).
  - Customer database evidence agent running within the customer VPC / secure enclave.
  - Independent Besu QBFT validator nodes (assuming <= f Byzantine validators in the 3f+1 network).
  - Customer offline verification tools (AirGappedProofVerifier, UniversalReceiptVerifier).

---

### 1.2 Attack Scenario A: Modification or Tampering of Commitments Before Besu Submission

#### Analysis:
When a customer database agent dispatches a commitment to the Gateway, the payload includes checkpointDigest, stateMerkleRoot, changeChainHead, logicalTimestampUs, gentSignature, and customerSignature.

Under a compromised Gateway model, the Gateway operator can alter any of these fields before invoking Besu RPC.

#### Code Evidence (lockchain/contracts/WolverineTrustRegistry.sol:81-154):
The commitState function accepts ytes calldata agentSignature and ytes calldata customerSignature, but NEVER calls crecover or any signature verification routine. Furthermore, commitmentDigest is accepted directly without recomputing keccak256(abi.encode(...)) or sha256() over the fields.

#### Vulnerability Mechanics & Impact:
A compromised Gateway can forge any state root (R_fake), compute a fake digest (D_fake), supply random 64-byte buffers for gentSignature and customerSignature, and commit them on-chain. Besu QBFT will successfully finalize the block. Offline verifiers will reject these faked receipts, but the on-chain canonical sequence head is permanently poisoned and locked at D_fake, preventing legitimate customer submissions (due to SequenceGapDetected and InvalidPreviousCommitment).

---

### 1.3 Attack Scenario B: Sequence Number Forgery, Transaction Censorship, and Split-View Forking

1. **Transaction Dropping (Censorship)**: Because the Gateway is the single mTLS ingress point for agent daemons (WdbGatewayDaemon.handleRequest at /v1/commitments), a compromised Gateway can silently drop customer commitments, returning HTTP 503 CONSENSUS_UNAVAILABLE or timing out. The customer database accumulates offline commitments in offlineQueue without on-chain finality.
2. **Sequence Number Forgery and State Locking (Denial of Service)**: A compromised Gateway with access to the Besu operator key (operatorPrivateKeyHex) can call commitState repeatedly for any tenant ID and database ID, incrementing commitSeq from 1 to N with bogus Merkle roots. Because the contract does not check customer signatures, the tenant on-chain database state is permanently hijacked and locked.
3. **Equivocation / Split-View Forking Attack**:
   - Step 1: Customer agent submits genuine commitment C_A at commitSeq = 10.
   - Step 2: Gateway returns an aggregated Quorum Certificate or Universal Trust Receipt for C_A off-chain.
   - Step 3: Gateway submits conflicting commitment C_B (with different state root) at commitSeq = 10 to Besu.
   - Step 4: Besu registers C_B. Customer believes their state is C_A.
   - Step 5: At commitSeq = 11, customer creates C_{A+1} referencing Digest(C_A).
   - Step 6: When C_{A+1} is submitted to Besu, commitState reverts with InvalidPreviousCommitment(Digest(C_B), Digest(C_A)).
   - **Result**: Complete permanent desynchronization between off-chain customer state and authoritative on-chain ledger.

---

### 1.4 Attack Scenario C: Replay Attacks (Past Commitments, Cross-Tenant, and Cross-Chain)

1. **Replay of Past Commitments (Same Tenant)**: Prevented on Besu via DuplicateCommitment(commitmentDigest) and sequence monotonicity (commitSeq == currentHead + 1).
2. **Cross-Tenant Replay Vulnerability**: In src/proof/universal_receipt_verifier.ts:91-96, the customer signature preimage is computed as "WDB:CUST_AUTH:v2:" || checkpointDigest || commitSeq. Because tenantId and databaseId are omitted from the v2 authorization preimage, if Tenant 1 and Tenant 2 have identical checkpoint hashes at sequence 1, Tenant 1 KMS signature can be replayed as Tenant 2 authorization.
3. **Cross-Chain and Cross-Environment Replay**: None of the commitment digests or signature preimages across the entire codebase include chainId or contractAddress. A valid signature collected on Staging can be replayed against the Production Besu cluster at the same sequence number.

---

### 1.5 Attack Scenario D: Bypass of Customer KMS Authorization and Agent Attestation

| Target Layer | Bypass Feasibility | Mechanism and Root Cause |
|---|---|---|
| **Besu Smart Contract** | **100% Bypassable** | WolverineTrustRegistry.sol does not execute signature checks or verify public keys. Dummy bytes are accepted. |
| **Besu Submitter Middleware** | **100% Bypassable** | BesuTransactionSubmitter:11-23 only checks input.customerSignatureHex is non-empty string. |
| **Legacy CloudKmsSigningProvider** | **100% Bypassable** | src/crypto/signing_provider.ts:110 creates an HMAC-SHA512 with keyArn as key when KMS is unconfigured. |
| **Dev Signing Fallback** | **Bypassable via Env** | src/crypto/dev_signing_provider.ts:21-31 allows local software keys if WOLVERINE_DEV_SIGNER=1 or NODE_ENV=test. |
| **Air-Gapped Proof Verifier** | **Protected (with Caveats)** | AirGappedProofVerifier verifies Ed25519 signatures, but Step 2 uses hardcoded dummy digests. |

---

## 2. Byte-Level Preimage Mapping for Dual-Attestation Signatures

The audit identified three conflicting, incompatible signature schemas in the codebase:

### 2.1 Scheme 1: Canonical Dual Attestation (src/trust/commitment.ts)
1. **Unsigned Commitment Payload Digest (D_commit)**:
   - Preimage = "WDB:COMMITMENT:v2:" || JSON_C14N(Payload)
   - CommitmentDigest = SHA256(Preimage)
   - Serialized via RFC 8785 JSON Canonicalization (canonicalizeJson) with sorted keys: checkpointDigestHex, changeChainHeadHex, commitSeq, commitmentId, databaseId, epoch, logicalTimestampUs, lsn, previousCommitmentDigestHex, stateMerkleRootHex, tenantId.

2. **Customer Authorization Preimage (sigma_cust)**:
   - Preimage_cust = "WDB:CUST_AUTH:v1:" || D_commit (32B) || u64be(commitSeq) (8B)
   - AuthDigest_cust = SHA256(Preimage_cust)
   - sigma_cust = Ed25519_Sign(SK_cust, AuthDigest_cust)
   - Total preimage length: 56 bytes.
   - Layout: [00..15] ASCII "WDB:CUST_AUTH:v1:", [16..47] SHA-256 digest (32B), [48..55] Big-Endian uint64 commitSeq (8B).

3. **Agent Enclave Attestation Preimage (sigma_agent)**:
   - Preimage_agent = "WDB:AGENT_ATTEST:v1:" || D_commit (32B) || u16be(len(LSN)) (2B) || UTF8(LSN)
   - AttestDigest_agent = SHA256(Preimage_agent)
   - sigma_agent = Ed25519_Sign(SK_agent, AttestDigest_agent)

### 2.2 Scheme 2: Legacy Trust Network Commitment (src/trust_network/commitment.ts)
- Preimage = "WDB:TRUST:v1:" || JSON_C14N(LegacyPayload)
- D_trust = SHA256(Preimage)
- sigma_cust = Ed25519_Sign(SK_cust, D_trust) (Signed directly without auth prefix; no agent signature).

### 2.3 Scheme 3: Universal Trust Receipt v2 Verifier (src/proof/universal_receipt_verifier.ts)
- Customer: Preimage = "WDB:CUST_AUTH:v2:" || checkpointDigest (32B) || UTF8(commitSeq)
- Agent: Preimage = "WDB:AGENT_ATTEST:v2:" || checkpointDigest (32B) || UTF8(LSN)
- Deficiencies: Uses checkpointDigest instead of full commitmentDigest, stringified integers, omits tenantId, databaseId, chainId, and contractAddress.

---

## 3. KMS Signing Providers and Authorization Audit

### 3.1 Exhaustive Provider Matrix

| Module and File | Class Name | Underlying Cryptography | Fail-Closed Status | Insecure Fallback / Flaw |
|---|---|---|---|---|
| src/crypto/aws_kms_provider.ts | AwsKmsSigningProvider | AWS KMS Asymmetric API (Ed25519 / P-256) | **FAIL-CLOSED** | @aws-sdk/client-kms not installed; defaults public key to 0x00...00 (32 zeros) if unsupplied. |
| src/crypto/gcp_kms_provider.ts | GcpKmsSigningProvider | GCP Cloud KMS Asymmetric API | **FAIL-CLOSED** | @google-cloud/kms not installed; defaults public key to 0x00...00 (32 zeros) if unsupplied. |
| src/crypto/customer_signer.ts | CloudKmsCustomerSigner | Cloud KMS interface client | **FAIL-CLOSED** | Throws MISSING_SECRET_KEY on missing client or error. Sound fail-closed implementation. |
| src/crypto/signing_provider.ts | CloudKmsSigningProvider | **Simulated HMAC-SHA512** | **FAILS OPEN** | **CRITICAL VULNERABILITY**: Computes crypto.createHmac("sha512", keyArn).update(digest). Deterministic mock signature from public ARN! |
| src/crypto/signing_provider.ts | HsmSigningProvider | **Simulated HMAC-SHA512** | **FAILS OPEN** | **CRITICAL VULNERABILITY**: Computes crypto.createHmac("sha512", keyId).update(digest). |
| src/crypto/dev_signing_provider.ts | LocalDevelopmentSigningProvider | Local Software Ed25519 KeyObject | **CONDITIONAL** | Allowed when WOLVERINE_DEV_SIGNER=1 or NODE_ENV=test. Insecure if env variable leaks. |

### 3.2 Deep Dive on Insecure Fallbacks
1. **Public Key ARN HMAC Forgery** (src/crypto/signing_provider.ts:104-113): If an enterprise deploys CloudKmsSigningProvider without supplying a custom mockKey, the system silently produces a 64-byte HMAC using the customer AWS KMS Key ARN as the secret key. Because Key ARNs are visible in configurations and CloudTrail logs, any attacker can compute valid signatures without AWS IAM permissions.
2. **Default Zero Public Key Fallback** (src/crypto/aws_kms_provider.ts:57): Initializing publicKeyBytes to 32 bytes of zeros (Buffer.alloc(32, 0)) leads to silent authentication bypasses if verification functions perform unvalidated comparisons or if zero-keys are registered.

---

## 4. Transaction Submission Path: Gateway to Besu RPC

### 4.1 Step-by-Step Path Analysis
1. **Agent to Gateway**: WdbAgentDaemon.commitAndWitness() (src/daemons/wdb_agent_daemon.ts:75-166) computes digests, dual-signs via enclave and KMS, and dispatches over mTLS POST to Gateway /v1/commitments.
2. **Gateway Processing Disconnect**: WdbGatewayDaemon.handleRequest() (src/daemons/wdb_gateway_daemon.ts:104-186) receives commitments, collects attestations from validators, and stores a CanonicalQuorumCertificate in memory. **WdbGatewayDaemon NEVER submits to BesuClient!** It only returns the Quorum Certificate to the client.
3. **Besu Submitter Shallow Validation**: BesuTransactionSubmitter.submitStateCommitment() (src/blockchain/besu/transaction_submitter.ts:8-27) only checks that signature strings are non-empty, performing zero cryptographic verification.
4. **BesuClient Execution**: BesuClient.submitCommitment() (src/blockchain/besu/client.ts:59-140) submits commitState calldata signed with the Gateway operator private key (config.operatorPrivateKeyHex).
5. **Smart Contract Inscription**: WolverineTrustRegistry.sol:commitState validates sequence monotonicity and linkage, but does not verify signatures, caller permissions, or digest calculations.

---

## 5. Architectural Remediation and Mitigation Designs

### 5.1 Remediation 1: On-Chain EIP-712 / Secp256k1 Verification or Ed25519 Precompile Validation in WolverineTrustRegistry.sol
The smart contract must enforce on-chain cryptographic authorization:
1. Register authorized customer signing addresses per tenant (tenantOwners[tenantId]).
2. Verify that commitmentDigest matches keccak256(abi.encode(...)) of all input fields on-chain.
3. Verify customer authorization signature using ecrecover (EIP-712 structured data) or RIP-7212 / ALT_BN128 / Ed25519 precompile on Besu.

### 5.2 Remediation 2: Unify Dual-Attestation Preimage Schema with Explicit Domain Separation
Standardize all signature preimages to a single canonical specification containing chainId, contractAddress, tenantId, and databaseId:
- DomainSeparator = SHA256("WDB:DOMAIN:v3:" || u64be(chainId) || contractAddress || tenantId || databaseId)
- Preimage_cust = "WDB:CUST_AUTH:v3:" || DomainSeparator || D_commit || u64be(commitSeq)

### 5.3 Remediation 3: Eliminate Insecure KMS HMAC Fallbacks and Enforce Strict Fail-Closed
1. Delete silent HMAC fallbacks in src/crypto/signing_provider.ts and strictly throw WolverineError(KMS_OUTAGE) when unconfigured.
2. Install @aws-sdk/client-kms and @google-cloud/kms in package.json.
3. Disallow LocalDevelopmentSigningProvider in production builds, throwing an error if NODE_ENV === "production".

### 5.4 Remediation 4: Wire Gateway Daemons to Besu Submitter Pipeline
Update WdbGatewayDaemon.handleRequest() (src/daemons/wdb_gateway_daemon.ts) so that upon collecting a valid Quorum Certificate, it immediately dispatches the dual-signed commitment to BesuClient.submitCommitment(), attaching the Besu transaction hash and block number to the issued receipt.

---

## 6. Audit Verdict Matrix

| Dimension | Score / Status | Critical Finding Reference |
|---|---|---|
| **Gateway Byzantine Resistance** | **FAIL (Fragile)** | Compromised Gateway can commit falsified state roots directly to Besu due to missing on-chain signature checks. |
| **KMS Provider Fail-Closed Semantics** | **PARTIAL** | CloudKmsCustomerSigner is fail-closed, but legacy CloudKmsSigningProvider retains HMAC mock fallback. |
| **Signature Preimage and Domain Separation** | **FAIL (Inconsistent)** | 3 conflicting preimages; missing chainId and contractAddress domain separation. |
| **Besu RPC Integration Pipeline** | **DISCONNECTED** | Daemon layer does not invoke Besu submission path during live execution. |
