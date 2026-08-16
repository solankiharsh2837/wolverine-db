# WolverineDB v1.3: External Trust Anchoring & Product Architecture Specification

> **“Your database can lie. Your audit trail cannot.”**

---

## 1. What WolverineDB Is

**WolverineDB** is an independent cryptographic trust boundary and continuous verified state reconstruction layer for relational and document databases (PostgreSQL, MySQL, SQLite). 

It continuously audits database mutation streams, maintains immutable hash chains and Merkle state roots, and anchors state commitments into the **Wolverine Trust Network**—an independent, permissioned Byzantine Fault Tolerant (BFT) trust ledger.

```text
CUSTOMER DATABASE
       │
       ▼
WOLVERINE DB CORE (OSS)
       │
       ├── CDC / WAL Capture (PostgresAdapter)
       ├── Canonical Hash Chains (SHA-256)
       ├── RFC 6962 Merkle State Roots
       ├── Dependency Graph Analysis
       └── Continuous State Reconstruction
              │
              ▼
       WOLVERINE CLIENT SDK
              │ (SigningProvider: KMS / HSM / Software)
              ▼
      EXTERNAL TRUST NETWORK
              │
       ┌──────┴──────┐
       ▼             ▼
 MANAGED CLOUD    SELF-HOSTED
 (Wolverine SaaS) (Sovereign Cluster)
       │             │
       └──────┬──────┘
              ▼
       BFT TRUST LEDGER
       (4-of-5 Byzantine Quorum)
              │
              ▼
       IMMUTABLE TRUST RECEIPT
              │
       ┌──────┴──────┐
       ▼             ▼
 OFFLINE VERIFIER  OPTIONAL PUBLIC
 (Zero Network)    CHAIN BRIDGE (EVM)
```

---

## 2. The Core Problem: Why Database Integrity Alone Fails

Traditional databases suffer from the **Administrative State Vulnerability**:
1. **Superuser Omnipotence**: A database administrator, privileged cloud IAM role, or compromised infrastructure root can execute raw SQL mutations (`UPDATE accounts SET balance = ...`), modify WAL files, or backdate records.
2. **Internal Audit Poisoning**: Built-in audit tables (e.g. `audit_log`, `pg_audit`) live inside the same security boundary as the database engine itself. If the database is compromised, the audit trail is compromised.
3. **No Independent Provability**: When an enterprise is audited or sued, presenting a database dump or cloud backup proves nothing about whether the data was altered 10 minutes prior to the dump.

**WolverineDB's Solution**: Move the root of trust **outside the customer's database and infrastructure**.

---

## 3. The Commercial Product Model: External Trust Anchoring

The commercial product is the **Wolverine External Trust Anchoring Service**. Customers choose between two deployment models:

### Deployment Model A: Managed Wolverine Trust Network (Wolverine Cloud SaaS)
- **Target**: High-velocity startups, FinTechs, healthcare, and SaaS enterprises.
- **Workflow**:
  1. The customer installs the lightweight `WolverineClient` SDK / Evidence Agent.
  2. The local SDK captures CDC/WAL events, computes 32-byte Merkle roots, and signs commitments via **Cloud KMS (AWS/GCP/Azure) or Hardware HSM**.
  3. **Zero customer data leaves the customer's VPC**—only 32-byte cryptographic fingerprints and sequence metadata leave the boundary.
  4. Wolverine Cloud's distributed validator cluster verifies sequence monotonicity and finalizes commitments at 4-of-5 quorum.
  5. The customer receives portable **Immutable Trust Receipts** (`receipt.json`).

### Deployment Model B: Self-Hosted Wolverine Trust Network (Sovereignty)
- **Target**: Sovereign governments, central banks, defense contractors, and air-gapped institutions.
- **Workflow**:
  1. The customer deploys their own validator daemons, ledger replicas, and trust gateway (`wolverine-trust-node`).
  2. The customer SDK connects to their self-hosted gateway.
  3. **Protocol Compatibility**: The wire format, block structure, and proof verification are 100% identical to Wolverine Cloud.
  4. The customer has zero runtime dependency on Wolverine Cloud infrastructure.

---

## 4. Hardware Security & Cloud KMS Key Abstraction

To ensure commercial credibility, applications do not hold raw Ed25519 private keys in application memory. WolverineDB provides the `ISigningProvider` interface:

```text
SigningProvider
 ├── LocalSoftwareKeyProvider   (Development / Local testing)
 ├── AwsKmsSigningProvider      (AWS KMS Asymmetric Sign)
 ├── GcpKmsSigningProvider      (Google Cloud Cloud HSM / KMS)
 ├── VaultSigningProvider       (HashiCorp Vault / Azure Key Vault)
 └── Pkcs11HsmSigningProvider   (Hardware Security Module / Sovereign)
```

```typescript
// Customer connects using AWS KMS Key ARN instead of raw software private keys
const wolverine = await WolverineClient.connect({
  endpoint: 'https://trust.wolverine-db.com/v1',
  networkType: 'MANAGED',
  tenantId: 'enterprise-fintech',
  databaseId: 'production-ledger',
  signingProvider: new CloudKmsSigningProvider({
    provider: 'AWS_KMS',
    keyArn: 'arn:aws:kms:us-east-1:123456789012:key/wolverine-signing-key',
    region: 'us-east-1',
    publicKey: customerKmsPublicKey,
  }),
});
```

---

## 5. Merkle State Commitment vs. State Reconstruction

A critical architectural distinction:

$$\begin{aligned}
\text{\bf 32-Byte Merkle Root} &\implies \text{\bf State Commitment Proof ("What state existed at time } T \text{")} \\
\text{\bf Continuous Reconstruction Engine} &\implies \text{\bf Complete Data Recovery ("How to recover full rows and tables")}
\end{aligned}$$

- **The External Anchor**: Proves that a specific database state with Merkle root $R$ existed at sequence $S$ and was attested by Quorum.
- **The Reconstruction Engine**: Combines the trusted checkpoint anchor with verified WORM mutation logs, provenance graphs, and authorized replay to rebuild the full PostgreSQL tables and rows.

---

## 6. The Complete External Anchor Lifecycle & Adversarial Defense

```text
[ACT I] Legitimate PostgreSQL Operations
  ├── Orders placed: Balance = $10,000
  ├── Checkpoint #1842 computed (Merkle Root = 0x5a4f...)
  ├── SDK signs commitment via Cloud KMS
  ├── Wolverine Trust Network reaches 5/5 Byzantine Quorum
  └── Immutable Trust Receipt (receipt-1842.json) generated & saved

[ACT II] Rogue DBA / Attacker Compromise
  ├── Attacker gains PostgreSQL superuser / root credentials
  ├── Attacker updates Balance = $1,000,000 directly via SQL
  ├── Attacker deletes local audit tables (pg_audit, audit_log)
  ├── Attacker alters local WAL replication logs
  └── Attacker attempts to publish rogue Checkpoint #1842 to Wolverine Trust Network

[ACT III] Byzantine Network Defense
  ├── 5/5 Validators reject the rogue commitment (CONFLICTING_COMMITMENT)
  ├── Sequence monotonicity and previous commitment hash invariants hold
  └── Wolverine Trust Ledger remains 100% untouched and authentic

[ACT IV] Air-Gapped Standalone Verification
  ├── Auditor runs: wdb receipt verify ./receipt-1842.json
  ├── Zero network requests, zero server calls, zero database access
  └── Cryptographic Verdict: AUTHENTIC & IMMUTABLE (PASS)
      (Mathematically proves original state was $10,000, exposing the DBA attack)
```

---

## 7. Subsystem Maturity & Production Classification

| Subsystem | Maturity Classification | Notes |
| :--- | :--- | :--- |
| **Cryptographic Primitives** | **REAL PRODUCTION** | Merkle trees with bound leaf counts, `encodeProtocolTuple`, Ed25519 signatures, SHA-256 hash chains. |
| **Concurrency & Storage** | **REAL PRODUCTION** | Serialized atomic ledger append queue, POSIX `O_EXCL` (`wx`) atomic checkpoint stores, crash-safe persistence journals. |
| **Customer SDK & Ingestion** | **REAL PRODUCTION** | `WolverineClient`, `ISigningProvider`, `WalNormalizer`, `PostgresAdapter` CDC polling, offline buffering queues. |
| **BFT Consensus & Ledger** | **PRODUCTION REFERENCE** | 4-of-5 BFT quorum engine, deterministic block headers, dynamic epoch rotation, dual-signed key rotation. |
| **Network Transport** | **REFERENCE / PLUGGABLE** | Asynchronous RPC transport with structured failure telemetry (`TIMEOUT`, `PEER_REJECTED`, `UNREACHABLE`). Ready for HTTP/gRPC. |
| **Public Chain Bridge** | **OPTIONAL BRIDGE** | `EvmAnchorBridge` for periodic cross-domain timestamping on Ethereum/Base/Arbitrum. |

---

## 8. Commercial SaaS Tiering Architecture

| Tier | Deployment | Anchoring Frequency | Validators | Key Feature |
| :--- | :--- | :--- | :--- | :--- |
| **Core (OSS)** | On-Premise | Local Checkpoints | Local Engine | Open-source hash chains & verified reconstruction |
| **Cloud Professional** | Wolverine Cloud | Every 1 Minute | 5 Managed Nodes | Managed BFT consensus + Cloud KMS support + 30-day proof retention |
| **Cloud Enterprise** | Wolverine Cloud | Continuous / Real-time | 7 Global Nodes | Real-time finality + SLA guarantee + offline receipt export |
| **Sovereign** | Self-Hosted | Customer Configured | Customer Cluster | Sovereign enterprise deployment with zero external dependencies |
| **Public Anchor Addon** | Cross-Domain | Daily / Hourly | EVM Chain | Periodic 32-byte Merkle root anchoring to Ethereum / Base / Arbitrum |
