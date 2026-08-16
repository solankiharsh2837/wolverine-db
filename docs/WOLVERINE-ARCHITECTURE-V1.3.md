# WolverineDB: External Trust & Evidence Infrastructure for Databases

> **“Your database can lie. Your audit trail cannot.”**

---

## 1. Executive Summary & Product Positioning

**WolverineDB is an external trust and evidence infrastructure for databases.** 

Traditional databases (PostgreSQL, MySQL, SQLite) operate under the *Administrative State Vulnerability*: anyone with superuser credentials, root access, or compromised cloud IAM can modify tables, rewrite audit logs, or alter database replication streams with zero cryptographic accountability.

WolverineDB creates an **independent cryptographic trust boundary** outside the customer's database and cloud environment.

```text
                    CUSTOMER VPC
                         │
                  PostgreSQL / MySQL
                         │
                         ▼
                ┌─────────────────┐
                │ Wolverine Agent │
                │  CDC / WAL      │
                │  Merkle State   │
                │  KMS Signing    │
                └────────┬────────┘
                         │
                  commitment only (32 bytes)
                         │
                         ▼
               ╔═══════════════════╗
               ║ WOLVERINE CLOUD   ║
               ║ TRUST NETWORK     ║
               ╠═══════════════════╣
               ║ Validator 1       ║
               ║ Validator 2       ║
               ║ Validator 3       ║
               ║ Validator 4       ║
               ║ Validator 5       ║
               ║                   ║
               ║ 4/5 BFT FINALITY  ║
               ╚═════════╤═════════╝
                         │
                         ▼
                 IMMUTABLE RECEIPT
                         │
                ┌────────┴────────┐
                ▼                 ▼
         Offline Auditor      Public Anchor
         (Zero Network)       Ethereum / Base
```

---

## 2. The Three Commercial Product Offerings

### Product 1: WolverineDB Core (Open Source)
- **Target**: Developers, DBAs, and software engineers.
- **Scope**: Local database integrity, CDC/WAL capture (`PostgresAdapter`), canonical SHA-256 hash chains, RFC 6962 Merkle tree checkpoints, WORM evidence tracking, and continuous state reconstruction.

### Product 2: Wolverine Trust Cloud (Commercial SaaS)
- **Target**: FinTechs, healthcare, SaaS platforms, and compliance-driven enterprises.
- **Scope**: Managed Byzantine Trust Network (5 geographically isolated validator nodes), sub-second 4-of-5 BFT finality, AWS/GCP/Azure KMS key integration, immutable trust receipts (`receipt.json`), proof export APIs, and SLA guarantees.

### Product 3: Wolverine Sovereign / Enterprise (Air-Gapped & Regulated)
- **Target**: Sovereign governments, central banks, defense contractors, and air-gapped institutions.
- **Scope**: Self-hosted validator and ledger nodes (`wolverine-trust-node`), private BFT consensus, PKCS#11 Hardware Security Module (HSM) integration, configurable quorum thresholds, zero external cloud dependencies.

---

## 3. Commercial Pricing Model: Anchoring Frequency

WolverineDB does not charge per database or per gigabyte of storage. Customers subscribe based on **Anchoring Frequency & External Trust Guarantees**:

| Tier | Deployment Model | Anchoring Frequency | Consensus Topology | Key Capability |
| :--- | :--- | :--- | :--- | :--- |
| **Developer** | Core (Local OSS) | Local Checkpoints | Single Engine | Open-source hash chains & verified reconstruction |
| **Startup** | Wolverine Cloud | Every 15 Minutes | 5 Managed Nodes | Cloud KMS + 30-Day receipt retention |
| **Business** | Wolverine Cloud | Every 5 Minutes | 5 Managed Nodes | Cloud KMS + 1-Year retention + audit export |
| **Enterprise** | Wolverine Cloud | Continuous / Real-Time | 7 Global Nodes | Real-time finality + SLA guarantee + dedicated gateway |
| **Regulated** | Wolverine Cloud | Continuous + EVM | 7 Global + Chain | BFT Finality + Periodic Ethereum / Base public anchor |
| **Sovereign** | Self-Hosted | Customer Configured | Customer Cluster | Sovereign enterprise cluster + HSM support |

---

## 4. State Attestation vs. State Reconstruction

A fundamental architectural distinction:

```text
                    IMMUTABLE RECEIPT
                           │
                           ▼
               "STATE ROOT H WAS FINALIZED"
                           │
                 ┌─────────┴─────────┐
                 ▼                   ▼
           OFFLINE PROOF       RECOVERY ENGINE
           VERIFICATION         + WORM HISTORY
                 │                   │
                 ▼                   ▼
     "This commitment was     "This is the genuine
      externally finalized"    reconstructed state"
```

1. **The 32-Byte State Commitment ($H$)**: Proves *what* mathematical root was attested and finalized by 4-of-5 BFT Quorum at sequence $S$ and time $T$.
2. **The Continuous Reconstruction Engine**: Takes the verified commitment anchor and replays authorized WORM mutation logs through a strict dependency graph to rebuild full rows, columns, and tables.

---

## 5. Enterprise Hardware Key Abstraction (`ISigningProvider`)

Applications never pass raw private keys in process memory:

```text
ISigningProvider
 ├── LocalSoftwareSigningProvider (Development & testing)
 ├── CloudKmsSigningProvider      (AWS KMS, GCP Cloud HSM, Azure Key Vault)
 └── HsmSigningProvider           (PKCS#11 Hardware Security Modules / Sovereign)
```

```typescript
import { WolverineClient, CloudKmsSigningProvider } from 'wolverine-db';

const wolverine = await WolverineClient.connect({
  endpoint: 'https://trust.wolverine-db.com/v1',
  networkType: 'MANAGED',
  tenantId: 'enterprise-fintech',
  databaseId: 'production-ledger',
  signingProvider: new CloudKmsSigningProvider({
    provider: 'AWS_KMS',
    keyArn: 'arn:aws:kms:us-east-1:112233445566:key/wolverine-enterprise-key',
    region: 'us-east-1',
    publicKey: customerKmsPublicKey,
  }),
  apiKey: 'wdb_live_sec_fintech_prod',
});
```

---

## 6. Public Blockchain: The Ultimate External Anchor

Wolverine does not run on a blockchain—it is an independent BFT trust network. Ethereum and Base serve as an **optional cross-domain public anchor**:

```text
Customer Database
       │
       ▼
Wolverine Trust Network (5 BFT Validators)
       │
       │ BFT Finality
       ▼
Trust Block #1842
       │
       ├────────────────────────┐
       ▼                        ▼
Immutable Receipt         Public EVM Anchor
(receipt-1842.json)             │
                                ▼
                         Ethereum / Base
```

- **Wolverine Trust Network states**: *"Our 5 independent validators witnessed and certified this commitment."*
- **Public Blockchain states**: *"And independently, this state root existed publicly at block #X."*

---

## 7. The SSIP Adversarial Verification Scenario

```text
[ACT I] Legitimate Operations
  ├── Account Balance = $10,000.00
  ├── Checkpoint #1842 computed
  ├── Signed via AWS KMS -> 5/5 Byzantine Quorum reached
  └── Immutable Trust Receipt (receipt-1842.json) generated

[ACT II] Rogue DBA Attack + Byzantine Collusion
  ├── Attacker gets PostgreSQL superuser: sets Balance = $100,000,000.00
  ├── Attacker drops audit tables and alters local WAL history
  ├── 1 Colluding Byzantine Validator attempts to double-sign
  └── Attacker submits forged Checkpoint #1842 to Wolverine Trust Network

[ACT III] Byzantine Defense
  ├── Validators 1-4 [Honest]: REJECT (Sequence 1842 already finalized)
  ├── Validator 5 [Byzantine]: ATTEST (Rogue double-sign attempt)
  ├── Quorum Result: 1 / 5 Signatures (Threshold 4 / 5 Required)
  └── Finality: DENIED (Fail-Closed) — Ledger 100% untouched

[ACT IV] Air-Gapped Standalone Offline Verification
  ├── Auditor runs: wdb receipt verify ./receipt-1842.json
  ├── Result: AUTHENTIC_AND_IMMUTABLE (PASS)
  └── Conclusion: Proves genuine state was $10,000.00, exposing the DBA attack
```

---

## 8. Subsystem Maturity Classifications

| Subsystem | Maturity Classification | Operational Status |
| :--- | :--- | :--- |
| **Cryptographic Primitives** | **REAL PRODUCTION** | Merkle trees with bound leaf counts, `encodeProtocolTuple`, Ed25519 signatures, SHA-256 hash chains. |
| **Concurrency & Storage** | **REAL PRODUCTION** | Serialized atomic ledger append queue, POSIX `O_EXCL` (`wx`) atomic checkpoint stores, crash-safe persistence journals. |
| **SDK & Ingestion Engine** | **REAL PRODUCTION** | `WolverineClient`, `ISigningProvider`, `WalNormalizer`, `PostgresAdapter` CDC polling, offline buffering queues. |
| **BFT Consensus & Ledger** | **PRODUCTION REFERENCE** | 4-of-5 BFT quorum engine, deterministic block headers, dynamic epoch rotation, dual-signed key rotation. |
| **Network Transport** | **REFERENCE / PLUGGABLE** | Asynchronous RPC transport with structured failure telemetry (`TIMEOUT`, `PEER_REJECTED`, `UNREACHABLE`). Ready for HTTP/gRPC. |
| **Public Chain Bridge** | **OPTIONAL BRIDGE** | `EvmAnchorBridge` for periodic cross-domain timestamping on Ethereum/Base/Arbitrum. |
