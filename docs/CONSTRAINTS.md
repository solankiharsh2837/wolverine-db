# WolverineDB // Architectural & Cryptographic Constraints

> **Source Code is Authoritative.**  
> This document specifies the HARD and SOFT engineering constraints that govern all modifications to **WolverineDB v1.3.0**.

---

## 1. HARD CONSTRAINTS (Never Violate Without Major Protocol RFC)

1. **Non-Malleable Canonical Hashing**:
   - ALL cryptographic digests over structured payloads MUST use `canonicalizeJson` from [`src/binary/c14n.ts`](../src/binary/c14n.ts) with strict domain prefixes (`WDB:COMMITMENT:v1:`, `WDB:TRUST:v1:`, `WDB:ATTESTATION:v1:`). Never use raw `JSON.stringify`.
2. **Durable Replay Protection**:
   - Recovery approval nonces MUST be persisted via `IApprovalNonceStore` (backed by PostgreSQL `wolverine_sys.approval_nonces`). In-memory sets are strictly forbidden in production paths.
3. **Byzantine Quorum Safety ($2f+1$)**:
   - Quorum threshold MUST satisfy $Q \ge 2f + 1$ where $N = 3f + 1$. A quorum certificate with fewer than $2f+1$ valid signatures is cryptographically invalid.
4. **Gateway Ingress Signer Authentication**:
   - Ingress gateways MUST verify customer Ed25519 signatures before dispatching attestation requests to validators (`verifyCustomerCommitment`).
5. **Ledger Record Binding**:
   - Ingress gateways and consensus engines MUST explicitly bind the returned `ledgerRecord` and `PortableTrustProof` to the commitment that was attested.
6. **Sentinel Policy Gate Blast Radius & TOCTOU**:
   - Maximum blast radius for autonomous proposals is strictly capped at `MAX_AUTONOMOUS_BLAST_RADIUS = 1000` rows.
   - Basis checkpoint and EVM anchor digests MUST be re-verified immediately prior to granting `POLICY_APPROVED`.

---

## 2. SOFT CONSTRAINTS (Configurable via Deployment Configs)

1. **Batching Interval**:
   - Default commit batch interval is 100ms or 1,000 transactions (configurable via `TrustGatewayConfig`).
2. **Required EVM Confirmations**:
   - Default on-chain anchor confirmation count is 1 block in test environments and 12 blocks on Ethereum Mainnet.
3. **Outage Queue Size**:
   - Default disaster recovery queue holds up to 100,000 pending commitments before shedding load.
