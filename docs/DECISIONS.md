# WolverineDB // Architectural Decision Records (ADRs)

> **Source Code is Authoritative.**  
> This document records the primary architectural decisions, trade-offs, and technical rationale across the evolution of **WolverineDB** from v0.1 to v1.3.0.

---

## ADR-01: Canonical JSON (c14n) vs. Binary Protobuf Serialization
- **Decision**: Use deterministic canonical JSON (`c14n`) with alphabetical key sorting and zero whitespace for state hashing.
- **Rationale**: Provides cross-language determinism, human inspectability in audit trails, and elimination of protobuf field tag malleability.
- **Location**: [`src/binary/c14n.ts`](../src/binary/c14n.ts)

---

## ADR-02: Ed25519 for Asymmetric Signatures
- **Decision**: Standardize on Ed25519 (RFC 8032) for customer commitment signing, validator attestations, and approval nonces.
- **Rationale**: High signing and verification throughput, resistance to side-channel attacks, and compact 32-byte public keys and 64-byte signatures.
- **Location**: [`src/crypto/approval.ts`](../src/crypto/approval.ts)

---

## ADR-03: Durable PostgreSQL Approval Nonce Store (Issue #1)
- **Decision**: Persist consumed recovery approval nonces in PostgreSQL `wolverine_sys.approval_nonces` table with unique constraint handling (`23505`) rather than relying on in-memory sets.
- **Rationale**: Guarantees durable atomic replay protection surviving process restarts, cluster failovers, and multi-threaded recovery workers.
- **Location**: [`src/postgres/nonce_store.ts`](../src/postgres/nonce_store.ts)

---

## ADR-04: Strict Cryptographic Binding at Ingress Gateway (Issue #2 & #3)
- **Decision**: Ingress gateways authenticate customer Ed25519 signatures before validator dispatch and return the explicitly bound ledger record rather than the ledger tail.
- **Rationale**: Enforces defense-in-depth at network boundaries and guarantees that generated `PortableTrustProof` objects reflect the exact ingested commitment under concurrent multi-tenant loads.
- **Location**: [`src/runtime/gateway.ts`](../src/runtime/gateway.ts)

---

## ADR-05: Sentinel Policy Gate TOCTOU Defense (Issue #4)
- **Decision**: Implement atomic pre-approval re-verification of the basis checkpoint digest and finalized on-chain EVM anchor immediately before issuing `POLICY_APPROVED`.
- **Rationale**: Eliminates time-of-check to time-of-use race conditions if storage is corrupted or a blockchain reorg occurs mid-evaluation.
- **Location**: [`src/sentinel/policy_gate.ts`](../src/sentinel/policy_gate.ts)
