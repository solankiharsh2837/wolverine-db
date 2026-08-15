# WDB-0087: Tenant Security and Isolation Model

Status: Normative Specification (v0.8.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details the multi-tenant isolation model, domain boundaries, and zero-knowledge guarantees of the Wolverine Trust Network.

## 2. Cryptographic Tenant Isolation

1. **Independent Key Bindings**: Each tenant $T_k$ is provisioned with unique Ed25519 signing keys. A commitment is cryptographically invalid unless signed by $T_k$'s registered public key.
2. **Domain Separation**: All commitment and attestation hashing incorporates `tenantId` in the canonical preimage string. A commitment created by Tenant $A$ cannot be ingested or verified under Tenant $B$'s account.
3. **Zero Plaintext Leakage**:
   - No SQL query strings
   - No table row contents
   - No customer schema details
   - Only 32-byte SHA-256 Merkle root commitments are transmitted.
