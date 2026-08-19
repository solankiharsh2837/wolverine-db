# WolverineDB // Portable Trust Proofs & Offline Verification

> **Source Code is Authoritative.**  
> This specification defines the format, generation, and zero-trust offline verification algorithm of `PortableTrustProof` objects in **WolverineDB v1.3.0**.

---

## 1. Concept of Portable Trust Proofs

A `PortableTrustProof` ([`src/trust_network/types.ts`](../src/trust_network/types.ts)) is a self-contained, cryptographically complete artifact proving that a specific database checkpoint or transaction commitment was validated and finalized by a Byzantine validator quorum.

### Key Capabilities:
- **Zero-Trust Independent Verification**: An external auditor, regulator, or insurance entity can verify database integrity without network access to the database or WolverineDB cluster.
- **Cross-Domain Portability**: Serialized into canonical JSON or binary for archival, legal evidence, or cross-chain bridging.

---

## 2. Data Structure

```ts
export interface PortableTrustProof {
  proofId: string;
  protocolVersion: number;
  commitment: TrustCommitment;
  certificate: QuorumCertificate;
  ledgerRecord: TrustLedgerRecord;
  validatorKeySet: Record<string, string>; // validatorId -> hex encoded public key
  generatedAtUs: bigint;
}
```

---

## 3. Offline Verification Algorithm

Implemented by `OfflineTrustProofVerifier.verifyPortableProof` in [`src/trust_network/proof.ts`](../src/trust_network/proof.ts):

```
                       PortableTrustProof
                               │
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
   1. Customer Signature   2. Quorum Signatures  3. Ledger Hash-Chain
   - Verify customer key   - Check threshold >= Q - Validate recordDigest
   - Recompute digest      - Verify each Ed25519  - Check commitmentId match
   - Ed25519 verify        - Check certDigest     - Check certDigest match
            │                  │                  │
            └──────────────────┼──────────────────┘
                               ▼
                    PROVED VALID (True/False)
```

**Step-by-Step Verification Invariants**:
1. **Customer Commitment Integrity**: Recomputes commitment digest and validates `commitment.customerSignature` against `commitment.customerPubkey`.
2. **Quorum Certificate Threshold**: Validates that `certificate.signatures.length >= certificate.quorumThreshold`.
3. **Validator Signatures**: For each participating validator, verifies its Ed25519 attestation signature against `validatorKeySet[validatorId]`.
4. **Ledger Record Binding**: Validates that `ledgerRecord.payload['commitmentId'] === commitment.commitmentId` and `ledgerRecord.payload['certificateDigestHex'] === certificate.certificateDigest.toString('hex')`.
5. **Ledger Hash-Chain**: Recomputes `ledgerRecord.recordDigest` and verifies consistency.
