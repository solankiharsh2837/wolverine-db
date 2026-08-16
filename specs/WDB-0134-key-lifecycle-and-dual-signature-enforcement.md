# WDB-0134: Key Lifecycle and Dual-Signature Enforcement

**Status**: Normative (Frozen)  
**Version**: 1.3.0  
**Domain**: BFT Hardening & Customer Key Rotation Protocol

---

## 1. Abstract

This specification defines the cryptographic preconditions for customer key rotation, preventing keypair mismatch errors and ensuring dual-signature verification prior to ledger state updates.

---

## 2. Invariants

1. **Keypair Derivation Consistency**: The rotation manager must cryptographically derive public keys from provided private keys:
   $$\text{PublicKey}_{\text{derived}} = \text{DerivePubkey}(\text{PrivateKey})$$
   If $\text{PublicKey}_{\text{derived}} \ne \text{PublicKey}_{\text{provided}}$, the rotation MUST fail closed with `UNAUTHORIZED_MUTATION`.
2. **Pre-Commit Dual Signature Verification**:
   - The rotation record MUST be signed by both the active old key and the incoming new key.
   - The rotation manager MUST verify $\text{Verify}(\text{OldPub}, \text{Payload}, \text{OldSig}) == \text{TRUE}$ and $\text{Verify}(\text{NewPub}, \text{Payload}, \text{NewSig}) == \text{TRUE}$ before appending the rotation record to the ledger.
