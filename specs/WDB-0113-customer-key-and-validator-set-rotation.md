# WDB-0113: Customer Key and Validator Set Rotation Protocol

Status: Normative Specification (v1.1.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Customer Signing Key Rotation

- A customer can rotate their Ed25519 signing key ($K_{\text{old}} \to K_{\text{new}}$) by issuing a cryptographically linked `KEY_ROTATION` commitment.
- The commitment MUST contain:
  1. `previousKeyDigest`: SHA-256 hash of $K_{\text{old}}$.
  2. `newKeyDigest`: SHA-256 hash of $K_{\text{new}}$.
  3. `dualSignature`: Signature produced by $K_{\text{old}}$ and signature produced by $K_{\text{new}}$.
- Once finalized in the Trust Ledger, subsequent database commitments MUST be signed by $K_{\text{new}}$.

## 2. Validator Set Rotation

- When validators are added, removed, or keys rotated:
  1. A `VALIDATOR_SET_CHANGE` ledger record is submitted with $M$-of-$N$ threshold approval from the current validator set.
  2. A new `validatorSetId` is created with updated public key mappings.
