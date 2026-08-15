# Threat Model: Compromised Wolverine Gateway

This document analyzes the scenario where an attacker gains complete control over the Wolverine Cloud API Gateway.

## Attack Vectors Evaluated
1. **Malicious Digest Injection**: Gateway attempts to replace Checkpoint 1842's digest with attacker digest.
   - *Defense*: All 5 validators observe sequence non-monotonicity or hash mismatch against customer signature; attestations are refused. Quorum reached = 0/4.
2. **Attestation Forgery**: Gateway attempts to synthesize validator signatures.
   - *Defense*: Consensus engine and offline verifiers validate Ed25519 signatures against validator public keys.
3. **Equivocation / Double Finalization**: Gateway attempts to create alternate fork.
   - *Defense*: Byzantine validators generate slashable equivocation evidence.
