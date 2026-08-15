# Portable Trust Proofs & Standalone Offline Verification

A **Portable Trust Proof** is a self-contained cryptographic audit package.

## Offline Verification Checklist
Any independent auditor can run:
```bash
wdb trust proof verify proof.json
```
The verifier performs offline checks:
1. Validates the customer Ed25519 signature over the commitment.
2. Validates $M$-of-$N$ validator Ed25519 signatures over the commitment digest.
3. Checks ledger predecessor continuity and record digests.
4. Verifies the proof digest without contacting any network endpoints.
