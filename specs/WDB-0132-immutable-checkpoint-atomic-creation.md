# WDB-0132: Immutable Checkpoint Atomic Creation

**Status**: Normative (Frozen)  
**Version**: 1.3.0  
**Domain**: WORM / Local Checkpoint Storage Invariance

---

## 1. Abstract

This specification defines the atomic creation invariants for local and WORM checkpoint stores, eliminating Time-of-Check to Time-of-Use (TOCTOU) race conditions during concurrent checkpoint creation.

---

## 2. Invariants

1. **Atomic Creation**: Checkpoints must be written to disk using atomic exclusive creation semantics (POSIX `O_CREAT | O_EXCL` / Node.js `flag: 'wx'`).
2. **Single State Transition**: A checkpoint identifier may transition from `ABSENT` $\to$ `PRESENT` at most once.
3. **Idempotence on Collision**: If a write fails due to `EEXIST` (already present), the store must read the existing record and verify cryptographic digest equality:
   - If $\text{Digest}(\text{Existing}) == \text{Digest}(\text{Incoming})$: Return success (idempotent duplicate).
   - If $\text{Digest}(\text{Existing}) \ne \text{Digest}(\text{Incoming})$: Reject with `ANCHOR_VERIFICATION_FAILED`.
