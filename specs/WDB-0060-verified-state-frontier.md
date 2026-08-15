# WDB-0060: Verified State Frontier Protocol

Status: Normative Specification (v0.6.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the **Verified State Frontier** in WolverineDB v0.6.0. The Verified State Frontier represents the maximum database commit sequence ($S_{\text{frontier}}$) that WolverineDB can authoritatively and mathematically prove to be valid, authorized, and uncorrupted, even when the live database engine or privileged DBA credentials have been compromised.

## 2. Invariant: The 7 Pillars of Frontier Verification

A database state at commit sequence $S$ is a member of the Verified State Frontier if and only if all 7 cryptographic criteria are strictly satisfied:

1. **Cryptographically Valid Basis Checkpoint**: The state originates from a verified checkpoint $C_{\text{base}}$ recorded in `wolverine_sys.checkpoints` whose Merkle root and hash chain head verify bit-for-bit (`WDB-0004`, `WDB-0012`).
2. **External Vault & Blockchain Proof**: The basis checkpoint $C_{\text{base}}$ is independently verified in external immutable WORM/S3 Object Lock storage (`WDB-0011`) and corroborated by external blockchain anchor consensus (`WDB-0021`, `WDB-0023`).
3. **Continuous Canonical Change Chain**: Every intermediate change record $R_i$ for $i \in (\text{commitSeq}(C_{\text{base}}), S]$ is linked via an unbroken SHA-256 hash chain:
   $$\text{previousHash}(R_{i}) = \text{computeChangeHash}(R_{i-1})$$
4. **Sequence Monotonicity**: Sequences are strictly contiguous without gaps, duplicate sequences, or out-of-order commits:
   $$\text{commitSeq}(R_i) = \text{commitSeq}(R_{i-1}) + 1$$
5. **Verified Execution Provenance**: Every change record $R_i$ contains authentic execution provenance linking it to a valid session, trace context, and non-compromised actor identity (`WDB-0013`, `WDB-0041`).
6. **Mandatory Authorization & Scope Conformance**: Every change record $R_i$ satisfies registered authorization policy rules, maintenance window constraints, and required ticket IDs (`WDB-0006`, `WDB-0031`).
7. **Deterministic State Merkle Convergence**: Forward replay of authorized mutations against $C_{\text{base}}$ reconstructs a state whose recomputed Merkle root equals the deterministic hash of all live row versions.

## 3. Frontier Calculation Algorithm

```text
findLatestVerifiedCheckpoint()
        ↓
verifyCheckpointAgainstExternalEvidence()
        ↓
loadCheckpointState()
        ↓
loadCanonicalChangesAfterCheckpoint()
        ↓
verifyHashChain()
        ↓
verifySequenceContinuity()
        ↓
verifyProvenance()
        ↓
verifyAuthorization()
        ↓
replayAuthorizedChange()
        ↓
STOP at first invalid / unauthorized / tampered mutation
        ↓
recomputeMerkleRoot()
        ↓
verifyReconstructedState()
```

The frontier terminates immediately prior to the first mutation that fails any verification criterion.
