# WDB-0070: Continuous Verified State Reconstruction Protocol

Status: Normative Specification (v0.7.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the **Continuous Verified State Reconstruction Protocol** in WolverineDB v0.7.0. Unlike v0.6.0 (which terminates reconstruction at the first invalid mutation boundary), v0.7.0 reconstructs the **Maximum Reconstructable State** by evaluating both History Integrity and Mutation Authenticity across all post-checkpoint transactions, selectively preserving non-compromised, independently provable mutations even when interleaved with malicious or corrupt actions.

## 2. Fundamental Architectural Distinction

WolverineDB v0.7.0 strictly separates the state horizon into two distinct cryptographic entities:

1. **Contiguous Verified Frontier (`CONTIGUOUS_VERIFIED_FRONTIER`)**:
   The highest commit sequence ($S_{\text{contig}}$) up to which the canonical change hash chain, sequence numbers, and authorization envelopes are unbroken and strictly contiguous.
2. **Maximum Reconstructable State (`MAXIMUM_RECONSTRUCTABLE_STATE`)**:
   The database state ($S_{\text{max\_recon}}$) materialized by starting from a trusted external checkpoint ($C_{\text{base}}$) and forward-replaying all mutations that possess a valid, independently verifiable reconstruction proof and whose causal data dependencies are completely satisfied.

The system **MUST NOT** conflate the contiguous frontier with the maximum reconstructable state.

## 3. The Dual-Dimension Verification Model

Every mutation candidate $M$ is evaluated across two orthogonal dimensions:

```text
                                MUTATION EVALUATION
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
         HISTORY INTEGRITY                              MUTATION AUTHENTICITY
   • Canonical Predecessor Hash                   • Cryptographic Auth Envelope
   • Commit Sequence Continuity                   • Uncompromised Actor Identity
   • Checkpoint Lineage                           • Execution Trace Provenance
   • Checkpoint Hash Binding                      • Scope & Window Conformance
                                                  • External Trust Commitment
```

1. **History Integrity Failure**: Indicates that historical sequence ordering is fractured or unanchored. Subsequent mutations cannot rely on implicit sequence order and MUST provide independent cryptographic proof.
2. **Mutation Authenticity Failure**: Indicates that an individual mutation was forged, executed by a compromised actor, out-of-scope, or unauthorized. That specific mutation is marked `EXCLUDED`.
