# WDB-0034: Self-Healing Policy Gate Engine

Status: Normative Specification (v0.4 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification defines the deterministic Policy Gate that stands between Sentinel advisory intelligence and the cryptographic recovery execution engine.

## 2. Policy Evaluation Rules

The Policy Gate MUST evaluate all of the following deterministic rules before allowing an `AdvisoryRecoveryProposal` to proceed to the signature collection stage:

```text
                                ADVISORY PROPOSAL
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
                 [RULE EVALUATION]             [RULE EVALUATION]
                 • Basis Version Exists?       • Bounded Scope?
                 • External Anchor Valid?      • Hash Integrity Match?
                         │                             │
                         └──────────────┬──────────────┘
                                        ▼
                               [GATE EVALUATION]
                                        │
                       ┌────────────────┴────────────────┐
                       ▼                                 ▼
                 ALLOW_PROPOSAL                   REJECT_PROPOSAL
               (Proceed to Quorum)             (Fail-Closed Immediate)
```

### 2.1 Normative Invariants
1. **Verifiable Basis Invariant**: `targetBasisVersionId` MUST resolve to a committed version record in `wolverine_sys.versions` whose Merkle root matches `expectedMerkleRoot`.
2. **Anchor Agreement Invariant**: `sourceCheckpointId` MUST exist in configured external stores (`WDB-0011`) and verify against external blockchain anchors (`WDB-0022`).
3. **Strict Scope Bounding**: The proposal MUST ONLY restore records belonging to the registered `protectedScope`. Wildcard or unconstrained restoration requests MUST be rejected immediately.
4. **Non-Speculative Payload**: `proposedChangesHash` MUST equal the bit-for-bit SHA-256 hash of the canonical restoration payload.

If any invariant is violated, the Policy Gate MUST return `REJECT_PROPOSAL` with a structured `WolverineError` (`WDB5xx`).
