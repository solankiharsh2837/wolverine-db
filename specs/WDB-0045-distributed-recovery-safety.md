# WDB-0045: Distributed Recovery Safety & Plane Isolation

Status: Normative Specification (v0.5 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details the safety guarantees isolating the recovery plane from the application and intelligence planes, preventing adversarial manipulation of the recovery mechanism itself.

## 2. Invariant: Recovery Plane Isolation

```text
[APPLICATION / RUNTIME PLANE]     [INTELLIGENCE PLANE: AEGIS]
(Compromised Web App / Attacker)  (Threat Intelligence / Correlation)
             │                                   │
             ▼                                   ▼
┌─────────────────────────────────────────────────────────────┐
│                 SENTINEL ADVISORY LAYER                     │
│                  (Proposal Formulation)                     │
└─────────────────────────────┬───────────────────────────────┘
                              │ PROPOSAL ONLY
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 CRYPTOGRAPHIC POLICY GATE                   │
│          • Validates External Anchor Proof                  │
│          • Validates Exact Scope Boundaries                 │
│          • Requires Independent Multi-Party Ed25519 Quorum  │
└─────────────────────────────┬───────────────────────────────┘
                              │ VERIFIED & SIGNED
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 ISOLATED RECOVERY ENGINE                    │
│             (Atomic Forward-Additive Restore)               │
└─────────────────────────────────────────────────────────────┘
```

## 3. Defense Against Recovery Hijacking

1. **No External Execution Trigger**: Neither application-plane clients nor AEGIS analytics can invoke `executeRecoveryProposal` directly.
2. **Anchor-Binding Constraint**: A recovery proposal CANNOT restore records to an arbitrary state; the target state MUST match an independently verifiable historical Checkpoint Digest anchored in external storage (`WDB-0011`) or public blockchain registries (`WDB-0021`).
3. **Multi-Party Separation of Duties**: The entity submitting the advisory proposal (`requesterId`) is strictly forbidden from signing the approval envelope (`WDB-0006`).
