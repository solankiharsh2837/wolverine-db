# WDB-0035: Autonomous Recovery Safety Model

Status: Normative Specification (v0.4 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details the operational safety modes of WolverineDB self-healing and establishes the strict default of `APPROVAL-GATED` execution.

## 2. Operational Safety Modes

A WolverineDB deployment MUST operate in one of three explicit safety modes:

```
[Mode 1: ADVISORY]
Incident Detected ──► Sentinel Analysis ──► Incident Report Logged
(No proposal generated)

[Mode 2: PROPOSE]
Incident Detected ──► Sentinel Analysis ──► Recovery Proposal Formulated ──► Human Review Required
(No signature collection)

[Mode 3: APPROVAL-GATED EXECUTE] (DEFAULT)
Incident Detected ──► Proposal ──► Policy Gate ──► Ed25519 Quorum Signatures ──► Atomic Recovery Execution ──► Re-Anchor
```

## 3. Safety Invariants

1. **Default Mode**: Implementations MUST default to `APPROVAL_GATED_EXECUTE`.
2. **No Autonomous Rollbacks**: WolverineDB MUST NEVER execute unapproved or automatic rollbacks based solely on AI or heuristic advisory outputs.
3. **Audit Provenance**: All executed recoveries MUST emit complete recovery provenance lineages (`WDB-0013`) and post-recovery anchor commitments (`WDB-0020`).
