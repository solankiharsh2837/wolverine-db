# WDB-0030: Sentinel Architecture & Trust Plane Separation

Status: Normative Specification (v0.4 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification defines the architectural separation of trust planes between the **Deterministic Cryptographic Core** (WolverineDB v0.1–v0.3) and the **Sentinel Intelligence & Advisory Plane** (v0.4).

## 2. Invariant: Separation of Proposal from Authority

1. **Advisory Authority Only**: The Sentinel Intelligence Plane (comprising anomaly detection, statistical baselines, heuristic rules, and AI/LLM models) **MUST NOT** possess execution authority, write access to protected tables, or direct cryptographic signing privileges.
2. **Deterministic Cryptographic Enforcement**: All recovery executions **MUST** be gated through the deterministic Policy Gate (`WDB-0034`) and require valid multi-party Ed25519 signatures (`WDB-0006`) binding to verified historical checkpoints (`WDB-0012`, `WDB-0022`).

```text
                         WOLVERINE v0.4
                              │
                 ┌────────────┴────────────┐
                 │                         │
          DETERMINISTIC CORE          SENTINEL PLANE
                 │                         │
        WolverineDB v0.3              AI / ML / Rules
                 │                         │
                 │                    anomaly detection
                 │                    behavioral analysis
                 │                    incident correlation
                 │                    recovery proposal
                 │                         │
                 └────────────┬────────────┘
                              │
                       PROPOSAL ONLY
                              │
                              ▼
                    DETERMINISTIC POLICY GATE
                              │
                     Ed25519 Quorum Approvals
                              │
                              ▼
                       RECOVERY ENGINE
                              │
                              ▼
                    POST-RECOVERY VERIFY
                              │
                              ▼
                    NEW EXTERNAL ANCHOR
```

## 3. Plane Responsibilities

### 3.1 Deterministic Security Core
- Captures change records, calculates RFC 8785 JSON canonical representations, advances SHA-256 hash chains, builds state Merkle trees, verifies external object vaults (S3/WORM), and queries blockchain anchors.

### 3.2 Sentinel Intelligence Plane
- Ingests operational telemetry and change streams.
- Computes behavioral baselines for actors, tables, access windows, and mutation rates.
- Detects anomalous deviations and generates structured Anomaly Events (`WDB-0032`).
- Formulates non-destructive Recovery Proposals (`WDB-0033`) with explicit confidence scores and explanations.

### 3.3 Deterministic Policy Gate
- Evaluates recovery proposals against mathematical criteria: boundary checks, historical version existence, external anchor agreement, and quorum thresholds.
- Rejects invalid, speculative, or unanchored proposals immediately.
