# WDB-0100: Wolverine Production Trust Service Architecture

Status: Normative Specification (v1.0.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification defines the production **Wolverine Trust Plane** for WolverineDB v1.0.0. It enforces total architectural separation between the **Wolverine Cloud Control Plane** (Gateway, Billing, Tenant Management) and the **Wolverine Trust Plane** (Validators, BFT Consensus, Merkle State Root, Persistent Ledger).

## 2. Zero-Trust Architecture Invariant

> **The Control Plane and Gateway do NOT define cryptographic truth.**
> **The customer owns the data. Wolverine Trust Network owns the independent evidence of what state existed and when.**

```text
                 ┌────────────────────────────────┐
                 │    WOLVERINE CONTROL PLANE     │
                 │  - Billing / Tenant Quota      │
                 │  - API Gateway / Routing       │ (UNTRUSTED TRANSPORT)
                 └───────────────┬────────────────┘
                                 │ (Untrusted RPC Dispatch)
                                 ▼
        ┌─────────────────────────────────────────────────┐
        │              WOLVERINE TRUST PLANE              │
        │                                                 │
        │  ┌───────────────┐           ┌───────────────┐  │
        │  │ Validator #01 │   ...     │ Validator #05 │  │
        │  │ (PrivKey HSM) │           │ (PrivKey HSM) │  │
        │  └───────┬───────┘           └───────┬───────┘  │
        │          │ (Signed Attestations)     │          │
        │          └─────────────┬─────────────┘          │
        │                        ▼                        │
        │            BFT CONSENSUS ENGINE (M-of-N)        │
        │                        │                        │
        │                        ▼                        │
        │           PERSISTENT TRUST LEDGER &             │
        │            INCREMENTAL MERKLE ROOT              │
        └────────────────────────┬────────────────────────┘
                                 ▼
                    PORTABLE TRUST PROOF (OFFLINE)
```

## 3. Physical Process Independence & Threat Boundary

- The Gateway **MUST NOT** possess signing keys for any validator or tenant.
- A compromise of the Gateway **MUST NOT** enable the adversary to alter previously finalized ledger records, forge validator signatures, or issue fraudulent finality certificates.
- All proof verification **MUST** be executable completely offline without contacting the Gateway or Control Plane.
