# WDB-0052: Node Trust Lifecycle & Attestation

Status: Normative Specification (v0.6 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details the trust lifecycle states and transition criteria for nodes participating in the federation.

## 2. Node Trust Lifecycle States

```text
       [REGISTRATION]
             │
             ▼
        ┌─────────┐
        │ TRUSTED │ ◄─────────────────────┐
        └────┬────┘                       │
             │                            │
      anomalous behavior          admin re-attestation
             │                            │
             ▼                            │
        ┌──────────┐                      │
        │ DEGRADED │ ─────────────────────┤
        └────┬─────┘                      │
             │                            │
      signature failure /                 │
      divergent checkpoint                │
             │                            │
             ▼                            │
      ┌─────────────┐                     │
      │ QUARANTINED │ ────────────────────┘
      └──────┬──────┘
             │
      key compromise
             │
             ▼
        ┌─────────┐
        │ REVOKED │ (TERMINAL)
        └─────────┘
```

1. **`TRUSTED`**: Normal operating state; node participates in consensus and recovery quorum.
2. **`DEGRADED`**: High telemetry latency or sporadic dropped heartbeats; voting weight reduced.
3. **`QUARANTINED`**: Active divergence, signature failure, or impossible sequence detected; isolated from consensus, but forensic evidence is preserved.
4. **`REVOKED`**: Terminal state; node identity key permanently blacklisted.
