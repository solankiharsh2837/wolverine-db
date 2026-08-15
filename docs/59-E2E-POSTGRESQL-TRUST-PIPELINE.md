# End-to-End PostgreSQL Trust Pipeline

This guide outlines the production deployment topology for attaching WolverineDB to an existing PostgreSQL cluster.

```text
[PostgreSQL Primary] ──(Logical Replication / CDC)──> [Wolverine Agent]
                                                               │
                                                       (HTTPS / Commitments)
                                                               │
                                                               ▼
                                                      [Trust Gateway API]
                                                               │
                                                      [Validator Cluster]
                                                               │
                                                      [Ledger Replicas]
```

## Failure Recovery Lifecycle
- **Attacker DBA Intrusion**: Malicious SQL update executed directly against live database.
- **Divergence Detected**: Sentinel and Hash Chain flag state fracture.
- **Basis Verification**: Checkpoint basis verified against Wolverine Trust Network in Trust Time.
- **Selective Reconstruction**: Safe mutations preserved; compromised transactions excluded.
- **State Restored**: Database synchronized and re-anchored at next Trust Sequence.
