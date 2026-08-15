# Cross-Layer Incident Correlation

In WolverineDB v0.5, security events are correlated across three orthogonal observation planes:

1. **Database Layer (WolverineDB)**: Captures state-level Merkle root mismatches, hash chain divergences, and out-of-band table mutations.
2. **Runtime Layer (Wolverine Runtime)**: Captures execution-level provenance, unfamiliar service identities, request traces, and privilege escalation attempts.
3. **Intelligence Layer (AEGIS)**: Captures infrastructure threat intelligence, cross-service attacker campaign correlation, and compromised credential feeds.

## Correlation Graph

```text
               Actor (dba_service_07)
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
Runtime Session Node          Threat Intel Node
(Privilege Escalation)        (AEGIS Campaign Ref)
        │                           │
        ▼                           │
Database Transaction Node           │
(37 UPDATEs on public.users)        │
        │                           │
        ▼                           ▼
Affected Record Nodes ◄─────── Correlated Incident
(Primary Keys 1..17)
```

The unified Correlation Graph ensures that isolated, low-confidence signals in separate subsystems are correlated into a high-confidence, actionable incident.
