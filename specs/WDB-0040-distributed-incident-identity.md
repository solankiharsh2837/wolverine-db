# WDB-0040: Distributed Incident Identity

Status: Normative Specification (v0.5 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the globally unique, cryptographically bound incident identity format across distributed defensive systems (WolverineDB, Wolverine Runtime, AEGIS, and Wolverine Sentinel).

## 2. Canonical Incident Identifier Format

A distributed incident identifier MUST be formatted as a deterministic URI string:

```text
inc:<epoch_day>:<origin_plane>:<deterministic_digest_hex_16>
```

Example: `inc:20260815:wolverine_db:7f3a9b2c8e14d05a`

### 2.1 Identifier Computation
The 16-byte suffix is computed via SHA-256 over canonical incident genesis attributes:

```
IncidentGenesisDigest = SHA-256(
    "WDB:INCIDENT_ID:v1:" ||
    origin_plane_bytes (UTF-8) ||
    root_event_id (16 bytes UUID) ||
    timestamp_us (8 bytes BE I64) ||
    affected_scope_bytes (UTF-8)
)
```

## 3. Incident Lifecycle States

A distributed incident tracks through the following discrete lifecycle states:
1. `DETECTED`: Initial single-layer anomaly or integrity failure observed.
2. `CORRELATING`: Cross-layer events from DB, Runtime, and AEGIS are being aggregated into the Incident Correlation Graph (`WDB-0042`).
3. `EVALUATED`: Multi-factor risk engine has scored the incident (`WDB-0043`).
4. `PROPOSAL_PENDING`: Sentinel Advisor has formulated a recovery proposal awaiting policy evaluation (`WDB-0033`).
5. `RECOVERY_STAGED`: Policy Gate has approved the proposal; Ed25519 quorum signing in progress (`WDB-0006`).
6. `RESOLVED_RECOVERED`: Atomic recovery executed, verified, and re-anchored (`WDB-0013`).
7. `DISMISSED`: Investigated and marked false positive with forensic audit trail.
