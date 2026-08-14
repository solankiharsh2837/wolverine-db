# WRT-0004: WolverineDB Bridge & AEGIS Telemetry Stream

Status: Normative Specification (v0.1 Frozen).

## WolverineDB Verification Bridge

- When a `CRITICAL` or `SUSPICIOUS` behavioral incident occurs, Wolverine Runtime MUST query `WolverineDB.verify(scope)` to verify database state integrity.
- If WolverineDB reports `MERKLE_ROOT_MISMATCH` or `CHANGE_HASH_MISMATCH`, the Runtime MUST generate an incident and trigger a non-destructive recovery proposal.

## AEGIS Threat Exporter

- Exports tamper-evident JSON logs and OpenTelemetry spans to AEGIS Cyber Threat Intelligence platform.
- Schema aligns with AEGIS security event specification.
