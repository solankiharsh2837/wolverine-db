# WRT-0003: Incident & Anomaly Engine

Status: Normative Specification (v0.1 Frozen).

## Event Severity Classification

- `NORMAL`: Standard execution within policy bounds.
- `SUSPICIOUS`: Execution missing ticket/reason, unusual query pattern, or unauthenticated role elevation attempt.
- `CRITICAL`: Failed authorization, state divergence detected by WolverineDB, or direct un-instrumented DB query.

## Incident Report Grammar

```typescript
interface IncidentReport {
  incidentId: string; // UUID v4
  severity: 'NORMAL' | 'SUSPICIOUS' | 'CRITICAL';
  eventType: string; // e.g. "UNAUTHORIZED_DB_WRITE", "MISSING_PROVENANCE"
  timestampUs: bigint;
  context: WolverineContextSnapshot;
  executionStackTrace?: string;
  details: Record<string, unknown>;
}
```
