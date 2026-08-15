# WDB-0041: Cross-Layer Security Event Protocol

Status: Normative Specification (v0.5 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification establishes the common security event envelope normalizing heterogeneous events across WolverineDB, Wolverine Runtime, AEGIS, and Sentinel.

## 2. Common Security Event Envelope Schema

All layers MUST format security telemetry into the canonical `SecurityEventEnvelope`:

```typescript
export type SecurityPlane = 'DATABASE' | 'RUNTIME' | 'AEGIS_INTEL' | 'SENTINEL' | 'RECOVERY';

export type SecurityEventType =
  | 'DB_MERKLE_DIVERGENCE'
  | 'DB_HASH_CHAIN_TAMPERED'
  | 'DB_UNAUTHORIZED_MUTATION'
  | 'RUNTIME_PRIVILEGE_ESCALATION'
  | 'RUNTIME_UNFAMILIAR_SERVICE'
  | 'RUNTIME_SESSION_HIJACK'
  | 'AEGIS_THREAT_CORRELATION'
  | 'AEGIS_INFRASTRUCTURE_ALERT'
  | 'SENTINEL_ANOMALY_TRIGGER'
  | 'RECOVERY_EXECUTED';

export interface SecurityEventEnvelope {
  eventId: string; // UUID v4
  plane: SecurityPlane;
  eventType: SecurityEventType;
  timestampUs: bigint;
  actorId: string;
  serviceId: string;
  traceId?: string;
  scope: string; // e.g. "public.users"
  payload: Record<string, unknown>;
  evidenceHash: Buffer; // 32 bytes SHA-256 over canonicalized payload
}
```

## 3. Evidence Commitment Invariant

The `evidenceHash` MUST be computed using domain-separated SHA-256 over the RFC 8785 canonical JSON representation of `payload`:

```
EvidenceHash = SHA-256("WDB:EVENT_EVIDENCE:v1:" || RFC8785_Canonicalize(payload))
```
This guarantees that event evidence cannot be modified retroactively once received by the security fabric.
