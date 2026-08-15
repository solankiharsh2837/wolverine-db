# WDB-0032: Anomaly Event & Incident Protocol

Status: Normative Specification (v0.4 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification defines the canonical Anomaly Incident schema produced by Sentinel when suspicious activity, state divergence, or out-of-baseline mutations are detected.

## 2. Canonical Anomaly Event Schema

An Anomaly Event MUST contain the following structured fields:

```typescript
export type AnomalySeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type AnomalyClassification =
  | 'SUSPECTED_UNAUTHORIZED_MUTATION'
  | 'OUT_OF_WINDOW_DBA_ACTIVITY'
  | 'SCOPE_EXPANSION_VIOLATION'
  | 'BULK_ROLE_OR_BALANCE_MODIFICATION'
  | 'MISSING_PROVENANCE_TICKET'
  | 'CROSS_DOMAIN_STATE_DIVERGENCE'
  | 'BASELINE_INTEGRITY_TAMPERED';

export interface AnomalyIncident {
  incidentId: string; // UUID v4
  timestampUs: bigint;
  actorId: string;
  serviceId: string;
  affectedScope: string;
  classification: AnomalyClassification;
  severity: AnomalySeverity;
  anomalyScore: number; // 0..100
  affectedRecordIds: string[]; // Primary key hex strings
  observedMutationCount: number;
  evidenceRefs: {
    checkpointId?: string;
    localMerkleRootHex?: string;
    expectedAnchorDigestHex?: string;
    baselineHashHex?: string;
    rawLogSnippet?: string;
  };
  narrativeExplanation: string;
}
```

## 3. Immutability & Indexing

- All emitted `AnomalyIncident` records MUST be committed append-only into `wolverine_sys.incidents` (`RecordType 5`).
- The `incidentId` serves as the cryptographic anchor for subsequent recovery proposals (`WDB-0033`).
