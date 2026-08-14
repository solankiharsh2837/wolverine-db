# AEG-0001: Evidence Record Schema & Immutability

Status: Normative Specification (v0.1 Frozen).

## Overview

AEGIS normalizes all harvested payloads into immutable `EvidenceRecord` objects.

## Schema Definition

```typescript
interface EvidenceRecord {
  evidenceId: string; // UUID v4 (16 bytes)
  sourceType: 'OSINT' | 'DARKWEB' | 'TELEMETRY' | 'LAB_SYNTHETIC';
  sourceUri: string;
  collectedAtUs: bigint;
  payloadHash: Buffer; // SHA-256 (32 bytes)
  rawPayload: string; // UTF-8 JSON / string payload
  metadata: Record<string, unknown>;
  wolverineStateHash?: Buffer; // Optional WolverineDB state commitment
}
```

## Immutability Invariants

1. `payloadHash` MUST equal `SHA256(rawPayload)`.
2. Once created, `EvidenceRecord` MUST NOT be mutated. Any modification creates a new `EvidenceRecord` referencing the original via `parentEvidenceId`.
