# WDB-0054: Evidence-Preserving Node Quarantine Protocol

Status: Normative Specification (v0.6 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification defines the deterministic quarantine protocol that isolates compromised or divergent nodes without destroying pre-quarantine forensic evidence.

## 2. Quarantine Invariant: Non-Destructive Isolation

Quarantine MUST isolate the node from:
- Submitting telemetry into the security fabric.
- Participating in federated checkpoint consensus (`WDB-0053`).
- Signing recovery approval envelopes (`WDB-0055`).

Quarantine MUST NOT purge:
- Historical change records emitted prior to quarantine.
- The node's last valid checkpoint and event hash.
- Forensic logs capturing the specific triggering failure.

## 3. Quarantine Record Schema

```typescript
export interface NodeQuarantineRecord {
  nodeId: string;
  quarantineEpochUs: bigint;
  reason:
    | 'INVALID_EVENT_SIGNATURE'
    | 'DIVERGENT_CHECKPOINT_ATTESTATION'
    | 'IMPOSSIBLE_EVENT_SEQUENCE'
    | 'ANOMALOUS_RECOVERY_ATTEMPT'
    | 'ADMINISTRATIVE_ISOLATION';
  lastValidEventSequence: bigint;
  lastValidEventHash: Buffer;
  lastValidCheckpointId?: string;
  triggeringEvidence: Record<string, unknown>;
  quarantineAuthority: string;
}
```
