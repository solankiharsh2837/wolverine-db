# WDB-0042: Incident Correlation Graph & Evidence Binding

Status: Normative Specification (v0.5 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the immutable directed acyclic graph (DAG) structure that links multi-layer observations into an auditable forensic correlation graph.

## 2. Graph Topology

```text
               Actor Node (e.g. dba_service_07)
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

## 3. Node & Edge Definitions

### 3.1 Graph Node
```typescript
export type CorrelationNodeType =
  | 'ACTOR'
  | 'RUNTIME_CONTEXT'
  | 'DATABASE_TX'
  | 'AFFECTED_RECORD'
  | 'THREAT_INTEL'
  | 'EXTERNAL_ANCHOR';

export interface CorrelationGraphNode {
  nodeId: string;
  nodeType: CorrelationNodeType;
  label: string;
  attributes: Record<string, unknown>;
  evidenceEventId?: string;
}
```

### 3.2 Graph Edge
```typescript
export interface CorrelationGraphEdge {
  sourceNodeId: string;
  targetNodeId: string;
  relationship:
    | 'INITIATED_BY'
    | 'EXECUTED_IN_CONTEXT'
    | 'MODIFIED_RECORD'
    | 'CORRELATED_WITH'
    | 'PROVEN_BY_ANCHOR';
  weight: number; // 0.0 .. 1.0
  evidenceDigest: Buffer; // 32 bytes SHA-256
}
```

## 4. Immutability & Forensic Integrity

- Once an incident is transitioned to `EVALUATED`, its correlation graph is frozen.
- Graph serialization MUST be canonicalized under RFC 8785, and the graph root digest attached to the `AnomalyIncident` record.
