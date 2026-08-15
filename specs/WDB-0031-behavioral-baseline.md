# WDB-0031: Behavioral Baselining & Baseline Integrity Commitments

Status: Normative Specification (v0.4 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the statistical behavioral baselining model used by WolverineDB Sentinel to identify out-of-character actor mutations, abnormal execution windows, unauthorized scope expansions, and high-frequency bulk operations.

## 2. Actor Baseline Profile

Each registered actor or service identity MUST have an accumulated statistical baseline profile tracking:

```typescript
export interface ActorBaselineProfile {
  actorId: string;
  allowedScopes: string[]; // e.g. ["public.users", "public.accounts"]
  typicalOperations: number[]; // 1=INSERT, 2=UPDATE, 3=DELETE
  maintenanceWindows: Array<{
    startUtcHour: number; // 0..23
    endUtcHour: number;   // 0..23
    daysOfWeek: number[]; // 0=Sunday..6=Saturday
  }>;
  maxMutationsPerMinute: number;
  averageBatchSize: number;
  requiresTicketProvenance: boolean;
  baselineHash: Buffer; // 32 bytes SHA-256 integrity commitment
}
```

## 3. Baseline Integrity Protection

1. **Commitment Hashing**: The baseline profile MUST be cryptographically committed using domain-separated SHA-256:
   ```
   BaselineHash = SHA-256("WDB:BASELINE:v1:" || actor_id || canonical_profile_bytes)
   ```
2. **Tampering Detection**: If an attacker directly modifies baseline records in database tables (attempting to whitelist unauthorized activity), the Sentinel engine MUST detect hash divergence and flag `BASELINE_INTEGRITY_TAMPERED`.

## 4. Anomaly Scoring Metrics

The engine computes an anomaly score $S \in [0, 100]$ based on weighted feature evaluations:
- **Out-of-Window Mutation**: Actor modifying tables outside registered maintenance windows (+35).
- **Scope Violation**: Actor modifying tables outside authorized scope list (+40).
- **Missing Provenance Ticket**: Mutation missing required authorization or ticket ID (+25).
- **Rate Spike**: Mutation frequency exceeding $3\times$ baseline velocity (+20).

An anomaly score $\ge 70$ triggers a `CRITICAL` severity incident.
