# WDB-0033: Advisory Recovery Proposal Protocol

Status: Normative Specification (v0.4 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details the formal protocol for formulating structured, advisory recovery proposals generated in response to detected incidents.

## 2. Invariant: Advisory Nature & Zero Execution Authority

1. A Recovery Proposal represents an **advisory request**, NOT an execution instruction.
2. The proposal generator (whether heuristic rule or AI model) MUST set `decisionAuthority: 'NONE'`.
3. Generating a proposal MUST be strictly non-destructive and MUST NOT alter live tables.

## 3. Proposal Payload Schema

```typescript
export interface AdvisoryRecoveryProposal {
  proposalId: string; // UUID v4
  incidentId: string;
  protectedScope: string;
  targetBasisVersionId: string; // Version ID of authentic pre-incident state
  sourceCheckpointId: string;   // Historical checkpoint used as reference
  expectedMerkleRoot: Buffer;   // 32 bytes SHA-256
  expectedAnchorDigest: Buffer; // 32 bytes SHA-256
  affectedRecords: Array<{
    tableName: string;
    primaryKeyHex: string;
    fieldName: string;
    compromisedValue: unknown;
    restoredValue: unknown;
  }>;
  proposedChangesHash: Buffer; // 32 bytes SHA-256 of canonical field restorations
  confidenceScore: number;     // 0..100
  riskAssessment: 'LOW' | 'MEDIUM' | 'HIGH';
  rationale: string;
  decisionAuthority: 'NONE';
  status: 'PENDING_POLICY_EVALUATION' | 'POLICY_APPROVED' | 'POLICY_REJECTED';
}
```

## 4. Proposed Changes Hash Computation

The `proposedChangesHash` binds the exact restorative actions:
```
ProposedChangesHash = SHA-256(RFC8785_Canonicalize(affectedRecords))
```
This 32-byte digest is the exact payload signed by authorized Ed25519 approvers under `WDB-0006`.
