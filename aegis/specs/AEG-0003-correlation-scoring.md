# AEG-0003: Correlation & Evidence Lineage Scoring

Status: Normative Specification (v0.1 Frozen).

## Core Rule: Correlation Is Never Proof

AEGIS MUST NOT output binary attribution judgments. It MUST output structured `AttributionCandidate` objects with explainable confidence weights and direct evidence links.

## Scoring Category Breakdown

| Category | Weight Range | Description |
|---|---|---|
| `ARTIFACT_REUSE` | +25 | Identical binary hash, script reuse, cryptographic key reuse. |
| `INFRASTRUCTURE_COLOCATION` | +20 | Shared C2 server IP, SSL certificate fingerprint, domain registrant. |
| `HANDLE_SIMILARITY` | +15 | Matching alias, forum handle, PGP key ID. |
| `STYLOMETRIC_MATCH` | +12 | Writing style similarity, vocabulary, typo patterns. |
| `TEMPORAL_CORRELATION` | +10 | Synchronous activity windows, timezone alignment. |

## Evidence Lineage Requirement

Every score MUST contain an array of `EvidenceLineageItem`:

```typescript
interface EvidenceLineageItem {
  category: string;
  weight: number;
  evidenceId: string;
  sourceUri: string;
  rationale: string;
}
```
