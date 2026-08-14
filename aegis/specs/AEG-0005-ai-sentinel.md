# AEG-0005: Advisory AI Sentinel Specification

Status: Normative Specification (v0.1 Frozen).

## Boundary Statement

The AI Sentinel layer generates natural-language summaries, investigative hypotheses, and recommended next steps based strictly on deterministic evidence lineage items.

It MUST NOT:
- Make autonomous execution or destructive actions.
- Modify evidence lineage weights directly.
- Declare definitive guilt.

```typescript
interface SentinelHypothesisReport {
  hypothesisId: string;
  candidateId: string;
  summaryText: string;
  recommendedInvestigativeSteps: string[];
  evidenceIds: string[];
}
```
