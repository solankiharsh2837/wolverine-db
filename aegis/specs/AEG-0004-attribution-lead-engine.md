# AEG-0004: Attribution Lead Engine & Dual Execution Planes

Status: Normative Specification (v0.1 Frozen).

## Execution Planes

1. **CONTROLLED_LAB_PLANE**: Evaluates synthetic threat datasets against known ground-truth actor IDs.
2. **REAL_WORLD_PLANE**: Evaluates OSINT, public threat feeds, and dark web observations.

## Candidate Output Format

```typescript
interface AttributionCandidate {
  candidateId: string; // UUID v4
  actorProfile: ActorCandidateProfile;
  totalConfidenceScore: number; // 0 to 100
  evidenceLineage: EvidenceLineageItem[];
  executionPlane: 'CONTROLLED_LAB_PLANE' | 'REAL_WORLD_PLANE';
  groundTruthMatch?: boolean; // Only present in CONTROLLED_LAB_PLANE
}
```
