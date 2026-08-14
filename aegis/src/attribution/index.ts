import crypto from 'node:crypto';
import { ActorCandidateProfile } from '../extraction/index.js';
import { CorrelationPolicy, DEFAULT_CORRELATION_POLICY } from '../policy/index.js';

export type FactorCategory =
  | 'ARTIFACT_REUSE'
  | 'INFRASTRUCTURE_COLOCATION'
  | 'HANDLE_SIMILARITY'
  | 'STYLOMETRIC_MATCH'
  | 'TEMPORAL_CORRELATION';

export interface RawObservationFactor {
  category: FactorCategory;
  factorKey: string; // Unique key to prevent double counting (e.g. "hash:e3b0...", "ip:198.51...", "handle:nocturne")
  evidenceId: string;
  sourceUri: string;
  rationale: string;
}

export interface AggregatedFactor {
  category: FactorCategory;
  factorKey: string;
  weight: number;
  rationale: string;
  supportingEvidenceIds: string[];
  sourceUris: string[];
}

export type AttributionCandidate =
  | {
      executionPlane: 'CONTROLLED_LAB_PLANE';
      candidateId: string;
      actorProfile: ActorCandidateProfile;
      investigativeCorrelationScore: number;
      aggregatedFactors: AggregatedFactor[];
      groundTruthMatch: boolean;
    }
  | {
      executionPlane: 'REAL_WORLD_PLANE';
      candidateId: string;
      actorProfile: ActorCandidateProfile;
      investigativeCorrelationScore: number;
      aggregatedFactors: AggregatedFactor[];
      groundTruthMatch?: never;
    };

export class AttributionEngine {
  /**
   * Aggregates multiple raw observations into unique relationship factors,
   * completely eliminating duplicate-observation score saturation.
   */
  public static aggregateFactors(
    observations: RawObservationFactor[],
    policy: CorrelationPolicy = DEFAULT_CORRELATION_POLICY
  ): AggregatedFactor[] {
    const factorMap = new Map<string, AggregatedFactor>();

    for (const obs of observations) {
      const existing = factorMap.get(obs.factorKey);
      if (existing) {
        if (!existing.supportingEvidenceIds.includes(obs.evidenceId)) {
          existing.supportingEvidenceIds.push(obs.evidenceId);
        }
        if (!existing.sourceUris.includes(obs.sourceUri)) {
          existing.sourceUris.push(obs.sourceUri);
        }
      } else {
        let weight = 0;
        if (obs.category === 'ARTIFACT_REUSE') weight = policy.artifactReuseWeight;
        else if (obs.category === 'INFRASTRUCTURE_COLOCATION') weight = policy.infraColocationWeight;
        else if (obs.category === 'HANDLE_SIMILARITY') weight = policy.handleSimilarityWeight;
        else if (obs.category === 'STYLOMETRIC_MATCH') weight = policy.stylometricMatchWeight;
        else if (obs.category === 'TEMPORAL_CORRELATION') weight = policy.temporalCorrelationWeight;

        factorMap.set(obs.factorKey, {
          category: obs.category,
          factorKey: obs.factorKey,
          weight,
          rationale: obs.rationale,
          supportingEvidenceIds: [obs.evidenceId],
          sourceUris: [obs.sourceUri],
        });
      }
    }

    return Array.from(factorMap.values());
  }

  public static calculateAttributionCandidate(
    actorProfile: ActorCandidateProfile,
    observationsOrFactors: RawObservationFactor[] | AggregatedFactor[],
    executionPlane: 'CONTROLLED_LAB_PLANE' | 'REAL_WORLD_PLANE',
    groundTruthActorId?: string,
    policy: CorrelationPolicy = DEFAULT_CORRELATION_POLICY
  ): AttributionCandidate {
    // If raw observations provided, aggregate first
    const aggregatedFactors: AggregatedFactor[] =
      observationsOrFactors.length > 0 && 'factorKey' in observationsOrFactors[0] && 'supportingEvidenceIds' in observationsOrFactors[0]
        ? (observationsOrFactors as AggregatedFactor[])
        : this.aggregateFactors(observationsOrFactors as RawObservationFactor[], policy);

    // Sum unique aggregated factor weights, capped at 100
    const rawScore = aggregatedFactors.reduce((acc, factor) => acc + factor.weight, 0);
    const investigativeCorrelationScore = Math.min(100, Math.max(0, rawScore));

    if (executionPlane === 'CONTROLLED_LAB_PLANE') {
      return {
        executionPlane: 'CONTROLLED_LAB_PLANE',
        candidateId: crypto.randomUUID(),
        actorProfile,
        investigativeCorrelationScore,
        aggregatedFactors,
        groundTruthMatch: actorProfile.actorId === groundTruthActorId,
      };
    }

    return {
      executionPlane: 'REAL_WORLD_PLANE',
      candidateId: crypto.randomUUID(),
      actorProfile,
      investigativeCorrelationScore,
      aggregatedFactors,
    };
  }
}
