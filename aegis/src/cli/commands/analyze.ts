import { AttributionEngine, AttributionCandidate, RawObservationFactor, AggregatedFactor } from '../../attribution/index.js';
import { AISentinelEngine, SentinelHypothesisReport } from '../../sentinel/index.js';
import { ActorCandidateProfile } from '../../extraction/index.js';

export interface AnalysisResult {
  candidate: AttributionCandidate;
  sentinelReport: SentinelHypothesisReport;
}

export function handleAnalyze(
  actorProfile: ActorCandidateProfile,
  factors: RawObservationFactor[] | AggregatedFactor[],
  executionPlane: 'CONTROLLED_LAB_PLANE' | 'REAL_WORLD_PLANE' = 'REAL_WORLD_PLANE',
  groundTruthActorId?: string,
  contradictions: string[] = []
): AnalysisResult {
  const candidate = AttributionEngine.calculateAttributionCandidate(
    actorProfile,
    factors,
    executionPlane,
    groundTruthActorId
  );

  const sentinelReport = AISentinelEngine.generateHypothesisReport(candidate, contradictions);

  return { candidate, sentinelReport };
}
