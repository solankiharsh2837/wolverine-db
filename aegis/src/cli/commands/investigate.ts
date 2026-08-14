import { CollectionEngine, CollectionResult } from '../../collection/index.js';
import { AttributionEngine, AttributionCandidate, RawObservationFactor } from '../../attribution/index.js';
import { AISentinelEngine, SentinelHypothesisReport } from '../../sentinel/index.js';
import { StixExporter, StixBundle } from '../../stix/index.js';
import { ActorCandidateProfile } from '../../extraction/index.js';

export interface InvestigationResult {
  targetIdentifier: string;
  collection: CollectionResult;
  candidate: AttributionCandidate;
  sentinelReport: SentinelHypothesisReport;
  stixBundle: StixBundle;
}

export function handleInvestigate(
  targetIdentifier: string,
  executionPlane: 'CONTROLLED_LAB_PLANE' | 'REAL_WORLD_PLANE' = 'REAL_WORLD_PLANE',
  groundTruthActorId?: string
): InvestigationResult {
  // 1. Automated Discovery & Collection
  const collection = CollectionEngine.collectAndNormalizeTarget(targetIdentifier);

  // 2. Build Raw Observation Factors with unique factorKeys
  const observations: RawObservationFactor[] = [];

  for (const ev of collection.evidenceRecords) {
    try {
      const parsed = JSON.parse(ev.rawPayload);
      if (parsed.artifactHash) {
        observations.push({
          category: 'ARTIFACT_REUSE',
          factorKey: `artifact:${parsed.artifactHash}`,
          evidenceId: ev.evidenceId,
          sourceUri: ev.sourceUri,
          rationale: `Shared binary script hash ${parsed.artifactHash.substring(0, 16)}...`,
        });
      }
      if (parsed.ip) {
        observations.push({
          category: 'INFRASTRUCTURE_COLOCATION',
          factorKey: `ip:${parsed.ip}`,
          evidenceId: ev.evidenceId,
          sourceUri: ev.sourceUri,
          rationale: `Shared C2 infrastructure IP ${parsed.ip}`,
        });
      }
      if (parsed.handle) {
        observations.push({
          category: 'HANDLE_SIMILARITY',
          factorKey: `handle:${parsed.handle}`,
          evidenceId: ev.evidenceId,
          sourceUri: ev.sourceUri,
          rationale: `Handle alias ${parsed.handle}`,
        });
      }
    } catch {
      // Fallback
    }
  }

  const profile: ActorCandidateProfile = {
    actorId: groundTruthActorId || `actor_${targetIdentifier}`,
    primaryHandle: targetIdentifier,
    aliases: collection.allEntities.filter((e) => e.type === 'HANDLE').map((e) => e.value),
    entityNodeIds: collection.allEntities.map((e) => e.entityId),
  };

  // 3. Calculate Attribution Lead Candidate with Factor Aggregation
  const candidate = AttributionEngine.calculateAttributionCandidate(
    profile,
    observations,
    executionPlane,
    groundTruthActorId
  );

  // 4. Generate Auditable AI Sentinel Hypothesis
  const sentinelReport = AISentinelEngine.generateHypothesisReport(candidate);

  // 5. Generate STIX 2.1 Bundle
  const stixBundle = StixExporter.exportCandidateToStix21(candidate);

  return {
    targetIdentifier,
    collection,
    candidate,
    sentinelReport,
    stixBundle,
  };
}
