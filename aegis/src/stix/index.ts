import crypto from 'node:crypto';
import { AttributionCandidate } from '../attribution/index.js';

export interface StixBundle {
  type: 'bundle';
  id: string;
  objects: Array<Record<string, unknown>>;
}

export class StixExporter {
  public static exportCandidateToStix21(candidate: AttributionCandidate): StixBundle {
    const actorId = `threat-actor--${crypto.randomUUID()}`;
    const nowIso = new Date().toISOString();

    // Map internal investigative correlation score to standard STIX confidence (0-100 scale)
    // Low (<40) -> 30, Medium (40-69) -> 60, High (>=70) -> 85
    let stixConfidence = 30;
    if (candidate.investigativeCorrelationScore >= 70) {
      stixConfidence = 85;
    } else if (candidate.investigativeCorrelationScore >= 40) {
      stixConfidence = 60;
    }

    const threatActorObj: Record<string, unknown> = {
      type: 'threat-actor',
      spec_version: '2.1',
      id: actorId,
      created: nowIso,
      modified: nowIso,
      name: candidate.actorProfile.primaryHandle,
      aliases: candidate.actorProfile.aliases,
      confidence: stixConfidence,
      x_aegis_investigative_correlation_score: candidate.investigativeCorrelationScore,
      x_aegis_execution_plane: candidate.executionPlane,
      x_aegis_unique_factors_count: candidate.aggregatedFactors.length,
    };

    return {
      type: 'bundle',
      id: `bundle--${crypto.randomUUID()}`,
      objects: [threatActorObj],
    };
  }
}
