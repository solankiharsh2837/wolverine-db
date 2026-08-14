import crypto from 'node:crypto';
import { AttributionCandidate } from '../attribution/index.js';

export interface SentinelHypothesisReport {
  hypothesisId: string;
  candidateId: string;
  summaryText: string;
  positiveFactors: string[];
  contradictions: string[];
  citedEvidenceIds: string[];
  investigativeCorrelationScore: number;
  advisoryRating: 'LOW_CORRELATION' | 'MEDIUM_CORRELATION' | 'HIGH_CORRELATION';
  decisionAuthority: 'NONE';
}

export class AISentinelEngine {
  public static generateHypothesisReport(
    candidate: AttributionCandidate,
    contradictions: string[] = []
  ): SentinelHypothesisReport {
    // Collect all unique supporting evidence IDs across all unique factors
    const allEvidenceIds = new Set<string>();
    for (const factor of candidate.aggregatedFactors) {
      for (const evId of factor.supportingEvidenceIds) {
        allEvidenceIds.add(evId);
      }
    }
    const citedEvidenceIds = Array.from(allEvidenceIds);

    const positiveFactors = candidate.aggregatedFactors.map(
      (factor) => `${factor.category} (+${factor.weight}): ${factor.rationale} [Cited in ${factor.supportingEvidenceIds.length} observations]`
    );

    let advisoryRating: SentinelHypothesisReport['advisoryRating'] = 'LOW_CORRELATION';
    if (candidate.investigativeCorrelationScore >= 70) {
      advisoryRating = 'HIGH_CORRELATION';
    } else if (candidate.investigativeCorrelationScore >= 40) {
      advisoryRating = 'MEDIUM_CORRELATION';
    }

    let summaryText = `Advisory Lead Report for handle '${candidate.actorProfile.primaryHandle}' (Investigative Score: ${candidate.investigativeCorrelationScore}/100 based on ${candidate.aggregatedFactors.length} unique factors across ${citedEvidenceIds.length} evidence citations).`;

    if (contradictions.length > 0) {
      summaryText += ` WARNING: ${contradictions.length} potential contradictions noted.`;
    }

    return {
      hypothesisId: crypto.randomUUID(),
      candidateId: candidate.candidateId,
      summaryText,
      positiveFactors,
      contradictions,
      citedEvidenceIds,
      investigativeCorrelationScore: candidate.investigativeCorrelationScore,
      advisoryRating,
      decisionAuthority: 'NONE',
    };
  }
}
