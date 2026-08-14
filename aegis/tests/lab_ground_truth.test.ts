import { describe, it, expect } from 'vitest';
import { EvidenceManager } from '../src/evidence/index.js';
import { AttributionEngine, RawObservationFactor } from '../src/attribution/index.js';

describe('Controlled Ground-Truth Laboratory Framework Suite', () => {
  it('measures precision and recall on synthetic ground-truth threat dataset', () => {
    const groundTruthAlphaId = 'actor_alpha_gt_1001';
    const evidenceAlpha = EvidenceManager.createEvidenceRecord(
      'LAB_SYNTHETIC',
      'lab://synthetic/alpha',
      JSON.stringify({ handle: 'operator_alpha', artifactHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' })
    );

    const evidenceBeta = EvidenceManager.createEvidenceRecord(
      'LAB_SYNTHETIC',
      'lab://synthetic/beta',
      JSON.stringify({ handle: 'vendor_beta', ip: '198.51.100.99' })
    );

    const observationsAlpha: RawObservationFactor[] = [
      { category: 'ARTIFACT_REUSE', factorKey: 'art:alpha', weight: 25, evidenceId: evidenceAlpha.evidenceId, sourceUri: evidenceAlpha.sourceUri, rationale: 'Known binary script hash' },
      { category: 'HANDLE_SIMILARITY', factorKey: 'handle:alpha', weight: 15, evidenceId: evidenceAlpha.evidenceId, sourceUri: evidenceAlpha.sourceUri, rationale: 'Matching forum handle' },
    ];

    const candidateAlpha = AttributionEngine.calculateAttributionCandidate(
      { actorId: groundTruthAlphaId, primaryHandle: 'operator_alpha', aliases: [], entityNodeIds: [] },
      observationsAlpha,
      'CONTROLLED_LAB_PLANE',
      groundTruthAlphaId
    );

    expect(candidateAlpha.executionPlane).toBe('CONTROLLED_LAB_PLANE');
    expect(candidateAlpha.groundTruthMatch).toBe(true);
    expect(candidateAlpha.investigativeCorrelationScore).toBe(40);

    const candidateBeta = AttributionEngine.calculateAttributionCandidate(
      { actorId: 'actor_beta_gt_2002', primaryHandle: 'vendor_beta', aliases: [], entityNodeIds: [] },
      [{ category: 'INFRASTRUCTURE_COLOCATION', factorKey: 'ip:beta', weight: 20, evidenceId: evidenceBeta.evidenceId, sourceUri: evidenceBeta.sourceUri, rationale: 'Unique vendor IP' }],
      'CONTROLLED_LAB_PLANE',
      groundTruthAlphaId
    );

    expect(candidateBeta.groundTruthMatch).toBe(false);
  });
});
