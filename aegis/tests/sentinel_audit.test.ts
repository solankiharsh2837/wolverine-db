import { describe, it, expect } from 'vitest';
import { EvidenceManager } from '../src/evidence/index.js';
import { AttributionEngine, RawObservationFactor } from '../src/attribution/index.js';
import { AISentinelEngine } from '../src/sentinel/index.js';

describe('Auditable AI Sentinel Citation Enforcement Suite', () => {
  it('enforces 100% evidence citation linkability and decisionAuthority NONE', () => {
    const ev1 = EvidenceManager.createEvidenceRecord('OSINT', 'http://src1.org', 'data1');
    const ev2 = EvidenceManager.createEvidenceRecord('DARKWEB', 'http://src2.onion', 'data2');

    const observations: RawObservationFactor[] = [
      { category: 'ARTIFACT_REUSE', factorKey: 'art:match', weight: 25, evidenceId: ev1.evidenceId, sourceUri: ev1.sourceUri, rationale: 'Binary match' },
      { category: 'INFRASTRUCTURE_COLOCATION', factorKey: 'ip:coloc', weight: 20, evidenceId: ev2.evidenceId, sourceUri: ev2.sourceUri, rationale: 'IP co-location' },
    ];

    const candidate = AttributionEngine.calculateAttributionCandidate(
      { actorId: 'actor_9', primaryHandle: 'target_op', aliases: [], entityNodeIds: [] },
      observations,
      'REAL_WORLD_PLANE'
    );

    const report = AISentinelEngine.generateHypothesisReport(candidate);

    expect(report.citedEvidenceIds).toContain(ev1.evidenceId);
    expect(report.citedEvidenceIds).toContain(ev2.evidenceId);
    expect(report.citedEvidenceIds.length).toBe(2);
    expect(report.positiveFactors.length).toBe(2);
    expect(report.positiveFactors[0]).toContain('ARTIFACT_REUSE');
    expect(report.decisionAuthority).toBe('NONE');
  });
});
