import { describe, it, expect } from 'vitest';
import { EvidenceManager } from '../src/evidence/index.js';
import { AttributionEngine, RawObservationFactor } from '../src/attribution/index.js';

describe('False Positive & "Similarity != Identity" Stress Suite', () => {
  it('proves shared public VPN IP or temporal overlap NEVER forces high attribution score', () => {
    const ev1 = EvidenceManager.createEvidenceRecord('OSINT', 'http://forum.org/1', JSON.stringify({ ip: '198.51.100.1' }));

    const weakObservations: RawObservationFactor[] = [
      { category: 'INFRASTRUCTURE_COLOCATION', factorKey: 'ip:public_vpn', weight: 20, evidenceId: ev1.evidenceId, sourceUri: ev1.sourceUri, rationale: 'Shared public VPN / Tor exit node IP' },
      { category: 'TEMPORAL_CORRELATION', factorKey: 'tz:utc_0', weight: 10, evidenceId: ev1.evidenceId, sourceUri: ev1.sourceUri, rationale: 'Overlapping timezone activity window' },
    ];

    const candidate = AttributionEngine.calculateAttributionCandidate(
      { actorId: 'candidate_user', primaryHandle: 'shadow_user_1', aliases: [], entityNodeIds: [] },
      weakObservations,
      'REAL_WORLD_PLANE'
    );

    expect(candidate.investigativeCorrelationScore).toBe(30);
    expect(candidate.investigativeCorrelationScore).toBeLessThan(75);
  });

  it('proves username prefix similarity alone is evaluated as low correlation', () => {
    const ev = EvidenceManager.createEvidenceRecord('OSINT', 'http://forum.org/2', 'shadow_user_2');
    const observations: RawObservationFactor[] = [
      { category: 'HANDLE_SIMILARITY', factorKey: 'handle:shadow_prefix', weight: 15, evidenceId: ev.evidenceId, sourceUri: ev.sourceUri, rationale: 'Similar handle prefix' },
    ];

    const candidate = AttributionEngine.calculateAttributionCandidate(
      { actorId: 'cand2', primaryHandle: 'shadow_user_2', aliases: [], entityNodeIds: [] },
      observations,
      'REAL_WORLD_PLANE'
    );

    expect(candidate.investigativeCorrelationScore).toBe(15);
  });
});
