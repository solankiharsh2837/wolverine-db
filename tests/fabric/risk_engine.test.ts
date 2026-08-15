import { describe, it, expect } from 'vitest';
import { DistributedRiskEngine } from '../../src/fabric/risk_engine.js';

describe('Distributed Explainable Risk Engine (WDB-0043 Hardening)', () => {
  it('property: calculates explainable composite risk breakdown with 5 signal vectors', () => {
    const signals = {
      stateIntegrity: { score: 90, evidence: 'Merkle root mismatch on public.users' },
      provenance: { score: 70, evidence: 'Missing ticket ID and untrusted IP origin' },
      behavioral: { score: 85, evidence: 'Out of maintenance window DBA update' },
      historical: { score: 40, evidence: '1 prior medium alert on this actor' },
      externalIntel: { score: 80, evidence: 'AEGIS flagged active credential leak' },
    };

    // Expected:
    // 90 * 0.35 = 31.5
    // 70 * 0.20 = 14.0
    // 85 * 0.20 = 17.0
    // 40 * 0.10 = 4.0
    // 80 * 0.15 = 12.0
    // Sum = 78.5 -> rounded = 79 (HIGH)
    const breakdown = DistributedRiskEngine.evaluateRisk(signals);
    expect(breakdown.compositeScore).toBe(79);
    expect(breakdown.severity).toBe('HIGH');

    expect(breakdown.factors.stateIntegrity.contribution).toBe(31.5);
    expect(breakdown.factors.provenance.contribution).toBe(14.0);
    expect(breakdown.factors.behavioral.contribution).toBe(17.0);
    expect(breakdown.factors.historical.contribution).toBe(4.0);
    expect(breakdown.factors.externalIntel.contribution).toBe(12.0);

    const responseLevel = DistributedRiskEngine.mapResponseLevel(breakdown.compositeScore);
    expect(responseLevel).toBe('LEVEL_4_REQUIRE_APPROVAL');
  });

  it('property: low risk signals map to LEVEL_1_OBSERVE', () => {
    const signals = {
      stateIntegrity: { score: 0, evidence: 'Intact' },
      provenance: { score: 10, evidence: 'Valid ticket' },
      behavioral: { score: 10, evidence: 'In maintenance window' },
      historical: { score: 0, evidence: 'Clean history' },
      externalIntel: { score: 0, evidence: 'No alerts' },
    };

    const breakdown = DistributedRiskEngine.evaluateRisk(signals);
    expect(breakdown.compositeScore).toBeLessThan(30);
    expect(breakdown.severity).toBe('LOW');
    expect(DistributedRiskEngine.mapResponseLevel(breakdown.compositeScore)).toBe('LEVEL_1_OBSERVE');
  });
});
