import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { EvidenceManager } from '../src/evidence/index.js';
import { AISentinelEngine } from '../src/sentinel/index.js';
import { AttributionEngine } from '../src/attribution/index.js';

describe('Contradictory & Tampered Evidence Resolution Suite', () => {
  it('detects payload tampering by comparing SHA-256 evidence digests', () => {
    const rawPayload = JSON.stringify({ actor: 'dev', key: 'pgp_key_001' });
    const evidence = EvidenceManager.createEvidenceRecord('OSINT', 'http://keys.example.com', rawPayload);

    // Compute expected SHA-256
    const computedHash = crypto.createHash('sha256').update(rawPayload).digest();
    expect(evidence.payloadHash.equals(computedHash)).toBe(true);

    // Mutate raw payload
    const tamperedPayload = rawPayload + ' ';
    const tamperedHash = crypto.createHash('sha256').update(tamperedPayload).digest();

    // Verify hash mismatch is detected
    expect(evidence.payloadHash.equals(tamperedHash)).toBe(false);
  });

  it('includes explicit contradictions in Sentinel hypothesis report', () => {
    const candidate = AttributionEngine.calculateAttributionCandidate(
      { actorId: 'actor_1', primaryHandle: 'operator_z', aliases: [], entityNodeIds: [] },
      [],
      'REAL_WORLD_PLANE'
    );

    const contradictions = [
      'Contradictory PGP key ID (key_A vs key_B) associated with same handle.',
      'Incompatible timezone activity windows (UTC+8 vs UTC-5).',
    ];

    const report = AISentinelEngine.generateHypothesisReport(candidate, contradictions);
    expect(report.contradictions.length).toBe(2);
    expect(report.contradictions[0]).toContain('Contradictory PGP key ID');
  });
});
