import { describe, it, expect } from 'vitest';
import { EvidenceManager } from '../src/evidence/index.js';
import { EntityExtractor, ActorCandidateProfile } from '../src/extraction/index.js';
import { AttributionEngine, RawObservationFactor } from '../src/attribution/index.js';
import { AISentinelEngine } from '../src/sentinel/index.js';
import { StixExporter } from '../src/stix/index.js';

describe('AEGIS CTI Platform Core Engine & Dual Execution Plane Suite', () => {
  // 1. Evidence Normalization & Immutability Test
  it('creates immutable EvidenceRecord with SHA-256 payload digest', () => {
    const rawPayload = JSON.stringify({ handle: 'operator_x', ip: '192.0.2.1', wallet: 'tb1qsynthetic0017labtestnetaddress99x' });
    const evidence = EvidenceManager.createEvidenceRecord('OSINT', 'https://forum.example.com/post/42', rawPayload);

    expect(evidence.evidenceId).toBeDefined();
    expect(evidence.sourceType).toBe('OSINT');
    expect(evidence.payloadHash.length).toBe(32);
  });

  // 2. Controlled Lab Plane Benchmark Ground-Truth Match Test
  it('evaluates Controlled Lab Plane candidate against ground-truth actor', () => {
    const rawPayload = JSON.stringify({ handle: 'threat_actor_alpha', ip: '198.51.100.42', wallet: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh' });
    const evidence = EvidenceManager.createEvidenceRecord('LAB_SYNTHETIC', 'lab://synthetic/actor_alpha', rawPayload);

    const entities = EntityExtractor.extractEntities(evidence);
    expect(entities.length).toBe(3);

    const profile: ActorCandidateProfile = {
      actorId: 'actor_alpha_ground_truth',
      primaryHandle: 'threat_actor_alpha',
      aliases: ['alpha_dev', 'alpha_pgp'],
      entityNodeIds: entities.map((e) => e.entityId),
    };

    const observations: RawObservationFactor[] = [
      { category: 'ARTIFACT_REUSE', factorKey: 'art:1', weight: 25, evidenceId: evidence.evidenceId, sourceUri: evidence.sourceUri, rationale: 'Identical ransomware script hash match' },
      { category: 'INFRASTRUCTURE_COLOCATION', factorKey: 'ip:1', weight: 20, evidenceId: evidence.evidenceId, sourceUri: evidence.sourceUri, rationale: 'C2 IP address 198.51.100.42 co-location' },
      { category: 'HANDLE_SIMILARITY', factorKey: 'handle:1', weight: 15, evidenceId: evidence.evidenceId, sourceUri: evidence.sourceUri, rationale: 'Forum handle threat_actor_alpha match' },
      { category: 'STYLOMETRIC_MATCH', factorKey: 'style:1', weight: 12, evidenceId: evidence.evidenceId, sourceUri: evidence.sourceUri, rationale: 'Unique PGP key comment vocabulary match' },
      { category: 'TEMPORAL_CORRELATION', factorKey: 'tz:1', weight: 10, evidenceId: evidence.evidenceId, sourceUri: evidence.sourceUri, rationale: 'Synchronous attack window UTC 02:00-04:00' },
    ];

    // Total score = 25 + 20 + 15 + 12 + 10 = 82 / 100
    const candidate = AttributionEngine.calculateAttributionCandidate(
      profile,
      observations,
      'CONTROLLED_LAB_PLANE',
      'actor_alpha_ground_truth'
    );

    expect(candidate.investigativeCorrelationScore).toBe(82);
    expect(candidate.executionPlane).toBe('CONTROLLED_LAB_PLANE');
    expect(candidate.groundTruthMatch).toBe(true);
    expect(candidate.aggregatedFactors.length).toBe(5);
  });

  // 3. Evidence Lineage Rule Test: Correlation Is Never Proof
  it('proves that lead score is explainable and points to source evidence', () => {
    const profile: ActorCandidateProfile = {
      actorId: 'actor_unknown',
      primaryHandle: 'suspect_beta',
      aliases: [],
      entityNodeIds: [],
    };

    const observations: RawObservationFactor[] = [
      { category: 'HANDLE_SIMILARITY', factorKey: 'handle:beta', weight: 15, evidenceId: 'ev_123', sourceUri: 'https://osint.example.com', rationale: 'Username similarity' },
    ];

    const candidate = AttributionEngine.calculateAttributionCandidate(profile, observations, 'REAL_WORLD_PLANE');

    // Score is 15/100 -> MUST NOT be treated as proof
    expect(candidate.investigativeCorrelationScore).toBe(15);
    expect(candidate.aggregatedFactors[0].supportingEvidenceIds).toContain('ev_123');
  });

  // 4. Advisory AI Sentinel Test
  it('generates advisory hypothesis report without autonomous action', () => {
    const profile: ActorCandidateProfile = { actorId: 'actor_1', primaryHandle: 'gamma', aliases: [], entityNodeIds: [] };
    const candidate = AttributionEngine.calculateAttributionCandidate(profile, [], 'REAL_WORLD_PLANE');

    const report = AISentinelEngine.generateHypothesisReport(candidate);
    expect(report.decisionAuthority).toBe('NONE');
    expect(report.positiveFactors).toBeDefined();
  });

  // 5. STIX 2.1 JSON Export Test
  it('exports STIX 2.1 compliant JSON threat-actor bundle', () => {
    const profile: ActorCandidateProfile = { actorId: 'actor_1', primaryHandle: 'delta', aliases: ['delta_alias'], entityNodeIds: [] };
    const candidate = AttributionEngine.calculateAttributionCandidate(profile, [], 'REAL_WORLD_PLANE');

    const stixBundle = StixExporter.exportCandidateToStix21(candidate);
    expect(stixBundle.type).toBe('bundle');
    expect(stixBundle.objects[0].type).toBe('threat-actor');
    expect(stixBundle.objects[0].spec_version).toBe('2.1');
    expect(stixBundle.objects[0].name).toBe('delta');
  });
});
