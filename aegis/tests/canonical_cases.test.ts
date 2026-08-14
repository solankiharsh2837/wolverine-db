import { describe, it, expect } from 'vitest';
import { AttributionEngine, RawObservationFactor } from '../src/attribution/index.js';
import { AISentinelEngine } from '../src/sentinel/index.js';
import { StixExporter } from '../src/stix/index.js';
import { ActorCandidateProfile } from '../src/extraction/index.js';

describe('AEGIS v0.1-rc2 Canonical Intelligence Test Cases (4 Scenarios)', () => {
  // CASE 1: Strong Unique Evidence -> Non-Saturated Calibrated High Score
  it('CASE 1: Evaluates strong unique evidence accurately without artificial score saturation', () => {
    const profile: ActorCandidateProfile = {
      actorId: 'operator_alpha_gt',
      primaryHandle: 'nocturne',
      aliases: ['nocturne_dev'],
      entityNodeIds: ['e1', 'e2'],
    };

    const observations: RawObservationFactor[] = [
      {
        category: 'ARTIFACT_REUSE',
        factorKey: 'artifact:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        weight: 25,
        evidenceId: 'ev_001',
        sourceUri: 'tor://market-a.onion',
        rationale: 'Unique ransomware script hash',
      },
      {
        category: 'INFRASTRUCTURE_COLOCATION',
        factorKey: 'ip:198.51.100.42',
        weight: 20,
        evidenceId: 'ev_001',
        sourceUri: 'tor://market-a.onion',
        rationale: 'C2 IP address 198.51.100.42',
      },
      {
        category: 'HANDLE_SIMILARITY',
        factorKey: 'handle:nocturne_dev',
        weight: 15,
        evidenceId: 'ev_002',
        sourceUri: 'https://forum.org',
        rationale: 'Forum handle alias',
      },
    ];

    const candidate = AttributionEngine.calculateAttributionCandidate(
      profile,
      observations,
      'CONTROLLED_LAB_PLANE',
      'operator_alpha_gt'
    );

    // Sum of unique factors: 25 + 20 + 15 = 60 / 100
    expect(candidate.investigativeCorrelationScore).toBe(60);
    expect(candidate.aggregatedFactors.length).toBe(3);
    expect(candidate.executionPlane).toBe('CONTROLLED_LAB_PLANE');
    expect(candidate.groundTruthMatch).toBe(true);

    const stix = StixExporter.exportCandidateToStix21(candidate);
    expect(stix.objects[0].confidence).toBe(60);
    expect(stix.objects[0].x_aegis_investigative_correlation_score).toBe(60);
  });

  // CASE 2: Many Weak Similarities -> Does NOT become high merely through duplication
  it('CASE 2: Proves 10 repeated observations of weak features DO NOT inflate score to 100', () => {
    const profile: ActorCandidateProfile = {
      actorId: 'operator_shadow',
      primaryHandle: 'shadow_user',
      aliases: [],
      entityNodeIds: ['e1'],
    };

    // 10 repeated observations across 10 forums of the same public VPN IP and same timezone
    const observations: RawObservationFactor[] = [];
    for (let i = 1; i <= 10; i++) {
      observations.push({
        category: 'INFRASTRUCTURE_COLOCATION',
        factorKey: 'ip:203.0.113.1', // Same public IP observed 10 times
        weight: 20,
        evidenceId: `ev_pub_${i}`,
        sourceUri: `https://forum-${i}.org`,
        rationale: 'Public VPN IP address',
      });
      observations.push({
        category: 'TEMPORAL_CORRELATION',
        factorKey: 'tz:UTC+0', // Same timezone observed 10 times
        weight: 10,
        evidenceId: `ev_pub_${i}`,
        sourceUri: `https://forum-${i}.org`,
        rationale: 'UTC+0 activity window',
      });
    }

    const candidate = AttributionEngine.calculateAttributionCandidate(
      profile,
      observations,
      'REAL_WORLD_PLANE'
    );

    // Factors MUST aggregate into exactly 2 unique factors: IP (+20) and Timezone (+10) = 30 / 100
    // MUST NOT saturate to 100!
    expect(candidate.aggregatedFactors.length).toBe(2);
    expect(candidate.investigativeCorrelationScore).toBe(30);
    expect(candidate.investigativeCorrelationScore).toBeLessThan(40);

    // Supporting evidence citations must preserve all 10 source evidence IDs
    const ipFactor = candidate.aggregatedFactors.find((f) => f.category === 'INFRASTRUCTURE_COLOCATION');
    expect(ipFactor?.supportingEvidenceIds.length).toBe(10);
  });

  // CASE 3: Strong Evidence + Contradictions -> High Correlation with Visible Contradictions
  it('CASE 3: Displays visible unhidden contradictions alongside strong evidence factors', () => {
    const profile: ActorCandidateProfile = {
      actorId: 'operator_target',
      primaryHandle: 'target_dev',
      aliases: [],
      entityNodeIds: ['e1'],
    };

    const observations: RawObservationFactor[] = [
      {
        category: 'ARTIFACT_REUSE',
        factorKey: 'artifact:hash_unique_payload',
        weight: 25,
        evidenceId: 'ev_100',
        sourceUri: 'tor://darknet.onion',
        rationale: 'Identical builder binary',
      },
      {
        category: 'INFRASTRUCTURE_COLOCATION',
        factorKey: 'ip:198.51.100.77',
        weight: 20,
        evidenceId: 'ev_100',
        sourceUri: 'tor://darknet.onion',
        rationale: 'Dedicated C2 server',
      },
    ];

    const candidate = AttributionEngine.calculateAttributionCandidate(
      profile,
      observations,
      'REAL_WORLD_PLANE'
    );

    const contradictions = [
      'Incompatible PGP key fingerprints: key_AAA (revoked 2024) vs key_BBB (created 2026).',
      'Conflicting operator language locale (Russian vs Mandarin comments in code).',
    ];

    const sentinelReport = AISentinelEngine.generateHypothesisReport(candidate, contradictions);

    expect(candidate.investigativeCorrelationScore).toBe(45);
    expect(sentinelReport.contradictions.length).toBe(2);
    expect(sentinelReport.summaryText).toContain('WARNING: 2 potential contradictions noted.');
    expect(sentinelReport.decisionAuthority).toBe('NONE');
  });

  // CASE 4: Completely Unrelated Entities -> No False Entity Merge
  it('CASE 4: Correctly evaluates completely independent synthetic operators with 0 ground-truth match', () => {
    const profileA: ActorCandidateProfile = {
      actorId: 'operator_alpha',
      primaryHandle: 'alpha_user',
      aliases: [],
      entityNodeIds: ['ea'],
    };

    const candidateA = AttributionEngine.calculateAttributionCandidate(
      profileA,
      [],
      'CONTROLLED_LAB_PLANE',
      'operator_beta_ground_truth' // Evaluating against Beta ground truth
    );

    expect(candidateA.groundTruthMatch).toBe(false);
    expect(candidateA.investigativeCorrelationScore).toBe(0);
    expect(candidateA.aggregatedFactors.length).toBe(0);
  });
});
