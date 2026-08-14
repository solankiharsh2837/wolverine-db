import { describe, it, expect } from 'vitest';
import { handleInvestigate } from '../src/cli/commands/investigate.js';

describe('End-to-End Automated Investigation Pipeline Suite', () => {
  it('runs complete automated investigation for target "nocturne_operator"', () => {
    const result = handleInvestigate('nocturne_operator', 'CONTROLLED_LAB_PLANE', 'actor_alpha_gt_1001');

    // 1. Evidence Collection Verification
    expect(result.collection.evidenceRecords.length).toBe(3);
    expect(result.collection.allEntities.length).toBeGreaterThan(0);

    // 2. Factor Aggregation & Non-Saturated Score Verification:
    // Unique factors:
    // 1. ARTIFACT_REUSE (hash_script_X): +25
    // 2. INFRASTRUCTURE_COLOCATION (198.51.100.42): +20
    // 3. HANDLE_SIMILARITY (nocturne): +15
    // 4. HANDLE_SIMILARITY (nocturne_2): +15
    // 5. HANDLE_SIMILARITY (nocturne_dev): +15
    // Total aggregated score = 25 + 20 + 15 + 15 + 15 = 90 / 100 (Properly non-saturated unique factor sum)
    expect(result.candidate.investigativeCorrelationScore).toBe(90);
    expect(result.candidate.aggregatedFactors.length).toBe(5);
    expect(result.candidate.executionPlane).toBe('CONTROLLED_LAB_PLANE');
    expect(result.candidate.groundTruthMatch).toBe(true); // Matches ground truth actor_alpha_gt_1001

    // 3. AI Sentinel Audit Verification
    expect(result.sentinelReport.citedEvidenceIds.length).toBe(3);
    expect(result.sentinelReport.decisionAuthority).toBe('NONE');
    expect(result.sentinelReport.positiveFactors.length).toBe(5);

    // 4. STIX 2.1 Export Verification
    expect(result.stixBundle.type).toBe('bundle');
    expect(result.stixBundle.objects[0].type).toBe('threat-actor');
    expect(result.stixBundle.objects[0].name).toBe('nocturne_operator');
    expect(result.stixBundle.objects[0].confidence).toBe(85); // Standard STIX confidence mapped for high score >=70
  });
});
