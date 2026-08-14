import { describe, it, expect } from 'vitest';
import { handleIngest } from '../src/cli/commands/ingest.js';
import { handleAnalyze } from '../src/cli/commands/analyze.js';
import { handleExportStix21 } from '../src/cli/commands/export.js';
import { handleStatus } from '../src/cli/commands/status.js';
import { RawObservationFactor } from '../src/attribution/index.js';

describe('AEGIS Investigator Platform CLI Suite', () => {
  it('executes aegis ingest command, normalizes evidence, and extracts entities', () => {
    const res = handleIngest('OSINT', 'https://forum.org/post/100', JSON.stringify({ handle: 'operator_k', ip: '198.51.100.5' }));

    expect(res.evidence.sourceType).toBe('OSINT');
    expect(res.evidence.payloadHash.length).toBe(32);
    expect(res.extractedEntities.length).toBe(2);
    expect(res.extractedEntities[0].value).toBe('operator_k');
  });

  it('executes aegis analyze command, computes correlation score, and generates auditable Sentinel report', () => {
    const profile = { actorId: 'actor_k', primaryHandle: 'operator_k', aliases: [], entityNodeIds: [] };
    const observations: RawObservationFactor[] = [
      { category: 'ARTIFACT_REUSE' as const, factorKey: 'art:k', weight: 25, evidenceId: 'ev_1', sourceUri: 'https://forum.org', rationale: 'Script match' },
      { category: 'INFRASTRUCTURE_COLOCATION' as const, factorKey: 'ip:k', weight: 20, evidenceId: 'ev_1', sourceUri: 'https://forum.org', rationale: 'IP match' },
    ];

    const { candidate, sentinelReport } = handleAnalyze(profile, observations, 'REAL_WORLD_PLANE');

    expect(candidate.investigativeCorrelationScore).toBe(45);
    expect(sentinelReport.citedEvidenceIds).toEqual(['ev_1']);
    expect(sentinelReport.decisionAuthority).toBe('NONE');
    expect(sentinelReport.advisoryRating).toBe('MEDIUM_CORRELATION');
  });

  it('executes aegis export command and outputs STIX 2.1 JSON bundle', () => {
    const profile = { actorId: 'actor_k', primaryHandle: 'operator_k', aliases: [], entityNodeIds: [] };
    const { candidate } = handleAnalyze(profile, [], 'REAL_WORLD_PLANE');

    const stixBundle = handleExportStix21(candidate);

    expect(stixBundle.type).toBe('bundle');
    expect(stixBundle.objects[0].type).toBe('threat-actor');
    expect(stixBundle.objects[0].name).toBe('operator_k');
  });

  it('executes aegis status command and verifies Wolverine self-protection state', () => {
    const status = handleStatus();

    expect(status.wolverineDbProtection).toBe('PROTECTED_VALID');
    expect(status.wolverineRuntimeStatus).toBe('ACTIVE_OBSERVER');
    expect(status.protectedTables.length).toBeGreaterThan(0);
  });
});
