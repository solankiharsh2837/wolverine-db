import { describe, it, expect } from 'vitest';
import {
  handleCaseShow,
  handleEvidenceShow,
  handleEntityShow,
  handleGraphShow,
  handleExplain,
} from '../src/cli/commands/drilldown.js';

describe('AEGIS Investigator Experience & Interactive Drilldown Suite', () => {
  it('executes aegis case show <caseId> and generates rich terminal banner', () => {
    const res = handleCaseShow('CASE-2026-0017');
    expect(res.caseId).toBe('CASE-2026-0017');
    expect(res.banner).toContain('AEGIS INVESTIGATOR');
    expect(res.banner).toContain('Investigation: CASE-2026-0017');
    expect(res.banner).toContain('CORRELATION');
    expect(res.banner).toContain('90 / 100');
    expect(res.banner).toContain('ARTIFACT_REUSE');
    expect(res.banner).toContain('AI SENTINEL');
  });

  it('executes aegis evidence show <evidenceId> and displays raw payload and digest', () => {
    const res = handleEvidenceShow('ev_test_1001');
    expect(res.evidenceId).toBeDefined();
    expect(res.sha256PayloadDigest.startsWith('0x')).toBe(true);
    expect(res.stateIntegrityStatus).toBe('WOLVERINE_DB_VERIFIED');
  });

  it('executes aegis entity show <query> and matches entity graph nodes', () => {
    const res = handleEntityShow('nocturne');
    expect(res.matches.length).toBeGreaterThan(0);
    expect(res.linkedProfile.primaryHandle).toBe('nocturne_operator');
  });

  it('executes aegis graph <target> and renders ASCII relationship network', () => {
    const res = handleGraphShow('nocturne_operator');
    expect(res.asciiGraph).toContain('Marketplace Alpha');
    expect(res.asciiGraph).toContain('Marketplace Beta');
    expect(res.asciiGraph).toContain('OSINT Security Forum');
    expect(res.asciiGraph).toContain('Aggregated: 90 / 100');
  });

  it('executes aegis explain <candidateId> and provides factor breakdown with citations', () => {
    const res = handleExplain('CANDIDATE-12');
    expect(res.candidateId).toBe('CANDIDATE-12');
    expect(res.investigativeCorrelationScore).toBe(90);
    expect(res.factorCount).toBe(5);
    expect(res.factors[0].evidenceCitations.length).toBeGreaterThan(0);
  });
});
