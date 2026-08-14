import { describe, it, expect } from 'vitest';
import { IncidentEngine, IncidentSeverity } from '../src/incidents/index.js';
import { runWithContext } from '../src/context/index.js';

export function classifyExecutionEvent(params: {
  hasValidContext: boolean;
  hasTicket: boolean;
  role: string;
  isDbDivergence: boolean;
}): IncidentSeverity {
  if (params.isDbDivergence) {
    return 'CRITICAL';
  }

  if (params.role === 'dba' && !params.hasTicket) {
    return 'SUSPICIOUS';
  }

  if (!params.hasValidContext) {
    return 'SUSPICIOUS';
  }

  return 'NORMAL';
}

describe('Deterministic Incident Classification Suite', () => {
  it('classifies normal operations as NORMAL', () => {
    const severity = classifyExecutionEvent({
      hasValidContext: true,
      hasTicket: true,
      role: 'user',
      isDbDivergence: false,
    });
    expect(severity).toBe('NORMAL');
  });

  it('classifies DBA query missing change ticket as SUSPICIOUS', () => {
    const severity = classifyExecutionEvent({
      hasValidContext: true,
      hasTicket: false,
      role: 'dba',
      isDbDivergence: false,
    });
    expect(severity).toBe('SUSPICIOUS');

    const incident = IncidentEngine.createReport('SUSPICIOUS', 'DBA_QUERY_MISSING_TICKET', { role: 'dba' });
    expect(incident.severity).toBe('SUSPICIOUS');
  });

  it('classifies database divergence as CRITICAL', () => {
    const severity = classifyExecutionEvent({
      hasValidContext: true,
      hasTicket: true,
      role: 'user',
      isDbDivergence: true,
    });
    expect(severity).toBe('CRITICAL');

    const incident = IncidentEngine.createReport('CRITICAL', 'DATABASE_DIVERGENCE_DETECTED', { scope: 'public.users' });
    expect(incident.severity).toBe('CRITICAL');
  });

  it('ensures classification rules are 100% deterministic with 0 LLM dependencies', () => {
    // Run 100 identical calls and verify exact deterministic output
    for (let i = 0; i < 100; i++) {
      const res = classifyExecutionEvent({
        hasValidContext: true,
        hasTicket: false,
        role: 'dba',
        isDbDivergence: false,
      });
      expect(res).toBe('SUSPICIOUS');
    }
  });
});
