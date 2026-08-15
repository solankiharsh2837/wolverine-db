import { describe, it, expect } from 'vitest';
import { BaselineTracker } from '../../src/sentinel/baseline.js';
import { SentinelAnomalyEngine } from '../../src/sentinel/anomaly_engine.js';

describe('Sentinel Anomaly Detection Engine (WDB-0032 Hardening)', () => {
  const tracker = new BaselineTracker();
  tracker.registerBaseline({
    actorId: 'dba_service_07',
    allowedScopes: ['public.users'],
    typicalOperations: [2],
    maintenanceWindows: [{ startUtcHour: 2, endUtcHour: 4, daysOfWeek: [0] }], // Sunday 2-4 AM
    maxMutationsPerMinute: 50,
    averageBatchSize: 5,
    requiresTicketProvenance: true,
  });

  const anomalyEngine = new SentinelAnomalyEngine(tracker);

  it('property: detects out-of-window, unauthorized DBA mutation with missing ticket', () => {
    const suspiciousEvent = {
      actorId: 'dba_service_07',
      serviceId: 'pg_direct_admin',
      scope: 'public.accounts', // Scope violation
      operation: 2,
      recordIds: Array.from({ length: 15 }, (_, i) => `rec-${i}`), // Bulk update
      utcHour: 14, // Out of window (2 PM on Tuesday)
      dayOfWeek: 2,
      // No ticketId provided
    };

    const incident = anomalyEngine.analyzeMutation(suspiciousEvent);
    expect(incident).not.toBeNull();
    expect(incident?.severity).toBe('CRITICAL');
    expect(incident?.anomalyScore).toBeGreaterThanOrEqual(70);
    expect(incident?.classification).toBe('SCOPE_EXPANSION_VIOLATION');
    expect(incident?.affectedRecordIds).toHaveLength(15);
  });

  it('property: normal in-window authorized mutation produces zero incidents', () => {
    const benignEvent = {
      actorId: 'dba_service_07',
      serviceId: 'maint_runner',
      scope: 'public.users',
      operation: 2,
      recordIds: ['rec-1'],
      utcHour: 3, // In window (3 AM on Sunday)
      dayOfWeek: 0,
      ticketId: 'CHG-99214',
    };

    const incident = anomalyEngine.analyzeMutation(benignEvent);
    expect(incident).toBeNull();
  });
});
