import { describe, it, expect } from 'vitest';
import { BaselineTracker, computeBaselineHash } from '../../src/sentinel/baseline.js';

describe('Sentinel Behavioral Baseline (WDB-0031 Hardening)', () => {
  it('property: computes domain-separated baseline hash and verifies profile integrity', () => {
    const tracker = new BaselineTracker();

    const profileData = {
      actorId: 'dba_service_07',
      allowedScopes: ['public.users', 'public.accounts'],
      typicalOperations: [1, 2],
      maintenanceWindows: [{ startUtcHour: 2, endUtcHour: 4, daysOfWeek: [0, 6] }],
      maxMutationsPerMinute: 100,
      averageBatchSize: 10,
      requiresTicketProvenance: true,
    };

    const registered = tracker.registerBaseline(profileData);
    expect(registered.baselineHash).toHaveLength(32);
    expect(tracker.verifyBaselineIntegrity('dba_service_07')).toBe(true);

    // Tamper with profile in memory
    (registered as any).allowedScopes.push('public.admin_secrets');
    expect(tracker.verifyBaselineIntegrity('dba_service_07')).toBe(false);
  });
});
