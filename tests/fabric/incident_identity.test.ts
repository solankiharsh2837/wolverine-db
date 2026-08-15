import { describe, it, expect } from 'vitest';
import { createSecurityEvent, computeDistributedIncidentId, computeEventEvidenceHash } from '../../src/fabric/events.js';

describe('Distributed Incident Identity & Event Envelopes (WDB-0040, WDB-0041)', () => {
  it('property: creates canonical security event with deterministic evidence hash', () => {
    const event = createSecurityEvent({
      plane: 'DATABASE',
      eventType: 'DB_MERKLE_DIVERGENCE',
      actorId: 'dba_service_07',
      serviceId: 'pg_primary',
      scope: 'public.users',
      payload: {
        observedMerkleRoot: 'deadbeef',
        expectedMerkleRoot: 'cafebabe',
        divergentRecordCount: 17,
      },
    });

    expect(event.evidenceHash).toHaveLength(32);
    expect(event.eventId).toMatch(/^[0-9a-f-]{36}$/);

    // Identical payload produces bit-for-bit identical evidence hash
    const recomputedHash = computeEventEvidenceHash(event.payload);
    expect(event.evidenceHash.equals(recomputedHash)).toBe(true);
  });

  it('property: computes deterministic incident ID with epoch day and origin plane', () => {
    const rootEventId = '00000000-0000-0000-0000-000000000001';
    const timestampUs = 1723500000000000n; // 2024-08-12 / epoch date
    const scope = 'public.accounts';

    const incId = computeDistributedIncidentId('DATABASE', rootEventId, timestampUs, scope);
    expect(incId).toMatch(/^inc:\d{8}:database:[0-9a-f]{16}$/);

    // Same inputs produce identical deterministic incident ID
    const incId2 = computeDistributedIncidentId('DATABASE', rootEventId, timestampUs, scope);
    expect(incId).toBe(incId2);
  });
});
