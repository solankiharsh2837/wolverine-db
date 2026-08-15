import { describe, it, expect } from 'vitest';
import { IncidentCorrelationGraph } from '../../src/fabric/correlation_graph.js';
import { createSecurityEvent } from '../../src/fabric/events.js';

describe('Incident Correlation Graph & Evidence Binding (WDB-0042 Hardening)', () => {
  it('property: constructs multi-layer DAG and computes deterministic graph root digest', () => {
    const graph = new IncidentCorrelationGraph('inc:20260815:database:1234567890abcdef');

    // 1. Ingest Database Event
    const dbEvent = createSecurityEvent({
      plane: 'DATABASE',
      eventType: 'DB_UNAUTHORIZED_MUTATION',
      actorId: 'dba_service_07',
      serviceId: 'pg_primary',
      scope: 'public.users',
      payload: { modifiedRecords: 17 },
    });
    graph.ingestSecurityEvent(dbEvent);

    // 2. Ingest Runtime Event
    const runtimeEvent = createSecurityEvent({
      plane: 'RUNTIME',
      eventType: 'RUNTIME_PRIVILEGE_ESCALATION',
      actorId: 'dba_service_07',
      serviceId: 'web_auth_gateway',
      scope: 'public.users',
      payload: { attemptedRole: 'SUPERUSER' },
    });
    graph.ingestSecurityEvent(runtimeEvent);

    // 3. Ingest AEGIS Threat Intelligence
    const aegisEvent = createSecurityEvent({
      plane: 'AEGIS_INTEL',
      eventType: 'AEGIS_THREAT_CORRELATION',
      actorId: 'dba_service_07',
      serviceId: 'aegis_analyzer',
      scope: 'public.users',
      payload: { campaignId: 'APT-SUSPECT-42' },
    });
    graph.ingestSecurityEvent(aegisEvent);

    expect(graph.getNodeCount()).toBeGreaterThanOrEqual(4); // 1 actor + 3 context nodes
    expect(graph.getEdgeCount()).toBe(3);

    const rootDigest1 = graph.computeGraphRootDigest();
    expect(rootDigest1).toHaveLength(32);

    const rootDigest2 = graph.computeGraphRootDigest();
    expect(rootDigest1.equals(rootDigest2)).toBe(true);
  });
});
