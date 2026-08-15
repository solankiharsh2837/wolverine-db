import { describe, it, expect } from 'vitest';
import { SecurityFabricCoordinator } from '../../src/fabric/coordinator.js';
import { createSecurityEvent } from '../../src/fabric/events.js';

describe('Coordinated Response & Recovery Plane Isolation (WDB-0044, WDB-0045)', () => {
  it('property: aggregates cross-layer events, evaluates risk, and synthesizes structured anomaly incident', () => {
    const coordinator = new SecurityFabricCoordinator();

    const dbEvent = createSecurityEvent({
      plane: 'DATABASE',
      eventType: 'DB_UNAUTHORIZED_MUTATION',
      actorId: 'dba_service_07',
      serviceId: 'pg_primary',
      scope: 'public.users',
      payload: { recordIds: ['rec-1', 'rec-2', 'rec-3'] },
    });

    const { incidentId, graph } = coordinator.correlateEvent(dbEvent);
    expect(incidentId).toMatch(/^inc:\d{8}:database:[0-9a-f]{16}$/);
    expect(graph.getNodeCount()).toBeGreaterThan(0);

    const signals = {
      stateIntegrity: { score: 95, evidence: 'Merkle root mismatch' },
      provenance: { score: 85, evidence: 'No ticket provenance' },
      behavioral: { score: 90, evidence: 'Out of window mutation' },
      historical: { score: 50, evidence: 'Prior anomalies' },
      externalIntel: { score: 90, evidence: 'AEGIS active incident' },
    };

    const { riskBreakdown, responseLevel } = coordinator.evaluateIncidentRisk(incidentId, signals);
    expect(riskBreakdown.compositeScore).toBeGreaterThanOrEqual(85);
    expect(responseLevel).toBe('LEVEL_4_REQUIRE_APPROVAL');

    const anomalyIncident = coordinator.synthesizeFabricAnomalyIncident(
      incidentId,
      dbEvent,
      riskBreakdown.compositeScore,
      'Cross-layer fabric detected critical DBA breach on public.users'
    );

    expect(anomalyIncident.incidentId).toBe(incidentId);
    expect(anomalyIncident.severity).toBe('CRITICAL');
    expect(anomalyIncident.affectedRecordIds).toEqual(['rec-1', 'rec-2', 'rec-3']);
  });
});
