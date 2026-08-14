import { describe, it, expect } from 'vitest';
import { IncidentEngine, IncidentReport } from '../src/incidents/index.js';
import { runWithContext } from '../src/context/index.js';

export function formatAegisTelemetryEvent(report: IncidentReport): Record<string, unknown> {
  return {
    specversion: '1.0',
    type: `com.wolverine.security.${report.eventType.toLowerCase()}`,
    source: `wolverine.runtime.${report.service}`,
    id: report.incidentId,
    time: new Date(Number(report.timestampUs / 1000n)).toISOString(),
    datacontenttype: 'application/json',
    data: {
      severity: report.severity,
      actor: report.actor,
      details: report.details,
      hasStackTrace: !!report.stackTrace,
    },
  };
}

describe('AEGIS Telemetry Ingestion Stream Suite', () => {
  it('formats structured IncidentReport into AEGIS CloudEvents JSON telemetry schema', () => {
    runWithContext({ actorId: 'attacker_script', serviceName: 'payment_api' }, () => {
      const incident = IncidentEngine.createReport('CRITICAL', 'SQL_INJECTION_ATTEMPT', {
        inputQuery: "SELECT * FROM users WHERE '1'='1'",
      });

      const aegisEvent = formatAegisTelemetryEvent(incident);

      expect(aegisEvent.specversion).toBe('1.0');
      expect(aegisEvent.type).toBe('com.wolverine.security.sql_injection_attempt');
      expect(aegisEvent.source).toBe('wolverine.runtime.payment_api');
      expect(aegisEvent.id).toBe(incident.incidentId);

      const data = aegisEvent.data as Record<string, unknown>;
      expect(data.severity).toBe('CRITICAL');
      expect(data.actor).toBe('attacker_script');
      expect(data.hasStackTrace).toBe(true);
    });
  });
});
