import crypto from 'node:crypto';
import { getCurrentContext } from '../context/index.js';

export type IncidentSeverity = 'NORMAL' | 'SUSPICIOUS' | 'CRITICAL';

export interface IncidentReport {
  incidentId: string;
  severity: IncidentSeverity;
  eventType: string;
  timestampUs: bigint;
  actor: string;
  service: string;
  details: Record<string, unknown>;
  stackTrace?: string;
}

export class IncidentEngine {
  public static createReport(
    severity: IncidentSeverity,
    eventType: string,
    details: Record<string, unknown>
  ): IncidentReport {
    const ctx = getCurrentContext();
    const err = new Error();

    return {
      incidentId: crypto.randomUUID(),
      severity,
      eventType,
      timestampUs: BigInt(Date.now() * 1000),
      actor: ctx?.actorId || 'UNKNOWN',
      service: ctx?.serviceName || 'unregistered',
      details,
      stackTrace: err.stack,
    };
  }
}
