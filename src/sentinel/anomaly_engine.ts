import crypto from 'node:crypto';
import { AnomalyIncident, AnomalySeverity, AnomalyClassification } from './types.js';
import { BaselineTracker } from './baseline.js';

export interface MutationTelemetryEvent {
  actorId: string;
  serviceId: string;
  scope: string; // "public.users"
  operation: number; // 1=I, 2=U, 3=D
  recordIds: string[];
  utcHour: number;
  dayOfWeek: number;
  ticketId?: string;
  mutationRatePerMin?: number;
}

export class SentinelAnomalyEngine {
  private baselineTracker: BaselineTracker;

  constructor(baselineTracker: BaselineTracker) {
    this.baselineTracker = baselineTracker;
  }

  /**
   * Analyzes an incoming mutation event against baseline models and generates an AnomalyIncident if suspicious.
   */
  public analyzeMutation(event: MutationTelemetryEvent): AnomalyIncident | null {
    const isBaselineValid = this.baselineTracker.verifyBaselineIntegrity(event.actorId);
    if (!isBaselineValid && this.baselineTracker.getBaseline(event.actorId) !== null) {
      return this.createIncident(
        event,
        'BASELINE_INTEGRITY_TAMPERED',
        'CRITICAL',
        100,
        `Actor baseline profile for "${event.actorId}" failed cryptographic hash verification (suspected tampering).`
      );
    }

    const baseline = this.baselineTracker.getBaseline(event.actorId);
    if (!baseline) {
      // Unregistered actor modifying protected scope
      return this.createIncident(
        event,
        'SUSPECTED_UNAUTHORIZED_MUTATION',
        'HIGH',
        75,
        `Unregistered actor "${event.actorId}" executed mutations on protected scope "${event.scope}".`
      );
    }

    let anomalyScore = 0;
    const anomalyReasons: string[] = [];
    let classification: AnomalyClassification = 'SUSPECTED_UNAUTHORIZED_MUTATION';

    // 1. Scope check (Highest Priority)
    if (!baseline.allowedScopes.includes(event.scope)) {
      anomalyScore += 40;
      anomalyReasons.push(`Scope violation: "${event.scope}" not in allowed list [${baseline.allowedScopes.join(', ')}]`);
      classification = 'SCOPE_EXPANSION_VIOLATION';
    }

    // 2. Maintenance window check
    const inWindow = baseline.maintenanceWindows.some(
      (w) =>
        w.daysOfWeek.includes(event.dayOfWeek) &&
        event.utcHour >= w.startUtcHour &&
        event.utcHour <= w.endUtcHour
    );

    if (!inWindow && baseline.maintenanceWindows.length > 0) {
      anomalyScore += 35;
      anomalyReasons.push(`Out-of-window activity: UTC hour ${event.utcHour} on day ${event.dayOfWeek} is outside registered maintenance windows.`);
      if (classification === 'SUSPECTED_UNAUTHORIZED_MUTATION') {
        classification = 'OUT_OF_WINDOW_DBA_ACTIVITY';
      }
    }

    // 3. Ticket provenance check
    if (baseline.requiresTicketProvenance && !event.ticketId) {
      anomalyScore += 25;
      anomalyReasons.push('Missing required change management ticket ID.');
    }

    // 4. Rate check
    if (event.mutationRatePerMin && event.mutationRatePerMin > baseline.maxMutationsPerMinute * 3) {
      anomalyScore += 20;
      anomalyReasons.push(`Velocity spike: ${event.mutationRatePerMin} mut/min exceeds 3x baseline limit (${baseline.maxMutationsPerMinute}).`);
    }

    // 5. Bulk modification of critical columns
    if (event.recordIds.length >= 10 && event.operation === 2) {
      anomalyScore += 25;
      anomalyReasons.push(`Bulk update anomaly: ${event.recordIds.length} records updated in single batch.`);
      if (classification === 'SUSPECTED_UNAUTHORIZED_MUTATION') {
        classification = 'BULK_ROLE_OR_BALANCE_MODIFICATION';
      }
    }

    if (anomalyScore >= 40) {
      const severity: AnomalySeverity =
        anomalyScore >= 70 ? 'CRITICAL' : anomalyScore >= 50 ? 'HIGH' : 'MEDIUM';

      return this.createIncident(
        event,
        classification,
        severity,
        Math.min(100, anomalyScore),
        anomalyReasons.join(' ')
      );
    }

    return null;
  }

  private createIncident(
    event: MutationTelemetryEvent,
    classification: AnomalyClassification,
    severity: AnomalySeverity,
    anomalyScore: number,
    explanation: string
  ): AnomalyIncident {
    return {
      incidentId: crypto.randomUUID(),
      timestampUs: BigInt(Date.now()) * 1000n,
      actorId: event.actorId,
      serviceId: event.serviceId,
      affectedScope: event.scope,
      classification,
      severity,
      anomalyScore,
      affectedRecordIds: [...event.recordIds],
      observedMutationCount: event.recordIds.length,
      evidenceRefs: {
        rawLogSnippet: `Actor: ${event.actorId}, Op: ${event.operation}, Scope: ${event.scope}`,
      },
      narrativeExplanation: explanation,
    };
  }
}
