import { SecurityEventEnvelope, ResponseLevel } from './types.js';
import { computeDistributedIncidentId } from './events.js';
import { IncidentCorrelationGraph } from './correlation_graph.js';
import { DistributedRiskEngine, RiskInputSignals } from './risk_engine.js';
import { AnomalyIncident } from '../sentinel/types.js';

export class SecurityFabricCoordinator {
  private activeIncidents = new Map<string, IncidentCorrelationGraph>();

  /**
   * Correlates an incoming security event into a distributed incident.
   */
  public correlateEvent(event: SecurityEventEnvelope): {
    incidentId: string;
    graph: IncidentCorrelationGraph;
  } {
    const incidentId = computeDistributedIncidentId(
      event.plane,
      event.eventId,
      event.timestampUs,
      event.scope
    );

    let graph = this.activeIncidents.get(incidentId);
    if (!graph) {
      graph = new IncidentCorrelationGraph(incidentId);
      this.activeIncidents.set(incidentId, graph);
    }

    graph.ingestSecurityEvent(event);
    return { incidentId, graph };
  }

  /**
   * Evaluates the risk of a correlated incident and determines coordinated response level.
   */
  public evaluateIncidentRisk(
    _incidentId: string,
    signals: RiskInputSignals
  ): {
    riskBreakdown: ReturnType<typeof DistributedRiskEngine.evaluateRisk>;
    responseLevel: ResponseLevel;
  } {
    const riskBreakdown = DistributedRiskEngine.evaluateRisk(signals);
    const responseLevel = DistributedRiskEngine.mapResponseLevel(riskBreakdown.compositeScore);

    return {
      riskBreakdown,
      responseLevel,
    };
  }

  /**
   * Converts a correlated fabric incident into a canonical AnomalyIncident for Sentinel advisory consumption.
   */
  public synthesizeFabricAnomalyIncident(
    incidentId: string,
    event: SecurityEventEnvelope,
    riskScore: number,
    explanation: string
  ): AnomalyIncident {
    return {
      incidentId,
      timestampUs: event.timestampUs,
      actorId: event.actorId,
      serviceId: event.serviceId,
      affectedScope: event.scope,
      classification: 'SUSPECTED_UNAUTHORIZED_MUTATION',
      severity: riskScore >= 80 ? 'CRITICAL' : riskScore >= 60 ? 'HIGH' : 'MEDIUM',
      anomalyScore: riskScore,
      affectedRecordIds: Array.isArray(event.payload.recordIds) ? (event.payload.recordIds as string[]) : [],
      observedMutationCount: Array.isArray(event.payload.recordIds) ? event.payload.recordIds.length : 1,
      evidenceRefs: {
        rawLogSnippet: `Fabric Event: ${event.eventType} on plane ${event.plane}`,
      },
      narrativeExplanation: explanation,
    };
  }
}
