export type SecurityPlane = 'DATABASE' | 'RUNTIME' | 'AEGIS_INTEL' | 'SENTINEL' | 'RECOVERY';

export type SecurityEventType =
  | 'DB_MERKLE_DIVERGENCE'
  | 'DB_HASH_CHAIN_TAMPERED'
  | 'DB_UNAUTHORIZED_MUTATION'
  | 'RUNTIME_PRIVILEGE_ESCALATION'
  | 'RUNTIME_UNFAMILIAR_SERVICE'
  | 'RUNTIME_SESSION_HIJACK'
  | 'AEGIS_THREAT_CORRELATION'
  | 'AEGIS_INFRASTRUCTURE_ALERT'
  | 'SENTINEL_ANOMALY_TRIGGER'
  | 'RECOVERY_EXECUTED';

export interface SecurityEventEnvelope {
  eventId: string; // UUID v4
  plane: SecurityPlane;
  eventType: SecurityEventType;
  timestampUs: bigint;
  actorId: string;
  serviceId: string;
  traceId?: string | undefined;
  scope: string; // e.g. "public.users"
  payload: Record<string, unknown>;
  evidenceHash: Buffer; // 32 bytes SHA-256
}

export type CorrelationNodeType =
  | 'ACTOR'
  | 'RUNTIME_CONTEXT'
  | 'DATABASE_TX'
  | 'AFFECTED_RECORD'
  | 'THREAT_INTEL'
  | 'EXTERNAL_ANCHOR';

export interface CorrelationGraphNode {
  nodeId: string;
  nodeType: CorrelationNodeType;
  label: string;
  attributes: Record<string, unknown>;
  evidenceEventId?: string | undefined;
}

export type CorrelationEdgeRelationship =
  | 'INITIATED_BY'
  | 'EXECUTED_IN_CONTEXT'
  | 'MODIFIED_RECORD'
  | 'CORRELATED_WITH'
  | 'PROVEN_BY_ANCHOR';

export interface CorrelationGraphEdge {
  sourceNodeId: string;
  targetNodeId: string;
  relationship: CorrelationEdgeRelationship;
  weight: number; // 0.0 .. 1.0
  evidenceDigest: Buffer; // 32 bytes SHA-256
}

export interface RiskFactorItem {
  score: number; // 0..100
  contribution: number; // score * weight
  evidence: string;
}

export interface RiskScoreBreakdown {
  compositeScore: number; // 0..100
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  factors: {
    stateIntegrity: RiskFactorItem;
    provenance: RiskFactorItem;
    behavioral: RiskFactorItem;
    historical: RiskFactorItem;
    externalIntel: RiskFactorItem;
  };
}

export type ResponseLevel =
  | 'LEVEL_1_OBSERVE'
  | 'LEVEL_2_FLAG'
  | 'LEVEL_3_PROPOSE'
  | 'LEVEL_4_REQUIRE_APPROVAL'
  | 'LEVEL_5_CRITICAL_DEFENSE';
