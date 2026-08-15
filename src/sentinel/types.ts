export type AnomalySeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type AnomalyClassification =
  | 'SUSPECTED_UNAUTHORIZED_MUTATION'
  | 'OUT_OF_WINDOW_DBA_ACTIVITY'
  | 'SCOPE_EXPANSION_VIOLATION'
  | 'BULK_ROLE_OR_BALANCE_MODIFICATION'
  | 'MISSING_PROVENANCE_TICKET'
  | 'CROSS_DOMAIN_STATE_DIVERGENCE'
  | 'BASELINE_INTEGRITY_TAMPERED';

export type SafetyMode = 'ADVISORY' | 'PROPOSE' | 'APPROVAL_GATED_EXECUTE';

export interface MaintenanceWindow {
  startUtcHour: number; // 0..23
  endUtcHour: number;   // 0..23
  daysOfWeek: number[]; // 0=Sunday..6=Saturday
}

export interface ActorBaselineProfile {
  actorId: string;
  allowedScopes: string[];
  typicalOperations: number[]; // 1=INSERT, 2=UPDATE, 3=DELETE
  maintenanceWindows: MaintenanceWindow[];
  maxMutationsPerMinute: number;
  averageBatchSize: number;
  requiresTicketProvenance: boolean;
  baselineHash: Buffer; // 32 bytes SHA-256
}

export interface AnomalyIncident {
  incidentId: string; // UUID v4
  timestampUs: bigint;
  actorId: string;
  serviceId: string;
  affectedScope: string;
  classification: AnomalyClassification;
  severity: AnomalySeverity;
  anomalyScore: number; // 0..100
  affectedRecordIds: string[];
  observedMutationCount: number;
  evidenceRefs: {
    checkpointId?: string;
    localMerkleRootHex?: string;
    expectedAnchorDigestHex?: string;
    baselineHashHex?: string;
    rawLogSnippet?: string;
  };
  narrativeExplanation: string;
}

export interface AdvisoryRecoveryProposal {
  proposalId: string; // UUID v4
  incidentId: string;
  protectedScope: string;
  targetBasisVersionId: string;
  sourceCheckpointId: string;
  expectedMerkleRoot: Buffer; // 32 bytes
  expectedAnchorDigest: Buffer; // 32 bytes
  affectedRecords: Array<{
    tableName: string;
    primaryKeyHex: string;
    fieldName: string;
    compromisedValue: unknown;
    restoredValue: unknown;
  }>;
  proposedChangesHash: Buffer; // 32 bytes
  confidenceScore: number; // 0..100
  riskAssessment: 'LOW' | 'MEDIUM' | 'HIGH';
  rationale: string;
  decisionAuthority: 'NONE';
  status: 'PENDING_POLICY_EVALUATION' | 'POLICY_APPROVED' | 'POLICY_REJECTED';
}
