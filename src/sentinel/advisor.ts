import crypto from 'node:crypto';
import { AnomalyIncident, AdvisoryRecoveryProposal } from './types.js';
import { canonicalizeJson } from '../binary/c14n.js';

export class SentinelAdvisor {
  /**
   * Generates a non-destructive advisory recovery proposal based on an anomaly incident
   * and verified historical checkpoint reference.
   */
  public static formulateRecoveryProposal(
    incident: AnomalyIncident,
    sourceCheckpointId: string,
    targetBasisVersionId: string,
    expectedMerkleRoot: Buffer,
    expectedAnchorDigest: Buffer,
    affectedRecords: Array<{
      tableName: string;
      primaryKeyHex: string;
      fieldName: string;
      compromisedValue: unknown;
      restoredValue: unknown;
    }>,
    rationale: string
  ): AdvisoryRecoveryProposal {
    // Calculate proposed changes hash using canonical JSON
    const canonicalPayload = canonicalizeJson(affectedRecords);
    const proposedChangesHash = crypto
      .createHash('sha256')
      .update(Buffer.from(canonicalPayload, 'utf8'))
      .digest();

    return {
      proposalId: crypto.randomUUID(),
      incidentId: incident.incidentId,
      protectedScope: incident.affectedScope,
      targetBasisVersionId,
      sourceCheckpointId,
      expectedMerkleRoot,
      expectedAnchorDigest,
      affectedRecords,
      proposedChangesHash,
      confidenceScore: Math.max(80, incident.anomalyScore),
      riskAssessment: affectedRecords.length > 50 ? 'HIGH' : 'LOW',
      rationale,
      decisionAuthority: 'NONE',
      status: 'PENDING_POLICY_EVALUATION',
    };
  }
}
