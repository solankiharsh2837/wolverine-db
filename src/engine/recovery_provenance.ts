import { RecoveryProposal, RecoveryExecutionResult, validateAndPrepareRecovery } from './recovery.js';
import { IApprovalNonceStore } from './nonce_store.js';
import { SignedApprovalEnvelope } from '../crypto/approval.js';
import { CheckpointStore, AnchoredCheckpoint } from '../checkpoint/types.js';
import { CheckpointAnchorEngine } from '../checkpoint/anchor.js';

export interface RecoveryProvenanceAuditTrail {
  incidentId: string;
  proposalId: string;
  targetVersionId: string;
  requesterId: string;
  approverPubkeyHex: string;
  executionTimestampUs: bigint;
  postRecoveryCheckpoint: AnchoredCheckpoint;
  auditStatus: 'PROVABLY_CORRECT' | 'APPROVAL_TAMPERED' | 'UNANCHORED';
}

export class RecoveryProvenanceEngine {
  /**
   * Executes a recovery proposal with full provenance tracking and immediate external anchoring.
   */
  public static async executeWithProvenance(
    proposal: RecoveryProposal,
    approvalEnvelope: SignedApprovalEnvelope,
    trustedApprovers: Buffer[],
    consumedNonces: Set<string> | IApprovalNonceStore,
    externalStore: CheckpointStore,
    currentSeq: bigint,
    preIncidentMerkleRoot: Buffer,
    previousCheckpointId: string | null = null
  ): Promise<{ result: RecoveryExecutionResult; auditTrail: RecoveryProvenanceAuditTrail }> {
    const nowUs = BigInt(Date.now()) * 1000n;
    const trustedApproversHex = trustedApprovers.map((k) => k.toString('hex'));

    // 1. Execute recovery under WDB-0006 approval rules
    const result = await validateAndPrepareRecovery(
      proposal,
      approvalEnvelope,
      trustedApproversHex,
      consumedNonces,
      nowUs
    );

    // 2. Emit and anchor post-recovery checkpoint to external store under WDB-0012 & WDB-0013
    const postRecoveryCheckpoint = await CheckpointAnchorEngine.anchorCheckpoint(externalStore, {
      checkpointId: `chk-recov-${proposal.incidentId.slice(0, 8)}`,
      scope: proposal.protectedScope,
      commitSeq: currentSeq + 1n,
      previousCheckpointId,
      merkleRoot: preIncidentMerkleRoot,
      changeChainHead: proposal.proposedChangesHash,
      createdAtUs: nowUs,
      protocolVersion: 2,
    });

    const auditTrail: RecoveryProvenanceAuditTrail = {
      incidentId: proposal.incidentId,
      proposalId: proposal.proposalId,
      targetVersionId: proposal.targetVersionId,
      requesterId: proposal.requesterId,
      approverPubkeyHex: approvalEnvelope.approverPubkey.toString('hex'),
      executionTimestampUs: nowUs,
      postRecoveryCheckpoint,
      auditStatus: 'PROVABLY_CORRECT',
    };

    return { result, auditTrail };
  }

  /**
   * Validates an entire historical recovery provenance audit trail
   */
  public static async auditRecoveryLineage(
    auditTrail: RecoveryProvenanceAuditTrail,
    trustedApprovers: Buffer[],
    externalStore: CheckpointStore
  ): Promise<boolean> {
    // 1. Verify that approver is in trusted approvers
    const approverBuf = Buffer.from(auditTrail.approverPubkeyHex, 'hex');
    const isTrusted = trustedApprovers.some((key) => Buffer.compare(key, approverBuf) === 0);
    if (!isTrusted) {
      return false;
    }

    // 2. Verify that post-recovery checkpoint exists and is valid in external store
    const isValidCheckpoint = await externalStore.verify(auditTrail.postRecoveryCheckpoint.checkpointId);
    return isValidCheckpoint;
  }
}
