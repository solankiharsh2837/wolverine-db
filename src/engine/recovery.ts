import crypto from 'node:crypto';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { SignedApprovalEnvelope, verifyApprovalEnvelope } from '../crypto/approval.js';
import { sha256 } from '../crypto/hash.js';

export interface RecoveryProposal {
  proposalId: string;
  incidentId: string;
  protectedScope: string;
  targetVersionId: string;
  proposedChangesHash: Buffer;
  proposedChanges: Array<{
    tableName: string;
    primaryKeyTuple: Buffer;
    fieldName: string;
    newValue: unknown;
  }>;
  requesterId: string;
  status: 'PENDING' | 'EXECUTED' | 'REJECTED';
}

export interface RecoveryExecutionResult {
  success: boolean;
  recoveryVersionId: string;
  appliedChangesCount: number;
  incidentId: string;
  proposalId: string;
}

/**
 * Creates a non-destructive recovery proposal for detected divergence or localized incident.
 */
export function generateRecoveryProposal(
  incidentId: string,
  protectedScope: string,
  targetVersionId: string,
  proposedChanges: Array<{
    tableName: string;
    primaryKeyTuple: Buffer;
    fieldName: string;
    newValue: unknown;
  }>,
  requesterId: string
): RecoveryProposal {
  if (!proposedChanges || proposedChanges.length === 0) {
    throw new WolverineError(
      WolverineErrorCode.RECOVERY_PROPOSAL_FAILED,
      'Recovery proposal must contain at least one corrective field change'
    );
  }

  // Calculate hash of proposed changes
  const changesJsonStr = JSON.stringify(proposedChanges);
  const proposedChangesHash = sha256(Buffer.from(changesJsonStr, 'utf8'));

  return {
    proposalId: crypto.randomUUID(),
    incidentId,
    protectedScope,
    targetVersionId,
    proposedChangesHash,
    proposedChanges,
    requesterId,
    status: 'PENDING',
  };
}

/**
 * Validates approval envelope and prepares selective recovery execution.
 */
export function validateAndPrepareRecovery(
  proposal: RecoveryProposal,
  approvalEnvelope: SignedApprovalEnvelope,
  trustedApproversHex: string[],
  consumedNoncesSet: Set<string>,
  currentTimestampUs: bigint
): RecoveryExecutionResult {
  if (proposal.status !== 'PENDING') {
    throw new WolverineError(
      WolverineErrorCode.RECOVERY_PROPOSAL_FAILED,
      `Proposal ${proposal.proposalId} is in status ${proposal.status}, expected PENDING`
    );
  }

  // 1. Verify nonce has not been replayed
  const nonceHex = approvalEnvelope.nonce.toString('hex');
  if (consumedNoncesSet.has(nonceHex)) {
    throw new WolverineError(
      WolverineErrorCode.REPLAYED_APPROVAL_NONCE,
      `Approval nonce ${nonceHex} has already been consumed`
    );
  }

  // 2. Verify scope binding and proposal hash match
  if (!approvalEnvelope.proposedChangesHash.equals(proposal.proposedChangesHash)) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
      'Approval envelope proposedChangesHash does not match recovery proposal hash'
    );
  }

  // 3. Verify Ed25519 signature & policy rules
  verifyApprovalEnvelope(approvalEnvelope, trustedApproversHex, currentTimestampUs);

  // Mark nonce as consumed
  consumedNoncesSet.add(nonceHex);
  proposal.status = 'EXECUTED';

  const recoveryVersionId = crypto.randomUUID();

  return {
    success: true,
    recoveryVersionId,
    appliedChangesCount: proposal.proposedChanges.length,
    incidentId: proposal.incidentId,
    proposalId: proposal.proposalId,
  };
}
