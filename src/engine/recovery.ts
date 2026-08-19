import crypto from 'node:crypto';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { SignedApprovalEnvelope, verifyApprovalEnvelope } from '../crypto/approval.js';
import { sha256 } from '../crypto/hash.js';

import { IApprovalNonceStore, formatNonceUuid } from './nonce_store.js';

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

function isNonceStore(obj: any): obj is IApprovalNonceStore {
  return obj !== null && typeof obj === 'object' && typeof obj.isConsumed === 'function' && typeof obj.recordConsumed === 'function';
}

/**
 * Validates approval envelope and prepares selective recovery execution.
 * Accepts either a durable IApprovalNonceStore or an in-memory Set<string>.
 */
export function validateAndPrepareRecovery(
  proposal: RecoveryProposal,
  approvalEnvelope: SignedApprovalEnvelope,
  trustedApproversHex: string[],
  consumedNonces: Set<string> | IApprovalNonceStore,
  currentTimestampUs: bigint
): RecoveryExecutionResult | Promise<RecoveryExecutionResult> {
  if (proposal.status !== 'PENDING') {
    throw new WolverineError(
      WolverineErrorCode.RECOVERY_PROPOSAL_FAILED,
      `Proposal ${proposal.proposalId} is in status ${proposal.status}, expected PENDING`
    );
  }

  // 1. Verify nonce has not been replayed
  if (isNonceStore(consumedNonces)) {
    const isConsumedResult = consumedNonces.isConsumed(approvalEnvelope.nonce);
    if (isConsumedResult instanceof Promise) {
      return isConsumedResult.then((consumed) => {
        if (consumed) {
          const canonical = formatNonceUuid(approvalEnvelope.nonce);
          throw new WolverineError(
            WolverineErrorCode.REPLAYED_APPROVAL_NONCE,
            `Approval nonce ${canonical} has already been consumed`
          );
        }
        return completeRecoveryValidation(
          proposal,
          approvalEnvelope,
          trustedApproversHex,
          consumedNonces,
          currentTimestampUs
        );
      });
    }

    if (isConsumedResult) {
      const canonical = formatNonceUuid(approvalEnvelope.nonce);
      throw new WolverineError(
        WolverineErrorCode.REPLAYED_APPROVAL_NONCE,
        `Approval nonce ${canonical} has already been consumed`
      );
    }
  } else {
    const nonceHex = approvalEnvelope.nonce.toString('hex');
    const canonical = formatNonceUuid(approvalEnvelope.nonce);
    if (consumedNonces.has(nonceHex) || consumedNonces.has(canonical)) {
      throw new WolverineError(
        WolverineErrorCode.REPLAYED_APPROVAL_NONCE,
        `Approval nonce ${nonceHex} has already been consumed`
      );
    }
  }

  return completeRecoveryValidation(
    proposal,
    approvalEnvelope,
    trustedApproversHex,
    consumedNonces,
    currentTimestampUs
  );
}

function completeRecoveryValidation(
  proposal: RecoveryProposal,
  approvalEnvelope: SignedApprovalEnvelope,
  trustedApproversHex: string[],
  consumedNonces: Set<string> | IApprovalNonceStore,
  currentTimestampUs: bigint
): RecoveryExecutionResult | Promise<RecoveryExecutionResult> {
  // 2. Verify scope binding and proposal hash match
  if (!approvalEnvelope.proposedChangesHash.equals(proposal.proposedChangesHash)) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
      'Approval envelope proposedChangesHash does not match recovery proposal hash'
    );
  }

  // 3. Verify Ed25519 signature & policy rules
  verifyApprovalEnvelope(approvalEnvelope, trustedApproversHex, currentTimestampUs);

  // 4. Mark nonce as consumed
  if (isNonceStore(consumedNonces)) {
    const recordResult = consumedNonces.recordConsumed(
      approvalEnvelope.nonce,
      proposal.incidentId,
      approvalEnvelope.approverPubkey
    );
    if (recordResult instanceof Promise) {
      return recordResult.then(() => {
        proposal.status = 'EXECUTED';
        const recoveryVersionId = crypto.randomUUID();
        return {
          success: true,
          recoveryVersionId,
          appliedChangesCount: proposal.proposedChanges.length,
          incidentId: proposal.incidentId,
          proposalId: proposal.proposalId,
        };
      });
    }
  } else {
    const nonceHex = approvalEnvelope.nonce.toString('hex');
    consumedNonces.add(nonceHex);
  }

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

/**
 * Async version of validateAndPrepareRecovery for explicit async callers.
 */
export async function validateAndPrepareRecoveryAsync(
  proposal: RecoveryProposal,
  approvalEnvelope: SignedApprovalEnvelope,
  trustedApproversHex: string[],
  consumedNonces: Set<string> | IApprovalNonceStore,
  currentTimestampUs: bigint
): Promise<RecoveryExecutionResult> {
  return await validateAndPrepareRecovery(
    proposal,
    approvalEnvelope,
    trustedApproversHex,
    consumedNonces,
    currentTimestampUs
  );
}
