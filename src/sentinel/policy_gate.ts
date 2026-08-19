import crypto from 'node:crypto';
import { AdvisoryRecoveryProposal } from './types.js';
import { CheckpointStore } from '../checkpoint/types.js';
import { EvmAnchorAdapter } from '../anchors/evm.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface PolicyGateResult {
  allowed: boolean;
  verdict: 'ALLOW_PROPOSAL' | 'REJECT_PROPOSAL';
  reason: string;
  evaluatedProposal: AdvisoryRecoveryProposal;
}

/**
 * Strictly evaluates whether a table belongs to a protected scope without substring/prefix leakage.
 */
export function matchesProtectedScope(tableName: string, protectedScope: string): boolean {
  if (!tableName || !protectedScope) return false;
  if (protectedScope === '*' || protectedScope === 'global') return true;
  if (protectedScope === tableName) return true;

  if (protectedScope.endsWith('.*')) {
    const schema = protectedScope.slice(0, -2);
    return tableName.startsWith(schema + '.') && tableName.lastIndexOf('.') === schema.length;
  }

  return false;
}

export class PolicyGate {
  /**
   * Evaluates an advisory proposal against mathematical and cryptographic invariants.
   */
  public static async evaluateProposal(
    proposal: AdvisoryRecoveryProposal,
    externalVaultStore: CheckpointStore,
    evmAnchorAdapter: EvmAnchorAdapter,
    registeredScopes: string[]
  ): Promise<PolicyGateResult> {
    // 1. Strict Scope Bounding
    if (!registeredScopes.includes(proposal.protectedScope)) {
      proposal.status = 'POLICY_REJECTED';
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `PolicyGate: Scope "${proposal.protectedScope}" is not in registered protected scopes [${registeredScopes.join(', ')}]`
      );
    }

    for (const record of proposal.affectedRecords) {
      if (!matchesProtectedScope(record.tableName, proposal.protectedScope)) {
        proposal.status = 'POLICY_REJECTED';
        throw new WolverineError(
          WolverineErrorCode.UNAUTHORIZED_MUTATION,
          `PolicyGate: Affected record table "${record.tableName}" breaches proposal scope "${proposal.protectedScope}"`
        );
      }
    }

    // 2. Non-Speculative Payload Hash Invariant
    const canonicalPayload = canonicalizeJson(proposal.affectedRecords);
    const computedChangesHash = crypto
      .createHash('sha256')
      .update(Buffer.from(canonicalPayload, 'utf8'))
      .digest();

    if (!timingSafeEqualHashes(computedChangesHash, proposal.proposedChangesHash)) {
      proposal.status = 'POLICY_REJECTED';
      throw new WolverineError(
        WolverineErrorCode.CHANGE_HASH_MISMATCH,
        'PolicyGate: Recomputed proposed changes hash does not match proposal commitment'
      );
    }

    // 3. Verifiable Basis & External Store Immutability Invariant
    const basisCheckpoint = await externalVaultStore.get(proposal.sourceCheckpointId);
    if (!basisCheckpoint) {
      proposal.status = 'POLICY_REJECTED';
      throw new WolverineError(
        WolverineErrorCode.UNTRUSTED_RECOVERY_BASIS,
        `PolicyGate: Basis checkpoint ${proposal.sourceCheckpointId} not found in trusted store`
      );
    }

    // Explicitly verify cryptographic integrity and WORM immutability in the store
    const isStoreImmutablyValid = await externalVaultStore.verify(proposal.sourceCheckpointId);
    if (!isStoreImmutablyValid) {
      proposal.status = 'POLICY_REJECTED';
      throw new WolverineError(
        WolverineErrorCode.UNTRUSTED_RECOVERY_BASIS,
        `PolicyGate: Basis checkpoint ${proposal.sourceCheckpointId} failed cryptographic immutability verification in external store`
      );
    }

    if (!timingSafeEqualHashes(basisCheckpoint.merkleRoot, proposal.expectedMerkleRoot)) {
      proposal.status = 'POLICY_REJECTED';
      throw new WolverineError(
        WolverineErrorCode.MERKLE_ROOT_MISMATCH,
        'PolicyGate: Basis checkpoint Merkle root does not match proposal expectation'
      );
    }

    // 4. Verifiable External Ethereum Anchor Check
    const anchor = await evmAnchorAdapter.getAnchor(proposal.sourceCheckpointId);
    if (!anchor || anchor.status !== 'FINALIZED') {
      proposal.status = 'POLICY_REJECTED';
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
        `PolicyGate: Target basis checkpoint ${proposal.sourceCheckpointId} has no finalized EVM anchor`
      );
    }

    if (!timingSafeEqualHashes(anchor.checkpointDigest, proposal.expectedAnchorDigest)) {
      proposal.status = 'POLICY_REJECTED';
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
        'PolicyGate: On-chain anchor digest does not match proposal expectation'
      );
    }

    // 5. Blast Radius Cap Invariant (Max 1000 records per autonomous proposal)
    const MAX_AUTONOMOUS_BLAST_RADIUS = 1000;
    if (proposal.affectedRecords.length > MAX_AUTONOMOUS_BLAST_RADIUS) {
      proposal.status = 'POLICY_REJECTED';
      throw new WolverineError(
        WolverineErrorCode.RECOVERY_PROPOSAL_FAILED,
        `PolicyGate: Blast radius exceeded (${proposal.affectedRecords.length} > ${MAX_AUTONOMOUS_BLAST_RADIUS})`
      );
    }

    // 6. Atomic Pre-Approval TOCTOU Re-verification
    // Re-verify basis checkpoint and EVM anchor immediately prior to granting approval
    const preApprovalCheckpoint = await externalVaultStore.get(proposal.sourceCheckpointId);
    if (
      !preApprovalCheckpoint ||
      !timingSafeEqualHashes(preApprovalCheckpoint.merkleRoot, proposal.expectedMerkleRoot) ||
      !timingSafeEqualHashes(preApprovalCheckpoint.digest, basisCheckpoint.digest)
    ) {
      proposal.status = 'POLICY_REJECTED';
      throw new WolverineError(
        WolverineErrorCode.UNTRUSTED_RECOVERY_BASIS,
        `PolicyGate: TOCTOU violation - Basis checkpoint ${proposal.sourceCheckpointId} modified or invalidated prior to final approval`
      );
    }

    const preApprovalAnchor = await evmAnchorAdapter.getAnchor(proposal.sourceCheckpointId);
    if (
      !preApprovalAnchor ||
      preApprovalAnchor.status !== 'FINALIZED' ||
      !timingSafeEqualHashes(preApprovalAnchor.checkpointDigest, proposal.expectedAnchorDigest)
    ) {
      proposal.status = 'POLICY_REJECTED';
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
        `PolicyGate: TOCTOU violation - EVM anchor for ${proposal.sourceCheckpointId} modified or unfinalized prior to final approval`
      );
    }

    proposal.status = 'POLICY_APPROVED';
    const evaluatedProposal: AdvisoryRecoveryProposal = {
      ...proposal,
      status: 'POLICY_APPROVED',
    };

    return {
      allowed: true,
      verdict: 'ALLOW_PROPOSAL',
      reason: 'All mathematical and cryptographic policy invariants satisfied',
      evaluatedProposal,
    };
  }
}
