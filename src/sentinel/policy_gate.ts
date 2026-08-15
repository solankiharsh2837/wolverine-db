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
      if (!record.tableName.startsWith(proposal.protectedScope) && !proposal.protectedScope.includes(record.tableName)) {
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

    // 3. Verifiable Basis & External Anchor Invariant
    const vaultChk = await externalVaultStore.get(proposal.sourceCheckpointId);
    if (!vaultChk) {
      proposal.status = 'POLICY_REJECTED';
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
        `PolicyGate: Source checkpoint ${proposal.sourceCheckpointId} not found in external vault store`
      );
    }

    if (!timingSafeEqualHashes(vaultChk.merkleRoot, proposal.expectedMerkleRoot)) {
      proposal.status = 'POLICY_REJECTED';
      throw new WolverineError(
        WolverineErrorCode.MERKLE_ROOT_MISMATCH,
        'PolicyGate: Vault checkpoint Merkle root does not match proposal expected Merkle root'
      );
    }

    // 4. Verify against public blockchain anchor
    const anchorRecord = await evmAnchorAdapter.getAnchor(proposal.sourceCheckpointId);
    if (!anchorRecord) {
      proposal.status = 'POLICY_REJECTED';
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_UNAVAILABLE,
        `PolicyGate: Source checkpoint ${proposal.sourceCheckpointId} has no corresponding public blockchain anchor`
      );
    }

    if (!timingSafeEqualHashes(anchorRecord.checkpointDigest, proposal.expectedAnchorDigest)) {
      proposal.status = 'POLICY_REJECTED';
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
        'PolicyGate: Blockchain anchor digest does not match proposal expected anchor digest'
      );
    }

    proposal.status = 'POLICY_APPROVED';
    return {
      allowed: true,
      verdict: 'ALLOW_PROPOSAL',
      reason: 'Proposal satisfies all cryptographic basis, scope bounding, and anchor invariants.',
      evaluatedProposal: proposal,
    };
  }
}
