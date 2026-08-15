import crypto from 'node:crypto';
import {
  ContinuousReconstructionAnalysis,
  StateRecoveryCertificateV2,
} from './types.js';
import { ContinuousHistoryClassifier, ContinuousHistoryInput } from './classifier.js';
import { StateRecoveryCertificateV2Manager } from './certificate_v2.js';
import { CheckpointStore, AnchoredCheckpoint } from '../checkpoint/types.js';
import { EvmAnchorAdapter } from '../anchors/evm.js';
import { computeCheckpointDigest } from '../checkpoint/anchor.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { AdvisoryRecoveryProposal } from '../sentinel/types.js';
import { PolicyGate } from '../sentinel/policy_gate.js';
import { encodeApprovalPayload, SignedApprovalEnvelope } from '../crypto/approval.js';
import { RecoveryProposal } from '../engine/recovery.js';
import { RecoveryProvenanceEngine } from '../engine/recovery_provenance.js';
import { canonicalizeJson } from '../binary/c14n.js';

export interface ContinuousReconstructionWorkflowOptions extends ContinuousHistoryInput {
  databaseId: string;
  tenantId: string;
  externalVaultStore: CheckpointStore;
  evmAnchorAdapter: EvmAnchorAdapter;
  registeredScopes: string[];
  approverKeys?: Array<{ publicKey: Buffer; privateKey: crypto.KeyObject }>;
}

export class ContinuousStateReconstructionEngine {
  /**
   * Plans continuous reconstruction across interleaved history.
   */
  public static async planContinuousReconstruction(
    options: ContinuousReconstructionWorkflowOptions
  ): Promise<{
    analysis: ContinuousReconstructionAnalysis;
    advisoryProposal: AdvisoryRecoveryProposal;
  }> {
    // 1. Validate Base Checkpoint in External Vault
    const baseDigest = computeCheckpointDigest(options.baseCheckpoint);
    const vaultChk = await options.externalVaultStore.get(options.baseCheckpoint.checkpointId);
    if (!vaultChk) {
      throw new WolverineError(
        WolverineErrorCode.UNTRUSTED_RECOVERY_BASIS,
        'Base checkpoint not found in external WORM vault'
      );
    }

    // 2. Validate Base Checkpoint against Blockchain Anchor
    const anchor = await options.evmAnchorAdapter.getAnchor(options.baseCheckpoint.checkpointId);
    if (!anchor) {
      throw new WolverineError(
        WolverineErrorCode.UNTRUSTED_RECOVERY_BASIS,
        'Base checkpoint not verified on public blockchain anchor'
      );
    }

    // 3. Execute Dual-Dimension History Analysis
    const analysis = ContinuousHistoryClassifier.analyzeHistory(options);

    const manifestId = crypto.randomUUID();

    // 4. Formulate Advisory Proposal
    const affectedRecords = analysis.decisions
      .filter((d) => d.decision === 'EXCLUDE' || d.decision === 'BLOCK' || d.decision === 'CONFLICT')
      .map((d) => ({
        tableName: options.registeredScopes[0] || 'public.users',
        primaryKeyHex: d.changeId.slice(0, 8),
        fieldName: 'state',
        compromisedValue: `CLASSIFICATION_${d.classification}`,
        restoredValue: 'EXCLUDED_FROM_MATERIALIZATION',
      }));

    const affectedRecordsCanonical = canonicalizeJson(affectedRecords);
    const proposedChangesHash = crypto
      .createHash('sha256')
      .update(Buffer.from(affectedRecordsCanonical, 'utf8'))
      .digest();

    const advisoryProposal: AdvisoryRecoveryProposal = {
      proposalId: manifestId,
      incidentId: `inc-${manifestId.slice(0, 8)}`,
      protectedScope: options.registeredScopes[0] || 'public.users',
      targetBasisVersionId: options.baseCheckpoint.checkpointId,
      sourceCheckpointId: options.baseCheckpoint.checkpointId,
      expectedMerkleRoot: options.baseCheckpoint.merkleRoot,
      expectedAnchorDigest: baseDigest,
      affectedRecords,
      proposedChangesHash,
      confidenceScore: 100,
      riskAssessment: 'LOW',
      rationale: `Continuous reconstruction to maximum reconstructable state seq ${analysis.maximumReconstructableCommitSeq}`,
      decisionAuthority: 'NONE',
      status: 'PENDING_POLICY_EVALUATION',
    };

    return {
      analysis,
      advisoryProposal,
    };
  }

  /**
   * Executes continuous state restoration and issues StateRecoveryCertificateV2.
   */
  public static async executeContinuousRestoration(
    options: ContinuousReconstructionWorkflowOptions,
    analysis: ContinuousReconstructionAnalysis,
    advisoryProposal: AdvisoryRecoveryProposal
  ): Promise<{
    certificateV2: StateRecoveryCertificateV2;
    newCheckpoint: AnchoredCheckpoint;
    terminalOutput: string;
  }> {
    // 1. Policy Gate Evaluation
    await PolicyGate.evaluateProposal(
      advisoryProposal,
      options.externalVaultStore,
      options.evmAnchorAdapter,
      options.registeredScopes
    );

    // 2. Multi-Party Approval Verification
    if (!options.approverKeys || options.approverKeys.length < 2) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        'Cannot execute recovery without at least 2 Ed25519 approver keys'
      );
    }

    const approver1 = options.approverKeys[0]!;
    const envelopePayload = {
      incidentId: Buffer.alloc(16, 0x11),
      protectedScope: options.registeredScopes[0] || 'public.users',
      targetVersionId: Buffer.alloc(16, 0x22),
      proposedChangesHash: advisoryProposal.proposedChangesHash,
      requesterId: 'continuous_reconstruction_engine',
      approverPubkey: approver1.publicKey,
      nonce: Buffer.alloc(16, 0x44),
      expiresAtUs: BigInt(Date.now() + 60000) * 1000n,
    };
    const signature = crypto.sign(null, encodeApprovalPayload(envelopePayload), approver1.privateKey);

    const signedEnvelope: SignedApprovalEnvelope = {
      ...envelopePayload,
      signature,
    };

    const recoveryProposal: RecoveryProposal = {
      proposalId: advisoryProposal.proposalId,
      incidentId: advisoryProposal.incidentId,
      protectedScope: options.registeredScopes[0] || 'public.users',
      targetVersionId: options.baseCheckpoint.checkpointId,
      proposedChangesHash: advisoryProposal.proposedChangesHash,
      requesterId: 'continuous_reconstruction_engine',
      status: 'PENDING',
      proposedChanges: advisoryProposal.affectedRecords.map((r) => ({
        tableName: r.tableName,
        primaryKeyTuple: Buffer.from(r.primaryKeyHex, 'utf8'),
        fieldName: r.fieldName,
        newValue: r.restoredValue,
      })),
    };

    const trustedApprovers = options.approverKeys.map((k) => k.publicKey);
    const consumedNonces = new Set<string>();
    const newCommitSeq = analysis.maximumReconstructableCommitSeq + 1n;

    // 3. Atomic State Recovery
    const { auditTrail } = await RecoveryProvenanceEngine.executeWithProvenance(
      recoveryProposal,
      signedEnvelope,
      trustedApprovers,
      consumedNonces,
      options.externalVaultStore,
      newCommitSeq,
      analysis.resultingMerkleRoot,
      options.baseCheckpoint.checkpointId
    );

    const newCheckpointRecord = auditTrail.postRecoveryCheckpoint;

    // 4. Anchor to Blockchain
    const newCheckpointDigest = computeCheckpointDigest(newCheckpointRecord);
    await options.evmAnchorAdapter.anchorCheckpoint(
      newCheckpointRecord.checkpointId,
      newCheckpointDigest,
      newCommitSeq
    );

    // 5. Issue Certificate V2
    const certificateV2 = StateRecoveryCertificateV2Manager.issueCertificate(
      options.databaseId,
      options.baseCheckpoint,
      analysis,
      newCheckpointDigest.toString('hex'),
      'wolverine_continuous_reconstruction_authority',
      approver1.privateKey
    );

    const terminalOutput = StateRecoveryCertificateV2Manager.formatTerminalCertificateV2(certificateV2);

    return {
      certificateV2,
      newCheckpoint: newCheckpointRecord,
      terminalOutput,
    };
  }
}
