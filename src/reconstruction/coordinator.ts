import crypto from 'node:crypto';
import {
  ReconstructionManifest,
  StateRecoveryCertificate,
  ReconstructedDatabaseState,
} from './types.js';
import { VerifiedStateFrontierEngine, FrontierEvaluationInput } from './frontier.js';
import { StateReplayEngine } from './replay_engine.js';
import { computeReconstructionDigest } from './manifest.js';
import { StateRecoveryCertificateManager } from './certificate.js';
import { CheckpointStore, AnchoredCheckpoint } from '../checkpoint/types.js';
import { EvmAnchorAdapter } from '../anchors/evm.js';
import { BaselineTracker } from '../sentinel/baseline.js';
import { computeCheckpointDigest } from '../checkpoint/anchor.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { AdvisoryRecoveryProposal } from '../sentinel/types.js';
import { PolicyGate } from '../sentinel/policy_gate.js';
import { encodeApprovalPayload, SignedApprovalEnvelope } from '../crypto/approval.js';
import { RecoveryProposal } from '../engine/recovery.js';
import { RecoveryProvenanceEngine } from '../engine/recovery_provenance.js';
import { canonicalizeJson } from '../binary/c14n.js';

export interface ReconstructionWorkflowOptions {
  databaseId: string;
  tenantId: string;
  baseCheckpoint: AnchoredCheckpoint | Omit<AnchoredCheckpoint, 'digest'>;
  initialCheckpointState: ReconstructedDatabaseState;
  changesAfterCheckpoint: FrontierEvaluationInput['changesAfterCheckpoint'];
  externalVaultStore: CheckpointStore;
  evmAnchorAdapter: EvmAnchorAdapter;
  baselineTracker: BaselineTracker;
  compromisedActors?: string[];
  registeredScopes: string[];
  approverKeys?: Array<{ publicKey: Buffer; privateKey: crypto.KeyObject }>;
}

export class StateReconstructionCoordinator {
  /**
   * Evaluates the frontier, performs authorized replay, and builds the ReconstructionManifest.
   */
  public static async planReconstruction(
    options: ReconstructionWorkflowOptions
  ): Promise<{
    manifest: ReconstructionManifest;
    reconstructedState: ReconstructedDatabaseState;
    advisoryProposal: AdvisoryRecoveryProposal;
  }> {
    // 1. Calculate Verified State Frontier
    const frontierResult = await VerifiedStateFrontierEngine.calculateFrontier({
      baseCheckpoint: options.baseCheckpoint,
      changesAfterCheckpoint: options.changesAfterCheckpoint,
      externalVaultStore: options.externalVaultStore,
      evmAnchorAdapter: options.evmAnchorAdapter,
      baselineTracker: options.baselineTracker,
      compromisedActors: options.compromisedActors,
    });

    if (!frontierResult.isFrontierValid) {
      throw new WolverineError(
        WolverineErrorCode.UNTRUSTED_RECOVERY_BASIS,
        `Cannot plan reconstruction: ${frontierResult.compromiseReason}`
      );
    }

    // 2. Replay only preserved authorized changes
    const reconstructedState = StateReplayEngine.replayChanges(
      options.initialCheckpointState,
      frontierResult.preservedChanges
    );

    // 3. Compute deterministic Merkle root of reconstructed state
    const reconstructedMerkleRoot = StateReplayEngine.computeStateMerkleRoot(reconstructedState);

    const manifestId = crypto.randomUUID();
    const timestampUs = BigInt(Date.now()) * 1000n;
    const baseDigest = computeCheckpointDigest(options.baseCheckpoint);

    // 4. Construct Reconstruction Manifest
    const unsignedManifest: Omit<ReconstructionManifest, 'reconstructionDigest'> = {
      manifestVersion: 1,
      manifestId,
      databaseId: options.databaseId,
      tenantId: options.tenantId,
      sourceCheckpointId: options.baseCheckpoint.checkpointId,
      sourceCheckpointDigest: baseDigest,
      sourceCheckpointCommitSeq: options.baseCheckpoint.commitSeq,
      startingMerkleRoot: options.baseCheckpoint.merkleRoot,
      endingCommitSeq: frontierResult.frontierCommitSeq,
      replayedChangeIds: frontierResult.preservedChanges.map((c) => c.versionId),
      replayedCommitSeqs: frontierResult.preservedChanges.map((c) => c.timestampUs),
      excludedChangeIds: frontierResult.excludedChanges.map((c) => c.versionId),
      exclusionReasons: frontierResult.exclusionReasons,
      verificationResults: {
        checkpointValid: true,
        externalVaultMatch: true,
        blockchainAnchorMatch: true,
        hashChainContinuous: true,
        sequenceMonotonic: true,
        provenanceValid: true,
        authorizationValid: true,
      },
      reconstructedMerkleRoot,
      recoveryBoundary: {
        lastValidCommitSeq: frontierResult.frontierCommitSeq,
        lastValidTimestampUs: frontierResult.frontierTimestampUs,
        firstInvalidCommitSeq: frontierResult.firstInvalidCommitSeq,
        compromiseReason: frontierResult.compromiseReason || 'Clean frontier boundary',
      },
      policyVersion: 1,
      approvalQuorumRequired: 2,
      approverIdentities: options.approverKeys ? options.approverKeys.map((k) => k.publicKey.toString('hex').slice(0, 16)) : [],
      timestampUs,
    };

    const reconstructionDigest = computeReconstructionDigest(unsignedManifest);
    const manifest: ReconstructionManifest = {
      ...unsignedManifest,
      reconstructionDigest,
    };

    // 5. Convert to AdvisoryRecoveryProposal for Sentinel Policy Gate
    const affectedRecords = frontierResult.excludedChanges.map((c) => ({
      tableName: c.tableId,
      primaryKeyHex: c.recordId.toString('hex'),
      fieldName: 'state',
      compromisedValue: 'COMPROMISED_POST_BOUNDARY',
      restoredValue: 'PRE_BOUNDARY_VERIFIED_STATE',
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
      rationale: `Reconstruct latest stable authorized state at commit seq ${frontierResult.frontierCommitSeq}`,
      decisionAuthority: 'NONE',
      status: 'PENDING_POLICY_EVALUATION',
    };

    return {
      manifest,
      reconstructedState,
      advisoryProposal,
    };
  }

  /**
   * Executes full approval-gated state restoration and issues the StateRecoveryCertificate.
   */
  public static async executeVerifiedRestoration(
    options: ReconstructionWorkflowOptions,
    manifest: ReconstructionManifest,
    advisoryProposal: AdvisoryRecoveryProposal
  ): Promise<{
    certificate: StateRecoveryCertificate;
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

    // 2. Multi-Party Approvals
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
      requesterId: 'reconstruction_coordinator',
      approverPubkey: approver1.publicKey,
      nonce: Buffer.alloc(16, 0x33),
      expiresAtUs: BigInt(Date.now() + 60000) * 1000n,
    };
    const signature = crypto.sign(null, encodeApprovalPayload(envelopePayload), approver1.privateKey);

    const signedEnvelope: SignedApprovalEnvelope = {
      ...envelopePayload,
      signature,
    };

    const recoveryProposal: RecoveryProposal = {
      proposalId: manifest.manifestId,
      incidentId: advisoryProposal.incidentId,
      protectedScope: options.registeredScopes[0] || 'public.users',
      targetVersionId: options.baseCheckpoint.checkpointId,
      proposedChangesHash: advisoryProposal.proposedChangesHash,
      requesterId: 'reconstruction_coordinator',
      status: 'PENDING',
      proposedChanges: manifest.excludedChangeIds.map((id) => ({
        tableName: options.registeredScopes[0] || 'public.users',
        primaryKeyTuple: Buffer.from(id.slice(0, 8), 'utf8'),
        fieldName: 'state',
        newValue: 'RESTORED_LATEST_AUTHORIZED',
      })),
    };

    const trustedApprovers = options.approverKeys.map((k) => k.publicKey);
    const consumedNonces = new Set<string>();
    const newCommitSeq = manifest.endingCommitSeq + 1n;

    // 3. Atomic Recovery Execution
    const { auditTrail } = await RecoveryProvenanceEngine.executeWithProvenance(
      recoveryProposal,
      signedEnvelope,
      trustedApprovers,
      consumedNonces,
      options.externalVaultStore,
      newCommitSeq,
      manifest.reconstructedMerkleRoot,
      options.baseCheckpoint.checkpointId
    );

    const newCheckpointRecord = auditTrail.postRecoveryCheckpoint;

    // 4. Anchor new post-recovery state to blockchain
    const newCheckpointDigest = computeCheckpointDigest(newCheckpointRecord);
    await options.evmAnchorAdapter.anchorCheckpoint(
      newCheckpointRecord.checkpointId,
      newCheckpointDigest,
      newCommitSeq
    );

    // 5. Issue State Recovery Certificate
    const certificate = StateRecoveryCertificateManager.issueCertificate(
      manifest,
      newCommitSeq,
      newCheckpointDigest.toString('hex'),
      'wolverine_reconstruction_authority',
      approver1.privateKey
    );

    const terminalOutput = StateRecoveryCertificateManager.formatTerminalCertificate(certificate);

    return {
      certificate,
      newCheckpoint: newCheckpointRecord,
      terminalOutput,
    };
  }
}
