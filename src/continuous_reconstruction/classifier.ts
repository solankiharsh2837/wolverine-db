import { ChangeRecordData } from '../protocol/types.js';
import { AnchoredCheckpoint } from '../checkpoint/types.js';
import { BaselineTracker } from '../sentinel/baseline.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';
import {
  ReconstructionDecision,
  ContinuousReconstructionAnalysis,
} from './types.js';
import { ReconstructionProofGraphBuilder, computeReconstructionGraphDigest } from './proof_graph.js';
import { StateDependencyGraphBuilder, computeDependencyGraphDigest } from './dependency_graph.js';
import { StateReplayEngine } from '../reconstruction/replay_engine.js';
import { ReconstructedDatabaseState } from '../reconstruction/types.js';

export interface ContinuousHistoryInput {
  baseCheckpoint: AnchoredCheckpoint | Omit<AnchoredCheckpoint, 'digest'>;
  initialCheckpointState: ReconstructedDatabaseState;
  changesAfterCheckpoint: Array<{
    data: ChangeRecordData;
    recordBytes: Buffer;
    computedHash: Buffer;
    commitSeq: bigint;
    actorId: string;
    utcHour: number;
    dayOfWeek: number;
    ticketId?: string | undefined;
    isIndependentCommitment?: boolean | undefined;
  }>;
  baselineTracker: BaselineTracker;
  compromisedActors?: string[] | undefined;
  revokedKeys?: string[] | undefined;
}

export class ContinuousHistoryClassifier {
  /**
   * Analyzes interleaved history, builds proof and dependency graphs, and produces reconstruction decisions.
   */
  public static analyzeHistory(input: ContinuousHistoryInput): ContinuousReconstructionAnalysis {
    const { baseCheckpoint, baselineTracker } = input;

    const proofGraphBuilder = new ReconstructionProofGraphBuilder();
    const dependencyGraphBuilder = new StateDependencyGraphBuilder(input.initialCheckpointState);

    const rootNodeId = proofGraphBuilder.addCheckpointNode(
      baseCheckpoint.checkpointId,
      baseCheckpoint.commitSeq,
      baseCheckpoint.merkleRoot
    );

    let lastContinuousSeq = baseCheckpoint.commitSeq;
    let lastContinuousHash = baseCheckpoint.changeChainHead;
    let isHistoryContiguous = true;

    const decisions: ReconstructionDecision[] = [];
    const preservedChanges: ChangeRecordData[] = [];
    const compromisedActors = new Set(input.compromisedActors || []);
    const revokedKeys = new Set(input.revokedKeys || []);

    let maxReconstructableSeq = baseCheckpoint.commitSeq;
    let priorNodeId = rootNodeId;

    for (const item of input.changesAfterCheckpoint) {
      const change = item.data;
      const changeId = change.versionId;
      const seq = item.commitSeq;

      // 1. History Integrity Check
      const isPredecessorHashValid = timingSafeEqualHashes(change.previousHash, lastContinuousHash);
      const isSeqContiguous = seq === lastContinuousSeq + 1n;

      if (!isPredecessorHashValid || !isSeqContiguous) {
        isHistoryContiguous = false;
      }

      // 2. Mutation Authenticity Check
      let isActorCompromised = compromisedActors.has(item.actorId);
      let isKeyRevoked = revokedKeys.has(item.actorId);
      let isScopeValid = true;
      let isInWindow = true;
      let isTicketValid = true;

      const baseline = baselineTracker.getBaseline(item.actorId);
      if (baseline) {
        if (!baseline.allowedScopes.includes(change.tableId)) {
          isScopeValid = false;
        }

        if (baseline.maintenanceWindows.length > 0) {
          isInWindow = baseline.maintenanceWindows.some(
            (w) =>
              w.daysOfWeek.includes(item.dayOfWeek) &&
              item.utcHour >= w.startUtcHour &&
              item.utcHour <= w.endUtcHour
          );
        }

        if (baseline.requiresTicketProvenance && !item.ticketId) {
          isTicketValid = false;
        }
      }

      const isAuthValid = !isKeyRevoked && isScopeValid && isInWindow;
      const isProvValid = !isActorCompromised && isTicketValid;
      const isDirectlyAuthentic = isAuthValid && isProvValid;

      // Add to Proof Graph
      const { mutationNodeId } = proofGraphBuilder.addMutationProofPath(
        changeId,
        seq,
        item.computedHash,
        priorNodeId,
        isAuthValid,
        isProvValid,
        !!item.isIndependentCommitment
      );

      // 3. State Dependency Check
      const isDirectlyExcluded = !isDirectlyAuthentic || (!isHistoryContiguous && !item.isIndependentCommitment);
      const depResult = dependencyGraphBuilder.analyzeMutationDependency(
        change,
        seq,
        isDirectlyExcluded
      );

      // 4. Formulate Decision
      let decision: ReconstructionDecision;

      if (isKeyRevoked) {
        decision = {
          changeId,
          commitSeq: seq,
          decision: 'EXCLUDE',
          classification: 'REVOKED',
          reason: `REVOKED: Actor key "${item.actorId}" is marked revoked`,
          proofReferences: [mutationNodeId],
          predecessorStatus: isPredecessorHashValid ? 'VERIFIED' : 'BROKEN',
          authorizationStatus: 'FAILED',
          provenanceStatus: 'COMPROMISED',
          externalAnchorStatus: item.isIndependentCommitment ? 'ANCHORED' : 'NOT_ANCHORED',
        };
      } else if (isActorCompromised) {
        decision = {
          changeId,
          commitSeq: seq,
          decision: 'EXCLUDE',
          classification: 'COMPROMISED',
          reason: `COMPROMISED: Actor "${item.actorId}" credential is compromised`,
          proofReferences: [mutationNodeId],
          predecessorStatus: isPredecessorHashValid ? 'VERIFIED' : 'BROKEN',
          authorizationStatus: 'FAILED',
          provenanceStatus: 'COMPROMISED',
          externalAnchorStatus: item.isIndependentCommitment ? 'ANCHORED' : 'NOT_ANCHORED',
        };
      } else if (!isScopeValid || !isInWindow) {
        decision = {
          changeId,
          commitSeq: seq,
          decision: 'EXCLUDE',
          classification: 'UNAUTHORIZED',
          reason: !isScopeValid
            ? `UNAUTHORIZED: Scope "${change.tableId}" not permitted for actor`
            : `UNAUTHORIZED: Out of maintenance window at UTC hour ${item.utcHour}`,
          proofReferences: [mutationNodeId],
          predecessorStatus: isPredecessorHashValid ? 'VERIFIED' : 'BROKEN',
          authorizationStatus: 'FAILED',
          provenanceStatus: isProvValid ? 'VERIFIED' : 'UNVERIFIABLE',
          externalAnchorStatus: item.isIndependentCommitment ? 'ANCHORED' : 'NOT_ANCHORED',
        };
      } else if (!isTicketValid) {
        decision = {
          changeId,
          commitSeq: seq,
          decision: 'EXCLUDE',
          classification: 'UNVERIFIABLE',
          reason: 'UNVERIFIABLE: Missing required change control ticket ID',
          proofReferences: [mutationNodeId],
          predecessorStatus: isPredecessorHashValid ? 'VERIFIED' : 'BROKEN',
          authorizationStatus: 'VERIFIED',
          provenanceStatus: 'UNVERIFIABLE',
          externalAnchorStatus: item.isIndependentCommitment ? 'ANCHORED' : 'NOT_ANCHORED',
        };
      } else if (depResult.isBlocked) {
        decision = {
          changeId,
          commitSeq: seq,
          decision: 'BLOCK',
          classification: 'DEPENDENCY_BLOCKED',
          reason: depResult.reason || 'DEPENDENCY_BLOCKED: Causal predecessor was excluded',
          proofReferences: [mutationNodeId],
          predecessorStatus: isPredecessorHashValid ? 'VERIFIED' : 'INDEPENDENT',
          authorizationStatus: 'VERIFIED',
          provenanceStatus: 'VERIFIED',
          externalAnchorStatus: item.isIndependentCommitment ? 'ANCHORED' : 'NOT_ANCHORED',
        };
      } else if (depResult.isConflict) {
        decision = {
          changeId,
          commitSeq: seq,
          decision: 'CONFLICT',
          classification: 'STATE_CONFLICT',
          reason: depResult.reason || 'STATE_CONFLICT: Competing row version update',
          proofReferences: [mutationNodeId],
          predecessorStatus: isPredecessorHashValid ? 'VERIFIED' : 'INDEPENDENT',
          authorizationStatus: 'VERIFIED',
          provenanceStatus: 'VERIFIED',
          externalAnchorStatus: item.isIndependentCommitment ? 'ANCHORED' : 'NOT_ANCHORED',
        };
      } else if (!isHistoryContiguous && !item.isIndependentCommitment) {
        decision = {
          changeId,
          commitSeq: seq,
          decision: 'EXCLUDE',
          classification: 'MISSING',
          reason: 'MISSING: Sequence gap or broken hash chain with no independent commitment',
          proofReferences: [mutationNodeId],
          predecessorStatus: 'BROKEN',
          authorizationStatus: 'VERIFIED',
          provenanceStatus: 'VERIFIED',
          externalAnchorStatus: 'NOT_ANCHORED',
        };
      } else {
        // Valid & Replayable!
        decision = {
          changeId,
          commitSeq: seq,
          decision: 'PRESERVE',
          classification: 'VALID',
          reason: 'VALID: Cryptographically verified and all dependencies satisfied',
          proofReferences: [mutationNodeId],
          predecessorStatus: isPredecessorHashValid ? 'VERIFIED' : 'INDEPENDENT',
          authorizationStatus: 'VERIFIED',
          provenanceStatus: 'VERIFIED',
          externalAnchorStatus: item.isIndependentCommitment ? 'ANCHORED' : 'NOT_ANCHORED',
        };
        preservedChanges.push(change);
        maxReconstructableSeq = seq;
      }

      decisions.push(decision);

      // Advance contiguous frontier only if continuous
      if (isHistoryContiguous && decision.decision === 'PRESERVE') {
        lastContinuousSeq = seq;
        lastContinuousHash = item.computedHash;
      }
      priorNodeId = mutationNodeId;
    }

    // Materialize Reconstructed State
    const reconstructedState = StateReplayEngine.replayChanges(
      input.initialCheckpointState,
      preservedChanges
    );
    const resultingMerkleRoot = StateReplayEngine.computeStateMerkleRoot(reconstructedState);

    const proofGraph = proofGraphBuilder.build();
    const dependencyGraph = dependencyGraphBuilder.build();

    const reconstructionGraphDigest = computeReconstructionGraphDigest(proofGraph);
    const dependencyGraphDigest = computeDependencyGraphDigest(dependencyGraph);

    return {
      contiguousVerifiedFrontierSeq: lastContinuousSeq,
      maximumReconstructableCommitSeq: maxReconstructableSeq,
      decisions,
      proofGraph,
      dependencyGraph,
      reconstructionGraphDigest,
      dependencyGraphDigest,
      reconstructedState,
      resultingMerkleRoot,
    };
  }
}
