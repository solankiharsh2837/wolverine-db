import { BootstrapSnapshot } from '../evidence/types.js';
import { DurableEvidenceJournal } from '../evidence/journal.js';
import { DeterministicStateFrontier } from '../evidence/state_frontier.js';
import { CanonicalQuorumCertificate } from '../trust/quorum_certificate.js';
import { IndependentQuorumVerifier } from '../trust/quorum_verifier.js';
import { ValidatorSetManager } from '../trust/validator_set.js';
import {
  CrossEpochTransitionCertificate,
  verifyEpochTransitionCertificate,
} from '../trust/epoch_transition.js';
import { TrustHistoryAuditor } from './history_verifier.js';
import { DurableDisasterQueue, DisasterType, DisasterState } from './disaster_queue.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface RecoveryPlan {
  bootstrapSnapshot: BootstrapSnapshot;
  evidenceJournal: DurableEvidenceJournal;
  quorumCertificates: CanonicalQuorumCertificate[];
  epochTransitionCertificates?: CrossEpochTransitionCertificate[];
  validatorSetsByEpoch: Map<number, ValidatorSetManager>;
  customerPubkey?: Buffer;
}

export interface ReconstructedTrustState {
  recoveredEpoch: number;
  recoveredSequence: bigint;
  stateMerkleRootHex: string;
  chainHeadHex: string;
  frontier: DeterministicStateFrontier;
  canFinalize: boolean;
  activeDisastersCount: number;
}

export class TrustCloudRecoveryEngine {
  private disasterQueue?: DurableDisasterQueue;
  private auditor: TrustHistoryAuditor;

  constructor(disasterQueue?: DurableDisasterQueue) {
    this.disasterQueue = disasterQueue;
    this.auditor = new TrustHistoryAuditor(disasterQueue);
  }

  /**
   * Cold-reconstructs the entire Trust Cloud state from durable disk evidence.
   * Enforces: Unverified Recovery State != Finalizable State.
   */
  public async reconstructFromDurableHistory(
    plan: RecoveryPlan
  ): Promise<ReconstructedTrustState> {
    // 1. Audit Evidence Journal Integrity
    const entries = await plan.evidenceJournal.replay();
    const auditRes = this.auditor.auditJournalHistory(entries);

    // 2. Initialize and Bootstrap State Frontier S0
    let currentEpoch = plan.bootstrapSnapshot.schemaEpoch;
    const frontier = new DeterministicStateFrontier(currentEpoch);
    frontier.bootstrap(plan.bootstrapSnapshot);

    // 3. Verify all Quorum Certificates against Authoritative Epoch Validator Sets
    const sortedQCs = [...plan.quorumCertificates].sort((a, b) =>
      a.epoch === b.epoch ? Number(a.commitSeq - b.commitSeq) : a.epoch - b.epoch
    );

    let lastVerifiedSeq = 0n;
    let lastVerifiedDigestHex = '0000000000000000000000000000000000000000000000000000000000000000';

    for (const qc of sortedQCs) {
      const valSetManager = plan.validatorSetsByEpoch.get(qc.epoch);
      if (!valSetManager) {
        if (this.disasterQueue) {
          this.disasterQueue.recordDisaster(
            DisasterType.D003_VALIDATOR_SET_UNAVAILABLE,
            `Recovery failed: Validator set for epoch ${qc.epoch} not registered`
          );
        }
        throw new WolverineError(
          WolverineErrorCode.UNAUTHORIZED_MUTATION,
          `Validator set for epoch ${qc.epoch} missing during recovery`
        );
      }

      // Independent Zero-Trust Verification of QC
      IndependentQuorumVerifier.verify(qc, valSetManager);

      lastVerifiedSeq = qc.commitSeq;
      lastVerifiedDigestHex = qc.commitmentDigestHex;
    }

    // 4. Verify and Apply Cross-Epoch Transitions (if present)
    if (plan.epochTransitionCertificates && plan.epochTransitionCertificates.length > 0) {
      for (const tc of plan.epochTransitionCertificates) {
        const oldSet = plan.validatorSetsByEpoch.get(tc.oldEpoch);
        const newSet = plan.validatorSetsByEpoch.get(tc.newEpoch);

        if (!oldSet || !newSet) {
          throw new WolverineError(
            WolverineErrorCode.UNAUTHORIZED_MUTATION,
            `Validator set missing for transition ${tc.oldEpoch} -> ${tc.newEpoch}`
          );
        }

        const transitionResult = verifyEpochTransitionCertificate(
          tc,
          oldSet,
          newSet.getActiveSet(),
          plan.customerPubkey
        );

        currentEpoch = tc.newEpoch;
        frontier.setSchemaEpoch(tc.newEpoch);
        lastVerifiedDigestHex = transitionResult.newGenesisDigest.toString('hex');
      }
    }

    // 5. Apply Journal Changes to Frontier
    if (entries.length > 0) {
      for (const entry of entries) {
        frontier.applyChangeRecords(
          [entry.changeRecord],
          entry.lsn,
          entry.sequenceNumber,
          entry.changeHash
        );
      }
    }

    const stateMerkleRootHex = frontier.computeStateMerkleRoot().toString('hex');
    const activeDisasters = this.disasterQueue ? this.disasterQueue.getActiveDisasters().length : 0;

    // INVARIANT: If there are unverified/quarantined disasters, the state cannot finalize new commitments
    const canFinalize = activeDisasters === 0;

    return {
      recoveredEpoch: currentEpoch,
      recoveredSequence: lastVerifiedSeq > 0n ? lastVerifiedSeq : BigInt(entries.length),
      stateMerkleRootHex,
      chainHeadHex: auditRes.chainHeadHex,
      frontier,
      canFinalize,
      activeDisastersCount: activeDisasters,
    };
  }
}
