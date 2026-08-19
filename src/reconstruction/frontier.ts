import { ChangeRecordData } from '../protocol/types.js';
import { AnchoredCheckpoint, CheckpointStore } from '../checkpoint/types.js';
import { EvmAnchorAdapter } from '../anchors/evm.js';
import { computeCheckpointDigest } from '../checkpoint/anchor.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';
import { BaselineTracker } from '../sentinel/baseline.js';
import { FrontierVerificationResult } from './types.js';

export interface FrontierEvaluationInput {
  baseCheckpoint: AnchoredCheckpoint | Omit<AnchoredCheckpoint, 'digest'>;
  changesAfterCheckpoint: Array<{
    data: ChangeRecordData;
    recordBytes: Buffer;
    computedHash: Buffer;
    commitSeq: bigint;
    actorId: string;
    utcHour: number;
    dayOfWeek: number;
    ticketId?: string | undefined;
  }>;
  externalVaultStore: CheckpointStore;
  evmAnchorAdapter: EvmAnchorAdapter;
  baselineTracker: BaselineTracker;
  compromisedActors?: string[] | undefined;
}

export class VerifiedStateFrontierEngine {
  /**
   * Evaluates the Verified State Frontier against the 7 verification pillars.
   */
  public static async calculateFrontier(
    input: FrontierEvaluationInput
  ): Promise<FrontierVerificationResult> {
    const { baseCheckpoint, externalVaultStore, evmAnchorAdapter, baselineTracker } = input;
    const baseDigest = computeCheckpointDigest(baseCheckpoint);

    // 1. Verify basis checkpoint in external vault
    const vaultChk = await externalVaultStore.get(baseCheckpoint.checkpointId);
    if (!vaultChk) {
      return {
        frontierCommitSeq: 0n,
        frontierTimestampUs: 0n,
        isFrontierValid: false,
        baseCheckpointId: baseCheckpoint.checkpointId,
        baseCheckpointCommitSeq: baseCheckpoint.commitSeq,
        preservedChanges: [],
        excludedChanges: input.changesAfterCheckpoint.map((c) => c.data),
        exclusionReasons: {
          baseCheckpoint: 'BASE_CHECKPOINT_NOT_IN_EXTERNAL_VAULT',
        },
        firstInvalidCommitSeq: baseCheckpoint.commitSeq,
        compromiseReason: 'Basis checkpoint missing from external WORM vault',
      };
    }

    const vaultDigest = computeCheckpointDigest(vaultChk);
    if (!timingSafeEqualHashes(baseDigest, vaultDigest)) {
      return {
        frontierCommitSeq: 0n,
        frontierTimestampUs: 0n,
        isFrontierValid: false,
        baseCheckpointId: baseCheckpoint.checkpointId,
        baseCheckpointCommitSeq: baseCheckpoint.commitSeq,
        preservedChanges: [],
        excludedChanges: input.changesAfterCheckpoint.map((c) => c.data),
        exclusionReasons: {
          baseCheckpoint: 'BASE_CHECKPOINT_VAULT_DIGEST_MISMATCH',
        },
        firstInvalidCommitSeq: baseCheckpoint.commitSeq,
        compromiseReason: 'Basis checkpoint diverges from external vault state',
      };
    }

    // 2. Verify basis checkpoint against blockchain anchor
    const anchor = await evmAnchorAdapter.getAnchor(baseCheckpoint.checkpointId);
    if (!anchor || !timingSafeEqualHashes(anchor.checkpointDigest, baseDigest)) {
      return {
        frontierCommitSeq: 0n,
        frontierTimestampUs: 0n,
        isFrontierValid: false,
        baseCheckpointId: baseCheckpoint.checkpointId,
        baseCheckpointCommitSeq: baseCheckpoint.commitSeq,
        preservedChanges: [],
        excludedChanges: input.changesAfterCheckpoint.map((c) => c.data),
        exclusionReasons: {
          baseCheckpoint: 'BASE_CHECKPOINT_BLOCKCHAIN_ANCHOR_MISMATCH',
        },
        firstInvalidCommitSeq: baseCheckpoint.commitSeq,
        compromiseReason: 'Basis checkpoint not verified on public blockchain anchor',
      };
    }

    // 3. Inspect changes forward from checkpoint
    let lastValidSeq = baseCheckpoint.commitSeq;
    let lastValidTimestampUs = baseCheckpoint.createdAtUs;
    let lastValidHash = baseCheckpoint.changeChainHead;

    const preservedChanges: ChangeRecordData[] = [];
    const excludedChanges: ChangeRecordData[] = [];
    const exclusionReasons: Record<string, string> = {};
    let firstInvalidCommitSeq: bigint | null = null;
    let compromiseReason: string | null = null;

    const compromisedActors = new Set(input.compromisedActors || []);

    for (let idx = 0; idx < input.changesAfterCheckpoint.length; idx++) {
      const item = input.changesAfterCheckpoint[idx]!;
      const change = item.data;

      // Check A: Post-compromise actor
      if (compromisedActors.has(item.actorId)) {
        firstInvalidCommitSeq = item.commitSeq;
        compromiseReason = `POST_COMPROMISE_MUTATION: Actor "${item.actorId}" is compromised`;
        this.excludeRemaining(input.changesAfterCheckpoint, idx, excludedChanges, exclusionReasons, compromiseReason);
        break;
      }

      // Check B: Sequence Monotonicity
      if (item.commitSeq !== lastValidSeq + 1n) {
        firstInvalidCommitSeq = item.commitSeq;
        compromiseReason = `SEQUENCE_GAP_OR_OUT_OF_ORDER: Expected ${lastValidSeq + 1n}, observed ${item.commitSeq}`;
        this.excludeRemaining(input.changesAfterCheckpoint, idx, excludedChanges, exclusionReasons, compromiseReason);
        break;
      }

      // Check C: Hash-chain continuity
      if (!timingSafeEqualHashes(change.previousHash, lastValidHash)) {
        firstInvalidCommitSeq = item.commitSeq;
        compromiseReason = 'HASH_CHAIN_DISCONTINUITY: previousHash does not match prior change digest';
        this.excludeRemaining(input.changesAfterCheckpoint, idx, excludedChanges, exclusionReasons, compromiseReason);
        break;
      }

      // Check D: Authorization & Scope via Baseline
      const baseline = baselineTracker.getBaseline(item.actorId);
      if (baseline) {
        if (!baseline.allowedScopes.includes(change.tableId)) {
          firstInvalidCommitSeq = item.commitSeq;
          compromiseReason = `UNAUTHORIZED_SCOPE_MUTATION: Actor "${item.actorId}" cannot mutate scope "${change.tableId}"`;
          this.excludeRemaining(input.changesAfterCheckpoint, idx, excludedChanges, exclusionReasons, compromiseReason);
          break;
        }

        const inWindow = baseline.maintenanceWindows.some((w) => {
          if (!w.daysOfWeek.includes(item.dayOfWeek)) return false;
          return w.startUtcHour <= w.endUtcHour
            ? item.utcHour >= w.startUtcHour && item.utcHour <= w.endUtcHour
            : item.utcHour >= w.startUtcHour || item.utcHour <= w.endUtcHour;
        });
        if (!inWindow && baseline.maintenanceWindows.length > 0) {
          firstInvalidCommitSeq = item.commitSeq;
          compromiseReason = `OUT_OF_WINDOW_MUTATION: UTC Hour ${item.utcHour} is outside maintenance window`;
          this.excludeRemaining(input.changesAfterCheckpoint, idx, excludedChanges, exclusionReasons, compromiseReason);
          break;
        }

        if (baseline.requiresTicketProvenance && !item.ticketId) {
          firstInvalidCommitSeq = item.commitSeq;
          compromiseReason = 'MISSING_PROVENANCE_TICKET: Critical mutation requires change ticket';
          this.excludeRemaining(input.changesAfterCheckpoint, idx, excludedChanges, exclusionReasons, compromiseReason);
          break;
        }
      }

      // Mutation is verified!
      preservedChanges.push(change);
      lastValidSeq = item.commitSeq;
      lastValidTimestampUs = change.timestampUs;
      lastValidHash = item.computedHash;
    }

    return {
      frontierCommitSeq: lastValidSeq,
      frontierTimestampUs: lastValidTimestampUs,
      isFrontierValid: true,
      baseCheckpointId: baseCheckpoint.checkpointId,
      baseCheckpointCommitSeq: baseCheckpoint.commitSeq,
      preservedChanges,
      excludedChanges,
      exclusionReasons,
      firstInvalidCommitSeq,
      compromiseReason,
    };
  }

  private static excludeRemaining(
    allChanges: FrontierEvaluationInput['changesAfterCheckpoint'],
    startIdx: number,
    excludedList: ChangeRecordData[],
    exclusionReasons: Record<string, string>,
    initialReason: string
  ): void {
    for (let i = startIdx; i < allChanges.length; i++) {
      const c = allChanges[i]!.data;
      excludedList.push(c);
      exclusionReasons[c.versionId] = i === startIdx ? initialReason : 'POST_COMPROMISE_SUBSEQUENT_MUTATION';
    }
  }
}
