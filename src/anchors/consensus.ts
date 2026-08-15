import { ConsensusPolicy, ConsensusReport, ConsensusVerdict, AnchorRecord, AnchorStatus } from './types.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export class MultiAnchorConsensusEngine {
  /**
   * Evaluates consensus across multiple anchor records against expected local checkpoint digest.
   */
  public static evaluateConsensus(
    expectedCheckpointDigest: Buffer,
    anchors: Array<AnchorRecord | null>,
    policy: ConsensusPolicy
  ): ConsensusReport {
    let matchingCount = 0;
    let totalEvaluated = 0;
    const anchorResults: ConsensusReport['anchorResults'] = [];

    for (const anchor of anchors) {
      if (!anchor) continue;
      totalEvaluated++;

      const isDigestMatch = timingSafeEqualHashes(anchor.checkpointDigest, expectedCheckpointDigest);
      const isFinalized =
        anchor.status === AnchorStatus.FINALIZED ||
        (anchor.status === AnchorStatus.CONFIRMING && anchor.confirmationCount >= (policy.minimumFinalizedAnchors || 1));

      const matches = isDigestMatch && isFinalized;
      if (matches) {
        matchingCount++;
      }

      anchorResults.push({
        anchorId: anchor.anchorId,
        chainId: anchor.chainId,
        status: anchor.status,
        matches,
        digestHex: anchor.checkpointDigest.toString('hex'),
      });
    }

    let verdict: ConsensusVerdict;
    let summaryMessage: string;

    if (matchingCount >= policy.requiredQuorum) {
      verdict = 'CONSENSUS_VALID';
      summaryMessage = `Quorum achieved: ${matchingCount}/${policy.totalAnchors} independent anchors confirm state (required: ${policy.requiredQuorum})`;
    } else if (matchingCount > 0 && matchingCount < policy.requiredQuorum) {
      verdict = 'CONSENSUS_SUSPICIOUS';
      summaryMessage = `Minority quorum alert: only ${matchingCount}/${policy.totalAnchors} anchors confirm state (required: ${policy.requiredQuorum})`;
    } else if (totalEvaluated > 0 && matchingCount === 0) {
      verdict = 'CONSENSUS_DIVERGENCE';
      summaryMessage = `Critical divergence: 0/${totalEvaluated} active anchors confirm local database state`;
    } else {
      verdict = 'CONSENSUS_INDETERMINATE';
      summaryMessage = 'Insufficient active anchors available for consensus evaluation';
    }

    return {
      verdict,
      matchingCount,
      totalEvaluated,
      requiredQuorum: policy.requiredQuorum,
      anchorResults,
      summaryMessage,
    };
  }
}
