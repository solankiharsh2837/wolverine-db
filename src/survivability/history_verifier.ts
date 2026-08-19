import crypto from 'node:crypto';
import { EvidenceJournalEntry } from '../evidence/types.js';
import { DurableDisasterQueue, DisasterType } from './disaster_queue.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { timingSafeEqualHashes, computeChangeHash } from '../crypto/hash.js';

export interface AuditResult {
  valid: boolean;
  totalEntries: number;
  startSeq: bigint;
  endSeq: bigint;
  chainHeadHex: string;
}

export class TrustHistoryAuditor {
  private disasterQueue?: DurableDisasterQueue;

  constructor(disasterQueue?: DurableDisasterQueue) {
    this.disasterQueue = disasterQueue;
  }

  /**
   * Performs an exhaustive cryptographic audit over journal entries.
   * Detects sequence gaps (truncation attacks) and hash chain breakages (corruption).
   */
  public auditJournalHistory(
    entries: EvidenceJournalEntry[],
    initialPrevHash: Buffer = Buffer.alloc(32, 0),
    expectedStartSeq: bigint = 1n
  ): AuditResult {
    if (entries.length === 0) {
      return {
        valid: true,
        totalEntries: 0,
        startSeq: 0n,
        endSeq: 0n,
        chainHeadHex: initialPrevHash.toString('hex'),
      };
    }

    let expectedSeq = expectedStartSeq;
    let runningHead = Buffer.from(initialPrevHash);

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i]!;

      // 1. Strict Sequence Gap Check (History Truncation Attack Defense)
      if (entry.sequenceNumber !== expectedSeq) {
        const details = `TRUST_HISTORY_GAP detected: Expected sequence ${expectedSeq}, observed ${entry.sequenceNumber}. Missing sequence range: [${expectedSeq}..${entry.sequenceNumber - 1n}].`;
        if (this.disasterQueue) {
          this.disasterQueue.recordDisaster(DisasterType.D008_TRUST_HISTORY_GAP, details, {
            missingRangeStart: expectedSeq.toString(),
            missingRangeEnd: (entry.sequenceNumber - 1n).toString(),
            observedSequence: entry.sequenceNumber.toString(),
          });
        }
        throw new WolverineError(WolverineErrorCode.SEQUENCE_GAP_DETECTED, details);
      }

      // 2. Hash Chain Continuity Check
      if (!timingSafeEqualHashes(entry.previousHash, runningHead)) {
        const details = `JOURNAL_CORRUPTION: Hash chain break at sequence ${entry.sequenceNumber}. Expected previousHash ${runningHead.toString('hex')}, observed ${entry.previousHash.toString('hex')}.`;
        if (this.disasterQueue) {
          this.disasterQueue.recordDisaster(DisasterType.D005_JOURNAL_CORRUPTION, details, {
            corruptedSequence: entry.sequenceNumber.toString(),
            expectedPreviousHash: runningHead.toString('hex'),
            observedPreviousHash: entry.previousHash.toString('hex'),
          });
        }
        throw new WolverineError(WolverineErrorCode.HASH_CHAIN_DISCONTINUITY, details);
      }

      // 3. Cryptographic Change Hash Recomputation
      const computedChangeHash = computeChangeHash(entry.recordBytes, entry.previousHash);
      if (!timingSafeEqualHashes(computedChangeHash, entry.changeHash)) {
        const details = `JOURNAL_CORRUPTION: Payload checksum mismatch at sequence ${entry.sequenceNumber}. Stored changeHash ${entry.changeHash.toString('hex')}, computed ${computedChangeHash.toString('hex')}.`;
        if (this.disasterQueue) {
          this.disasterQueue.recordDisaster(DisasterType.D005_JOURNAL_CORRUPTION, details, {
            corruptedSequence: entry.sequenceNumber.toString(),
          });
        }
        throw new WolverineError(WolverineErrorCode.CHECKSUM_MISMATCH, details);
      }

      runningHead = Buffer.from(entry.changeHash);
      expectedSeq++;
    }

    return {
      valid: true,
      totalEntries: entries.length,
      startSeq: entries[0]!.sequenceNumber,
      endSeq: entries[entries.length - 1]!.sequenceNumber,
      chainHeadHex: runningHead.toString('hex'),
    };
  }
}
