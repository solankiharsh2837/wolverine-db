import { LedgerSnapshot, LedgerRecoveryResult } from './types.js';
import { TrustLedgerRecord } from '../trust_network/types.js';
import { TrustLedgerRecoveryEngine, computeSnapshotDigest } from './ledger_recovery_engine.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export class MaliciousSnapshotDefense {
  public static detectAndRecover(
    candidateSnapshot: LedgerSnapshot,
    fallbackCleanSnapshot: LedgerSnapshot,
    journalSuffix: TrustLedgerRecord[]
  ): {
    isForgedSnapshotDetected: boolean;
    recoveryResult: LedgerRecoveryResult;
  } {
    const expectedDigest = computeSnapshotDigest(candidateSnapshot);
    const isDigestTampered = !timingSafeEqualHashes(candidateSnapshot.snapshotDigest, expectedDigest);

    if (isDigestTampered) {
      // Forged snapshot detected! Recover from fallback clean snapshot
      const result = TrustLedgerRecoveryEngine.recoverLedgerState(
        fallbackCleanSnapshot,
        journalSuffix
      );
      return {
        isForgedSnapshotDetected: true,
        recoveryResult: result,
      };
    }

    try {
      const result = TrustLedgerRecoveryEngine.recoverLedgerState(
        candidateSnapshot,
        journalSuffix
      );
      return {
        isForgedSnapshotDetected: false,
        recoveryResult: result,
      };
    } catch {
      // Recovery failed on candidate snapshot, fallback
      const result = TrustLedgerRecoveryEngine.recoverLedgerState(
        fallbackCleanSnapshot,
        journalSuffix
      );
      return {
        isForgedSnapshotDetected: true,
        recoveryResult: result,
      };
    }
  }
}
