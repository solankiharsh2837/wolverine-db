import crypto from 'node:crypto';
import {
  LedgerSnapshot,
  LedgerRecoveryResult,
} from './types.js';
import { TrustLedgerRecord } from '../trust_network/types.js';
import { MerkleTree } from '../crypto/merkle.js';
import { computeLedgerRecordDigest } from '../trust_network/ledger.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export function computeSnapshotDigest(
  snapshot: Omit<LedgerSnapshot, 'snapshotDigest'>
): Buffer {
  const domain = Buffer.from('WDB:SNAPSHOT:v1:', 'utf8');
  const canonical = canonicalizeJson({
    snapshotId: snapshot.snapshotId,
    epoch: snapshot.epoch,
    snapshotLedgerSeq: snapshot.snapshotLedgerSeq.toString(),
    stateRootHex: snapshot.stateRoot.toString('hex'),
    chainHeadDigestHex: snapshot.chainHeadDigest.toString('hex'),
    validatorSetDigestHex: snapshot.validatorSetDigest.toString('hex'),
    timestampUs: snapshot.timestampUs.toString(),
  });

  return crypto
    .createHash('sha256')
    .update(Buffer.concat([domain, Buffer.from(canonical, 'utf8')]))
    .digest();
}

export class TrustLedgerRecoveryEngine {
  public static recoverLedgerState(
    snapshot: LedgerSnapshot,
    journalSuffix: TrustLedgerRecord[]
  ): LedgerRecoveryResult {
    // 1. Verify Snapshot Digest
    const expectedSnapshotDigest = computeSnapshotDigest(snapshot);
    if (!timingSafeEqualHashes(snapshot.snapshotDigest, expectedSnapshotDigest)) {
      throw new WolverineError(
        WolverineErrorCode.HISTORY_MUTATION_DETECTED,
        'Snapshot hash integrity validation failed'
      );
    }

    // 2. Sequential Replay of Journal Records
    const allRecords: TrustLedgerRecord[] = [...snapshot.records];
    let currentHead = snapshot.chainHeadDigest;
    let expectedSeq = snapshot.snapshotLedgerSeq + 1n;

    for (const rec of journalSuffix) {
      if (rec.ledgerSeq !== expectedSeq) {
        throw new WolverineError(
          WolverineErrorCode.HISTORY_MUTATION_DETECTED,
          `Ledger sequence gap during replay: expected ${expectedSeq}, got ${rec.ledgerSeq}`
        );
      }

      if (Buffer.compare(rec.previousRecordDigest, currentHead) !== 0) {
        throw new WolverineError(
          WolverineErrorCode.HISTORY_MUTATION_DETECTED,
          `Ledger previous record hash mismatch at seq ${rec.ledgerSeq}`
        );
      }

      const expectedDigest = computeLedgerRecordDigest(
        rec.previousRecordDigest,
        rec.ledgerSeq,
        rec.payload
      );

      if (Buffer.compare(rec.recordDigest, expectedDigest) !== 0) {
        throw new WolverineError(
          WolverineErrorCode.HISTORY_MUTATION_DETECTED,
          `Ledger record digest corrupted at seq ${rec.ledgerSeq}`
        );
      }

      allRecords.push(rec);
      currentHead = rec.recordDigest;
      expectedSeq += 1n;
    }

    // 3. Recompute Merkle State Root across all record digests
    const digests = allRecords.map((r) => r.recordDigest);
    const tree = new MerkleTree(digests);
    const reconstructedStateRoot = tree.root;

    // 4. Compute Recovery Proof Digest
    const recoveryProofDigest = crypto
      .createHash('sha256')
      .update(
        Buffer.concat([
          Buffer.from('WDB:RECOVERY_PROOF:v1:', 'utf8'),
          snapshot.snapshotDigest,
          reconstructedStateRoot,
          currentHead,
        ])
      )
      .digest();

    return {
      isSuccess: true,
      snapshotDigest: snapshot.snapshotDigest,
      replayStartSeq: snapshot.snapshotLedgerSeq + 1n,
      replayEndSeq: BigInt(allRecords.length),
      reconstructedStateRoot,
      reconstructedLedgerDigest: currentHead,
      recoveryProofDigest,
    };
  }
}
