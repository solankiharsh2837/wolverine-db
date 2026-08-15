import crypto from 'node:crypto';
import { ReconstructionManifest } from './types.js';
import { canonicalizeJson } from '../binary/c14n.js';

export function computeReconstructionDigest(
  manifest: Omit<ReconstructionManifest, 'reconstructionDigest'>
): Buffer {
  const domain = Buffer.from('WDB:RECON_MANIFEST:v1:', 'utf8');

  const canonicalPayload = canonicalizeJson({
    manifestId: manifest.manifestId,
    databaseId: manifest.databaseId,
    tenantId: manifest.tenantId,
    sourceCheckpointId: manifest.sourceCheckpointId,
    sourceCheckpointDigest: manifest.sourceCheckpointDigest.toString('hex'),
    sourceCheckpointCommitSeq: manifest.sourceCheckpointCommitSeq.toString(),
    startingMerkleRoot: manifest.startingMerkleRoot.toString('hex'),
    endingCommitSeq: manifest.endingCommitSeq.toString(),
    replayedChangeIds: manifest.replayedChangeIds,
    replayedCommitSeqs: manifest.replayedCommitSeqs.map((s) => s.toString()),
    excludedChangeIds: manifest.excludedChangeIds,
    exclusionReasons: manifest.exclusionReasons,
    reconstructedMerkleRoot: manifest.reconstructedMerkleRoot.toString('hex'),
    recoveryBoundary: {
      lastValidCommitSeq: manifest.recoveryBoundary.lastValidCommitSeq.toString(),
      lastValidTimestampUs: manifest.recoveryBoundary.lastValidTimestampUs.toString(),
      firstInvalidCommitSeq: manifest.recoveryBoundary.firstInvalidCommitSeq !== null
        ? manifest.recoveryBoundary.firstInvalidCommitSeq.toString()
        : null,
      compromiseReason: manifest.recoveryBoundary.compromiseReason,
    },
    policyVersion: manifest.policyVersion,
    timestampUs: manifest.timestampUs.toString(),
  });

  return crypto.createHash('sha256').update(Buffer.concat([domain, Buffer.from(canonicalPayload, 'utf8')])).digest();
}
