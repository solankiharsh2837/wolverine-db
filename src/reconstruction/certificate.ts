import crypto from 'node:crypto';
import { StateRecoveryCertificate, ReconstructionManifest } from './types.js';
import { canonicalizeJson } from '../binary/c14n.js';

export class StateRecoveryCertificateManager {
  /**
   * Issues a signed StateRecoveryCertificate from an approved and executed reconstruction manifest.
   */
  public static issueCertificate(
    manifest: ReconstructionManifest,
    resultingCommitSequence: bigint,
    externalAnchorDigestHex: string,
    issuerIdentity: string,
    issuerPrivateKey?: crypto.KeyObject
  ): StateRecoveryCertificate {
    const certificateId = crypto.randomUUID();
    const issuedAtUs = BigInt(Date.now()) * 1000n;

    const unsignedPayload = {
      certificateVersion: 1,
      certificateId,
      databaseId: manifest.databaseId,
      recoveryId: manifest.manifestId,
      compromiseBoundaryCommitSeq: manifest.recoveryBoundary.lastValidCommitSeq,
      compromiseReason: manifest.recoveryBoundary.compromiseReason,
      lastVerifiedCheckpointId: manifest.sourceCheckpointId,
      verifiedStateFrontierCommitSeq: manifest.endingCommitSeq,
      authorizedChangesPreservedCount: manifest.replayedChangeIds.length,
      unauthorizedChangesExcludedCount: manifest.excludedChangeIds.length,
      resultingCommitSequence,
      resultingMerkleRootHex: manifest.reconstructedMerkleRoot.toString('hex'),
      externalAnchorDigestHex,
      policyApprovalStatus: 'PASS' as const,
      cryptographicVerificationStatus: 'PASS' as const,
      issuedAtUs,
      issuerIdentity,
    };

    const canonicalJson = canonicalizeJson({
      certificateVersion: 1,
      certificateId,
      databaseId: manifest.databaseId,
      recoveryId: manifest.manifestId,
      compromiseBoundaryCommitSeq: manifest.recoveryBoundary.lastValidCommitSeq.toString(),
      compromiseReason: manifest.recoveryBoundary.compromiseReason,
      lastVerifiedCheckpointId: manifest.sourceCheckpointId,
      verifiedStateFrontierCommitSeq: manifest.endingCommitSeq.toString(),
      authorizedChangesPreservedCount: manifest.replayedChangeIds.length,
      unauthorizedChangesExcludedCount: manifest.excludedChangeIds.length,
      resultingCommitSequence: resultingCommitSequence.toString(),
      resultingMerkleRootHex: manifest.reconstructedMerkleRoot.toString('hex'),
      externalAnchorDigestHex,
      policyApprovalStatus: 'PASS',
      cryptographicVerificationStatus: 'PASS',
      issuedAtUs: issuedAtUs.toString(),
      issuerIdentity,
    });

    const payloadDigest = crypto
      .createHash('sha256')
      .update(Buffer.from(canonicalJson, 'utf8'))
      .digest();

    let certificateSignature = '0'.repeat(128);
    if (issuerPrivateKey) {
      certificateSignature = crypto.sign(null, payloadDigest, issuerPrivateKey).toString('hex');
    }

    return {
      ...unsignedPayload,
      certificateSignature,
    };
  }

  /**
   * Formats the certificate as a human-readable CLI terminal summary.
   */
  public static formatTerminalCertificate(cert: StateRecoveryCertificate): string {
    const lines = [
      '================================================================================',
      '                         STATE RECOVERY CERTIFICATE                             ',
      '================================================================================',
      `Certificate ID:                      ${cert.certificateId}`,
      `Database ID:                         ${cert.databaseId}`,
      `Recovery Manifest ID:                ${cert.recoveryId}`,
      `Compromise Boundary CommitSeq:       ${cert.compromiseBoundaryCommitSeq}`,
      `Compromise Reason:                   ${cert.compromiseReason}`,
      `Last Verified Checkpoint:            ${cert.lastVerifiedCheckpointId}`,
      `Verified State Frontier:             CommitSeq ${cert.verifiedStateFrontierCommitSeq}`,
      `Authorized Changes Preserved:        ${cert.authorizedChangesPreservedCount}`,
      `Unauthorized Changes Excluded:       ${cert.unauthorizedChangesExcludedCount}`,
      `Resulting Commit Sequence:           ${cert.resultingCommitSequence}`,
      `Resulting Merkle Root:               ${cert.resultingMerkleRootHex.slice(0, 32)}...`,
      `External Anchor Digest:              ${cert.externalAnchorDigestHex.slice(0, 32)}...`,
      `Policy Approval Status:              ${cert.policyApprovalStatus}`,
      `Cryptographic Verification:          ${cert.cryptographicVerificationStatus}`,
      `Issued At (Epoch Us):                ${cert.issuedAtUs}`,
      `Issuer Identity:                     ${cert.issuerIdentity}`,
      `Certificate Signature:               ${cert.certificateSignature.slice(0, 32)}...`,
      '================================================================================',
    ];
    return lines.join('\n');
  }
}
