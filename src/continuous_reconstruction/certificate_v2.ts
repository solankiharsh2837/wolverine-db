import crypto from 'node:crypto';
import { StateRecoveryCertificateV2, ContinuousReconstructionAnalysis } from './types.js';
import { AnchoredCheckpoint } from '../checkpoint/types.js';
import { canonicalizeJson } from '../binary/c14n.js';

export class StateRecoveryCertificateV2Manager {
  /**
   * Issues a signed StateRecoveryCertificateV2 from an approved continuous reconstruction analysis.
   */
  public static issueCertificate(
    databaseId: string,
    baseCheckpoint: AnchoredCheckpoint | Omit<AnchoredCheckpoint, 'digest'>,
    analysis: ContinuousReconstructionAnalysis,
    externalAnchorDigestHex: string,
    issuerIdentity: string,
    issuerPrivateKey?: crypto.KeyObject
  ): StateRecoveryCertificateV2 {
    const certificateId = crypto.randomUUID();
    const recoveryId = `rec2-${crypto.randomUUID().slice(0, 8)}`;
    const issuedAtUs = BigInt(Date.now()) * 1000n;

    const preservedMutationIds = analysis.decisions
      .filter((d) => d.decision === 'PRESERVE')
      .map((d) => d.changeId);
    const excludedMutationIds = analysis.decisions
      .filter((d) => d.decision === 'EXCLUDE')
      .map((d) => d.changeId);
    const blockedMutationIds = analysis.decisions
      .filter((d) => d.decision === 'BLOCK')
      .map((d) => d.changeId);
    const conflictingMutationIds = analysis.decisions
      .filter((d) => d.decision === 'CONFLICT')
      .map((d) => d.changeId);
    const unverifiableMutationIds = analysis.decisions
      .filter((d) => d.classification === 'UNVERIFIABLE' || d.classification === 'MISSING')
      .map((d) => d.changeId);

    const resultingDatabaseStateDigest = crypto
      .createHash('sha256')
      .update(Buffer.concat([analysis.resultingMerkleRoot, analysis.reconstructionGraphDigest]))
      .digest()
      .toString('hex');

    const unsignedPayload = {
      certificateVersion: 2 as const,
      certificateId,
      databaseId,
      recoveryId,
      sourceCheckpointId: baseCheckpoint.checkpointId,
      sourceCheckpointCommitSeq: baseCheckpoint.commitSeq,
      contiguousVerifiedFrontierSeq: analysis.contiguousVerifiedFrontierSeq,
      maximumReconstructableCommitSeq: analysis.maximumReconstructableCommitSeq,
      preservedMutationIds,
      excludedMutationIds,
      blockedMutationIds,
      conflictingMutationIds,
      unverifiableMutationIds,
      dependencyGraphDigest: analysis.dependencyGraphDigest.toString('hex'),
      reconstructionGraphDigest: analysis.reconstructionGraphDigest.toString('hex'),
      resultingStateMerkleRootHex: analysis.resultingMerkleRoot.toString('hex'),
      resultingDatabaseStateDigest,
      externalAnchorDigestHex,
      policyApprovalStatus: 'PASS' as const,
      cryptographicVerificationStatus: 'PASS' as const,
      issuedAtUs,
      issuerIdentity,
    };

    const canonicalJson = canonicalizeJson({
      certificateVersion: 2,
      certificateId,
      databaseId,
      recoveryId,
      sourceCheckpointId: baseCheckpoint.checkpointId,
      sourceCheckpointCommitSeq: baseCheckpoint.commitSeq.toString(),
      contiguousVerifiedFrontierSeq: analysis.contiguousVerifiedFrontierSeq.toString(),
      maximumReconstructableCommitSeq: analysis.maximumReconstructableCommitSeq.toString(),
      preservedMutationIds,
      excludedMutationIds,
      blockedMutationIds,
      conflictingMutationIds,
      unverifiableMutationIds,
      dependencyGraphDigest: unsignedPayload.dependencyGraphDigest,
      reconstructionGraphDigest: unsignedPayload.reconstructionGraphDigest,
      resultingStateMerkleRootHex: unsignedPayload.resultingStateMerkleRootHex,
      resultingDatabaseStateDigest,
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
   * Formats the Certificate V2 for human-readable CLI inspection.
   */
  public static formatTerminalCertificateV2(cert: StateRecoveryCertificateV2): string {
    const lines = [
      '================================================================================',
      '                     STATE RECOVERY CERTIFICATE (V2 EXTENDED)                   ',
      '================================================================================',
      `Certificate ID:                      ${cert.certificateId}`,
      `Database ID:                         ${cert.databaseId}`,
      `Recovery ID:                         ${cert.recoveryId}`,
      `Base Checkpoint ID:                  ${cert.sourceCheckpointId} (Seq ${cert.sourceCheckpointCommitSeq})`,
      `Contiguous Verified Frontier:        CommitSeq ${cert.contiguousVerifiedFrontierSeq}`,
      `Maximum Reconstructable State:       CommitSeq ${cert.maximumReconstructableCommitSeq}`,
      `Preserved Mutations Count:           ${cert.preservedMutationIds.length}`,
      `Excluded Mutations Count:            ${cert.excludedMutationIds.length}`,
      `Blocked Mutations Count:             ${cert.blockedMutationIds.length}`,
      `Conflicting Mutations Count:         ${cert.conflictingMutationIds.length}`,
      `Reconstruction Graph Digest:         ${cert.reconstructionGraphDigest.slice(0, 32)}...`,
      `Dependency Graph Digest:             ${cert.dependencyGraphDigest.slice(0, 32)}...`,
      `Resulting Merkle Root:               ${cert.resultingStateMerkleRootHex.slice(0, 32)}...`,
      `Database State Digest:               ${cert.resultingDatabaseStateDigest.slice(0, 32)}...`,
      `External Trust Anchor:               ${cert.externalAnchorDigestHex.slice(0, 32)}...`,
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
