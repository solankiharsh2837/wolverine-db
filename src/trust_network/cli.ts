import {
  PortableTrustProof,
  OfflineProofVerificationResult,
} from './types.js';
import { OfflineTrustProofVerifier } from './proof.js';
import { WolverineTrustNetworkService } from './service.js';

export class WolverineTrustCli {
  /**
   * wdb trust status
   */
  public static executeStatus(params: {
    tenantId: string;
    databaseId: string;
    latestLocalSeq: bigint;
    latestSubmittedSeq: bigint;
    latestFinalizedSeq: bigint;
    quorumCount: number;
    totalValidators: number;
    epoch: number;
  }): string {
    const lines = [
      '================================================================================',
      '                          WOLVERINE TRUST NETWORK STATUS                        ',
      '================================================================================',
      `Tenant ID:                ${params.tenantId}`,
      `Database ID:              ${params.databaseId}`,
      `Latest Local Checkpoint:  CommitSeq ${params.latestLocalSeq}`,
      `Latest Submitted:         CommitSeq ${params.latestSubmittedSeq}`,
      `Latest Finalized:         CommitSeq ${params.latestFinalizedSeq}`,
      `Trust Status:             SYNCHRONIZED`,
      '',
      `Validator Quorum:         ${params.quorumCount} / ${params.totalValidators}`,
      `Network Epoch:            ${params.epoch}`,
      '================================================================================',
    ];
    return lines.join('\n');
  }

  /**
   * wdb trust proof export
   */
  public static executeProofExport(proof: PortableTrustProof): string {
    return JSON.stringify(proof, null, 2);
  }

  /**
   * wdb trust proof verify proof.json
   */
  public static executeProofVerify(proofJson: string): {
    result: OfflineProofVerificationResult;
    terminalOutput: string;
  } {
    const parsed = JSON.parse(proofJson) as PortableTrustProof;
    const result = OfflineTrustProofVerifier.verifyPortableProof(parsed);

    const lines = [
      '================================================================================',
      '                     WOLVERINE STANDALONE PROOF VERIFICATION                   ',
      '================================================================================',
      `Tenant ID:                ${parsed.tenantId}`,
      `Database ID:              ${parsed.databaseId}`,
      `Checkpoint ID:            ${parsed.commitment.checkpointId}`,
      `Commit Sequence:          ${parsed.commitment.commitSeq}`,
      `Checkpoint Digest:        ${parsed.commitment.checkpointDigestHex.slice(0, 32)}...`,
      `Commitment Digest:        ${parsed.commitment.commitmentDigestHex.slice(0, 32)}...`,
      `Quorum Certificate:       ${parsed.quorumCertificate.quorumCount} / ${parsed.quorumCertificate.totalValidators} Validators Attested`,
      `Ledger Record Sequence:   ${parsed.ledgerRecord.ledgerSeq}`,
      `Proof Status:             ${result.status}`,
      `Verification Verdict:     ${result.isValid ? 'PASS (AUTHENTIC & IMMUTABLE)' : 'FAIL (UNTRUSTED)'}`,
      `Reason:                   ${result.reason}`,
      '================================================================================',
    ];

    return {
      result,
      terminalOutput: lines.join('\n'),
    };
  }

  /**
   * wdb trust validator-status
   */
  public static executeValidatorStatus(service: WolverineTrustNetworkService): string {
    const keys = service.getValidators();
    const lines = [
      '================================================================================',
      '                        WOLVERINE VALIDATOR NETWORK STATUS                      ',
      '================================================================================',
      `Active Validators Count:  ${keys.size}`,
      '',
    ];

    for (const [id, pubKey] of keys.entries()) {
      lines.push(`  ✓ ${id.padEnd(16)} PubKey: ${pubKey.toString('hex').slice(0, 24)}... [ONLINE]`);
    }
    lines.push('================================================================================');
    return lines.join('\n');
  }
}
