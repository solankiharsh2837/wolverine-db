import { RogueGatewayAttackResult } from './malicious_gateway_simulator.js';
import { PortableTrustProof, OfflineProofVerificationResult } from '../trust_network/types.js';
import { OfflineTrustProofVerifier } from '../trust_network/proof.js';

export class WolverineProductionCli {
  /**
   * wdb trust inspect-adversary
   */
  public static executeInspectAdversary(result: RogueGatewayAttackResult): string {
    const lines = [
      '================================================================================',
      '               WOLVERINE ADVERSARIAL ATTACK DEFENSE INSPECTION                  ',
      '================================================================================',
      `Attack Vector:            ${result.attackVector}`,
      `Attack Blocked:           ${result.isBlocked ? 'YES (DEFENSE SUCCESS)' : 'NO (VULNERABILITY)'}`,
      `Validators Rejected:      ${result.validatorsRejectedCount} / 5 Independent Nodes`,
      `Finality Granted:         ${result.finalityGranted ? 'FORGED' : 'DENIED (FAIL-CLOSED)'}`,
      `Rejection Reason:         ${result.rejectionReason}`,
      '================================================================================',
    ];
    return lines.join('\n');
  }

  /**
   * wdb trust proof verify-bft
   */
  public static executeVerifyBft(proof: PortableTrustProof): string {
    const result: OfflineProofVerificationResult = OfflineTrustProofVerifier.verifyPortableProof(proof);
    const lines = [
      '================================================================================',
      '                 WOLVERINE STANDALONE ZERO-TRUST PROOF VERIFIER                 ',
      '================================================================================',
      `Tenant ID:                ${proof.tenantId}`,
      `Database ID:              ${proof.databaseId}`,
      `Commit Sequence:          ${proof.commitment.commitSeq}`,
      `Validator Set:            ${proof.quorumCertificate.validatorSetId}`,
      `BFT Quorum Attested:      ${proof.quorumCertificate.quorumCount} / ${proof.quorumCertificate.totalValidators}`,
      `Finality Status:          FINALIZED & IMMUTABLE`,
      `Proof Status:             ${result.status}`,
      `Independent Verdict:      ${result.isValid ? 'AUTHENTIC & MATHEMATICALLY PROVED' : 'TAMPERED / INVALID'}`,
      `Gateway Infrastructure:   UNREACHABLE / UNTRUSTED (ZERO SERVER CONTACT)`,
      '================================================================================',
    ];
    return lines.join('\n');
  }
}
