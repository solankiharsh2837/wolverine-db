import { ValidatorStateProof } from './types.js';
import { ImmutableTrustReceiptVerifier } from '../trust_receipt/receipt.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export class ValidatorStateProofEngine {
  /**
   * Compares candidate state claims from peer validators and selects the latest state
   * that is mathematically supported by verified finality evidence.
   */
  public static selectAuthoritativeState(
    candidateProofs: ValidatorStateProof[]
  ): ValidatorStateProof {
    const verifiedCandidates: ValidatorStateProof[] = [];

    for (const proof of candidateProofs) {
      if (proof.latestReceipt) {
        const verifyRes = ImmutableTrustReceiptVerifier.verifyReceiptOffline(proof.latestReceipt);
        if (verifyRes.isValid) {
          verifiedCandidates.push(proof);
        }
      }
    }

    if (verifiedCandidates.length === 0) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
        'No candidate state claims possess valid cryptographic finality receipts'
      );
    }

    // Select the highest verified ledger sequence
    verifiedCandidates.sort((a, b) => (b.ledgerSeq > a.ledgerSeq ? 1 : b.ledgerSeq < a.ledgerSeq ? -1 : 0));

    return verifiedCandidates[0]!;
  }
}
