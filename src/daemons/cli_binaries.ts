import { ImmutableTrustReceipt } from '../bft_hardening/types.js';
import { ImmutableTrustReceiptVerifier } from '../trust_receipt/receipt.js';

export class WolverineReceiptCli {
  /**
   * wdb receipt verify receipt.json
   */
  public static executeVerifyReceipt(receipt: ImmutableTrustReceipt): string {
    const res = ImmutableTrustReceiptVerifier.verifyReceiptOffline(receipt);
    const lines = [
      '================================================================================',
      '                     WOLVERINE IMMUTABLE TRUST RECEIPT VERIFIER                 ',
      '================================================================================',
      `Receipt ID:               ${receipt.receiptId}`,
      `Tenant ID:                ${receipt.tenantId}`,
      `Database ID:              ${receipt.databaseId}`,
      `Database Time:            CommitSeq ${receipt.databaseTime.commitSeq}`,
      `Checkpoint ID:            ${receipt.databaseTime.checkpointId}`,
      `Checkpoint Digest:        ${receipt.databaseTime.checkpointDigestHex.slice(0, 32)}...`,
      `Trust Time:               LedgerSeq ${receipt.trustTime.ledgerSeq} (Epoch ${receipt.trustTime.epoch})`,
      `Merkle State Root:        ${receipt.trustTime.merkleStateRootHex.slice(0, 32)}...`,
      `Byzantine Consensus:      ${receipt.consensus.quorumCount} / ${receipt.consensus.totalValidators} Validators Attested`,
      `Receipt Status:           ${res.status}`,
      `Cryptographic Verdict:    ${res.isValid ? 'AUTHENTIC & IMMUTABLE (PASS)' : 'INVALID / TAMPERED (FAIL)'}`,
      '================================================================================',
      'Guarantee: Your database can lie. Your audit trail cannot.',
      '================================================================================',
    ];
    return lines.join('\n');
  }
}
