import crypto from 'node:crypto';
import {
  ImmutableTrustReceipt,
} from '../bft_hardening/types.js';
import { PortableTrustProof, OfflineProofVerificationResult } from '../trust_network/types.js';
import { OfflineTrustProofVerifier } from '../trust_network/proof.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export function computeTrustReceiptDigest(
  receipt: Omit<ImmutableTrustReceipt, 'receiptDigestHex'>
): Buffer {
  const domain = Buffer.from('WDB:RECEIPT:v1:', 'utf8');
  const canonicalPayload = canonicalizeJson({
    receiptVersion: receipt.receiptVersion,
    receiptId: receipt.receiptId,
    tenantId: receipt.tenantId,
    databaseId: receipt.databaseId,
    databaseTime: receipt.databaseTime,
    trustTime: receipt.trustTime,
    consensus: receipt.consensus,
    portableProof: receipt.portableProof,
  });

  return crypto
    .createHash('sha256')
    .update(Buffer.concat([domain, Buffer.from(canonicalPayload, 'utf8')]))
    .digest();
}

export class ImmutableTrustReceiptGenerator {
  public static generateReceipt(
    proof: PortableTrustProof,
    merkleStateRoot: Buffer
  ): ImmutableTrustReceipt {
    const receiptBase = {
      receiptVersion: 1 as const,
      receiptId: `rcpt-${proof.commitment.commitmentId}`,
      tenantId: proof.tenantId,
      databaseId: proof.databaseId,
      databaseTime: {
        checkpointId: proof.commitment.checkpointId,
        commitSeq: proof.commitment.commitSeq,
        checkpointDigestHex: proof.commitment.checkpointDigestHex,
      },
      trustTime: {
        ledgerSeq: proof.ledgerRecord.ledgerSeq,
        epoch: proof.quorumCertificate.epoch,
        finalizedAtUs: proof.quorumCertificate.finalizedAtUs,
        merkleStateRootHex: merkleStateRoot.toString('hex'),
      },
      consensus: {
        validatorSetId: proof.quorumCertificate.validatorSetId,
        quorumCount: proof.quorumCertificate.quorumCount,
        totalValidators: proof.quorumCertificate.totalValidators,
        quorumCertificateDigestHex: proof.quorumCertificate.certificateDigestHex,
      },
      portableProof: proof,
    };

    const receiptDigest = computeTrustReceiptDigest(receiptBase);

    return {
      ...receiptBase,
      receiptDigestHex: receiptDigest.toString('hex'),
    };
  }
}

export class ImmutableTrustReceiptVerifier {
  public static verifyReceiptOffline(receipt: ImmutableTrustReceipt): {
    isValid: boolean;
    status: string;
    details?: Record<string, unknown> | undefined;
  } {
    // 1. Verify Receipt Payload Digest
    const recomputedDigest = computeTrustReceiptDigest(receipt);
    if (!timingSafeEqualHashes(Buffer.from(receipt.receiptDigestHex, 'hex'), recomputedDigest)) {
      return {
        isValid: false,
        status: 'MALFORMED_RECEIPT',
      };
    }

    // 2. Verify Embedded Portable Proof
    const proofResult: OfflineProofVerificationResult = OfflineTrustProofVerifier.verifyPortableProof(receipt.portableProof);
    if (!proofResult.isValid) {
      return {
        isValid: false,
        status: `INVALID_EMBEDDED_PROOF: ${proofResult.reason}`,
      };
    }

    // 3. Cross-Timeline Consistency Checks
    if (receipt.databaseTime.commitSeq !== receipt.portableProof.commitment.commitSeq) {
      return {
        isValid: false,
        status: 'TIMELINE_SEQUENCE_MISMATCH',
      };
    }

    if (receipt.trustTime.ledgerSeq !== receipt.portableProof.ledgerRecord.ledgerSeq) {
      return {
        isValid: false,
        status: 'LEDGER_SEQUENCE_MISMATCH',
      };
    }

    return {
      isValid: true,
      status: 'AUTHENTIC_RECEIPT',
      details: {
        tenantId: receipt.tenantId,
        databaseId: receipt.databaseId,
        commitSeq: receipt.databaseTime.commitSeq,
        ledgerSeq: receipt.trustTime.ledgerSeq,
        finalizedAtUs: receipt.trustTime.finalizedAtUs,
        quorumCount: receipt.consensus.quorumCount,
      },
    };
  }
}
