import crypto from 'node:crypto';
import {
  TrustCommitment,
  QuorumCertificate,
  TrustLedgerRecord,
  PortableTrustProof,
  OfflineProofVerificationResult,
} from './types.js';
import { verifyCustomerCommitment } from './commitment.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';
import { computeQuorumCertificateDigest } from './consensus.js';
import { computeAttestationDigest } from './validator.js';

export function computePortableProofDigest(
  proof: Omit<PortableTrustProof, 'proofDigestHex'>
): Buffer {
  const domain = Buffer.from('WDB:PROOF_VERIFY:v1:', 'utf8');

  const canonicalPayload = canonicalizeJson({
    proofVersion: proof.proofVersion,
    tenantId: proof.tenantId,
    databaseId: proof.databaseId,
    commitment: proof.commitment,
    validatorSet: proof.validatorSet,
    quorumCertificate: proof.quorumCertificate,
    validatorAttestations: proof.validatorAttestations,
    ledgerRecord: proof.ledgerRecord,
  });

  return crypto
    .createHash('sha256')
    .update(Buffer.concat([domain, Buffer.from(canonicalPayload, 'utf8')]))
    .digest();
}

export class PortableTrustProofGenerator {
  public static generateProof(
    commitment: TrustCommitment,
    quorumCertificate: QuorumCertificate,
    ledgerRecord: TrustLedgerRecord,
    validatorPublicKeys: Map<string, Buffer>
  ): PortableTrustProof {
    const validatorSet = Array.from(validatorPublicKeys.entries()).map(([id, key]) => ({
      validatorId: id,
      publicKeyHex: key.toString('hex'),
    }));

    const validatorAttestations = quorumCertificate.attestations.map((a) => ({
      validatorId: a.validatorId,
      observedCommitmentDigestHex: a.observedCommitmentDigest.toString('hex'),
      signatureHex: a.signature.toString('hex'),
      timestampUs: a.timestampUs.toString(),
    }));

    const proofBase = {
      proofVersion: 1,
      tenantId: commitment.tenantId,
      databaseId: commitment.databaseId,
      commitment: {
        commitmentId: commitment.commitmentId,
        checkpointId: commitment.checkpointId,
        commitSeq: commitment.commitSeq.toString(),
        checkpointDigestHex: commitment.checkpointDigest.toString('hex'),
        previousTrustCommitmentHex: commitment.previousTrustCommitment.toString('hex'),
        protocolVersion: commitment.protocolVersion,
        logicalTimestamp: commitment.logicalTimestamp.toString(),
        epoch: commitment.epoch,
        validatorSetId: commitment.validatorSetId,
        customerPubkeyHex: commitment.customerPubkey.toString('hex'),
        customerSignatureHex: commitment.customerSignature.toString('hex'),
        commitmentDigestHex: commitment.commitmentDigest.toString('hex'),
      },
      validatorSet,
      quorumCertificate: {
        commitmentId: quorumCertificate.commitmentId,
        commitmentDigestHex: quorumCertificate.commitmentDigest.toString('hex'),
        validatorSetId: quorumCertificate.validatorSetId,
        epoch: quorumCertificate.epoch,
        quorumCount: quorumCertificate.quorumCount,
        totalValidators: quorumCertificate.totalValidators,
        finalizedAtUs: quorumCertificate.finalizedAtUs.toString(),
        certificateDigestHex: quorumCertificate.certificateDigest.toString('hex'),
      },
      validatorAttestations,
      ledgerRecord: {
        ledgerSeq: ledgerRecord.ledgerSeq.toString(),
        previousRecordDigestHex: ledgerRecord.previousRecordDigest.toString('hex'),
        recordDigestHex: ledgerRecord.recordDigest.toString('hex'),
      },
    };

    const proofDigestHex = computePortableProofDigest(proofBase).toString('hex');

    return {
      ...proofBase,
      proofDigestHex,
    };
  }
}

export class OfflineTrustProofVerifier {
  /**
   * Performs 100% offline verification of a PortableTrustProof without contacting any server.
   */
  public static verifyPortableProof(proof: PortableTrustProof): OfflineProofVerificationResult {
    // 1. Check Protocol Version
    if (proof.proofVersion !== 1) {
      return {
        status: 'EXPIRED_PROTOCOL',
        isValid: false,
        reason: `Unsupported proof version: ${proof.proofVersion}`,
      };
    }

    // 2. Verify Customer Commitment Digest and Signature
    const commitmentObj: TrustCommitment = {
      commitmentId: proof.commitment.commitmentId,
      tenantId: proof.tenantId,
      databaseId: proof.databaseId,
      checkpointId: proof.commitment.checkpointId,
      commitSeq: BigInt(proof.commitment.commitSeq),
      checkpointDigest: Buffer.from(proof.commitment.checkpointDigestHex, 'hex'),
      previousTrustCommitment: Buffer.from(proof.commitment.previousTrustCommitmentHex, 'hex'),
      protocolVersion: proof.commitment.protocolVersion,
      logicalTimestamp: BigInt(proof.commitment.logicalTimestamp),
      epoch: proof.commitment.epoch,
      validatorSetId: proof.commitment.validatorSetId,
      customerPubkey: Buffer.from(proof.commitment.customerPubkeyHex, 'hex'),
      customerSignature: Buffer.from(proof.commitment.customerSignatureHex, 'hex'),
      commitmentDigest: Buffer.from(proof.commitment.commitmentDigestHex, 'hex'),
    };

    const isCustomerValid = verifyCustomerCommitment(commitmentObj);
    if (!isCustomerValid) {
      return {
        status: 'INVALID_SIGNATURE',
        isValid: false,
        reason: 'Customer commitment signature or tenant binding verification failed',
      };
    }

    // 3. Verify Quorum Certificate Binding
    if (proof.quorumCertificate.commitmentDigestHex !== proof.commitment.commitmentDigestHex) {
      return {
        status: 'EQUIVOCATION',
        isValid: false,
        reason: 'Quorum certificate commitment digest does not match customer commitment digest',
      };
    }

    const expectedCertDigest = computeQuorumCertificateDigest(
      proof.quorumCertificate.commitmentId,
      proof.quorumCertificate.commitmentDigestHex,
      proof.quorumCertificate.validatorSetId,
      proof.quorumCertificate.epoch,
      proof.quorumCertificate.quorumCount,
      proof.quorumCertificate.totalValidators,
      BigInt(proof.quorumCertificate.finalizedAtUs)
    );

    if (proof.quorumCertificate.certificateDigestHex !== expectedCertDigest.toString('hex')) {
      return {
        status: 'MALFORMED_PROOF',
        isValid: false,
        reason: 'Quorum certificate digest mismatch',
      };
    }

    // 4. Verify Validator Attestations & Quorum Count
    const valKeyMap = new Map<string, Buffer>();
    for (const v of proof.validatorSet) {
      valKeyMap.set(v.validatorId, Buffer.from(v.publicKeyHex, 'hex'));
    }

    let validAttestationCount = 0;

    for (const att of proof.validatorAttestations) {
      const pubKey = valKeyMap.get(att.validatorId);
      if (!pubKey) continue;

      if (att.observedCommitmentDigestHex !== proof.commitment.commitmentDigestHex) {
        continue;
      }

      const attDigest = computeAttestationDigest(
        proof.commitment.commitmentId,
        att.validatorId,
        Buffer.from(att.observedCommitmentDigestHex, 'hex'),
        BigInt(att.timestampUs)
      );

      try {
        const pubKeyObject = crypto.createPublicKey({
          key: Buffer.concat([
            Buffer.from('302a300506032b6570032100', 'hex'),
            pubKey,
          ]),
          format: 'der',
          type: 'spki',
        });

        if (crypto.verify(null, attDigest, pubKeyObject, Buffer.from(att.signatureHex, 'hex'))) {
          validAttestationCount++;
        }
      } catch {
        // Invalid signature ignored
      }
    }

    if (validAttestationCount < proof.quorumCertificate.quorumCount) {
      return {
        status: 'INVALID_QUORUM',
        isValid: false,
        reason: `Only ${validAttestationCount}/${proof.quorumCertificate.quorumCount} valid validator attestations found`,
      };
    }

    // 5. Verify Overall Proof Digest
    const recomputedProofDigest = computePortableProofDigest(proof);
    if (!timingSafeEqualHashes(Buffer.from(proof.proofDigestHex, 'hex'), recomputedProofDigest)) {
      return {
        status: 'MALFORMED_PROOF',
        isValid: false,
        reason: 'Portable proof payload digest mismatch',
      };
    }

    return {
      status: 'VALID',
      isValid: true,
      reason: `Proof verified: Quorum ${validAttestationCount}/${proof.quorumCertificate.totalValidators} validators attested commitment at ledgerSeq ${proof.ledgerRecord.ledgerSeq}`,
      details: {
        tenantId: proof.tenantId,
        databaseId: proof.databaseId,
        checkpointId: proof.commitment.checkpointId,
        commitSeq: proof.commitment.commitSeq,
        finalizedAtUs: proof.quorumCertificate.finalizedAtUs,
      },
    };
  }
}
