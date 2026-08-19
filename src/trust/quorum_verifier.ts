import crypto from 'node:crypto';
import { CanonicalQuorumCertificate, computeCanonicalQuorumCertificateDigest } from './quorum_certificate.js';
import { ValidatorSetManager } from './validator_set.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export class IndependentQuorumVerifier {
  /**
   * Independently verifies a Quorum Certificate against an authoritative validator set.
   * Requires zero trust in gateway or coordinator nodes.
   */
  public static verify(
    cert: CanonicalQuorumCertificate,
    validatorSetManager: ValidatorSetManager
  ): { valid: boolean; verifiedSignatures: number; commitmentDigest: Buffer } {
    // 1. Recompute Certificate Envelope Digest
    const computedDigest = computeCanonicalQuorumCertificateDigest(cert);
    const storedDigest = Buffer.from(cert.certificateDigestHex, 'hex');

    if (!timingSafeEqualHashes(computedDigest, storedDigest)) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
        'Quorum certificate digest envelope integrity check failed'
      );
    }

    // 2. Validator Set Binding Check
    if (cert.validatorSetId !== validatorSetManager.validatorSetId) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `Validator set mismatch: expected ${validatorSetManager.validatorSetId}, observed ${cert.validatorSetId}`
      );
    }

    // 3. Quorum Count Check
    if (cert.attestations.length < validatorSetManager.quorumThreshold) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
        `Quorum threshold violation: certificate contains ${cert.attestations.length} signatures, threshold requires ${validatorSetManager.quorumThreshold}`
      );
    }

    // 4. Verify Individual Validator Signatures
    const commitmentDigest = Buffer.from(cert.commitmentDigestHex, 'hex');
    const seenValidators = new Set<string>();
    let verifiedCount = 0;

    for (const att of cert.attestations) {
      if (seenValidators.has(att.validatorId)) {
        throw new WolverineError(
          WolverineErrorCode.DUPLICATE_FIELD_TAG,
          `Duplicate validator signature in quorum certificate for validator "${att.validatorId}"`
        );
      }

      if (!validatorSetManager.hasValidator(att.validatorId)) {
        throw new WolverineError(
          WolverineErrorCode.UNTRUSTED_APPROVER_KEY,
          `Unknown validator "${att.validatorId}" in quorum certificate`
        );
      }

      if (att.commitmentDigestHex !== cert.commitmentDigestHex) {
        throw new WolverineError(
          WolverineErrorCode.CHANGE_HASH_MISMATCH,
          `Attestation digest mismatch for validator "${att.validatorId}"`
        );
      }

      if (att.commitSeq !== cert.commitSeq) {
        throw new WolverineError(
          WolverineErrorCode.SEQUENCE_GAP_DETECTED,
          `Attestation sequence mismatch for validator "${att.validatorId}"`
        );
      }

      const pubkeyObj = validatorSetManager.getPublicKeyObject(att.validatorId);
      if (!pubkeyObj) {
        throw new WolverineError(
          WolverineErrorCode.UNTRUSTED_APPROVER_KEY,
          `Public key not found for validator "${att.validatorId}"`
        );
      }

      const attDigest = this.computeAttestationDigest(
        att.validatorId,
        commitmentDigest,
        att.epoch,
        att.commitSeq,
        att.attestationTimestampUs
      );

      const sigBuf = Buffer.from(att.signatureHex, 'hex');
      const isValid = crypto.verify(null, attDigest, pubkeyObj, sigBuf);

      if (!isValid) {
        throw new WolverineError(
          WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
          `Invalid cryptographic signature for validator "${att.validatorId}"`
        );
      }

      seenValidators.add(att.validatorId);
      verifiedCount++;
    }

    if (verifiedCount < validatorSetManager.quorumThreshold) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
        `Verified signatures count (${verifiedCount}) is below required quorum (${validatorSetManager.quorumThreshold})`
      );
    }

    return {
      valid: true,
      verifiedSignatures: verifiedCount,
      commitmentDigest,
    };
  }

  private static computeAttestationDigest(
    validatorId: string,
    commitmentDigest: Buffer,
    epoch: number,
    commitSeq: bigint,
    timestampUs: bigint
  ): Buffer {
    const valIdBuf = Buffer.from(validatorId, 'utf8');
    const valIdLenBuf = Buffer.alloc(2);
    valIdLenBuf.writeUInt16BE(valIdBuf.length, 0);

    const epochBuf = Buffer.alloc(4);
    epochBuf.writeUInt32BE(epoch, 0);

    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(commitSeq, 0);

    const timeBuf = Buffer.alloc(8);
    timeBuf.writeBigInt64BE(timestampUs, 0);

    const preimage = Buffer.concat([
      Buffer.from('WDB:VAL_ATTEST:v2:', 'utf8'),
      commitmentDigest,
      valIdLenBuf,
      valIdBuf,
      epochBuf,
      seqBuf,
      timeBuf,
    ]);

    return crypto.createHash('sha256').update(preimage).digest();
  }
}
