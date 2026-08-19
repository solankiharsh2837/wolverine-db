import crypto from 'node:crypto';
import { CanonicalCommitment, computeCanonicalCommitmentDigest } from './commitment.js';
import { ValidatorAttestation } from './validator_state_machine.js';
import { ValidatorSetManager } from './validator_set.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface CanonicalQuorumCertificate {
  certificateVersion: number;
  commitmentId: string;
  commitmentDigestHex: string;
  validatorSetId: string;
  epoch: number;
  commitSeq: bigint;
  quorumCount: number;
  totalValidators: number;
  finalizedAtUs: bigint;
  attestations: ValidatorAttestation[];
  certificateDigestHex: string;
}

export function computeCanonicalQuorumCertificateDigest(
  cert: Omit<CanonicalQuorumCertificate, 'certificateDigestHex'>
): Buffer {
  const rawPayload = {
    certificateVersion: cert.certificateVersion,
    commitmentId: cert.commitmentId,
    commitmentDigestHex: cert.commitmentDigestHex,
    validatorSetId: cert.validatorSetId,
    epoch: cert.epoch,
    commitSeq: cert.commitSeq.toString(),
    quorumCount: cert.quorumCount,
    totalValidators: cert.totalValidators,
    finalizedAtUs: cert.finalizedAtUs.toString(),
  };

  const canonicalJson = canonicalizeJson(rawPayload);
  return crypto
    .createHash('sha256')
    .update(Buffer.from(`WDB:QUORUM_CERT:v2:${canonicalJson}`, 'utf8'))
    .digest();
}

export class QuorumAggregator {
  /**
   * Aggregates independent validator attestations, validates threshold, and forms a Quorum Certificate.
   */
  public static aggregate(
    commitment: CanonicalCommitment,
    attestations: ValidatorAttestation[],
    validatorSetManager: ValidatorSetManager
  ): CanonicalQuorumCertificate {
    const commitmentDigest = computeCanonicalCommitmentDigest(commitment);
    const digestHex = commitmentDigest.toString('hex');

    const seenValidators = new Set<string>();
    const validAttestations: ValidatorAttestation[] = [];

    for (const att of attestations) {
      // 1. Validator membership check
      if (!validatorSetManager.hasValidator(att.validatorId)) {
        continue;
      }

      // 2. Deduplicate validator IDs
      if (seenValidators.has(att.validatorId)) {
        continue;
      }

      // 3. Digest and sequence alignment
      if (att.commitmentDigestHex !== digestHex || att.commitSeq !== commitment.commitSeq || att.epoch !== commitment.epoch) {
        continue;
      }

      // 4. Verify cryptographic signature
      const pubkeyObj = validatorSetManager.getPublicKeyObject(att.validatorId);
      if (!pubkeyObj) continue;

      const attDigest = this.computeAttestationDigest(
        att.validatorId,
        commitmentDigest,
        att.epoch,
        att.commitSeq,
        att.attestationTimestampUs
      );

      const sigBuf = Buffer.from(att.signatureHex, 'hex');
      const isValid = crypto.verify(null, attDigest, pubkeyObj, sigBuf);

      if (isValid) {
        seenValidators.add(att.validatorId);
        validAttestations.push(att);
      }
    }

    if (validAttestations.length < validatorSetManager.quorumThreshold) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
        `CONSENSUS_UNAVAILABLE: Insufficient validator signatures. Required ${validatorSetManager.quorumThreshold}, obtained ${validAttestations.length} for sequence ${commitment.commitSeq}`
      );
    }

    const finalizedAtUs = BigInt(Date.now()) * 1000n;
    const partialCert = {
      certificateVersion: 2,
      commitmentId: commitment.commitmentId,
      commitmentDigestHex: digestHex,
      validatorSetId: validatorSetManager.validatorSetId,
      epoch: commitment.epoch,
      commitSeq: commitment.commitSeq,
      quorumCount: validAttestations.length,
      totalValidators: validatorSetManager.totalValidators,
      finalizedAtUs,
      attestations: validAttestations,
    };

    const certificateDigest = computeCanonicalQuorumCertificateDigest(partialCert);

    return {
      ...partialCert,
      certificateDigestHex: certificateDigest.toString('hex'),
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
