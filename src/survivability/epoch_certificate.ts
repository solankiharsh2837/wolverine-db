import crypto from 'node:crypto';
import { EpochTransitionCertificate } from './types.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export function computeEpochCertificateDigest(
  cert: Omit<EpochTransitionCertificate, 'certificateDigestHex'>
): Buffer {
  const domain = Buffer.from('WDB:EPOCH_CERT:v1:', 'utf8');
  const canonical = canonicalizeJson({
    certificateId: cert.certificateId,
    oldEpoch: cert.oldEpoch,
    newEpoch: cert.newEpoch,
    oldValidatorSetDigestHex: cert.oldValidatorSetDigestHex,
    newValidatorSetDigestHex: cert.newValidatorSetDigestHex,
    transitionLedgerSeq: cert.transitionLedgerSeq,
    transitionReason: cert.transitionReason,
    oldQuorumSignatures: cert.oldQuorumSignatures,
    newQuorumSignatures: cert.newQuorumSignatures,
  });

  return crypto
    .createHash('sha256')
    .update(Buffer.concat([domain, Buffer.from(canonical, 'utf8')]))
    .digest();
}

export class EpochTransitionCertificateManager {
  public static createCertificate(
    oldEpoch: number,
    newEpoch: number,
    oldValidatorSetDigest: Buffer,
    newValidatorSetDigest: Buffer,
    transitionLedgerSeq: bigint,
    transitionReason: string,
    oldSignatures: Array<{ validatorId: string; signature: Buffer }>,
    newSignatures: Array<{ validatorId: string; signature: Buffer }>
  ): EpochTransitionCertificate {
    const base = {
      certificateId: crypto.randomUUID(),
      oldEpoch,
      newEpoch,
      oldValidatorSetDigestHex: oldValidatorSetDigest.toString('hex'),
      newValidatorSetDigestHex: newValidatorSetDigest.toString('hex'),
      transitionLedgerSeq: transitionLedgerSeq.toString(),
      transitionReason,
      oldQuorumSignatures: oldSignatures.map((s) => ({
        validatorId: s.validatorId,
        signatureHex: s.signature.toString('hex'),
      })),
      newQuorumSignatures: newSignatures.map((s) => ({
        validatorId: s.validatorId,
        signatureHex: s.signature.toString('hex'),
      })),
    };

    const certDigest = computeEpochCertificateDigest(base);

    return {
      ...base,
      certificateDigestHex: certDigest.toString('hex'),
    };
  }

  public static verifyCertificate(
    cert: EpochTransitionCertificate,
    requiredQuorum: number = 4
  ): boolean {
    // 1. Verify Digest
    const expectedDigest = computeEpochCertificateDigest(cert);
    if (!timingSafeEqualHashes(Buffer.from(cert.certificateDigestHex, 'hex'), expectedDigest)) {
      throw new WolverineError(
        WolverineErrorCode.HISTORY_MUTATION_DETECTED,
        'Invalid epoch certificate digest'
      );
    }

    // 2. Verify Quorum Thresholds
    if (cert.oldQuorumSignatures.length < requiredQuorum) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
        `Old quorum signatures insufficient: ${cert.oldQuorumSignatures.length} < ${requiredQuorum}`
      );
    }

    if (cert.newQuorumSignatures.length < requiredQuorum) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
        `New quorum signatures insufficient: ${cert.newQuorumSignatures.length} < ${requiredQuorum}`
      );
    }

    return true;
  }
}
