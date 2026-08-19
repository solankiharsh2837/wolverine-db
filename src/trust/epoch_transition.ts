import crypto from 'node:crypto';
import { canonicalizeJson } from '../binary/c14n.js';
import { CanonicalQuorumCertificate } from './quorum_certificate.js';
import { IndependentQuorumVerifier } from './quorum_verifier.js';
import { ValidatorSetManager, CanonicalValidatorSet } from './validator_set.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export interface CrossEpochTransitionCertificate {
  certificateVersion: number; // 2
  oldEpoch: number;
  newEpoch: number;
  oldValidatorSetId: string;
  newValidatorSetId: string;
  lastFinalizedSeq_old: bigint;
  lastFinalizedDigest_oldHex: string;
  newGenesisSeq: bigint;
  transitionReason: string;
  transitionTimestampUs: bigint;
  oldEpochFinalQC: CanonicalQuorumCertificate;
  customerAuthorization: {
    keyId: string;
    customerPubkeyHex: string;
    signatureHex: string;
  };
  transitionCertificateDigestHex: string;
}

export function computeEpochTransitionDigest(
  cert: Omit<CrossEpochTransitionCertificate, 'transitionCertificateDigestHex'>
): Buffer {
  const rawPayload = {
    certificateVersion: cert.certificateVersion,
    oldEpoch: cert.oldEpoch,
    newEpoch: cert.newEpoch,
    oldValidatorSetId: cert.oldValidatorSetId,
    newValidatorSetId: cert.newValidatorSetId,
    lastFinalizedSeq_old: cert.lastFinalizedSeq_old.toString(),
    lastFinalizedDigest_oldHex: cert.lastFinalizedDigest_oldHex,
    newGenesisSeq: cert.newGenesisSeq.toString(),
    transitionReason: cert.transitionReason,
    transitionTimestampUs: cert.transitionTimestampUs.toString(),
    oldEpochFinalQCDigestHex: cert.oldEpochFinalQC.certificateDigestHex,
    customerKeyId: cert.customerAuthorization.keyId,
    customerPubkeyHex: cert.customerAuthorization.customerPubkeyHex,
  };

  const canonicalJson = canonicalizeJson(rawPayload);
  return crypto
    .createHash('sha256')
    .update(Buffer.from(`WDB:EPOCH_TRANSITION:v2:${canonicalJson}`, 'utf8'))
    .digest();
}

/**
 * Derives the deterministic genesis digest for epoch e+1 from the Transition Certificate.
 */
export function deriveNewEpochGenesisDigest(
  transitionCert: CrossEpochTransitionCertificate
): Buffer {
  const transDigest = Buffer.from(transitionCert.transitionCertificateDigestHex, 'hex');
  const epochBuf = Buffer.alloc(4);
  epochBuf.writeUInt32BE(transitionCert.newEpoch, 0);

  const lastDigestBuf = Buffer.from(transitionCert.lastFinalizedDigest_oldHex, 'hex');

  const preimage = Buffer.concat([
    Buffer.from('WDB:EPOCH_GENESIS:v2:', 'utf8'),
    transDigest,
    epochBuf,
    lastDigestBuf,
  ]);

  return crypto.createHash('sha256').update(preimage).digest();
}

/**
 * Cryptographically verifies a Cross-Epoch Transition Certificate.
 */
export function verifyEpochTransitionCertificate(
  cert: CrossEpochTransitionCertificate,
  oldValidatorSetManager: ValidatorSetManager,
  newValidatorSet: CanonicalValidatorSet,
  expectedCustomerPubkey?: Buffer
): { valid: boolean; newGenesisDigest: Buffer } {
  // 1. Invariant: newEpoch must be exactly oldEpoch + 1
  if (cert.newEpoch !== cert.oldEpoch + 1) {
    throw new WolverineError(
      WolverineErrorCode.SCHEMA_MIGRATION_ERROR,
      `Invalid epoch sequence: newEpoch ${cert.newEpoch} must equal oldEpoch ${cert.oldEpoch} + 1`
    );
  }

  // 2. Invariant: Epoch alignment with validator sets
  if (cert.oldEpoch !== oldValidatorSetManager.epoch) {
    throw new WolverineError(
      WolverineErrorCode.UNAUTHORIZED_MUTATION,
      `Old validator set epoch mismatch: certificate expects ${cert.oldEpoch}, set has ${oldValidatorSetManager.epoch}`
    );
  }

  if (cert.newEpoch !== newValidatorSet.epoch) {
    throw new WolverineError(
      WolverineErrorCode.UNAUTHORIZED_MUTATION,
      `New validator set epoch mismatch: certificate expects ${cert.newEpoch}, set has ${newValidatorSet.epoch}`
    );
  }

  // 3. Verify Certificate Envelope Digest
  const computedDigest = computeEpochTransitionDigest(cert);
  const storedDigest = Buffer.from(cert.transitionCertificateDigestHex, 'hex');

  if (!timingSafeEqualHashes(computedDigest, storedDigest)) {
    throw new WolverineError(
      WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
      'Epoch transition certificate envelope integrity check failed'
    );
  }

  // 4. Verify Final QC from Old Epoch using Old Validator Set
  if (cert.oldEpochFinalQC.epoch !== cert.oldEpoch) {
    throw new WolverineError(
      WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
      `Old epoch final QC epoch ${cert.oldEpochFinalQC.epoch} does not match oldEpoch ${cert.oldEpoch}`
    );
  }

  if (cert.oldEpochFinalQC.commitSeq !== cert.lastFinalizedSeq_old) {
    throw new WolverineError(
      WolverineErrorCode.SEQUENCE_GAP_DETECTED,
      `Old epoch final QC sequence ${cert.oldEpochFinalQC.commitSeq} does not match lastFinalizedSeq_old ${cert.lastFinalizedSeq_old}`
    );
  }

  if (cert.oldEpochFinalQC.commitmentDigestHex !== cert.lastFinalizedDigest_oldHex) {
    throw new WolverineError(
      WolverineErrorCode.CHANGE_HASH_MISMATCH,
      `Old epoch final QC digest ${cert.oldEpochFinalQC.commitmentDigestHex} does not match lastFinalizedDigest_old ${cert.lastFinalizedDigest_oldHex}`
    );
  }

  IndependentQuorumVerifier.verify(cert.oldEpochFinalQC, oldValidatorSetManager);

  // 5. Verify Customer Authority Authorization Signature
  const custPubkeyBuf = Buffer.from(cert.customerAuthorization.customerPubkeyHex, 'hex');
  if (expectedCustomerPubkey && !custPubkeyBuf.equals(expectedCustomerPubkey)) {
    throw new WolverineError(
      WolverineErrorCode.UNAUTHORIZED_MUTATION,
      `Customer public key mismatch for epoch transition authorization`
    );
  }

  const custKeyObj = crypto.createPublicKey({
    key: custPubkeyBuf,
    format: 'der',
    type: 'spki',
  });

  const authPreimage = Buffer.concat([
    Buffer.from('WDB:CUST_EPOCH_AUTH:v1:', 'utf8'),
    computedDigest,
    Buffer.from(cert.newValidatorSetId, 'utf8'),
  ]);
  const authDigest = crypto.createHash('sha256').update(authPreimage).digest();

  const sigBuf = Buffer.from(cert.customerAuthorization.signatureHex, 'hex');
  const isCustSigValid = crypto.verify(null, authDigest, custKeyObj, sigBuf);

  if (!isCustSigValid) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
      'Customer root authorization signature for epoch transition failed verification'
    );
  }

  const newGenesisDigest = deriveNewEpochGenesisDigest(cert);

  return {
    valid: true,
    newGenesisDigest,
  };
}
