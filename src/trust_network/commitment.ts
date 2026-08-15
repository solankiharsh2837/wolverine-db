import crypto from 'node:crypto';
import { TrustCommitment } from './types.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export function computeTrustCommitmentDigest(
  commitment: Omit<TrustCommitment, 'commitmentDigest' | 'customerSignature'>
): Buffer {
  const domain = Buffer.from('WDB:TRUST:v1:', 'utf8');

  const canonicalPayload = canonicalizeJson({
    commitmentId: commitment.commitmentId,
    tenantId: commitment.tenantId,
    databaseId: commitment.databaseId,
    checkpointId: commitment.checkpointId,
    commitSeq: commitment.commitSeq.toString(),
    checkpointDigestHex: commitment.checkpointDigest.toString('hex'),
    previousTrustCommitmentHex: commitment.previousTrustCommitment.toString('hex'),
    protocolVersion: commitment.protocolVersion,
    logicalTimestamp: commitment.logicalTimestamp.toString(),
    epoch: commitment.epoch,
    validatorSetId: commitment.validatorSetId,
  });

  return crypto
    .createHash('sha256')
    .update(Buffer.concat([domain, Buffer.from(canonicalPayload, 'utf8')]))
    .digest();
}

export function createSignedCustomerCommitment(
  params: {
    commitmentId: string;
    tenantId: string;
    databaseId: string;
    checkpointId: string;
    commitSeq: bigint;
    checkpointDigest: Buffer;
    previousTrustCommitment: Buffer;
    protocolVersion?: number;
    logicalTimestamp?: bigint;
    epoch?: number;
    validatorSetId?: string;
  },
  customerPrivateKey: crypto.KeyObject,
  customerPubkey: Buffer
): TrustCommitment {
  const commitmentBase = {
    commitmentId: params.commitmentId,
    tenantId: params.tenantId,
    databaseId: params.databaseId,
    checkpointId: params.checkpointId,
    commitSeq: params.commitSeq,
    checkpointDigest: params.checkpointDigest,
    previousTrustCommitment: params.previousTrustCommitment,
    protocolVersion: params.protocolVersion ?? 1,
    logicalTimestamp: params.logicalTimestamp ?? (BigInt(Date.now()) * 1000n),
    epoch: params.epoch ?? 1,
    validatorSetId: params.validatorSetId ?? 'valset-genesis',
    customerPubkey,
  };

  const commitmentDigest = computeTrustCommitmentDigest(commitmentBase);
  const customerSignature = crypto.sign(null, commitmentDigest, customerPrivateKey);

  return {
    ...commitmentBase,
    customerSignature,
    commitmentDigest,
  };
}

export function verifyCustomerCommitment(
  commitment: TrustCommitment,
  expectedCustomerPubkey?: Buffer
): boolean {
  if (expectedCustomerPubkey && !timingSafeEqualHashes(commitment.customerPubkey, expectedCustomerPubkey)) {
    return false;
  }

  const recomputedDigest = computeTrustCommitmentDigest(commitment);
  if (!timingSafeEqualHashes(commitment.commitmentDigest, recomputedDigest)) {
    return false;
  }

  try {
    const pubKeyObject = crypto.createPublicKey({
      key: Buffer.concat([
        // Ed25519 SPKI Prefix
        Buffer.from('302a300506032b6570032100', 'hex'),
        commitment.customerPubkey,
      ]),
      format: 'der',
      type: 'spki',
    });

    return crypto.verify(null, commitment.commitmentDigest, pubKeyObject, commitment.customerSignature);
  } catch {
    return false;
  }
}
