import crypto from 'node:crypto';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface ApprovalEnvelopeParams {
  incidentId: Buffer; // 16 bytes UUID
  protectedScope: string; // UTF8
  targetVersionId: Buffer; // 16 bytes UUID
  proposedChangesHash: Buffer; // 32 bytes SHA256
  requesterId: string; // UTF8
  approverPubkey: Buffer; // 32 bytes raw Ed25519 SPKI/raw key
  nonce: Buffer; // 16 bytes UUID v4
  expiresAtUs: bigint; // 8 bytes I64 Unix microseconds
}

export interface SignedApprovalEnvelope extends ApprovalEnvelopeParams {
  signature: Buffer; // 64 bytes Ed25519 signature
}

/**
 * Encodes the canonical binary payload for Ed25519 approval signing with unambiguous length prefixing.
 */
export function encodeApprovalPayload(params: ApprovalEnvelopeParams): Buffer {
  const domain = Buffer.from('WDB:APPROVAL_ENVELOPE:v2:', 'utf8');

  if (params.incidentId.length !== 16) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
      `incidentId must be 16 bytes, got ${params.incidentId.length}`
    );
  }
  if (params.targetVersionId.length !== 16) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
      `targetVersionId must be 16 bytes, got ${params.targetVersionId.length}`
    );
  }
  if (params.proposedChangesHash.length !== 32) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
      `proposedChangesHash must be 32 bytes, got ${params.proposedChangesHash.length}`
    );
  }
  if (params.approverPubkey.length !== 32) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
      `approverPubkey must be 32 bytes, got ${params.approverPubkey.length}`
    );
  }
  if (params.nonce.length !== 16) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
      `nonce must be 16 bytes, got ${params.nonce.length}`
    );
  }

  const scopeBuf = Buffer.from(params.protectedScope, 'utf8');
  const scopeLenBuf = Buffer.alloc(4);
  scopeLenBuf.writeUInt32BE(scopeBuf.length, 0);

  const reqIdBuf = Buffer.from(params.requesterId, 'utf8');
  const reqIdLenBuf = Buffer.alloc(4);
  reqIdLenBuf.writeUInt32BE(reqIdBuf.length, 0);

  const expiresBuf = Buffer.alloc(8);
  expiresBuf.writeBigInt64BE(params.expiresAtUs, 0);

  return Buffer.concat([
    domain,
    params.incidentId,
    scopeLenBuf,
    scopeBuf,
    params.targetVersionId,
    params.proposedChangesHash,
    reqIdLenBuf,
    reqIdBuf,
    params.approverPubkey,
    params.nonce,
    expiresBuf,
  ]);
}

/**
 * Validates and verifies an Ed25519 signed approval envelope against policy rules.
 */
export function verifyApprovalEnvelope(
  envelope: SignedApprovalEnvelope,
  trustedApproverKeysHex: string[],
  currentTimestampUs: bigint
): void {
  // 1. Strict canonical separation of duties check (exact equality)
  const approverHex = envelope.approverPubkey.toString('hex').toLowerCase();
  const requesterNormalized = envelope.requesterId.toLowerCase();

  if (approverHex === requesterNormalized) {
    throw new WolverineError(
      WolverineErrorCode.REQUESTER_IS_APPROVER,
      `Separation of duties violation: approver ${approverHex} cannot be requester ${envelope.requesterId}`
    );
  }

  // 2. Trusted approver key check
  const isTrustedKey = trustedApproverKeysHex.some(
    (key) => key.toLowerCase() === approverHex
  );
  if (!isTrustedKey) {
    throw new WolverineError(
      WolverineErrorCode.UNTRUSTED_APPROVER_KEY,
      `Approver public key 0x${approverHex} is not in configured trusted approvers`
    );
  }

  // 3. Expiration check
  if (envelope.expiresAtUs <= currentTimestampUs) {
    throw new WolverineError(
      WolverineErrorCode.EXPIRED_APPROVAL_ENVELOPE,
      `Approval envelope expired at ${envelope.expiresAtUs} us (current time: ${currentTimestampUs} us)`
    );
  }

  // 4. Ed25519 signature verification
  const payload = encodeApprovalPayload(envelope);

  // Import raw Ed25519 32-byte public key into Node KeyObject
  const ed25519SpkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
  const spkiBuffer = Buffer.concat([ed25519SpkiHeader, envelope.approverPubkey]);

  try {
    const publicKeyObject = crypto.createPublicKey({
      key: spkiBuffer,
      format: 'der',
      type: 'spki',
    });

    const isValid = crypto.verify(
      null,
      payload,
      publicKeyObject,
      envelope.signature
    );

    if (!isValid) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
        'Ed25519 signature verification failed for approval envelope'
      );
    }
  } catch (err: any) {
    if (err instanceof WolverineError) {
      throw err;
    }
    throw new WolverineError(
      WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
      `Ed25519 signature validation error: ${err.message}`,
      { cause: err }
    );
  }
}
