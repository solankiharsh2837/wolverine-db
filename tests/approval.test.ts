import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  encodeApprovalPayload,
  verifyApprovalEnvelope,
  SignedApprovalEnvelope,
} from '../src/crypto/approval.js';
import { WolverineErrorCode } from '../src/errors/codes.js';

describe('Ed25519 Policy Approval Verification (WDB-0006)', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const approverPubkey = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const approverHex = approverPubkey.toString('hex');

  const baseParams = {
    incidentId: Buffer.alloc(16, 1),
    protectedScope: 'public.users',
    targetVersionId: Buffer.alloc(16, 2),
    proposedChangesHash: Buffer.alloc(32, 3),
    requesterId: 'operator1@example.com',
    approverPubkey,
    nonce: Buffer.alloc(16, 4),
    expiresAtUs: 2000000000000000n, // Future timestamp
  };

  function createSignedEnvelope(): SignedApprovalEnvelope {
    const payload = encodeApprovalPayload(baseParams);
    const signature = crypto.sign(null, payload, privateKey);
    return {
      ...baseParams,
      signature,
    };
  }

  it('verifies valid signed approval envelope', () => {
    const envelope = createSignedEnvelope();
    const currentTimestampUs = 1000000000000000n;
    const trustedApprovers = [approverHex];

    expect(() =>
      verifyApprovalEnvelope(envelope, trustedApprovers, currentTimestampUs)
    ).not.toThrow();
  });

  it('rejects approval when requester is approver (separation of duties)', () => {
    const envelope = createSignedEnvelope();
    envelope.requesterId = approverHex; // Violation

    expect(() =>
      verifyApprovalEnvelope(envelope, [approverHex], 1000000000000000n)
    ).toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.REQUESTER_IS_APPROVER })
    );
  });

  it('rejects untrusted approver public key', () => {
    const envelope = createSignedEnvelope();
    const untrustedApprovers = ['00'.repeat(32)];

    expect(() =>
      verifyApprovalEnvelope(envelope, untrustedApprovers, 1000000000000000n)
    ).toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.UNTRUSTED_APPROVER_KEY })
    );
  });

  it('rejects expired approval envelope', () => {
    const envelope = createSignedEnvelope();
    const futureTime = 3000000000000000n; // Past expiry

    expect(() =>
      verifyApprovalEnvelope(envelope, [approverHex], futureTime)
    ).toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.EXPIRED_APPROVAL_ENVELOPE })
    );
  });

  it('rejects invalid signature', () => {
    const envelope = createSignedEnvelope();
    envelope.signature = Buffer.alloc(64, 0x00); // Invalid signature

    expect(() =>
      verifyApprovalEnvelope(envelope, [approverHex], 1000000000000000n)
    ).toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.INVALID_APPROVAL_SIGNATURE })
    );
  });
});
