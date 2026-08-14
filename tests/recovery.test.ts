import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  generateRecoveryProposal,
  validateAndPrepareRecovery,
} from '../src/engine/recovery.js';
import { encodeApprovalPayload } from '../src/crypto/approval.js';
import { WolverineErrorCode } from '../src/errors/codes.js';

describe('Recovery Engine (WDB-0006 & docs/10-RECOVERY-ENGINE)', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const approverPubkey = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const approverHex = approverPubkey.toString('hex');

  it('generates non-destructive recovery proposal and executes with valid approval', () => {
    const proposal = generateRecoveryProposal(
      crypto.randomUUID(),
      'public.users',
      crypto.randomUUID(),
      [
        {
          tableName: 'public.users',
          primaryKeyTuple: Buffer.from([1, 2, 3]),
          fieldName: 'email',
          newValue: 'alice@example.com',
        },
      ],
      'operator1@example.com'
    );

    expect(proposal.status).toBe('PENDING');

    const nonce = crypto.randomUUID();
    const nonceBuf = Buffer.from(nonce.replace(/-/g, ''), 'hex');
    const incidentBuf = Buffer.from(proposal.incidentId.replace(/-/g, ''), 'hex');
    const targetVerBuf = Buffer.from(proposal.targetVersionId.replace(/-/g, ''), 'hex');

    const approvalParams = {
      incidentId: incidentBuf,
      protectedScope: proposal.protectedScope,
      targetVersionId: targetVerBuf,
      proposedChangesHash: proposal.proposedChangesHash,
      requesterId: proposal.requesterId,
      approverPubkey,
      nonce: nonceBuf,
      expiresAtUs: 3000000000000000n,
    };

    const payload = encodeApprovalPayload(approvalParams);
    const signature = crypto.sign(null, payload, privateKey);

    const signedEnvelope = {
      ...approvalParams,
      signature,
    };

    const consumedNonces = new Set<string>();

    const result = validateAndPrepareRecovery(
      proposal,
      signedEnvelope,
      [approverHex],
      consumedNonces,
      1000000000000000n
    );

    expect(result.success).toBe(true);
    expect(result.appliedChangesCount).toBe(1);
    expect(proposal.status).toBe('EXECUTED');
    expect(consumedNonces.has(nonceBuf.toString('hex'))).toBe(true);
  });

  it('rejects replayed approval nonces', () => {
    const proposal = generateRecoveryProposal(
      crypto.randomUUID(),
      'public.users',
      crypto.randomUUID(),
      [
        {
          tableName: 'public.users',
          primaryKeyTuple: Buffer.from([1]),
          fieldName: 'name',
          newValue: 'Bob',
        },
      ],
      'op@example.com'
    );

    const nonceBuf = Buffer.alloc(16, 0x99);
    const approvalParams = {
      incidentId: Buffer.from(proposal.incidentId.replace(/-/g, ''), 'hex'),
      protectedScope: proposal.protectedScope,
      targetVersionId: Buffer.from(proposal.targetVersionId.replace(/-/g, ''), 'hex'),
      proposedChangesHash: proposal.proposedChangesHash,
      requesterId: proposal.requesterId,
      approverPubkey,
      nonce: nonceBuf,
      expiresAtUs: 3000000000000000n,
    };

    const payload = encodeApprovalPayload(approvalParams);
    const signature = crypto.sign(null, payload, privateKey);
    const signedEnvelope = { ...approvalParams, signature };

    const consumedNonces = new Set<string>([nonceBuf.toString('hex')]); // Nonce already consumed

    expect(() =>
      validateAndPrepareRecovery(
        proposal,
        signedEnvelope,
        [approverHex],
        consumedNonces,
        1000000000000000n
      )
    ).toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.REPLAYED_APPROVAL_NONCE })
    );
  });
});
