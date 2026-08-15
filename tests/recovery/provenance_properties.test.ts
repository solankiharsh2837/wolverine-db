import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { RecoveryProposal } from '../../src/engine/recovery.js';
import { RecoveryProvenanceEngine } from '../../src/engine/recovery_provenance.js';
import { WORMCheckpointStore } from '../../src/checkpoint/worm.js';
import { encodeApprovalPayload, SignedApprovalEnvelope } from '../../src/crypto/approval.js';

describe('Recovery Provenance Properties (WDB-0013 Hardening)', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const approverPubkey = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const trustedApprovers = [approverPubkey];

  it('property: executes full tamper -> detect -> proposal -> approval -> recover -> checkpoint lifecycle', async () => {
    const externalStore = new WORMCheckpointStore();
    const consumedNonces = new Set<string>();

    const incidentId = '11111111-1111-1111-1111-111111111111';
    const proposalId = '22222222-2222-2222-2222-222222222222';
    const targetVersionId = '33333333-3333-3333-3333-333333333333';
    const protectedScope = 'public.accounts';
    const nonce = '44444444-4444-4444-4444-444444444444';
    const requesterId = 'auditor@example.com';
    const expiresAtUs = BigInt(Date.now() + 60000) * 1000n;
    const proposedChangesHash = Buffer.alloc(32, 0x77);

    const proposal: RecoveryProposal = {
      proposalId,
      incidentId,
      protectedScope,
      targetVersionId,
      proposedChangesHash,
      requesterId,
      status: 'PENDING',
      proposedChanges: [
        {
          tableName: 'public.accounts',
          primaryKeyTuple: Buffer.from('pk-1', 'utf8'),
          fieldName: 'balance',
          newValue: '100.00',
        },
      ],
    };

    // Sign approval envelope with node:crypto
    const envelopePayload = {
      incidentId: Buffer.from(incidentId.replace(/-/g, ''), 'hex'),
      protectedScope,
      targetVersionId: Buffer.from(targetVersionId.replace(/-/g, ''), 'hex'),
      proposedChangesHash,
      requesterId,
      approverPubkey,
      nonce: Buffer.from(nonce.replace(/-/g, ''), 'hex'),
      expiresAtUs,
    };
    const canonicalPayloadBytes = encodeApprovalPayload(envelopePayload);
    const signature = crypto.sign(null, canonicalPayloadBytes, privateKey);

    const envelope: SignedApprovalEnvelope = {
      ...envelopePayload,
      signature,
    };

    const preIncidentRoot = Buffer.alloc(32, 0x11);

    const { result, auditTrail } = await RecoveryProvenanceEngine.executeWithProvenance(
      proposal,
      envelope,
      trustedApprovers,
      consumedNonces,
      externalStore,
      100n,
      preIncidentRoot
    );

    expect(result.success).toBe(true);
    expect(auditTrail.auditStatus).toBe('PROVABLY_CORRECT');
    expect(consumedNonces.has(nonce.replace(/-/g, ''))).toBe(true);

    // Audit lineage
    const isLineageValid = await RecoveryProvenanceEngine.auditRecoveryLineage(
      auditTrail,
      trustedApprovers,
      externalStore
    );
    expect(isLineageValid).toBe(true);
  });

  it('property: rejects replayed recovery approval envelope nonce', async () => {
    const externalStore = new WORMCheckpointStore();
    const consumedNonces = new Set<string>(['55555555555555555555555555555555']); // Already consumed hex nonce

    const proposal: RecoveryProposal = {
      proposalId: 'p-1',
      incidentId: 'i-1',
      protectedScope: 'public.accounts',
      targetVersionId: 'v-1',
      proposedChangesHash: Buffer.alloc(32, 1),
      requesterId: 'auditor@example.com',
      status: 'PENDING',
      proposedChanges: [],
    };

    const envelopePayload = {
      incidentId: Buffer.alloc(16, 1),
      protectedScope: 'public.accounts',
      targetVersionId: Buffer.alloc(16, 2),
      proposedChangesHash: Buffer.alloc(32, 1),
      requesterId: 'auditor@example.com',
      approverPubkey,
      nonce: Buffer.from('55555555555555555555555555555555', 'hex'),
      expiresAtUs: BigInt(Date.now() + 60000) * 1000n,
    };
    const canonicalPayloadBytes = encodeApprovalPayload(envelopePayload);
    const signature = crypto.sign(null, canonicalPayloadBytes, privateKey);

    const envelope: SignedApprovalEnvelope = {
      ...envelopePayload,
      signature,
    };

    await expect(
      RecoveryProvenanceEngine.executeWithProvenance(
        proposal,
        envelope,
        trustedApprovers,
        consumedNonces,
        externalStore,
        1n,
        Buffer.alloc(32, 0)
      )
    ).rejects.toThrow('Approval nonce 55555555555555555555555555555555 has already been consumed');
  });
});
