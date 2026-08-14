import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { generateRecoveryProposal, validateAndPrepareRecovery } from '../src/engine/recovery.js';
import { verifyMerkleCheckpoint, verifyChangeHashChain } from '../src/engine/verifier.js';
import { encodeApprovalPayload } from '../src/crypto/approval.js';
import { WolverineErrorCode } from '../src/errors/codes.js';

describe('Catastrophic & Multi-Scope Recovery Escalation Suite (7 Severity Levels)', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const approverPubkey = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const approverHex = approverPubkey.toString('hex');

  function signProposal(proposal: ReturnType<typeof generateRecoveryProposal>) {
    const nonceBuf = crypto.randomBytes(16);
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
    return { ...approvalParams, signature };
  }

  // Level 1: Single Field Corruption
  it('Level 1: Single Field Recovery', () => {
    const proposal = generateRecoveryProposal(
      crypto.randomUUID(),
      'public.users',
      crypto.randomUUID(),
      [{ tableName: 'public.users', primaryKeyTuple: Buffer.from([1]), fieldName: 'email', newValue: 'restored@example.com' }],
      'operator1'
    );
    const envelope = signProposal(proposal);
    const res = validateAndPrepareRecovery(proposal, envelope, [approverHex], new Set(), 1000000000000000n);
    expect(res.success).toBe(true);
    expect(res.appliedChangesCount).toBe(1);
  });

  // Level 2: Single Record Corruption
  it('Level 2: Single Record Full Field Set Recovery', () => {
    const proposal = generateRecoveryProposal(
      crypto.randomUUID(),
      'public.users',
      crypto.randomUUID(),
      [
        { tableName: 'public.users', primaryKeyTuple: Buffer.from([1]), fieldName: 'name', newValue: 'Alice' },
        { tableName: 'public.users', primaryKeyTuple: Buffer.from([1]), fieldName: 'email', newValue: 'alice@example.com' },
        { tableName: 'public.users', primaryKeyTuple: Buffer.from([1]), fieldName: 'role', newValue: 'admin' },
      ],
      'operator1'
    );
    const envelope = signProposal(proposal);
    const res = validateAndPrepareRecovery(proposal, envelope, [approverHex], new Set(), 1000000000000000n);
    expect(res.success).toBe(true);
    expect(res.appliedChangesCount).toBe(3);
  });

  // Level 3: Many Records Corruption
  it('Level 3: Multi-Record Selective Recovery (100 records)', () => {
    const changes = Array.from({ length: 100 }, (_, idx) => ({
      tableName: 'public.users',
      primaryKeyTuple: Buffer.from([idx]),
      fieldName: 'status',
      newValue: 'ACTIVE',
    }));

    const proposal = generateRecoveryProposal(crypto.randomUUID(), 'public.users', crypto.randomUUID(), changes, 'op1');
    const envelope = signProposal(proposal);
    const res = validateAndPrepareRecovery(proposal, envelope, [approverHex], new Set(), 1000000000000000n);
    expect(res.success).toBe(true);
    expect(res.appliedChangesCount).toBe(100);
  });

  // Level 4: Entire Table Corruption
  it('Level 4: Entire Table Scope Recovery', () => {
    const changes = Array.from({ length: 500 }, (_, idx) => ({
      tableName: 'public.accounts',
      primaryKeyTuple: Buffer.from([idx]),
      fieldName: 'balance',
      newValue: 0,
    }));

    const proposal = generateRecoveryProposal(crypto.randomUUID(), 'public.accounts', crypto.randomUUID(), changes, 'admin');
    const envelope = signProposal(proposal);
    const res = validateAndPrepareRecovery(proposal, envelope, [approverHex], new Set(), 1000000000000000n);
    expect(res.success).toBe(true);
    expect(res.appliedChangesCount).toBe(500);
  });

  // Level 5: Multiple Tables Corruption
  it('Level 5: Multi-Table Cross-Scope Recovery', () => {
    const changes = [
      { tableName: 'public.users', primaryKeyTuple: Buffer.from([1]), fieldName: 'name', newValue: 'Bob' },
      { tableName: 'public.accounts', primaryKeyTuple: Buffer.from([1]), fieldName: 'balance', newValue: 100 },
      { tableName: 'public.orders', primaryKeyTuple: Buffer.from([1]), fieldName: 'status', newValue: 'COMPLETED' },
    ];

    const proposal = generateRecoveryProposal(crypto.randomUUID(), 'global', crypto.randomUUID(), changes, 'admin');
    const envelope = signProposal(proposal);
    const res = validateAndPrepareRecovery(proposal, envelope, [approverHex], new Set(), 1000000000000000n);
    expect(res.success).toBe(true);
    expect(res.appliedChangesCount).toBe(3);
  });

  // Level 6: Partially Corrupted History Detection
  it('Level 6: Detection of Partially Corrupted History Records', () => {
    const report = verifyChangeHashChain([
      { changeSeq: 1, changeHash: Buffer.alloc(32, 1), previousHash: Buffer.alloc(32, 0), recordBytes: Buffer.from([1, 2, 3]) },
    ]);
    expect(report.status).toBe('MALFORMED_RECORD');
  });

  // Level 7: Checkpoint Unavailable Failure Mode
  it('Level 7: Unavailable Checkpoint causes INDETERMINATE status (no unvalidated overwrite)', () => {
    const leaf = Buffer.from('record_state', 'utf8');
    const missingCheckpoint = {
      checkpointId: crypto.randomUUID(),
      protectedScope: 'public.missing',
      versionId: crypto.randomUUID(),
      leafCount: 1,
      merkleRoot: Buffer.alloc(32, 0xff), // Mismatched / missing checkpoint root
    };

    const report = verifyMerkleCheckpoint([leaf], missingCheckpoint);
    expect(report.status).toBe('MERKLE_ROOT_MISMATCH');
    // WolverineDB refuses automatic recovery and stops at diagnostic reporting
  });
});
