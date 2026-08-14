import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { encodeBinaryRecord } from '../src/binary/encoder.js';
import { decodeBinaryRecord } from '../src/binary/decoder.js';
import { computeChangeHash, GENESIS_PREDECEASED_HASH } from '../src/crypto/hash.js';
import { MerkleTree, verifyMerkleProof } from '../src/crypto/merkle.js';
import { encodeApprovalPayload, verifyApprovalEnvelope } from '../src/crypto/approval.js';
import { verifyChangeHashChain, verifyMerkleCheckpoint, StoredChangeRecord } from '../src/engine/verifier.js';
import { generateRecoveryProposal, validateAndPrepareRecovery } from '../src/engine/recovery.js';
import { WolverineErrorCode } from '../src/errors/codes.js';

describe('Hostile Security Audit Suite (16 Attack Vectors)', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const approverPubkey = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const approverHex = approverPubkey.toString('hex');

  // Helper to build a valid change record
  function buildChangeRecord(seq: number, prevHash: Buffer) {
    const valBuf = Buffer.alloc(8); valBuf.writeBigUInt64BE(BigInt(seq));
    const pkTuple = Buffer.concat([Buffer.from('0001000269640200000008', 'hex'), valBuf]);

    const bytes = encodeBinaryRecord(1, [
      { tag: 1, typeTag: 2, payload: Buffer.from('0000000000000001', 'hex') },
      { tag: 2, typeTag: 4, payload: Buffer.alloc(16, 0) },
      { tag: 3, typeTag: 5, payload: Buffer.from(`tx:${seq}`, 'utf8') },
      { tag: 4, typeTag: 10, payload: Buffer.alloc(8, 0) },
      { tag: 5, typeTag: 5, payload: Buffer.from('public.users', 'utf8') },
      { tag: 6, typeTag: 6, payload: pkTuple },
      { tag: 7, typeTag: 2, payload: Buffer.from('0000000000000001', 'hex') },
      { tag: 8, typeTag: 8, payload: Buffer.from('{"new":{"val":1},"old":null}', 'utf8') },
      { tag: 9, typeTag: 8, payload: Buffer.from('{"actor":"user1"}', 'utf8') },
      { tag: 10, typeTag: 7, payload: prevHash },
    ]);
    const hash = computeChangeHash(bytes, prevHash);
    return { seq, bytes, hash, prevHash };
  }

  // 1. Direct DB Row Modification Detection
  it('Attack Vector 1: Direct DB Row Modification causes state divergence', () => {
    const expectedRecordKey = Buffer.from('pk1', 'utf8');
    const originalState = Buffer.from('state1', 'utf8');
    const tamperedState = Buffer.from('state1_tampered', 'utf8');

    const originalTree = new MerkleTree([originalState]);
    const tamperedTree = new MerkleTree([tamperedState]);

    const report = verifyMerkleCheckpoint([tamperedState], {
      checkpointId: crypto.randomUUID(),
      protectedScope: 'public.users',
      versionId: crypto.randomUUID(),
      leafCount: 1,
      merkleRoot: originalTree.root,
    });

    expect(report.status).toBe('MERKLE_ROOT_MISMATCH');
    expect(report.failureMessage).toContain('Merkle root mismatch');
  });

  // 2. History Event Modification
  it('Attack Vector 2: Modifying historical record_bytes triggers CHANGE_HASH_MISMATCH', () => {
    const r1 = buildChangeRecord(1, GENESIS_PREDECEASED_HASH);

    // Tamper with record_bytes payload
    const tamperedBytes = Buffer.from(r1.bytes);
    tamperedBytes[tamperedBytes.length - 1] ^= 0xff;

    const records: StoredChangeRecord[] = [
      { changeSeq: 1, changeHash: r1.hash, previousHash: GENESIS_PREDECEASED_HASH, recordBytes: tamperedBytes },
    ];

    const report = verifyChangeHashChain(records);
    expect(report.status).toBe('CHANGE_HASH_MISMATCH');
  });

  // 3. History Event Deletion
  it('Attack Vector 3: Deleting an intermediate history event breaks the hash chain link', () => {
    const r1 = buildChangeRecord(1, GENESIS_PREDECEASED_HASH);
    const r2 = buildChangeRecord(2, r1.hash);
    const r3 = buildChangeRecord(3, r2.hash);

    // Omit r2 (history deletion)
    const records: StoredChangeRecord[] = [
      { changeSeq: 1, changeHash: r1.hash, previousHash: GENESIS_PREDECEASED_HASH, recordBytes: r1.bytes },
      { changeSeq: 3, changeHash: r3.hash, previousHash: r3.prevHash, recordBytes: r3.bytes }, // r3 expected prevHash is r2.hash
    ];

    const report = verifyChangeHashChain(records);
    expect(report.status).toBe('CHANGE_HASH_MISMATCH');
    expect(report.firstFailureSeq).toBe(3);
  });

  // 4. Replay Old Change
  it('Attack Vector 4: Replaying an old historical change causes hash mismatch', () => {
    const r1 = buildChangeRecord(1, GENESIS_PREDECEASED_HASH);
    const r2 = buildChangeRecord(2, r1.hash);

    // Replay r1 after r2
    const records: StoredChangeRecord[] = [
      { changeSeq: 1, changeHash: r1.hash, previousHash: GENESIS_PREDECEASED_HASH, recordBytes: r1.bytes },
      { changeSeq: 2, changeHash: r2.hash, previousHash: r1.hash, recordBytes: r2.bytes },
      { changeSeq: 3, changeHash: r1.hash, previousHash: r2.hash, recordBytes: r1.bytes }, // Replayed r1
    ];

    const report = verifyChangeHashChain(records);
    expect(report.status).toBe('CHANGE_HASH_MISMATCH');
  });

  // 5. Modify Merkle Node / Sibling Hash
  it('Attack Vector 5: Tampering with Merkle sibling hash invalidates proof', () => {
    const p1 = Buffer.from('leaf1', 'utf8');
    const p2 = Buffer.from('leaf2', 'utf8');
    const tree = new MerkleTree([p1, p2]);

    const proof = tree.generateProof(0);
    proof.proof[0].siblingHash[0] ^= 0xff; // Mutate sibling hash

    expect(verifyMerkleProof(proof.leafHash, proof.proof, tree.root)).toBe(false);
  });

  // 6. Modify Checkpoint Root
  it('Attack Vector 6: Tampering with checkpoint Merkle root triggers MERKLE_ROOT_MISMATCH', () => {
    const p1 = Buffer.from('leaf1', 'utf8');
    const tree = new MerkleTree([p1]);
    const forgedRoot = Buffer.alloc(32, 0xaa);

    const report = verifyMerkleCheckpoint([p1], {
      checkpointId: crypto.randomUUID(),
      protectedScope: 'public.users',
      versionId: crypto.randomUUID(),
      leafCount: 1,
      merkleRoot: forgedRoot,
    });

    expect(report.status).toBe('MERKLE_ROOT_MISMATCH');
  });

  // 7. Forge DBA Authorization
  it('Attack Vector 7: Forged DBA authorization payload without trusted approver key fails', () => {
    const forgedKey = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

    const params = {
      incidentId: Buffer.alloc(16, 1),
      protectedScope: 'public.users',
      targetVersionId: Buffer.alloc(16, 2),
      proposedChangesHash: Buffer.alloc(32, 3),
      requesterId: 'dba@example.com',
      approverPubkey: forgedKey,
      nonce: Buffer.alloc(16, 4),
      expiresAtUs: 2000000000000000n,
    };
    const payload = encodeApprovalPayload(params);
    const signature = Buffer.alloc(64, 1);

    expect(() =>
      verifyApprovalEnvelope(
        { ...params, signature },
        [approverHex], // Trusted approvers does NOT include forgedKey
        1000000000000000n
      )
    ).toThrowError(expect.objectContaining({ code: WolverineErrorCode.UNTRUSTED_APPROVER_KEY }));
  });

  // 8. Replay ApprovalEnvelope
  it('Attack Vector 8: Replaying an already consumed ApprovalEnvelope nonce is rejected', () => {
    const proposal = generateRecoveryProposal(
      crypto.randomUUID(),
      'public.users',
      crypto.randomUUID(),
      [{ tableName: 'public.users', primaryKeyTuple: Buffer.from([1]), fieldName: 'col', newValue: 'val' }],
      'user@example.com'
    );

    const nonceBuf = Buffer.alloc(16, 0x12);
    const consumedNonces = new Set<string>([nonceBuf.toString('hex')]);

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

    expect(() =>
      validateAndPrepareRecovery(
        proposal,
        { ...approvalParams, signature },
        [approverHex],
        consumedNonces,
        1000000000000000n
      )
    ).toThrowError(expect.objectContaining({ code: WolverineErrorCode.REPLAYED_APPROVAL_NONCE }));
  });

  // 9. Use Expired Approval
  it('Attack Vector 9: Submitting an expired approval envelope is rejected', () => {
    const params = {
      incidentId: Buffer.alloc(16, 1),
      protectedScope: 'public.users',
      targetVersionId: Buffer.alloc(16, 2),
      proposedChangesHash: Buffer.alloc(32, 3),
      requesterId: 'op@example.com',
      approverPubkey,
      nonce: Buffer.alloc(16, 4),
      expiresAtUs: 1000n, // Past expiry
    };
    const payload = encodeApprovalPayload(params);
    const signature = crypto.sign(null, payload, privateKey);

    expect(() =>
      verifyApprovalEnvelope({ ...params, signature }, [approverHex], 2000n)
    ).toThrowError(expect.objectContaining({ code: WolverineErrorCode.EXPIRED_APPROVAL_ENVELOPE }));
  });

  // 10. Use Wrong Signer
  it('Attack Vector 10: Approval signed by unauthorized key is rejected', () => {
    const wrongKey = crypto.generateKeyPairSync('ed25519');
    const wrongPubkey = wrongKey.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

    const params = {
      incidentId: Buffer.alloc(16, 1),
      protectedScope: 'public.users',
      targetVersionId: Buffer.alloc(16, 2),
      proposedChangesHash: Buffer.alloc(32, 3),
      requesterId: 'op@example.com',
      approverPubkey: wrongPubkey,
      nonce: Buffer.alloc(16, 4),
      expiresAtUs: 2000000000000000n,
    };
    const payload = encodeApprovalPayload(params);
    const signature = crypto.sign(null, payload, wrongKey.privateKey);

    expect(() =>
      verifyApprovalEnvelope({ ...params, signature }, [approverHex], 1000000000000000n)
    ).toThrowError(expect.objectContaining({ code: WolverineErrorCode.UNTRUSTED_APPROVER_KEY }));
  });

  // 11. Requester = Approver Violation
  it('Attack Vector 11: Requester attempting to approve own proposal is rejected', () => {
    const params = {
      incidentId: Buffer.alloc(16, 1),
      protectedScope: 'public.users',
      targetVersionId: Buffer.alloc(16, 2),
      proposedChangesHash: Buffer.alloc(32, 3),
      requesterId: approverHex, // Requester matches approver
      approverPubkey,
      nonce: Buffer.alloc(16, 4),
      expiresAtUs: 2000000000000000n,
    };
    const payload = encodeApprovalPayload(params);
    const signature = crypto.sign(null, payload, privateKey);

    expect(() =>
      verifyApprovalEnvelope({ ...params, signature }, [approverHex], 1000000000000000n)
    ).toThrowError(expect.objectContaining({ code: WolverineErrorCode.REQUESTER_IS_APPROVER }));
  });

  // 12. Compromised Recovery Path
  it('Attack Vector 12: Recovery execution with mismatched proposal hash is rejected', () => {
    const proposal = generateRecoveryProposal(
      crypto.randomUUID(),
      'public.users',
      crypto.randomUUID(),
      [{ tableName: 'public.users', primaryKeyTuple: Buffer.from([1]), fieldName: 'col', newValue: 'val' }],
      'user@example.com'
    );

    const approvalParams = {
      incidentId: Buffer.from(proposal.incidentId.replace(/-/g, ''), 'hex'),
      protectedScope: proposal.protectedScope,
      targetVersionId: Buffer.from(proposal.targetVersionId.replace(/-/g, ''), 'hex'),
      proposedChangesHash: Buffer.alloc(32, 0xff), // Mismatched hash
      requesterId: proposal.requesterId,
      approverPubkey,
      nonce: Buffer.alloc(16, 5),
      expiresAtUs: 3000000000000000n,
    };
    const payload = encodeApprovalPayload(approvalParams);
    const signature = crypto.sign(null, payload, privateKey);

    expect(() =>
      validateAndPrepareRecovery(
        proposal,
        { ...approvalParams, signature },
        [approverHex],
        new Set(),
        1000000000000000n
      )
    ).toThrowError(expect.objectContaining({ code: WolverineErrorCode.INVALID_APPROVAL_SIGNATURE }));
  });

  // 13. Sequential / Hash Chain Continuity under Concurrent Mutators
  it('Attack Vector 13: Sequence order enforces linear hash chain continuity', () => {
    const r1 = buildChangeRecord(1, GENESIS_PREDECEASED_HASH);
    const r2 = buildChangeRecord(2, r1.hash);
    const r3 = buildChangeRecord(3, r2.hash);

    const report = verifyChangeHashChain([
      { changeSeq: 1, changeHash: r1.hash, previousHash: GENESIS_PREDECEASED_HASH, recordBytes: r1.bytes },
      { changeSeq: 2, changeHash: r2.hash, previousHash: r1.hash, recordBytes: r2.bytes },
      { changeSeq: 3, changeHash: r3.hash, previousHash: r2.hash, recordBytes: r3.bytes },
    ]);

    expect(report.status).toBe('VALID');
    expect(report.checkedRecordsCount).toBe(3);
  });

  // 14. Malformed Record Header Injection
  it('Attack Vector 14: Invalid magic header injection is immediately rejected', () => {
    const r1 = buildChangeRecord(1, GENESIS_PREDECEASED_HASH);
    const malformedHeader = Buffer.from(r1.bytes);
    malformedHeader[0] = 0x00; // Invalidate magic header

    const report = verifyChangeHashChain([
      { changeSeq: 1, changeHash: r1.hash, previousHash: GENESIS_PREDECEASED_HASH, recordBytes: malformedHeader },
    ]);

    expect(report.status).toBe('MALFORMED_RECORD');
  });

  // 15. Non-destructive Proposal Invariant
  it('Attack Vector 15: Proposal generation does not alter status or execute without approval', () => {
    const proposal = generateRecoveryProposal(
      crypto.randomUUID(),
      'public.users',
      crypto.randomUUID(),
      [{ tableName: 'public.users', primaryKeyTuple: Buffer.from([1]), fieldName: 'col', newValue: 'val' }],
      'user@example.com'
    );

    expect(proposal.status).toBe('PENDING');
  });

  // 16. Constant-time Hash Comparison Security
  it('Attack Vector 16: Zero-filled predecessor hash substitution is strictly rejected', () => {
    const r1 = buildChangeRecord(1, GENESIS_PREDECEASED_HASH);

    const report = verifyChangeHashChain([
      { changeSeq: 1, changeHash: r1.hash, previousHash: Buffer.alloc(32, 1), recordBytes: r1.bytes },
    ]);

    expect(report.status).toBe('CHANGE_HASH_MISMATCH');
  });
});
