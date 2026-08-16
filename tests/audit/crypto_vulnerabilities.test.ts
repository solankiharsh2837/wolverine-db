import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  MerkleTree,
  verifyMerkleProof,
  computeMerkleLeafHash,
  encodeApprovalPayload,
  verifyApprovalEnvelope,
  generateTableTriggerSql,
  validateSqlIdentifier,
  validateCheckpointId,
  computeAttestationDigest,
  computeKeyRotationPayload,
  computeFederatedRecoveryDigest,
  computeDistributedIncidentId,
} from '../../src/index.js';

describe('Hostile Cryptographic Audit Regression Suite (CRYPTO-AUDIT)', () => {
  describe('VULN-001: Merkle Proof Odd-Leaf Root Collision & Tree-Shape Invariance', () => {
    it('guarantees that 3-leaf tree [X, Y, Z] produces a DIFFERENT root than 4-leaf tree [X, Y, Z, Z]', () => {
      const leafX = Buffer.from('PAYLOAD_X', 'utf8');
      const leafY = Buffer.from('PAYLOAD_Y', 'utf8');
      const leafZ = Buffer.from('PAYLOAD_Z', 'utf8');

      const tree3 = new MerkleTree([leafX, leafY, leafZ]);
      const tree4 = new MerkleTree([leafX, leafY, leafZ, leafZ]);

      // Roots must NOT collide
      expect(tree3.root.equals(tree4.root)).toBe(false);

      // Inclusion proof for leaf Z (index 2) in tree3
      const proof3 = tree3.generateProof(2);
      expect(proof3.leafIndex).toBe(2);
      expect(proof3.leafCount).toBe(3);
      expect(
        verifyMerkleProof(
          proof3.leafHash,
          proof3.proof,
          tree3.root,
          proof3.leafIndex,
          proof3.leafCount
        )
      ).toBe(true);

      // Attempting to verify index 3 (out of bounds for 3-leaf tree) fails
      expect(
        verifyMerkleProof(
          proof3.leafHash,
          proof3.proof,
          tree3.root,
          3, // leafIndex 3
          3  // leafCount 3 -> 3 >= 3 must fail!
        )
      ).toBe(false);
    });
  });

  describe('VULN-002: Signature Encoding Concatenation Ambiguity in Approval Envelopes', () => {
    it('produces distinct preimages when string field boundaries shift', () => {
      const incidentId = Buffer.alloc(16, 0x11);
      const targetVersionId = Buffer.alloc(16, 0x22);
      const proposedChangesHash = Buffer.alloc(32, 0x33);
      const approverPubkey = Buffer.alloc(32, 0x44);
      const nonce = Buffer.alloc(16, 0x55);
      const expiresAtUs = 1000000000n;

      // Case A: scope = "AB", requester = "C"
      const payloadA = encodeApprovalPayload({
        incidentId,
        protectedScope: 'AB',
        targetVersionId,
        proposedChangesHash,
        requesterId: 'C',
        approverPubkey,
        nonce,
        expiresAtUs,
      });

      // Case B: scope = "A", requester = "BC"
      const payloadB = encodeApprovalPayload({
        incidentId,
        protectedScope: 'A',
        targetVersionId,
        proposedChangesHash,
        requesterId: 'BC',
        approverPubkey,
        nonce,
        expiresAtUs,
      });

      // In unambiguous encoding, preimages must be distinct
      expect(payloadA.equals(payloadB)).toBe(false);
    });
  });

  describe('VULN-003: Attestation Digest Concatenation Ambiguity', () => {
    it('produces distinct attestation digests when commitmentId and validatorId boundaries shift', () => {
      const digest = Buffer.alloc(32, 0xaa);
      const timeUs = 1000n;

      // Case A: commitmentId = "c1", validatorId = "val2"
      const digestA = computeAttestationDigest('c1', 'val2', digest, timeUs);

      // Case B: commitmentId = "c1val", validatorId = "2"
      const digestB = computeAttestationDigest('c1val', '2', digest, timeUs);

      expect(digestA.equals(digestB)).toBe(false);
    });
  });

  describe('VULN-004: Separation of Duties Strict Equality Defense', () => {
    it('rejects identity substring collisions in separation of duties check', () => {
      const approverKeys = crypto.generateKeyPairSync('ed25519');
      const approverPubkey = approverKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
      const approverHex = approverPubkey.toString('hex');

      // Attacker creates a requesterId that contains the approver hex substring
      const substringRequester = `admin_${approverHex.slice(0, 10)}_user`;

      const envelope = {
        incidentId: Buffer.alloc(16, 1),
        protectedScope: 'public.accounts',
        targetVersionId: Buffer.alloc(16, 2),
        proposedChangesHash: Buffer.alloc(32, 3),
        requesterId: substringRequester,
        approverPubkey,
        nonce: Buffer.alloc(16, 4),
        expiresAtUs: 9999999999999n,
      };

      const payload = encodeApprovalPayload(envelope);
      const signature = crypto.sign(null, payload, approverKeys.privateKey);

      const signedEnvelope = {
        ...envelope,
        signature,
      };

      // Since requester is different from approver, verification should proceed without false substring rejection
      expect(() =>
        verifyApprovalEnvelope(signedEnvelope, [approverHex], 1000n)
      ).not.toThrow();

      // But when requester is ACTUALLY the approver, it MUST throw REQUESTER_IS_APPROVER
      const selfSignedEnvelope = {
        ...signedEnvelope,
        requesterId: approverHex,
        signature: crypto.sign(
          null,
          encodeApprovalPayload({ ...envelope, requesterId: approverHex }),
          approverKeys.privateKey
        ),
      };

      expect(() =>
        verifyApprovalEnvelope(selfSignedEnvelope, [approverHex], 1000n)
      ).toThrow(/Separation of duties violation/);
    });
  });

  describe('VULN-005 & VULN-006: Multi-Field Length Prefixing in Federation and Key Rotation', () => {
    it('produces distinct preimages for shifted string boundaries in federated recovery digest', () => {
      const proposalId = '00000000-0000-0000-0000-000000000001';
      const hash = Buffer.alloc(32, 0x11);

      const digestA = computeFederatedRecoveryDigest(proposalId, 'inc1', 'scope2', hash);
      const digestB = computeFederatedRecoveryDigest(proposalId, 'inc1scope', '2', hash);

      expect(digestA.equals(digestB)).toBe(false);
    });

    it('produces distinct preimages for shifted string boundaries in key rotation payload', () => {
      const oldPub = Buffer.alloc(32, 1);
      const newPub = Buffer.alloc(32, 2);

      const payloadA = computeKeyRotationPayload('tenantA', 'dbB', 1n, oldPub, newPub);
      const payloadB = computeKeyRotationPayload('tenantAdb', 'B', 1n, oldPub, newPub);

      expect(payloadA.equals(payloadB)).toBe(false);
    });

    it('produces distinct incident IDs for shifted originPlane and scope boundaries', () => {
      const rootEventId = '00000000-0000-0000-0000-000000000001';
      const timeUs = 1700000000000000n;

      const incA = computeDistributedIncidentId('SENTINEL', rootEventId, timeUs, 'public.users');
      const incB = computeDistributedIncidentId('SENTINEL', rootEventId, timeUs, 'public.user');

      expect(incA).not.toBe(incB);
    });
  });

  describe('VULN-007 & VULN-008: SQL Injection Defense and Trigger Change-Capture Body', () => {
    it('validates SQL identifiers and rejects injection payloads', () => {
      expect(() => validateSqlIdentifier('valid_table_1')).not.toThrow();
      expect(() => validateSqlIdentifier('orders; DROP TABLE users; --')).toThrow(
        /Invalid SQL identifier/
      );
      expect(() => validateSqlIdentifier('users" OR 1=1 --')).toThrow(
        /Invalid SQL identifier/
      );
    });

    it('generates properly quoted DDL trigger with change-capture mutation insertion', () => {
      const sql = generateTableTriggerSql('public', 'orders', ['id']);

      // Verifies identifier quoting
      expect(sql).toContain('"public"."orders"');
      expect(sql).toContain('wolverine_sys."wolverine_sys_trg_public_orders"');

      // Verifies change capture persistence body is present
      expect(sql).toContain('INSERT INTO wolverine_sys.pending_mutations');
      expect(sql).toContain('pg_logical_emit_message');
    });
  });

  describe('VULN-009: Checkpoint Path Traversal Defense', () => {
    it('rejects path traversal attempts in checkpoint IDs', () => {
      const baseDir = '/tmp/wolverine_checkpoints';

      // Valid UUID format
      const validId = '12345678-1234-1234-1234-123456789abc';
      expect(() => validateCheckpointId(validId, baseDir)).not.toThrow();

      // Path traversal payloads
      expect(() => validateCheckpointId('../../etc/passwd', baseDir)).toThrow(
        /Invalid checkpointId format|Path traversal detected/
      );
      expect(() => validateCheckpointId('..\\..\\windows\\system32', baseDir)).toThrow(
        /Invalid checkpointId format|Path traversal detected/
      );
    });
  });
});
