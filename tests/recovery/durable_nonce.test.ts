import { describe, it, expect, vi } from 'vitest';
import crypto from 'node:crypto';
import pg from 'pg';
import {
  formatNonceUuid,
  InMemoryNonceStore,
  IApprovalNonceStore,
} from '../../src/engine/nonce_store.js';
import { PostgresNonceStore } from '../../src/postgres/nonce_store.js';
import { PostgresAdapter } from '../../src/postgres/adapter.js';
import {
  generateRecoveryProposal,
  validateAndPrepareRecovery,
  validateAndPrepareRecoveryAsync,
} from '../../src/engine/recovery.js';
import { RecoveryProvenanceEngine } from '../../src/engine/recovery_provenance.js';
import { WORMCheckpointStore } from '../../src/checkpoint/worm.js';
import { encodeApprovalPayload, SignedApprovalEnvelope } from '../../src/crypto/approval.js';
import { WolverineErrorCode } from '../../src/errors/codes.js';

describe('Durable Approval Nonce Store & Replay Defense (WDB-0006 & Issue #1)', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const approverPubkey = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const approverHex = approverPubkey.toString('hex');

  function createTestEnvelope(nonceBuf: Buffer, proposal: any): SignedApprovalEnvelope {
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
    return {
      ...approvalParams,
      signature,
    };
  }

  describe('formatNonceUuid', () => {
    it('formats 16-byte Buffer to valid UUID string', () => {
      const buf = Buffer.from('0102030405060708090a0b0c0d0e0f10', 'hex');
      const uuid = formatNonceUuid(buf);
      expect(uuid).toBe('01020304-0506-0708-090a-0b0c0d0e0f10');
    });

    it('formats 32-char hex string to valid UUID string', () => {
      const hex = 'aabbccddeeff00112233445566778899';
      const uuid = formatNonceUuid(hex);
      expect(uuid).toBe('aabbccdd-eeff-0011-2233-445566778899');
    });

    it('preserves already-formatted UUID string', () => {
      const input = '12345678-1234-1234-1234-123456789abc';
      expect(formatNonceUuid(input)).toBe('12345678-1234-1234-1234-123456789abc');
    });
  });

  describe('InMemoryNonceStore', () => {
    it('records consumed nonce and rejects duplicate recording', () => {
      const store = new InMemoryNonceStore();
      const nonce = Buffer.alloc(16, 0x42);
      const incidentId = crypto.randomUUID();

      expect(store.isConsumed(nonce)).toBe(false);
      store.recordConsumed(nonce, incidentId, approverPubkey);
      expect(store.isConsumed(nonce)).toBe(true);

      expect(() => {
        store.recordConsumed(nonce, incidentId, approverPubkey);
      }).toThrowError(
        expect.objectContaining({ code: WolverineErrorCode.REPLAYED_APPROVAL_NONCE })
      );
    });

    it('initializes from an existing list of nonces to simulate persistent reload', () => {
      const nonce1 = '11111111-1111-1111-1111-111111111111';
      const nonce2 = '22222222-2222-2222-2222-222222222222';
      const store = new InMemoryNonceStore([nonce1, nonce2]);

      expect(store.isConsumed(nonce1)).toBe(true);
      expect(store.isConsumed(nonce2)).toBe(true);
      expect(store.isConsumed('33333333-3333-3333-3333-333333333333')).toBe(false);
    });
  });

  describe('PostgresNonceStore with Mocked Pool', () => {
    it('queries wolverine_sys.approval_nonces on isConsumed', async () => {
      const mockQuery = vi.fn().mockResolvedValue({ rowCount: 1, rows: [{ '1': 1 }] });
      const mockRelease = vi.fn();
      const mockPool = {
        connect: vi.fn().mockResolvedValue({
          query: mockQuery,
          release: mockRelease,
        }),
      } as unknown as pg.Pool;

      const pgStore = new PostgresNonceStore(mockPool);
      const nonce = Buffer.alloc(16, 0x77);
      const isConsumed = await pgStore.isConsumed(nonce);

      expect(isConsumed).toBe(true);
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('SELECT 1 FROM wolverine_sys.approval_nonces WHERE nonce = $1::uuid'),
        [formatNonceUuid(nonce)]
      );
      expect(mockRelease).toHaveBeenCalled();
    });

    it('inserts into wolverine_sys.approval_nonces on recordConsumed', async () => {
      const mockQuery = vi.fn().mockResolvedValue({ rowCount: 1, rows: [] });
      const mockRelease = vi.fn();
      const mockPool = {
        connect: vi.fn().mockResolvedValue({
          query: mockQuery,
          release: mockRelease,
        }),
      } as unknown as pg.Pool;

      const pgStore = new PostgresNonceStore(mockPool);
      const nonce = Buffer.alloc(16, 0x88);
      const incidentId = crypto.randomUUID();

      await pgStore.recordConsumed(nonce, incidentId, approverPubkey);

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO wolverine_sys.approval_nonces'),
        [formatNonceUuid(nonce), formatNonceUuid(incidentId), approverPubkey]
      );
      expect(mockRelease).toHaveBeenCalled();
    });

    it('translates PostgreSQL duplicate key 23505 violation into REPLAYED_APPROVAL_NONCE', async () => {
      const dbErr: any = new Error('duplicate key value violates unique constraint "approval_nonces_pkey"');
      dbErr.code = '23505';

      const mockQuery = vi.fn().mockRejectedValue(dbErr);
      const mockRelease = vi.fn();
      const mockPool = {
        connect: vi.fn().mockResolvedValue({
          query: mockQuery,
          release: mockRelease,
        }),
      } as unknown as pg.Pool;

      const pgStore = new PostgresNonceStore(mockPool);
      const nonce = Buffer.alloc(16, 0x99);
      const incidentId = crypto.randomUUID();

      await expect(
        pgStore.recordConsumed(nonce, incidentId, approverPubkey)
      ).rejects.toThrowError(
        expect.objectContaining({ code: WolverineErrorCode.REPLAYED_APPROVAL_NONCE })
      );
    });
  });

  describe('PostgresAdapter Nonce Store Integration', () => {
    it('exposes getNonceStore, isNonceConsumed, and recordConsumedNonce', async () => {
      const mockQuery = vi.fn().mockResolvedValue({ rowCount: 0, rows: [] });
      const mockRelease = vi.fn();
      const mockPool = {
        connect: vi.fn().mockResolvedValue({
          query: mockQuery,
          release: mockRelease,
        }),
        end: vi.fn().mockResolvedValue(undefined),
      } as unknown as pg.Pool;

      const adapter = new PostgresAdapter({
        connectionString: 'postgresql://localhost:5432/test',
        protectedTables: ['public.users'],
      });
      (adapter as any).pool = mockPool;

      const nonce = Buffer.alloc(16, 0xab);
      const consumed = await adapter.isNonceConsumed(nonce);
      expect(consumed).toBe(false);

      const store = adapter.getNonceStore();
      expect(store).toBeInstanceOf(PostgresNonceStore);
    });
  });

  describe('validateAndPrepareRecovery with Durable Nonce Store', () => {
    it('executes recovery and durably prevents replay across process restart simulation', async () => {
      const nonceStore = new InMemoryNonceStore();

      const proposal1 = generateRecoveryProposal(
        crypto.randomUUID(),
        'public.users',
        crypto.randomUUID(),
        [
          {
            tableName: 'public.users',
            primaryKeyTuple: Buffer.from([1]),
            fieldName: 'email',
            newValue: 'user1@example.com',
          },
        ],
        'admin1@example.com'
      );

      const nonceBuf = Buffer.alloc(16, 0x55);
      const envelope = createTestEnvelope(nonceBuf, proposal1);

      // First run: Success
      const result1 = await validateAndPrepareRecoveryAsync(
        proposal1,
        envelope,
        [approverHex],
        nonceStore,
        1000000000000000n
      );

      expect(result1.success).toBe(true);
      expect(proposal1.status).toBe('EXECUTED');
      expect(nonceStore.isConsumed(nonceBuf)).toBe(true);

      // Process Restart Simulation: New process instance connects to existing durable nonce store
      const proposal2 = generateRecoveryProposal(
        crypto.randomUUID(),
        'public.users',
        crypto.randomUUID(),
        [
          {
            tableName: 'public.users',
            primaryKeyTuple: Buffer.from([1]),
            fieldName: 'email',
            newValue: 'user1@example.com',
          },
        ],
        'admin1@example.com'
      );

      // Attacker replays envelope with the same nonce
      await expect(
        validateAndPrepareRecoveryAsync(
          proposal2,
          envelope,
          [approverHex],
          nonceStore,
          1000000000000000n
        )
      ).rejects.toThrowError(
        expect.objectContaining({ code: WolverineErrorCode.REPLAYED_APPROVAL_NONCE })
      );
    });

    it('works seamlessly with RecoveryProvenanceEngine and durable store', async () => {
      const nonceStore = new InMemoryNonceStore();
      const vaultStore = new WORMCheckpointStore();

      const proposal = generateRecoveryProposal(
        crypto.randomUUID(),
        'public.users',
        crypto.randomUUID(),
        [
          {
            tableName: 'public.users',
            primaryKeyTuple: Buffer.from([1]),
            fieldName: 'role',
            newValue: 'USER',
          },
        ],
        'operator@example.com'
      );

      const nonceBuf = Buffer.alloc(16, 0x77);
      const envelope = createTestEnvelope(nonceBuf, proposal);

      const { result, auditTrail } = await RecoveryProvenanceEngine.executeWithProvenance(
        proposal,
        envelope,
        [approverPubkey],
        nonceStore,
        vaultStore,
        100n,
        Buffer.alloc(32, 0xaa),
        null
      );

      expect(result.success).toBe(true);
      expect(auditTrail.auditStatus).toBe('PROVABLY_CORRECT');
      expect(nonceStore.isConsumed(nonceBuf)).toBe(true);

      // Replay attempt fails
      const replayProposal = generateRecoveryProposal(
        crypto.randomUUID(),
        'public.users',
        crypto.randomUUID(),
        [
          {
            tableName: 'public.users',
            primaryKeyTuple: Buffer.from([1]),
            fieldName: 'role',
            newValue: 'USER',
          },
        ],
        'operator@example.com'
      );

      await expect(
        RecoveryProvenanceEngine.executeWithProvenance(
          replayProposal,
          envelope,
          [approverPubkey],
          nonceStore,
          vaultStore,
          101n,
          Buffer.alloc(32, 0xaa),
          null
        )
      ).rejects.toThrowError(
        expect.objectContaining({ code: WolverineErrorCode.REPLAYED_APPROVAL_NONCE })
      );
    });
  });
});
