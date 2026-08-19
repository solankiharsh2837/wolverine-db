import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  NodeRegistry,
  WalNormalizer,
  MutationOperation,
  PostgresAdapter,
  TrustGatewayServer,
  WolverineTrustLedger,
  WolverineEvidenceAgentClient,
  computeAttestationDigest,
  WolverineErrorCode,
  WolverineError,
  createSignedCustomerCommitment,
} from '../../src/index.js';

describe('WolverineDB v1.3.1 Trust Boundary Hardening & Convergence Suite', () => {
  describe('1. Node Trust State Machine & No Fake Signatures (Finding #9)', () => {
    it('marks un-signed node registration as UNATTESTED and rejects trust queries', () => {
      const registry = new NodeRegistry();
      const { publicKey } = crypto.generateKeyPairSync('ed25519');
      const pubKeyBytes = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

      // Register without private key
      const node = registry.registerNode(
        'node:unattested-01',
        pubKeyBytes,
        ['DATABASE_MUTATION_CAPTURE'],
        'org-alpha',
        'cluster-main'
      );

      expect(node.status).toBe('UNATTESTED');
      expect(node.attestationSignature.equals(Buffer.alloc(64, 0))).toBe(true);
      expect(registry.isNodeTrusted(node.nodeId)).toBe(false);
    });

    it('marks legitimately signed node registration as TRUSTED and passes trust queries', () => {
      const registry = new NodeRegistry();
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const pubKeyBytes = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

      // Register with private key
      const node = registry.registerNode(
        'node:trusted-01',
        pubKeyBytes,
        ['DATABASE_MUTATION_CAPTURE'],
        'org-alpha',
        'cluster-main',
        privateKey
      );

      expect(node.status).toBe('TRUSTED');
      expect(node.attestationSignature.equals(Buffer.alloc(64, 0))).toBe(false);
      expect(registry.isNodeTrusted(node.nodeId)).toBe(true);
    });

    it('rejects node registration with mismatched keypair correspondence', () => {
      const registry = new NodeRegistry();
      const pairA = crypto.generateKeyPairSync('ed25519');
      const pairB = crypto.generateKeyPairSync('ed25519');

      const pubKeyBytesA = pairA.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

      expect(() =>
        registry.registerNode(
          'node:mismatch-01',
          pubKeyBytesA,
          ['DATABASE_MUTATION_CAPTURE'],
          'org-alpha',
          'cluster-main',
          pairB.privateKey // MISMATCHED private key
        )
      ).toThrow(/Keypair correspondence failure/);
    });
  });

  describe('2. Mandatory Mutation Validation Boundary (Finding #7)', () => {
    it('WalNormalizer enforces validateChangeRecordData and rejects invalid tableId or formatVersion', () => {
      const normalizer = new WalNormalizer();

      const invalidBlock = {
        xid: '1001',
        commitLsn: '0/16B3748',
        commitTimestampUs: 1723500000000000n,
        mutations: [
          {
            action: 'I' as const,
            schema: '', // Missing schema!
            table: 'invalid',
            primaryKeyFields: [{ name: 'id', typeTag: 2, valueBuffer: Buffer.alloc(8, 1) }],
            newValues: { id: 1, name: 'Alice' },
            oldValues: null,
          },
        ],
      };

      expect(() =>
        normalizer.normalizeTransaction(
          invalidBlock,
          '00000000-0000-0000-0000-000000000001',
          Buffer.alloc(32, 0)
        )
      ).toThrow(/Invalid table identifier/);
    });
  });

  describe('3. Structured Failure Telemetry (Finding #10)', () => {
    it('records structured failure events on validator timeout or rejection', async () => {
      const mockTransport = {
        sendAttestRpc: async (endpoint: string) => {
          if (endpoint.includes('node-01')) {
            throw new Error('connection timeout to validator node-01');
          }
          if (endpoint.includes('node-02')) {
            return { success: false, error: 'Sequence rollback detected' };
          }
          return { success: true };
        },
        sendReplicateRpc: async () => ({ success: true, acknowledgedSeq: '1' }),
      };

      const gateway = new TrustGatewayServer(
        {
          gatewayId: 'gw-test',
          port: 8080,
          host: '127.0.0.1',
          requiredQuorum: 2,
          totalValidators: 3,
          validatorEndpoints: [
            { validatorId: 'val-01', endpoint: 'http://node-01:9001' },
            { validatorId: 'val-02', endpoint: 'http://node-02:9002' },
          ],
          replicaEndpoints: [],
        },
        mockTransport as any,
        new WolverineTrustLedger()
      );

      const customerKeys = crypto.generateKeyPairSync('ed25519');
      const customerPub = customerKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
      gateway.registerTenant('tenant-telemetry', customerPub, 'db-telemetry');

      const commitment = createSignedCustomerCommitment(
        {
          commitmentId: crypto.randomUUID(),
          tenantId: 'tenant-telemetry',
          databaseId: 'db-telemetry',
          checkpointId: '00000000-0000-0000-0000-000000001001',
          commitSeq: 1001n,
          checkpointDigest: Buffer.alloc(32, 0x11),
          previousTrustCommitment: Buffer.alloc(32, 0),
          epoch: 1,
        },
        customerKeys.privateKey,
        customerPub
      );

      await expect(gateway.ingestCommitment(commitment)).rejects.toThrow();

      const failures = gateway.getPeerFailures();
      expect(failures.length).toBe(2);

      const timeoutFailure = failures.find((f) => f.peerId === 'val-01');
      expect(timeoutFailure?.reason).toBe('TIMEOUT');
      expect(timeoutFailure?.errorMessage).toContain('timeout');

      const rejectedFailure = failures.find((f) => f.peerId === 'val-02');
      expect(rejectedFailure?.reason).toBe('PEER_REJECTED');
      expect(rejectedFailure?.errorMessage).toBe('Sequence rollback detected');
    });
  });

  describe('4. Deterministic Timestamp Persistence (Finding #11)', () => {
    it('reconstructs identical attestation digest using persisted timestampUs without drift', () => {
      const commitmentId = 'cmt-persist-01';
      const validatorId = 'val-01';
      const observedDigest = Buffer.alloc(32, 0xaa);
      const timestampUs = 1723500999999000n;

      const digest1 = computeAttestationDigest(
        commitmentId,
        validatorId,
        observedDigest,
        timestampUs
      );

      // Later point in time: verifier uses the exact recorded timestampUs
      const digest2 = computeAttestationDigest(
        commitmentId,
        validatorId,
        observedDigest,
        timestampUs
      );

      expect(digest1.equals(digest2)).toBe(true);
    });
  });

  describe('5. Error Code Invariant Enforcement (Finding #12)', () => {
    it('throws MISSING_SECRET_KEY when evidence agent client has no private key', () => {
      const customerKeys = crypto.generateKeyPairSync('ed25519');
      const customerPub = customerKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

      expect(() => {
        new WolverineEvidenceAgentClient({
          tenantId: 'tenant-test',
          databaseId: 'db-test',
          customerPubkey: customerPub,
          customerPrivateKey: null as any,
          gateway: {} as any,
        });
      }).toThrowError(
        expect.objectContaining({
          code: WolverineErrorCode.MISSING_SECRET_KEY,
        })
      );
    });
  });
});
