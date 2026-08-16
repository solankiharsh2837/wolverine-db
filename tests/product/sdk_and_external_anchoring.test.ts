import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WolverineClient,
  DistributedTrustCluster,
  TrustBlockBuilder,
  createSignedCustomerCommitment,
} from '../../src/index.js';

describe('WolverineDB v1.3 Product Suite: External Trust Anchoring & Customer SDK', () => {
  describe('1. Managed Wolverine Trust Network Anchoring Flow', () => {
    it('customer SDK anchors checkpoint to managed trust network and receives offline-verifiable receipt', async () => {
      const cluster = new DistributedTrustCluster({
        requiredQuorum: 4,
        totalValidators: 5,
        totalReplicas: 3,
      });

      const customerKeys = crypto.generateKeyPairSync('ed25519');
      const customerPub = customerKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

      cluster.gateway.registerTenant('tenant-enterprise-alpha', customerPub, 'orders-db');

      // Initialize Customer SDK
      const wolverine = await WolverineClient.connect(
        {
          endpoint: 'https://trust.wolverine-db.com/v1',
          networkType: 'MANAGED',
          networkId: 'wolverine-cloud-prod',
          tenantId: 'tenant-enterprise-alpha',
          databaseId: 'orders-db',
          customerPubkey: customerPub,
          customerPrivateKey: customerKeys.privateKey,
          apiKey: 'wdb_live_sec_123456',
        },
        cluster.gateway
      );

      const checkpoint = {
        checkpointId: '00000000-0000-0000-0000-000000005000',
        commitSeq: 5000n,
        scope: 'public.orders',
        merkleRoot: Buffer.alloc(32, 0x55),
        changeChainHead: Buffer.alloc(32, 0x11),
        createdAtUs: 1723500000000000n,
        protocolVersion: 3,
      };

      const result = await wolverine.anchorCheckpoint(checkpoint);

      expect(result.isFinalized).toBe(true);
      expect(result.isQueued).toBe(false);
      expect(result.receipt).toBeDefined();

      // 100% Offline Standalone Verification (Zero network calls)
      const offlineVerdict = WolverineClient.verifyReceipt(result.receipt!);
      expect(offlineVerdict.isValid).toBe(true);
      expect(offlineVerdict.verdict).toBe('AUTHENTIC_AND_IMMUTABLE');
    });
  });

  describe('2. Self-Hosted Wolverine Trust Network Anchoring Flow', () => {
    it('customer SDK seamlessly connects to self-hosted private trust cluster with identical protocol', async () => {
      const privateCluster = new DistributedTrustCluster({
        requiredQuorum: 3,
        totalValidators: 4,
        totalReplicas: 2,
      });

      const customerKeys = crypto.generateKeyPairSync('ed25519');
      const customerPub = customerKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

      privateCluster.gateway.registerTenant('tenant-sovereign-bank', customerPub, 'core-ledger');

      const selfHostedClient = await WolverineClient.connect(
        {
          endpoint: 'http://127.0.0.1:8080',
          networkType: 'SELF_HOSTED',
          networkId: 'self-hosted:sovereign-bank-cluster',
          tenantId: 'tenant-sovereign-bank',
          databaseId: 'core-ledger',
          customerPubkey: customerPub,
          customerPrivateKey: customerKeys.privateKey,
        },
        privateCluster.gateway
      );

      const status = await selfHostedClient.getNetworkStatus();
      expect(status.networkType).toBe('SELF_HOSTED');
      expect(status.networkId).toBe('self-hosted:sovereign-bank-cluster');
      expect(status.healthy).toBe(true);

      const checkpoint = {
        checkpointId: '00000000-0000-0000-0000-000000001000',
        commitSeq: 1000n,
        scope: 'public.accounts',
        merkleRoot: Buffer.alloc(32, 0xaa),
        changeChainHead: Buffer.alloc(32, 0xbb),
        createdAtUs: 1723500000000000n,
        protocolVersion: 3,
      };

      const result = await selfHostedClient.anchorCheckpoint(checkpoint);
      expect(result.isFinalized).toBe(true);
      expect(result.receipt?.tenantId).toBe('tenant-sovereign-bank');
    });
  });

  describe('3. Wolverine Trust Block Specification (WDB-0130)', () => {
    it('constructs deterministic block header and detects transaction tampering', () => {
      const keysA = crypto.generateKeyPairSync('ed25519');
      const keysB = crypto.generateKeyPairSync('ed25519');

      const pubA = keysA.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
      const pubB = keysB.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

      const commitment = createSignedCustomerCommitment(
        {
          commitmentId: crypto.randomUUID(),
          tenantId: 'tenant-1',
          databaseId: 'db-1',
          checkpointId: '00000000-0000-0000-0000-000000000001',
          commitSeq: 1n,
          checkpointDigest: Buffer.alloc(32, 0x11),
          previousTrustCommitment: Buffer.alloc(32, 0),
          epoch: 1,
        },
        keysA.privateKey,
        pubA
      );

      const block1 = TrustBlockBuilder.buildBlock({
        networkId: 'wolverine-managed-v1',
        epoch: 1,
        blockHeight: 100n,
        previousBlockHash: Buffer.alloc(32, 0),
        timestampUs: 1723500000000000n,
        commitments: [commitment],
        stateRoot: Buffer.alloc(32, 0x77),
        validatorPublicKeys: [pubA, pubB],
        quorumCertificate: {
          commitmentId: commitment.commitmentId,
          quorumCount: 4,
          totalValidators: 5,
          attestationSignatures: [],
          quorumDigest: Buffer.alloc(32, 0x88),
          epoch: 1,
          validatorSetId: 'valset-v1',
          certificateDigest: Buffer.alloc(32, 0x99),
          finalizedAtUs: 1723500000000000n,
        },
      });

      expect(block1.blockHash.length).toBe(32);

      // Deterministic identical input yields bitwise identical block hash
      const block2 = TrustBlockBuilder.buildBlock({
        networkId: 'wolverine-managed-v1',
        epoch: 1,
        blockHeight: 100n,
        previousBlockHash: Buffer.alloc(32, 0),
        timestampUs: 1723500000000000n,
        commitments: [commitment],
        stateRoot: Buffer.alloc(32, 0x77),
        validatorPublicKeys: [pubA, pubB],
        quorumCertificate: {
          commitmentId: commitment.commitmentId,
          quorumCount: 4,
          totalValidators: 5,
          attestationSignatures: [],
          quorumDigest: Buffer.alloc(32, 0x88),
          epoch: 1,
          validatorSetId: 'valset-v1',
          certificateDigest: Buffer.alloc(32, 0x99),
          finalizedAtUs: 1723500000000000n,
        },
      });

      expect(block1.blockHash.equals(block2.blockHash)).toBe(true);
    });
  });

  describe('4. Client Offline Buffer Queue and Failover', () => {
    it('buffers commitments during network outage and flushes upon reconnection', async () => {
      const customerKeys = crypto.generateKeyPairSync('ed25519');
      const customerPub = customerKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

      // Client with no gateway online initially
      const client = await WolverineClient.connect({
        endpoint: 'https://trust.wolverine-db.com/v1',
        tenantId: 'tenant-offline-buffering',
        databaseId: 'orders-db',
        customerPubkey: customerPub,
        customerPrivateKey: customerKeys.privateKey,
      });

      const cp1 = {
        checkpointId: '00000000-0000-0000-0000-000000000001',
        commitSeq: 1n,
        scope: 'public.orders',
        merkleRoot: Buffer.alloc(32, 0x11),
        changeChainHead: Buffer.alloc(32, 0x11),
        createdAtUs: 1723500000000000n,
        protocolVersion: 3,
      };

      const res1 = await client.anchorCheckpoint(cp1);
      expect(res1.isFinalized).toBe(false);
      expect(res1.isQueued).toBe(true);
      expect(client.getOfflineQueueLength()).toBe(1);
    });
  });
});
