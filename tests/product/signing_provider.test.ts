import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  LocalSoftwareSigningProvider,
  CloudKmsSigningProvider,
  HsmSigningProvider,
  WolverineClient,
  DistributedTrustCluster,
} from '../../src/index.js';

describe('Signing Provider & Enterprise KMS / HSM Abstraction (WDB-0135)', () => {
  it('LocalSoftwareSigningProvider signs digests and verifies against Ed25519 public key', async () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const provider = new LocalSoftwareSigningProvider(pair.privateKey);

    const digest = crypto.createHash('sha256').update('TEST_STATE_COMMITMENT').digest();
    const signature = await provider.sign(digest);

    const valid = crypto.verify(null, digest, pair.publicKey, signature);
    expect(valid).toBe(true);
  });

  it('CloudKmsSigningProvider signs commitments via AWS KMS Key ARN without exposing raw private keys', async () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pubBytes = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

    const kms = new CloudKmsSigningProvider({
      provider: 'AWS_KMS',
      keyArn: 'arn:aws:kms:us-east-1:112233445566:key/wolverine-prod-key',
      region: 'us-east-1',
      publicKey: pubBytes,
      mockSigningKey: pair.privateKey,
    });

    expect(kms.getProviderType()).toBe('AWS_KMS');
    expect(kms.getKeyId()).toContain('arn:aws:kms:us-east-1');

    const digest = crypto.createHash('sha256').update('COMMITMENT_DIGEST_#1842').digest();
    const signature = await kms.sign(digest);

    const valid = crypto.verify(null, digest, pair.publicKey, signature);
    expect(valid).toBe(true);
  });

  it('WolverineClient anchors checkpoint using CloudKmsSigningProvider and receives verified receipt', async () => {
    const cluster = new DistributedTrustCluster({
      requiredQuorum: 4,
      totalValidators: 5,
      totalReplicas: 3,
    });

    const keyPair = crypto.generateKeyPairSync('ed25519');
    const pubBytes = keyPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

    cluster.gateway.registerTenant('tenant-fintech-kms', pubBytes, 'prod-db');

    const kms = new CloudKmsSigningProvider({
      provider: 'GCP_KMS',
      keyArn: 'projects/enterprise/locations/global/keyRings/wdb/cryptoKeys/ed25519',
      region: 'global',
      publicKey: pubBytes,
      mockSigningKey: keyPair.privateKey,
    });

    const client = await WolverineClient.connect(
      {
        endpoint: 'https://trust.wolverine-db.com/v1',
        tenantId: 'tenant-fintech-kms',
        databaseId: 'prod-db',
        signingProvider: kms,
      },
      cluster.gateway
    );

    const result = await client.anchorCheckpoint({
      checkpointId: '00000000-0000-0000-0000-000000001842',
      commitSeq: 1842n,
      scope: 'public.accounts',
      merkleRoot: Buffer.alloc(32, 0x99),
      changeChainHead: Buffer.alloc(32, 0x11),
      createdAtUs: 1723500000000000n,
      protocolVersion: 3,
    });

    expect(result.isFinalized).toBe(true);
    expect(result.receipt).toBeDefined();

    const offlineCheck = WolverineClient.verifyReceipt(result.receipt!);
    expect(offlineCheck.isValid).toBe(true);
  });
});
