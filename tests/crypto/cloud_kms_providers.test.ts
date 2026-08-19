import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { AwsKmsSigningProvider } from '../../src/crypto/aws_kms_provider.js';
import { GcpKmsSigningProvider } from '../../src/crypto/gcp_kms_provider.js';
import { WolverineErrorCode } from '../../src/errors/index.js';

describe('Milestone 3 — Cloud KMS Signing Providers (AWS KMS & GCP KMS)', () => {
  const keyPair = crypto.generateKeyPairSync('ed25519');
  const pubRaw = keyPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const testDigest = crypto.createHash('sha256').update('test_payload_commitment').digest();

  describe('AwsKmsSigningProvider', () => {
    it('initializes and signs using mock signing key with cryptographic validity', async () => {
      const provider = new AwsKmsSigningProvider({
        keyId: 'arn:aws:kms:us-east-1:123456789012:key/wolverine-state-signer',
        region: 'us-east-1',
        mockSigningKey: keyPair.privateKey,
        publicKey: pubRaw,
      });

      expect(provider.getProviderType()).toBe('AWS_KMS');
      expect(provider.getKeyId()).toBe('arn:aws:kms:us-east-1:123456789012:key/wolverine-state-signer');
      expect(provider.getRegion()).toBe('us-east-1');
      expect(provider.getPublicKey()).toEqual(pubRaw);

      const signature = await provider.sign(testDigest);
      expect(signature.length).toBe(64);

      // Verify signature with public key
      const verified = crypto.verify(null, testDigest, keyPair.publicKey, signature);
      expect(verified).toBe(true);
    });

    it('interacts with mock AWS KMS Client interface and handles RPC failure', async () => {
      const mockClient = {
        sign: async (params: any) => {
          return { Signature: new Uint8Array(Buffer.alloc(64, 0x77)) };
        },
        getPublicKey: async (params: any) => {
          return { PublicKey: new Uint8Array(pubRaw) };
        },
      };

      const provider = new AwsKmsSigningProvider({
        keyId: 'alias/wolverine-signer',
        kmsClient: mockClient,
      });

      const fetchedPub = await provider.fetchPublicKey();
      expect(fetchedPub).toEqual(pubRaw);

      const sig = await provider.sign(testDigest);
      expect(sig).toEqual(Buffer.alloc(64, 0x77));

      // Test KMS failure handling
      const failingClient = {
        sign: async () => {
          throw new Error('KMS.AccessDeniedException');
        },
        getPublicKey: async () => {
          throw new Error('KMS.NotFoundException');
        },
      };

      const failingProvider = new AwsKmsSigningProvider({
        keyId: 'alias/failing-key',
        kmsClient: failingClient,
      });

      await expect(failingProvider.sign(testDigest)).rejects.toThrowError(/AWS KMS Asymmetric Sign failed/);
      await expect(failingProvider.fetchPublicKey()).rejects.toThrowError(/AWS KMS failed to fetch public key/);
    });
  });

  describe('GcpKmsSigningProvider', () => {
    it('initializes and signs using mock signing key with cryptographic validity', async () => {
      const keyName = 'projects/prod-vault/locations/global/keyRings/wolverine-ring/cryptoKeys/state-signer/cryptoKeyVersions/1';
      const provider = new GcpKmsSigningProvider({
        keyVersionName: keyName,
        mockSigningKey: keyPair.privateKey,
        publicKey: pubRaw,
      });

      expect(provider.getProviderType()).toBe('GCP_KMS');
      expect(provider.getKeyId()).toBe(keyName);
      expect(provider.getPublicKey()).toEqual(pubRaw);

      const signature = await provider.sign(testDigest);
      expect(signature.length).toBe(64);

      const verified = crypto.verify(null, testDigest, keyPair.publicKey, signature);
      expect(verified).toBe(true);
    });

    it('interacts with mock GCP KMS Client interface and handles RPC outage', async () => {
      const keyName = 'projects/prod-vault/locations/global/keyRings/wolverine-ring/cryptoKeys/state-signer/cryptoKeyVersions/1';
      const pem = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();

      const mockClient = {
        asymmetricSign: async (params: any) => {
          return [{ signature: new Uint8Array(Buffer.alloc(64, 0x88)) }] as [{ signature: Uint8Array }];
        },
        getPublicKey: async (params: any) => {
          return [{ pem }] as [{ pem: string }];
        },
      };

      const provider = new GcpKmsSigningProvider({
        keyVersionName: keyName,
        kmsClient: mockClient,
      });

      const fetchedPub = await provider.fetchPublicKey();
      expect(fetchedPub).toEqual(pubRaw);

      const sig = await provider.sign(testDigest);
      expect(sig).toEqual(Buffer.alloc(64, 0x88));

      // Test outage handling
      const failingClient = {
        asymmetricSign: async () => {
          throw new Error('GoogleAuthError: token expired');
        },
        getPublicKey: async () => {
          throw new Error('DEADLINE_EXCEEDED');
        },
      };

      const failingProvider = new GcpKmsSigningProvider({
        keyVersionName: keyName,
        kmsClient: failingClient,
      });

      await expect(failingProvider.sign(testDigest)).rejects.toThrowError(/GCP Cloud KMS Asymmetric Sign failed/);
      await expect(failingProvider.fetchPublicKey()).rejects.toThrowError(/GCP Cloud KMS failed to fetch public key/);
    });
  });
});
