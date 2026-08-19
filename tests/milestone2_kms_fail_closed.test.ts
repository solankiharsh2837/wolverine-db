import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  CloudKmsCustomerSigner,
  SoftwareCustomerSigner,
  computeCustomerAuthorizationDigest,
  WolverineErrorCode,
} from '../src/index.js';

describe('Milestone 2.10 — Fail-Closed Customer KMS Signing Engine', () => {
  const customerKeypair = crypto.generateKeyPairSync('ed25519');
  const customerPubkey = customerKeypair.publicKey.export({ format: 'der', type: 'spki' });

  it('1. Cloud KMS Signer: succeeds when KMS provider returns valid Ed25519 signature', async () => {
    const dummyDigest = crypto.createHash('sha256').update('COMMITMENT_DIGEST').digest();

    const mockKmsClient = {
      asymmetricSign: async (params: any) => {
        expect(params.KeyId).toBe('arn:aws:kms:us-east-1:123456789012:key/prod-wolverine-key');
        expect(params.SigningAlgorithm).toBe('ED25519');
        const sig = crypto.sign(null, params.Message, customerKeypair.privateKey);
        return { Signature: new Uint8Array(sig) };
      },
    };

    const signer = new CloudKmsCustomerSigner(
      {
        keyArn: 'arn:aws:kms:us-east-1:123456789012:key/prod-wolverine-key',
        kmsClient: mockKmsClient,
      },
      customerPubkey
    );

    const sig = await signer.signCommitment(dummyDigest, 1n);
    expect(sig.length).toBe(64);

    const authDigest = computeCustomerAuthorizationDigest(dummyDigest, 1n);
    const keyObj = crypto.createPublicKey({ key: customerPubkey, format: 'der', type: 'spki' });
    const verified = crypto.verify(null, authDigest, keyObj, sig);
    expect(verified).toBe(true);
  });

  it('2. KMS Client Missing: fails closed with MISSING_SECRET_KEY, rejecting silent local fallback', async () => {
    const dummyDigest = crypto.createHash('sha256').update('COMMITMENT_DIGEST').digest();

    const signer = new CloudKmsCustomerSigner(
      {
        keyArn: 'arn:aws:kms:us-east-1:123456789012:key/prod-wolverine-key',
        kmsClient: undefined, // UNCONFIGURED / MISSING
      },
      customerPubkey
    );

    await expect(signer.signCommitment(dummyDigest, 1n)).rejects.toThrowError(
      /FAIL_CLOSED.*Cloud KMS client unavailable/
    );
  });

  it('3. KMS Outage / Network Error: fails closed and halts execution rather than producing mock signatures', async () => {
    const dummyDigest = crypto.createHash('sha256').update('COMMITMENT_DIGEST').digest();

    const faultyKmsClient = {
      asymmetricSign: async () => {
        throw new Error('KmsUnavailableException: Service unreachable');
      },
    };

    const signer = new CloudKmsCustomerSigner(
      {
        keyArn: 'arn:aws:kms:us-east-1:123456789012:key/prod-wolverine-key',
        kmsClient: faultyKmsClient,
      },
      customerPubkey
    );

    await expect(signer.signCommitment(dummyDigest, 1n)).rejects.toThrowError(
      /FAIL_CLOSED.*KmsUnavailableException/
    );
  });

  it('4. KMS Empty Signature Response: fails closed on corrupted/empty KMS payload', async () => {
    const dummyDigest = crypto.createHash('sha256').update('COMMITMENT_DIGEST').digest();

    const emptyKmsClient = {
      asymmetricSign: async () => ({ Signature: undefined }),
    };

    const signer = new CloudKmsCustomerSigner(
      {
        keyArn: 'arn:aws:kms:us-east-1:123456789012:key/prod-wolverine-key',
        kmsClient: emptyKmsClient,
      },
      customerPubkey
    );

    await expect(signer.signCommitment(dummyDigest, 1n)).rejects.toThrowError(
      /Cloud KMS returned empty signature/
    );
  });
});
