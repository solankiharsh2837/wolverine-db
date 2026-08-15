import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WolverineTrustNetworkService,
  createSignedCustomerCommitment,
  verifyCustomerCommitment,
} from '../../src/index.js';

describe('Tenant Isolation & Cryptographic Domain Separation (WDB-0081, WDB-0087)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('property: commitment signed by Tenant A is cryptographically invalid under Tenant B', () => {
    const tenantA = genKeys();
    const tenantB = genKeys();

    const commitmentA = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId: 'tenant-alpha',
        databaseId: 'db-orders',
        checkpointId: 'chk-001',
        commitSeq: 100n,
        checkpointDigest: Buffer.alloc(32, 0x11),
        previousTrustCommitment: Buffer.alloc(32, 0),
      },
      tenantA.priv,
      tenantA.pub
    );

    // Verify under Tenant A's pubkey -> PASS
    expect(verifyCustomerCommitment(commitmentA, tenantA.pub)).toBe(true);

    // Verify under Tenant B's pubkey -> FAILS
    expect(verifyCustomerCommitment(commitmentA, tenantB.pub)).toBe(false);

    // Attempting to spoof tenantId with Tenant A's signature -> FAILS
    const spoofedCommitment = {
      ...commitmentA,
      tenantId: 'tenant-beta',
    };
    expect(verifyCustomerCommitment(spoofedCommitment, tenantA.pub)).toBe(false);
  });

  it('service rejection: Trust Network rejects submissions from unauthorized databases or cross-tenant replays', async () => {
    const service = new WolverineTrustNetworkService(3, 5);
    const tenantA = genKeys();
    const tenantB = genKeys();

    service.registerTenant('tenant-alpha', tenantA.pub, 'db-orders');
    service.registerTenant('tenant-beta', tenantB.pub, 'db-payments');

    const commitmentA = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId: 'tenant-alpha',
        databaseId: 'db-orders',
        checkpointId: 'chk-001',
        commitSeq: 100n,
        checkpointDigest: Buffer.alloc(32, 0x11),
        previousTrustCommitment: Buffer.alloc(32, 0),
      },
      tenantA.priv,
      tenantA.pub
    );

    // Legitimate submission from Tenant A
    const resA = await service.submitCommitment(commitmentA);
    expect(resA.status).toBe('FINALIZED');

    // Tenant B attempts to submit Tenant A's commitment under Tenant B
    const rogueCommitment = {
      ...commitmentA,
      commitmentId: crypto.randomUUID(),
      tenantId: 'tenant-beta',
      databaseId: 'db-payments',
    };

    await expect(service.submitCommitment(rogueCommitment)).rejects.toThrow();
  });
});
