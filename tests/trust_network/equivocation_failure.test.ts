import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WolverineTrustNetworkService,
  createSignedCustomerCommitment,
} from '../../src/index.js';

describe('Equivocation & Double-Commitment Defense (WDB-0084, WDB-0086)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('fails closed: rejects attempted replacement of finalized commitment at same sequence', async () => {
    const service = new WolverineTrustNetworkService(3, 5);
    const customer = genKeys();

    service.registerTenant('tenant-bank', customer.pub, 'db-ledger');

    const commit1 = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId: 'tenant-bank',
        databaseId: 'db-ledger',
        checkpointId: 'chk-100',
        commitSeq: 100n,
        checkpointDigest: Buffer.alloc(32, 0x11),
        previousTrustCommitment: Buffer.alloc(32, 0),
      },
      customer.priv,
      customer.pub
    );

    // Finalize first commitment
    const res1 = await service.submitCommitment(commit1);
    expect(res1.status).toBe('FINALIZED');

    // Attacker / divergent branch attempts to submit conflicting commitment at seq 100
    const commitConflicting = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId: 'tenant-bank',
        databaseId: 'db-ledger',
        checkpointId: 'chk-100-divergent',
        commitSeq: 100n,
        checkpointDigest: Buffer.alloc(32, 0x99), // Different digest!
        previousTrustCommitment: Buffer.alloc(32, 0),
      },
      customer.priv,
      customer.pub
    );

    await expect(service.submitCommitment(commitConflicting)).rejects.toThrow();
  });
});
