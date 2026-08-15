import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WolverineTrustNetworkService,
  WolverineEvidenceAgent,
  OfflineTrustProofVerifier,
  WolverineTrustCli,
} from '../../src/index.js';

describe('Portable Trust Proof & Standalone Offline Verification (WDB-0085)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('offline verification: proof verifies standalone when Wolverine servers are completely offline', async () => {
    const service = new WolverineTrustNetworkService(3, 5);
    const customer = genKeys();

    service.registerTenant('tenant-acme', customer.pub, 'db-production');

    const agent = new WolverineEvidenceAgent({
      tenantId: 'tenant-acme',
      databaseId: 'db-production',
      customerPubkey: customer.pub,
      customerPrivateKey: customer.priv,
      service,
    });

    const checkpoint = {
      checkpointId: '00000000-0000-0000-0000-000000001842',
      commitSeq: 1842n,
      scope: 'public.orders',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 0x55),
      changeChainHead: Buffer.alloc(32, 0x66),
      createdAtUs: 1723500000000000n,
      protocolVersion: 3,
    };
    const checkpointDigest = Buffer.alloc(32, 0x8a);

    // Commit checkpoint
    const commitResult = await agent.commitCheckpoint(checkpoint, checkpointDigest);
    expect(commitResult.isSynchronized).toBe(true);
    expect(commitResult.proof).toBeDefined();

    const proof = commitResult.proof!;

    // Export Proof JSON
    const exportedJson = WolverineTrustCli.executeProofExport(proof);

    // TAKE WOLVERINE TRUST API OFFLINE
    service.setNetworkOnlineStatus(false);

    // Standalone Verifier parses and verifies without server access
    const { result, terminalOutput } = WolverineTrustCli.executeProofVerify(exportedJson);

    expect(result.isValid).toBe(true);
    expect(result.status).toBe('VALID');
    expect(terminalOutput).toContain('WOLVERINE STANDALONE PROOF VERIFICATION');
    expect(terminalOutput).toContain('PASS (AUTHENTIC & IMMUTABLE)');
  });

  it('fails closed: rejects tampered proof when validator signature is forged or digest modified', async () => {
    const service = new WolverineTrustNetworkService(3, 5);
    const customer = genKeys();
    service.registerTenant('tenant-acme', customer.pub, 'db-production');

    const agent = new WolverineEvidenceAgent({
      tenantId: 'tenant-acme',
      databaseId: 'db-production',
      customerPubkey: customer.pub,
      customerPrivateKey: customer.priv,
      service,
    });

    const checkpoint = {
      checkpointId: '00000000-0000-0000-0000-000000001843',
      commitSeq: 1843n,
      scope: 'public.orders',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 0x55),
      changeChainHead: Buffer.alloc(32, 0x66),
      createdAtUs: 1723500000000000n,
      protocolVersion: 3,
    };
    const checkpointDigest = Buffer.alloc(32, 0x8a);

    const commitResult = await agent.commitCheckpoint(checkpoint, checkpointDigest);
    const proof = commitResult.proof!;

    // Tamper with checkpoint digest in proof
    const tamperedProof = {
      ...proof,
      commitment: {
        ...proof.commitment,
        checkpointDigestHex: '00'.repeat(32),
      },
    };

    const verifyResult = OfflineTrustProofVerifier.verifyPortableProof(tamperedProof);
    expect(verifyResult.isValid).toBe(false);
  });
});
