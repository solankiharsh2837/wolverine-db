import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { NodeRegistry } from '../../src/federation/identity.js';
import { FederatedRecoveryAuthority, computeFederatedRecoveryDigest } from '../../src/federation/authority.js';

describe('Adversarial: Federated Quorum Failure Handling (WDB-0055)', () => {
  it('property: fails closed when required multi-node recovery quorum threshold is not met', () => {
    const registry = new NodeRegistry();
    const authority = new FederatedRecoveryAuthority(registry);

    const nodeKeys: crypto.KeyPairSyncResult<Buffer, Buffer>[] = [];
    const nodeIds: string[] = [];

    for (let i = 0; i < 3; i++) {
      const keys = crypto.generateKeyPairSync('ed25519');
      const pubBytes = keys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
      const nodeId = `node:cluster:auth-node-0${i}`;
      registry.registerNode(nodeId, pubBytes, ['POLICY_GATEKEEPER'], 'org', 'cluster', keys.privateKey);
      nodeKeys.push(keys);
      nodeIds.push(nodeId);
    }

    const proposalId = '00000000-0000-0000-0000-000000000184';
    const incidentId = 'inc:20260815:database:1234567890abcdef';
    const protectedScope = 'public.users';
    const proposedChangesHash = Buffer.alloc(32, 0x88);

    const digest = computeFederatedRecoveryDigest(
      proposalId,
      incidentId,
      protectedScope,
      proposedChangesHash
    );

    // Scenario A: Only 1 signature collected when 2 are required
    const partialRequest = {
      proposalId,
      incidentId,
      protectedScope,
      proposedChangesHash,
      proposingNodeId: 'node:cluster:proposer-node',
      signatures: [
        {
          nodeId: nodeIds[0],
          signature: crypto.sign(null, digest, nodeKeys[0].privateKey),
        },
      ],
    };

    expect(() => authority.verifyFederatedAuthorization(partialRequest, 2)).toThrow(
      'FederatedRecoveryAuthorizationFailed: Insufficient valid quorum signatures (1/2 required)'
    );

    // Scenario B: 2 valid signatures satisfy required 2-of-3 quorum
    const completeRequest = {
      ...partialRequest,
      signatures: [
        ...partialRequest.signatures,
        {
          nodeId: nodeIds[1],
          signature: crypto.sign(null, digest, nodeKeys[1].privateKey),
        },
      ],
    };

    const authResult = authority.verifyFederatedAuthorization(completeRequest, 2);
    expect(authResult.authorized).toBe(true);
    expect(authResult.validSigners).toEqual([nodeIds[0], nodeIds[1]]);
  });
});
