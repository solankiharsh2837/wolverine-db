import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { NodeRegistry } from '../../src/federation/identity.js';
import { FederatedRecoveryAuthority, computeFederatedRecoveryDigest } from '../../src/federation/authority.js';

describe('Adversarial: Malicious Recovery Attempt & Self-Approval Rejection (WDB-0055)', () => {
  it('property: rejects self-signed recovery proposals from proposing nodes', () => {
    const registry = new NodeRegistry();
    const authority = new FederatedRecoveryAuthority(registry);

    const proposerKeys = crypto.generateKeyPairSync('ed25519');
    const proposerPubBytes = proposerKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    const proposerNodeId = 'node:compromised-app:proposer';
    registry.registerNode(proposerNodeId, proposerPubBytes, ['SENTINEL_ADVISORY_ENGINE'], 'org', 'cluster', proposerKeys.privateKey);

    const honestKeys = crypto.generateKeyPairSync('ed25519');
    const honestPubBytes = honestKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    const honestNodeId = 'node:sec-auth:honest-01';
    registry.registerNode(honestNodeId, honestPubBytes, ['POLICY_GATEKEEPER'], 'org', 'cluster', honestKeys.privateKey);

    const proposalId = '00000000-0000-0000-0000-000000000999';
    const incidentId = 'inc:20260815:runtime:1234567890abcdef';
    const protectedScope = 'public.users';
    const proposedChangesHash = Buffer.alloc(32, 0x99);

    const digest = computeFederatedRecoveryDigest(
      proposalId,
      incidentId,
      protectedScope,
      proposedChangesHash
    );

    // Proposer attempts to sign its own proposal to bypass separation of duties
    const maliciousRequest = {
      proposalId,
      incidentId,
      protectedScope,
      proposedChangesHash,
      proposingNodeId: proposerNodeId,
      signatures: [
        {
          nodeId: proposerNodeId,
          signature: crypto.sign(null, digest, proposerKeys.privateKey),
        },
        {
          nodeId: honestNodeId,
          signature: crypto.sign(null, digest, honestKeys.privateKey),
        },
      ],
    };

    // Fails closed because proposer's signature is rejected (leaving only 1 valid signature < 2 required)
    expect(() => authority.verifyFederatedAuthorization(maliciousRequest, 2)).toThrow(
      'FederatedRecoveryAuthorizationFailed: Insufficient valid quorum signatures (1/2 required)'
    );
  });

  it('property: rejects recovery signatures from quarantined nodes', () => {
    const registry = new NodeRegistry();
    const authority = new FederatedRecoveryAuthority(registry);

    const quarantinedKeys = crypto.generateKeyPairSync('ed25519');
    const quarantinedPubBytes = quarantinedKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    const quarantinedNodeId = 'node:quarantined-node';
    registry.registerNode(quarantinedNodeId, quarantinedPubBytes, ['POLICY_GATEKEEPER'], 'org', 'cluster', quarantinedKeys.privateKey);
    registry.setNodeStatus(quarantinedNodeId, 'QUARANTINED');

    const digest = computeFederatedRecoveryDigest('prop-1', 'inc-1', 'public.users', Buffer.alloc(32, 0));

    const request = {
      proposalId: 'prop-1',
      incidentId: 'inc-1',
      protectedScope: 'public.users',
      proposedChangesHash: Buffer.alloc(32, 0),
      proposingNodeId: 'node:other-proposer',
      signatures: [
        {
          nodeId: quarantinedNodeId,
          signature: crypto.sign(null, digest, quarantinedKeys.privateKey),
        },
      ],
    };

    expect(() => authority.verifyFederatedAuthorization(request, 1)).toThrow(
      'FederatedRecoveryAuthorizationFailed: Insufficient valid quorum signatures (0/1 required)'
    );
  });
});
