import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { NodeRegistry } from '../../src/federation/identity.js';
import { FederatedEventChainBuilder } from '../../src/federation/event_chain.js';
import { createSecurityEvent } from '../../src/fabric/events.js';

describe('Adversarial: Key Compromise & Revocation Defense (WDB-0052)', () => {
  it('property: permanently halts event processing from revoked node keys', () => {
    const registry = new NodeRegistry();
    const eventChainBuilder = new FederatedEventChainBuilder(registry);

    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const pubBytes = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

    const node = registry.registerNode(
      'node:us-west-2:compromised-key',
      pubBytes,
      ['DATABASE_MUTATION_CAPTURE'],
      'org',
      'cluster',
      privateKey
    );

    const event = createSecurityEvent({
      plane: 'DATABASE',
      eventType: 'DB_MERKLE_DIVERGENCE',
      actorId: 'admin',
      serviceId: 'pg_primary',
      scope: 'public.users',
      payload: { leak: true },
    });

    // 1. Sign while TRUSTED
    const validEnvelope = eventChainBuilder.signFederatedEvent(node.nodeId, event, privateKey);
    expect(eventChainBuilder.verifyFederatedEvent(validEnvelope)).toBe(true);

    // 2. Admin flags key compromise and REVOKES node
    registry.setNodeStatus(node.nodeId, 'REVOKED');
    expect(registry.isNodeTrusted(node.nodeId)).toBe(false);

    // 3. Any new event generation or verification from this node is rejected
    expect(() => eventChainBuilder.signFederatedEvent(node.nodeId, event, privateKey)).toThrow(
      'is not TRUSTED'
    );
    expect(eventChainBuilder.verifyFederatedEvent(validEnvelope)).toBe(false);
  });
});
