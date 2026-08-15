import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { NodeRegistry } from '../../src/federation/identity.js';
import { FederatedEventChainBuilder } from '../../src/federation/event_chain.js';
import { createSecurityEvent } from '../../src/fabric/events.js';

describe('Adversarial: Event Replay & Sequence Mismatch Defense (WDB-0051)', () => {
  it('property: rejects replayed events with stale sequence or broken hash continuity', () => {
    const registry = new NodeRegistry();
    const eventChainBuilder = new FederatedEventChainBuilder(registry);

    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const pubBytes = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

    const node = registry.registerNode(
      'node:eu-west-1:replay-target',
      pubBytes,
      ['DATABASE_MUTATION_CAPTURE'],
      'org',
      'cluster',
      privateKey
    );

    const event1 = createSecurityEvent({
      plane: 'DATABASE',
      eventType: 'DB_UNAUTHORIZED_MUTATION',
      actorId: 'admin',
      serviceId: 'pg_primary',
      scope: 'public.users',
      payload: { seq: 1 },
    });

    const event2 = createSecurityEvent({
      plane: 'DATABASE',
      eventType: 'DB_UNAUTHORIZED_MUTATION',
      actorId: 'admin',
      serviceId: 'pg_primary',
      scope: 'public.users',
      payload: { seq: 2 },
    });

    const env1 = eventChainBuilder.signFederatedEvent(node.nodeId, event1, privateKey);
    const env2 = eventChainBuilder.signFederatedEvent(node.nodeId, event2, privateKey);

    expect(env1.nodeSequence).toBe(1n);
    expect(env2.nodeSequence).toBe(2n);
    expect(env2.previousEventHash).toEqual(env1.eventChainHash);

    // Receiver verifies env1 at seq 1
    expect(eventChainBuilder.verifyFederatedEvent(env1, Buffer.alloc(32, 0), 1n)).toBe(true);

    // Attacker attempts to replay env1 again when receiver expects seq 2
    expect(eventChainBuilder.verifyFederatedEvent(env1, env1.eventChainHash, 2n)).toBe(false);

    // Receiver accepts genuine env2 at seq 2
    expect(eventChainBuilder.verifyFederatedEvent(env2, env1.eventChainHash, 2n)).toBe(true);
  });
});
