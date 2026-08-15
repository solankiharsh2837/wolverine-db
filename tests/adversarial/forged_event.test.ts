import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { NodeRegistry } from '../../src/federation/identity.js';
import { FederatedEventChainBuilder } from '../../src/federation/event_chain.js';
import { createSecurityEvent } from '../../src/fabric/events.js';

describe('Adversarial: Forged Event Signature & Tampering (WDB-0051)', () => {
  it('property: rejects forged events and signature mismatches from unauthenticated origins', () => {
    const registry = new NodeRegistry();
    const eventChainBuilder = new FederatedEventChainBuilder(registry);

    const honestKeys = crypto.generateKeyPairSync('ed25519');
    const honestPubBytes = honestKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

    const attackerKeys = crypto.generateKeyPairSync('ed25519');

    const honestNode = registry.registerNode(
      'node:us-east-1:honest-01',
      honestPubBytes,
      ['DATABASE_MUTATION_CAPTURE'],
      'org-enterprise',
      'cluster-01',
      honestKeys.privateKey
    );

    const event = createSecurityEvent({
      plane: 'DATABASE',
      eventType: 'DB_UNAUTHORIZED_MUTATION',
      actorId: 'admin',
      serviceId: 'pg_primary',
      scope: 'public.users',
      payload: { role: 'SUPERUSER' },
    });

    // 1. Legitimate node signs event -> Verification succeeds
    const legitimateEnvelope = eventChainBuilder.signFederatedEvent(
      honestNode.nodeId,
      event,
      honestKeys.privateKey
    );
    expect(eventChainBuilder.verifyFederatedEvent(legitimateEnvelope)).toBe(true);

    // 2. Attacker attempts to forge signature with different private key
    const forgedEnvelope = {
      ...legitimateEnvelope,
      nodeSignature: crypto.sign(null, legitimateEnvelope.eventChainHash, attackerKeys.privateKey),
    };
    expect(eventChainBuilder.verifyFederatedEvent(forgedEnvelope)).toBe(false);

    // 3. Attacker modifies payload without resigning
    const tamperedPayloadEnvelope = {
      ...legitimateEnvelope,
      event: {
        ...legitimateEnvelope.event,
        payload: { role: 'ATTACKER_ESCALATED' },
      },
    };
    expect(eventChainBuilder.verifyFederatedEvent(tamperedPayloadEnvelope)).toBe(false);
  });
});
