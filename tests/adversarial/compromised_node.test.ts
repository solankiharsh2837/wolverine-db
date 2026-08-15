import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { NodeRegistry } from '../../src/federation/identity.js';
import { NodeQuarantineManager } from '../../src/federation/quarantine.js';

describe('Adversarial: Compromised Node Isolation & Quarantine (WDB-0054)', () => {
  it('property: quarantines compromised node on detection without destroying historical evidence', () => {
    const registry = new NodeRegistry();
    const quarantineManager = new NodeQuarantineManager(registry);

    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const pubKeyBytes = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

    const node = registry.registerNode(
      'node:us-east-1:node-compromised',
      pubKeyBytes,
      ['DATABASE_MUTATION_CAPTURE'],
      'org-enterprise',
      'cluster-01',
      privateKey
    );

    expect(registry.isNodeTrusted(node.nodeId)).toBe(true);

    // Byzantine node starts submitting divergent checkpoints
    const quarantineRecord = quarantineManager.quarantineNode(
      node.nodeId,
      'DIVERGENT_CHECKPOINT_ATTESTATION',
      42n,
      Buffer.alloc(32, 0xaa),
      { observedMerkleRoot: 'corrupted', expectedMerkleRoot: 'authentic' },
      'sentinel_federation_guard',
      'chk-42'
    );

    // Node is isolated
    expect(registry.isNodeTrusted(node.nodeId)).toBe(false);
    expect(registry.getNode(node.nodeId)?.status).toBe('QUARANTINED');

    // Historical forensic evidence is preserved
    expect(quarantineRecord.lastValidEventSequence).toBe(42n);
    expect(quarantineRecord.lastValidEventHash).toEqual(Buffer.alloc(32, 0xaa));
    expect(quarantineRecord.lastValidCheckpointId).toBe('chk-42');
  });
});
