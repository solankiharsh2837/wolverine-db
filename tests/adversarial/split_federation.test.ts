import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { NodeRegistry } from '../../src/federation/identity.js';
import { FederatedConsensusEngine } from '../../src/federation/consensus.js';

describe('Adversarial: Federated Split & Partition Consensus (WDB-0053)', () => {
  it('property: fails closed under Byzantine split when quorum cannot be formed', () => {
    const registry = new NodeRegistry();
    const consensusEngine = new FederatedConsensusEngine(registry);

    // Setup 5 nodes
    const nodeKeys: crypto.KeyPairSyncResult<Buffer, Buffer>[] = [];
    const nodeIds: string[] = [];

    for (let i = 0; i < 5; i++) {
      const keys = crypto.generateKeyPairSync('ed25519');
      const pubBytes = keys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
      const nodeId = `node:region:cluster-node-0${i}`;
      registry.registerNode(nodeId, pubBytes, ['DATABASE_MUTATION_CAPTURE'], 'org-enterprise', 'cluster', keys.privateKey);
      nodeKeys.push(keys);
      nodeIds.push(nodeId);
    }

    const checkpointId = '00000000-0000-0000-0000-000000009182';
    const honestDigest = Buffer.alloc(32, 0x11);
    const divergentDigest = Buffer.alloc(32, 0x22);

    // 4-of-5 Quorum Policy
    const policy4of5 = { requiredQuorum: 4, totalNodes: 5 };

    // Scenario A: 3 nodes honest, 2 nodes partitioned / divergent
    const attestations = [
      consensusEngine.createAttestation(nodeIds[0], checkpointId, honestDigest, 100n, Buffer.alloc(32), nodeKeys[0].privateKey),
      consensusEngine.createAttestation(nodeIds[1], checkpointId, honestDigest, 100n, Buffer.alloc(32), nodeKeys[1].privateKey),
      consensusEngine.createAttestation(nodeIds[2], checkpointId, honestDigest, 100n, Buffer.alloc(32), nodeKeys[2].privateKey),
      consensusEngine.createAttestation(nodeIds[3], checkpointId, divergentDigest, 100n, Buffer.alloc(32), nodeKeys[3].privateKey),
      consensusEngine.createAttestation(nodeIds[4], checkpointId, divergentDigest, 100n, Buffer.alloc(32), nodeKeys[4].privateKey),
    ];

    const result = consensusEngine.evaluateConsensus(honestDigest, attestations, policy4of5);

    // Fails closed (DEGRADED / DIVERGENCE rather than false VALID)
    expect(result.verdict).toBe('FEDERATION_CONSENSUS_DIVERGENCE');
    expect(result.validMatchingNodes).toHaveLength(3);
    expect(result.divergentNodes).toHaveLength(2);

    // Scenario B: 4 nodes agree -> Satisfies 4-of-5 Quorum
    const healthyAttestations = [
      ...attestations.slice(0, 3),
      consensusEngine.createAttestation(nodeIds[3], checkpointId, honestDigest, 100n, Buffer.alloc(32), nodeKeys[3].privateKey),
    ];
    const healthyResult = consensusEngine.evaluateConsensus(honestDigest, healthyAttestations, policy4of5);
    expect(healthyResult.verdict).toBe('FEDERATION_CONSENSUS_VALID');
    expect(healthyResult.validMatchingNodes).toHaveLength(4);
  });
});
