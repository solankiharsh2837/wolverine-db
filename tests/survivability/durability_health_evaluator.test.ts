import { describe, it, expect } from 'vitest';
import {
  TrustNetworkHealthEvaluator,
  PersistentTrustLedger,
  ByzantineTrustValidator,
} from '../../src/index.js';

describe('Trust Network Durability & Health Model (WDB-0120)', () => {
  it('evaluates transitions between HEALTHY, DEGRADED, QUORUM_LOST, and PARTITIONED states', () => {
    const ledger = new PersistentTrustLedger();
    const validators = new Map<string, { validator: ByzantineTrustValidator; isOnline: boolean }>();

    for (let i = 1; i <= 5; i++) {
      const vId = `val-0${i}`;
      validators.set(vId, {
        validator: new ByzantineTrustValidator({
          validatorId: vId,
          validatorSetId: 'valset-prod-v1',
          epoch: 1,
          port: 9600 + i,
          host: '127.0.0.1',
        }),
        isOnline: true,
      });
    }

    const replicas = [
      { replicaId: 'rep-01', stateRoot: Buffer.alloc(32, 0x11), isOnline: true },
      { replicaId: 'rep-02', stateRoot: Buffer.alloc(32, 0x11), isOnline: true },
    ];

    // 1. All 5 online -> HEALTHY
    const h1 = TrustNetworkHealthEvaluator.evaluateHealth({
      validators,
      replicas,
      ledger,
      currentEpoch: 1,
      totalConfiguredValidators: 5,
      requiredQuorum: 4,
    });
    expect(h1.durabilityState).toBe('HEALTHY');
    expect(h1.isQuorumAvailable).toBe(true);

    // 2. 1 validator drops (4/5 active) -> DEGRADED
    validators.get('val-01')!.isOnline = false;
    const h2 = TrustNetworkHealthEvaluator.evaluateHealth({
      validators,
      replicas,
      ledger,
      currentEpoch: 1,
      totalConfiguredValidators: 5,
      requiredQuorum: 4,
    });
    expect(h2.durabilityState).toBe('DEGRADED');
    expect(h2.isQuorumAvailable).toBe(true);

    // 3. 2nd validator drops (3/5 active, < 4 quorum) -> QUORUM_LOST
    validators.get('val-02')!.isOnline = false;
    const h3 = TrustNetworkHealthEvaluator.evaluateHealth({
      validators,
      replicas,
      ledger,
      currentEpoch: 1,
      totalConfiguredValidators: 5,
      requiredQuorum: 4,
    });
    expect(h3.durabilityState).toBe('QUORUM_LOST');
    expect(h3.isQuorumAvailable).toBe(false);

    // 4. Replica state root divergence -> PARTITIONED
    replicas[1]!.stateRoot = Buffer.alloc(32, 0x99); // Divergent root
    const h4 = TrustNetworkHealthEvaluator.evaluateHealth({
      validators,
      replicas,
      ledger,
      currentEpoch: 1,
      totalConfiguredValidators: 5,
      requiredQuorum: 4,
    });
    expect(h4.durabilityState).toBe('PARTITIONED');
  });
});
