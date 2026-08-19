import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import {
  DurableDisasterQueue,
  DisasterType,
  DisasterState,
} from '../src/index.js';

describe('Milestone 4.4 — Durable Disaster Recovery Queue & Lifecycle Transitions', () => {
  const testDir = path.join(process.cwd(), 'tmp', 'test_disasters');
  const queuePath = path.join(testDir, 'disasters.wdbjrn');

  beforeEach(() => {
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
  });

  afterEach(() => {
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('1. Disaster Lifecycle & Persistence: records disaster in QUARANTINED state and transitions to RESOLVED', async () => {
    const queue1 = new DurableDisasterQueue(queuePath);

    const disaster = queue1.recordDisaster(
      DisasterType.D001_REPLICATION_SLOT_LOSS,
      'PostgreSQL logical replication slot unexpectedly dropped'
    );

    expect(disaster.state).toBe(DisasterState.QUARANTINED);
    expect(queue1.getActiveDisasters().length).toBe(1);

    // Transition to RECOVERY_REQUIRED
    queue1.transitionState(disaster.disasterId, DisasterState.RECOVERY_REQUIRED, 'Operator initiated resynchronization');
    expect(queue1.getDisaster(disaster.disasterId)?.state).toBe(DisasterState.RECOVERY_REQUIRED);

    // Transition to RECOVERY_VERIFIED
    queue1.transitionState(disaster.disasterId, DisasterState.RECOVERY_VERIFIED, 'Baseline snapshot S0 verified');
    expect(queue1.getDisaster(disaster.disasterId)?.state).toBe(DisasterState.RECOVERY_VERIFIED);

    await queue1.close();

    // SIMULATE PROCESS RESTART: Re-instantiate queue from disk
    const queue2 = new DurableDisasterQueue(queuePath);
    const loaded = queue2.getDisaster(disaster.disasterId);

    expect(loaded).toBeDefined();
    expect(loaded?.state).toBe(DisasterState.RECOVERY_VERIFIED);
    expect(loaded?.details).toContain('Baseline snapshot S0 verified');

    // Finalize resolution
    queue2.transitionState(disaster.disasterId, DisasterState.RESOLVED, 'Replication resumed from new snapshot');
    expect(queue2.getActiveDisasters().length).toBe(0);
    expect(queue2.getDisaster(disaster.disasterId)?.state).toBe(DisasterState.RESOLVED);

    await queue2.close();
  });
});
