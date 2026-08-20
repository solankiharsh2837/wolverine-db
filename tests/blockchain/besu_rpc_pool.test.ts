import { describe, it, expect } from 'vitest';
import { BesuRpcPool } from '../../src/blockchain/besu/rpc_pool.js';
import { WolverineError, WolverineErrorCode } from '../../src/errors/index.js';

describe('BesuRpcPool High Availability & Failover', () => {
  it('initializes with multiple validator nodes and manages round-robin rotation', () => {
    const pool = new BesuRpcPool({
      nodes: [
        'http://127.0.0.1:8545',
        'http://127.0.0.1:8546',
        'http://127.0.0.1:8547',
      ],
      chainId: 13370,
    });

    expect(pool.getAllNodes()).toHaveLength(3);
    expect(pool.getHealthyNodes()).toHaveLength(3);

    const node1 = pool.getNextNodeUrl();
    const node2 = pool.getNextNodeUrl();
    const node3 = pool.getNextNodeUrl();
    const node4 = pool.getNextNodeUrl();

    expect(node1).toBe('http://127.0.0.1:8545');
    expect(node2).toBe('http://127.0.0.1:8546');
    expect(node3).toBe('http://127.0.0.1:8547');
    expect(node4).toBe('http://127.0.0.1:8545');
  });

  it('fails over to healthy node when one node fails', async () => {
    const pool = new BesuRpcPool({
      nodes: [
        'http://127.0.0.1:9991', // Will fail
        'http://127.0.0.1:9992', // Will succeed
      ],
      chainId: 13370,
      timeoutMs: 500,
      maxRetries: 3,
      retryBackoffMs: 10,
    });

    let attemptCount = 0;
    const res = await pool.executeWithFailover(async (url) => {
      attemptCount++;
      if (url.includes('9991')) {
        throw new Error('Connection refused to 9991');
      }
      return { success: true, url };
    });

    expect(res.success).toBe(true);
    expect(res.url).toBe('http://127.0.0.1:9992');
    expect(attemptCount).toBeGreaterThanOrEqual(2);
  });

  it('does NOT retry when error is a contract execution revert (e.g. SequenceGapDetected)', async () => {
    const pool = new BesuRpcPool({
      nodes: [
        'http://127.0.0.1:8545',
        'http://127.0.0.1:8546',
      ],
      chainId: 13370,
      maxRetries: 3,
    });

    let callCount = 0;
    await expect(
      pool.executeWithFailover(async () => {
        callCount++;
        throw new Error('Execution reverted: SequenceGapDetected(expected: 2, received: 5)');
      })
    ).rejects.toThrow('SequenceGapDetected');

    expect(callCount).toBe(1); // Exactly 1 call, zero redundant retries
  });

  it('throws NETWORK_ERROR when all nodes fail', async () => {
    const pool = new BesuRpcPool({
      nodes: [
        'http://127.0.0.1:9991',
        'http://127.0.0.1:9992',
      ],
      chainId: 13370,
      maxRetries: 2,
      retryBackoffMs: 10,
    });

    await expect(
      pool.executeWithFailover(async () => {
        throw new Error('All nodes down');
      })
    ).rejects.toThrow(WolverineError);
  });
});
