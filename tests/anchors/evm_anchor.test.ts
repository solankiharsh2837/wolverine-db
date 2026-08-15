import { describe, it, expect } from 'vitest';
import { EvmAnchorAdapter } from '../../src/anchors/evm.js';
import { AnchorStatus } from '../../src/anchors/types.js';

describe('EVM Anchor Adapter (WDB-0021 Hardening)', () => {
  it('property: tracks confirmation depth from confirming to finalized', async () => {
    const adapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 5,
    });

    const checkpointId = '00000000-0000-0000-0000-000000000100';
    const digest = Buffer.alloc(32, 0x11);

    const record = await adapter.anchorCheckpoint(checkpointId, digest, 100n);
    expect(record.status).toBe(AnchorStatus.CONFIRMING);
    expect(record.confirmationCount).toBe(1);

    // Advance 3 blocks (total 4 confirmations)
    adapter.advanceBlock(3n);
    const mid = await adapter.getAnchor(checkpointId);
    expect(mid?.status).toBe(AnchorStatus.CONFIRMING);
    expect(mid?.confirmationCount).toBe(4);

    // Advance 1 more block (total 5 confirmations -> FINALIZED)
    adapter.advanceBlock(1n);
    const finalized = await adapter.getAnchor(checkpointId);
    expect(finalized?.status).toBe(AnchorStatus.FINALIZED);
    expect(finalized?.confirmationCount).toBe(5);
  });

  it('property: rejects conflicting on-chain anchor commitment', async () => {
    const adapter = new EvmAnchorAdapter({
      chainId: '8453',
      contractAddress: '0x0000000000000000000000000000000000000001',
      requiredConfirmations: 1,
    });

    const checkpointId = '00000000-0000-0000-0000-000000000200';
    const digest1 = Buffer.alloc(32, 0xaa);
    const digest2 = Buffer.alloc(32, 0xbb);

    await adapter.anchorCheckpoint(checkpointId, digest1, 200n);

    // Idempotent re-put with exact same digest succeeds
    await expect(adapter.anchorCheckpoint(checkpointId, digest1, 200n)).resolves.not.toThrow();

    // Differing digest with same checkpointId throws conflict error
    await expect(adapter.anchorCheckpoint(checkpointId, digest2, 200n)).rejects.toThrow(
      'ConflictingAnchorCommitmentError'
    );
  });

  it('property: enforces max gas price limit', async () => {
    const adapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
      maxGasPriceGwei: 50,
    });

    const checkpointId = '00000000-0000-0000-0000-000000000300';
    const digest = Buffer.alloc(32, 0xcc);

    // Gas price = 100 Gwei > 50 Gwei limit
    await expect(adapter.anchorCheckpoint(checkpointId, digest, 300n, 100)).rejects.toThrow(
      'exceeds max configured limit'
    );
  });
});
