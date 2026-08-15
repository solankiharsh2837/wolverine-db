import { describe, it, expect } from 'vitest';
import { EvmAnchorAdapter } from '../../src/anchors/evm.js';
import { AnchorStatus } from '../../src/anchors/types.js';

describe('Anchor Failure & Reorg Semantics (WDB-0024 Hardening)', () => {
  it('property: detects blockchain reorg and unwinds anchor confirmations to ORPHANED_REORG', async () => {
    const adapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 10,
    });

    const checkpointId = '00000000-0000-0000-0000-000000000060';
    const digest = Buffer.alloc(32, 0x60);

    await adapter.anchorCheckpoint(checkpointId, digest, 60n);
    adapter.advanceBlock(4n); // Block height 1004

    const beforeReorg = await adapter.getAnchor(checkpointId);
    expect(beforeReorg?.status).toBe(AnchorStatus.CONFIRMING);
    expect(beforeReorg?.confirmationCount).toBe(5);

    // Deep reorg of 10 blocks (rolls chain back to 994, before block 1000)
    adapter.triggerReorg(10n);

    const afterReorg = await adapter.getAnchor(checkpointId);
    expect(afterReorg?.status).toBe(AnchorStatus.ORPHANED_REORG);
    expect(afterReorg?.confirmationCount).toBe(0);
  });

  it('property: handles RPC outage gracefully without throwing uncaught exceptions', async () => {
    const adapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
    });

    // Simulate network RPC crash
    adapter.setRpcOnline(false);

    await expect(
      adapter.anchorCheckpoint('chk-rpc-fail', Buffer.alloc(32, 0), 1n)
    ).rejects.toThrow('EVM RPC endpoint unreachable');
  });
});
